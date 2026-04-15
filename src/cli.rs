//! CLI definition and subcommand handlers for secretsh.
//!
//! This module owns:
//! - The [`Cli`] struct and all [`Subcommand`] variants (parsed by `clap`).
//! - [`default_vault_path`] — platform-aware default vault location.
//! - [`emit_audit`] — JSON Lines audit entry emitted to stderr.
//! - One handler function per subcommand (`run_init`, `run_set`, …).

use std::io::{self, Read, Write};
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand as ClapSubcommand};
use ring::digest::{digest, SHA256};
use serde_json::json;
use zeroize::Zeroizing;

use crate::dotenv::parse_dotenv;
use crate::error::SecretshError;
use crate::redact::Redactor;
use crate::spawn::{spawn_child, SpawnConfig};
use crate::tokenizer::tokenize;
use crate::vault::{Vault, VaultConfig};

// ─────────────────────────────────────────────────────────────────────────────
// Default vault path
// ─────────────────────────────────────────────────────────────────────────────

/// Return the platform-appropriate default vault path.
///
/// | Platform | Path                                                        |
/// |----------|-------------------------------------------------------------|
/// | macOS    | `~/Library/Application Support/secretsh/vault.bin`          |
/// | Linux    | `$XDG_DATA_HOME/secretsh/vault.bin`                         |
/// |          | (falls back to `~/.local/share/secretsh/vault.bin`)         |
pub fn default_vault_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        // macOS: ~/Library/Application Support/secretsh/vault.bin
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("secretsh")
            .join("vault.bin")
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Linux / other: $XDG_DATA_HOME/secretsh/vault.bin
        // Falls back to ~/.local/share/secretsh/vault.bin
        let base = std::env::var("XDG_DATA_HOME")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
                PathBuf::from(home).join(".local").join("share")
            });
        base.join("secretsh").join("vault.bin")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit logging
// ─────────────────────────────────────────────────────────────────────────────

/// Emit a JSON Lines audit entry to stderr.
///
/// The entry always contains:
/// - `ts`        — ISO 8601 UTC timestamp
/// - `op`        — operation name (e.g. `"set"`, `"run"`)
/// - `key_count` — number of vault keys involved
///
/// Any additional fields from `extra` are merged into the top-level object.
pub fn emit_audit(op: &str, key_count: usize, extra: &serde_json::Value) {
    let ts = chrono::Utc::now().to_rfc3339();

    let mut entry = json!({
        "ts": ts,
        "op": op,
        "key_count": key_count,
    });

    // Merge extra fields into the top-level object.
    if let (Some(obj), Some(extra_obj)) = (entry.as_object_mut(), extra.as_object()) {
        for (k, v) in extra_obj {
            obj.insert(k.clone(), v.clone());
        }
    }

    // Write to stderr as a single JSON line; ignore write errors (best-effort).
    let _ = writeln!(io::stderr(), "{}", entry);
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared vault-path / master-key-env args (reused across subcommands)
// ─────────────────────────────────────────────────────────────────────────────

/// Common vault-location and authentication arguments shared by every
/// subcommand that needs to open an existing vault.
#[derive(Args, Debug)]
pub struct VaultArgs {
    /// Path to the vault file.
    ///
    /// Defaults to the platform-appropriate location when omitted.
    #[arg(long, value_name = "PATH")]
    pub vault: Option<PathBuf>,

    /// Name of the environment variable that holds the master passphrase
    /// (defaults to SECRETSH_KEY).
    #[arg(long, value_name = "ENV_VAR", default_value = "SECRETSH_KEY")]
    pub master_key_env: String,
}

impl VaultArgs {
    /// Resolve the vault path, falling back to [`default_vault_path`].
    pub fn vault_path(&self) -> PathBuf {
        self.vault.clone().unwrap_or_else(default_vault_path)
    }

    /// Build a [`VaultConfig`] from these args.
    pub fn to_vault_config(&self) -> VaultConfig {
        VaultConfig {
            vault_path: self.vault_path(),
            master_key_env: self.master_key_env.clone(),
            allow_insecure_permissions: false,
            kdf_memory: None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI definition
// ─────────────────────────────────────────────────────────────────────────────

/// secretsh — secure subprocess secret injection.
#[derive(Parser, Debug)]
#[command(
    name = "secretsh",
    version,
    about = "Inject secrets from an encrypted vault into subprocess arguments",
    long_about = None,
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// All top-level subcommands.
#[derive(ClapSubcommand, Debug)]
pub enum Command {
    /// Create a new encrypted vault.
    Init(InitArgs),

    /// Store or update a secret in the vault.
    Set(SetArgs),

    /// Remove a secret from the vault.
    Delete(DeleteArgs),

    /// List all key names stored in the vault.
    List(ListArgs),

    /// Run a command with secrets injected from the vault.
    Run(RunArgs),

    /// Export vault secrets to an encrypted file.
    Export(ExportArgs),

    /// Import secrets from an encrypted export file.
    Import(ImportArgs),

    /// Import secrets from a .env file.
    ImportEnv(ImportEnvArgs),
}

// ─────────────────────────────────────────────────────────────────────────────
// init
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `secretsh init`.
#[derive(Args, Debug)]
pub struct InitArgs {
    /// Path to the vault file (created at the platform default when omitted).
    #[arg(long, value_name = "PATH")]
    pub vault: Option<PathBuf>,

    /// Name of the environment variable that holds the master passphrase
    /// (defaults to SECRETSH_KEY).
    #[arg(long, value_name = "ENV_VAR", default_value = "SECRETSH_KEY")]
    pub master_key_env: String,

    /// Argon2id memory cost in KiB (minimum 65536, default 131072 = 128 MiB).
    #[arg(long, value_name = "KiB", default_value_t = 131_072, value_parser = clap::value_parser!(u32).range(65_536..))]
    pub kdf_memory: u32,

    /// Skip the minimum passphrase-length check (useful for machine-generated
    /// passphrases).
    #[arg(long)]
    pub no_passphrase_check: bool,

    /// Overwrite an existing vault without prompting.
    #[arg(long)]
    pub force: bool,
}

impl InitArgs {
    fn vault_path(&self) -> PathBuf {
        self.vault.clone().unwrap_or_else(default_vault_path)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// set
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `secretsh set <KEY_NAME>`.
#[derive(Args, Debug)]
pub struct SetArgs {
    /// The key name to store (must match `[A-Za-z_][A-Za-z0-9_]*`).
    pub key_name: String,

    #[command(flatten)]
    pub vault: VaultArgs,
}

// ─────────────────────────────────────────────────────────────────────────────
// delete
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `secretsh delete <KEY_NAME>`.
#[derive(Args, Debug)]
pub struct DeleteArgs {
    /// The key name to remove.
    pub key_name: String,

    #[command(flatten)]
    pub vault: VaultArgs,
}

// ─────────────────────────────────────────────────────────────────────────────
// list
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `secretsh list`.
#[derive(Args, Debug)]
pub struct ListArgs {
    #[command(flatten)]
    pub vault: VaultArgs,
}

// ─────────────────────────────────────────────────────────────────────────────
// run
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `secretsh run`.
#[derive(Args, Debug)]
pub struct RunArgs {
    #[command(flatten)]
    pub vault: VaultArgs,

    /// Maximum wall-clock seconds the child may run before being killed
    /// (default 300).
    #[arg(long, value_name = "SECONDS", default_value_t = 300)]
    pub timeout: u64,

    /// Maximum bytes accepted from the child's stdout before it is killed
    /// (default 52428800 = 50 MiB).
    #[arg(long, value_name = "BYTES", default_value_t = 52_428_800)]
    pub max_output: usize,

    /// Maximum bytes accepted from the child's stderr before it is killed
    /// (default 1048576 = 1 MiB).
    #[arg(long, value_name = "BYTES", default_value_t = 1_048_576)]
    pub max_stderr: usize,

    /// Suppress audit output.
    #[arg(long)]
    pub quiet: bool,

    /// Enable verbose/debug output.
    #[arg(long)]
    pub verbose: bool,

    /// The command string to execute (with `{{KEY}}` placeholders).
    ///
    /// Pass after `--`, e.g.: `secretsh run ... -- "psql {{DB_URL}}"`
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// export
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `secretsh export`.
#[derive(Args, Debug)]
pub struct ExportArgs {
    #[command(flatten)]
    pub vault: VaultArgs,

    /// Path to write the encrypted export file.
    #[arg(long, value_name = "PATH", required = true)]
    pub out: PathBuf,
}

// ─────────────────────────────────────────────────────────────────────────────
// import
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `secretsh import`.
#[derive(Args, Debug)]
pub struct ImportArgs {
    #[command(flatten)]
    pub vault: VaultArgs,

    /// Path to the encrypted export file to import from.
    // Note: `in` is a reserved keyword in Rust; we use `input` as the field
    // name and map it to `--in` via the `name` attribute.
    #[arg(long = "in", value_name = "PATH", required = true)]
    pub input: PathBuf,

    /// Replace existing entries with imported values.
    #[arg(long)]
    pub overwrite: bool,

    /// Name of the environment variable holding the import file's passphrase.
    #[arg(long, value_name = "ENV_VAR")]
    pub import_key_env: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// import-env
// ─────────────────────────────────────────────────────────────────────────────

/// Arguments for `secretsh import-env`.
#[derive(Args, Debug)]
pub struct ImportEnvArgs {
    #[command(flatten)]
    pub vault: VaultArgs,

    /// Path to the .env file to import.
    #[arg(long = "file", short = 'f', value_name = "PATH", required = true)]
    pub file: PathBuf,

    /// Replace existing entries with imported values.
    #[arg(long)]
    pub overwrite: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Subcommand handlers
// ─────────────────────────────────────────────────────────────────────────────

// ── init ──────────────────────────────────────────────────────────────────────

/// Handle `secretsh init`.
///
/// Creates a new empty vault at the specified (or default) path.
///
/// - If the vault already exists and `--force` is **not** given, the command
///   fails with a clear error message (exit code 125).
/// - If `--force` is given and the vault already exists, it is removed first
///   so that `Vault::init` can write a fresh vault atomically.
pub fn run_init(args: &InitArgs) -> Result<(), SecretshError> {
    let vault_path = args.vault_path();

    if vault_path.exists() {
        if args.force {
            // Remove the existing vault so Vault::init can create a fresh one.
            std::fs::remove_file(&vault_path)
                .map_err(|e| SecretshError::Io(crate::error::IoError(e)))?;
        } else {
            // Refuse to overwrite without --force.
            return Err(SecretshError::Io(crate::error::IoError(
                std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!(
                        "vault already exists at {} — use --force to overwrite",
                        vault_path.display()
                    ),
                ),
            )));
        }
    }

    let config = VaultConfig {
        vault_path: vault_path.clone(),
        master_key_env: args.master_key_env.clone(),
        allow_insecure_permissions: false,
        kdf_memory: Some(args.kdf_memory),
    };

    if args.no_passphrase_check {
        Vault::init_no_passphrase_check(&config)?;
    } else {
        Vault::init(&config)?;
    }

    eprintln!("secretsh: vault initialised at {}", vault_path.display());
    Ok(())
}

// ── set ───────────────────────────────────────────────────────────────────────

/// Handle `secretsh set <KEY_NAME>`.
///
/// Reads the secret value from stdin (stripping a single trailing newline),
/// stores it in the vault, and emits an audit entry.
pub fn run_set(args: &SetArgs) -> Result<(), SecretshError> {
    let config = args.vault.to_vault_config();
    let mut vault = Vault::open(&config)?;

    // Read secret value from stdin.
    // We read the raw bytes so that binary secrets are supported.
    // A single trailing newline is stripped because shells (and `echo`)
    // typically append one.
    let value: Zeroizing<Vec<u8>> = {
        let stdin = io::stdin();
        let mut buf = Vec::new();
        stdin
            .lock()
            .read_to_end(&mut buf)
            .map_err(|e| SecretshError::Io(crate::error::IoError(e)))?;
        if buf.ends_with(b"\n") {
            buf.pop();
        }
        Zeroizing::new(buf)
    };

    vault.set(&args.key_name, &value)?;

    let key_count = vault.list_keys().len();
    emit_audit("set", key_count, &json!({}));

    Ok(())
}

// ── delete ────────────────────────────────────────────────────────────────────

/// Handle `secretsh delete <KEY_NAME>`.
///
/// Removes the named entry from the vault and emits an audit entry.
pub fn run_delete(args: &DeleteArgs) -> Result<(), SecretshError> {
    let config = args.vault.to_vault_config();
    let mut vault = Vault::open(&config)?;

    let removed = vault.delete(&args.key_name)?;

    if !removed {
        eprintln!(
            "secretsh: key {:?} not found in vault — nothing to delete",
            args.key_name
        );
    }

    let key_count = vault.list_keys().len();
    emit_audit("delete", key_count, &json!({ "removed": removed }));

    Ok(())
}

// ── list ──────────────────────────────────────────────────────────────────────

/// Handle `secretsh list`.
///
/// Prints one key name per line to stdout.
pub fn run_list(args: &ListArgs) -> Result<(), SecretshError> {
    let config = args.vault.to_vault_config();
    let vault = Vault::open(&config)?;

    let keys = vault.list_keys();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for key in &keys {
        writeln!(out, "{key}").map_err(|e| SecretshError::Io(crate::error::IoError(e)))?;
    }

    Ok(())
}

// ── run ───────────────────────────────────────────────────────────────────────

/// Handle `secretsh run`.
///
/// Full pipeline:
/// 1. Open vault.
/// 2. Join the command parts into a single string and tokenize it.
/// 3. Resolve all `{{KEY}}` placeholders against the vault.
/// 4. Build the resolved argv as `Vec<Zeroizing<Vec<u8>>>` (null-terminated).
/// 5. Build a [`Redactor`] from all vault secrets.
/// 6. Spawn the child via [`spawn_child`].
/// 7. Print stdout/stderr, emit audit, exit with the child's exit code.
///
/// Returns the child's exit code (or a secretsh error code) so that `main`
/// can call `std::process::exit`.
pub fn run_run(args: &RunArgs) -> Result<i32, SecretshError> {
    let config = args.vault.to_vault_config();
    let vault = Vault::open(&config)?;

    // Join the command parts into a single string.
    // clap collects everything after `--` into `args.command`.
    let command_str = args.command.join(" ");

    if args.verbose {
        eprintln!("[secretsh] tokenizing command: {command_str:?}");
    }

    // Tokenize.
    let token_result = tokenize(&command_str)?;

    if args.verbose {
        eprintln!("[secretsh] tokens: {:?}", token_result.tokens);
    }

    // Resolve placeholders and build the argv.
    //
    // Each token's value may contain zero or more `{{KEY}}` placeholders.
    // We perform in-place substitution working from right to left (so that
    // byte offsets remain valid as we splice bytes in).
    let mut argv: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(token_result.tokens.len());

    for token in &token_result.tokens {
        // Start with the raw token value as bytes.
        let mut resolved: Vec<u8> = token.value.as_bytes().to_vec();

        // Apply substitutions right-to-left so earlier offsets stay valid.
        for placeholder in token.placeholders.iter().rev() {
            let secret = vault.resolve_placeholder(&placeholder.key).ok_or_else(|| {
                crate::error::PlaceholderError::UnresolvedKey {
                    key: placeholder.key.clone(),
                }
            })?;

            // Replace bytes[start..end] with the secret value.
            let mut new_resolved = Vec::with_capacity(
                resolved.len() - (placeholder.end - placeholder.start) + secret.len(),
            );
            new_resolved.extend_from_slice(&resolved[..placeholder.start]);
            new_resolved.extend_from_slice(secret);
            new_resolved.extend_from_slice(&resolved[placeholder.end..]);
            resolved = new_resolved;
        }

        // Append null terminator (required by spawn_child / posix_spawnp).
        resolved.push(0u8);
        argv.push(Zeroizing::new(resolved));
    }

    // Build the Redactor from all vault secrets.
    let secrets: Vec<(&str, &[u8])> = vault.all_secret_values();
    let redactor = Redactor::new(&secrets)?;

    // Compute audit hashes before argv is moved into spawn_child.
    let cmd_resolved_hash = {
        let mut combined: Vec<u8> = Vec::new();
        for arg in &argv {
            let without_nul = &arg[..arg.len().saturating_sub(1)];
            combined.extend_from_slice(without_nul);
            combined.push(0u8);
        }
        let h = digest(&SHA256, &combined);
        format!("sha256:{}", hex::encode(h.as_ref()))
    };

    // Build SpawnConfig from CLI args.
    let spawn_config = SpawnConfig {
        timeout_secs: args.timeout,
        max_output_bytes: args.max_output,
        max_stderr_bytes: args.max_stderr,
    };

    // Spawn the child.
    let result = spawn_child(argv, &redactor, &spawn_config)?;

    // Print stdout to stdout, stderr to stderr.
    {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        out.write_all(result.stdout.as_bytes())
            .map_err(|e| SecretshError::Io(crate::error::IoError(e)))?;
    }
    {
        let stderr = io::stderr();
        let mut err = stderr.lock();
        err.write_all(result.stderr.as_bytes())
            .map_err(|e| SecretshError::Io(crate::error::IoError(e)))?;
    }

    // Emit audit log (unless --quiet).
    if !args.quiet {
        let key_count = vault.list_keys().len();

        let cmd_template_hash = {
            let h = digest(&SHA256, command_str.as_bytes());
            format!("sha256:{}", hex::encode(h.as_ref()))
        };

        emit_audit(
            "run",
            key_count,
            &json!({
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "cmd_template_hash": cmd_template_hash,
                "cmd_resolved_hash": cmd_resolved_hash,
            }),
        );
    }

    Ok(result.exit_code)
}

// ── export ────────────────────────────────────────────────────────────────────

/// Handle `secretsh export`.
///
/// Decrypts the current vault and writes an encrypted backup to the output
/// path using a fresh salt and nonces.
pub fn run_export(args: &ExportArgs) -> Result<(), SecretshError> {
    let config = args.vault.to_vault_config();
    let vault = Vault::open(&config)?;

    vault.export(&args.out)?;

    let key_count = vault.list_keys().len();
    emit_audit("export", key_count, &json!({}));

    eprintln!("secretsh: vault exported to {}", args.out.display());
    Ok(())
}

// ── import ────────────────────────────────────────────────────────────────────

/// Handle `secretsh import`.
///
/// Merges entries from an encrypted export file into the current vault.
/// Existing entries are skipped unless `--overwrite` is given.
pub fn run_import(args: &ImportArgs) -> Result<(), SecretshError> {
    let config = args.vault.to_vault_config();
    let mut vault = Vault::open(&config)?;

    let (added, skipped, replaced) =
        vault.import(&args.input, args.import_key_env.as_deref(), args.overwrite)?;

    let key_count = vault.list_keys().len();
    emit_audit(
        "import",
        key_count,
        &json!({
            "added": added,
            "skipped": skipped,
            "replaced": replaced,
        }),
    );

    eprintln!(
        "secretsh: imported {} entries ({} skipped, {} replaced) from {}",
        added,
        skipped,
        replaced,
        args.input.display()
    );
    Ok(())
}

// ── import-env ───────────────────────────────────────────────────────────────

/// Handle `secretsh import-env`.
///
/// Parses a `.env` file and stores each key-value pair in the vault.
/// Existing entries are skipped unless `--overwrite` is given.
pub fn run_import_env(args: &ImportEnvArgs) -> Result<(), SecretshError> {
    let config = args.vault.to_vault_config();
    let mut vault = Vault::open(&config)?;

    let entries = parse_dotenv(&args.file)?;

    if entries.is_empty() {
        eprintln!("secretsh: no entries found in {}", args.file.display());
        return Ok(());
    }

    let existing_keys: std::collections::HashSet<String> = vault.list_keys().into_iter().collect();

    let mut added: usize = 0;
    let mut skipped: usize = 0;
    let mut replaced: usize = 0;

    for entry in &entries {
        let exists = existing_keys.contains(&entry.key);

        if exists && !args.overwrite {
            eprintln!(
                "secretsh: skipping {:?} (already exists, use --overwrite)",
                entry.key
            );
            skipped += 1;
            continue;
        }

        vault.set(&entry.key, &entry.value)?;

        if exists {
            replaced += 1;
        } else {
            added += 1;
        }
    }

    let key_count = vault.list_keys().len();
    emit_audit(
        "import-env",
        key_count,
        &json!({
            "added": added,
            "skipped": skipped,
            "replaced": replaced,
            "source": args.file.display().to_string(),
        }),
    );

    eprintln!(
        "secretsh: imported {} entries ({} skipped, {} replaced) from {}",
        added,
        skipped,
        replaced,
        args.file.display()
    );
    Ok(())
}
