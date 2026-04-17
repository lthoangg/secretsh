//! CLI definition and subcommand handlers for secretsh.

use std::io::{self, Write};
use std::path::PathBuf;

use clap::Parser;
use ring::digest::{digest, SHA256};
use serde_json::json;
use zeroize::Zeroizing;

use crate::dotenv::parse_dotenv;
use crate::error::{SecretshError, SpawnError};
use crate::redact::Redactor;
use crate::spawn::{spawn_child, SpawnConfig};
use crate::tokenizer::tokenize;

/// secretsh — inject secrets from a .env file into subprocess arguments.
#[derive(Parser, Debug)]
#[command(
    name = "secretsh",
    version,
    about = "Inject secrets from a .env file into subprocess arguments",
    long_about = None,
)]
pub struct Cli {
    /// Path to the .env file.
    #[arg(long, value_name = "PATH", required = true)]
    pub env: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Run(RunArgs),
}

#[derive(clap::Args, Debug)]
pub struct RunArgs {
    /// Maximum wall-clock seconds the child may run before being killed (default 300).
    #[arg(long, value_name = "SECONDS", default_value_t = 300)]
    pub timeout: u64,

    /// Maximum bytes accepted from the child's stdout before it is killed (default 52428800 = 50 MiB).
    #[arg(long, value_name = "BYTES", default_value_t = 52_428_800)]
    pub max_output: usize,

    /// Maximum bytes accepted from the child's stderr before it is killed (default 1048576 = 1 MiB).
    #[arg(long, value_name = "BYTES", default_value_t = 1_048_576)]
    pub max_stderr: usize,

    /// Suppress audit output.
    #[arg(long)]
    pub quiet: bool,

    /// Enable verbose/debug output.
    #[arg(long)]
    pub verbose: bool,

    /// Reject shell interpreters (sh, bash, zsh, dash, fish, ksh, tcsh) as the command binary.
    ///
    /// Recommended for all AI-agent contexts.
    #[arg(long)]
    pub no_shell: bool,

    /// The command string to execute (with `{{KEY}}` placeholders).
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

fn emit_audit(op: &str, key_count: usize, extra: &serde_json::Value) {
    let ts = chrono::Utc::now().to_rfc3339();
    let mut entry = json!({
        "ts": ts,
        "op": op,
        "key_count": key_count,
    });
    if let (Some(obj), Some(extra_obj)) = (entry.as_object_mut(), extra.as_object()) {
        for (k, v) in extra_obj {
            obj.insert(k.clone(), v.clone());
        }
    }
    let _ = writeln!(io::stderr(), "{}", entry);
}

pub fn run(cli: &Cli) -> Result<i32, SecretshError> {
    let env_path = &cli.env;
    let entries = parse_dotenv(env_path)?;
    let mut secret_map = std::collections::HashMap::with_capacity(entries.len());
    for entry in entries {
        secret_map.insert(entry.key, entry.value);
    }

    let Command::Run(args) = &cli.command;

    let command_str = args.command.join(" ");

    if args.verbose {
        eprintln!("[secretsh] tokenizing command: {command_str:?}");
    }

    let token_result = tokenize(&command_str)?;

    if args.verbose {
        eprintln!("[secretsh] tokens: {:?}", token_result.tokens);
    }
    let mut argv: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(token_result.tokens.len());

    for token in &token_result.tokens {
        let mut resolved: Vec<u8> = token.value.as_bytes().to_vec();
        for placeholder in token.placeholders.iter().rev() {
            let secret = secret_map.get(&placeholder.key).ok_or_else(|| {
                crate::error::PlaceholderError::UnresolvedKey {
                    key: placeholder.key.clone(),
                }
            })?;
            let mut new_resolved = Vec::with_capacity(
                resolved.len() - (placeholder.end - placeholder.start) + secret.len(),
            );
            new_resolved.extend_from_slice(&resolved[..placeholder.start]);
            new_resolved.extend_from_slice(secret.as_slice());
            new_resolved.extend_from_slice(&resolved[placeholder.end..]);
            resolved = new_resolved;
        }
        resolved.push(0u8);
        argv.push(Zeroizing::new(resolved));
    }

    if args.no_shell {
        const BLOCKED_SHELLS: &[&str] = &[
            "sh", "bash", "zsh", "dash", "fish", "ksh", "ksh93", "mksh", "tcsh", "csh",
        ];
        let argv0_raw = argv[0].as_slice();
        let argv0_without_nul = argv0_raw.strip_suffix(b"\0").unwrap_or(argv0_raw);
        let argv0_str = String::from_utf8_lossy(argv0_without_nul);
        let basename = argv0_str.rsplit('/').next().unwrap_or(&argv0_str);
        if BLOCKED_SHELLS.contains(&basename) {
            return Err(SecretshError::Spawn(SpawnError::ShellDelegationBlocked {
                shell: basename.to_owned(),
            }));
        }
    }

    let secrets: Vec<(&str, &[u8])> = secret_map
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_slice()))
        .collect();
    let redactor = Redactor::new(&secrets)?;

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

    let spawn_config = SpawnConfig {
        timeout_secs: args.timeout,
        max_output_bytes: args.max_output,
        max_stderr_bytes: args.max_stderr,
    };

    let result = spawn_child(argv, &redactor, &spawn_config)?;

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

    if !args.quiet {
        let key_count = secret_map.len();
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
                "env_file": env_path.display().to_string(),
            }),
        );
    }

    Ok(result.exit_code)
}
