//! PyO3 Python bindings for secretsh.
//!
//! Exposes the vault, tokenizer, redactor, and spawn pipeline as a native
//! Python extension module named `_native` (imported as `secretsh._native`).
//!
//! # Feature gate
//!
//! This entire module is compiled only when the `python` Cargo feature is
//! enabled (i.e. `cargo build --features python` or via maturin).
//!
//! # Exception hierarchy
//!
//! ```text
//! SecretSHError (base, inherits from Exception)
//! ├── VaultNotFoundError
//! ├── VaultCorruptError
//! ├── VaultPermissionError
//! ├── DecryptionError
//! ├── MasterKeyError
//! ├── PlaceholderError
//! ├── TokenizationError
//! ├── CommandError
//! ├── EntryLimitError
//! └── LockError
//! ```

#![cfg(feature = "python")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{
    MasterKeyError as RustMasterKeyError, PlaceholderError as RustPlaceholderError, SecretshError,
    SpawnError, VaultError,
};
use crate::harden::harden_process;
use crate::redact::Redactor;
use crate::spawn::{spawn_child, SpawnConfig};
use crate::tokenizer::tokenize;
use crate::vault::{Vault, VaultConfig};

// ─────────────────────────────────────────────────────────────────────────────
// One-time harden guard
// ─────────────────────────────────────────────────────────────────────────────

/// Ensures `harden_process()` is called at most once across the lifetime of
/// the extension module, regardless of how many `Vault` objects are created.
static HARDENED: AtomicBool = AtomicBool::new(false);

fn ensure_hardened() {
    // Relaxed ordering is sufficient: we only need the bool to flip once.
    // A race where two threads both see `false` and both call `harden_process`
    // is harmless — the function is idempotent (it just calls `setrlimit`).
    if !HARDENED.swap(true, Ordering::Relaxed) {
        harden_process();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Exception hierarchy
// ─────────────────────────────────────────────────────────────────────────────

// Base exception — all secretsh errors inherit from this.
pyo3::create_exception!(
    _native,
    SecretSHError,
    PyException,
    "Base exception for all secretsh errors."
);

// Vault file not found.
pyo3::create_exception!(
    _native,
    VaultNotFoundError,
    SecretSHError,
    "The vault file does not exist. Run `secretsh init` to create one."
);

// Vault integrity / format errors (HMAC mismatch, bad magic, truncated, etc.).
pyo3::create_exception!(
    _native,
    VaultCorruptError,
    SecretSHError,
    "The vault file is corrupt or has been tampered with."
);

// Vault has insecure file permissions.
pyo3::create_exception!(
    _native,
    VaultPermissionError,
    SecretSHError,
    "The vault file has insecure permissions."
);

// Wrong passphrase / decryption failure.
pyo3::create_exception!(
    _native,
    DecryptionError,
    SecretSHError,
    "Decryption failed — the master passphrase is incorrect or the vault is corrupt."
);

// Master key / environment variable problems.
pyo3::create_exception!(
    _native,
    MasterKeyError,
    SecretSHError,
    "Master key error — the passphrase environment variable is not set or the passphrase is too short."
);

// Unresolved `{{KEY}}` placeholder.
pyo3::create_exception!(
    _native,
    PlaceholderError,
    SecretSHError,
    "A placeholder could not be resolved against the vault."
);

// Command-string tokenization errors.
pyo3::create_exception!(
    _native,
    TokenizationError,
    SecretSHError,
    "The command string was rejected by the tokenizer."
);

// Child process errors (not found, not executable, fork/exec failed, timeout, output limit).
pyo3::create_exception!(
    _native,
    CommandError,
    SecretSHError,
    "The child process could not be spawned or was killed by a resource limit."
);

// Vault entry limit exceeded (10,000 entries).
pyo3::create_exception!(
    _native,
    EntryLimitError,
    SecretSHError,
    "The vault entry limit (10,000) has been reached."
);

// Advisory lock timeout or stale lock.
pyo3::create_exception!(
    _native,
    LockError,
    SecretSHError,
    "Could not acquire the vault lock."
);

// ─────────────────────────────────────────────────────────────────────────────
// Error mapping: SecretshError → PyErr
// ─────────────────────────────────────────────────────────────────────────────

/// Convert a Rust [`SecretshError`] into the appropriate Python exception.
///
/// The mapping preserves the full `Display` message of the original error so
/// that Python callers receive actionable diagnostic text.
fn to_py_err(e: SecretshError) -> PyErr {
    let msg = e.to_string();
    match &e {
        // ── Vault errors ──────────────────────────────────────────────────────
        SecretshError::Vault(ve) => match ve {
            VaultError::NotFound { .. } => VaultNotFoundError::new_err(msg),

            // Integrity / format corruption
            VaultError::HmacMismatch
            | VaultError::CommitTagMismatch
            | VaultError::GcmMismatch { .. }
            | VaultError::AadMismatch { .. }
            | VaultError::BadMagic { .. }
            | VaultError::Truncated { .. }
            | VaultError::VersionTooNew { .. }
            | VaultError::VersionInvalid { .. } => VaultCorruptError::new_err(msg),

            VaultError::InsecurePermissions { .. } => VaultPermissionError::new_err(msg),

            VaultError::WrongPassphrase => DecryptionError::new_err(msg),

            VaultError::EntryLimitExceeded { .. } => EntryLimitError::new_err(msg),

            VaultError::LockTimeout { .. } | VaultError::StaleLock { .. } => {
                LockError::new_err(msg)
            }
        },

        // ── Master key errors ─────────────────────────────────────────────────
        SecretshError::MasterKey(mke) => match mke {
            RustMasterKeyError::EnvVarNotSet { .. }
            | RustMasterKeyError::PassphraseTooShort { .. } => MasterKeyError::new_err(msg),
        },

        // ── Placeholder errors ────────────────────────────────────────────────
        SecretshError::Placeholder(RustPlaceholderError::UnresolvedKey { .. }) => {
            PlaceholderError::new_err(msg)
        }

        // ── Tokenization errors ───────────────────────────────────────────────
        SecretshError::Tokenization(_) => TokenizationError::new_err(msg),

        // ── Spawn errors ──────────────────────────────────────────────────────
        SecretshError::Spawn(se) => match se {
            SpawnError::NotFound { .. }
            | SpawnError::NotExecutable { .. }
            | SpawnError::ForkExecFailed { .. }
            | SpawnError::Timeout { .. }
            | SpawnError::OutputLimitExceeded { .. } => CommandError::new_err(msg),
        },

        // ── Config / Redaction / I/O errors ──────────────────────────────────
        SecretshError::Config(_) | SecretshError::Redaction(_) | SecretshError::Io(_) => {
            SecretSHError::new_err(msg)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RunResult — returned by Vault.run()
// ─────────────────────────────────────────────────────────────────────────────

/// The result of running a command through the vault pipeline.
///
/// All output has been passed through the redactor — no raw secret values
/// will appear in `stdout` or `stderr`.
#[pyclass(name = "RunResult")]
pub struct PyRunResult {
    /// Redacted stdout (UTF-8 lossy decoded).
    #[pyo3(get)]
    pub stdout: String,

    /// Redacted stderr (UTF-8 lossy decoded).
    #[pyo3(get)]
    pub stderr: String,

    /// The child process exit code (0–255), or 124 on timeout/output-limit,
    /// or 128+N when killed by signal N.
    #[pyo3(get)]
    pub exit_code: i32,

    /// `True` when the child was killed because it exceeded `timeout_secs`.
    #[pyo3(get)]
    pub timed_out: bool,
}

#[pymethods]
impl PyRunResult {
    fn __repr__(&self) -> String {
        format!(
            "RunResult(exit_code={}, timed_out={}, stdout={:?}, stderr={:?})",
            self.exit_code,
            if self.timed_out { "True" } else { "False" },
            // Truncate long output in repr for readability.
            if self.stdout.len() > 120 {
                format!("{}…", &self.stdout[..120])
            } else {
                self.stdout.clone()
            },
            if self.stderr.len() > 120 {
                format!("{}…", &self.stderr[..120])
            } else {
                self.stderr.clone()
            },
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Vault Python class
// ─────────────────────────────────────────────────────────────────────────────

/// An open, decrypted secretsh vault.
///
/// Use as a context manager to ensure the vault is closed (and all in-memory
/// secret data is zeroized) when you are done:
///
/// ```python
/// with secretsh.Vault(master_key_env="SECRETSH_KEY") as v:
///     result = v.run("echo {{MY_SECRET}}")
///     print(result.stdout)
/// ```
///
/// The Python API does not expose `init` — use the `secretsh init` CLI command
/// to create a new vault before using this class.
#[pyclass(name = "Vault")]
pub struct PyVault {
    /// The inner Rust vault, wrapped in `Option` so that `close()` can take it.
    ///
    /// `Mutex` provides interior mutability across `&self` pymethods and
    /// satisfies PyO3's `Send` requirement for pyclass types.
    inner: Mutex<Option<Vault>>,

    /// Set to `true` after `close()` is called so that subsequent calls are
    /// no-ops.
    closed: AtomicBool,
}

#[pymethods]
impl PyVault {
    // ── __init__ ──────────────────────────────────────────────────────────────

    /// Open an existing vault.
    ///
    /// Parameters
    /// ----------
    /// master_key_env : str
    ///     Name of the environment variable that holds the master passphrase.
    /// vault_path : str | None
    ///     Path to the vault file.  Defaults to
    ///     `~/.local/share/secretsh/vault.bin` when `None`.
    /// allow_insecure_permissions : bool
    ///     If `True`, skip the group/world-readable permission check.
    ///
    /// Raises
    /// ------
    /// VaultNotFoundError
    ///     If the vault file does not exist.
    /// VaultCorruptError
    ///     If the vault file is corrupt or has been tampered with.
    /// VaultPermissionError
    ///     If the vault file has insecure permissions.
    /// DecryptionError
    ///     If the master passphrase is incorrect.
    /// MasterKeyError
    ///     If the passphrase environment variable is not set.
    #[new]
    #[pyo3(signature = (master_key_env, vault_path = None, allow_insecure_permissions = false))]
    fn new(
        py: Python<'_>,
        master_key_env: String,
        vault_path: Option<String>,
        allow_insecure_permissions: bool,
    ) -> PyResult<Self> {
        // Apply OS-level hardening exactly once per process.
        ensure_hardened();

        // Resolve the vault path: use the provided path or fall back to the
        // XDG-compliant default `~/.local/share/secretsh/vault.bin`.
        let resolved_path = match vault_path {
            Some(p) => std::path::PathBuf::from(p),
            None => {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_owned());
                std::path::PathBuf::from(home)
                    .join(".local")
                    .join("share")
                    .join("secretsh")
                    .join("vault.bin")
            }
        };

        let config = VaultConfig {
            vault_path: resolved_path,
            master_key_env,
            allow_insecure_permissions,
            kdf_memory: None, // use production default (128 MiB)
        };

        // Release the GIL while performing the potentially-slow Argon2id KDF.
        let vault = py
            .allow_threads(|| Vault::open(&config))
            .map_err(to_py_err)?;

        Ok(PyVault {
            inner: Mutex::new(Some(vault)),
            closed: AtomicBool::new(false),
        })
    }

    // ── set ───────────────────────────────────────────────────────────────────

    /// Insert or update a secret entry.
    ///
    /// Parameters
    /// ----------
    /// key : str
    ///     The secret key name (must match ``[A-Za-z_][A-Za-z0-9_]*``).
    /// value : str | bytes | bytearray
    ///     The secret value.  If a `bytearray` is passed, its contents are
    ///     copied into Rust-managed memory and the source bytearray is zeroed
    ///     before this method returns.
    ///
    /// Raises
    /// ------
    /// SecretSHError
    ///     If the vault is closed.
    /// EntryLimitError
    ///     If the vault already contains 10,000 entries.
    /// TokenizationError
    ///     If the key name contains invalid characters.
    fn set(&self, py: Python<'_>, key: String, value: &Bound<'_, PyAny>) -> PyResult<()> {
        self.check_open()?;

        // Accept str, bytes, or bytearray.
        // Check bytearray FIRST — `extract::<Vec<u8>>()` also matches bytearray
        // but would not zero the source buffer.
        let secret_bytes: Zeroizing<Vec<u8>> =
            if let Ok(ba) = value.downcast::<pyo3::types::PyByteArray>() {
                // `bytearray` — copy the data, then zero the source buffer.
                let data = Zeroizing::new(ba.to_vec());
                // SAFETY: We hold the GIL; no other thread can resize the bytearray.
                // Zero the source bytearray in-place so the secret is not left in
                // Python-managed memory.
                unsafe {
                    ba.as_bytes_mut().zeroize();
                }
                data
            } else if let Ok(s) = value.extract::<String>() {
                Zeroizing::new(s.into_bytes())
            } else if let Ok(b) = value.extract::<Vec<u8>>() {
                // `bytes` — immutable, just copy.
                Zeroizing::new(b)
            } else {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "value must be str, bytes, or bytearray",
                ));
            };

        // Release the GIL while performing the Argon2id KDF + disk write.
        py.allow_threads(|| {
            let mut guard = self.inner.lock().unwrap();
            let vault = guard
                .as_mut()
                .ok_or_else(|| SecretSHError::new_err("vault is closed"))?;
            vault.set(&key, &secret_bytes).map_err(to_py_err)
        })
    }

    // ── delete ────────────────────────────────────────────────────────────────

    /// Remove a secret entry by key name.
    ///
    /// Returns
    /// -------
    /// bool
    ///     `True` if the entry existed and was removed, `False` if not found.
    ///
    /// Raises
    /// ------
    /// SecretSHError
    ///     If the vault is closed.
    fn delete(&self, py: Python<'_>, key: String) -> PyResult<bool> {
        self.check_open()?;

        py.allow_threads(|| {
            let mut guard = self.inner.lock().unwrap();
            let vault = guard
                .as_mut()
                .ok_or_else(|| SecretSHError::new_err("vault is closed"))?;
            vault.delete(&key).map_err(to_py_err)
        })
    }

    // ── list_keys ─────────────────────────────────────────────────────────────

    /// Return all key names stored in the vault.
    ///
    /// Secret values are never exposed — only the key names are returned.
    ///
    /// Returns
    /// -------
    /// list[str]
    ///
    /// Raises
    /// ------
    /// SecretSHError
    ///     If the vault is closed.
    fn list_keys(&self) -> PyResult<Vec<String>> {
        self.check_open()?;

        // list_keys is fast (in-memory) — no GIL release needed.
        let guard = self.inner.lock().unwrap();
        let vault = guard
            .as_ref()
            .ok_or_else(|| SecretSHError::new_err("vault is closed"))?;
        Ok(vault.list_keys())
    }

    // ── run ───────────────────────────────────────────────────────────────────

    /// Run a command with secrets injected from the vault.
    ///
    /// The full pipeline is:
    ///
    /// 1. Tokenize ``command`` using the secretsh POSIX-subset tokenizer.
    /// 2. Resolve every ``{{KEY_NAME}}`` placeholder against the vault.
    /// 3. Build a redaction automaton from all vault secrets.
    /// 4. Spawn the child process via ``posix_spawnp``.
    /// 5. Return a :class:`RunResult` with redacted stdout/stderr.
    ///
    /// Parameters
    /// ----------
    /// command : str
    ///     The command string to execute.  Shell metacharacters (``|``, ``>``,
    ///     ``&``, ``;``, etc.) are rejected unless quoted.
    /// timeout_secs : int
    ///     Maximum wall-clock seconds the child may run.  Default: 300.
    /// max_output_bytes : int
    ///     Maximum stdout bytes before the child is killed.  Default: 50 MiB.
    /// max_stderr_bytes : int
    ///     Maximum stderr bytes before the child is killed.  Default: 1 MiB.
    ///
    /// Returns
    /// -------
    /// RunResult
    ///
    /// Raises
    /// ------
    /// TokenizationError
    ///     If the command string contains rejected metacharacters or malformed
    ///     placeholders.
    /// PlaceholderError
    ///     If a ``{{KEY}}`` placeholder references a key not in the vault.
    /// CommandError
    ///     If the command binary is not found, not executable, or the child
    ///     exceeds the timeout or output limit.
    /// SecretSHError
    ///     If the vault is closed or an internal error occurs.
    #[pyo3(signature = (command, timeout_secs = 300, max_output_bytes = 52428800, max_stderr_bytes = 1048576))]
    fn run(
        &self,
        py: Python<'_>,
        command: String,
        timeout_secs: u64,
        max_output_bytes: usize,
        max_stderr_bytes: usize,
    ) -> PyResult<PyRunResult> {
        self.check_open()?;

        // Snapshot the secrets we need while holding the GIL, then release it
        // for the heavy work (tokenize → resolve → spawn → redact).
        //
        // We collect all secret values as owned `Zeroizing<Vec<u8>>` so that
        // the vault lock is not held across the blocking spawn call.
        type ArgvVec = Vec<Zeroizing<Vec<u8>>>;
        type SecretsVec = Vec<(String, Vec<u8>)>;
        let (resolved_argv, all_secrets): (ArgvVec, SecretsVec) = {
            let guard = self.inner.lock().unwrap();
            let vault = guard
                .as_ref()
                .ok_or_else(|| SecretSHError::new_err("vault is closed"))?;

            // ── Step 1: Tokenize ──────────────────────────────────────────────
            let tokenize_result = tokenize(&command).map_err(to_py_err)?;

            // ── Step 2: Resolve placeholders ──────────────────────────────────
            //
            // For each token, replace every `{{KEY}}` span with the vault value.
            // We build the final argv as null-terminated `Zeroizing<Vec<u8>>`
            // elements, as required by `spawn_child`.
            let mut argv: Vec<Zeroizing<Vec<u8>>> =
                Vec::with_capacity(tokenize_result.tokens.len());

            for token in &tokenize_result.tokens {
                if token.placeholders.is_empty() {
                    // Fast path: no placeholders — use the token value directly.
                    let mut bytes = token.value.as_bytes().to_vec();
                    bytes.push(0); // null terminator
                    argv.push(Zeroizing::new(bytes));
                } else {
                    // Build the argv element at the byte level in a single
                    // left-to-right pass.  Placeholders are already sorted by
                    // ascending start offset by the tokenizer.
                    let token_bytes = token.value.as_bytes();
                    let mut out_bytes: Vec<u8> = Vec::new();
                    let mut cursor = 0usize;

                    for ph in &token.placeholders {
                        // Append the literal bytes before this placeholder.
                        out_bytes.extend_from_slice(&token_bytes[cursor..ph.start]);

                        // Resolve the placeholder key against the vault.
                        let secret = vault.resolve_placeholder(&ph.key).ok_or_else(|| {
                            to_py_err(SecretshError::Placeholder(
                                RustPlaceholderError::UnresolvedKey {
                                    key: ph.key.clone(),
                                },
                            ))
                        })?;

                        // Append the raw secret bytes (may be arbitrary binary).
                        out_bytes.extend_from_slice(secret);
                        cursor = ph.end;
                    }

                    // Append any trailing literal bytes after the last placeholder.
                    out_bytes.extend_from_slice(&token_bytes[cursor..]);
                    // Null-terminate as required by `spawn_child`.
                    out_bytes.push(0);

                    argv.push(Zeroizing::new(out_bytes));
                }
            }

            // ── Step 3: Collect all secrets for the redactor ──────────────────
            let secrets: Vec<(String, Vec<u8>)> = vault
                .all_secret_values()
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_vec()))
                .collect();

            (argv, secrets)
        };
        // The vault lock is released here.

        // ── Steps 4–5: Spawn + redact (GIL released) ─────────────────────────
        let spawn_result = py.allow_threads(|| {
            // Build the redactor from the collected secrets.
            let secret_refs: Vec<(&str, &[u8])> = all_secrets
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_slice()))
                .collect();

            let redactor = Redactor::new(&secret_refs).map_err(to_py_err)?;

            let config = SpawnConfig {
                timeout_secs,
                max_output_bytes,
                max_stderr_bytes,
            };

            spawn_child(resolved_argv, &redactor, &config).map_err(to_py_err)
        })?;

        Ok(PyRunResult {
            stdout: spawn_result.stdout,
            stderr: spawn_result.stderr,
            exit_code: spawn_result.exit_code,
            timed_out: spawn_result.timed_out,
        })
    }

    // ── export ─────────────────────────────────────────────────────────────────

    /// Export the vault to an encrypted backup file.
    ///
    /// The export is re-encrypted with a fresh salt and nonces using the same
    /// master passphrase.
    ///
    /// Parameters
    /// ----------
    /// out_path : str
    ///     Path to write the encrypted export file.
    ///
    /// Raises
    /// ------
    /// SecretSHError
    ///     If the vault is closed or the export fails.
    fn export(&self, py: Python<'_>, out_path: String) -> PyResult<()> {
        self.check_open()?;

        py.allow_threads(|| {
            let guard = self.inner.lock().unwrap();
            let vault = guard
                .as_ref()
                .ok_or_else(|| SecretSHError::new_err("vault is closed"))?;
            vault
                .export(std::path::Path::new(&out_path))
                .map_err(to_py_err)
        })
    }

    // ── import ─────────────────────────────────────────────────────────────────

    /// Import entries from an encrypted export file.
    ///
    /// Parameters
    /// ----------
    /// import_path : str
    ///     Path to the encrypted vault file to import from.
    /// overwrite : bool
    ///     If `True`, replace existing entries with imported values.
    ///     If `False` (default), skip entries whose key names already exist.
    /// import_key_env : str | None
    ///     Name of the env var holding the import file's passphrase.
    ///     If `None`, the current vault's passphrase is used.
    ///
    /// Returns
    /// -------
    /// tuple[int, int, int]
    ///     ``(added, skipped, replaced)`` counts.
    ///
    /// Raises
    /// ------
    /// SecretSHError
    ///     If the vault is closed or the import fails.
    #[pyo3(signature = (import_path, overwrite = false, import_key_env = None), name = "import_vault")]
    fn import_vault(
        &self,
        py: Python<'_>,
        import_path: String,
        overwrite: bool,
        import_key_env: Option<String>,
    ) -> PyResult<(usize, usize, usize)> {
        self.check_open()?;

        py.allow_threads(|| {
            let mut guard = self.inner.lock().unwrap();
            let vault = guard
                .as_mut()
                .ok_or_else(|| SecretSHError::new_err("vault is closed"))?;
            vault
                .import(
                    std::path::Path::new(&import_path),
                    import_key_env.as_deref(),
                    overwrite,
                )
                .map_err(to_py_err)
        })
    }

    // ── close ─────────────────────────────────────────────────────────────────

    /// Zeroize all in-memory secret data and release the vault.
    ///
    /// Safe to call multiple times — subsequent calls are no-ops.
    fn close(&self) {
        // Use `swap` so that only the first caller actually closes the vault.
        if !self.closed.swap(true, Ordering::Relaxed) {
            let mut guard = self.inner.lock().unwrap();
            if let Some(mut vault) = guard.take() {
                vault.close();
            }
        }
    }

    // ── Context manager ───────────────────────────────────────────────────────

    /// Enter the context manager — returns `self`.
    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Exit the context manager — calls `close()`.
    fn __exit__(
        &self,
        _exc_type: &Bound<'_, PyAny>,
        _exc_val: &Bound<'_, PyAny>,
        _exc_tb: &Bound<'_, PyAny>,
    ) {
        self.close();
    }

    // ── __del__ ───────────────────────────────────────────────────────────────

    /// Best-effort cleanup when the object is garbage-collected.
    fn __del__(&self) {
        self.close();
    }
}

impl PyVault {
    /// Return an error if the vault has been closed.
    fn check_open(&self) -> PyResult<()> {
        if self.closed.load(Ordering::Relaxed) {
            Err(SecretSHError::new_err("vault is closed"))
        } else {
            Ok(())
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Module registration
// ─────────────────────────────────────────────────────────────────────────────

/// Native extension module for secretsh.
///
/// Import as ``secretsh._native`` (re-exported by ``secretsh.__init__``).
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // ── Classes ───────────────────────────────────────────────────────────────
    m.add_class::<PyVault>()?;
    m.add_class::<PyRunResult>()?;

    // ── Exception hierarchy ───────────────────────────────────────────────────
    //
    // The base exception must be added first so that subclasses can reference
    // it.  PyO3's `create_exception!` macro produces a type that is registered
    // as a Python class; we add it to the module so Python code can import it.
    m.add("SecretSHError", m.py().get_type::<SecretSHError>())?;
    m.add(
        "VaultNotFoundError",
        m.py().get_type::<VaultNotFoundError>(),
    )?;
    m.add("VaultCorruptError", m.py().get_type::<VaultCorruptError>())?;
    m.add(
        "VaultPermissionError",
        m.py().get_type::<VaultPermissionError>(),
    )?;
    m.add("DecryptionError", m.py().get_type::<DecryptionError>())?;
    m.add("MasterKeyError", m.py().get_type::<MasterKeyError>())?;
    m.add("PlaceholderError", m.py().get_type::<PlaceholderError>())?;
    m.add("TokenizationError", m.py().get_type::<TokenizationError>())?;
    m.add("CommandError", m.py().get_type::<CommandError>())?;
    m.add("EntryLimitError", m.py().get_type::<EntryLimitError>())?;
    m.add("LockError", m.py().get_type::<LockError>())?;

    Ok(())
}
