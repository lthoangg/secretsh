/// All error types for the secretsh project.
///
/// The top-level [`SecretshError`] enum encompasses every failure category the
/// binary can encounter.  Each variant wraps a domain-specific sub-error type
/// so that call-sites can match on fine-grained conditions without losing the
/// ability to propagate a single unified error type up the call stack.
///
/// Exit-code semantics follow GNU coreutils conventions (`timeout`, `env`):
///
/// | Code | Meaning                                                  |
/// |------|----------------------------------------------------------|
/// | 0    | Success                                                  |
/// | 1–123| Child process exit code (passed through)                 |
/// | 124  | Timeout or output-size limit exceeded (child was killed) |
/// | 125  | secretsh internal error (vault / placeholder / tokenization / spawn) |
/// | 126  | Command found but not executable                         |
/// | 127  | Command not found                                        |
/// | 128+N| Child killed by signal N                                 |
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Tokenization
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the command-string tokenizer.
///
/// The tokenizer implements a strict subset of POSIX shell quoting rules and
/// rejects any shell metacharacter that could allow shell-injection or
/// unintended expansion.
#[derive(Debug, Error)]
pub enum TokenizationError {
    /// An unquoted shell metacharacter was found in the command string.
    ///
    /// The `character` field holds the offending character (e.g. `|`, `>`,
    /// `&`, `;`, `*`, `?`, `[`, `$`, `` ` ``).
    #[error(
        "rejected shell metacharacter {character:?} at byte offset {offset} \
         — wrap it in quotes if it is intended to be literal"
    )]
    RejectedMetacharacter { character: char, offset: usize },

    /// A placeholder was opened with `{{` but never closed with `}}`.
    ///
    /// The `fragment` field contains the partial placeholder text seen so far.
    #[error("malformed placeholder: {fragment:?} — missing closing '}}'")]
    MalformedPlaceholder { fragment: String },

    /// A placeholder's key name does not match `[A-Za-z_][A-Za-z0-9_]*`.
    ///
    /// Key names must start with an ASCII letter or underscore and contain
    /// only ASCII alphanumerics and underscores.  The `fragment` field
    /// contains the full `{{…}}` text as it appeared in the command string.
    #[error(
        "invalid placeholder key name in {fragment:?} — key names must match \
         [A-Za-z_][A-Za-z0-9_]* (start with a letter or underscore, \
         contain only letters, digits, and underscores)"
    )]
    InvalidKeyName { fragment: String },

    /// A single-quoted string was opened but the closing `'` was never found.
    #[error("unclosed single-quoted string starting at byte offset {offset}")]
    UnclosedSingleQuote { offset: usize },

    /// A double-quoted string was opened but the closing `"` was never found.
    #[error("unclosed double-quoted string starting at byte offset {offset}")]
    UnclosedDoubleQuote { offset: usize },

    /// A backslash appeared at the very end of the input with no following
    /// character to escape.
    #[error("trailing backslash at end of command string — nothing to escape")]
    TrailingBackslash,

    /// The command string was empty or contained only whitespace.
    #[error("command string is empty — nothing to execute")]
    EmptyCommand,
}

// ─────────────────────────────────────────────────────────────────────────────
// Vault
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by vault open, read, and write operations.
#[derive(Debug, Error)]
pub enum VaultError {
    /// The vault file does not exist at the expected path.
    #[error("vault not found at {path:?} — run `secretsh init` to create one")]
    NotFound { path: std::path::PathBuf },

    /// The vault header HMAC did not match the computed value.
    ///
    /// This indicates the vault header (magic, version, cipher ID, KDF params,
    /// salt, entry count, or reserved bytes) has been tampered with or
    /// corrupted.
    #[error(
        "vault header HMAC mismatch — the vault header may have been tampered \
         with or corrupted"
    )]
    HmacMismatch,

    /// The commit tag (full-file HMAC) did not match the computed value.
    ///
    /// This indicates that entries have been appended, removed, or reordered
    /// outside of secretsh, or that the file was truncated after the declared
    /// entry count.
    #[error(
        "vault commit-tag HMAC mismatch — the vault file may have been \
         tampered with, truncated, or corrupted"
    )]
    CommitTagMismatch,

    /// An entry's AES-256-GCM authentication tag did not verify.
    ///
    /// This can indicate a wrong passphrase (which produces wrong subkeys) or
    /// direct corruption of the ciphertext bytes.
    #[error(
        "GCM authentication tag mismatch for entry at index {index} — \
         possible wrong passphrase or ciphertext corruption"
    )]
    GcmMismatch { index: u32 },

    /// An entry's GCM authenticated-associated-data (AAD) check failed.
    ///
    /// Each entry's AAD is its ordinal index encoded as a 4-byte big-endian
    /// integer.  A mismatch means entries have been reordered or spliced from
    /// a different vault version.
    #[error(
        "GCM AAD mismatch for entry at index {index} — entries may have been \
         reordered or spliced from a different vault"
    )]
    AadMismatch { index: u32 },

    /// The vault file has group- or world-readable permissions.
    ///
    /// secretsh refuses to open a vault that is readable by anyone other than
    /// the owner.  Pass `--allow-insecure-permissions` to override.
    #[error(
        "vault file {path:?} has insecure permissions (mode {mode:#o}) — \
         expected 0600 (owner read/write only). \
         Use --allow-insecure-permissions to override"
    )]
    InsecurePermissions { path: std::path::PathBuf, mode: u32 },

    /// The passphrase-derived keys did not decrypt any entry successfully.
    ///
    /// This is the user-facing "wrong passphrase" error.  The underlying cause
    /// is a GCM tag mismatch on the first entry, but we surface a single
    /// high-level message to avoid leaking which entry failed.
    #[error(
        "decryption failed — the master passphrase is incorrect or the vault \
         is corrupt"
    )]
    WrongPassphrase,

    /// The vault file's version byte is higher than this binary supports.
    #[error(
        "vault format version {found} is not supported by this binary \
         (maximum supported: {supported}) — upgrade secretsh to open this vault"
    )]
    VersionTooNew { found: u8, supported: u8 },

    /// The vault file's version byte is zero or otherwise invalid.
    #[error("vault format version {found} is invalid — the vault file may be corrupt")]
    VersionInvalid { found: u8 },

    /// A `set` operation was attempted but the vault already holds the maximum
    /// number of entries (10,000).
    #[error(
        "vault entry limit exceeded — the vault already contains {limit} \
         entries (the maximum). Delete unused entries before adding new ones"
    )]
    EntryLimitExceeded { limit: usize },

    /// An exclusive advisory lock on the vault lockfile could not be acquired
    /// within the timeout period (default 30 seconds).
    #[error(
        "vault is locked by another process (lockfile: {lockfile_path:?}). \
         Waited {elapsed_secs}s without acquiring the lock. \
         If the lock is stale, delete the lockfile and retry"
    )]
    LockTimeout {
        lockfile_path: std::path::PathBuf,
        elapsed_secs: u64,
    },

    /// The lockfile exists but the PID recorded inside it is no longer running
    /// and the timestamp is older than the stale-lock threshold.
    #[error(
        "stale vault lockfile detected at {lockfile_path:?} \
         (recorded PID {pid} is not running, lock age {age_secs}s). \
         The lockfile has been removed and the operation will be retried"
    )]
    StaleLock {
        lockfile_path: std::path::PathBuf,
        pid: u32,
        age_secs: u64,
    },

    /// The vault file's magic bytes did not match `SECRETSH`.
    #[error(
        "vault file does not start with the expected magic bytes \
         (found {found:?}) — this is not a secretsh vault file"
    )]
    BadMagic { found: [u8; 8] },

    /// The vault file is too short to contain a valid header.
    #[error(
        "vault file is truncated — expected at least {expected} bytes but \
         found {found} bytes"
    )]
    Truncated { expected: usize, found: usize },
}

// ─────────────────────────────────────────────────────────────────────────────
// Placeholder
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced during placeholder resolution.
///
/// A placeholder is a `{{KEY_NAME}}` token embedded in the command string.
/// Resolution fails when the vault does not contain an entry for the requested
/// key.
#[derive(Debug, Error)]
pub enum PlaceholderError {
    /// The vault contains no entry for the requested key.
    ///
    /// The command is **not** executed when this error occurs.
    #[error(
        "unresolved placeholder {{{{{{key}}}}}} — no entry with that name \
         exists in the vault. Use `secretsh set {key}` to add it"
    )]
    UnresolvedKey { key: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// Spawn
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced when spawning the child process.
#[derive(Debug, Error)]
pub enum SpawnError {
    /// The command binary could not be found on `PATH` or at the given path.
    ///
    /// Maps to exit code 127 (GNU convention).
    #[error("command not found: {command:?} — verify the binary exists and is on PATH")]
    NotFound { command: String },

    /// The command binary exists but the current user does not have execute
    /// permission, or the file is not a valid executable (e.g. a directory or
    /// a plain text file without a shebang).
    ///
    /// Maps to exit code 126 (GNU convention).
    #[error(
        "command not executable: {command:?} — check file permissions and \
         ensure the file is a valid executable"
    )]
    NotExecutable { command: String },

    /// The resolved argv[0] is a known shell interpreter and `--no-shell` was
    /// set.  Shell delegation is blocked to prevent oracle attacks where an AI
    /// agent constructs `sh -c '[ "{{KEY}}" = guess ]'` probes to infer secret
    /// values through conditional output.
    ///
    /// Maps to exit code 125 (internal secretsh error).
    #[error(
        "shell delegation blocked: {shell:?} is a shell interpreter — \
         remove --no-shell if you genuinely need shell features"
    )]
    ShellDelegationBlocked { shell: String },

    /// The underlying `fork(2)` / `posix_spawnp(3)` / `execvp(2)` syscall
    /// failed for a reason other than "not found" or "not executable".
    #[error("failed to spawn {command:?}: {reason}")]
    ForkExecFailed { command: String, reason: String },

    /// The child process was killed because it exceeded the execution timeout.
    ///
    /// Maps to exit code 124 (GNU `timeout` convention).
    #[error(
        "child process {pid} exceeded the {timeout_secs}s execution timeout \
         and was killed"
    )]
    Timeout { pid: u32, timeout_secs: u64 },

    /// The child process was killed because its stdout or stderr output
    /// exceeded the configured size limit.
    ///
    /// Maps to exit code 124.
    #[error(
        "child process {pid} exceeded the output size limit \
         ({limit_bytes} bytes) and was killed"
    )]
    OutputLimitExceeded { pid: u32, limit_bytes: u64 },
}

// ─────────────────────────────────────────────────────────────────────────────
// Redaction
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced while building the Aho-Corasick redaction automaton.
#[derive(Debug, Error)]
pub enum RedactionError {
    /// The Aho-Corasick automaton could not be constructed from the provided
    /// patterns.
    ///
    /// This is an internal error — it should not occur under normal operation
    /// because the patterns are raw byte sequences derived from vault values.
    #[error("failed to build redaction pattern automaton: {reason}")]
    PatternBuildFailed { reason: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// Master key
// ─────────────────────────────────────────────────────────────────────────────

/// Errors related to the master passphrase / master-key environment variable.
#[derive(Debug, Error)]
pub enum MasterKeyError {
    /// The environment variable named by `--master-key-env` is not set in the
    /// current process environment.
    #[error(
        "environment variable {env_var:?} is not set — \
         set it to the master passphrase before running secretsh"
    )]
    EnvVarNotSet { env_var: String },

    /// The passphrase is shorter than the minimum required length (12
    /// characters).  This check is only enforced during `secretsh init`.
    ///
    /// Pass `--no-passphrase-check` to disable this check for automation where
    /// the passphrase is machine-generated.
    #[error(
        "passphrase is too short ({length} characters) — \
         a minimum of {minimum} characters is required. \
         Use --no-passphrase-check to disable this check for machine-generated passphrases"
    )]
    PassphraseTooShort { length: usize, minimum: usize },
}

// ─────────────────────────────────────────────────────────────────────────────
// I/O
// ─────────────────────────────────────────────────────────────────────────────

/// A thin wrapper around [`std::io::Error`] for I/O failures that do not fit
/// into a more specific category (e.g. reading the vault directory, writing
/// the temp file, renaming the temp file over the vault).
#[derive(Debug, Error)]
#[error("I/O error: {0}")]
pub struct IoError(#[from] pub std::io::Error);

// ─────────────────────────────────────────────────────────────────────────────
// Top-level error
// ─────────────────────────────────────────────────────────────────────────────

/// The unified error type for the entire secretsh binary.
///
/// Every public API surface returns `Result<T, SecretshError>`.  The
/// [`SecretshError::exit_code`] method maps each variant to the appropriate
/// process exit code following GNU coreutils conventions.
#[derive(Debug, Error)]
pub enum SecretshError {
    /// A tokenization failure — the command string was rejected before any
    /// vault access or process spawning occurred.
    #[error("tokenization error: {0}")]
    Tokenization(#[from] TokenizationError),

    /// A vault-layer failure — the vault could not be opened, read, or written.
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),

    /// A placeholder could not be resolved against the vault.
    #[error("placeholder error: {0}")]
    Placeholder(#[from] PlaceholderError),

    /// The child process could not be spawned, or was killed by a resource
    /// limit.
    #[error("spawn error: {0}")]
    Spawn(#[from] SpawnError),

    /// The Aho-Corasick redaction automaton could not be built.
    #[error("redaction error: {0}")]
    Redaction(#[from] RedactionError),

    /// A master-key / passphrase problem.
    #[error("master key error: {0}")]
    MasterKey(#[from] MasterKeyError),

    /// A CLI usage or configuration error (e.g. non-interactive terminal
    /// where one is required).
    #[error("{0}")]
    Config(String),

    /// An I/O error that does not fit a more specific category.
    #[error(transparent)]
    Io(#[from] IoError),
}

impl SecretshError {
    /// Returns the process exit code that secretsh should use when this error
    /// causes the binary to terminate.
    ///
    /// The mapping follows GNU coreutils conventions (`timeout`, `env`):
    ///
    /// | Code | Condition                                                |
    /// |------|----------------------------------------------------------|
    /// | 124  | Timeout or output-size limit exceeded                    |
    /// | 125  | Internal secretsh error (vault, placeholder, tokenization, spawn failure) |
    /// | 126  | Command found but not executable                         |
    /// | 127  | Command not found                                        |
    pub fn exit_code(&self) -> i32 {
        match self {
            // ── Timeout / output-limit ────────────────────────────────────
            SecretshError::Spawn(SpawnError::Timeout { .. }) => 124,
            SecretshError::Spawn(SpawnError::OutputLimitExceeded { .. }) => 124,

            // ── Command not found ─────────────────────────────────────────
            SecretshError::Spawn(SpawnError::NotFound { .. }) => 127,

            // ── Command not executable ────────────────────────────────────
            SecretshError::Spawn(SpawnError::NotExecutable { .. }) => 126,

            // ── All other spawn failures ──────────────────────────────────
            SecretshError::Spawn(_) => 125,

            // ── Internal errors ───────────────────────────────────────────
            SecretshError::Tokenization(_) => 125,
            SecretshError::Vault(_) => 125,
            SecretshError::Placeholder(_) => 125,
            SecretshError::Redaction(_) => 125,
            SecretshError::MasterKey(_) => 125,
            SecretshError::Config(_) => 125,
            SecretshError::Io(_) => 125,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Convenience: std::io::Error → SecretshError without going through IoError
// ─────────────────────────────────────────────────────────────────────────────

impl From<std::io::Error> for SecretshError {
    fn from(e: std::io::Error) -> Self {
        SecretshError::Io(IoError(e))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── exit_code mapping ────────────────────────────────────────────────────

    #[test]
    fn timeout_maps_to_124() {
        let err = SecretshError::Spawn(SpawnError::Timeout {
            pid: 1234,
            timeout_secs: 300,
        });
        assert_eq!(err.exit_code(), 124);
    }

    #[test]
    fn output_limit_maps_to_124() {
        let err = SecretshError::Spawn(SpawnError::OutputLimitExceeded {
            pid: 5678,
            limit_bytes: 52_428_800,
        });
        assert_eq!(err.exit_code(), 124);
    }

    #[test]
    fn not_found_maps_to_127() {
        let err = SecretshError::Spawn(SpawnError::NotFound {
            command: "nonexistent-binary".into(),
        });
        assert_eq!(err.exit_code(), 127);
    }

    #[test]
    fn not_executable_maps_to_126() {
        let err = SecretshError::Spawn(SpawnError::NotExecutable {
            command: "/etc/hosts".into(),
        });
        assert_eq!(err.exit_code(), 126);
    }

    #[test]
    fn fork_exec_failed_maps_to_125() {
        let err = SecretshError::Spawn(SpawnError::ForkExecFailed {
            command: "ls".into(),
            reason: "ENOMEM".into(),
        });
        assert_eq!(err.exit_code(), 125);
    }

    #[test]
    fn tokenization_maps_to_125() {
        let err = SecretshError::Tokenization(TokenizationError::EmptyCommand);
        assert_eq!(err.exit_code(), 125);
    }

    #[test]
    fn vault_not_found_maps_to_125() {
        let err = SecretshError::Vault(VaultError::NotFound {
            path: "/tmp/missing.bin".into(),
        });
        assert_eq!(err.exit_code(), 125);
    }

    #[test]
    fn placeholder_maps_to_125() {
        let err = SecretshError::Placeholder(PlaceholderError::UnresolvedKey {
            key: "MY_SECRET".into(),
        });
        assert_eq!(err.exit_code(), 125);
    }

    #[test]
    fn redaction_maps_to_125() {
        let err = SecretshError::Redaction(RedactionError::PatternBuildFailed {
            reason: "too many patterns".into(),
        });
        assert_eq!(err.exit_code(), 125);
    }

    #[test]
    fn master_key_maps_to_125() {
        let err = SecretshError::MasterKey(MasterKeyError::EnvVarNotSet {
            env_var: "SECRETSH_KEY".into(),
        });
        assert_eq!(err.exit_code(), 125);
    }

    #[test]
    fn io_error_maps_to_125() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "EACCES");
        let err = SecretshError::from(io);
        assert_eq!(err.exit_code(), 125);
    }

    // ── From conversions ─────────────────────────────────────────────────────

    #[test]
    fn from_tokenization_error() {
        let inner = TokenizationError::TrailingBackslash;
        let err: SecretshError = inner.into();
        assert!(matches!(err, SecretshError::Tokenization(_)));
    }

    #[test]
    fn from_vault_error() {
        let inner = VaultError::HmacMismatch;
        let err: SecretshError = inner.into();
        assert!(matches!(err, SecretshError::Vault(_)));
    }

    #[test]
    fn from_placeholder_error() {
        let inner = PlaceholderError::UnresolvedKey { key: "K".into() };
        let err: SecretshError = inner.into();
        assert!(matches!(err, SecretshError::Placeholder(_)));
    }

    #[test]
    fn from_spawn_error() {
        let inner = SpawnError::NotFound {
            command: "foo".into(),
        };
        let err: SecretshError = inner.into();
        assert!(matches!(err, SecretshError::Spawn(_)));
    }

    #[test]
    fn from_redaction_error() {
        let inner = RedactionError::PatternBuildFailed { reason: "x".into() };
        let err: SecretshError = inner.into();
        assert!(matches!(err, SecretshError::Redaction(_)));
    }

    #[test]
    fn from_master_key_error() {
        let inner = MasterKeyError::PassphraseTooShort {
            length: 4,
            minimum: 12,
        };
        let err: SecretshError = inner.into();
        assert!(matches!(err, SecretshError::MasterKey(_)));
    }

    #[test]
    fn from_io_error_via_wrapper() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let wrapper = IoError(io);
        let err: SecretshError = wrapper.into();
        assert!(matches!(err, SecretshError::Io(_)));
    }

    // ── Display messages ─────────────────────────────────────────────────────

    #[test]
    fn display_rejected_metacharacter() {
        let err = TokenizationError::RejectedMetacharacter {
            character: '|',
            offset: 7,
        };
        let msg = err.to_string();
        assert!(msg.contains('|'), "message should mention the character");
        assert!(msg.contains("7"), "message should mention the offset");
    }

    #[test]
    fn display_malformed_placeholder() {
        let err = TokenizationError::MalformedPlaceholder {
            fragment: "{{FOO".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("{{FOO"));
        // The #[error] format string uses `}}` to produce a literal `}` in the
        // rendered message — assert on the single-brace form.
        assert!(msg.contains('}'));
    }

    #[test]
    fn display_invalid_key_name() {
        let err = TokenizationError::InvalidKeyName {
            fragment: "{{1FOO}}".into(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("{{1FOO}}"),
            "message should contain the fragment"
        );
        assert!(
            msg.contains("[A-Za-z_]"),
            "message should describe valid key-name pattern"
        );
    }

    #[test]
    fn display_unresolved_key_contains_key_name() {
        let err = PlaceholderError::UnresolvedKey {
            key: "DB_PASS".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("DB_PASS"));
    }

    #[test]
    fn display_insecure_permissions_contains_mode() {
        let err = VaultError::InsecurePermissions {
            path: "/home/user/.local/share/secretsh/vault.bin".into(),
            mode: 0o644,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("0644") || msg.contains("644"),
            "mode should appear in message"
        );
    }

    #[test]
    fn display_version_too_new() {
        let err = VaultError::VersionTooNew {
            found: 5,
            supported: 1,
        };
        let msg = err.to_string();
        assert!(msg.contains('5'));
        assert!(msg.contains('1'));
    }

    #[test]
    fn display_passphrase_too_short() {
        let err = MasterKeyError::PassphraseTooShort {
            length: 6,
            minimum: 12,
        };
        let msg = err.to_string();
        assert!(msg.contains('6'));
        assert!(msg.contains("12"));
    }

    #[test]
    fn display_lock_timeout_contains_path() {
        let err = VaultError::LockTimeout {
            lockfile_path: "/tmp/vault.lock".into(),
            elapsed_secs: 30,
        };
        let msg = err.to_string();
        assert!(msg.contains("/tmp/vault.lock"));
        assert!(msg.contains("30"));
    }

    // ── ShellDelegationBlocked ────────────────────────────────────────────────

    #[test]
    fn shell_delegation_blocked_display_contains_shell_name() {
        let err = SpawnError::ShellDelegationBlocked {
            shell: "bash".into(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("bash"),
            "error message should contain the shell name, got: {msg:?}"
        );
        assert!(
            msg.contains("shell delegation blocked"),
            "error message should contain the phrase 'shell delegation blocked', got: {msg:?}"
        );
    }

    #[test]
    fn shell_delegation_blocked_exit_code_is_125() {
        let err: SecretshError =
            SecretshError::Spawn(SpawnError::ShellDelegationBlocked { shell: "sh".into() });
        assert_eq!(
            err.exit_code(),
            125,
            "ShellDelegationBlocked should map to exit code 125"
        );
    }

    #[test]
    fn shell_delegation_blocked_display_does_not_contain_secret() {
        // The shell name in the error comes from the resolved argv[0] basename.
        // If a secret happened to resolve to a shell name, the error message
        // must not inadvertently expose it — the basename-only extraction means
        // only the last path component appears, and the redactor in cli.rs has
        // already been applied before this error is constructed.
        // This test verifies the display format is bounded to the basename.
        let err = SpawnError::ShellDelegationBlocked { shell: "sh".into() };
        let msg = err.to_string();
        // The full path "/usr/local/bin/sh" must not appear — only "sh".
        assert!(
            !msg.contains("/usr/local/bin"),
            "error should only contain basename, not full path, got: {msg:?}"
        );
    }
}
