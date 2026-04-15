# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Vault export/import:** Full implementation of `export` and `import` subcommands (previously stubs). Python bindings include `export()` and `import_vault()` methods.
- **`TokenizationError::InvalidKeyName`:** Distinct error variant for placeholder key names that don't match `[A-Za-z_][A-Za-z0-9_]*` (previously reported as `MalformedPlaceholder`).
- **Documentation:** Migrated design docs from `PLAN.md` into `docs/` directory: `architecture.md`, `vault-format.md`, `threat-model.md`, `tokenizer.md`, `python-api.md`, `testing.md`, `cli.md`.

### Changed

- **cli.rs:** Simplified stdin reading in `run_set` from `BufRead::split` loop to `read_to_end` + strip trailing newline.
- **vault.rs:** Cursor mismatch after entry decryption now returns `VaultError::Truncated` instead of misleading `CommitTagMismatch`.
- **python.rs:** Bytearray zeroing uses `zeroize::Zeroize` trait instead of manual byte loop.
- **redact.rs:** Doc comment on `redact_stream` now references spawn.rs 50 MiB output limit as buffer bound.

## [0.1.0] - 2026-04-15

### Added

- **Vault:** AES-256-GCM encrypted vault with Argon2id KDF and HKDF-SHA256 key separation. Key names and values are both encrypted. Vault header and full file authenticated with HMAC-SHA256.
- **CLI:** `init`, `set`, `delete`, `list`, `run`, `export` (stub), `import` (stub) subcommands.
- **Tokenizer:** Strict POSIX shell subset parser. Rejects pipes, redirects, globs, subshells, variable expansion, and command chaining when unquoted. Supports single quotes, double quotes, and backslash escaping.
- **Placeholder injection:** `{{KEY}}` placeholders resolved against the vault at the argv level. Secrets never appear in shell history or LLM context.
- **Output redaction:** Aho-Corasick streaming multi-pattern replacement. Detects secrets in raw, base64, base64url, URL-encoded, hex-lowercase, and hex-uppercase forms.
- **Process spawning:** Direct `posix_spawnp` (macOS) without shell intermediary. Argv zeroized immediately after spawn. Linux `fork+execvp` path planned but not yet implemented.
- **Process hardening:** Core dump suppression (`RLIMIT_CORE=0`). `mlock` and `O_CLOEXEC` helpers available but not yet wired into the vault open path.
- **Resource limits:** Configurable timeout (default 300s), stdout cap (50 MiB), stderr cap (1 MiB) with SIGTERM/SIGKILL escalation.
- **Atomic writes:** Vault mutations use temp file + rename for crash safety.
- **Advisory locking:** `flock()` with PID + timestamp stale lock detection.
- **Audit logging:** JSON Lines to stderr with operation and key count.
- **Signal forwarding:** SIGINT, SIGTERM, SIGHUP forwarded to child with clean escalation.
- **Python bindings:** PyO3 + maturin. `secretsh.Vault` class with `run()`, `set()`, `delete()`, `list_keys()`, context manager, and typed exceptions. Secrets stay on the Rust heap. GIL released during blocking operations. `bytearray` values zeroed after copy.

### Security

- Secrets never cross the Rust/Python FFI boundary in plaintext.
- All secret memory wrapped in `zeroize::Zeroizing<Vec<u8>>`.
- Vault file permissions enforced at 0600 (hard error if group/world-readable).
- Exit codes follow GNU coreutils conventions.

[Unreleased]: https://github.com/lthoangg/secretsh/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/lthoangg/secretsh/releases/tag/v0.1.0
