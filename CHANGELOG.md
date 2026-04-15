# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-04-15

### Added

- **Interactive `set` command:** `secretsh set KEY` now prompts with hidden input (like `passwd`) and submits on Enter. Piped stdin is rejected with an error directing users to `import-env`.
- **`SecretshError::Config` variant:** New error variant for CLI usage errors (e.g. non-interactive terminal).
- **CLI integration tests:** `tests/cli_set.rs` — 2 `assert_cmd` tests verifying pipe rejection behavior.

### Changed

- **README:** Added honest security disclaimer about exfiltration limits. Updated `set` description to reflect interactive-only behavior.
- **docs/cli.md:** Rewrote `set` section — removed pipe/EOF examples, documented hidden input prompt.
- **docs/architecture.md:** Updated `cli.rs` module description for `rpassword`-based `run_set`.
- **examples/basic_cli.sh:** Replaced `printf | secretsh set` with `import-env` workflow.
- **AGENTS.md:** E2E smoke test uses `import-env` instead of pipe.

### Dependencies

- Added `rpassword = "7"` for cross-platform hidden terminal input.

## [0.1.2] - 2026-04-15

### Added

- **`import-env` command:** Import secrets from a `.env` file (`secretsh import-env -f .env`). Supports comments, blank lines, `export` prefix, double-quoted and single-quoted values, inline comments, and escape sequences.
- **`--master-key-env` defaults to `SECRETSH_KEY`:** All commands now work without `--master-key-env` if the `SECRETSH_KEY` environment variable is set. Use `--master-key-env OTHER_VAR` to override.

### Changed

- **README:** Rewrote Quick Start with clearer step-by-step instructions. Replaced `echo -n "secret"` anti-pattern with secure alternatives (interactive stdin, file redirection, `import-env`).
- **docs/cli.md:** Simplified all examples to use the default env var. Added full `import-env` reference section.
- **examples/basic_cli.sh:** Updated to use default `SECRETSH_KEY` and `printf` instead of `echo -n`.
- **AGENTS.md:** Simplified E2E smoke test.

## [0.1.1] - 2026-04-15

### Added

- **Vault export/import:** Full implementation of `export` and `import` subcommands (previously stubs). Python bindings include `export()` and `import_vault()` methods.
- **`TokenizationError::InvalidKeyName`:** Distinct error variant for placeholder key names that don't match `[A-Za-z_][A-Za-z0-9_]*` (previously reported as `MalformedPlaceholder`).
- **Documentation:** Migrated design docs from `PLAN.md` into `docs/` directory: `architecture.md`, `vault-format.md`, `threat-model.md`, `tokenizer.md`, `python-api.md`, `testing.md`, `cli.md`.
- **Examples:** `basic_cli.sh`, `basic_python.py`, `multi_vault.py`.
- **Homebrew:** `brew tap lthoangg/tap && brew install secretsh`.

### Changed

- **cli.rs:** Simplified stdin reading in `run_set` from `BufRead::split` loop to single-read + strip trailing newline.
- **vault.rs:** Cursor mismatch after entry decryption now returns `VaultError::Truncated` instead of misleading `CommitTagMismatch`.
- **python.rs:** Bytearray zeroing uses `zeroize::Zeroize` trait instead of manual byte loop.
- **redact.rs:** Doc comment on `redact_stream` now references spawn.rs 50 MiB output limit as buffer bound.

### Fixed

- **CI:** Release binaries now uploaded to GitHub Release (not just workflow artifacts).
- **CI:** Homebrew workflow waits for binaries before downloading.
- **CI:** Linux aarch64 PyPI wheel uses native arm64 runner.
- **CI:** Docs-only PRs skip build/test jobs.
- **CI:** Publish workflows are idempotent on re-release.

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

[0.1.3]: https://github.com/lthoangg/secretsh/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/lthoangg/secretsh/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/lthoangg/secretsh/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/lthoangg/secretsh/releases/tag/v0.1.0
