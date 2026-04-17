# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-17

> **Architecture change.** The encrypted vault model (AES-256-GCM + Argon2id, `init`/`set`/`delete`/`list` subcommands, `--master-key-env`) has been removed. Secrets are now read directly from a plain `.env` file. This is a **breaking change** for any caller using the vault CLI or the `secretsh.Vault` Python class.

### Changed

- **Primary interface simplified to `--env`:** `secretsh --env <path> run -- <command>` is now the only subcommand. The vault subcommands (`init`, `set`, `delete`, `list`, `export`, `import`, `import-env`) are removed.
- **`python/secretsh/__init__.py`** (CLI subprocess wrapper): already matched the `.env` model; no changes needed.
- **`docs/python-api.md`:** Rewritten for the `secretsh.run()` API.
- **`docs/testing.md`:** Test counts corrected (187 Rust tests).
- **`docs/architecture.md`:** Module map cleaned up.

### Removed

- `src/vault.rs` and encrypted vault model (AES-256-GCM + Argon2id + HKDF).
- `src/python.rs` PyO3 native extension (`secretsh._native`) — no longer needed without in-process vault decryption. Use `import secretsh` directly.
- CLI subcommands: `init`, `set`, `delete`, `list`, `export`, `import`, `import-env`.
- `--master-key-env` flag.
- `rpassword` and `pyo3` dependencies.
- `ring`-based KDF / HKDF key material. `ring` is still present for SHA-256 audit log hashing.

### Migration

```bash
# Before (0.1.x)
secretsh --master-key-env SECRETSH_KEY init
secretsh --master-key-env SECRETSH_KEY set API_PASS
secretsh --master-key-env SECRETSH_KEY run -- curl -u admin:{{API_PASS}} https://example.com

# After (0.2.0)
echo 'API_PASS=hunter2' > .env
chmod 600 .env
secretsh --env .env run -- curl -u admin:{{API_PASS}} https://example.com
```

Python callers:

```python
# Before (0.1.x)
import secretsh._native as _n
with _n.Vault(master_key_env="SECRETSH_KEY") as v:
    result = v.run("curl -u admin:{{API_PASS}} https://example.com")

# After (0.2.0)
import secretsh
result = secretsh.run(".env", "curl -u admin:{{API_PASS}} https://example.com")
```

[0.2.0]: https://github.com/lthoangg/secretsh/compare/v0.1.5...v0.2.0

## [0.1.5] - 2026-04-15

### Fixed

- **`python.rs` non-exhaustive match on `SpawnError`:** `ShellDelegationBlocked` variant added in 0.1.4 was missing from the PyO3 error mapping, causing a compile error in the PyPI publish workflow. The match now covers all variants and has an exhaustiveness guard comment.
- **CI now checks `--features python`:** `cargo clippy --features python` and `cargo test --lib --features python` added to CI so this class of error is caught before release.

[0.1.5]: https://github.com/lthoangg/secretsh/compare/v0.1.4...v0.1.5

## [0.1.4] - 2026-04-15

> **Beta release.** Core functionality is stable and tested. The security model has known limitations around substring redaction false positives and the redaction side-channel oracle — see [docs/threat-model.md](docs/threat-model.md) before deploying in sensitive environments.

### Added

- **`--no-shell` flag for `run`:** Rejects known shell interpreters (`sh`, `bash`, `zsh`, `dash`, `fish`, `ksh`, `mksh`, `tcsh`, `csh`) as argv[0] by basename, including absolute paths (e.g. `/bin/sh`). Exits with code 125. Closes the shell conditional oracle attack where an AI agent constructs `sh -c '[ "{{KEY}}" = guess ] && echo yes'` probes. Recommended for all AI-agent deployments.
- **`SpawnError::ShellDelegationBlocked`:** New error variant with exit code 125.
- **Secret redacted in spawn error messages:** argv[0] is now passed through the redactor before appearing in `NotFound`, `NotExecutable`, or `ForkExecFailed` error messages. Previously, `secretsh run -- "{{KEY}}"` would print `command not found: "s3cr3t"`, leaking the secret value.
- **Integration tests `tests/cli_no_shell.rs`:** 11 `assert_cmd` tests covering shell blocking by name and absolute path, non-shell pass-through, oracle probe rejection, and exit code.
- **Unit tests in `src/spawn.rs`:** `secret_value_in_argv0_is_redacted_in_not_found_error`, `secret_value_in_argv0_is_redacted_in_not_executable_error`, `secret_value_in_argv0_is_redacted_in_fork_exec_failed_error`, `secret_value_in_argv0_with_suffix_is_redacted_in_error`, `secret_value_appearing_twice_in_output_both_redacted`, `secret_in_stderr_is_redacted`.
- **Unit tests in `src/error.rs`:** `shell_delegation_blocked_display_contains_shell_name`, `shell_delegation_blocked_exit_code_is_125`, `shell_delegation_blocked_display_does_not_contain_secret`.

### Changed

- **`docs/threat-model.md`:** Substantially rewritten. Redaction now described as "best effort" in the in-scope table. Added dedicated Oracle Attacks section distinguishing the redaction side-channel (not closeable) from the shell conditional oracle (closed by `--no-shell`). Added Redaction Limitations section documenting false positives for common values. Added Recommended Configuration block for AI-agent deployments.
- **`docs/testing.md`:** Rewritten with accurate counts (233 Rust, not 188). Added "What Is Not Tested" section documenting known gaps honestly.
- **`docs/cli.md`:** `--no-shell` added to flag table with full description and examples. Security Notes section expanded with `--vault`-placement warning, `--no-shell` recommendation, and redaction false-positive caveat.
- **`docs/architecture.md`:** `cli.rs` and `spawn.rs` module descriptions updated. Resource limits table expanded to include `--no-shell`. Redaction section notes false-positive limitation.
- **`README.md`:** Security Model rewritten to be honest about partial redaction, false positives, and the two oracle attacks. `--no-shell` added to run flags table. Development section test count corrected (188 → 233).
- **`AGENTS.md`:** Test count corrected. E2E smoke test extended with `--no-shell` examples. Security conventions section added.

### Fixed

- Secret value no longer appears in `command not found` / `command not executable` / spawn failure error messages when argv[0] was derived from a `{{KEY}}` placeholder substitution.

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

[0.1.4]: https://github.com/lthoangg/secretsh/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/lthoangg/secretsh/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/lthoangg/secretsh/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/lthoangg/secretsh/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/lthoangg/secretsh/releases/tag/v0.1.0
