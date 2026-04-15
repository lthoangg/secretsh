# Testing

## Quick Reference

```bash
cargo test                           # 233 tests (220 unit + 13 integration), ~27s
cargo clippy -- -D warnings          # must be zero warnings
cargo fmt --check                    # rustfmt.toml: max_width=100

# Python tests (requires venv + maturin)
maturin develop --features python
python -m pytest tests/ -v           # 20 Python tests, ~67s (Argon2id is slow)
```

## Rust Unit Tests (220 tests)

### By Module

| Module | Count | Coverage |
|--------|-------|----------|
| Tokenizer | 91 | Valid splitting, quote handling, backslash escaping, metacharacter rejection (all 9 types), placeholder extraction, malformed/invalid placeholder detection, nested quotes, multi-byte UTF-8, real-world commands |
| Redaction | 31 | Single/multi-pattern, base64/URL/hex encoded, overlapping secrets, empty secrets, stream redaction, deduplication |
| Error | 29 | Exit code mapping, error display messages, all variant conversions, `ShellDelegationBlocked` display and exit code |
| Vault | 25 | Round-trip encrypt/decrypt, HMAC verification, commit tag tamper detection, wrong passphrase, version mismatch, key name encryption, GCM AAD position binding, entry limit, export/import, stale lock detection |
| Dotenv | 23 | Key/value parsing, quoted values, escape sequences, comments, blank lines, export prefix, error cases |
| Spawn | 16 | Echo, exit code passthrough, command not found, stderr capture, secret redaction in stdout/stderr, timeout, output limit, secret redacted in error messages (NotFound/NotExecutable/ForkExecFailed/mixed-token argv0), redaction oracle double-redact |
| Harden | 5 | Core dump disable, mlock/munlock, madvise, zero-length edge cases |

### Test Conventions

- **Vault tests use unique env var names** per test (e.g., `VAULT_TEST_RT`, `VAULT_TEST_HMAC`) to avoid cross-test interference in parallel execution
- **Vault tests use `kdf_memory: Some(8192)`** (8 MiB) to keep Argon2id fast. Production default is 131072 (128 MiB)
- **Temp directories** via `tempfile::TempDir` — automatically cleaned up

## Rust Integration Tests (13 tests)

Integration tests use `assert_cmd` to invoke the compiled binary end-to-end.

### `tests/cli_set.rs` (2 tests)

| Test | What it verifies |
|------|-----------------|
| `set_rejects_piped_stdin` | `secretsh set` refuses non-interactive stdin |
| `set_rejects_empty_pipe` | `secretsh set` refuses empty piped input |

### `tests/cli_no_shell.rs` (11 tests)

| Test | What it verifies |
|------|-----------------|
| `no_shell_blocks_sh` | `--no-shell` rejects `sh` as argv[0] |
| `no_shell_blocks_bash` | `--no-shell` rejects `bash` as argv[0] |
| `no_shell_blocks_zsh` | `--no-shell` rejects `zsh` as argv[0] |
| `no_shell_blocks_dash` | `--no-shell` rejects `dash` as argv[0] |
| `no_shell_blocks_absolute_path_to_sh` | `/bin/sh` blocked via basename extraction |
| `no_shell_blocks_usr_bin_bash` | `/usr/bin/bash` blocked via basename extraction |
| `no_shell_allows_echo` | Non-shell binaries are still permitted |
| `no_shell_allows_true` | Non-shell binaries succeed normally |
| `without_no_shell_sh_is_permitted` | Shell is allowed when flag is absent |
| `no_shell_blocks_oracle_probe_via_sh_conditional` | AI oracle probe rejected before child runs; stdout empty |
| `no_shell_exit_code_is_125` | Blocked shell exits with code 125 |

## Python Tests (20 tests)

| Test | What it verifies |
|------|-----------------|
| `test_init_and_open` | Vault creation and opening |
| `test_set_and_list` | Store and list keys |
| `test_set_bytearray_zeros_source` | `bytearray` zeroed after `set()` |
| `test_delete` | Key removal |
| `test_run_basic` | Placeholder injection + redaction |
| `test_run_redacts_secret` | Output contains `[REDACTED_...]` |
| `test_run_exit_code` | Child exit code passthrough |
| `test_run_timeout` | Timeout triggers kill + `timed_out=True` |
| `test_wrong_passphrase` | `SecretSHError` on wrong key |
| `test_vault_not_found` | `VaultNotFoundError` for missing vault |
| `test_unresolved_placeholder` | `PlaceholderError` for missing key |
| `test_tokenization_error_pipe` | `TokenizationError` for `\|` |
| `test_tokenization_error_semicolon` | `TokenizationError` for `;` |
| `test_context_manager` | `with` syntax + auto-close |
| `test_close_idempotent` | Double `close()` doesn't crash |
| `test_export_round_trip` | Export + reimport preserves entries |
| `test_import_adds_new` | Import adds entries not in target |
| `test_import_skips_existing` | Import skips duplicate keys |
| `test_import_overwrites` | `overwrite=True` replaces entries |
| `test_export_after_close` | Operation after close raises error |

### Python Test Conventions

- **`kdf_memory=65536`** (64 MiB) — faster than production default
- **Unique env var names:** `PYTEST_KEY_{os.getpid()}` avoids parallel test interference
- **Cleanup:** Environment variables restored in `finally` blocks

## What Is Not Tested (Known Gaps)

The following are documented as not yet covered by automated tests:

| Gap | Notes |
|-----|-------|
| Redaction false positives for common secret values | If `SECRET=123456`, any `123456` in child output is redacted including unrelated occurrences. No test asserts this behaviour; it is a known design limitation of substring matching. |
| `--vault` flag after `--` swallowed as argv | `secretsh run -- cmd --vault path` silently uses the default vault. No test asserts the confusing error. |
| `--no-shell` when argv[0] resolves from a placeholder | `{{KEY}}` substituted to `bash` should be blocked. Currently only tested with literal shell names. |
| Secret in `/proc/<pid>/cmdline` | Secret is in child argv for process lifetime. No test verifies this exposure window. |
| Secret not in parent memory after spawn | No heap scan verifies zeroization in release builds. |
| Redaction completeness across chunk boundaries | `redact_stream` buffers the full input; chunk-boundary behaviour is not fuzz-tested. |
| `mlock` failure path | When `mlock` is unavailable, a warning is printed but execution continues. Not tested under resource limits. |

## Fuzz Testing (planned)

The tokenizer is the primary fuzz target. Strategy from the design:

| Target | Strategy |
|--------|----------|
| Tokenizer | Arbitrary byte sequences → assert no panics. Accepted input must round-trip. Rejected input must produce a typed error. |
| Tokenizer metacharacter bypass | Inputs with `\|`, `;`, `$()`, etc. in quoting combinations → assert unquoted dangerous patterns are rejected. |
| Vault format parser | Arbitrary bytes as vault files → assert no panics, only typed errors. |
| Redaction engine | Random secrets + random output → assert no secret appears in redacted output. |
