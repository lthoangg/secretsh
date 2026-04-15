# Testing

## Quick Reference

```bash
cargo test                           # 188 Rust unit tests, ~4s
cargo clippy -- -D warnings          # must be zero warnings
cargo fmt --check                    # rustfmt.toml: max_width=100

# Python tests (requires venv + maturin)
maturin develop --features python
python -m pytest tests/ -v           # 20 Python tests, ~67s (Argon2id is slow)
```

## Rust Unit Tests (188 tests)

### By Module

| Module | Coverage |
|--------|----------|
| Tokenizer (~150 tests) | Valid splitting, quote handling, backslash escaping, metacharacter rejection (all 9 types), placeholder extraction, malformed/invalid placeholder detection, nested quotes, multi-byte UTF-8, real-world commands |
| Vault (~30 tests) | Round-trip encrypt/decrypt, HMAC verification, commit tag tamper detection, wrong passphrase, version mismatch, key name encryption, GCM AAD position binding, entry limit, export/import, stale lock detection |
| Redaction (~40 tests) | Single/multi-pattern, base64/URL/hex encoded, overlapping secrets, empty secrets, stream redaction, deduplication |
| Spawn (~8 tests) | Echo, exit code passthrough, command not found, stderr capture, secret redaction, timeout, output limit |
| Harden (~5 tests) | Core dump disable, mlock/munlock, madvise, zero-length edge cases |
| Error (~20 tests) | Exit code mapping, error display messages, all variant conversions |

### Test Conventions

- **Vault tests use unique env var names** per test (e.g., `VAULT_TEST_RT`, `VAULT_TEST_HMAC`) to avoid cross-test interference in parallel execution
- **Vault tests use `kdf_memory: Some(8192)`** (8 MiB) to keep Argon2id fast. Production default is 131072 (128 MiB)
- **Temp directories** via `tempfile::TempDir` — automatically cleaned up

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

## Fuzz Testing (planned)

The tokenizer is the primary fuzz target. Strategy from the design:

| Target | Strategy |
|--------|----------|
| Tokenizer | Arbitrary byte sequences → assert no panics. Accepted input must round-trip. Rejected input must produce a typed error. |
| Tokenizer metacharacter bypass | Inputs with `\|`, `;`, `$()`, etc. in quoting combinations → assert unquoted dangerous patterns are rejected. |
| Vault format parser | Arbitrary bytes as vault files → assert no panics, only typed errors. |
| Redaction engine | Random secrets + random output → assert no secret appears in redacted output. |

## Security-Specific Tests (design targets)

These are documented in the design for future implementation:

- Secret not in parent memory after spawn (scan heap for secret bytes in release mode)
- Zeroization verification in release builds (`write_volatile` not elided)
- `mlock` verification via `/proc/self/smaps` (Linux)
- Core dump disabled (`RLIMIT_CORE=0`)
- Secret not in child environment (`/proc/<child_pid>/environ`)
- Redaction completeness (`echo {{SECRET}}` → `[REDACTED_SECRET]`)
- Vault tamper detection (bit-flip in each section)
- Key name confidentiality (raw vault bytes don't contain key names)
- HKDF key separation (enc key can't verify HMAC and vice versa)
- O_CLOEXEC enforcement (`fcntl(fd, F_GETFD)`)
