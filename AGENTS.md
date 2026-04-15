# AGENTS.md

## What this is

secretsh is a single-crate Rust binary + library that injects secrets from an encrypted vault into subprocess argv and redacts them from output. It targets macOS and Linux.

## Documentation

| Document | Content |
|----------|---------|
| [docs/architecture.md](docs/architecture.md) | Execution pipeline, module map, platform spawning, memory hardening, signal handling, redaction |
| [docs/vault-format.md](docs/vault-format.md) | Binary format spec, crypto (AES-256-GCM, Argon2id, HKDF), nonce management, atomicity, locking |
| [docs/threat-model.md](docs/threat-model.md) | Security principles, in-scope/out-of-scope threats, comparison with alternatives |
| [docs/tokenizer.md](docs/tokenizer.md) | Quoting rules, metacharacter rejection, placeholder syntax, error cases |
| [docs/python-api.md](docs/python-api.md) | PyO3 bindings, Vault class, exception hierarchy, memory lifetime, GIL release |
| [docs/testing.md](docs/testing.md) | Test inventory (188 Rust + 20 Python), conventions, fuzz testing plans |
| [docs/cli.md](docs/cli.md) | Full CLI subcommand reference, exit codes, vault location |
| [examples/](examples/) | Runnable examples: CLI walkthrough, Python API, multi-vault |

## Build & verify

```bash
cargo build                          # dev build
cargo test                           # 188 unit tests, ~4s
cargo clippy -- -D warnings          # must be zero warnings (CI enforces -D)
cargo fmt --check                    # rustfmt.toml: max_width=100
cargo build --release                # LTO + strip
```

CI runs: `check` → `fmt` → `clippy` → `test` (ubuntu + macos) → `audit` → `deny`. All must pass on PR.

## Critical conventions

- **All secret bytes must be `Zeroizing<Vec<u8>>`**. Never use `String` or plain `Vec<u8>` for secret material.
- **Argv elements passed to `spawn_child` must be null-terminated `Zeroizing<Vec<u8>>`**. The spawn module does not add terminators.
- **Vault tests use unique env var names** per test (e.g., `VAULT_TEST_RT`, `VAULT_TEST_HMAC`) to avoid cross-test interference in parallel execution. Follow this pattern for new vault tests.
- **Vault tests use `kdf_memory: Some(8192)`** (8 MiB) to keep Argon2id fast. Production default is 131072 (128 MiB).
- **`spawn.rs` is macOS-specific** — it uses `posix_spawnp` only. A Linux `fork+execvp` path needs `#[cfg(target_os)]` gating if added.

## Tokenizer changes are high risk

The tokenizer is the security boundary between agent-generated input and process execution. Any change to `tokenizer.rs` must:
1. Include tests for the specific edge case
2. Verify all metacharacter rejection tests still pass
3. Be fuzz-tested before merge

## Vault write path

Every `set`/`delete`/`import` re-derives keys from a fresh salt and re-encrypts all entries. This means:
- Nonce reuse is impossible (fresh key per write)
- Write latency is O(entries) — bounded at 10,000 max
- The temp file uses `O_EXCL` with PID suffix; rename is atomic

On open, verification order is: header HMAC → commit tag → per-entry GCM decrypt.

## Platform gotcha

`Vault::init` calls `set_permissions(parent, 0o700)` on the vault directory — but only if the directory **does not already exist**. Setting 0700 on an existing system directory like `/tmp` fails with `EPERM` on macOS.

## E2E smoke test

```bash
export SECRETSH_KEY="test-passphrase-12chars"
./target/release/secretsh init --kdf-memory 65536
echo 'MY_SECRET=hunter2' > /tmp/test.env
./target/release/secretsh import-env -f /tmp/test.env
rm /tmp/test.env
./target/release/secretsh run --quiet -- "echo {{MY_SECRET}}"
# Output: [REDACTED_MY_SECRET]
```

## Releasing a new version

Update the version in **all three files** before tagging:

| File | Field | Example |
|------|-------|---------|
| `Cargo.toml` | `version = "X.Y.Z"` | `version = "0.1.1"` |
| `pyproject.toml` | `version = "X.Y.Z"` | `version = "0.1.1"` |
| `CHANGELOG.md` | Add `## [X.Y.Z] - YYYY-MM-DD` section, update footer links | Move `[Unreleased]` items into new section |

After updating, regenerate `Cargo.lock`:

```bash
cargo generate-lockfile
```

Commit all four files (`Cargo.toml`, `pyproject.toml`, `CHANGELOG.md`, `Cargo.lock`), merge to main, then tag and release:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
gh release create vX.Y.Z --title "vX.Y.Z" --generate-notes
```

This triggers: `release-binaries` (4 platform tarballs) → `publish-homebrew` (waits for binaries) + `publish-crates` + `publish-pypi`.

## Python bindings

PyO3 + maturin. See [docs/python-api.md](docs/python-api.md) for full API reference.

```bash
uv venv .venv && source .venv/bin/activate
uv sync --group dev                      # installs pytest + pytest-cov from [dependency-groups]
maturin develop --features python        # build + install into venv
python -m pytest tests/ -v               # 20 Python tests, ~67s (Argon2id is slow)
```

Key files:
- `src/python.rs` — PyO3 bindings (gated behind `#[cfg(feature = "python")]`)
- `python/secretsh/__init__.py` — re-exports from `_native`
- `python/secretsh/__init__.pyi` — type stubs for IDE support
- `python/secretsh/py.typed` — PEP 561 marker
- `tests/test_python_bindings.py` — pytest suite
- `pyproject.toml` — maturin build config (`module-name = "secretsh._native"`)

Python binding conventions:
- Secrets **never** cross FFI as Python `str`. All secret data stays on the Rust heap.
- `vault.set("KEY", bytearray(b"val"))` zeroes the source bytearray after copy via `zeroize::Zeroize`. Check `bytearray` **before** `bytes` in the type dispatch — `extract::<Vec<u8>>()` matches both.
- `py.allow_threads()` wraps all blocking operations (open, set, delete, run) to release the GIL.
- `PyVault` wraps `Mutex<Option<Vault>>` for interior mutability — `close()` takes the inner vault.
- Python tests use `kdf_memory=65536` (64 MiB) and unique env var names per test (`PYTEST_KEY_{pid}`).
