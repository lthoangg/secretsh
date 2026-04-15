# Python API

secretsh provides native Python bindings via PyO3 + maturin. The extension module is `secretsh._native`, re-exported through `python/secretsh/__init__.py`.

## Install

```bash
# From source (development)
uv venv .venv && source .venv/bin/activate
uv sync --group dev
maturin develop --features python
python -m pytest tests/ -v

# From PyPI (when published)
pip install secretsh
```

Requires Python 3.10+.

## Quick Start

```python
import secretsh

# master_key_env is the NAME of an env var holding the passphrase
with secretsh.Vault(master_key_env="SECRETSH_KEY") as vault:
    vault.set("API_KEY", bytearray(b"sk-live-abc123"))  # bytearray zeroed after copy
    result = vault.run("curl -H 'Authorization: Bearer {{API_KEY}}' https://api.example.com")
    print(result.stdout)     # secrets redacted
    print(result.exit_code)
```

## Vault Class

### Constructor

```python
vault = secretsh.Vault(
    master_key_env="SECRETSH_KEY",               # required: env var name holding passphrase
    vault_path="/path/to/vault.bin",             # optional: custom vault path
    allow_insecure_permissions=False,            # optional: skip permission check
    kdf_memory=131072,                           # optional: Argon2id memory cost in KiB
)
```

### Methods

| Method | Description |
|--------|-------------|
| `set(key, value)` | Store a secret. Accepts `str`, `bytes`, or `bytearray`. |
| `delete(key) → bool` | Remove a secret. Returns `True` if it existed. |
| `list_keys() → list[str]` | List all key names (never values). |
| `run(command, ...) → RunResult` | Execute command with placeholder injection + redaction. |
| `export(out_path)` | Write encrypted vault backup to `out_path`. |
| `import_vault(path, overwrite=False, import_key_env=None) → tuple` | Import entries. Returns `(added, skipped, replaced)`. |
| `close()` | Zeroize all secrets and release resources. |

### Context Manager

```python
with secretsh.Vault(master_key_env="SECRETSH_KEY") as vault:
    # use vault
    pass
# close() called automatically
```

### RunResult

```python
result = vault.run("echo {{KEY}}", timeout_secs=60, max_output_bytes=10485760)
result.stdout      # str — decoded UTF-8 (lossy), secrets redacted
result.stderr      # str — decoded UTF-8 (lossy), secrets redacted
result.exit_code   # int — 0-255, 124 (timeout), 128+N (signal)
result.timed_out   # bool
```

## Secret Value Handling

The `set()` method accepts three types:

| Type | Behavior |
|------|----------|
| `bytearray` | **Preferred.** Copied to Rust heap, then source buffer zeroed in-place. |
| `str` | Converted to UTF-8 bytes. Source cannot be zeroed (Python strings are immutable). |
| `bytes` | Copied to Rust heap. Source cannot be zeroed (Python bytes are immutable). |

For maximum security, prefer `bytearray` or use the CLI `secretsh set` command (reads from stdin in Rust — value never enters Python).

## Memory Lifetime

Secrets stay on the **Rust heap** — they never cross the FFI boundary as Python `str`:

1. Values are decrypted into `Zeroizing<Vec<u8>>` in Rust
2. Placeholder substitution and Aho-Corasick pattern construction happen in Rust
3. Only redacted `RunResult` (stdout, stderr, exit_code) crosses into Python
4. `close()` or context manager exit triggers `zeroize` + `munlock` + `madvise`

`__del__` provides best-effort cleanup if `close()` is not called, but deterministic cleanup via `close()` or `with` is strongly recommended.

## GIL Release

All blocking operations release the Python GIL via `py.allow_threads()`:

- `Vault()` constructor (Argon2id KDF)
- `set()` / `delete()` (re-encryption + disk write)
- `run()` (child process spawn + output streaming)
- `export()` / `import_vault()` (KDF + re-encryption)

This prevents blocking the Python interpreter during operations that may take seconds.

## Exception Hierarchy

```
SecretSHError (base)
├── VaultNotFoundError      — vault file does not exist
├── VaultCorruptError       — HMAC/GCM verification failed
├── VaultPermissionError    — insecure file permissions
├── DecryptionError         — wrong passphrase
├── MasterKeyError          — env var not set
├── PlaceholderError        — unresolved {{KEY}}
├── TokenizationError       — rejected metacharacter or invalid key name
├── CommandError            — child spawn failed (not found, not executable)
├── EntryLimitError         — 10,000 entry limit exceeded
└── LockError               — lock acquisition timeout
```

All exceptions inherit from `secretsh.SecretSHError`.

## Internal Architecture

- `PyVault` wraps `Mutex<Option<Vault>>` for thread-safe interior mutability
- `close()` takes the inner vault via `Option::take()`
- `ensure_hardened()` calls `harden_process()` at most once via `AtomicBool`
- Error mapping: Rust `SecretshError` variants → typed Python exceptions
