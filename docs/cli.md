# CLI Reference

All commands require `--master-key-env <ENV_VAR>` to specify which environment variable holds the passphrase. The passphrase itself is never passed on the command line.

## Commands

### `secretsh init`

Create a new encrypted vault.

```bash
secretsh init --master-key-env SECRETSH_KEY
secretsh init --master-key-env SECRETSH_KEY --kdf-memory 65536
secretsh init --master-key-env SECRETSH_KEY --no-passphrase-check
```

| Flag | Description |
|------|-------------|
| `--master-key-env` | Env var holding the passphrase |
| `--vault` | Custom vault path (default: platform-specific) |
| `--kdf-memory` | Argon2id memory cost in KiB (default: 131072 / 128 MiB, minimum: 65536 / 64 MiB) |
| `--no-passphrase-check` | Skip minimum-length validation (12 chars) |

Exits with error if vault already exists at the target path.

### `secretsh set <KEY_NAME>`

Store a secret. Value read from **stdin** (never on the command line).

```bash
echo -n "hunter2" | secretsh set API_PASS --master-key-env SECRETSH_KEY
printf '%s' "$(<key.pem)" | secretsh set TLS_KEY --master-key-env SECRETSH_KEY
```

- Reads until EOF (supports multi-line values like PEM keys)
- Strips a single trailing newline (accommodates `echo "value" | ...`)
- Key names must match `[A-Za-z_][A-Za-z0-9_]*`
- Binary values are accepted (vault stores raw bytes)

### `secretsh delete <KEY_NAME>`

Remove a secret from the vault.

```bash
secretsh delete API_PASS --master-key-env SECRETSH_KEY
```

### `secretsh list`

List key names (values are never displayed).

```bash
secretsh list --master-key-env SECRETSH_KEY
```

### `secretsh run -- "command"`

Execute a command with secret injection and output redaction.

```bash
secretsh run --master-key-env SECRETSH_KEY -- \
    "curl -u {{USER}}:{{PASS}} https://example.com/api"

secretsh run --master-key-env SECRETSH_KEY --timeout 60 -- \
    "curl -u admin:{{API_PASS}} https://internal/status"

secretsh run --master-key-env SECRETSH_KEY --quiet -- \
    "echo {{SECRET}}"
```

| Flag | Description | Default |
|------|-------------|---------|
| `--timeout` | Kill child after N seconds | 300 |
| `--max-output` | Max stdout bytes before kill | 50 MiB |
| `--max-stderr` | Max stderr bytes before kill | 1 MiB |
| `--quiet` | Suppress non-error output | false |

### `secretsh export --out <PATH>`

Export vault to an encrypted backup file.

```bash
secretsh export --master-key-env SECRETSH_KEY --out backup.vault.bin
```

The export is a complete vault file re-encrypted with a fresh salt and nonces.

### `secretsh import --in <PATH>`

Import entries from an exported vault.

```bash
secretsh import --master-key-env SECRETSH_KEY --in backup.vault.bin
secretsh import --master-key-env SECRETSH_KEY --in backup.vault.bin --overwrite
secretsh import --master-key-env SECRETSH_KEY --in backup.vault.bin --import-key-env BACKUP_KEY
```

| Flag | Description |
|------|-------------|
| `--overwrite` | Replace existing entries with imported values |
| `--import-key-env` | Env var for the import file's passphrase (if different) |

Reports: `N added, N skipped, N replaced`.

## There Is No `get` Command

This is deliberate. Secret values should never be displayed or piped to stdout. To verify a secret, set it again (overwriting) or run a test command with a placeholder and inspect the redacted output.

## Vault Location

| Platform | Default path |
|----------|-------------|
| macOS | `~/Library/Application Support/secretsh/vault.bin` |
| Linux | `$XDG_DATA_HOME/secretsh/vault.bin` |

Override with `--vault <path>` on any command.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (child exited 0) |
| 1–125 | Child process exit code (passthrough) |
| 124 | Timeout or output limit exceeded (child killed) |
| 125 | secretsh internal error (vault, placeholder, tokenization, spawn failure) |
| 126 | Command found but not executable |
| 127 | Command not found |
| 128+N | Child killed by signal N (e.g., 137 = SIGKILL, 143 = SIGTERM) |

These follow GNU coreutils conventions (`timeout`, `env`).

## Security Notes

- Set the master passphrase env var in your shell profile or process supervisor — **never** inline on the command line (`SECRETSH_KEY=pass secretsh run ...` is recorded in shell history).
- All audit entries are emitted to stderr as JSON Lines. Key names are never logged.
