# CLI Reference

All commands read the master passphrase from the `SECRETSH_KEY` environment variable by default. Use `--master-key-env <ENV_VAR>` to read from a different variable. The passphrase itself is never passed on the command line.

## Commands

### `secretsh init`

Create a new encrypted vault.

```bash
secretsh init
secretsh init --kdf-memory 65536
secretsh init --no-passphrase-check
```

| Flag | Description |
|------|-------------|
| `--master-key-env` | Env var holding the passphrase (default: `SECRETSH_KEY`) |
| `--vault` | Custom vault path (default: platform-specific) |
| `--kdf-memory` | Argon2id memory cost in KiB (default: 131072 / 128 MiB, minimum: 65536 / 64 MiB) |
| `--no-passphrase-check` | Skip minimum-length validation (12 chars) |

Exits with error if vault already exists at the target path.

### `secretsh set <KEY_NAME>`

Store a secret. Value read from **stdin** (never on the command line).

```bash
# Type the value interactively, then press Ctrl+D
secretsh set API_PASS

# Or pipe from a file (e.g. a PEM key)
secretsh set TLS_KEY < key.pem
```

- Reads until EOF (supports multi-line values like PEM keys)
- Strips a single trailing newline (accommodates `echo "value" | ...`)
- Key names must match `[A-Za-z_][A-Za-z0-9_]*`
- Binary values are accepted (vault stores raw bytes)

### `secretsh delete <KEY_NAME>`

Remove a secret from the vault.

```bash
secretsh delete API_PASS
```

### `secretsh list`

List key names (values are never displayed).

```bash
secretsh list
```

### `secretsh run -- "command"`

Execute a command with secret injection and output redaction.

```bash
secretsh run -- "curl -u {{USER}}:{{PASS}} https://example.com/api"

secretsh run --timeout 60 -- "curl -u admin:{{API_PASS}} https://internal/status"

secretsh run --quiet -- "echo {{SECRET}}"
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
secretsh export --out backup.vault.bin
```

The export is a complete vault file re-encrypted with a fresh salt and nonces.

### `secretsh import --in <PATH>`

Import entries from an exported vault.

```bash
secretsh import --in backup.vault.bin
secretsh import --in backup.vault.bin --overwrite
secretsh import --in backup.vault.bin --import-key-env BACKUP_KEY
```

| Flag | Description |
|------|-------------|
| `--overwrite` | Replace existing entries with imported values |
| `--import-key-env` | Env var for the import file's passphrase (if different) |

Reports: `N added, N skipped, N replaced`.

### `secretsh import-env -f <PATH>`

Import secrets from a `.env` file into the vault.

```bash
secretsh import-env -f .env
secretsh import-env -f .env --overwrite
```

| Flag | Description |
|------|-------------|
| `-f`, `--file` | Path to the `.env` file |
| `--overwrite` | Replace existing entries with imported values |

Supported `.env` syntax:

- `KEY=value` -- simple key-value
- `export KEY=value` -- optional `export` prefix (stripped)
- `KEY="value with spaces"` -- double-quoted (supports `\"`, `\\`, `\n`, `\t`, `\r` escapes)
- `KEY='literal value'` -- single-quoted (no escape processing)
- `# comment` -- comment lines (ignored)
- `KEY=value # comment` -- inline comments (stripped from unquoted values)
- Blank lines are ignored

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
| 1-125 | Child process exit code (passthrough) |
| 124 | Timeout or output limit exceeded (child killed) |
| 125 | secretsh internal error (vault, placeholder, tokenization, spawn failure) |
| 126 | Command found but not executable |
| 127 | Command not found |
| 128+N | Child killed by signal N (e.g., 137 = SIGKILL, 143 = SIGTERM) |

These follow GNU coreutils conventions (`timeout`, `env`).

## Security Notes

- Set the master passphrase env var in your shell session -- **never** inline on the command line (`SECRETSH_KEY=pass secretsh run ...` is recorded in shell history). Use `read -rs SECRETSH_KEY && export SECRETSH_KEY` instead.
- All audit entries are emitted to stderr as JSON Lines. Key names are never logged.
