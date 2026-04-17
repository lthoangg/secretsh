# CLI Reference

secretsh has a single command that reads secrets from a `.env` file.

## `secretsh --env <PATH> run -- "command"`

Execute a command with secret injection and output redaction.

```bash
secretsh --env .env run -- "curl -u {{USER}}:{{PASS}} https://example.com/api"

secretsh --env .env run --timeout 60 -- "curl -u admin:{{API_PASS}} https://internal/status"

secretsh --env .env run --quiet -- "echo {{SECRET}}"
```

### Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--env` | Path to the `.env` file (required) | — |
| `--timeout` | Kill child after N seconds | 300 |
| `--max-output` | Max stdout bytes before kill | 50 MiB |
| `--max-stderr` | Max stderr bytes before kill | 1 MiB |
| `--quiet` | Suppress audit JSON on stderr | false |
| `--verbose` | Show tokenization debug output | false |
| `--no-shell` | Reject shell interpreters as the command binary | false |

### `--no-shell`

Blocks `sh`, `bash`, `zsh`, `dash`, `fish`, `ksh`, `mksh`, `tcsh`, and `csh` — by basename, so both `bash` and `/usr/bin/bash` are rejected. Exits with code 125 if a shell is detected.

**Recommended for all AI-agent contexts.** Without this flag, an agent can construct shell conditionals to probe secret values:

```bash
# Without --no-shell: AI can infer the secret via conditional output
secretsh --env .env run -- sh -c "..."

# With --no-shell: rejected before any child process runs, exit 125
secretsh --env .env run --no-shell -- sh -c "..."
# → secretsh error: shell delegation blocked: "sh" is a shell interpreter

# Non-shell binaries are unaffected
secretsh --env .env run --no-shell -- curl -H "Authorization: {{TOKEN}}" https://api.example.com
```

Note: `--no-shell` closes the shell conditional oracle but does **not** close the redaction side-channel oracle. See `docs/threat-model.md` for details.

## .env File Format

Supported syntax:

- `KEY=value` — simple key-value
- `export KEY=value` — optional `export` prefix (stripped)
- `KEY="value with spaces"` — double-quoted (supports `\"`, `\\`, `\n`, `\t`, `\r` escapes)
- `KEY='literal value'` — single-quoted (no escape processing)
- `# comment` — comment lines (ignored)
- `KEY=value # comment` — inline comments (stripped from unquoted values)
- Blank lines are ignored

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (child exited 0) |
| 1-125 | Child process exit code (passthrough) |
| 124 | Timeout or output limit exceeded (child killed) |
| 125 | secretsh internal error (placeholder, tokenization, spawn failure) |
| 126 | Command found but not executable |
| 127 | Command not found |
| 128+N | Child killed by signal N (e.g., 137 = SIGKILL, 143 = SIGTERM) |

These follow GNU coreutils conventions (`timeout`, `env`).

## Security Notes

- `.env` files are plain text. Protect them with file permissions (`chmod 600 .env`).
- All audit entries are emitted to stderr as JSON Lines. Key names are never logged.
- Use `--no-shell` whenever secretsh is invoked by an AI agent. This prevents the agent from using `sh -c` conditionals to probe secret values.
- Output redaction is substring matching. If your secret value is a common string (e.g. `123456`, `true`, `yes`), expect false positives — unrelated output containing that string will also be redacted.
