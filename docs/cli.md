# CLI Reference

secretsh has a single command that reads secrets from a `.env` file.

## `secretsh --env <PATH> run [flags] -- <command>`

Execute a command with secret injection and output redaction.

```bash
# Basic usage
secretsh --env .env run -- "curl -u {{USER}}:{{PASS}} https://api.example.com"

# With timeout
secretsh --env .env run --timeout 60 -- "curl -u admin:{{API_PASS}} https://internal/status"

# Quiet mode (suppress audit JSON)
secretsh --env .env run --quiet -- "echo {{SECRET}}"

# Recommended for AI agents — blocks shell interpreters
secretsh --env .env run --no-shell --quiet -- "curl -sS -H 'X-Api-Key: {{NINJA_API_KEY}}' 'https://api.example.com/v1/data'"
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

Blocks `sh`, `bash`, `zsh`, `dash`, `fish`, `ksh`, `mksh`, `tcsh`, and `csh`
— by basename, so both `bash` and `/usr/bin/bash` are rejected. Exits with
code 125 if a shell is detected.

**Recommended for all AI-agent contexts.** Without this flag, an agent can
construct shell conditionals to probe secret values:

```bash
# Without --no-shell: agent can run sh -c to probe secrets
secretsh --env .env run -- sh -c "'[ \"{{KEY}}\" = guess ] && echo YES || echo NO'"
# → YES  (leaks one bit per probe, full secret via binary search)

# With --no-shell: rejected before any child process runs, exit 125
secretsh --env .env run --no-shell -- sh -c "'echo {{KEY}}'"
# → secretsh error: spawn error: shell delegation blocked: "sh" is a shell interpreter

# Non-shell binaries are unaffected
secretsh --env .env run --no-shell -- curl -H 'Authorization: {{TOKEN}}' https://api.example.com
```

Note: `--no-shell` closes the shell conditional oracle but does **not** close
the redaction side-channel oracle. See [docs/threat-model.md](threat-model.md)
for details.

## Quoting Guide

The command is parsed by secretsh's own tokenizer — not a shell. Write it as a
natural command string. Use single quotes for arguments containing spaces,
pipes, `$`, or `&`:

```bash
# Header with a space — single-quote the header value
secretsh --env .env run --no-shell -- "curl -H 'X-Api-Key: {{KEY}}' 'https://api.example.com'"

# jq filter with pipe and comparison — single-quote the filter
secretsh --env .env run --no-shell -- "jq '.[] | select(.score > 90)' data.json"

# awk with $ field reference — single-quote the awk program
secretsh --env .env run --no-shell -- "awk '\$2 > 10' file.txt"

# URL with & in query string — single-quote the URL
secretsh --env .env run --no-shell -- "curl 'https://api.example.com/search?q=hello&limit=10'"
```

**Important:** when calling from a shell, the parent shell strips quotes before
secretsh sees the command. Pass the entire command as a single double-quoted
string so that inner single quotes reach secretsh's tokenizer intact.

For actual piping, use the **parent shell** — not inside the command string:

```bash
# Correct: pipe at parent shell level, secretsh only runs curl
secretsh --env .env run --no-shell -- curl -sS -H 'X-Api-Key:\ {{KEY}}' 'https://api.example.com' | jq '.'

# Wrong: | inside the command string is rejected (would silently mis-behave if allowed)
secretsh --env .env run -- "curl ... | jq ."
# → secretsh error: tokenization error: rejected shell metacharacter '|'
```

## Unresolved Placeholder Errors

When a `{{KEY}}` placeholder is not found in the `.env` file, the error lists
all available keys so the issue is immediately actionable:

```
secretsh error: placeholder error: "NINJA_API_KEY" not found in env file;
  available keys: [DEMO_API_KEY, GITHUB_TOKEN, OPENAI_API_KEY]
```

If the `.env` file is empty or has no keys:

```
secretsh error: placeholder error: "NINJA_API_KEY" not found in env file;
  env file has no keys
```

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
| 1–125 | Child process exit code (passthrough) |
| 124 | Timeout or output limit exceeded (child killed) |
| 125 | secretsh internal error (placeholder, tokenization, spawn failure, shell blocked) |
| 126 | Command found but not executable |
| 127 | Command not found |
| 128+N | Child killed by signal N (e.g., 137 = SIGKILL, 143 = SIGTERM) |

These follow GNU coreutils conventions (`timeout`, `env`).

## Security Notes

- `.env` files are plain text. Protect them with `chmod 600 .env`.
- Audit entries are emitted to stderr as JSON Lines. Key names and values are never logged — only `key_count`.
- Use `--no-shell` whenever secretsh is invoked by an AI agent.
- Output redaction is substring matching. If your secret value is a common string (e.g. `123456`, `true`), unrelated output containing that string will also be redacted (false positive). There is no fix within the current model.
- Secrets are injected into the child's argv. Any process with the same UID or root can read them from `/proc/<pid>/cmdline` during the child's lifetime.
