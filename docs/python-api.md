# Python API

secretsh provides a Python package (`secretsh`) that wraps the `secretsh` CLI binary.

## Install

```bash
pip install secretsh

# From source with dev dependencies (pytest)
cd python
pip install -e ".[dev]"
```

Requires Python 3.10+. The `secretsh` CLI binary must also be installed — the Python package is a wrapper around it.

## Quick Start

```python
import secretsh

result = secretsh.run(
    ".env",
    "curl -sS -H 'X-Api-Key: {{NINJA_API_KEY}}' 'https://api.api-ninjas.com/v2/quoteoftheday'",
    no_shell=True,
    quiet=True,
)
print(result.stdout)   # [{"quote": "...", "author": "..."}]
print(result.exit_code)  # 0
```

## `secretsh.run()`

```python
def run(
    env_file: str | Path,
    command: str,
    *,
    timeout: int = 300,
    max_output: int = 52_428_800,
    max_stderr: int = 1_048_576,
    no_shell: bool = False,
    quiet: bool = False,
    verbose: bool = False,
) -> RunResult:
```

| Argument | Description | Default |
|----------|-------------|---------|
| `env_file` | Path to the `.env` file containing secrets. | (required) |
| `command` | Command string with `{{KEY}}` placeholders. See quoting guide below. | (required) |
| `timeout` | Max wall-clock seconds before SIGTERM + SIGKILL. | 300 |
| `max_output` | Max stdout bytes before child is killed. | 50 MiB |
| `max_stderr` | Max stderr bytes before child is killed. | 1 MiB |
| `no_shell` | Block shell interpreters (`sh`, `bash`, `zsh`, …). **Recommended for AI agents.** | False |
| `quiet` | Suppress audit JSON on stderr. | False |
| `verbose` | Emit tokenization debug output on stderr. | False |

## Quoting Guide

The `command` string is passed directly to secretsh's tokenizer — it does
**not** go through a parent shell. This means single quotes inside the string
work as expected, with no double-wrapping needed:

```python
# Header with a space — single-quote the header value
secretsh.run(".env", "curl -H 'Authorization: Bearer {{TOKEN}}' https://api.example.com")

# jq filter with pipe and comparison — single-quote the filter
secretsh.run(".env", "jq '.results[] | select(.score > 90)' data.json")

# awk with $ field reference — single-quote the awk program
secretsh.run(".env", "awk '$2 > 10' file.txt")

# URL with & in query string — single-quote the URL
secretsh.run(".env", "curl 'https://api.example.com/search?q=hello&limit=10'")
```

**What is rejected unquoted:** `|`, `&`, `;`, `` ` ``, `(`, `*`, and `$`
followed by alphanumeric/`{`. These raise `TokenizationError` with an
actionable message. Wrap them in single quotes inside the command string.

**What is allowed unquoted:** `?`, `<`, `>`, `[` — these are literal bytes
in argv (no shell expansion occurs).

For actual piping, pass the secretsh output to another Python call or
subprocess — do not put `|` inside the command string:

```python
import subprocess, json

result = secretsh.run(".env", "curl -sS 'https://api.example.com/data'", no_shell=True, quiet=True)
parsed = json.loads(result.stdout)
```

## `RunResult`

| Attribute | Type | Description |
|-----------|------|-------------|
| `stdout` | `str` | Child process stdout (secrets redacted). |
| `stderr` | `str` | Child process stderr (secrets redacted). |
| `exit_code` | `int` | Child exit code (0–255), 124 if timeout, 128+N if killed by signal. |
| `timed_out` | `bool` | True if the child was killed due to timeout. |
| `audit` | `dict \| None` | Audit log entry parsed from stderr (None if `quiet=True`). |

## Exception Hierarchy

```
SecretSHError (base)
├── TokenizationError   — unquoted | & ; ` ( * or expansion-trigger $
│                         message includes the rejected character and byte offset
│                         fix: wrap the argument in single quotes
├── PlaceholderError    — {{KEY}} not found in .env file
│                         message lists all available key names (never values)
└── CommandError        — binary not found (127), not executable (126),
                          shell blocked by --no-shell (125), or spawn failure
```

All exceptions inherit from `secretsh.SecretSHError`.

### Handling errors in an agent tool

```python
import secretsh

def shell(command: str) -> str:
    try:
        result = secretsh.run("~/.secrets/.env", command, no_shell=True, quiet=True)
        output = result.stdout
        if result.stderr:
            output += result.stderr
        if result.exit_code != 0:
            output += f"\n[exit code: {result.exit_code}]"
        return output
    except secretsh.PlaceholderError as e:
        # e.g. '"NINJA_API_KEY" not found in env file; available keys: [DEMO_API_KEY, GITHUB_TOKEN]'
        return f"Secret not found: {e}"
    except secretsh.TokenizationError as e:
        return f"Command syntax error: {e}\nHint: wrap arguments containing | $ & in single quotes."
    except secretsh.CommandError as e:
        return f"Command failed: {e}"
```

## Binary Discovery

`secretsh.run()` locates the CLI binary in this order:

1. `target/debug/secretsh` relative to the repo root (dev builds)
2. `target/release/secretsh` relative to the repo root
3. `/opt/homebrew/bin/secretsh`
4. `secretsh` on `PATH`

## Known Limitations

- **Secrets in child argv:** Secrets are injected as command-line arguments. Any process with the same UID or root can read them from `/proc/<pid>/cmdline` during the child's lifetime.
- **Redaction is substring matching:** If your secret value appears in unrelated output (e.g. secret is `123`), that output is also redacted (false positive). No fix within the current model.
- **`|` inside command string does not pipe:** `|` is rejected unquoted. Even if quoted, it is passed as a literal byte to the binary — it does not create a pipe. Use Python's `subprocess` or chain `secretsh.run()` calls for piping.
- **Files written by the child are not redacted:** secretsh only redacts what comes through the stdout/stderr pipes. If the child writes secrets to a file directly, those files contain raw values.
