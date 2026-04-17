# Python API

secretsh provides a Python package (`secretsh`) that wraps the `secretsh` CLI binary.

## Install

```bash
pip install secretsh

# From source with dev dependencies (pytest)
cd python
pip install -e ".[dev]"
```

Requires Python 3.10+.

## Quick Start

```python
import secretsh

result = secretsh.run(".env", "echo {{API_KEY}}", quiet=True)

print(result.stdout)      # [REDACTED_API_KEY]
print(result.exit_code)   # 0
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
| `command` | Command string with `{{KEY}}` placeholders. | (required) |
| `timeout` | Max seconds before SIGTERM + SIGKILL. | 300 |
| `max_output` | Max stdout bytes before kill. | 50 MiB |
| `max_stderr` | Max stderr bytes before kill. | 1 MiB |
| `no_shell` | Block shell interpreters (recommended for AI agents). | False |
| `quiet` | Suppress audit output on stderr. | False |
| `verbose` | Show tokenization debug output. | False |

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
├── TokenizationError   — Command contains rejected metacharacters
├── PlaceholderError    — A {{KEY}} could not be resolved from the .env file
└── CommandError        — Binary not found, not executable, spawn failure, or shell blocked
```

All exceptions inherit from `secretsh.SecretSHError`.

## Binary Discovery

`secretsh.run()` locates the CLI binary in this order:

1. `target/debug/secretsh` or `target/release/secretsh` relative to the repo root (dev builds)
2. `/opt/homebrew/bin/secretsh`
3. `secretsh` on `PATH`
