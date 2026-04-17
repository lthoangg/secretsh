# secretsh

**Inject secrets from a .env file into subprocess arguments for AI agents.**

[![CI](https://github.com/lthoangg/secretsh/actions/workflows/ci.yml/badge.svg)](https://github.com/lthoangg/secretsh/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/secretsh.svg)](https://crates.io/crates/secretsh)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Honest summary:** secretsh keeps secrets out of LLM context and shell history, and redacts them from stdout/stderr. It does **not** protect the `.env` file, hide secrets from the child process, or redact files the child writes directly. See [docs/threat-model.md](docs/threat-model.md).

```
Agent writes:  curl -H 'X-Api-Key: {{NINJA_API_KEY}}' 'https://api.example.com'
Child runs:    curl -H 'X-Api-Key: sk-realkey123' 'https://api.example.com'
Agent sees:    [{"result": "..."}]   ← [REDACTED_NINJA_API_KEY] if leaked in output
```

---

## Install

```bash
# CLI (Rust)
brew tap lthoangg/tap && brew install secretsh
# or: cargo install secretsh

# Python (wraps the CLI binary — install CLI first)
pip install secretsh
# or: uv add secretsh
```

Pre-built binaries: [GitHub Releases](https://github.com/lthoangg/secretsh/releases).

---

## Quick Start

```bash
echo 'NINJA_API_KEY=your-key-here' > .env && chmod 600 .env

secretsh --env .env run --no-shell --quiet -- \
  "curl -sS -H 'X-Api-Key: {{NINJA_API_KEY}}' 'https://api.api-ninjas.com/v2/quoteoftheday'"
```

```python
import secretsh

result = secretsh.run(
    ".env",
    "curl -sS -H 'X-Api-Key: {{NINJA_API_KEY}}' 'https://api.api-ninjas.com/v2/quoteoftheday'",
    no_shell=True, quiet=True,
)
print(result.stdout)  # [{"quote": "...", "author": "..."}]
```

### Agent Tool (LangChain)

```python
from langchain.tools import tool
import secretsh

@tool
def shell(command: str) -> str:
    """Run a command with secrets from .env. Use {{KEY_NAME}} placeholders.
    Single-quote arguments containing spaces, pipes, $ or &."""
    try:
        result = secretsh.run(".env", command, no_shell=True, quiet=True, timeout=30)
        return result.stdout or result.stderr
    except secretsh.PlaceholderError as e:
        return f"Secret not found: {e}"  # lists available key names
    except secretsh.TokenizationError as e:
        return f"Syntax error: {e}\nHint: wrap | $ & in single quotes."
    except secretsh.CommandError as e:
        return f"Command failed: {e}"
```

---

## Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--env` | required | Path to the `.env` file |
| `--no-shell` | off | Block `sh`/`bash`/`zsh`/etc. **Recommended for AI agents.** |
| `--timeout` | 300s | Kill child after N seconds |
| `--max-output` | 50 MiB | Kill child if stdout exceeds this |
| `--max-stderr` | 1 MiB | Kill child if stderr exceeds this |
| `--quiet` | off | Suppress audit JSON on stderr |
| `--verbose` | off | Show tokenization debug output |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1–125 | Child exit code (passthrough) |
| 124 | Timeout or output limit exceeded |
| 125 | secretsh error (tokenization, placeholder, shell blocked) |
| 126 / 127 | Not executable / not found |
| 128+N | Killed by signal N |

---

## Documentation

| Doc | Content |
|-----|---------|
| [docs/cli.md](docs/cli.md) | Flags, quoting guide, exit codes |
| [docs/python-api.md](docs/python-api.md) | `secretsh.run()` API, quoting guide, exceptions |
| [docs/tokenizer.md](docs/tokenizer.md) | Allowed/rejected chars, placeholder syntax |
| [docs/threat-model.md](docs/threat-model.md) | Security model, oracle attacks, limitations |
| [docs/architecture.md](docs/architecture.md) | Execution pipeline, module map |
| [docs/integrations/](docs/integrations/) | LangChain, PydanticAI, OpenClaw |
| [examples/](examples/) | LangChain demo, runnable examples |

---

## Development

```bash
cargo test && cargo clippy -- -D warnings && cargo fmt --check
cd python && PYTHONPATH=. pytest tests/ -v  # 39 Python tests
```

---

## License

[MIT](LICENSE) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)
