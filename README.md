# secretsh

**Inject secrets from a .env file into subprocess arguments for AI agents.**

[![CI](https://github.com/lthoangg/secretsh/actions/workflows/ci.yml/badge.svg)](https://github.com/lthoangg/secretsh/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/secretsh.svg)](https://crates.io/crates/secretsh)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Honest summary:** secretsh prevents secrets from appearing in LLM context and shell history. It does **not** encrypt secrets at rest, hide them from the child process, or block filesystem access. If the agent can read the `.env` file or the child's argv, it can read the secrets.

AI agents write commands with `{{PLACEHOLDER}}` tokens. secretsh resolves them from a `.env` file at exec time and scrubs any secrets that leak back through output.

```
Agent writes:  curl -u admin:{{API_PASS}} https://internal/api
Child runs:    curl -u admin:hunter2 https://internal/api
Agent sees:    curl -u admin:[REDACTED_API_PASS] https://internal/api
```

---

## Install

### CLI (Rust binary)

```bash
# Homebrew
brew tap lthoangg/tap && brew install secretsh

# Cargo
cargo install secretsh
```

Pre-built binaries for `x86_64`/`aarch64` on macOS and Linux: [GitHub Releases](https://github.com/lthoangg/secretsh/releases).

### Python package

```bash
# pip
pip install secretsh

# uv
uv add secretsh
```

The Python package wraps the CLI binary — the `secretsh` binary must be installed separately (see above).

---

## Quick Start

### CLI

```bash
# Create a .env file
echo 'API_PASS=hunter2' > .env

# Run commands — secrets injected and scrubbed
secretsh --env .env run -- curl -u admin:{{API_PASS}} https://api.example.com
```

### Python

```python
import secretsh

result = secretsh.run(".env", "curl -u admin:{{API_PASS}} https://api.example.com")
print(result.stdout)      # curl output with [REDACTED_API_PASS] in place of the secret
print(result.exit_code)   # child process exit code
```

---

## Usage

```
secretsh --env <.env-file> run [flags] -- <command>
```

### Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--env` | required | Path to the `.env` file |
| `--no-shell` | off | Block `sh`/`bash`/`zsh`/etc. as argv[0]. **Recommended for AI agents.** |
| `--timeout` | 300s | Kill child after N seconds |
| `--max-output` | 50 MiB | Kill child if stdout exceeds this |
| `--max-stderr` | 1 MiB | Kill child if stderr exceeds this |
| `--quiet` | off | Suppress audit JSON on stderr |
| `--verbose` | off | Show tokenization debug output |

---

## What it does and does NOT

### Does

| | |
|--|--|
| **Keeps secrets out of LLM context** | Agent only ever sees `{{PLACEHOLDER}}`, never the value (assuming it can't read the `.env` file or child's argv) |
| **Keeps secrets out of shell history** | secretsh reads from the `.env` file, not the command line |
| **Scrubs output (best effort)** | Aho-Corasick substring redaction on stdout/stderr — raw, base64, URL-encoded, hex |
| **Blocks shell oracle attacks** | `--no-shell` rejects `sh`/`bash`/`zsh`/etc. before any child runs |

### Does NOT

| | |
|--|--|
| **Protect the .env file** | It's plain text on disk. If the agent can read the file (e.g. `cat .env`), it can read the secrets. Use `chmod 600 .env`. |
| **Block filesystem access** | If the agent has read access to `.env`, it can read secrets directly. |
| **Hide secrets from the child process** | Secrets are injected as command-line arguments. The child process can read `/proc/<pid>/cmdline` or the `.env` file to see them. Output redaction catches most cases, but not all. |
| **Stop prompt injection** | If the agent is tricked into running a malicious command, secretsh executes it |
| **Handle common-value false positives** | If your secret is `123456`, every `123456` in output is redacted |
| **Fully close the redaction oracle** | `echo {{KEY}}==guess` leaks one bit per probe |
| **Replace a secrets manager** | No access control, no rotation, no audit trail beyond local stderr JSON |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1–125 | Child exit code (passthrough) |
| 124 | Timeout or output limit exceeded |
| 125 | secretsh error (tokenization, shell blocked) |
| 126 | Command not executable |
| 127 | Command not found |
| 128+N | Child killed by signal N |

---

## Documentation

| Doc | Content |
|-----|---------|
| [docs/cli.md](docs/cli.md) | All flags, exit codes |
| [docs/threat-model.md](docs/threat-model.md) | Full security model, oracle attacks, known limitations |
| [docs/architecture.md](docs/architecture.md) | Execution pipeline, memory hardening |
| [docs/tokenizer.md](docs/tokenizer.md) | Quoting rules, placeholder syntax |
| [examples/](examples/) | Runnable examples |

---

## Development

```bash
cargo test                    # 187 tests
cargo clippy -- -D warnings  # must be zero warnings
cargo fmt --check
```

---

## License

[MIT](LICENSE) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)
