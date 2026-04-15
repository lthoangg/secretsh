# secretsh

**Secure subprocess secret injection for AI agents.**

[![CI](https://github.com/lthoangg/secretsh/actions/workflows/ci.yml/badge.svg)](https://github.com/lthoangg/secretsh/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/secretsh.svg)](https://crates.io/crates/secretsh)
[![PyPI](https://img.shields.io/pypi/v/secretsh.svg)](https://pypi.org/project/secretsh/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Beta.** Core functionality is stable and tested. Read [What it does NOT](#what-it-does-and-does-not) before deploying in sensitive environments.

AI agents write commands with `{{PLACEHOLDER}}` tokens. secretsh resolves them from an encrypted vault at exec time and scrubs any secrets that leak back through output.

```
Agent writes:  curl -u admin:{{API_PASS}} https://internal/api
Child runs:    curl -u admin:hunter2 https://internal/api
Agent sees:    curl -u admin:[REDACTED_API_PASS] https://internal/api
```

---

## What it does and does NOT

### Does

| | |
|--|--|
| **Keeps secrets out of LLM context** | Agent only ever sees `{{PLACEHOLDER}}`, never the value |
| **Keeps secrets out of shell history** | secretsh reads from an encrypted vault, not the command line |
| **Keeps secrets out of spawn errors** | `command not found: "[REDACTED]"` — never the raw value |
| **Scrubs output (best effort)** | Aho-Corasick substring redaction on stdout/stderr — raw, base64, URL-encoded, hex |
| **Blocks shell oracle attacks** | `--no-shell` rejects `sh`/`bash`/`zsh`/etc. before any child runs |
| **Encrypts at rest** | AES-256-GCM + Argon2id + HKDF — key names and values both encrypted |

### Does NOT

| | |
|--|--|
| **Stop prompt injection** | If the agent is tricked into running a malicious command, secretsh executes it |
| **Stop a child reading its own argv** | Secret is in the process's argv for its lifetime — visible in `/proc/<pid>/cmdline` |
| **Handle common-value false positives** | If your secret is `123456`, every `123456` in output is redacted — including unrelated content |
| **Fully close the redaction oracle** | `echo {{KEY}}==guess` leaks one bit per probe — if `==guess` is also redacted, the guess matched |
| **Replace a secrets manager** | No access control, no audit trail beyond local stderr JSON, no rotation |
| **Protect against a compromised passphrase** | If `SECRETSH_KEY` is stolen, the vault is open |

> **In short:** secretsh gives your AI agent the ability to use credentials without the credentials appearing in its context, history, or output — it does not stop a sufficiently adversarial agent from probing or exfiltrating. Use `--no-shell` to raise the bar.

---

## Install

```bash
# Homebrew
brew tap lthoangg/tap && brew install secretsh

# PyPI
uv add secretsh

# From source
cargo install secretsh
```

Pre-built binaries for `x86_64`/`aarch64` on macOS and Linux: [GitHub Releases](https://github.com/lthoangg/secretsh/releases).

---

## Quick Start

```bash
# 1. Set passphrase (silent, not saved to history)
read -rs SECRETSH_KEY && export SECRETSH_KEY

# 2. Create vault and import secrets
secretsh init
secretsh import-env -f .env

# 3. Run commands — secrets injected and scrubbed
secretsh run --no-shell -- curl -u "{{API_USER}}:{{API_PASS}}" https://api.example.com

# 4. List what's stored (values never shown)
secretsh list
```

---

## Commands

| Command | Description |
|---------|-------------|
| `secretsh init` | Create a new encrypted vault |
| `secretsh set <KEY>` | Store a secret (interactive hidden input) |
| `secretsh delete <KEY>` | Remove a secret |
| `secretsh list` | List key names (never values) |
| `secretsh run -- <cmd>` | Execute with secret injection + output redaction |
| `secretsh export --out <path>` | Export vault to encrypted backup |
| `secretsh import --in <path>` | Import entries from a backup |
| `secretsh import-env -f <path>` | Bulk import from a `.env` file |

All commands read the passphrase from `SECRETSH_KEY` by default. Use `--master-key-env <VAR>` to override.

### Key `run` flags

| Flag | Default | Purpose |
|------|---------|---------|
| `--no-shell` | off | Block `sh`/`bash`/`zsh`/`dash`/`fish`/`ksh`/`tcsh`/`csh` as argv[0]. **Recommended for AI agents.** |
| `--timeout` | 300s | Kill child after N seconds |
| `--max-output` | 50 MiB | Kill child if stdout exceeds this |
| `--quiet` | off | Suppress audit JSON on stderr |

---

## Python API

```python
import secretsh

with secretsh.Vault(master_key_env="SECRETSH_KEY") as vault:
    result = vault.run("curl -H 'Authorization: Bearer {{API_KEY}}' https://api.example.com")
    print(result.stdout)     # Bearer [REDACTED_API_KEY]
    print(result.exit_code)  # 0
```

See [docs/python-api.md](docs/python-api.md) for the full API reference.

---

## Documentation

| Doc | Content |
|-----|---------|
| [docs/cli.md](docs/cli.md) | All flags, exit codes, vault location |
| [docs/threat-model.md](docs/threat-model.md) | Full security model, oracle attacks, known limitations |
| [docs/architecture.md](docs/architecture.md) | Execution pipeline, crypto, memory hardening |
| [docs/testing.md](docs/testing.md) | Test inventory, known gaps |
| [examples/](examples/) | Runnable CLI and Python examples |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1–125 | Child exit code (passthrough) |
| 124 | Timeout or output limit exceeded |
| 125 | secretsh error (vault, tokenization, shell blocked) |
| 126 | Command not executable |
| 127 | Command not found |
| 128+N | Child killed by signal N |

---

## Development

```bash
cargo test                    # 233 tests (220 unit + 13 integration)
cargo clippy -- -D warnings   # must be zero warnings
cargo fmt --check

# Python bindings
maturin develop --features python
python -m pytest tests/ -v
```

---

## License

[MIT](LICENSE) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)
