# Threat Model

## The Core Problem

When an AI agent runs a shell command with embedded credentials (e.g.,
`curl -u admin:hunter2 ...`), three security failures occur:

1. **The LLM knows the secret** — it can be tricked into leaking it via prompt injection.
2. **Shell history records it** — the password is stored in `~/.bash_history`.
3. **Command output may echo it** — verbose flags (`curl -v`) or misconfigured services can echo credentials into stdout/stderr, which the LLM then ingests.

secretsh addresses (1) and (2) unconditionally. It addresses (3) partially — see the limitations below.

## Security Principles

- **Zero-Knowledge Prompting:** The agent only ever sees `{{PLACEHOLDER}}` tokens, never raw secret values.
- **No Shell Intermediary:** Commands are executed via direct `posix_spawnp` — not through `sh -c` — eliminating shell-level expansion of untrusted input, unless the agent explicitly invokes a shell binary.
- **No History Leakage:** Secrets are read from the `.env` file at exec time, never passed on the command line by the caller.
- **Memory Hygiene:** `zeroize::Zeroizing<Vec<u8>>` for all secret data. `mlock()` prevents swap-out. Core dumps disabled.
- **Actionable Errors:** Unresolved `{{KEY}}` placeholders list available key names (never values) so agents can self-correct without probing.

## In Scope (protected against)

| Threat | Mitigation |
|--------|-----------|
| Secret leakage via LLM prompt/context | Placeholder model — LLM never sees values |
| Secret leakage via shell history | Value read from .env file, never on command line |
| Secret leakage via stdout/stderr (exact match) | Aho-Corasick streaming redaction (raw + 5 encoded forms) |
| Secret leaked in spawn error messages | argv[0] is passed through the redactor before appearing in any error |
| Encoded secret leakage (base64, URL, hex) | Encoded variants included in redaction patterns |
| Shell-delegation oracle when `--no-shell` is set | `--no-shell` rejects known shell interpreters as argv[0] before any child process runs |
| Metadata leakage from audit logs | Key names and values omitted — only `key_count` is logged |
| Swap-out of secret pages | `mlock()` on supported platforms |
| Core dump inclusion | `RLIMIT_CORE=0` at startup |
| FD leakage to child processes | `FD_CLOEXEC` on pipes |

## Out of Scope (not protected against)

### Fundamental Limitations

| Threat | Reason |
|--------|--------|
| **Secrets at rest** | `.env` files are plain text. Protect with `chmod 600 .env`. If the agent can read the file directly (e.g. `cat .env`), it reads all secrets. |
| Secret in child argv (`/proc/<pid>/cmdline`) | Secrets are injected as command-line arguments. Any process with the same UID or root can read them during the child's lifetime. |
| Malicious child exfiltrating its own argv | A process can always read `/proc/self/cmdline`. secretsh cannot prevent this. |
| Files written by the child | If the child writes secrets to disk (e.g. via `sh -c 'echo {{K}} > file'`), those files contain raw values. secretsh only redacts stdout/stderr pipes. |
| Network traffic sent by the child | If the child sends secrets over the network directly, secretsh has no visibility. |
| Physical memory attacks (cold boot, kernel exploits) | Outside user-space control. |

### Redaction Limitations

Redaction is **substring matching** on raw bytes and five encoded forms. It has
inherent false-positive and false-negative risks:

| Issue | Behaviour |
|-------|-----------|
| Common secret values (`123456`, `password`) | Any occurrence of the secret string in child output is redacted — including unrelated log lines or counts. False positive — legitimate output is hidden. No fix within substring matching. |
| Secret in unrecognized encoding | Only raw, base64 (standard + URL-safe), URL percent-encoded, hex-lower, hex-upper are covered. A child that re-encodes in any other form (ROT13, custom base32, JSON unicode escapes) is not redacted. |
| Files written by child | Not redacted. Only stdout/stderr pipes are scanned. |
| `mlock` unavailable | Warning printed; execution continues without memory locking. |

### Oracle Attacks

An **oracle attack** is when an adversary (an AI agent controlling the command
string) infers secret values by observing secretsh's behaviour on probe
commands, without ever seeing raw secret bytes.

| Oracle | Status | Notes |
|--------|--------|-------|
| **Redaction side-channel** — `echo {{KEY}}==guess` | **Not fully closed.** If the guess matches the secret, output is `[REDACTED_KEY]==[REDACTED_KEY]`; if it doesn't, output is `[REDACTED_KEY]==wrongguess`. The difference leaks one bit per probe. No fix within substring redaction. | Only exploitable if the agent controls the command string. |
| **Shell conditional oracle** — `sh -c '[ "{{KEY}}" = guess ] && echo YES'` | **Closed by `--no-shell`.** Without `--no-shell`, this fully reveals the secret one guess at a time with no redaction. Shell can also write secrets to files, exfiltrate via network, etc. | `--no-shell` is **strongly recommended** for all AI-agent deployments. |
| **Prefix/substring oracle** — `sh -c 'case {{KEY}} in sk-*) echo YES ;; esac'` | **Closed by `--no-shell`.** Any shell conditional is blocked. | Requires shell delegation. |
| **File exfil oracle** — `sh -c 'echo {{KEY}} > /tmp/out'` | **Closed by `--no-shell`.** Without it, the file contains the raw secret. | Requires shell delegation. |

## Recommended Configuration for AI-Agent Contexts

```python
# Python wrapper — recommended defaults for agent tool
result = secretsh.run(
    env_file="/path/to/.env",
    command=command,          # agent-provided, with {{KEY}} placeholders
    no_shell=True,            # closes shell oracle attacks
    quiet=True,               # suppress audit JSON from agent context
    timeout=30,               # bound execution time
)
```

```bash
# CLI equivalent
secretsh --env /path/to/.env run \
  --no-shell \
  --quiet \
  --timeout 30 \
  -- COMMAND
```

- **`--no-shell`** closes all shell-delegation oracle attacks
- **`--timeout`** bounds how long a misbehaving command can run
- **`--quiet`** keeps audit JSON out of the agent's context
- The human operator, not the agent, should control `--env`, `--no-shell`, and `--timeout`

The redaction side-channel oracle cannot be closed by any flag. If this is a
concern, do not allow the agent to construct commands that compare secrets to
guesses (e.g. `echo {{KEY}}==guess`).

## Comparison

| Feature | secretsh | `.env` files | Cloud Secret Managers |
|---------|----------|-------------|----------------------|
| Execution model | Single binary, no daemon | File on disk | Requires server / cloud API |
| Primary target | Shell / CLI / subprocesses | App config | Service-to-service auth |
| Secret in `ps aux` | Yes (child argv) | Depends | N/A (HTTP delivery) |
| Secret in LLM context | Never (placeholder model) | Visible if in prompt | Visible if fetched into prompt |
| Output scrubbing | Partial (stdout/stderr pipes only, substring match) | None | None |
| Shell oracle protection | `--no-shell` flag | None | N/A |
| Complexity | Single binary | Text file | Infrastructure dependency |

secretsh is not a replacement for production secret managers. It fills a
specific gap: preventing credential leakage when AI agents execute shell
commands, with known limitations around substring redaction, oracle attacks,
and file/network exfiltration by the child process.
