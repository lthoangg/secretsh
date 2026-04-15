# Threat Model

## The Core Problem

When an AI agent runs a shell command with embedded credentials (e.g., `curl -u admin:hunter2 ...`), three security failures occur:

1. **The LLM knows the secret** — it can be tricked into leaking it via prompt injection.
2. **Shell history records it** — the password is stored in `~/.bash_history`.
3. **Command output may echo it** — verbose flags (`curl -v`) or misconfigured services can echo credentials into stdout/stderr, which the LLM then ingests.

secretsh addresses (1) and (2) unconditionally. It addresses (3) partially — see the limitations below.

## Security Principles

- **Zero-Knowledge Prompting:** The agent reasoning engine only ever sees placeholder strings, never raw secrets.
- **No Shell Intermediary:** Commands are executed via direct process spawning (`posix_spawnp`), not through `sh -c`, eliminating shell-level expansion of untrusted input — unless the agent explicitly invokes a shell binary.
- **No History Leakage:** Secrets never appear in shell history or LLM context.
- **Memory Hygiene:** `zeroize::Zeroizing<Vec<u8>>` for all secret data. Platform-specific syscalls avoid uncontrolled copies. `mlock()` prevents swap-out. Core dumps disabled.
- **At-Rest Encryption:** AES-256-GCM with Argon2id KDF and HKDF key separation. Key names are encrypted — the vault file reveals no metadata about stored secrets.
- **Key Separation:** HKDF-SHA256 derives independent subkeys for encryption and HMAC.

## In Scope (protected against)

| Threat | Mitigation |
|--------|-----------|
| Secret leakage via LLM prompt/context | Placeholder model — LLM never sees values |
| Secret leakage via shell history | Value read from stdin, never on command line |
| Secret leakage via stdout/stderr (exact match) | Aho-Corasick streaming redaction (raw + 5 encoded forms) |
| Secret leaked in spawn error messages | argv[0] is passed through the redactor before appearing in any error |
| Encoded secret leakage (base64, URL, hex) | Encoded variants included in redaction patterns |
| Shell-delegation oracle when `--no-shell` is set | `--no-shell` rejects known shell interpreters as argv[0] before any child process runs |
| Vault tampering | HMAC-authenticated header + per-entry GCM with positional AAD + full-file commit tag |
| Metadata leakage from vault file | Key names encrypted inside GCM ciphertext |
| Metadata leakage from audit logs | Key names omitted from all audit entries |
| Swap-out of secret pages | `mlock()` on supported platforms |
| Core dump inclusion | `RLIMIT_CORE=0` at startup |
| FD leakage to child processes | `O_CLOEXEC` on vault FD, lockfile FD, and pipes |

## Out of Scope (not protected against)

### Fundamental Limitations

| Threat | Reason |
|--------|--------|
| Secret in child argv (`/proc/<pid>/cmdline`) | Secret is in child argv for its process lifetime — inherent to exec-based delivery. Any process with the same UID or root can read it. |
| Malicious child exfiltrating its own argv | A process can always read `/proc/self/cmdline`. secretsh cannot prevent this. |
| Physical memory attacks (cold boot, kernel exploits) | Outside user-space control. |
| Side-channel attacks on Argon2id / AES-256-GCM | Depends on underlying implementations (`argon2`, `ring`). |
| Kernel-side argv copies during spawn | Outside user-space control on both Linux and macOS. |

### Redaction Limitations

Redaction is **substring matching** on the raw secret bytes and five encoded forms. It has inherent false-positive and false-negative risks:

| Threat | Behaviour |
|--------|-----------|
| Common secret values (e.g. `123456`, `password`) | Any occurrence of the secret string in child output is redacted — including unrelated log lines, port numbers, counts, or any other content that happens to contain the same bytes. This is a false positive: legitimate output is hidden. There is no fix within a substring-matching model. |
| Secret in unrecognized encoding | Only raw, base64 (standard + URL-safe), URL percent-encoded, hex-lower, and hex-upper are covered. A child that re-encodes the secret in any other form (e.g. ROT13, custom base32, JSON unicode escapes) will not be redacted. |
| Swap-out when `mlock` unavailable | Warning printed; execution continues without memory locking. |
| Core dumps by external tools overriding rlimits | e.g. `gcore` run by root overrides `RLIMIT_CORE=0`. |

### Oracle Attacks

An **oracle attack** is when an adversary (here: an AI agent controlling the command string) can infer the value of a secret by observing how secretsh behaves on probe commands, without ever seeing the raw secret bytes.

| Oracle | Status | Notes |
|--------|--------|-------|
| **Redaction side-channel** — `echo {{KEY}}==guess` | **Not fully closed.** If the guess matches the secret, the output is `[REDACTED_KEY]==[REDACTED_KEY]`; if it doesn't match, the output is `[REDACTED_KEY]==wrongguess`. The difference reveals whether the guess matched. This leaks one bit per probe. No fix is possible within substring redaction without breaking legitimate use cases like `curl -H "Authorization: {{TOKEN}}"`. | Only exploitable if the AI controls the command string. |
| **Shell conditional oracle** — `sh -c '[ "{{KEY}}" = guess ] && echo yes'` | **Closed by `--no-shell`.** With `--no-shell`, shell interpreters are rejected before any child runs. Without `--no-shell`, this oracle fully reveals the secret value one guess at a time with no redaction. | `--no-shell` is **strongly recommended** for all AI-agent deployments. |
| **`--vault` flag after `--`** swallowed as argv | **Not a security issue, but confusing.** `secretsh run -- cmd --vault path` silently uses the default vault because `--vault path` is captured as part of the command. The error message ("HMAC mismatch" or "unresolved placeholder") does not hint at the cause. | Always place `--vault` before `--`. |

## Recommended Configuration for AI-Agent Contexts

```bash
# Minimum recommended flags when secretsh is invoked by an AI agent:
secretsh run \
  --vault /path/to/vault.bin \
  --no-shell \
  --timeout 30 \
  -- COMMAND {{ARGS}}
```

- `--no-shell` closes the shell conditional oracle
- `--timeout` bounds how long a misbehaving command can run
- The human operator, not the AI, should control `--vault` and `--no-shell`

The redaction side-channel oracle cannot be closed by any flag. If this is a concern, do not allow the AI to construct commands that compare secrets to guesses (e.g., restrict permitted binaries to a known allowlist via a wrapper script).

## Comparison

| Feature | secretsh | `.env` files | Cloud Secret Managers |
|---------|----------|-------------|----------------------|
| Execution model | Single binary, no daemon | File on disk | Requires server / cloud API |
| Primary target | Shell / CLI / subprocesses | App config | Service-to-service auth |
| Secret in `ps aux` | Yes (child argv) | Depends | N/A (HTTP delivery) |
| Secret in LLM context | Never (placeholder model) | Visible if in prompt | Visible if fetched into prompt |
| Output scrubbing | Partial (substring match only) | None | None |
| Shell oracle protection | `--no-shell` flag | None | N/A |
| Complexity | Single binary + vault file | Text file | Infrastructure dependency |

secretsh is not a replacement for production secret managers. It fills a specific gap: preventing credential leakage when AI agents execute shell commands, with known limitations around substring redaction and oracle attacks.
