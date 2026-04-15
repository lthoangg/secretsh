# Threat Model

## The Core Problem

When an AI agent runs a shell command with embedded credentials (e.g., `curl -u admin:hunter2 ...`), three security failures occur:

1. **The LLM knows the secret** — it can be tricked into leaking it via prompt injection.
2. **Shell history records it** — the password is stored in `~/.bash_history`.
3. **Command output may echo it** — verbose flags (`curl -v`) or misconfigured services can echo credentials into stdout/stderr, which the LLM then ingests.

secretsh addresses all three by keeping secrets inside an encrypted vault, injecting them only at exec time (via direct `posix_spawnp`, not `sh -c`), and redacting any leakage from output.

## Security Principles

- **Zero-Knowledge Prompting:** The agent reasoning engine only ever sees placeholder strings, never raw secrets.
- **No Shell Intermediary:** Commands are executed via direct process spawning, not through `sh -c`, eliminating shell-level expansion of untrusted input.
- **No History Leakage:** Secrets never appear in shell history or LLM context.
- **Memory Hygiene:** `zeroize::Zeroizing<Vec<u8>>` for all secret data. Platform-specific syscalls avoid uncontrolled copies. `mlock()` prevents swap-out. Core dumps disabled.
- **At-Rest Encryption:** AES-256-GCM with Argon2id KDF and HKDF key separation. Key names are encrypted — the vault file reveals no metadata about stored secrets.
- **Key Separation:** HKDF-SHA256 derives independent subkeys for encryption and HMAC.

## In Scope (protected against)

| Threat | Mitigation |
|--------|-----------|
| Secret leakage via LLM prompt/context | Placeholder model — LLM never sees values |
| Secret leakage via shell history | Value read from stdin, never on command line |
| Secret leakage via stdout/stderr | Aho-Corasick streaming redaction (raw + encoded forms) |
| Encoded secret leakage (base64, URL, hex) | Encoded variants included in redaction patterns |
| Vault tampering | HMAC-authenticated header + per-entry GCM with positional AAD + full-file commit tag |
| Metadata leakage from vault file | Key names encrypted inside GCM ciphertext |
| Metadata leakage from audit logs | Key names omitted by default |
| Swap-out of secret pages | `mlock()` on supported platforms |
| Core dump inclusion | `RLIMIT_CORE=0` at startup |
| FD leakage to child processes | `O_CLOEXEC` on vault FD, lockfile FD, and pipes |

## Out of Scope (not protected against)

| Threat | Reason |
|--------|--------|
| `/proc/<pid>/cmdline` inspection by same-UID or root | Secret is in child argv for process lifetime — inherent to exec-based delivery |
| Physical memory attacks (cold boot, kernel exploits) | Outside user-space control |
| Malicious child exfiltrating its own argv | A process reading its own `/proc/self/cmdline` cannot be prevented |
| Compromise of the master passphrase | Orthogonal to vault encryption |
| Side-channel attacks on Argon2id / AES-256-GCM | Depends on underlying implementations (`argon2`, `ring`) |
| Swap-out when `mlock` unavailable | Warning printed; execution continues |
| Core dumps by external tools overriding rlimits | e.g., `gcore` run by root |
| Kernel-side argv copies during spawn | Outside user-space control on both Linux and macOS |
| Secrets in unrecognized encodings | Only raw, base64, base64url, URL-encoded, hex-lower, hex-upper are covered |

## Comparison

| Feature | secretsh | `.env` files | Cloud Secret Managers |
|---------|----------|-------------|----------------------|
| Execution model | Single binary, no daemon | File on disk | Requires server / cloud API |
| Primary target | Shell / CLI / subprocesses | App config | Service-to-service auth |
| Secret in `ps aux` | Yes (child argv) | Depends | N/A (HTTP delivery) |
| Secret in LLM context | Never (placeholder model) | Visible if in prompt | Visible if fetched into prompt |
| Output scrubbing | Active (Aho-Corasick) | None | None |
| Complexity | Single binary + vault file | Text file | Infrastructure dependency |

secretsh is not a replacement for production secret managers. It fills a specific gap: preventing credential leakage when AI agents execute shell commands.
