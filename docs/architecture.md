# Architecture

secretsh is a single-crate Rust binary + library that injects secrets from an encrypted vault into subprocess argv and redacts them from output.

## Execution Pipeline

```
Command string      "curl -u admin:{{API_PASS}} https://example.com"
        │
        ▼
┌──────────────┐
│  Tokenizer   │    Strict POSIX-subset parser; rejects |;&$() etc.
│              │    Extracts {{KEY}} placeholders with byte offsets.
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Vault Decrypt│    AES-256-GCM + Argon2id KDF + HKDF key separation.
│ + Placeholder│    Resolves {{KEY}} → Zeroizing<Vec<u8>> values.
│  Resolution  │    Hard error if any key is missing.
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ posix_spawnp │    Direct exec (no sh -c). Argv zeroized after spawn.
│   (macOS)    │    FD_CLOEXEC on pipes, vault FD, lockfile FD.
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Aho-Corasick │    O(n) streaming redaction.
│ Output Filter│    Patterns: raw + base64 + base64url + URL + hex.
└──────┬───────┘
       │
       ▼
  Scrubbed output   "[REDACTED_API_PASS]"
```

## Module Map

| File | Role | Security notes |
|------|------|---------------|
| `main.rs` | Entry: `harden_process()` → clap parse → dispatch | Calls `harden` before anything else |
| `cli.rs` | Clap definitions + subcommand handlers | `run_run` does the full pipeline: tokenize → resolve → spawn → redact. `run_set` reads stdin via `read_to_end` + strips one trailing newline. Audit log emits `key_count` only (never key names). `cmd_template_hash`/`cmd_resolved_hash` on `run`. |
| `error.rs` | `SecretshError` enum + `exit_code()` mapping | Exit codes follow GNU coreutils (124/125/126/127/128+N). `TokenizationError::InvalidKeyName` for bad placeholder key names (distinct from `MalformedPlaceholder` which is for unclosed `{{`). |
| `tokenizer.rs` | POSIX shell subset parser | **Primary attack surface.** Rejects unquoted `\|;&$()` etc. Quoted chars are always literal. See [tokenizer.md](tokenizer.md). |
| `vault.rs` | AES-256-GCM vault, Argon2id KDF, HKDF key separation, export/import | Key names are encrypted. Every write re-encrypts with fresh salt. mlock on decrypted entries, O_CLOEXEC on all FDs. See [vault-format.md](vault-format.md). |
| `redact.rs` | Aho-Corasick multi-pattern redaction | Generates patterns for raw + base64 + base64url + URL-encoded + hex(lower/upper). Streaming redaction buffers entire input; bounded by spawn.rs output limit (default 50 MiB). |
| `spawn.rs` | `posix_spawnp` child process with pipe capture | **macOS only** — uses `posix_spawnp`, not `fork+exec`. FD_CLOEXEC on pipes, not `POSIX_SPAWN_CLOEXEC_DEFAULT` (breaks pipe dup2). |
| `harden.rs` | `setrlimit(RLIMIT_CORE, 0)`, `mlock`, `madvise` | All failures are warnings, never hard errors |
| `python.rs` | PyO3 bindings (feature-gated) | See [python-api.md](python-api.md). |

## Platform-Specific Spawning

### macOS (current implementation)

`posix_spawnp()` via the `libc` crate. This is Apple's recommended process creation API — `fork()` in a multithreaded process is unsafe on macOS per Apple's documentation (it can deadlock in system framework code). `posix_spawnp()` accepts the argv array directly, and the parent retains ownership of the `CString` values for zeroization after the call returns.

Pipes for stdout/stderr are configured via `posix_spawn_file_actions_t` before the spawn call.

### Linux (not yet implemented)

`libc::fork()` + `libc::execvp()`. After `fork()`, the child calls `execvp()` with the resolved argv. The parent retains ownership of the argv memory for zeroization. A Linux path would need `#[cfg(target_os)]` gating.

## Process Hardening

At startup, before any secrets are loaded:

| Measure | Syscall | Purpose |
|---------|---------|---------|
| Disable core dumps | `setrlimit(RLIMIT_CORE, 0)` | Prevent secret data in core dumps |
| Lock secret pages | `mlock()` | Prevent kernel from swapping secrets to disk |
| Exclude from dumps | `madvise(MADV_FREE)` | Reclaim pages after zeroization |

All hardening failures are **warnings**, never hard errors. Some environments (containers, sandboxed CI) cannot mlock, and refusing to operate would break legitimate use cases.

## File Descriptor Hygiene

- Vault FD: opened with `O_CLOEXEC` — automatically closed on exec
- Lockfile FD: opened with `O_CLOEXEC`
- Pipe FDs: `FD_CLOEXEC` set, then dup2'd for child stdin/stdout/stderr

## Memory Cleanup

After `posix_spawnp()` returns, all `CString` values containing resolved secrets are overwritten with zeroes via `zeroize::Zeroizing` before being dropped. Secret-containing pages are `mlock()`ed during use and `munlock()`ed after zeroization.

## Signal Forwarding

secretsh installs signal handlers for SIGINT, SIGTERM, and SIGHUP. When received, the signal is forwarded to the child process via `libc::kill()`. The handler uses only async-signal-safe operations (`AtomicI32::load` + `libc::kill`).

If the child does not exit within 5 seconds after SIGTERM, SIGKILL is sent. secretsh then exits with code `128 + signal_number`.

## Resource Limits

| Limit | Default | Flag | Python parameter |
|-------|---------|------|-----------------|
| Execution timeout | 300s | `--timeout` | `timeout_secs` |
| Max stdout | 50 MiB | `--max-output` | `max_output_bytes` |
| Max stderr | 1 MiB | `--max-stderr` | `max_stderr_bytes` |

Exceeding any limit triggers SIGTERM → 5s wait → SIGKILL escalation (exit code 124).

## Output Redaction

secretsh intercepts child stdout and stderr via pipes and scans for secret values using an Aho-Corasick multi-pattern automaton. Patterns are generated for each vault entry in these encodings:

| Encoding | Redaction label | Example |
|----------|----------------|---------|
| Raw bytes | `[REDACTED_KEY]` | `hunter2` → `[REDACTED_API_PASS]` |
| Base64 (standard) | `[REDACTED_KEY_B64]` | `aHVudGVyMg==` → `[REDACTED_API_PASS_B64]` |
| Base64 (URL-safe) | `[REDACTED_KEY_B64URL]` | `aHVudGVyMg` → `[REDACTED_API_PASS_B64URL]` |
| URL / percent-encoding | `[REDACTED_KEY_URL]` | `hunter%32` → `[REDACTED_API_PASS_URL]` |
| Hex (lowercase) | `[REDACTED_KEY_HEX]` | `68756e74657232` → `[REDACTED_API_PASS_HEX]` |
| Hex (uppercase) | `[REDACTED_KEY_HEX]` | `68756E74657232` → `[REDACTED_API_PASS_HEX]` |

Encoded patterns are only generated when the encoded form differs from the raw value. The current implementation buffers entire input in memory before replacement — bounded by the spawn.rs output limit (default 50 MiB).

## Audit Logging

secretsh writes JSON Lines to stderr for security-relevant operations:

```json
{"ts":"2025-01-15T10:30:00Z","op":"run","key_count":2,"cmd_template_hash":"sha256:aaa...","cmd_resolved_hash":"sha256:bbb..."}
```

Key names are **never** logged (the vault encrypts them for a reason). Only `key_count` is emitted.
