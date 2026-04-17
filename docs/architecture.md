# Architecture

secretsh is a single-crate Rust binary that injects secrets from a `.env` file into subprocess argv and redacts them from output.

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
│ .env Parse   │    Reads KEY=value pairs from the .env file.
│ + Placeholder│    Resolves {{KEY}} → Zeroizing<Vec<u8>> values.
│  Resolution  │    Hard error if any key is missing.
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ posix_spawnp │    Direct exec (no sh -c). Argv zeroized after spawn.
│   (macOS)    │    FD_CLOEXEC on pipes.
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
| `main.rs` | Entry: `harden_process()` → clap parse → run | Calls `harden` before anything else |
| `cli.rs` | Clap definitions + `run` handler | Tokenize → resolve → `--no-shell` check → spawn → redact. `--no-shell` rejects known shell interpreters by argv[0] basename before any child process runs. Audit log emits `key_count` only (never key names). |
| `error.rs` | `SecretshError` enum + `exit_code()` mapping | Exit codes follow GNU coreutils (124/125/126/127/128+N). |
| `tokenizer.rs` | POSIX shell subset parser | **Primary attack surface.** Rejects unquoted `\|;&$()` etc. Quoted chars are always literal. See [tokenizer.md](tokenizer.md). |
| `dotenv.rs` | `.env` file parser | Supports KEY=value, export prefix, quoting, comments. |
| `redact.rs` | Aho-Corasick multi-pattern redaction | Generates patterns for raw + base64 + base64url + URL-encoded + hex(lower/upper). Streaming redaction buffers entire input; bounded by spawn.rs output limit (default 50 MiB). |
| `spawn.rs` | `posix_spawnp` child process with pipe capture | **macOS only** — uses `posix_spawnp`. FD_CLOEXEC on pipes. argv[0] is passed through the redactor before appearing in any spawn error message. |
| `harden.rs` | `setrlimit(RLIMIT_CORE, 0)`, `mlock`, `madvise` | All failures are warnings, never hard errors. |

## Platform-Specific Spawning

### macOS (current implementation)

`posix_spawnp()` via the `libc` crate. This is Apple's recommended process creation API — `fork()` in a multithreaded process is unsafe on macOS per Apple's documentation. `posix_spawnp()` accepts the argv array directly, and the parent retains ownership of the `CString` values for zeroization after the call returns.

### Linux (not yet implemented)

`libc::fork()` + `libc::execvp()`. A Linux path would need `#[cfg(target_os)]` gating.

## Process Hardening

At startup, before any secrets are loaded:

| Measure | Syscall | Purpose |
|---------|---------|---------|
| Disable core dumps | `setrlimit(RLIMIT_CORE, 0)` | Prevent secret data in core dumps |
| Lock secret pages | `mlock()` | Prevent kernel from swapping secrets to disk |
| Exclude from dumps | `madvise(MADV_FREE)` | Reclaim pages after zeroization |

All hardening failures are **warnings**, never hard errors. Some environments (containers, sandboxed CI) cannot mlock, and refusing to operate would break legitimate use cases.

## File Descriptor Hygiene

- Pipes: opened with `O_CLOEXEC` — automatically closed on exec

## Memory Management

All secret values are stored as `Zeroizing<Vec<u8>>`. When dropped, the memory is zeroed. `mlock()` prevents secrets from being swapped to disk. After processing, `madvise(MADV_FREE)` returns the pages to the kernel for reuse.
