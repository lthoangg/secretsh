# Architecture

secretsh is a single-crate Rust binary that injects secrets from a `.env` file into subprocess argv and redacts them from output.

## Execution Pipeline

```
Command string      "curl -H 'X-Api-Key: {{NINJA_API_KEY}}' 'https://api.example.com'"
        │
        ▼
┌──────────────┐
│  Tokenizer   │    Strict POSIX-subset parser.
│              │    Rejects unquoted | & ; ` ( * and expansion-trigger $.
│              │    Allows unquoted ? < > [ (literal bytes, no shell expansion).
│              │    Extracts {{KEY}} placeholders with byte offsets.
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ .env Parse   │    Reads KEY=value pairs from the .env file.
│ + Placeholder│    Resolves {{KEY}} → Zeroizing<Vec<u8>> values.
│  Resolution  │    Hard error if any key is missing — lists available keys.
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ --no-shell   │    Optional: rejects known shell interpreters as argv[0]
│   check      │    (sh, bash, zsh, dash, fish, ksh, mksh, tcsh, csh).
│              │    Checked by basename — /usr/bin/bash is also blocked.
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ posix_spawnp │    Direct exec (no sh -c). Argv zeroized after spawn.
│   (macOS)    │    FD_CLOEXEC on pipes. Signal forwarding (SIGINT/TERM/HUP).
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Aho-Corasick │    O(n) streaming redaction on stdout + stderr pipes only.
│ Output Filter│    Patterns: raw + base64 + base64url + URL-encoded + hex.
│              │    Does NOT redact files the child writes directly.
└──────┬───────┘
       │
       ▼
  Scrubbed output   "[REDACTED_NINJA_API_KEY]"
```

## Module Map

| File | Role | Security notes |
|------|------|---------------|
| `main.rs` | Entry: `harden_process()` → clap parse → run | Calls `harden` before anything else |
| `cli.rs` | Clap definitions + `run` handler | Tokenize → resolve → `--no-shell` check → spawn → redact. Audit log emits `key_count` only (never key names or values). |
| `error.rs` | `SecretshError` enum + `exit_code()` mapping | Exit codes follow GNU coreutils (124/125/126/127/128+N). `UnresolvedKey` lists available key names (never values). |
| `tokenizer.rs` | POSIX shell subset parser | **Primary attack surface.** Rejects unquoted `\|;&$()\`` and `*`. Allows `?<>[` as literal bytes. Quoted chars are always literal. See [tokenizer.md](tokenizer.md). |
| `dotenv.rs` | `.env` file parser | Supports KEY=value, export prefix, quoting, inline comments. |
| `redact.rs` | Aho-Corasick multi-pattern redaction | Generates patterns for raw + base64 + base64url + URL-encoded + hex(lower/upper). Only covers stdout/stderr pipes — files written by child are not redacted. |
| `spawn.rs` | `posix_spawnp` child process with pipe capture | **macOS only.** FD_CLOEXEC on pipes. argv[0] passed through redactor before appearing in spawn error messages. |
| `harden.rs` | `setrlimit(RLIMIT_CORE, 0)`, `mlock`, `madvise` | All failures are warnings, never hard errors. |

## Platform-Specific Spawning

### macOS (current implementation)

`posix_spawnp()` via the `libc` crate. This is Apple's recommended process
creation API — `fork()` in a multithreaded process is unsafe on macOS.
`posix_spawnp()` accepts the argv array directly; the parent retains ownership
of the `CString` values for zeroization after the call returns.

### Linux (not yet implemented)

`libc::fork()` + `libc::execvp()`. A Linux path would need `#[cfg(target_os)]`
gating.

## Process Hardening

At startup, before any secrets are loaded:

| Measure | Syscall | Purpose |
|---------|---------|---------|
| Disable core dumps | `setrlimit(RLIMIT_CORE, 0)` | Prevent secret data in core dumps |
| Lock secret pages | `mlock()` | Prevent kernel from swapping secrets to disk |
| Exclude from dumps | `madvise(MADV_FREE)` | Reclaim pages after zeroization |

All hardening failures are **warnings**, never hard errors. Some environments
(containers, sandboxed CI) cannot mlock.

## File Descriptor Hygiene

Pipes are opened with `FD_CLOEXEC` — automatically closed on exec in
unrelated children. The file actions for the target child explicitly dup2
the write-ends to fd 1/2 before closing the originals.

## Memory Management

All secret values are stored as `Zeroizing<Vec<u8>>`. When dropped, the memory
is zeroed. `mlock()` prevents secrets from being swapped to disk. After
processing, `madvise(MADV_FREE)` returns the pages to the kernel. The CString
argv is zeroized immediately after `posix_spawnp` returns — secrets exist in
the parent's address space only until the spawn call completes.

## Redaction Scope

Redaction covers what comes through the **stdout and stderr pipes**. It does
not cover:

- Files the child writes directly (e.g. via `sh -c 'echo {{K}} > file'`)
- Network traffic the child sends
- Other file descriptors the child opens

This is why `--no-shell` is essential: it prevents the child from being a
shell that can route secrets around the pipes entirely.
