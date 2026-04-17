# Testing

## Quick Reference

```bash
cargo test                           # all Rust unit tests (~1s)
cargo clippy -- -D warnings          # must be zero warnings
cargo fmt --check                    # rustfmt.toml: max_width=100

# Python tests (requires secretsh binary on PATH or in target/)
cd python
pip install -e ".[dev]"
pytest tests/ -v
```

## Rust Unit Tests

### By Module

| Module | Coverage |
|--------|----------|
| `tokenizer` | Valid splitting, quote handling, backslash escaping, metacharacter rejection, placeholder extraction, malformed/invalid placeholder detection, nested quotes, multi-byte UTF-8, real-world commands |
| `redact` | Single/multi-pattern, base64/URL/hex encoded, overlapping secrets, empty secrets, stream redaction, deduplication |
| `error` | Exit code mapping, error display messages, `ShellDelegationBlocked` |
| `dotenv` | Key/value parsing, quoted values, escape sequences, comments, blank lines, export prefix, error cases |
| `spawn` | Echo, exit code passthrough, command not found, stderr capture, secret redaction in output and error messages, timeout, output limit, signal handling |
| `harden` | Core dump disable, mlock/munlock, madvise |

## Python Tests

Python tests exercise the CLI subprocess wrapper (`secretsh/__init__.py`).

| Test Suite | What it verifies |
|------------|-----------------|
| `TestRunResult` | Data class fields and audit log parsing |
| `TestExceptions` | Exception hierarchy and raising/catching |
| `TestBasicExecution` | Simple echo, secret injection, multiple secrets, redaction |
| `TestErrorHandling` | Missing keys, empty `.env`, nonexistent `.env`, tokenization rejection |
| `TestOptions` | Timeout, max_output, no_shell (blocking shells), allowing non-shells |
| `TestPathHandling` | String vs Path objects, relative paths |
| `TestVerboseMode` | Audit log capture in verbose mode vs quiet mode |
| `TestStderrCapture` | Capturing stderr and non-zero exit codes |
| `TestEdgeCases` | Empty commands, special characters in values, unicode secrets |

## What Is Not Tested (Known Gaps)

| Gap | Notes |
|-----|-------|
| Redaction false positives | Substring matching causes false positives for common values (e.g. `123456`). |
| Secret in `/proc/<pid>/cmdline` | Secret is visible to processes with same UID or root during the child's lifetime. |
| Redaction completeness across chunk boundaries | Current implementation buffers full input; no streaming chunk boundary testing yet. |
| `mlock` failure path | Warning printed when mlock fails (e.g. in CI); not explicitly tested under resource limits. |
