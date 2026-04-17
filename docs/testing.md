# Testing

## Quick Reference

```bash
cargo test                           # 217 Rust tests (~1s)
cargo clippy -- -D warnings          # must be zero warnings
cargo fmt --check                    # rustfmt.toml: max_width=100

# Python tests (requires secretsh binary on PATH or in target/)
cd python
PYTHONPATH=. pytest tests/ -v        # 39 tests
```

## Rust Tests

### By Module

| Module | Test count | Coverage |
|--------|-----------|----------|
| `tokenizer` | ~60 | Valid splitting, quote handling, backslash escaping, metacharacter rejection (`\|&;`\`(*`), allowed literals (`?<>[`), placeholder extraction, malformed/invalid placeholder detection, nested quotes, multi-byte UTF-8, real-world commands (curl, jq, awk, grep) |
| `redact` | ~30 | Single/multi-pattern, base64/URL/hex encoded variants, overlapping secrets, empty secrets, stream redaction, deduplication |
| `error` | ~25 | Exit code mapping, display messages, `UnresolvedKey` with available-keys list, empty env file, `ShellDelegationBlocked` |
| `dotenv` | ~30 | KEY=value, export prefix, double/single-quoted values, escape sequences, inline comments, blank lines, error cases |
| `spawn` | ~15 | Echo, exit code passthrough, command not found (127), stderr capture, secret redaction in output and error messages, timeout (124), output limit (124), signal handling |
| `harden` | ~5 | Core dump disable, mlock/munlock, madvise |

### Integration Tests (`tests/e2e.rs`)

25 end-to-end tests using `assert_cmd` that drive the real compiled binary:

| Test | What it verifies |
|------|-----------------|
| `secret_is_injected_into_argv` | Placeholder resolved, raw value absent from stdout |
| `secret_embedded_in_larger_arg` | `admin:{{PASS}}` → `admin:[REDACTED_PASS]` |
| `multiple_secrets_all_injected_and_redacted` | Multiple placeholders in one command |
| `unresolved_key_error_names_the_missing_key` | Error message contains the missing key name |
| `unresolved_key_error_lists_available_keys` | Error message lists all keys in the .env file |
| `unresolved_key_error_does_not_leak_secret_values` | Available-keys list never shows values |
| `unresolved_key_with_empty_env_file_says_no_keys` | Empty .env gives "env file has no keys" |
| `child_exit_code_zero_passed_through` | exit 0 |
| `child_exit_code_nonzero_passed_through` | exit 1 |
| `child_exit_code_arbitrary_passed_through` | exit 42 via `sh -c 'exit 42'` |
| `command_not_found_exits_127` | Unknown binary → 127 |
| `unquoted_pipe_is_rejected` | `\|` rejected with exit 125 |
| `unquoted_redirect_is_allowed_as_literal` | `>` passes as literal byte (no shell) |
| `no_shell_blocks_sh` | `sh` blocked → exit 125 |
| `no_shell_blocks_bash` | `bash` blocked → exit 125 |
| `no_shell_allows_non_shell_binary` | `echo` passes with `--no-shell` |
| `quiet_suppresses_audit_json_on_stderr` | No `{"op":` on stderr |
| `without_quiet_audit_json_is_emitted_to_stderr` | Audit JSON present on stderr |
| `secret_leaking_to_stdout_is_redacted` | Child echoing secret → redacted |
| `secret_leaking_to_stderr_is_redacted` | Child writing secret to stderr → redacted |
| `timeout_kills_child_and_exits_124` | `sleep 60` with `--timeout 1` → 124 |
| `missing_env_file_exits_125` | Non-existent .env → 125 |
| `unclosed_placeholder_is_rejected` | `{{UNCLOSED` → 125 with "malformed" message |
| `export_prefix_in_env_file_is_stripped` | `export KEY=val` parsed correctly |
| `double_quoted_env_value_is_parsed` | `KEY="hello world"` parsed correctly |

## Python Tests

Python tests exercise the CLI subprocess wrapper (`secretsh/__init__.py`).

| Test Suite | What it verifies |
|------------|-----------------|
| `TestRunResult` | Data class fields and audit log parsing |
| `TestExceptions` | Exception hierarchy and raising/catching |
| `TestBasicExecution` | Simple echo, secret injection, multiple secrets, redaction |
| `TestErrorHandling` | Missing keys (with available-keys message), empty `.env`, nonexistent `.env`, tokenization rejection |
| `TestOptions` | Timeout, max_output, no_shell (blocking shells), allowing non-shells |
| `TestPathHandling` | String vs Path objects, relative paths |
| `TestVerboseMode` | Audit log capture in verbose mode vs quiet mode |
| `TestStderrCapture` | Capturing stderr and non-zero exit codes |
| `TestEdgeCases` | Empty commands, special characters in values, unicode secrets |

## What Is Not Tested (Known Gaps)

| Gap | Notes |
|-----|-------|
| Redaction false positives | Substring matching causes false positives for common values (e.g. `123456`). No unit test for this by design — it's a known model limitation. |
| Secret in `/proc/<pid>/cmdline` | Secret is visible to processes with same UID or root during the child's lifetime. Not tested — inherent to exec-based delivery. |
| Files written by child | Redaction does not cover files. If a child writes a secret to disk (e.g. via `sh -c 'echo {{K}} > file'`), the file contains the raw value. `--no-shell` prevents this. |
| `mlock` failure path | Warning printed when mlock fails (e.g. in CI); not explicitly tested under resource limits. |
| Fuzz testing | Tokenizer changes require fuzz testing before merge per AGENTS.md, but no automated fuzz harness is wired into CI yet. |
| Linux platform | All spawn tests run macOS `posix_spawnp`. A Linux `fork+execvp` path is not yet implemented. |
