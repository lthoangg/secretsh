//! End-to-end integration tests for the secretsh binary.
//!
//! Each test drives the compiled binary via [`assert_cmd::Command`] and checks
//! stdout, stderr, and exit code.  A fresh temporary `.env` file is written for
//! every test that needs one.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::NamedTempFile;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Write `content` to a temporary file and return the handle.
///
/// The handle must stay alive for the duration of the test; the file is deleted
/// when it is dropped.
fn env_file(content: &str) -> NamedTempFile {
    let f = NamedTempFile::new().expect("create temp env file");
    fs::write(f.path(), content).expect("write temp env file");
    f
}

/// Return a [`Command`] pre-configured with `--env <path>`.
fn cmd_with_env(env: &NamedTempFile) -> Command {
    let mut c = Command::cargo_bin("secretsh").expect("binary must be built");
    c.arg("--env").arg(env.path());
    c
}

// ─────────────────────────────────────────────────────────────────────────────
// Secret injection
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn secret_is_injected_into_argv() {
    let env = env_file("MY_SECRET=hunter2\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "echo", "{{MY_SECRET}}"])
        .assert()
        .success()
        // The raw secret must NOT appear in stdout.
        .stdout(predicate::str::contains("hunter2").not())
        // The redaction label must appear instead.
        .stdout(predicate::str::contains("[REDACTED_MY_SECRET]"));
}

#[test]
fn secret_embedded_in_larger_arg() {
    // Simulates: curl -u admin:{{PASS}} ...
    let env = env_file("PASS=s3cr3t\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "echo", "admin:{{PASS}}"])
        .assert()
        .success()
        .stdout(predicate::str::contains("s3cr3t").not())
        .stdout(predicate::str::contains("admin:[REDACTED_PASS]"));
}

#[test]
fn multiple_secrets_all_injected_and_redacted() {
    let env = env_file("USER=alice\nPASS=p4ssw0rd\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "echo", "{{USER}}:{{PASS}}"])
        .assert()
        .success()
        .stdout(predicate::str::contains("alice").not())
        .stdout(predicate::str::contains("p4ssw0rd").not())
        .stdout(predicate::str::contains("[REDACTED_USER]:[REDACTED_PASS]"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Unresolved placeholder — the key behaviour being tested
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unresolved_key_error_names_the_missing_key() {
    let env = env_file("OTHER_KEY=value\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "echo", "{{NINJA_API_KEY}}"])
        .assert()
        .failure()
        .code(125)
        .stderr(predicate::str::contains("NINJA_API_KEY"));
}

#[test]
fn unresolved_key_error_lists_available_keys() {
    let env = env_file("GITHUB_TOKEN=tok123\nOPENAI_KEY=sk-abc\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "echo", "{{MISSING_KEY}}"])
        .assert()
        .failure()
        .code(125)
        .stderr(predicate::str::contains("GITHUB_TOKEN"))
        .stderr(predicate::str::contains("OPENAI_KEY"));
}

#[test]
fn unresolved_key_error_does_not_leak_secret_values() {
    // The error message may list key *names* but must never print the values.
    let env = env_file("API_KEY=super_secret_value\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "echo", "{{MISSING}}"])
        .assert()
        .failure()
        .code(125)
        .stderr(predicate::str::contains("super_secret_value").not());
}

#[test]
fn unresolved_key_with_empty_env_file_says_no_keys() {
    let env = env_file("# just a comment\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "echo", "{{FOO}}"])
        .assert()
        .failure()
        .code(125)
        .stderr(predicate::str::contains("no keys"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Exit code passthrough
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn child_exit_code_zero_passed_through() {
    let env = env_file("K=v\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "true"])
        .assert()
        .code(0);
}

#[test]
fn child_exit_code_nonzero_passed_through() {
    let env = env_file("K=v\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "false"])
        .assert()
        .code(1);
}

#[test]
fn child_exit_code_arbitrary_passed_through() {
    // Pass "exit 42" as a single-quoted token so the tokenizer treats it as
    // one argv element, giving sh exactly: sh -c 'exit 42'
    let env = env_file("K=v\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "sh", "-c", "'exit 42'"])
        .assert()
        .code(42);
}

// ─────────────────────────────────────────────────────────────────────────────
// Command not found → 127
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn command_not_found_exits_127() {
    let env = env_file("K=v\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "__secretsh_no_such_binary__"])
        .assert()
        .code(127)
        .stderr(predicate::str::contains("not found"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Tokenizer rejection — unquoted metacharacter
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unquoted_pipe_is_rejected() {
    let env = env_file("K=v\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "echo", "foo", "|", "cat"])
        .assert()
        .failure()
        .code(125)
        .stderr(predicate::str::contains("|"));
}

#[test]
fn unquoted_redirect_is_allowed_as_literal() {
    // > and < are literal bytes in argv — posix_spawnp never redirects.
    // echo treats > as a literal character in its argument.
    let env = env_file("K=v\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "echo", "a>b"])
        .assert()
        .success()
        .stdout(predicate::str::contains("a>b"));
}

// ─────────────────────────────────────────────────────────────────────────────
// --no-shell flag
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn no_shell_blocks_sh() {
    let env = env_file("K=v\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--no-shell", "--", "sh", "-c", "echo hi"])
        .assert()
        .failure()
        .code(125)
        .stderr(predicate::str::contains("shell delegation blocked"));
}

#[test]
fn no_shell_blocks_bash() {
    let env = env_file("K=v\n");
    cmd_with_env(&env)
        .args([
            "run",
            "--quiet",
            "--no-shell",
            "--",
            "bash",
            "-c",
            "echo hi",
        ])
        .assert()
        .failure()
        .code(125)
        .stderr(predicate::str::contains("shell delegation blocked"));
}

#[test]
fn no_shell_allows_non_shell_binary() {
    let env = env_file("K=v\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--no-shell", "--", "echo", "hello"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello"));
}

// ─────────────────────────────────────────────────────────────────────────────
// --quiet flag suppresses audit JSON
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn quiet_suppresses_audit_json_on_stderr() {
    let env = env_file("K=v\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "echo", "hello"])
        .assert()
        .success()
        // The audit entry is a JSON object — no `{` on stderr in quiet mode.
        .stderr(predicate::str::contains("{\"op\"").not());
}

#[test]
fn without_quiet_audit_json_is_emitted_to_stderr() {
    let env = env_file("K=v\n");
    cmd_with_env(&env)
        .args(["run", "--", "echo", "hello"])
        .assert()
        .success()
        .stderr(predicate::str::contains("\"op\""))
        .stderr(predicate::str::contains("\"run\""));
}

// ─────────────────────────────────────────────────────────────────────────────
// Output redaction
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn secret_leaking_to_stdout_is_redacted() {
    // If the child echoes the secret back, it must be redacted.
    let env = env_file("TOKEN=supersecret99\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "echo", "{{TOKEN}}"])
        .assert()
        .success()
        .stdout(predicate::str::contains("supersecret99").not())
        .stdout(predicate::str::contains("[REDACTED_TOKEN]"));
}

#[test]
fn secret_leaking_to_stderr_is_redacted() {
    // Write the secret directly to /dev/stderr to avoid the `>` metacharacter.
    let env = env_file("ERR_SECRET=stderr_leak_42\n");
    cmd_with_env(&env)
        .args([
            "run",
            "--quiet",
            "--",
            "sh",
            "-c",
            "'echo stderr_leak_42 >/dev/stderr'",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("stderr_leak_42").not())
        .stderr(predicate::str::contains("[REDACTED_ERR_SECRET]"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Timeout → exit code 124
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn timeout_kills_child_and_exits_124() {
    let env = env_file("K=v\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--timeout", "1", "--", "sleep", "60"])
        .assert()
        .code(124);
}

// ─────────────────────────────────────────────────────────────────────────────
// .env file not found
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn missing_env_file_exits_125() {
    Command::cargo_bin("secretsh")
        .expect("binary must be built")
        .args([
            "--env",
            "/tmp/__secretsh_no_such_env_file__.env",
            "run",
            "--quiet",
            "--",
            "echo",
            "hi",
        ])
        .assert()
        .failure()
        .code(125);
}

// ─────────────────────────────────────────────────────────────────────────────
// Malformed placeholder
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn unclosed_placeholder_is_rejected() {
    let env = env_file("K=v\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "echo", "{{UNCLOSED"])
        .assert()
        .failure()
        .code(125)
        .stderr(predicate::str::contains("malformed placeholder"));
}

// ─────────────────────────────────────────────────────────────────────────────
// export prefix in .env is handled
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn export_prefix_in_env_file_is_stripped() {
    let env = env_file("export EXPORTED_KEY=exported_val\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "echo", "{{EXPORTED_KEY}}"])
        .assert()
        .success()
        .stdout(predicate::str::contains("exported_val").not())
        .stdout(predicate::str::contains("[REDACTED_EXPORTED_KEY]"));
}

// ─────────────────────────────────────────────────────────────────────────────
// Quoted values in .env
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn double_quoted_env_value_is_parsed() {
    let env = env_file("GREETING=\"hello world\"\n");
    cmd_with_env(&env)
        .args(["run", "--quiet", "--", "echo", "{{GREETING}}"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello world").not())
        .stdout(predicate::str::contains("[REDACTED_GREETING]"));
}
