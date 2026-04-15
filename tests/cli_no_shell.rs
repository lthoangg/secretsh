//! Integration tests for `secretsh run --no-shell`.
//!
//! Verifies that shell interpreters are blocked when `--no-shell` is set,
//! that non-shell binaries are still permitted, that absolute paths to shells
//! are also blocked, and that omitting the flag allows shell delegation.

use assert_cmd::Command;
use predicates::prelude::*;
use std::env;
use tempfile::TempDir;

// ─────────────────────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────────────────────

/// Initialise a fresh vault in a temp dir, import a single secret, and return
/// the (dir guard, vault_path, key_env_var_name) triple.
///
/// Uses a per-process-unique env var name to avoid cross-test interference.
fn init_vault_with_secret(secret_key: &str, secret_value: &str) -> (TempDir, String, String) {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("vault.bin").display().to_string();
    let key_var = format!("NO_SHELL_TEST_{}", std::process::id());

    env::set_var(&key_var, "test-passphrase-12chars");

    // Init vault.
    Command::cargo_bin("secretsh")
        .unwrap()
        .args([
            "init",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
            "--kdf-memory",
            "65536",
            "--no-passphrase-check",
        ])
        .assert()
        .success();

    // Import the secret via a temp .env file.
    let env_file = dir.path().join("test.env");
    std::fs::write(&env_file, format!("{secret_key}={secret_value}\n")).unwrap();

    Command::cargo_bin("secretsh")
        .unwrap()
        .args([
            "import-env",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
            "-f",
            env_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    (dir, vault_path, key_var)
}

// ─────────────────────────────────────────────────────────────────────────────
// --no-shell blocks known shell names
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn no_shell_blocks_sh() {
    let (_dir, vault_path, key_var) = init_vault_with_secret("MY_KEY", "s3cr3t");

    Command::cargo_bin("secretsh")
        .unwrap()
        .env(&key_var, "test-passphrase-12chars")
        .args([
            "run",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
            "--no-shell",
            "--",
            "sh",
            "-c",
            "echo {{MY_KEY}}",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("shell delegation blocked"))
        .stderr(predicate::str::contains("sh"));
}

#[test]
fn no_shell_blocks_bash() {
    let (_dir, vault_path, key_var) = init_vault_with_secret("MY_KEY", "s3cr3t");

    Command::cargo_bin("secretsh")
        .unwrap()
        .env(&key_var, "test-passphrase-12chars")
        .args([
            "run",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
            "--no-shell",
            "--",
            "bash",
            "-c",
            "echo hello",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("shell delegation blocked"))
        .stderr(predicate::str::contains("bash"));
}

#[test]
fn no_shell_blocks_zsh() {
    let (_dir, vault_path, key_var) = init_vault_with_secret("MY_KEY", "s3cr3t");

    Command::cargo_bin("secretsh")
        .unwrap()
        .env(&key_var, "test-passphrase-12chars")
        .args([
            "run",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
            "--no-shell",
            "--",
            "zsh",
            "-c",
            "echo hello",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("shell delegation blocked"));
}

#[test]
fn no_shell_blocks_dash() {
    let (_dir, vault_path, key_var) = init_vault_with_secret("MY_KEY", "s3cr3t");

    Command::cargo_bin("secretsh")
        .unwrap()
        .env(&key_var, "test-passphrase-12chars")
        .args([
            "run",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
            "--no-shell",
            "--",
            "dash",
            "-c",
            "echo hello",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("shell delegation blocked"));
}

// ─────────────────────────────────────────────────────────────────────────────
// --no-shell blocks shells invoked via absolute path
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn no_shell_blocks_absolute_path_to_sh() {
    let (_dir, vault_path, key_var) = init_vault_with_secret("MY_KEY", "s3cr3t");

    Command::cargo_bin("secretsh")
        .unwrap()
        .env(&key_var, "test-passphrase-12chars")
        .args([
            "run",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
            "--no-shell",
            "--",
            "/bin/sh",
            "-c",
            "echo hello",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("shell delegation blocked"))
        // The error names the basename, not the full path.
        .stderr(predicate::str::contains("sh"));
}

#[test]
fn no_shell_blocks_usr_bin_bash() {
    let (_dir, vault_path, key_var) = init_vault_with_secret("MY_KEY", "s3cr3t");

    Command::cargo_bin("secretsh")
        .unwrap()
        .env(&key_var, "test-passphrase-12chars")
        .args([
            "run",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
            "--no-shell",
            "--",
            "/usr/bin/bash",
            "-c",
            "echo hello",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("shell delegation blocked"));
}

// ─────────────────────────────────────────────────────────────────────────────
// --no-shell does NOT block non-shell binaries
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn no_shell_allows_echo() {
    let (_dir, vault_path, key_var) = init_vault_with_secret("MY_KEY", "s3cr3t_value");

    Command::cargo_bin("secretsh")
        .unwrap()
        .env(&key_var, "test-passphrase-12chars")
        .args([
            "run",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
            "--no-shell",
            "--",
            "echo",
            "{{MY_KEY}}",
        ])
        .assert()
        .success()
        // Secret is injected then redacted from output.
        .stdout(predicate::str::contains("[REDACTED_MY_KEY]"));
}

#[test]
fn no_shell_allows_true() {
    let (_dir, vault_path, key_var) = init_vault_with_secret("MY_KEY", "s3cr3t");

    Command::cargo_bin("secretsh")
        .unwrap()
        .env(&key_var, "test-passphrase-12chars")
        .args([
            "run",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
            "--no-shell",
            "--",
            "true",
        ])
        .assert()
        .success();
}

// ─────────────────────────────────────────────────────────────────────────────
// Without --no-shell, sh is permitted
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn without_no_shell_sh_is_permitted() {
    let (_dir, vault_path, key_var) = init_vault_with_secret("MY_KEY", "s3cr3t_value");

    // The -c script must be a single token as secretsh sees it.  We pass it
    // as one element to assert_cmd so the OS doesn't split it; secretsh's
    // tokenizer then keeps it as one argv element for sh.
    Command::cargo_bin("secretsh")
        .unwrap()
        .env(&key_var, "test-passphrase-12chars")
        .args([
            "run",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
            // --no-shell intentionally omitted
            "--",
            "sh",
            "-c",
            "echo hello", // assert_cmd passes this as a single OS arg to secretsh
        ])
        .assert()
        .success();
    // Note: we don't assert stdout contains "hello" because when assert_cmd
    // passes the args as separate OS-level arguments, secretsh joins them with
    // spaces and tokenizes: "sh -c echo hello" → 4 tokens → sh runs "echo"
    // with $0=hello (no output).  The important assertion is that sh itself
    // is not rejected (exit 0, no "shell delegation blocked" in stderr).
}

// ─────────────────────────────────────────────────────────────────────────────
// --no-shell closes the oracle: AI cannot probe secret via sh -c conditional
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn no_shell_blocks_oracle_probe_via_sh_conditional() {
    // This is the exact oracle pattern: an AI tries to infer whether
    // MY_KEY == "guess" by running a shell conditional whose output
    // ("yes" or "no") is not the secret and would not be redacted.
    // With --no-shell, the attempt is rejected before the child runs.
    //
    // We use "sh" as the binary name — secretsh must reject it before
    // tokenizing the -c argument, so the metacharacter in the script
    // never even gets parsed.
    let (_dir, vault_path, key_var) = init_vault_with_secret("MY_KEY", "s3cr3t");

    // Pass only "sh" as the command — the shell delegation check fires on
    // argv[0] before any argument processing, so we don't need to pass
    // a valid -c script to trigger the rejection.
    Command::cargo_bin("secretsh")
        .unwrap()
        .env(&key_var, "test-passphrase-12chars")
        .args([
            "run",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
            "--no-shell",
            "--",
            "sh",   // argv[0] = "sh" → blocked immediately
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("shell delegation blocked"))
        // Critically: no child ran, so stdout is empty.
        .stdout(predicate::str::is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────
// --no-shell exit code is 125 (internal secretsh error)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn no_shell_exit_code_is_125() {
    let (_dir, vault_path, key_var) = init_vault_with_secret("MY_KEY", "s3cr3t");

    Command::cargo_bin("secretsh")
        .unwrap()
        .env(&key_var, "test-passphrase-12chars")
        .args([
            "run",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
            "--no-shell",
            "--",
            "sh",
            "-c",
            "echo hello",
        ])
        .assert()
        .code(125);
}
