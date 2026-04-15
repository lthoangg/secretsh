//! Integration tests for `secretsh set` — interactive-only enforcement.
//!
//! These tests use `assert_cmd` to invoke the real binary and verify that
//! piped stdin is rejected with an appropriate error message.

use assert_cmd::Command;
use predicates::prelude::*;
use std::env;
use tempfile::TempDir;

/// Helper: init a vault in a temp directory and return (dir, vault_path).
fn init_vault() -> (TempDir, String) {
    let dir = TempDir::new().unwrap();
    let vault_path = dir.path().join("vault.bin").display().to_string();

    // Ensure passphrase env var is set for tests.
    let key_var = format!("CLI_SET_TEST_{}", std::process::id());
    env::set_var(&key_var, "test-passphrase-12chars");

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

    (dir, vault_path)
}

#[test]
fn set_rejects_piped_stdin() {
    let (_dir, vault_path) = init_vault();
    let key_var = format!("CLI_SET_TEST_{}", std::process::id());

    Command::cargo_bin("secretsh")
        .unwrap()
        .args([
            "set",
            "MY_KEY",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
        ])
        .write_stdin("some-secret-value\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("interactive terminal"))
        .stderr(predicate::str::contains("import-env"));
}

#[test]
fn set_rejects_empty_pipe() {
    let (_dir, vault_path) = init_vault();
    let key_var = format!("CLI_SET_TEST_{}", std::process::id());

    Command::cargo_bin("secretsh")
        .unwrap()
        .args([
            "set",
            "MY_KEY",
            "--vault",
            &vault_path,
            "--master-key-env",
            &key_var,
        ])
        .write_stdin("")
        .assert()
        .failure()
        .stderr(predicate::str::contains("interactive terminal"));
}
