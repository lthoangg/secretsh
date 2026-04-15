#!/usr/bin/env python3
"""
examples/basic_python.py — Basic secretsh Python API walkthrough.

Prerequisites:
    pip install secretsh
    # or: maturin develop --features python

Usage:
    export SECRETSH_KEY="your-master-passphrase-here"
    python examples/basic_python.py
"""

import os
import subprocess
import sys
import tempfile

import secretsh


def main():
    # ── Check prerequisites ───────────────────────────────────────────────
    key_env = "SECRETSH_KEY"
    if key_env not in os.environ:
        print(
            f'Set {key_env} first: export {key_env}="your-passphrase"', file=sys.stderr
        )
        sys.exit(1)

    # Use a temp directory so we don't touch the default vault
    tmpdir = tempfile.mkdtemp()
    vault_path = os.path.join(tmpdir, "vault.bin")

    try:
        # ── 1. Create vault (via CLI — Python API doesn't expose init) ────
        print("--- init (via CLI) ---")
        subprocess.run(
            [
                "secretsh",
                "init",
                "--master-key-env",
                key_env,
                "--vault",
                vault_path,
                "--kdf-memory",
                "65536",
            ],
            check=True,
            capture_output=True,
        )
        print(f"Vault created at {vault_path}\n")

        # ── 2. Store secrets ──────────────────────────────────────────────
        print("--- set secrets ---")
        with secretsh.Vault(master_key_env=key_env, vault_path=vault_path) as vault:
            # bytearray is preferred — secretsh zeroes it after copy
            vault.set("DB_PASS", bytearray(b"super-secret-password"))
            vault.set("DB_USER", "admin")
            vault.set("API_KEY", b"sk-live-abc123xyz")

            print(f"Keys: {vault.list_keys()}\n")

        # ── 3. Bytearray zeroing ─────────────────────────────────────────
        print("--- bytearray zeroing ---")
        with secretsh.Vault(master_key_env=key_env, vault_path=vault_path) as vault:
            secret = bytearray(b"temporary-secret")
            print(f"Before: {secret}")
            vault.set("TEMP", secret)
            print(f"After:  {secret}  (zeroed)")
            assert all(b == 0 for b in secret)
            print()

        # ── 4. Run commands ───────────────────────────────────────────────
        print("--- run (placeholder injection + redaction) ---")
        with secretsh.Vault(master_key_env=key_env, vault_path=vault_path) as vault:
            result = vault.run("echo {{DB_USER}}:{{DB_PASS}}")
            print(f"stdout: {result.stdout.strip()}")
            print(f"exit:   {result.exit_code}")
            # The actual values are replaced with [REDACTED_*]
            assert "[REDACTED_DB_USER]" in result.stdout
            assert "[REDACTED_DB_PASS]" in result.stdout
            print()

        print("--- run (incidental secret in output is caught) ---")
        with secretsh.Vault(master_key_env=key_env, vault_path=vault_path) as vault:
            result = vault.run("echo 'the password is super-secret-password'")
            print(f"stdout: {result.stdout.strip()}")
            assert "super-secret-password" not in result.stdout
            print()

        # ── 5. Timeout handling ───────────────────────────────────────────
        print("--- timeout ---")
        with secretsh.Vault(master_key_env=key_env, vault_path=vault_path) as vault:
            result = vault.run("sleep 30", timeout_secs=1)
            print(f"timed_out: {result.timed_out}")
            print(f"exit_code: {result.exit_code}  (124 = timeout)")
            print()

        # ── 6. Error handling ─────────────────────────────────────────────
        print("--- error handling ---")

        # Unresolved placeholder
        try:
            with secretsh.Vault(master_key_env=key_env, vault_path=vault_path) as vault:
                vault.run("echo {{MISSING_KEY}}")
        except secretsh.PlaceholderError as e:
            print(f"PlaceholderError: {e}")

        # Rejected metacharacter
        try:
            with secretsh.Vault(master_key_env=key_env, vault_path=vault_path) as vault:
                vault.run("echo foo | cat")
        except secretsh.TokenizationError as e:
            print(f"TokenizationError: {e}")

        # Vault not found
        try:
            secretsh.Vault(master_key_env=key_env, vault_path="/nonexistent/vault.bin")
        except secretsh.VaultNotFoundError as e:
            print(f"VaultNotFoundError: {e}")

        print()

        # ── 7. Export & import ────────────────────────────────────────────
        print("--- export / import ---")
        backup_path = os.path.join(tmpdir, "backup.vault.bin")

        with secretsh.Vault(master_key_env=key_env, vault_path=vault_path) as vault:
            vault.export(backup_path)
            print(f"Exported to {backup_path}")

            # Delete a key, then restore from backup
            vault.delete("TEMP")
            print(f"Keys after delete: {vault.list_keys()}")

        with secretsh.Vault(master_key_env=key_env, vault_path=vault_path) as vault:
            added, skipped, replaced = vault.import_vault(backup_path)
            print(f"Import: added={added}, skipped={skipped}, replaced={replaced}")
            print(f"Keys after import: {vault.list_keys()}")
            print()

        # ── 8. Context manager + close ────────────────────────────────────
        print("--- context manager ---")
        with secretsh.Vault(master_key_env=key_env, vault_path=vault_path) as vault:
            keys = vault.list_keys()
            print(f"Inside context: {keys}")
        # vault.close() called automatically on exit
        print("Context exited, vault closed and zeroized.")

        print("\nDone.")

    finally:
        import shutil

        shutil.rmtree(tmpdir)


if __name__ == "__main__":
    main()
