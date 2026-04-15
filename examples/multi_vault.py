#!/usr/bin/env python3
"""
examples/multi_vault.py — Using multiple vaults for different environments.

Each vault has its own passphrase and entries. This is useful for separating
work, personal, staging, and production secrets.

Prerequisites:
    pip install secretsh

Usage:
    export STAGING_KEY="staging-passphrase-here"
    export PROD_KEY="production-passphrase-here"
    python examples/multi_vault.py
"""

import os
import subprocess
import sys
import tempfile

import secretsh


def main():
    staging_env = "STAGING_KEY"
    prod_env = "PROD_KEY"

    # Check env vars
    for env in [staging_env, prod_env]:
        if env not in os.environ:
            print(f'Set {env} first: export {env}="your-passphrase"', file=sys.stderr)
            sys.exit(1)

    tmpdir = tempfile.mkdtemp()
    staging_vault = os.path.join(tmpdir, "staging.vault")
    prod_vault = os.path.join(tmpdir, "prod.vault")

    try:
        # Create both vaults via CLI
        for path, env in [(staging_vault, staging_env), (prod_vault, prod_env)]:
            subprocess.run(
                [
                    "secretsh",
                    "init",
                    "--master-key-env",
                    env,
                    "--vault",
                    path,
                    "--kdf-memory",
                    "65536",
                ],
                check=True,
                capture_output=True,
            )

        # Populate staging
        print("--- Staging vault ---")
        with secretsh.Vault(
            master_key_env=staging_env, vault_path=staging_vault
        ) as vault:
            vault.set("API_URL", b"https://staging.example.com")
            vault.set("API_KEY", bytearray(b"staging-key-abc"))
            print(f"Keys: {vault.list_keys()}")

        # Populate production
        print("\n--- Production vault ---")
        with secretsh.Vault(master_key_env=prod_env, vault_path=prod_vault) as vault:
            vault.set("API_URL", b"https://api.example.com")
            vault.set("API_KEY", bytearray(b"prod-key-xyz-secret"))
            print(f"Keys: {vault.list_keys()}")

        # Run the same command against different vaults
        print("\n--- Same command, different vaults ---")
        cmd = "echo {{API_URL}} {{API_KEY}}"

        with secretsh.Vault(
            master_key_env=staging_env, vault_path=staging_vault
        ) as vault:
            result = vault.run(cmd)
            print(f"Staging: {result.stdout.strip()}")

        with secretsh.Vault(master_key_env=prod_env, vault_path=prod_vault) as vault:
            result = vault.run(cmd)
            print(f"Prod:    {result.stdout.strip()}")

        # Both outputs are redacted — the actual URLs and keys never appear
        print("\nBoth outputs are redacted. Secrets never reach the caller.")

    finally:
        import shutil

        shutil.rmtree(tmpdir)


if __name__ == "__main__":
    main()
