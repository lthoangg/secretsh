"""Tests for the secretsh Python bindings.

Each test creates an isolated vault in a temp directory and uses a unique
env-var name to avoid cross-test interference when pytest runs in parallel.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import secretsh

# ── Helpers ───────────────────────────────────────────────────────────────────

SECRETSH_BIN = Path(__file__).resolve().parents[1] / "target" / "debug" / "secretsh"

PASSPHRASE = "correct-horse-battery-staple"
KDF_MEMORY = "65536"  # 64 MiB — fast for tests


def _init_vault(vault_path: str, env_var: str) -> None:
    """Initialise a vault via the CLI (the Python API doesn't expose init)."""
    os.environ[env_var] = PASSPHRASE
    subprocess.run(
        [
            str(SECRETSH_BIN),
            "init",
            "--master-key-env",
            env_var,
            "--vault",
            vault_path,
            "--kdf-memory",
            KDF_MEMORY,
        ],
        check=True,
        capture_output=True,
    )


@pytest.fixture()
def vault_env(tmp_path):
    """Yield (vault_path, env_var) for an isolated, initialised vault."""
    vault_path = str(tmp_path / "vault.bin")
    env_var = f"PYTEST_KEY_{os.getpid()}"
    _init_vault(vault_path, env_var)
    yield vault_path, env_var
    # Cleanup env var
    os.environ.pop(env_var, None)


# ── Test: basic open / close ─────────────────────────────────────────────────


def test_open_and_close(vault_env):
    vault_path, env_var = vault_env
    vault = secretsh.Vault(master_key_env=env_var, vault_path=vault_path)
    assert vault.list_keys() == []
    vault.close()


def test_context_manager(vault_env):
    vault_path, env_var = vault_env
    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        assert vault.list_keys() == []
    # After exiting the context, the vault is closed.
    # Calling close() again is a no-op.
    vault.close()


# ── Test: set / list / delete ────────────────────────────────────────────────


def test_set_and_list(vault_env):
    vault_path, env_var = vault_env
    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        vault.set("KEY_A", "value_a")
        vault.set("KEY_B", b"value_b")
        keys = vault.list_keys()
    assert "KEY_A" in keys
    assert "KEY_B" in keys


def test_set_bytearray_is_zeroed(vault_env):
    """After set() with a bytearray, the source buffer should be all-zero."""
    vault_path, env_var = vault_env
    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        ba = bytearray(b"super-secret")
        vault.set("SECRET", ba)
        assert ba == bytearray(len(b"super-secret"))  # all zeros


def test_delete(vault_env):
    vault_path, env_var = vault_env
    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        vault.set("TO_DELETE", "value")
        assert "TO_DELETE" in vault.list_keys()
        removed = vault.delete("TO_DELETE")
        assert removed is True
        assert "TO_DELETE" not in vault.list_keys()


def test_delete_nonexistent(vault_env):
    vault_path, env_var = vault_env
    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        removed = vault.delete("NOPE")
        assert removed is False


# ── Test: run with redaction ─────────────────────────────────────────────────


def test_run_basic_redaction(vault_env):
    vault_path, env_var = vault_env
    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        vault.set("MY_SECRET", "hunter2")
        result = vault.run("echo {{MY_SECRET}}")
    assert result.exit_code == 0
    assert result.timed_out is False
    assert "[REDACTED_MY_SECRET]" in result.stdout
    assert "hunter2" not in result.stdout


def test_run_multiple_placeholders(vault_env):
    vault_path, env_var = vault_env
    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        vault.set("USER", "admin")
        vault.set("PASS", "s3cret")
        result = vault.run("echo {{USER}}:{{PASS}}")
    assert "[REDACTED_USER]" in result.stdout
    assert "[REDACTED_PASS]" in result.stdout
    assert "admin" not in result.stdout
    assert "s3cret" not in result.stdout


def test_run_no_placeholders(vault_env):
    vault_path, env_var = vault_env
    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        result = vault.run("echo hello world")
    assert result.stdout.strip() == "hello world"
    assert result.exit_code == 0


def test_run_exit_code_passthrough(vault_env):
    vault_path, env_var = vault_env
    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        result = vault.run("false")  # exits with code 1
    assert result.exit_code == 1


def test_run_timeout(vault_env):
    vault_path, env_var = vault_env
    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        result = vault.run("sleep 30", timeout_secs=1)
    assert result.timed_out is True
    assert result.exit_code == 124


# ── Test: error handling ─────────────────────────────────────────────────────


def test_vault_not_found():
    os.environ["PYTEST_KEY_NF"] = PASSPHRASE
    try:
        with pytest.raises(secretsh.VaultNotFoundError):
            secretsh.Vault(
                master_key_env="PYTEST_KEY_NF", vault_path="/tmp/no_such_vault.bin"
            )
    finally:
        os.environ.pop("PYTEST_KEY_NF", None)


def test_wrong_passphrase(vault_env):
    vault_path, _ = vault_env
    bad_var = f"PYTEST_BAD_{os.getpid()}"
    os.environ[bad_var] = "totally-wrong-passphrase!!"
    try:
        with pytest.raises(secretsh.SecretSHError):
            secretsh.Vault(master_key_env=bad_var, vault_path=vault_path)
    finally:
        os.environ.pop(bad_var, None)


def test_master_key_env_not_set(vault_env):
    vault_path, _ = vault_env
    # Use a vault that exists so the env-var check is reached
    # (not the vault-not-found check).
    with pytest.raises(secretsh.MasterKeyError):
        secretsh.Vault(
            master_key_env="THIS_VAR_DOES_NOT_EXIST_12345",
            vault_path=vault_path,
        )


def test_unresolved_placeholder(vault_env):
    vault_path, env_var = vault_env
    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        with pytest.raises(secretsh.PlaceholderError):
            vault.run("echo {{NONEXISTENT}}")


def test_tokenization_error_pipe(vault_env):
    vault_path, env_var = vault_env
    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        with pytest.raises(secretsh.TokenizationError):
            vault.run("echo foo | grep bar")


def test_tokenization_error_semicolon(vault_env):
    vault_path, env_var = vault_env
    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        with pytest.raises(secretsh.TokenizationError):
            vault.run("echo foo; echo bar")


def test_close_is_idempotent(vault_env):
    vault_path, env_var = vault_env
    vault = secretsh.Vault(master_key_env=env_var, vault_path=vault_path)
    vault.close()
    vault.close()  # should not raise
    vault.close()  # still no error


def test_operations_after_close_raise(vault_env):
    vault_path, env_var = vault_env
    vault = secretsh.Vault(master_key_env=env_var, vault_path=vault_path)
    vault.close()
    with pytest.raises(secretsh.SecretSHError, match="closed"):
        vault.list_keys()
    with pytest.raises(secretsh.SecretSHError, match="closed"):
        vault.set("KEY", "value")
    with pytest.raises(secretsh.SecretSHError, match="closed"):
        vault.run("echo hello")


# ── Test: exception hierarchy ────────────────────────────────────────────────


def test_all_exceptions_inherit_from_base():
    for exc_cls in [
        secretsh.VaultNotFoundError,
        secretsh.VaultCorruptError,
        secretsh.VaultPermissionError,
        secretsh.DecryptionError,
        secretsh.MasterKeyError,
        secretsh.PlaceholderError,
        secretsh.TokenizationError,
        secretsh.CommandError,
        secretsh.EntryLimitError,
        secretsh.LockError,
    ]:
        assert issubclass(exc_cls, secretsh.SecretSHError), (
            f"{exc_cls.__name__} does not inherit from SecretSHError"
        )


# ── Test: export / import ──────────────────────────────────────────────────────


def test_export_round_trip(vault_env, tmp_path):
    vault_path, env_var = vault_env
    export_path = str(tmp_path / "export.bin")

    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        vault.set("EXP_KEY", "exp_value")
        vault.export(export_path)

    assert Path(export_path).exists(), "export file should be created"

    with secretsh.Vault(master_key_env=env_var, vault_path=export_path) as exported:
        keys = exported.list_keys()
    assert "EXP_KEY" in keys


def test_import_adds_new_entries(vault_env, tmp_path):
    vault_path, env_var = vault_env
    export_path = str(tmp_path / "export.bin")

    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        vault.set("IMPORTED_KEY", "imported_value")
        vault.export(export_path)

    init_vault2 = str(tmp_path / "vault2.bin")
    env_var2 = f"PYTEST_KEY_IMPA_{os.getpid()}"
    _init_vault(init_vault2, env_var2)
    try:
        with secretsh.Vault(master_key_env=env_var2, vault_path=init_vault2) as vault2:
            added, skipped, replaced = vault2.import_vault(
                export_path, import_key_env=env_var
            )
        assert added == 1
        assert skipped == 0
        assert replaced == 0

        with secretsh.Vault(master_key_env=env_var2, vault_path=init_vault2) as vault2:
            assert "IMPORTED_KEY" in vault2.list_keys()
    finally:
        os.environ.pop(env_var2, None)


def test_import_skips_existing(vault_env, tmp_path):
    vault_path, env_var = vault_env
    export_path = str(tmp_path / "export.bin")

    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        vault.set("SHARED_KEY", "original_value")
        vault.export(export_path)

    init_vault2 = str(tmp_path / "vault2.bin")
    env_var2 = f"PYTEST_KEY_IMPS_{os.getpid()}"
    _init_vault(init_vault2, env_var2)
    try:
        with secretsh.Vault(master_key_env=env_var2, vault_path=init_vault2) as vault2:
            vault2.set("SHARED_KEY", "local_value")
            added, skipped, replaced = vault2.import_vault(
                export_path, import_key_env=env_var
            )
        assert added == 0
        assert skipped == 1
        assert replaced == 0
    finally:
        os.environ.pop(env_var2, None)


def test_import_overwrites_existing(vault_env, tmp_path):
    vault_path, env_var = vault_env
    export_path = str(tmp_path / "export.bin")

    with secretsh.Vault(master_key_env=env_var, vault_path=vault_path) as vault:
        vault.set("SHARED_KEY", "new_value")
        vault.export(export_path)

    init_vault2 = str(tmp_path / "vault2.bin")
    env_var2 = f"PYTEST_KEY_IMPO_{os.getpid()}"
    _init_vault(init_vault2, env_var2)
    try:
        with secretsh.Vault(master_key_env=env_var2, vault_path=init_vault2) as vault2:
            vault2.set("SHARED_KEY", "old_value")
            added, skipped, replaced = vault2.import_vault(
                export_path, overwrite=True, import_key_env=env_var
            )
        assert added == 0
        assert skipped == 0
        assert replaced == 1
    finally:
        os.environ.pop(env_var2, None)


def test_export_import_after_close_raises(vault_env, tmp_path):
    vault_path, env_var = vault_env
    export_path = str(tmp_path / "export.bin")
    vault = secretsh.Vault(master_key_env=env_var, vault_path=vault_path)
    vault.close()
    with pytest.raises(secretsh.SecretSHError, match="closed"):
        vault.export(export_path)
    with pytest.raises(secretsh.SecretSHError, match="closed"):
        vault.import_vault(export_path)
