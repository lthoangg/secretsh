"""Type stubs for secretsh — secure subprocess secret injection."""

from typing import Optional

__version__: str

class RunResult:
    """Result of a command execution with redacted output."""

    stdout: str
    """Child process stdout (UTF-8 lossy, secrets redacted)."""

    stderr: str
    """Child process stderr (UTF-8 lossy, secrets redacted)."""

    exit_code: int
    """Child exit code (0-255), 124 if timeout/limit, 128+N if killed by signal."""

    timed_out: bool
    """True if the child was killed due to timeout."""

class Vault:
    """Encrypted secret vault with placeholder injection and output redaction.

    Secrets are held exclusively on the Rust heap and never materialized as
    Python ``str`` objects. The only data crossing the FFI boundary is the
    already-redacted ``RunResult``.

    Use as a context manager for deterministic zeroization::

        with secretsh.Vault(master_key_env="SECRETSH_KEY") as vault:
            result = vault.run("curl -u {{USER}}:{{PASS}} https://api.example.com")
    """

    def __init__(
        self,
        master_key_env: str,
        vault_path: Optional[str] = None,
        allow_insecure_permissions: bool = False,
    ) -> None:
        """Open an existing vault.

        Args:
            master_key_env: Name of the environment variable holding the passphrase.
            vault_path: Path to the vault file. Uses platform default if None.
            allow_insecure_permissions: Skip file permission checks.

        Raises:
            VaultNotFoundError: Vault file does not exist.
            DecryptionError: Wrong passphrase.
            VaultCorruptError: HMAC/GCM verification failed.
            VaultPermissionError: Insecure file permissions.
            MasterKeyError: Environment variable not set.
        """
        ...

    def set(self, key: str, value: str | bytes | bytearray) -> None:
        """Store or update a secret.

        If ``value`` is a ``bytearray``, it is zeroed after copying to Rust.

        Args:
            key: Key name (must match ``[A-Za-z_][A-Za-z0-9_]*``).
            value: Secret value.

        Raises:
            EntryLimitError: Vault has 10,000 entries.
            SecretSHError: Vault is closed or I/O error.
        """
        ...

    def delete(self, key: str) -> bool:
        """Remove a secret. Returns True if the key existed.

        Raises:
            SecretSHError: Vault is closed or I/O error.
        """
        ...

    def list_keys(self) -> list[str]:
        """Return all key names. Values are never exposed.

        Raises:
            SecretSHError: Vault is closed.
        """
        ...

    def run(
        self,
        command: str,
        timeout_secs: int = 300,
        max_output_bytes: int = 52_428_800,
        max_stderr_bytes: int = 1_048_576,
    ) -> RunResult:
        """Execute a command with secret injection and output redaction.

        ``{{KEY}}`` placeholders in ``command`` are resolved against the vault.
        All output is scanned for secret values (raw, base64, URL-encoded, hex)
        and replaced with ``[REDACTED_KEY]``.

        Args:
            command: Shell command string with ``{{KEY}}`` placeholders.
            timeout_secs: Max seconds before SIGTERM + SIGKILL.
            max_output_bytes: Max stdout bytes before kill (default 50 MiB).
            max_stderr_bytes: Max stderr bytes before kill (default 1 MiB).

        Returns:
            RunResult with redacted stdout/stderr, exit code, and timeout flag.

        Raises:
            PlaceholderError: Unresolved ``{{KEY}}``.
            TokenizationError: Rejected shell metacharacter or malformed input.
            CommandError: Binary not found, not executable, or spawn failure.
            SecretSHError: Vault is closed or other error.
        """
        ...

    def export(self, out_path: str) -> None:
        """Export the vault to an encrypted backup file.

        The export is re-encrypted with a fresh salt and nonces using the same
        master passphrase.

        Args:
            out_path: Path to write the encrypted export file.

        Raises:
            SecretSHError: Vault is closed or export failed.
        """
        ...

    def import_vault(
        self,
        import_path: str,
        overwrite: bool = False,
        import_key_env: Optional[str] = None,
    ) -> tuple[int, int, int]:
        """Import entries from an encrypted export file.

        Args:
            import_path: Path to the encrypted vault file to import from.
            overwrite: Replace existing entries with imported values.
            import_key_env: Env var name for the import file's passphrase.
                Uses the current vault's passphrase if None.

        Returns:
            (added, skipped, replaced) counts.

        Raises:
            SecretSHError: Vault is closed or import failed.
        """
        ...

    def close(self) -> None:
        """Zeroize all secrets and release the vault. Idempotent."""
        ...

    def __enter__(self) -> "Vault": ...
    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None: ...
    def __del__(self) -> None: ...

# ── Exceptions ────────────────────────────────────────────────────────────────

class SecretSHError(Exception):
    """Base exception for all secretsh errors."""

    ...

class VaultNotFoundError(SecretSHError):
    """Vault file does not exist."""

    ...

class VaultCorruptError(SecretSHError):
    """HMAC, GCM, or structural integrity check failed."""

    ...

class VaultPermissionError(SecretSHError):
    """Vault file has insecure (group/world-readable) permissions."""

    ...

class DecryptionError(SecretSHError):
    """Wrong master passphrase."""

    ...

class MasterKeyError(SecretSHError):
    """Master key environment variable not set or passphrase too short."""

    ...

class PlaceholderError(SecretSHError):
    """Unresolved or malformed ``{{KEY}}`` placeholder."""

    ...

class TokenizationError(SecretSHError):
    """Rejected shell metacharacter or malformed command input."""

    ...

class CommandError(SecretSHError):
    """Child process spawn failure, timeout, or output limit exceeded."""

    ...

class EntryLimitError(SecretSHError):
    """Vault entry count limit (10,000) exceeded."""

    ...

class LockError(SecretSHError):
    """Vault advisory lock could not be acquired."""

    ...
