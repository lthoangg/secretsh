"""secretsh — Secure subprocess secret injection for AI agents.

Keeps credentials out of LLM context, shell history, and command output.
Secrets live in an AES-256-GCM encrypted vault; commands use ``{{KEY}}``
placeholders that are resolved at exec time with full output redaction.

Example::

    import secretsh

    with secretsh.Vault(master_key_env="SECRETSH_KEY") as vault:
        result = vault.run("curl -u {{USER}}:{{PASS}} https://api.example.com")
        print(result.stdout)   # secrets are redacted
        print(result.exit_code)
"""

from secretsh._native import (
    Vault,
    RunResult,
    SecretSHError,
    VaultNotFoundError,
    VaultCorruptError,
    VaultPermissionError,
    DecryptionError,
    MasterKeyError,
    PlaceholderError,
    TokenizationError,
    CommandError,
    EntryLimitError,
    LockError,
)

__all__ = [
    "Vault",
    "RunResult",
    "SecretSHError",
    "VaultNotFoundError",
    "VaultCorruptError",
    "VaultPermissionError",
    "DecryptionError",
    "MasterKeyError",
    "PlaceholderError",
    "TokenizationError",
    "CommandError",
    "EntryLimitError",
    "LockError",
]

__version__ = "0.1.0"
