"""secretsh — Inject secrets from a .env file into subprocess arguments.

Usage:
    import secretsh

    secretsh.run(".env", "echo {{KEY}}")
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class RunResult:
    """Result of a command execution with redacted output."""

    stdout: str
    """Child process stdout (secrets redacted)."""

    stderr: str
    """Child process stderr (secrets redacted)."""

    exit_code: int
    """Child exit code (0-255), 124 if timeout, 128+N if killed by signal."""

    timed_out: bool
    """True if the child was killed due to timeout."""

    audit: dict | None
    """Audit log entry parsed from stderr (None if --quiet was used)."""


class SecretSHError(Exception):
    """Base exception for all secretsh errors."""

    pass


class TokenizationError(SecretSHError):
    """Command string contains rejected metacharacters."""

    pass


class PlaceholderError(SecretSHError):
    """A {{KEY}} placeholder could not be resolved."""

    pass


class CommandError(SecretSHError):
    """Child process spawn failure, timeout, or output limit exceeded."""

    pass


def _find_binary() -> Path:
    """Find secretsh binary."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    debug_binary = repo_root / "target" / "debug" / "secretsh"
    release_binary = repo_root / "target" / "release" / "secretsh"

    if debug_binary.exists() and os.access(debug_binary, os.X_OK):
        return debug_binary
    if release_binary.exists() and os.access(release_binary, os.X_OK):
        return release_binary

    path_binary = Path("/opt/homebrew/bin/secretsh")
    if path_binary.exists() and os.access(path_binary, os.X_OK):
        return path_binary

    return Path("secretsh")


def run(
    env_file: str | Path,
    command: str,
    *,
    timeout: int = 300,
    max_output: int = 52_428_800,
    max_stderr: int = 1_048_576,
    no_shell: bool = False,
    quiet: bool = False,
    verbose: bool = False,
) -> RunResult:
    """Run a command with secret injection and output redaction.

    Args:
        env_file: Path to the .env file containing secrets.
        command: Command string with {{KEY}} placeholders.
        timeout: Max seconds before SIGTERM + SIGKILL (default 300).
        max_output: Max stdout bytes before kill (default 50 MiB).
        max_stderr: Max stderr bytes before kill (default 1 MiB).
        no_shell: Block shell interpreters (recommended for AI agents).
        quiet: Suppress audit output on stderr.
        verbose: Show tokenization debug output.

    Returns:
        RunResult with stdout, stderr, exit_code, timed_out, and audit.

    Raises:
        TokenizationError: Command contains rejected metacharacters.
        PlaceholderError: A {{KEY}} was not found in the .env file.
        CommandError: Binary not found, not executable, or spawn failure.
        SecretSHError: General error.

    Example:
        >>> result = run(".env", "curl -u {{USER}}:{{PASS}} https://api.example.com")
        >>> print(result.stdout)
    """
    binary = _find_binary()
    env_file = str(env_file)

    cmd = [str(binary), "--env", env_file, "run"]
    if no_shell:
        cmd.append("--no-shell")
    if quiet:
        cmd.append("--quiet")
    if verbose:
        cmd.append("--verbose")
    cmd.extend(["--timeout", str(timeout)])
    cmd.extend(["--max-output", str(max_output)])
    cmd.extend(["--max-stderr", str(max_stderr)])
    cmd.extend(["--", command])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 10,  # Give a bit extra for overhead
        )
    except FileNotFoundError:
        raise SecretSHError(f"secretsh binary not found: {binary}")
    except subprocess.TimeoutExpired:
        raise CommandError("secretsh process timed out")

    # Parse stderr for audit log and errors
    stderr_lines = result.stderr.strip().split("\n")
    audit = None
    error_msg = ""

    for line in stderr_lines:
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
            if "op" in parsed and "ts" in parsed:
                audit = parsed
            else:
                error_msg += line + "\n"
        except json.JSONDecodeError:
            error_msg += line + "\n"

    if result.returncode == 127:
        raise CommandError(f"secretsh not found: {binary}")
    elif result.returncode == 125:
        error_lower = error_msg.lower()
        if "tokenization" in error_lower or "rejected" in error_lower:
            raise TokenizationError(error_msg.strip())
        elif "placeholder" in error_lower or "unresolved" in error_lower:
            raise PlaceholderError(error_msg.strip())
        elif (
            "not found" in error_lower
            or "not executable" in error_lower
            or "i/o error" in error_lower
            or "shell delegation blocked" in error_lower
        ):
            raise CommandError(error_msg.strip())
        else:
            raise SecretSHError(error_msg.strip())
    elif result.returncode == 124:
        timed_out = True
    else:
        timed_out = False

    return RunResult(
        stdout=result.stdout,
        stderr=result.stderr,
        exit_code=result.returncode,
        timed_out=timed_out,
        audit=audit,
    )


__all__ = [
    "run",
    "RunResult",
    "SecretSHError",
    "TokenizationError",
    "PlaceholderError",
    "CommandError",
]
