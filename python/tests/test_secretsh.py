"""Tests for secretsh Python package."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from secretsh import (
    CommandError,
    PlaceholderError,
    RunResult,
    SecretSHError,
    TokenizationError,
    run,
)


class TestRunResult:
    """Tests for RunResult dataclass."""

    def test_run_result_creation(self):
        """Test RunResult can be created with all fields."""
        result = RunResult(
            stdout="hello",
            stderr="",
            exit_code=0,
            timed_out=False,
            audit=None,
        )
        assert result.stdout == "hello"
        assert result.exit_code == 0
        assert result.timed_out is False
        assert result.audit is None

    def test_run_result_with_audit(self):
        """Test RunResult with audit data."""
        audit_data = {"op": "exec", "ts": "2024-01-01T00:00:00Z"}
        result = RunResult(
            stdout="output",
            stderr='{"op": "exec", "ts": "2024-01-01T00:00:00Z"}',
            exit_code=0,
            timed_out=False,
            audit=audit_data,
        )
        assert result.audit is not None
        assert result.audit["op"] == "exec"


class TestExceptions:
    """Tests for exception hierarchy."""

    def test_exception_hierarchy(self):
        """Test that all exceptions inherit from SecretSHError."""
        assert issubclass(TokenizationError, SecretSHError)
        assert issubclass(PlaceholderError, SecretSHError)
        assert issubclass(CommandError, SecretSHError)

    def test_can_raise_and_catch_exceptions(self):
        """Test exceptions can be raised and caught."""
        with pytest.raises(SecretSHError):
            raise SecretSHError("test")

        with pytest.raises(TokenizationError):
            raise TokenizationError("rejected")

        with pytest.raises(PlaceholderError):
            raise PlaceholderError("not found")

        with pytest.raises(CommandError):
            raise CommandError("spawn failed")


class TestBasicExecution:
    """Tests for basic command execution."""

    def test_simple_echo(self, temp_env_file):
        """Test simple echo command with secret injection."""
        result = run(temp_env_file, "echo hello world", quiet=True)
        assert result.exit_code == 0
        assert "hello world" in result.stdout

    def test_secret_injection(self, temp_env_file):
        """Test secret placeholder is replaced and output redacted."""
        result = run(temp_env_file, "echo {{TEST_SECRET}}", quiet=True)
        assert result.exit_code == 0
        assert "hunter2" not in result.stdout
        assert "[REDACTED_TEST_SECRET]" in result.stdout

    def test_multiple_secrets(self, temp_env_file):
        """Test multiple secrets are injected and redacted."""
        result = run(temp_env_file, "echo {{TEST_SECRET}} and {{API_KEY}}", quiet=True)
        assert result.exit_code == 0
        assert "hunter2" not in result.stdout
        assert "sk-test-12345" not in result.stdout
        assert "[REDACTED_TEST_SECRET]" in result.stdout
        assert "[REDACTED_API_KEY]" in result.stdout

    def test_secret_in_middle_of_string(self, temp_env_file):
        """Test secret injection in the middle of a command."""
        result = run(temp_env_file, "echo prefix-{{TEST_SECRET}}-suffix", quiet=True)
        assert result.exit_code == 0
        assert "hunter2" not in result.stdout
        assert "prefix-[REDACTED_TEST_SECRET]-suffix" in result.stdout


class TestErrorHandling:
    """Tests for error handling."""

    def test_missing_secret_key(self, temp_env_file):
        """Test error when placeholder key is not in .env file."""
        with pytest.raises(PlaceholderError):
            run(temp_env_file, "echo {{NONEXISTENT_KEY}}", quiet=True)

    def test_empty_env_file_missing_key(self, empty_env_file):
        """Test placeholder error when .env is empty."""
        with pytest.raises(PlaceholderError):
            run(empty_env_file, "echo {{TEST_SECRET}}", quiet=True)

    def test_nonexistent_env_file(self):
        """Test error when .env file doesn't exist."""
        with pytest.raises(CommandError):
            run("/nonexistent/path/.env", "echo hello", quiet=True)

    def test_tokenization_rejected_metacharacter(self, temp_env_file):
        """Test error for rejected shell metacharacters."""
        with pytest.raises(TokenizationError):
            run(temp_env_file, "echo $(whoami)", quiet=True)


class TestOptions:
    """Tests for command options."""

    def test_timeout_option(self, temp_env_file):
        """Test timeout option is accepted."""
        result = run(temp_env_file, "echo hello", quiet=True, timeout=10)
        assert result.exit_code == 0

    def test_max_output_option(self, temp_env_file):
        """Test max_output option is accepted."""
        result = run(temp_env_file, "echo hello", quiet=True, max_output=1000)
        assert result.exit_code == 0

    def test_no_shell_option(self, temp_env_file):
        """Test --no-shell blocks shell interpreters."""
        with pytest.raises(CommandError):
            run(
                temp_env_file,
                "sh -c 'echo hello'",
                quiet=True,
                no_shell=True,
            )

    def test_no_shell_allows_regular_commands(self, temp_env_file):
        """Test --no-shell allows non-shell commands."""
        result = run(temp_env_file, "echo hello", quiet=True, no_shell=False)
        assert result.exit_code == 0
        assert "hello" in result.stdout


class TestPathHandling:
    """Tests for path handling."""

    def test_string_path(self, temp_env_file):
        """Test string path for env_file."""
        result = run(str(temp_env_file), "echo hello", quiet=True)
        assert result.exit_code == 0

    def test_pathlib_path(self, temp_env_file):
        """Test Path object for env_file."""
        result = run(temp_env_file, "echo hello", quiet=True)
        assert result.exit_code == 0

    def test_relative_path(self, temp_env_file, monkeypatch):
        """Test relative path for env_file."""
        monkeypatch.chdir(temp_env_file.parent)
        result = run(temp_env_file.name, "echo hello", quiet=True)
        assert result.exit_code == 0


class TestVerboseMode:
    """Tests for verbose/debug output."""

    def test_verbose_returns_audit(self, temp_env_file):
        """Test verbose mode returns audit data."""
        result = run(temp_env_file, "echo hello", quiet=False, verbose=True)
        assert result.audit is not None
        assert "op" in result.audit

    def test_quiet_suppresses_audit(self, temp_env_file):
        """Test quiet mode suppresses audit output."""
        result = run(temp_env_file, "echo hello", quiet=True)
        assert result.audit is None


class TestStderrCapture:
    """Tests for stderr capture."""

    def test_stderr_captured(self, temp_env_file):
        """Test stderr is captured in result."""
        result = run(temp_env_file, "sh -c 'echo hello >&2'", quiet=True)
        assert result.stderr is not None
        assert "hello" in result.stderr

    def test_exit_code_nonzero(self, temp_env_file):
        """Test non-zero exit codes are captured."""
        result = run(temp_env_file, "sh -c 'exit 1'", quiet=True)
        assert result.exit_code == 1


class TestPlaceholderError:
    """Tests for the improved PlaceholderError with available-keys listing."""

    def test_missing_key_error_contains_key_name(self, temp_env_file):
        """Error message names the missing key."""
        with pytest.raises(PlaceholderError) as exc_info:
            run(temp_env_file, "echo {{NONEXISTENT_KEY}}", quiet=True)
        assert "NONEXISTENT_KEY" in str(exc_info.value)

    def test_missing_key_error_lists_available_keys(self, temp_env_file):
        """Error message lists all available key names."""
        with pytest.raises(PlaceholderError) as exc_info:
            run(temp_env_file, "echo {{NONEXISTENT_KEY}}", quiet=True)
        msg = str(exc_info.value)
        assert "TEST_SECRET" in msg
        assert "API_KEY" in msg
        assert "DATABASE_URL" in msg

    def test_missing_key_error_does_not_leak_values(self, temp_env_file):
        """Error message never contains secret values."""
        with pytest.raises(PlaceholderError) as exc_info:
            run(temp_env_file, "echo {{NONEXISTENT_KEY}}", quiet=True)
        msg = str(exc_info.value)
        assert "hunter2" not in msg
        assert "sk-test-12345" not in msg

    def test_empty_env_file_says_no_keys(self, empty_env_file):
        """Empty .env gives 'no keys' message."""
        with pytest.raises(PlaceholderError) as exc_info:
            run(empty_env_file, "echo {{FOO}}", quiet=True)
        assert "no keys" in str(exc_info.value)


class TestQuotingPatterns:
    """Tests that single-quoted arguments inside command strings work correctly.

    Because run() passes the command as a single string to secretsh (not through
    a parent shell), single quotes inside the string reach the tokenizer directly.
    """

    def test_single_quoted_arg_with_space(self, temp_env_file):
        """Single-quoted argument containing a space is treated as one token."""
        result = run(temp_env_file, "echo 'hello world'", quiet=True)
        assert result.exit_code == 0
        assert "hello world" in result.stdout

    def test_pipe_inside_single_quotes_is_literal(self, temp_env_file):
        """| inside single quotes is a literal character, not a pipe."""
        # jq filter style — single-quoted so | reaches tokenizer as literal
        result = run(temp_env_file, "echo 'a|b'", quiet=True)
        assert result.exit_code == 0
        assert "a|b" in result.stdout

    def test_dollar_inside_single_quotes_is_literal(self, temp_env_file):
        """$ inside single quotes is not expanded."""
        result = run(temp_env_file, "echo '$2 > 10'", quiet=True)
        assert result.exit_code == 0
        assert "$2 > 10" in result.stdout

    def test_unquoted_pipe_rejected(self, temp_env_file):
        """Unquoted | is rejected with TokenizationError."""
        with pytest.raises(TokenizationError):
            run(temp_env_file, "echo foo | cat", quiet=True)

    def test_unquoted_ampersand_rejected(self, temp_env_file):
        """Unquoted & is rejected with TokenizationError."""
        with pytest.raises(TokenizationError):
            run(temp_env_file, "curl https://example.com?a=1&b=2", quiet=True)

    def test_question_mark_in_url_allowed(self, temp_env_file):
        """? in a URL is allowed unquoted."""
        # We can't make a real request in unit tests, but we can verify the
        # tokenizer accepts it by running echo with a URL-like string.
        result = run(temp_env_file, "echo https://api.example.com/v1?limit=1", quiet=True)
        assert result.exit_code == 0
        assert "https://api.example.com/v1?limit=1" in result.stdout

    def test_angle_brackets_allowed_as_literals(self, temp_env_file):
        """< and > are allowed unquoted as literal bytes."""
        result = run(temp_env_file, "echo a>b<c", quiet=True)
        assert result.exit_code == 0
        assert "a>b<c" in result.stdout

    def test_bracket_allowed_as_literal(self, temp_env_file):
        """[ is allowed unquoted as a literal byte."""
        result = run(temp_env_file, "echo [abc]", quiet=True)
        assert result.exit_code == 0
        assert "[abc]" in result.stdout

    def test_secret_in_single_quoted_header(self, temp_env_file):
        """Secret placeholder works inside single-quoted header argument."""
        result = run(
            temp_env_file,
            "echo 'Authorization: {{TEST_SECRET}}'",
            quiet=True,
        )
        assert result.exit_code == 0
        assert "hunter2" not in result.stdout
        assert "[REDACTED_TEST_SECRET]" in result.stdout
    """Tests for edge cases."""

    def test_empty_command(self, temp_env_file):
        """Test empty command string."""
        with pytest.raises((SecretSHError, ValueError)):
            run(temp_env_file, "", quiet=True)

    def test_secret_with_special_chars(self, temp_env_file):
        """Test secret injection with special characters in value."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("SPECIAL=pass@word!\n")
            special_path = Path(f.name)

        try:
            result = run(special_path, "echo {{SPECIAL}}", quiet=True)
            assert result.exit_code == 0
            assert "pass@word!" not in result.stdout
            assert "[REDACTED_SPECIAL]" in result.stdout
        finally:
            os.unlink(special_path)

    def test_unicode_secret(self, temp_env_file):
        """Test secret injection with unicode characters."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
            f.write("UNICODE=p@ssw0rd_日本語\n")
            unicode_path = Path(f.name)

        try:
            result = run(unicode_path, "echo {{UNICODE}}", quiet=True)
            assert result.exit_code == 0
            assert "p@ssw0rd_日本語" not in result.stdout
        finally:
            os.unlink(unicode_path)
