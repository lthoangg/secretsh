#!/usr/bin/env python3
"""LangChain agent with secretsh-protected shell tool.

Usage:
    pip install secretsh langchain
    python langchain_shell_tool_demo.py

Quoting guide for the agent
---------------------------
The shell tool accepts a natural command string.  Because secretsh parses it
directly (no parent shell involved), single quotes inside the string work as
expected:

    # Header with a space — single-quote the header value
    shell("curl -sS -H 'X-Api-Key: {{NINJA_API_KEY}}' 'https://api.api-ninjas.com/v2/quoteoftheday'")

    # jq filter with pipe and comparison
    shell("jq '.results[] | select(.score > 90)' data.json")

    # awk program with $ field references
    shell("awk '$2 > 10' file.txt")

    # URL with & — single-quote the URL
    shell("curl 'https://api.example.com/search?q=hello&limit=10'")

    # Pipe to jq — use the parent shell pipe, not inside the command string
    import subprocess
    result = shell("curl -sS -H 'X-Api-Key: {{NINJA_API_KEY}}' 'https://api.api-ninjas.com/v2/quoteoftheday'")
    # then: subprocess / LangChain chain to pipe result.stdout through jq

Available secret keys are listed in PlaceholderError if a key is missing.
"""

from pathlib import Path

import secretsh
from langchain.tools import tool

env_file = Path(__file__).parent / ".env"


@tool
def shell(command: str) -> str:
    """Execute a command with secrets injected from the .env file.

    Secrets are referenced using {{SECRET_NAME}} syntax — never put raw
    secret values in the command string.  Secret values are automatically
    redacted from all output returned to you.

    Write the command as a natural shell string.  Use single quotes for
    arguments containing spaces, pipes, $ signs, or & characters:

        curl -sS -H 'X-Api-Key: {{NINJA_API_KEY}}' 'https://api.api-ninjas.com/v2/quoteoftheday'
        jq '.results[] | select(.score > 90)' data.json
        awk '$2 > 10' file.txt
        curl 'https://api.example.com/search?q=hello&limit=10'

    If a secret key is not found, the error message lists all available keys.

    Args:
        command: Shell command string with optional {{KEY_NAME}} placeholders.
    """
    if not env_file.exists():
        return f"Error: .env file not found at {env_file}"

    try:
        result = secretsh.run(str(env_file), command, no_shell=True, quiet=True, timeout=30)
        output = result.stdout
        if result.stderr:
            output += result.stderr
        if result.exit_code != 0:
            output += f"\n[exit code: {result.exit_code}]"
        return output
    except secretsh.PlaceholderError as e:
        return f"Secret not found: {e}"
    except secretsh.TokenizationError as e:
        return f"Command syntax error: {e}\nHint: wrap arguments containing | $ & in single quotes."
    except secretsh.CommandError as e:
        return f"Command failed: {e}"


if __name__ == "__main__":
    print("Shell tool demo:")
    print(shell.invoke("echo API key is {{DEMO_API_KEY}}"))
    print(shell.invoke("echo DB password is {{DB_PASSWORD}}"))
    print(shell.invoke("curl -sS -H 'X-Api-Key: {{DEMO_API_KEY}}' 'https://httpbin.org/headers'"))
    print(shell.invoke("echo {{MISSING_KEY}}"))  # demonstrates available-keys error

# Example output:
# Shell tool demo:
# API key is [REDACTED_DEMO_API_KEY]
#
# DB password is [REDACTED_DB_PASSWORD]
#
# {"headers": {"Accept": "*/*", "Host": "httpbin.org", "X-Api-Key": "[REDACTED_DEMO_API_KEY]", ...}}
#
# Secret not found: secretsh error: placeholder error: "MISSING_KEY" not found in env file; available keys: [AWS_ACCESS_KEY_ID, ...]
