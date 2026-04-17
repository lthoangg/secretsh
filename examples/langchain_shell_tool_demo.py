#!/usr/bin/env python3
"""LangChain agent with secretsh-protected shell tool.

Usage:
    pip install secretsh langchain
    python langchain_shell_tool_demo.py
"""

from pathlib import Path

import secretsh
from langchain.tools import tool

env_file = Path(__file__).parent / ".env.example"


@tool
def shell(command: str) -> str:
    """Execute a shell command with secrets injected from .env file.

    Secrets are referenced using {{SECRET_NAME}} syntax.
    Secret values are automatically redacted from all output.

    Args:
        command: Shell command with optional {{SECRET_NAME}} placeholders.
    """

    if not env_file.exists():
        return "Error: .env.example file not found"

    result = secretsh.run(str(env_file), command, timeout=30, quiet=True)
    return result.stdout


if __name__ == "__main__":
    # Demo: invoke the tool directly
    print("Shell tool demo:")
    print(f"Result: {shell.invoke('echo API key is {{DEMO_API_KEY}}')}")
    print(f"Result: {shell.invoke('echo DB password is {{DB_PASSWORD}}')}")
    print(f"Result: {shell.invoke(f'cat {env_file}')}")

# Output:
# Shell tool demo:
# Result: API key is [REDACTED_DEMO_API_KEY]

# Result: DB password is [REDACTED_DB_PASSWORD]

# Result: # Example .env file for secretsh LangChain demo
# # Copy this to .env and fill in your actual secrets

# # API Keys
# DEMO_API_KEY=[REDACTED_DEMO_API_KEY]
# OPENAI_API_KEY=[REDACTED_OPENAI_API_KEY]

# # Database credentials
# DB_HOST=[REDACTED_DB_HOST]
# DB_PORT=[REDACTED_DB_PORT]
# DB_NAME=[REDACTED_DB_NAME]
# DB_USER=[REDACTED_DB_USER]
# DB_PASSWORD=[REDACTED_DB_PASSWORD]

# # Service tokens
# GITHUB_TOKEN=[REDACTED_GITHUB_TOKEN]
# AWS_ACCESS_KEY_ID=[REDACTED_AWS_ACCESS_KEY_ID]
# AWS_SECRET_ACCESS_KEY=[REDACTED_AWS_SECRET_ACCESS_KEY]

# # SSH keys (example path - don't put actual keys in .env!)
# SSH_KEY_PATH=[REDACTED_SSH_KEY_PATH]
