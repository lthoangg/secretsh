# LangChain Integration

```bash
pip install secretsh langchain-core
```

## Tool Definition

```python
from pathlib import Path
from langchain_core.tools import tool
import secretsh

ENV_FILE = Path(".env")


@tool
def shell(command: str) -> str:
    """Execute a shell command with secrets injected from .env.

    Use {{KEY_NAME}} placeholders for secrets — never raw values.
    Single-quote arguments containing spaces, pipes, $ or &:

        curl -sS -H 'X-Api-Key: {{API_KEY}}' 'https://api.example.com'
        jq '.results[] | select(.score > 90)' data.json
        awk '$2 > 10' file.txt
        curl 'https://api.example.com/search?q=hello&limit=10'

    If a key is missing, the error lists all available key names.
    """
    try:
        result = secretsh.run(
            ENV_FILE, command,
            no_shell=True, quiet=True, timeout=30,
        )
        out = result.stdout
        if result.stderr:
            out += result.stderr
        if result.exit_code != 0:
            out += f"\n[exit code: {result.exit_code}]"
        return out
    except secretsh.PlaceholderError as e:
        return f"Secret not found: {e}"
    except secretsh.TokenizationError as e:
        return f"Syntax error: {e}\nHint: wrap | $ & in single quotes."
    except secretsh.CommandError as e:
        return f"Command failed: {e}"
```

## System Prompt (recommended)

Add to your system prompt so the agent knows what keys are available:

```
You have access to a shell tool. Use {{KEY_NAME}} syntax for secrets.
Available keys: NINJA_API_KEY, GITHUB_TOKEN, DB_PASSWORD
Single-quote arguments containing spaces, pipes, $ or &.
Example: curl -sS -H 'X-Api-Key: {{NINJA_API_KEY}}' 'https://api.api-ninjas.com/v2/quoteoftheday'
```

If you omit the available keys list, the agent will still self-correct on first failure — the `PlaceholderError` message lists them automatically.
