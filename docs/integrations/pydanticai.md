# PydanticAI Integration

```bash
pip install secretsh pydantic-ai
```

## Tool Definition

Use `@agent.tool_plain` when the tool does not need runtime context:

```python
from pathlib import Path
from pydantic_ai import Agent
import secretsh

ENV_FILE = Path(".env")

agent = Agent(
    "openai:gpt-4o-mini",
    system_prompt=(
        "You have a shell tool. Use {{KEY_NAME}} placeholders for secrets — never raw values. "
        "Single-quote arguments containing spaces, pipes, $ or &. "
        "If a key is missing, the error lists all available key names."
    ),
)


@agent.tool_plain
def shell(command: str) -> str:
    """Run a shell command with secrets injected from .env.

    Use {{KEY_NAME}} for secrets. Single-quote arguments with spaces/pipes/$/&.
    Example: curl -sS -H 'X-Api-Key: {{API_KEY}}' 'https://api.example.com'
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


result = agent.run_sync("Fetch the quote of the day from the Ninja API")
print(result.output)
```

## Per-User Env Files with `RunContext`

Use `@agent.tool` with `RunContext` when the env file varies per request (e.g. per-user secrets):

```python
from dataclasses import dataclass
from pathlib import Path
from pydantic_ai import Agent, RunContext
import secretsh


@dataclass
class Deps:
    env_file: Path


agent = Agent("openai:gpt-4o-mini", deps_type=Deps)


@agent.tool
def shell(ctx: RunContext[Deps], command: str) -> str:
    """Run a shell command with secrets from the user's .env file.

    Use {{KEY_NAME}} for secrets. Single-quote arguments with spaces/pipes/$/&.
    """
    try:
        result = secretsh.run(
            ctx.deps.env_file, command,
            no_shell=True, quiet=True, timeout=30,
        )
        out = result.stdout
        if result.stderr:
            out += result.stderr
        if result.exit_code != 0:
            out += f"\n[exit code: {result.exit_code}]"
        return out
    except secretsh.SecretSHError as e:
        return f"Error: {e}"


result = agent.run_sync(
    "Fetch today's quote",
    deps=Deps(env_file=Path("/home/alice/.secrets/.env")),
)
print(result.output)
```

## Registering via `tools=` Argument

If you prefer not to use decorators, pass the function via the `tools` argument:

```python
from pydantic_ai import Agent, Tool

agent = Agent(
    "openai:gpt-4o-mini",
    tools=[Tool(shell, takes_ctx=False)],
)
```
