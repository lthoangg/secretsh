# Framework Integrations

How to wrap secretsh as a shell tool in popular AI agent frameworks.

## The Pattern

Every integration follows the same shape:

1. Agent writes a command with `{{KEY_NAME}}` placeholders — never raw values.
2. Your tool calls `secretsh.run()` with that string.
3. Errors are returned as strings so the agent can self-correct.
4. Redacted stdout/stderr is returned.

Because `secretsh.run()` passes the command directly to secretsh's tokenizer (not through a shell), single quotes inside the string work naturally:

```python
# These all work as-is inside secretsh.run()
"curl -sS -H 'X-Api-Key: {{API_KEY}}' 'https://api.example.com'"
"jq '.results[] | select(.score > 90)' data.json"
"awk '$2 > 10' file.txt"
"curl 'https://api.example.com/search?q=hello&limit=10'"
```

## Guides

| Framework | File |
|-----------|------|
| LangChain | [langchain.md](langchain.md) |
| PydanticAI | [pydanticai.md](pydanticai.md) |
| OpenClaw | [openclaw.md](openclaw.md) |

## Common Pitfalls

**Wrong key name** — the error lists all available keys:
```
Secret not found: "NINJA_KEY" not found in env file; available keys: [DB_PASSWORD, NINJA_API_KEY]
```
The agent sees the available keys and retries with the correct name.

**Unquoted `&` in URL** — wrap the URL in single quotes:
```python
# Wrong
"curl https://api.example.com?a=1&b=2"
# Correct
"curl 'https://api.example.com?a=1&b=2'"
```

**Piping inside the command string** — `|` is rejected unquoted. Pipe outside secretsh:
```python
result = secretsh.run(".env", "curl -sS 'https://api.example.com'", no_shell=True, quiet=True)
import json
data = json.loads(result.stdout)
```

**Always set `no_shell=True`** — without it, an agent can run `sh -c '[ "{{KEY}}" = guess ] && echo YES'` to probe secret values. See [threat-model.md](../threat-model.md).
