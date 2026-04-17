# OpenClaw Integration

OpenClaw's `exec` tool runs shell commands directly on the gateway or a paired node. Wrapping it with secretsh means the agent never sees raw secret values — it constructs commands with `{{KEY_NAME}}` placeholders and secretsh injects and redacts them.

## How It Fits Together

```
OpenClaw agent
    │  writes command with {{KEY_NAME}} placeholders
    ▼
exec tool  →  secretsh --env .env run --no-shell -- "<command>"
    │  injects secrets, redacts output
    ▼
stdout/stderr returned to agent  ← [REDACTED_KEY] in place of raw values
```

## Shell Wrapper Script

Place this on your gateway or node host so OpenClaw calls it instead of a bare shell:

```bash
#!/usr/bin/env bash
# ~/bin/secretsh-exec
# Usage: secretsh-exec "command with {{KEY}} placeholders"
set -euo pipefail

ENV_FILE="${SECRETSH_ENV_FILE:-$HOME/.secrets/.env}"

exec secretsh --env "$ENV_FILE" run --no-shell --quiet -- "$@"
```

```bash
chmod +x ~/bin/secretsh-exec
```

Then in your OpenClaw config, point exec at the wrapper or use it directly in your agent prompt:

```json5
{
  tools: {
    exec: {
      pathPrepend: ["~/bin"],
    },
  },
}
```

## Direct Usage

From an OpenClaw agent, construct commands with placeholders. secretsh is invoked as the command:

```json
{
  "tool": "exec",
  "command": "secretsh --env ~/.secrets/.env run --no-shell --quiet -- \"curl -sS -H 'X-Api-Key: {{NINJA_API_KEY}}' 'https://api.api-ninjas.com/v2/quoteoftheday'\""
}
```

The agent never sees `NINJA_API_KEY`'s value — only `[REDACTED_NINJA_API_KEY]` if it leaks in output.

## Security Considerations

### `--no-shell` is required

OpenClaw's exec already runs commands through a shell on the host. If you allow `sh -c` inside secretsh as well, an agent can construct shell conditionals to probe secret values:

```bash
# This would work without --no-shell:
sh -c '[ "{{KEY}}" = "guess" ] && echo YES'
```

`--no-shell` blocks this. Always pass it.

### `security=allowlist` vs secretsh

OpenClaw's `security=allowlist` restricts which binaries can run. Add `secretsh` to your allowlist explicitly:

```json5
// ~/.openclaw/exec-approvals.json
{
  "allowlist": ["/opt/homebrew/bin/secretsh", "/usr/local/bin/secretsh"]
}
```

### env file location

Set `SECRETSH_ENV_FILE` in your OpenClaw session environment, or hardcode the path in the wrapper script. Do not pass the path as an agent-controlled argument — the agent should not be able to point secretsh at an arbitrary file.

### `strictInlineEval`

If you enable `tools.exec.strictInlineEval`, inline interpreter eval forms (e.g. `python -c`, `node -e`) always require approval. This is compatible with secretsh — secretsh itself is not an interpreter.

## Agent Prompt

Tell the agent how to use placeholders:

```
When running shell commands that need secrets, use secretsh:
  secretsh --env ~/.secrets/.env run --no-shell --quiet -- "<command>"

Use {{KEY_NAME}} placeholders for secrets. Available keys: NINJA_API_KEY, GITHUB_TOKEN
Single-quote arguments containing spaces, pipes, $ or &.
Example: secretsh --env ~/.secrets/.env run --no-shell --quiet -- "curl -sS -H 'X-Api-Key: {{NINJA_API_KEY}}' 'https://api.api-ninjas.com/v2/quoteoftheday'"

If a key is missing, the error lists all available key names.
```
