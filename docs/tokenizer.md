# Tokenizer

The tokenizer is the **primary attack surface** of secretsh. It processes agent-generated input and determines what gets executed. A bypass would collapse the entire security model.

## Quoting Rules

secretsh implements a **strict subset of POSIX shell quoting rules**:

| Context | Behavior |
|---------|----------|
| Unquoted | Whitespace splits tokens; backslash escapes the next character |
| Single-quoted (`'...'`) | All characters are literal; no escape sequences |
| Double-quoted (`"..."`) | `\"` → `"`, `\\` → `\`; all other characters are literal |

## Rejected Metacharacters

The following characters are **rejected when unquoted**:

| Character | Why rejected |
|-----------|-------------|
| `\|` | Pipe — silently passes as a literal arg without a shell; agent gets wrong behaviour with no error |
| `&` | Backgrounding / AND-chain — same silent-failure risk as `\|` |
| `;` | Command chaining — same silent-failure risk |
| `` ` `` | Backtick command substitution |
| `(` | Subshell / process substitution |
| `*` | Glob — no legitimate unquoted use in direct argv |
| `$` | Variable expansion when followed by alphanumeric, `_`, `{`, or `(` |

### Why `|`, `&`, `;` are rejected (not a security reason)

secretsh uses `posix_spawnp` directly — no shell ever interprets these characters.
They are rejected to **prevent silent wrong behaviour**: if an agent writes
`curl ... | jq .` expecting a pipe, and `|` were allowed unquoted, curl would
receive `|` and `jq` as literal URL arguments, fetch them as hosts, and return
a confusing mix of success and errors with no pipe ever created.

Rejecting them gives the agent a **clear actionable error** instead:

```
secretsh error: tokenization error: rejected shell metacharacter '|' at byte offset 33
  — wrap it in quotes if it is intended to be literal
```

For actual piping, use the parent shell:

```bash
secretsh --env .env run --no-shell -- curl -sS -H 'X-Api-Key: {{KEY}}' 'https://api.example.com' | jq '.'
```

## Allowed Characters (previously rejected, now permitted)

The following characters are **not** rejected. secretsh spawns via `posix_spawnp`
directly — no shell ever interprets them — so they are always passed as literal
argv bytes:

| Character | Legitimate uses |
|-----------|----------------|
| `?` | URL query strings: `https://api.example.com/v1/quotes?limit=1` |
| `>` | jq/awk comparisons: `'.[] \| select(.age > 18)'`, `'$2 > 10'` |
| `<` | Angle brackets in patterns: `grep '<tag>' file.xml` |
| `[` | jq filters: `'.[0]'`, `'.results[]'`; regex: `'[a-z]+'` |

Note: `>` and `<` as redirect operators, and `[` as a glob prefix, require a
shell to have effect. Without a shell they are just bytes.

## Quoting Guide

Because the command string is parsed by secretsh's tokenizer directly (not by
a parent shell), single quotes inside the string work as expected:

```bash
# Header with a space — single-quote the header value
secretsh --env .env run -- "curl -H 'Authorization: Bearer {{TOKEN}}' https://api.example.com"

# jq filter with pipe and comparison — single-quote the filter
secretsh --env .env run -- "jq '.results[] | select(.score > 90)' data.json"

# awk with $ field reference — single-quote the program
secretsh --env .env run -- "awk '\$2 > 10' file.txt"

# URL with & in query string — single-quote the URL
secretsh --env .env run -- "curl 'https://api.example.com/search?q=hello&limit=10'"
```

**CLI note:** when calling secretsh from a shell, the parent shell strips quotes
before secretsh sees them. Protect inner single quotes with double-quoting or
pass the whole command as one double-quoted string:

```bash
# Each token split by parent shell — inner ' reaches secretsh tokenizer
secretsh --env .env run --no-shell -- jq "'.[] | select(.age > 18)'" data.json

# Or pass the whole command as one string — parent shell strips outer "
secretsh --env .env run --no-shell -- "jq '.[] | select(.age > 18)' data.json"
```

**Python wrapper:** the command is passed as a single string to secretsh via
`subprocess`, bypassing the parent shell entirely. Single quotes inside the
string reach the tokenizer directly — no double-wrapping needed:

```python
secretsh.run(".env", "jq '.results[] | select(.score > 90)' data.json")
secretsh.run(".env", "awk '$2 > 10' file.txt")
secretsh.run(".env", "curl 'https://api.example.com/search?q=hello&limit=10'")
```

## Placeholder Syntax

```
{{KEY_NAME}}
```

- Placeholders are recognized after tokenization, within each token's value.
- A placeholder may be a full token or embedded: `admin:{{PASS}}` → single token.
- Key names must match `[A-Za-z_][A-Za-z0-9_]*`.
- Byte offsets are recorded for in-place substitution.
- If a key is not found in the `.env` file, the error lists all available keys:
  `"NINJA_API_KEY" not found in env file; available keys: [GITHUB_TOKEN, OPENAI_KEY]`

### Error Cases

| Input | Error |
|-------|-------|
| `{{FOO` | `MalformedPlaceholder` — unclosed `{{` |
| `{{}}` | `InvalidKeyName` — empty key name |
| `{{1FOO}}` | `InvalidKeyName` — must start with letter or `_` |
| `{{FOO-BAR}}` | `InvalidKeyName` — hyphens not allowed |
| `{{MISSING}}` | `UnresolvedKey` — lists available keys from `.env` |

## Changing the Tokenizer

Any modification to `tokenizer.rs` must:

1. Include tests for the specific edge case being addressed
2. Verify all metacharacter rejection tests still pass
3. Be fuzz-tested before merge
