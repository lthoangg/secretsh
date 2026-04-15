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

| Character | Rejected pattern |
|-----------|-----------------|
| `\|` | Pipes |
| `>`, `<` | Redirects |
| `&` | Background execution, AND chains |
| `;` | Command chaining |
| `` ` `` | Command substitution (backtick) |
| `(` | Subshells, process substitution |
| `*`, `?`, `[` | Glob expansion |
| `$` | Variable expansion (when followed by alphanumeric, `_`, `{`, or `(`) |

Characters inside single or double quotes are **never** rejected — they are always literal.

## Placeholder Syntax

```
{{KEY_NAME}}
```

- Placeholders are recognized after tokenization, within each token's value.
- A placeholder may be a full token or embedded: `admin:{{PASS}}` → single token.
- Key names must match `[A-Za-z_][A-Za-z0-9_]*`.
- Byte offsets are recorded for in-place substitution.

### Error Cases

| Input | Error |
|-------|-------|
| `{{FOO` | `MalformedPlaceholder` — unclosed `{{` |
| `{{}}` | `InvalidKeyName` — empty key name |
| `{{1FOO}}` | `InvalidKeyName` — must start with letter or `_` |
| `{{FOO-BAR}}` | `InvalidKeyName` — hyphens not allowed |

## Examples

```bash
# OK — brackets are inside single quotes (literal)
secretsh run -- "jq '.data[0].value' response.json"

# OK — asterisk is inside double quotes (literal)
secretsh run -- "echo \"pattern: *\""

# REJECTED — unquoted pipe
secretsh run -- "cat foo | grep bar"

# REJECTED — unquoted glob
secretsh run -- ls *.txt

# REJECTED — unquoted variable expansion
secretsh run -- "echo $HOME"

# OK — dollar sign not followed by expansion trigger
secretsh run -- "echo price is $5"
```

## Changing the Tokenizer

Any modification to `tokenizer.rs` must:

1. Include tests for the specific edge case being addressed
2. Verify all metacharacter rejection tests still pass
3. Be fuzz-tested before merge
