//! Command-string tokenizer for secretsh.
//!
//! Implements a **strict subset of POSIX shell quoting rules** and rejects any
//! unquoted shell metacharacter that could allow shell-injection or unintended
//! expansion.  After tokenization each token is scanned for `{{KEY_NAME}}`
//! placeholders whose positions are recorded for later .env resolution.
//!
//! # Quoting rules
//!
//! | Context        | Behaviour                                                    |
//! |----------------|--------------------------------------------------------------|
//! | Unquoted       | Whitespace splits tokens; backslash escapes the next char    |
//! | Single-quoted  | All characters are literal; no escape sequences              |
//! | Double-quoted  | `\"` → `"`, `\\` → `\`; all other characters are literal    |
//!
//! # Rejected unquoted metacharacters
//!
//! `|`, `>`, `<`, `&`, `;`, `` ` ``, `(`, `*`, `?`, `[`, `$` (when followed
//! by an alphanumeric character or `{`).
//!
//! Characters inside single or double quotes are **never** rejected.

use crate::error::{SecretshError, TokenizationError};

// ─────────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────────

/// A single resolved token produced by [`tokenize`].
///
/// The `value` is the fully-unquoted, escape-processed string.  Any
/// `{{KEY_NAME}}` placeholders found inside `value` are listed in
/// `placeholders` with their byte offsets so that callers can perform
/// in-place substitution without re-scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The unquoted, escape-processed token value.
    pub value: String,
    /// Zero or more placeholders embedded in `value`.
    pub placeholders: Vec<Placeholder>,
}

/// A `{{KEY_NAME}}` placeholder found inside a [`Token`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placeholder {
    /// The key name between the double braces (e.g. `"DB_PASS"`).
    pub key: String,
    /// Byte offset of the opening `{{` within [`Token::value`] (inclusive).
    pub start: usize,
    /// Byte offset just past the closing `}}` within [`Token::value`]
    /// (exclusive).
    pub end: usize,
}

/// The result returned by a successful call to [`tokenize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenizeResult {
    /// The ordered list of tokens parsed from the input string.
    pub tokens: Vec<Token>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Tokenizer state
// ─────────────────────────────────────────────────────────────────────────────

/// Internal quoting context tracked by the lexer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteState {
    /// Outside any quote — whitespace splits tokens, metacharacters are
    /// rejected, backslash escapes the next character.
    Unquoted,
    /// Inside `'...'` — everything is literal until the closing `'`.
    SingleQuoted,
    /// Inside `"..."` — only `\"` and `\\` are escape sequences.
    DoubleQuoted,
}

// ─────────────────────────────────────────────────────────────────────────────
// Main entry point
// ─────────────────────────────────────────────────────────────────────────────

/// Tokenize `input` according to the secretsh quoting rules.
///
/// Returns a [`TokenizeResult`] on success, or a [`SecretshError`] wrapping a
/// [`TokenizationError`] on the first hard error encountered.
///
/// # Errors
///
/// - [`TokenizationError::EmptyCommand`] — input is empty or all-whitespace.
/// - [`TokenizationError::RejectedMetacharacter`] — an unquoted shell
///   metacharacter was found.
/// - [`TokenizationError::UnclosedSingleQuote`] — EOF inside `'...'`.
/// - [`TokenizationError::UnclosedDoubleQuote`] — EOF inside `"..."`.
/// - [`TokenizationError::TrailingBackslash`] — backslash at EOF.
/// - [`TokenizationError::MalformedPlaceholder`] — `{{` without matching `}}`.
pub fn tokenize(input: &str) -> Result<TokenizeResult, SecretshError> {
    let raw_tokens = lex(input)?;

    if raw_tokens.is_empty() {
        return Err(TokenizationError::EmptyCommand.into());
    }

    let mut tokens = Vec::with_capacity(raw_tokens.len());
    for value in raw_tokens {
        let placeholders = scan_placeholders(&value)?;
        tokens.push(Token {
            value,
            placeholders,
        });
    }

    Ok(TokenizeResult { tokens })
}

// ─────────────────────────────────────────────────────────────────────────────
// Lexer
// ─────────────────────────────────────────────────────────────────────────────

/// Walk `input` character-by-character, applying quoting rules and
/// metacharacter rejection.  Returns the list of raw (unquoted) token strings.
fn lex(input: &str) -> Result<Vec<String>, SecretshError> {
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();

    // Byte offsets for each character position (needed for error reporting).
    let byte_offsets: Vec<usize> = {
        let mut offsets = Vec::with_capacity(len + 1);
        let mut byte_pos = 0usize;
        for &ch in &chars {
            offsets.push(byte_pos);
            byte_pos += ch.len_utf8();
        }
        offsets.push(byte_pos); // sentinel: one past the last char
        offsets
    };

    let mut tokens: Vec<String> = Vec::new();
    // Accumulator for the token currently being built.
    let mut current = String::new();
    // Whether `current` has received at least one character (distinguishes an
    // empty-quoted token `""` from inter-token whitespace).
    let mut in_token = false;
    let mut state = QuoteState::Unquoted;
    // Byte offset at which the current quote was opened (for error messages).
    let mut quote_start: usize = 0;

    let mut i = 0usize;

    while i < len {
        let ch = chars[i];
        let byte_offset = byte_offsets[i];

        match state {
            // ── Unquoted ─────────────────────────────────────────────────────
            QuoteState::Unquoted => {
                match ch {
                    // ── Whitespace: flush current token ──────────────────────
                    ' ' | '\t' => {
                        if in_token {
                            tokens.push(std::mem::take(&mut current));
                            in_token = false;
                        }
                        i += 1;
                    }

                    // ── Single-quote open ─────────────────────────────────────
                    '\'' => {
                        state = QuoteState::SingleQuoted;
                        quote_start = byte_offset;
                        in_token = true;
                        i += 1;
                    }

                    // ── Double-quote open ─────────────────────────────────────
                    '"' => {
                        state = QuoteState::DoubleQuoted;
                        quote_start = byte_offset;
                        in_token = true;
                        i += 1;
                    }

                    // ── Backslash escape ──────────────────────────────────────
                    '\\' => {
                        if i + 1 >= len {
                            return Err(TokenizationError::TrailingBackslash.into());
                        }
                        // The next character is literal regardless of what it is.
                        let next = chars[i + 1];
                        current.push(next);
                        in_token = true;
                        i += 2;
                    }

                    // ── Metacharacter rejection ───────────────────────────────
                    //
                    // Checked before the default arm so that every forbidden
                    // character is caught even if it would otherwise be
                    // "harmless" in isolation.

                    // Pipe
                    '|' => {
                        return Err(TokenizationError::RejectedMetacharacter {
                            character: '|',
                            offset: byte_offset,
                        }
                        .into());
                    }

                    // Redirect (plain `>` or `<`)
                    // Note: `<(` and `>(` are also caught here because the
                    // leading `<`/`>` is rejected first.
                    '>' | '<' => {
                        return Err(TokenizationError::RejectedMetacharacter {
                            character: ch,
                            offset: byte_offset,
                        }
                        .into());
                    }

                    // Ampersand — covers `&` (background) and `&&` (AND-list)
                    '&' => {
                        return Err(TokenizationError::RejectedMetacharacter {
                            character: '&',
                            offset: byte_offset,
                        }
                        .into());
                    }

                    // Semicolon — command separator
                    ';' => {
                        return Err(TokenizationError::RejectedMetacharacter {
                            character: ';',
                            offset: byte_offset,
                        }
                        .into());
                    }

                    // Backtick — command substitution
                    '`' => {
                        return Err(TokenizationError::RejectedMetacharacter {
                            character: '`',
                            offset: byte_offset,
                        }
                        .into());
                    }

                    // Open-paren — subshell / `$(` / `<(` / `>(`
                    '(' => {
                        return Err(TokenizationError::RejectedMetacharacter {
                            character: '(',
                            offset: byte_offset,
                        }
                        .into());
                    }

                    // Glob characters
                    '*' | '?' | '[' => {
                        return Err(TokenizationError::RejectedMetacharacter {
                            character: ch,
                            offset: byte_offset,
                        }
                        .into());
                    }

                    // Dollar sign — reject only when followed by alnum, `_`,
                    // or `{` (variable/command expansion).  A bare `$` at EOF
                    // or followed by whitespace/quote is allowed as a literal.
                    '$' => {
                        let next = chars.get(i + 1).copied();
                        let is_expansion = match next {
                            Some(c) => c.is_alphanumeric() || c == '_' || c == '{' || c == '(',
                            None => false,
                        };
                        if is_expansion {
                            return Err(TokenizationError::RejectedMetacharacter {
                                character: '$',
                                offset: byte_offset,
                            }
                            .into());
                        }
                        // Bare `$` — treat as a literal character.
                        current.push('$');
                        in_token = true;
                        i += 1;
                    }

                    // ── Ordinary character ────────────────────────────────────
                    _ => {
                        current.push(ch);
                        in_token = true;
                        i += 1;
                    }
                }
            }

            // ── Single-quoted ─────────────────────────────────────────────────
            QuoteState::SingleQuoted => {
                match ch {
                    '\'' => {
                        // Closing quote — return to unquoted state.
                        state = QuoteState::Unquoted;
                        i += 1;
                    }
                    // Everything else is literal — no escape processing.
                    _ => {
                        current.push(ch);
                        i += 1;
                    }
                }
            }

            // ── Double-quoted ─────────────────────────────────────────────────
            QuoteState::DoubleQuoted => {
                match ch {
                    '"' => {
                        // Closing quote — return to unquoted state.
                        state = QuoteState::Unquoted;
                        i += 1;
                    }
                    '\\' => {
                        // Only `\"` and `\\` are escape sequences inside
                        // double quotes; any other `\X` keeps the backslash.
                        let next = chars.get(i + 1).copied();
                        match next {
                            Some('"') => {
                                current.push('"');
                                i += 2;
                            }
                            Some('\\') => {
                                current.push('\\');
                                i += 2;
                            }
                            Some(_) => {
                                // Backslash is literal when not before `"` or `\`.
                                current.push('\\');
                                i += 1;
                            }
                            None => {
                                // Backslash at EOF inside a double-quoted string.
                                // The string is unclosed, which we catch below
                                // after the loop; for now just consume the backslash.
                                current.push('\\');
                                i += 1;
                            }
                        }
                    }
                    _ => {
                        current.push(ch);
                        i += 1;
                    }
                }
            }
        }
    }

    // ── Post-loop checks ──────────────────────────────────────────────────────

    match state {
        QuoteState::SingleQuoted => {
            return Err(TokenizationError::UnclosedSingleQuote {
                offset: quote_start,
            }
            .into());
        }
        QuoteState::DoubleQuoted => {
            return Err(TokenizationError::UnclosedDoubleQuote {
                offset: quote_start,
            }
            .into());
        }
        QuoteState::Unquoted => {}
    }

    // Flush any trailing token that was not terminated by whitespace.
    if in_token {
        tokens.push(current);
    }

    Ok(tokens)
}

// ─────────────────────────────────────────────────────────────────────────────
// Placeholder scanner
// ─────────────────────────────────────────────────────────────────────────────

/// Scan a fully-unquoted token value for `{{KEY_NAME}}` patterns.
///
/// Returns the list of [`Placeholder`]s found, or a
/// [`TokenizationError::MalformedPlaceholder`] if an unclosed `{{` is
/// detected.
fn scan_placeholders(value: &str) -> Result<Vec<Placeholder>, SecretshError> {
    let mut placeholders = Vec::new();
    let bytes = value.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;

    while i < len {
        // Look for the opening `{{`.
        if i + 1 < len && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            let open_start = i;
            i += 2; // skip `{{`

            // Collect the key name until we find `}}` or EOF.
            let key_start = i;
            let mut found_close = false;

            while i < len {
                if i + 1 < len && bytes[i] == b'}' && bytes[i + 1] == b'}' {
                    found_close = true;
                    break;
                }
                i += 1;
            }

            if !found_close {
                // Build the fragment for the error message: `{{` + whatever
                // key characters we collected before EOF.
                let fragment = format!("{{{{{}}}", &value[key_start..i]);
                return Err(TokenizationError::MalformedPlaceholder { fragment }.into());
            }

            let key = &value[key_start..i];
            let close_end = i + 2; // byte offset just past `}}`

            // Validate the key name: `[A-Za-z_][A-Za-z0-9_]*`
            if !is_valid_key(key) {
                let fragment = format!("{{{{{}}}}}", key);
                return Err(TokenizationError::InvalidKeyName { fragment }.into());
            }

            placeholders.push(Placeholder {
                key: key.to_owned(),
                start: open_start,
                end: close_end,
            });

            i = close_end;
        } else {
            i += 1;
        }
    }

    Ok(placeholders)
}

/// Returns `true` if `key` matches `[A-Za-z_][A-Za-z0-9_]*` and is non-empty.
#[inline]
fn is_valid_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        None => false, // empty key
        Some(first) => {
            (first.is_ascii_alphabetic() || first == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{SecretshError, TokenizationError};

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Tokenize and unwrap, panicking with the error on failure.
    fn tok(input: &str) -> TokenizeResult {
        tokenize(input).unwrap_or_else(|e| panic!("tokenize({input:?}) failed: {e}"))
    }

    /// Tokenize and expect an error, panicking if it succeeds.
    fn tok_err(input: &str) -> TokenizationError {
        match tokenize(input) {
            Err(SecretshError::Tokenization(e)) => e,
            Err(other) => panic!("expected TokenizationError, got: {other}"),
            Ok(r) => panic!("expected error, got tokens: {r:?}"),
        }
    }

    /// Extract just the string values from a [`TokenizeResult`].
    fn values(r: &TokenizeResult) -> Vec<&str> {
        r.tokens.iter().map(|t| t.value.as_str()).collect()
    }

    // ── Empty input ───────────────────────────────────────────────────────────

    #[test]
    fn empty_string_is_error() {
        assert!(matches!(tok_err(""), TokenizationError::EmptyCommand));
    }

    #[test]
    fn all_whitespace_is_error() {
        assert!(matches!(
            tok_err("   \t  "),
            TokenizationError::EmptyCommand
        ));
    }

    // ── Basic whitespace splitting ────────────────────────────────────────────

    #[test]
    fn single_word() {
        assert_eq!(values(&tok("hello")), ["hello"]);
    }

    #[test]
    fn two_words_single_space() {
        assert_eq!(values(&tok("foo bar")), ["foo", "bar"]);
    }

    #[test]
    fn multiple_spaces_between_words() {
        assert_eq!(values(&tok("foo   bar")), ["foo", "bar"]);
    }

    #[test]
    fn tab_separates_tokens() {
        assert_eq!(values(&tok("foo\tbar")), ["foo", "bar"]);
    }

    #[test]
    fn leading_and_trailing_whitespace_ignored() {
        assert_eq!(values(&tok("  foo bar  ")), ["foo", "bar"]);
    }

    #[test]
    fn many_tokens() {
        assert_eq!(values(&tok("a b c d e")), ["a", "b", "c", "d", "e"]);
    }

    // ── Single-quote handling ─────────────────────────────────────────────────

    #[test]
    fn single_quoted_preserves_spaces() {
        assert_eq!(values(&tok("'hello world'")), ["hello world"]);
    }

    #[test]
    fn single_quoted_preserves_backslash() {
        // Inside single quotes, `\n` is two literal characters.
        assert_eq!(values(&tok(r"'foo\nbar'")), [r"foo\nbar"]);
    }

    #[test]
    fn single_quoted_preserves_double_quote() {
        assert_eq!(values(&tok("'say \"hi\"'")), ["say \"hi\""]);
    }

    #[test]
    fn single_quoted_preserves_metacharacters() {
        // Metacharacters inside single quotes must NOT be rejected.
        assert_eq!(values(&tok("'|><&;`(*?[$'")), ["|><&;`(*?[$"]);
    }

    #[test]
    fn single_quoted_preserves_dollar_expansion() {
        assert_eq!(values(&tok("'$HOME'")), ["$HOME"]);
    }

    #[test]
    fn empty_single_quotes_produce_empty_token() {
        assert_eq!(values(&tok("''")), [""]);
    }

    #[test]
    fn single_quote_adjacent_to_word() {
        // `foo'bar'baz` → `foobarbaz`
        assert_eq!(values(&tok("foo'bar'baz")), ["foobarbaz"]);
    }

    #[test]
    fn unclosed_single_quote_is_error() {
        let e = tok_err("'unclosed");
        assert!(
            matches!(e, TokenizationError::UnclosedSingleQuote { offset: 0 }),
            "got: {e:?}"
        );
    }

    #[test]
    fn unclosed_single_quote_offset_is_correct() {
        // The `'` is at byte offset 4 (after `foo `).
        let e = tok_err("foo 'bar");
        assert!(
            matches!(e, TokenizationError::UnclosedSingleQuote { offset: 4 }),
            "got: {e:?}"
        );
    }

    // ── Double-quote handling ─────────────────────────────────────────────────

    #[test]
    fn double_quoted_preserves_spaces() {
        assert_eq!(values(&tok(r#""hello world""#)), ["hello world"]);
    }

    #[test]
    fn double_quoted_escape_double_quote() {
        // `"\""` → `"`
        assert_eq!(values(&tok(r#""\"""#)), ["\""]);
    }

    #[test]
    fn double_quoted_escape_backslash() {
        // `"\\"` → `\`
        assert_eq!(values(&tok(r#""\\""#)), ["\\"]);
    }

    #[test]
    fn double_quoted_backslash_before_other_char_is_literal() {
        // `"\n"` → `\n` (two characters: backslash + n)
        assert_eq!(values(&tok(r#""\n""#)), [r"\n"]);
    }

    #[test]
    fn double_quoted_preserves_metacharacters() {
        assert_eq!(values(&tok(r#""|><&;`(*?[$""#)), ["|><&;`(*?[$"]);
    }

    #[test]
    fn double_quoted_preserves_dollar_expansion() {
        assert_eq!(values(&tok(r#""$HOME""#)), ["$HOME"]);
    }

    #[test]
    fn empty_double_quotes_produce_empty_token() {
        assert_eq!(values(&tok(r#""""#)), [""]);
    }

    #[test]
    fn double_quote_adjacent_to_word() {
        assert_eq!(values(&tok(r#"foo"bar"baz"#)), ["foobarbaz"]);
    }

    #[test]
    fn unclosed_double_quote_is_error() {
        let e = tok_err(r#""unclosed"#);
        assert!(
            matches!(e, TokenizationError::UnclosedDoubleQuote { offset: 0 }),
            "got: {e:?}"
        );
    }

    #[test]
    fn unclosed_double_quote_offset_is_correct() {
        // The `"` is at byte offset 4 (after `foo `).
        let e = tok_err(r#"foo "bar"#);
        assert!(
            matches!(e, TokenizationError::UnclosedDoubleQuote { offset: 4 }),
            "got: {e:?}"
        );
    }

    // ── Backslash escaping (unquoted) ─────────────────────────────────────────

    #[test]
    fn backslash_escapes_space() {
        // `foo\ bar` → single token `foo bar`
        assert_eq!(values(&tok(r"foo\ bar")), ["foo bar"]);
    }

    #[test]
    fn backslash_escapes_pipe() {
        assert_eq!(values(&tok(r"\|")), ["|"]);
    }

    #[test]
    fn backslash_escapes_dollar() {
        assert_eq!(values(&tok(r"\$HOME")), ["$HOME"]);
    }

    #[test]
    fn backslash_escapes_backslash() {
        assert_eq!(values(&tok(r"\\")), ["\\"]);
    }

    #[test]
    fn backslash_escapes_asterisk() {
        assert_eq!(values(&tok(r"\*")), ["*"]);
    }

    #[test]
    fn trailing_backslash_is_error() {
        assert!(matches!(
            tok_err(r"\"),
            TokenizationError::TrailingBackslash
        ));
    }

    #[test]
    fn trailing_backslash_after_token_is_error() {
        assert!(matches!(
            tok_err(r"foo \"),
            TokenizationError::TrailingBackslash
        ));
    }

    // ── Metacharacter rejection ───────────────────────────────────────────────

    #[test]
    fn rejects_pipe() {
        let e = tok_err("foo | bar");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter { character: '|', .. }
            ),
            "got: {e:?}"
        );
    }

    #[test]
    fn rejects_redirect_out() {
        let e = tok_err("foo > /dev/null");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter { character: '>', .. }
            ),
            "got: {e:?}"
        );
    }

    #[test]
    fn rejects_redirect_in() {
        let e = tok_err("foo < /dev/null");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter { character: '<', .. }
            ),
            "got: {e:?}"
        );
    }

    #[test]
    fn rejects_ampersand() {
        let e = tok_err("foo & bar");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter { character: '&', .. }
            ),
            "got: {e:?}"
        );
    }

    #[test]
    fn rejects_double_ampersand() {
        // `&&` — the first `&` is already rejected.
        let e = tok_err("foo && bar");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter { character: '&', .. }
            ),
            "got: {e:?}"
        );
    }

    #[test]
    fn rejects_semicolon() {
        let e = tok_err("foo; bar");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter { character: ';', .. }
            ),
            "got: {e:?}"
        );
    }

    #[test]
    fn rejects_backtick() {
        let e = tok_err("foo `bar`");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter { character: '`', .. }
            ),
            "got: {e:?}"
        );
    }

    #[test]
    fn rejects_open_paren() {
        let e = tok_err("foo (bar)");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter { character: '(', .. }
            ),
            "got: {e:?}"
        );
    }

    #[test]
    fn rejects_dollar_paren_subshell() {
        // `$(cmd)` — `$` followed by `(` triggers rejection.
        let e = tok_err("foo $(cmd)");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter { character: '$', .. }
            ),
            "got: {e:?}"
        );
    }

    #[test]
    fn rejects_dollar_brace_expansion() {
        let e = tok_err("foo ${VAR}");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter { character: '$', .. }
            ),
            "got: {e:?}"
        );
    }

    #[test]
    fn rejects_dollar_alphanumeric_expansion() {
        let e = tok_err("foo $HOME");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter { character: '$', .. }
            ),
            "got: {e:?}"
        );
    }

    #[test]
    fn rejects_glob_star() {
        let e = tok_err("ls *");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter { character: '*', .. }
            ),
            "got: {e:?}"
        );
    }

    #[test]
    fn rejects_glob_question() {
        let e = tok_err("ls ?");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter { character: '?', .. }
            ),
            "got: {e:?}"
        );
    }

    #[test]
    fn rejects_glob_bracket() {
        let e = tok_err("ls [abc]");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter { character: '[', .. }
            ),
            "got: {e:?}"
        );
    }

    #[test]
    fn rejected_metacharacter_offset_is_correct() {
        // `foo |` — the `|` is at byte offset 4.
        let e = tok_err("foo |");
        assert!(
            matches!(
                e,
                TokenizationError::RejectedMetacharacter {
                    character: '|',
                    offset: 4
                }
            ),
            "got: {e:?}"
        );
    }

    // ── Bare `$` (not followed by expansion trigger) is allowed ──────────────

    #[test]
    fn bare_dollar_at_eof_is_literal() {
        assert_eq!(values(&tok("foo$")), ["foo$"]);
    }

    #[test]
    fn bare_dollar_before_space_is_literal() {
        assert_eq!(values(&tok("$ foo")), ["$", "foo"]);
    }

    #[test]
    fn bare_dollar_before_quote_is_literal() {
        // `$'foo'` — `$` before `'` is literal, then single-quoted `foo`.
        assert_eq!(values(&tok("$'foo'")), ["$foo"]);
    }

    // ── Metacharacters inside quotes are allowed ──────────────────────────────

    #[test]
    fn pipe_inside_single_quotes_is_ok() {
        assert_eq!(values(&tok("'foo|bar'")), ["foo|bar"]);
    }

    #[test]
    fn redirect_inside_double_quotes_is_ok() {
        assert_eq!(values(&tok(r#""foo>bar""#)), ["foo>bar"]);
    }

    #[test]
    fn glob_inside_single_quotes_is_ok() {
        assert_eq!(values(&tok("'*.rs'")), ["*.rs"]);
    }

    #[test]
    fn dollar_expansion_inside_double_quotes_is_ok() {
        assert_eq!(values(&tok(r#""$HOME""#)), ["$HOME"]);
    }

    #[test]
    fn semicolon_inside_double_quotes_is_ok() {
        assert_eq!(values(&tok(r#""foo;bar""#)), ["foo;bar"]);
    }

    // ── Consecutive / mixed quotes ────────────────────────────────────────────

    #[test]
    fn consecutive_single_quotes_concatenate() {
        // `'foo''bar'` → `foobar`
        assert_eq!(values(&tok("'foo''bar'")), ["foobar"]);
    }

    #[test]
    fn consecutive_double_quotes_concatenate() {
        assert_eq!(values(&tok(r#""foo""bar""#)), ["foobar"]);
    }

    #[test]
    fn mixed_quotes_concatenate() {
        // `'foo'"bar"` → `foobar`
        assert_eq!(values(&tok(r#"'foo'"bar""#)), ["foobar"]);
    }

    #[test]
    fn single_then_double_then_unquoted() {
        // `'a'"b"c` → `abc`
        assert_eq!(values(&tok(r#"'a'"b"c"#)), ["abc"]);
    }

    // ── Placeholder extraction ────────────────────────────────────────────────

    #[test]
    fn placeholder_as_full_token() {
        let r = tok("{{DB_PASS}}");
        assert_eq!(r.tokens.len(), 1);
        let t = &r.tokens[0];
        assert_eq!(t.value, "{{DB_PASS}}");
        assert_eq!(t.placeholders.len(), 1);
        let p = &t.placeholders[0];
        assert_eq!(p.key, "DB_PASS");
        assert_eq!(p.start, 0);
        assert_eq!(p.end, 11); // `{{DB_PASS}}` is 11 bytes
    }

    #[test]
    fn placeholder_embedded_in_token() {
        let r = tok("admin:{{PASS}}");
        assert_eq!(r.tokens.len(), 1);
        let t = &r.tokens[0];
        assert_eq!(t.value, "admin:{{PASS}}");
        assert_eq!(t.placeholders.len(), 1);
        let p = &t.placeholders[0];
        assert_eq!(p.key, "PASS");
        assert_eq!(p.start, 6);
        assert_eq!(p.end, 14);
    }

    #[test]
    fn placeholder_with_underscore_key() {
        let r = tok("{{_PRIVATE_KEY}}");
        assert_eq!(r.tokens[0].placeholders[0].key, "_PRIVATE_KEY");
    }

    #[test]
    fn placeholder_with_mixed_case_key() {
        let r = tok("{{MySecret123}}");
        assert_eq!(r.tokens[0].placeholders[0].key, "MySecret123");
    }

    #[test]
    fn two_placeholders_in_one_token() {
        let r = tok("{{USER}}:{{PASS}}");
        let t = &r.tokens[0];
        assert_eq!(t.placeholders.len(), 2);
        assert_eq!(t.placeholders[0].key, "USER");
        assert_eq!(t.placeholders[1].key, "PASS");
        // `{{USER}}` is 8 bytes, `:` is 1 byte, `{{PASS}}` starts at 9.
        assert_eq!(t.placeholders[0].start, 0);
        assert_eq!(t.placeholders[0].end, 8);
        assert_eq!(t.placeholders[1].start, 9);
        assert_eq!(t.placeholders[1].end, 17);
    }

    #[test]
    fn placeholder_in_second_token() {
        let r = tok("cmd --password={{SECRET}}");
        assert_eq!(r.tokens.len(), 2);
        assert_eq!(r.tokens[0].placeholders.len(), 0);
        assert_eq!(r.tokens[1].placeholders.len(), 1);
        assert_eq!(r.tokens[1].placeholders[0].key, "SECRET");
    }

    #[test]
    fn no_placeholders_in_plain_token() {
        let r = tok("hello world");
        for t in &r.tokens {
            assert!(t.placeholders.is_empty());
        }
    }

    #[test]
    fn placeholder_survives_double_quote_context() {
        // The placeholder text is produced literally inside double quotes.
        let r = tok(r#""{{DB_PASS}}""#);
        assert_eq!(r.tokens[0].value, "{{DB_PASS}}");
        assert_eq!(r.tokens[0].placeholders[0].key, "DB_PASS");
    }

    #[test]
    fn placeholder_survives_single_quote_context() {
        let r = tok("'{{DB_PASS}}'");
        assert_eq!(r.tokens[0].value, "{{DB_PASS}}");
        assert_eq!(r.tokens[0].placeholders[0].key, "DB_PASS");
    }

    // ── Malformed placeholder detection ──────────────────────────────────────

    #[test]
    fn unclosed_placeholder_is_error() {
        let e = tok_err("{{FOO");
        assert!(
            matches!(e, TokenizationError::MalformedPlaceholder { .. }),
            "got: {e:?}"
        );
    }

    #[test]
    fn unclosed_placeholder_fragment_contains_opening() {
        let e = tok_err("{{FOO");
        if let TokenizationError::MalformedPlaceholder { fragment } = e {
            assert!(fragment.starts_with("{{"), "fragment: {fragment:?}");
            assert!(fragment.contains("FOO"), "fragment: {fragment:?}");
        } else {
            panic!("wrong error variant");
        }
    }

    #[test]
    fn unclosed_placeholder_embedded_in_token() {
        let e = tok_err("admin:{{PASS");
        assert!(
            matches!(e, TokenizationError::MalformedPlaceholder { .. }),
            "got: {e:?}"
        );
    }

    #[test]
    fn placeholder_with_empty_key_is_error() {
        // `{{}}` — empty key name is invalid.
        let e = tok_err("{{}}");
        assert!(
            matches!(e, TokenizationError::InvalidKeyName { .. }),
            "got: {e:?}"
        );
    }

    #[test]
    fn placeholder_with_numeric_start_key_is_error() {
        // `{{1FOO}}` — key must start with letter or `_`.
        let e = tok_err("{{1FOO}}");
        assert!(
            matches!(e, TokenizationError::InvalidKeyName { .. }),
            "got: {e:?}"
        );
    }

    #[test]
    fn placeholder_with_hyphen_in_key_is_error() {
        // `{{FOO-BAR}}` — hyphens are not allowed in key names.
        let e = tok_err("{{FOO-BAR}}");
        assert!(
            matches!(e, TokenizationError::InvalidKeyName { .. }),
            "got: {e:?}"
        );
    }

    // ── Lone braces are not placeholders ─────────────────────────────────────

    #[test]
    fn single_open_brace_is_literal() {
        assert_eq!(values(&tok("{foo}")), ["{foo}"]);
    }

    #[test]
    fn single_close_brace_is_literal() {
        assert_eq!(values(&tok("foo}")), ["foo}"]);
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn single_character_token() {
        assert_eq!(values(&tok("x")), ["x"]);
    }

    #[test]
    fn token_with_only_escaped_space() {
        assert_eq!(values(&tok(r"\ ")), [" "]);
    }

    #[test]
    fn multiple_escaped_spaces_form_one_token() {
        assert_eq!(values(&tok(r"a\ b\ c")), ["a b c"]);
    }

    #[test]
    fn empty_single_quote_between_words() {
        // `foo''bar` → `foobar` (empty single-quoted string concatenates)
        assert_eq!(values(&tok("foo''bar")), ["foobar"]);
    }

    #[test]
    fn empty_double_quote_between_words() {
        assert_eq!(values(&tok(r#"foo""bar"#)), ["foobar"]);
    }

    #[test]
    fn newline_inside_single_quotes_is_literal() {
        assert_eq!(values(&tok("'foo\nbar'")), ["foo\nbar"]);
    }

    #[test]
    fn newline_inside_double_quotes_is_literal() {
        assert_eq!(values(&tok("\"foo\nbar\"")), ["foo\nbar"]);
    }

    #[test]
    fn unicode_characters_pass_through() {
        assert_eq!(values(&tok("héllo wörld")), ["héllo", "wörld"]);
    }

    #[test]
    fn unicode_inside_single_quotes() {
        assert_eq!(values(&tok("'héllo wörld'")), ["héllo wörld"]);
    }

    #[test]
    fn backslash_escapes_unicode() {
        // `\é` → `é` (the backslash is consumed, the char is literal)
        assert_eq!(values(&tok("\\é")), ["é"]);
    }

    #[test]
    fn complex_real_world_command() {
        // Simulate: psql "postgresql://{{DB_USER}}:{{DB_PASS}}@localhost/mydb"
        let r = tok(r#"psql "postgresql://{{DB_USER}}:{{DB_PASS}}@localhost/mydb""#);
        assert_eq!(r.tokens.len(), 2);
        assert_eq!(r.tokens[0].value, "psql");
        assert_eq!(
            r.tokens[1].value,
            "postgresql://{{DB_USER}}:{{DB_PASS}}@localhost/mydb"
        );
        assert_eq!(r.tokens[1].placeholders.len(), 2);
        assert_eq!(r.tokens[1].placeholders[0].key, "DB_USER");
        assert_eq!(r.tokens[1].placeholders[1].key, "DB_PASS");
    }

    #[test]
    fn command_with_escaped_metachar_and_placeholder() {
        // `curl \-d '{"key":"{{API_KEY}}"}'`
        let r = tok(r#"curl \-d '{"key":"{{API_KEY}}"}'"#);
        assert_eq!(r.tokens.len(), 3);
        assert_eq!(r.tokens[0].value, "curl");
        assert_eq!(r.tokens[1].value, "-d");
        assert_eq!(r.tokens[2].value, r#"{"key":"{{API_KEY}}"}"#);
        assert_eq!(r.tokens[2].placeholders[0].key, "API_KEY");
    }

    #[test]
    fn placeholder_byte_offsets_are_correct_with_multibyte_prefix() {
        // Token value: `héllo:{{KEY}}` — `héllo` is 6 bytes (é = 2 bytes),
        // `:` is 1 byte, so `{{KEY}}` starts at byte 7.
        let r = tok("héllo:{{KEY}}");
        let p = &r.tokens[0].placeholders[0];
        assert_eq!(p.key, "KEY");
        // `h` = 1, `é` = 2, `l` = 1, `l` = 1, `o` = 1, `:` = 1 → 7 bytes
        assert_eq!(p.start, 7);
        assert_eq!(p.end, 14); // 7 + len("{{KEY}}") = 7 + 7 = 14
    }
}
