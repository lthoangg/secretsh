//! `.env` file parser for secretsh.
//!
//! Supported syntax:
//!
//! - `KEY=value`
//! - `export KEY=value` (optional `export` prefix, stripped)
//! - `KEY="value with spaces"` (double-quoted, `\"` and `\\` escapes)
//! - `KEY='literal value'` (single-quoted, no escape processing)
//! - `# comment lines` (ignored)
//! - Blank lines (ignored)
//! - Inline comments: `KEY=value # comment` (only when unquoted)
//!
//! Key names must match `[A-Za-z_][A-Za-z0-9_]*`.
//! Values are returned as raw bytes (`Vec<u8>`).

use std::path::Path;

use zeroize::Zeroizing;

use crate::error::SecretshError;

/// A single key-value entry parsed from a `.env` file.
#[derive(Debug)]
pub struct EnvEntry {
    /// The key name (e.g. `"API_KEY"`).
    pub key: String,
    /// The secret value as raw bytes.
    pub value: Zeroizing<Vec<u8>>,
    /// 1-based line number in the source file.
    pub line: usize,
}

/// Parse a `.env` file and return all key-value entries.
///
/// Lines that are blank, contain only whitespace, or start with `#` are
/// skipped.  Lines that cannot be parsed produce an error referencing the
/// line number.
pub fn parse_dotenv(path: &Path) -> Result<Vec<EnvEntry>, SecretshError> {
    let content =
        std::fs::read_to_string(path).map_err(|e| SecretshError::Io(crate::error::IoError(e)))?;
    parse_dotenv_str(&content)
}

/// Parse the string contents of a `.env` file.
///
/// This is the testable core — [`parse_dotenv`] is a thin wrapper that
/// reads the file first.
pub fn parse_dotenv_str(content: &str) -> Result<Vec<EnvEntry>, SecretshError> {
    let mut entries = Vec::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line_num = idx + 1;
        let line = raw_line.trim();

        // Skip blank lines and comments.
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Strip optional `export ` prefix.
        let line = line
            .strip_prefix("export ")
            .or_else(|| line.strip_prefix("export\t"))
            .unwrap_or(line);

        // Split on first `=`.
        let eq_pos = line.find('=').ok_or_else(|| {
            SecretshError::Io(crate::error::IoError(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(".env line {line_num}: missing '=' delimiter"),
            )))
        })?;

        let key = line[..eq_pos].trim().to_owned();
        let raw_value = &line[eq_pos + 1..];

        let value = parse_value(raw_value, line_num)?;

        entries.push(EnvEntry {
            key,
            value: Zeroizing::new(value),
            line: line_num,
        });
    }

    Ok(entries)
}

/// Parse the value portion of a `.env` line.
///
/// Handles double-quoted, single-quoted, and unquoted values.
fn parse_value(raw: &str, line_num: usize) -> Result<Vec<u8>, SecretshError> {
    let trimmed = raw.trim_start();

    if trimmed.starts_with('"') {
        // Double-quoted: process escape sequences, find closing quote.
        parse_double_quoted(trimmed, line_num)
    } else if trimmed.starts_with('\'') {
        // Single-quoted: literal content, find closing quote.
        parse_single_quoted(trimmed, line_num)
    } else {
        // Unquoted: strip inline comments and trailing whitespace.
        let value = strip_inline_comment(trimmed);
        Ok(value.as_bytes().to_vec())
    }
}

/// Parse a double-quoted value, processing `\"` and `\\` escapes.
fn parse_double_quoted(s: &str, line_num: usize) -> Result<Vec<u8>, SecretshError> {
    // s starts with `"`, find the matching closing `"`.
    let inner = &s[1..]; // skip opening quote
    let mut result = Vec::new();
    let mut chars = inner.chars();

    loop {
        match chars.next() {
            None => {
                return Err(SecretshError::Io(crate::error::IoError(
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(".env line {line_num}: unterminated double-quoted value"),
                    ),
                )));
            }
            Some('"') => break, // closing quote
            Some('\\') => {
                match chars.next() {
                    Some('n') => result.push(b'\n'),
                    Some('t') => result.push(b'\t'),
                    Some('r') => result.push(b'\r'),
                    Some('"') => result.push(b'"'),
                    Some('\\') => result.push(b'\\'),
                    Some(c) => {
                        // Unknown escape — keep both characters.
                        result.push(b'\\');
                        let mut buf = [0u8; 4];
                        result.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                    }
                    None => {
                        return Err(SecretshError::Io(crate::error::IoError(
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!(
                                    ".env line {line_num}: trailing backslash in double-quoted value"
                                ),
                            ),
                        )));
                    }
                }
            }
            Some(c) => {
                let mut buf = [0u8; 4];
                result.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }

    Ok(result)
}

/// Parse a single-quoted value (no escape processing).
fn parse_single_quoted(s: &str, line_num: usize) -> Result<Vec<u8>, SecretshError> {
    let inner = &s[1..]; // skip opening quote
    let end = inner.find('\'').ok_or_else(|| {
        SecretshError::Io(crate::error::IoError(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(".env line {line_num}: unterminated single-quoted value"),
        )))
    })?;
    Ok(inner.as_bytes()[..end].to_vec())
}

/// Strip an inline comment from an unquoted value.
///
/// Inline comments start with ` #` (space then hash).  A bare `#` at the
/// start of the value is **not** treated as a comment — it is part of the
/// value.  Trailing whitespace is also stripped.
fn strip_inline_comment(s: &str) -> &str {
    // Look for ` #` to detect inline comments.
    if let Some(pos) = s.find(" #") {
        s[..pos].trim_end()
    } else {
        s.trim_end()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn parse(input: &str) -> Vec<EnvEntry> {
        parse_dotenv_str(input).expect("parse failed")
    }

    fn keys_values(entries: &[EnvEntry]) -> Vec<(&str, &[u8])> {
        entries
            .iter()
            .map(|e| (e.key.as_str(), e.value.as_slice()))
            .collect()
    }

    // ── Basic parsing ────────────────────────────────────────────────────────

    #[test]
    fn simple_key_value() {
        let entries = parse("API_KEY=hunter2\n");
        assert_eq!(
            keys_values(&entries),
            vec![("API_KEY", b"hunter2" as &[u8])]
        );
    }

    #[test]
    fn multiple_entries() {
        let entries = parse("A=1\nB=2\nC=3\n");
        assert_eq!(entries.len(), 3);
        assert_eq!(keys_values(&entries)[0], ("A", b"1" as &[u8]));
        assert_eq!(keys_values(&entries)[2], ("C", b"3" as &[u8]));
    }

    #[test]
    fn empty_value() {
        let entries = parse("KEY=\n");
        assert_eq!(keys_values(&entries), vec![("KEY", b"" as &[u8])]);
    }

    // ── Comments ─────────────────────────────────────────────────────────────

    #[test]
    fn comment_lines_ignored() {
        let entries = parse("# This is a comment\nKEY=val\n# Another comment\n");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "KEY");
    }

    #[test]
    fn inline_comment_stripped() {
        let entries = parse("KEY=value # this is a comment\n");
        assert_eq!(keys_values(&entries), vec![("KEY", b"value" as &[u8])]);
    }

    #[test]
    fn hash_in_value_without_leading_space_preserved() {
        // A bare # without a preceding space is part of the value.
        let entries = parse("KEY=abc#def\n");
        assert_eq!(keys_values(&entries), vec![("KEY", b"abc#def" as &[u8])]);
    }

    // ── Blank lines ──────────────────────────────────────────────────────────

    #[test]
    fn blank_lines_ignored() {
        let entries = parse("\n\nKEY=val\n\n");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn whitespace_only_lines_ignored() {
        let entries = parse("   \n\t\nKEY=val\n");
        assert_eq!(entries.len(), 1);
    }

    // ── export prefix ────────────────────────────────────────────────────────

    #[test]
    fn export_prefix_stripped() {
        let entries = parse("export API_KEY=secret\n");
        assert_eq!(keys_values(&entries), vec![("API_KEY", b"secret" as &[u8])]);
    }

    #[test]
    fn export_with_tab() {
        let entries = parse("export\tAPI_KEY=secret\n");
        assert_eq!(keys_values(&entries), vec![("API_KEY", b"secret" as &[u8])]);
    }

    // ── Double-quoted values ─────────────────────────────────────────────────

    #[test]
    fn double_quoted_value() {
        let entries = parse(r#"KEY="hello world""#);
        assert_eq!(
            keys_values(&entries),
            vec![("KEY", b"hello world" as &[u8])]
        );
    }

    #[test]
    fn double_quoted_with_escapes() {
        let entries = parse(r#"KEY="line1\nline2""#);
        assert_eq!(
            keys_values(&entries),
            vec![("KEY", b"line1\nline2" as &[u8])]
        );
    }

    #[test]
    fn double_quoted_with_escaped_quote() {
        let entries = parse(r#"KEY="say \"hi\"""#);
        assert_eq!(keys_values(&entries), vec![("KEY", b"say \"hi\"" as &[u8])]);
    }

    #[test]
    fn double_quoted_preserves_hash() {
        let entries = parse(r#"KEY="value # not a comment""#);
        assert_eq!(
            keys_values(&entries),
            vec![("KEY", b"value # not a comment" as &[u8])]
        );
    }

    #[test]
    fn unterminated_double_quote_is_error() {
        let result = parse_dotenv_str(r#"KEY="unclosed"#);
        assert!(result.is_err());
    }

    // ── Single-quoted values ─────────────────────────────────────────────────

    #[test]
    fn single_quoted_value() {
        let entries = parse("KEY='hello world'\n");
        assert_eq!(
            keys_values(&entries),
            vec![("KEY", b"hello world" as &[u8])]
        );
    }

    #[test]
    fn single_quoted_no_escape_processing() {
        // Backslashes are literal in single quotes.
        let entries = parse(r"KEY='no\nescape'");
        assert_eq!(
            keys_values(&entries),
            vec![("KEY", br"no\nescape" as &[u8])]
        );
    }

    #[test]
    fn single_quoted_preserves_hash() {
        let entries = parse("KEY='value # not a comment'\n");
        assert_eq!(
            keys_values(&entries),
            vec![("KEY", b"value # not a comment" as &[u8])]
        );
    }

    #[test]
    fn unterminated_single_quote_is_error() {
        let result = parse_dotenv_str("KEY='unclosed");
        assert!(result.is_err());
    }

    // ── Missing delimiter ────────────────────────────────────────────────────

    #[test]
    fn missing_equals_is_error() {
        let result = parse_dotenv_str("NOEQUALS\n");
        assert!(result.is_err());
    }

    // ── Line numbers ─────────────────────────────────────────────────────────

    #[test]
    fn line_numbers_are_correct() {
        let entries = parse("# comment\n\nA=1\n# another\nB=2\n");
        assert_eq!(entries[0].line, 3);
        assert_eq!(entries[1].line, 5);
    }

    // ── Whitespace handling ──────────────────────────────────────────────────

    #[test]
    fn trailing_whitespace_on_unquoted_stripped() {
        let entries = parse("KEY=value   \n");
        assert_eq!(keys_values(&entries), vec![("KEY", b"value" as &[u8])]);
    }

    #[test]
    fn value_with_equals_sign() {
        // Only the first `=` is the delimiter.
        let entries = parse("KEY=abc=def\n");
        assert_eq!(keys_values(&entries), vec![("KEY", b"abc=def" as &[u8])]);
    }
}
