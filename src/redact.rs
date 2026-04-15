//! Output redaction engine for secretsh.
//!
//! [`Redactor`] builds an Aho-Corasick multi-pattern automaton from a set of
//! `(key_name, secret_value)` pairs and uses it to scan child-process output
//! in O(n) time, replacing every occurrence of a secret (in raw or encoded
//! form) with a bracketed label such as `[REDACTED_DB_PASS]`.
//!
//! # Encoded variants
//!
//! For each secret value the engine generates up to six patterns:
//!
//! | Encoding          | Replacement label          |
//! |-------------------|----------------------------|
//! | Raw bytes         | `[REDACTED_KEY]`           |
//! | Base64 standard   | `[REDACTED_KEY_B64]`       |
//! | Base64 URL-safe   | `[REDACTED_KEY_B64URL]`    |
//! | URL percent-enc.  | `[REDACTED_KEY_URL]`       |
//! | Hex lowercase     | `[REDACTED_KEY_HEX]`       |
//! | Hex uppercase     | `[REDACTED_KEY_HEX]`       |
//!
//! Encoded variants that are byte-for-byte identical to the raw value are
//! skipped to avoid duplicate automaton patterns.  Empty secret values are
//! also skipped entirely.

use std::io::{self, Read, Write};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use base64::{engine::general_purpose, Engine as _};
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};

use crate::error::{RedactionError, SecretshError};

// ─────────────────────────────────────────────────────────────────────────────
// Internal buffer size for streaming redaction
// ─────────────────────────────────────────────────────────────────────────────

/// Read chunk size for [`Redactor::redact_stream`].
///
/// 64 KiB is a reasonable balance between memory pressure and syscall
/// overhead.  The implementation accumulates the full input before replacing
/// so that multi-byte patterns that straddle chunk boundaries are never missed.
const STREAM_BUF_SIZE: usize = 65_536;

// ─────────────────────────────────────────────────────────────────────────────
// Redactor
// ─────────────────────────────────────────────────────────────────────────────

/// Multi-pattern output redactor.
///
/// Construct once with [`Redactor::new`], then call [`redact_bytes`],
/// [`redact_str`], or [`redact_stream`] as many times as needed.  The
/// automaton is immutable after construction and is safe to share across
/// threads.
///
/// [`redact_bytes`]: Redactor::redact_bytes
/// [`redact_str`]: Redactor::redact_str
/// [`redact_stream`]: Redactor::redact_stream
pub struct Redactor {
    /// The compiled Aho-Corasick automaton.  `None` when no non-empty patterns
    /// were provided (i.e. all secrets were empty strings).
    automaton: Option<AhoCorasick>,

    /// Replacement labels, indexed in lock-step with the patterns fed to the
    /// automaton.  `replacements[i]` is the byte string that replaces pattern
    /// `i` in the output.
    replacements: Vec<Vec<u8>>,
}

impl Redactor {
    // ── Construction ─────────────────────────────────────────────────────────

    /// Build a new [`Redactor`] from a slice of `(key_name, secret_value)`
    /// pairs.
    ///
    /// # Errors
    ///
    /// Returns [`SecretshError::Redaction`] if the Aho-Corasick automaton
    /// cannot be constructed (e.g. the combined pattern set is too large for
    /// the underlying DFA).
    pub fn new(secrets: &[(&str, &[u8])]) -> Result<Self, SecretshError> {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut replacements: Vec<Vec<u8>> = Vec::new();

        for (key, value) in secrets {
            // Skip empty secret values — they would match every position.
            if value.is_empty() {
                continue;
            }

            // ── Raw bytes ─────────────────────────────────────────────────
            let raw_label = format!("[REDACTED_{key}]");
            patterns.push(value.to_vec());
            replacements.push(raw_label.into_bytes());

            // ── Base64 standard ───────────────────────────────────────────
            let b64 = general_purpose::STANDARD.encode(value).into_bytes();
            if b64 != *value {
                let label = format!("[REDACTED_{key}_B64]");
                patterns.push(b64);
                replacements.push(label.into_bytes());
            }

            // ── Base64 URL-safe ───────────────────────────────────────────
            let b64url = general_purpose::URL_SAFE.encode(value).into_bytes();
            if b64url != *value {
                let label = format!("[REDACTED_{key}_B64URL]");
                patterns.push(b64url);
                replacements.push(label.into_bytes());
            }

            // ── URL percent-encoding ──────────────────────────────────────
            let url_enc = percent_encode(value, NON_ALPHANUMERIC)
                .to_string()
                .into_bytes();
            if url_enc != *value {
                let label = format!("[REDACTED_{key}_URL]");
                patterns.push(url_enc);
                replacements.push(label.into_bytes());
            }

            // ── Hex lowercase ─────────────────────────────────────────────
            let hex_lower = hex::encode(value).into_bytes();
            if hex_lower != *value {
                let label = format!("[REDACTED_{key}_HEX]");
                patterns.push(hex_lower);
                replacements.push(label.into_bytes());
            }

            // ── Hex uppercase ─────────────────────────────────────────────
            let hex_upper = hex::encode_upper(value).into_bytes();
            if hex_upper != *value {
                let label = format!("[REDACTED_{key}_HEX]");
                patterns.push(hex_upper);
                replacements.push(label.into_bytes());
            }
        }

        if patterns.is_empty() {
            return Ok(Self {
                automaton: None,
                replacements: Vec::new(),
            });
        }

        let automaton = AhoCorasickBuilder::new()
            // LeftmostFirst: prefer the pattern that starts earliest; among
            // ties, prefer the one listed first (raw > encoded variants).
            .match_kind(MatchKind::LeftmostFirst)
            .build(&patterns)
            .map_err(|e| {
                SecretshError::Redaction(RedactionError::PatternBuildFailed {
                    reason: e.to_string(),
                })
            })?;

        Ok(Self {
            automaton: Some(automaton),
            replacements,
        })
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Returns `true` if the redactor has at least one pattern to match.
    ///
    /// When this returns `false`, all `redact_*` methods are no-ops that
    /// return the input unchanged.
    #[inline]
    pub fn has_patterns(&self) -> bool {
        self.automaton.is_some()
    }

    /// Redact a byte slice, returning the redacted bytes.
    ///
    /// All occurrences of any registered pattern (raw or encoded) are replaced
    /// with the corresponding label.  The replacement is performed in a single
    /// left-to-right pass using the Aho-Corasick automaton, so overlapping
    /// matches are handled correctly (the leftmost match wins).
    pub fn redact_bytes(&self, input: &[u8]) -> Vec<u8> {
        let Some(ac) = &self.automaton else {
            return input.to_vec();
        };

        // Pre-allocate with the same capacity as the input; the output will
        // usually be similar in size (labels are short).
        let mut output = Vec::with_capacity(input.len());
        let mut last_end = 0usize;

        for mat in ac.find_iter(input) {
            // Append the unmatched bytes before this match.
            output.extend_from_slice(&input[last_end..mat.start()]);
            // Append the replacement label.
            output.extend_from_slice(&self.replacements[mat.pattern().as_usize()]);
            last_end = mat.end();
        }

        // Append any trailing bytes after the last match.
        output.extend_from_slice(&input[last_end..]);
        output
    }

    /// Redact a string slice, returning the redacted `String`.
    ///
    /// The input is treated as raw bytes during matching (patterns may be
    /// arbitrary byte sequences).  The output is converted back to `String`
    /// using [`String::from_utf8_lossy`] so that any replacement labels
    /// (which are always valid UTF-8) are preserved even if the surrounding
    /// bytes are not.
    pub fn redact_str(&self, input: &str) -> String {
        let redacted = self.redact_bytes(input.as_bytes());
        String::from_utf8_lossy(&redacted).into_owned()
    }

    /// Stream redaction: read all bytes from `input`, redact them, and write
    /// the result to `output`.
    ///
    /// The current implementation buffers the entire input in memory before
    /// performing replacement.  This is necessary because a secret value may
    /// straddle an arbitrary chunk boundary.  For very large outputs consider
    /// using a sliding-window approach, but for the typical use-case of
    /// subprocess stdout/stderr this is acceptable — `spawn_child` enforces a
    /// configurable output limit (default 50 MiB) so the buffer size is bounded.
    ///
    /// # Returns
    ///
    /// The number of bytes written to `output`.
    ///
    /// # Errors
    ///
    /// Returns an [`io::Error`] if reading from `input` or writing to `output`
    /// fails.
    pub fn redact_stream(
        &self,
        input: &mut dyn Read,
        output: &mut dyn Write,
    ) -> Result<u64, io::Error> {
        // Read the full input into a buffer.
        let mut buf = Vec::with_capacity(STREAM_BUF_SIZE);
        input.read_to_end(&mut buf)?;

        // Perform redaction.
        let redacted = self.redact_bytes(&buf);

        // Write the redacted bytes to the output.
        output.write_all(&redacted)?;

        Ok(redacted.len() as u64)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Convenience: build a Redactor from a single key/value pair.
    fn single(key: &str, value: &[u8]) -> Redactor {
        Redactor::new(&[(key, value)]).expect("Redactor::new should not fail")
    }

    // ── Basic redaction ───────────────────────────────────────────────────────

    #[test]
    fn single_secret_raw_redacted() {
        let r = single("DB_PASS", b"hunter2");
        let out = r.redact_str("The password is hunter2, keep it safe.");
        assert_eq!(out, "The password is [REDACTED_DB_PASS], keep it safe.");
    }

    #[test]
    fn multiple_secrets_all_redacted() {
        let r = Redactor::new(&[("API_KEY", b"abc123"), ("DB_PASS", b"hunter2")]).unwrap();
        let out = r.redact_str("key=abc123 pass=hunter2 end");
        assert_eq!(out, "key=[REDACTED_API_KEY] pass=[REDACTED_DB_PASS] end");
    }

    #[test]
    fn no_match_returns_input_unchanged() {
        let r = single("TOKEN", b"secret_token");
        let input = "nothing sensitive here";
        assert_eq!(r.redact_str(input), input);
    }

    // ── Encoded variant redaction ─────────────────────────────────────────────

    #[test]
    fn base64_encoded_secret_redacted() {
        let value = b"hunter2";
        let b64 = general_purpose::STANDARD.encode(value); // "aHVudGVyMg=="
        let r = single("DB_PASS", value);
        let input = format!("encoded={b64}");
        let out = r.redact_str(&input);
        assert_eq!(out, "encoded=[REDACTED_DB_PASS_B64]");
    }

    #[test]
    fn base64url_encoded_secret_redacted() {
        // Use a value whose URL-safe and standard encodings differ (padding
        // characters are the same here, but the alphabet differs for values
        // that produce `+` or `/` in standard base64).
        let value = b"\xfb\xff"; // standard: "+/8=", url-safe: "-_8="
        let b64url = general_purpose::URL_SAFE.encode(value);
        let r = single("BIN", value);
        let input = format!("data={b64url}");
        let out = r.redact_str(&input);
        assert_eq!(out, "data=[REDACTED_BIN_B64URL]");
    }

    #[test]
    fn url_encoded_secret_redacted() {
        let value = b"p@ss w0rd!";
        let url_enc = percent_encode(value, NON_ALPHANUMERIC).to_string();
        let r = single("PASS", value);
        let input = format!("password={url_enc}");
        let out = r.redact_str(&input);
        assert_eq!(out, "password=[REDACTED_PASS_URL]");
    }

    #[test]
    fn hex_lower_encoded_secret_redacted() {
        let value = b"deadbeef_raw";
        let hex_l = hex::encode(value);
        let r = single("KEY", value);
        let input = format!("hex={hex_l}");
        let out = r.redact_str(&input);
        assert_eq!(out, "hex=[REDACTED_KEY_HEX]");
    }

    #[test]
    fn hex_upper_encoded_secret_redacted() {
        let value = b"deadbeef_raw";
        let hex_u = hex::encode_upper(value);
        let r = single("KEY", value);
        let input = format!("hex={hex_u}");
        let out = r.redact_str(&input);
        assert_eq!(out, "hex=[REDACTED_KEY_HEX]");
    }

    // ── Edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn empty_secret_value_is_skipped() {
        // An empty value must not be added as a pattern (it would match
        // everywhere and produce nonsensical output).
        let r = Redactor::new(&[("EMPTY", b""), ("REAL", b"secret")]).unwrap();
        assert!(r.has_patterns(), "REAL should still produce patterns");
        let out = r.redact_str("value=secret");
        assert_eq!(out, "value=[REDACTED_REAL]");
    }

    #[test]
    fn all_empty_secrets_yields_no_patterns() {
        let r = Redactor::new(&[("A", b""), ("B", b"")]).unwrap();
        assert!(!r.has_patterns());
    }

    #[test]
    fn no_secrets_yields_no_patterns() {
        let r = Redactor::new(&[]).unwrap();
        assert!(!r.has_patterns());
        let input = "nothing to redact";
        assert_eq!(r.redact_str(input), input);
    }

    #[test]
    fn overlapping_secrets_leftmost_wins() {
        // "abcdef" contains both "abc" and "abcdef".  The automaton uses
        // LeftmostFirst so the longer (earlier-starting, same start) match
        // should win — but here both start at 0, so the first-listed pattern
        // ("abcdef") wins because it is listed first.
        let r = Redactor::new(&[("LONG", b"abcdef"), ("SHORT", b"abc")]).unwrap();
        let out = r.redact_str("abcdef");
        // LeftmostFirst: "abcdef" starts at 0 and is listed before "abc".
        assert_eq!(out, "[REDACTED_LONG]");
    }

    #[test]
    fn adjacent_secrets_both_redacted() {
        let r = Redactor::new(&[("A", b"foo"), ("B", b"bar")]).unwrap();
        let out = r.redact_str("foobar");
        assert_eq!(out, "[REDACTED_A][REDACTED_B]");
    }

    #[test]
    fn secret_at_start_of_input() {
        let r = single("S", b"secret");
        assert_eq!(r.redact_str("secret is here"), "[REDACTED_S] is here");
    }

    #[test]
    fn secret_at_end_of_input() {
        let r = single("S", b"secret");
        assert_eq!(
            r.redact_str("the value is secret"),
            "the value is [REDACTED_S]"
        );
    }

    #[test]
    fn multiple_occurrences_all_redacted() {
        let r = single("K", b"tok");
        let out = r.redact_str("tok tok tok");
        assert_eq!(out, "[REDACTED_K] [REDACTED_K] [REDACTED_K]");
    }

    // ── Deduplication: encoded == raw ─────────────────────────────────────────

    #[test]
    fn encoded_equal_to_raw_not_duplicated() {
        // If the raw value happens to be valid ASCII that is identical to its
        // hex-lower encoding (contrived but possible for single hex chars),
        // the duplicate must not be added.  We verify indirectly: the
        // automaton must still build successfully and produce correct output.
        //
        // More practically: for a value like b"61" (ASCII "61"), hex::encode
        // produces "3631" which differs, so no dedup occurs.  We test the
        // dedup guard by constructing a value whose base64 equals itself —
        // which is impossible for non-empty values, so we instead verify that
        // the automaton builds without error and that the pattern count is
        // bounded.
        let r = Redactor::new(&[("X", b"hello")]).unwrap();
        assert!(r.has_patterns());
        // "hello" in base64 is "aGVsbG8=" — different, so B64 pattern added.
        let b64 = general_purpose::STANDARD.encode(b"hello");
        let out = r.redact_str(&format!("raw=hello b64={b64}"));
        assert_eq!(out, "raw=[REDACTED_X] b64=[REDACTED_X_B64]");
    }

    // ── Label format ──────────────────────────────────────────────────────────

    #[test]
    fn label_format_raw() {
        let r = single("MY_SECRET", b"val");
        assert_eq!(r.redact_str("val"), "[REDACTED_MY_SECRET]");
    }

    #[test]
    fn label_format_b64() {
        let value = b"val";
        let b64 = general_purpose::STANDARD.encode(value);
        let r = single("MY_SECRET", value);
        assert_eq!(r.redact_str(&b64), "[REDACTED_MY_SECRET_B64]");
    }

    #[test]
    fn label_format_b64url() {
        // Use bytes that produce different standard vs URL-safe base64.
        let value = b"\xfb\xff\xfe";
        let b64url = general_purpose::URL_SAFE.encode(value);
        let r = single("MY_SECRET", value);
        assert_eq!(r.redact_str(&b64url), "[REDACTED_MY_SECRET_B64URL]");
    }

    #[test]
    fn label_format_url() {
        let value = b"a b";
        let url_enc = percent_encode(value, NON_ALPHANUMERIC).to_string();
        let r = single("MY_SECRET", value);
        assert_eq!(r.redact_str(&url_enc), "[REDACTED_MY_SECRET_URL]");
    }

    #[test]
    fn label_format_hex_lower() {
        let value = b"abc";
        let hex_l = hex::encode(value); // "616263"
        let r = single("MY_SECRET", value);
        assert_eq!(r.redact_str(&hex_l), "[REDACTED_MY_SECRET_HEX]");
    }

    #[test]
    fn label_format_hex_upper() {
        let value = b"abc";
        let hex_u = hex::encode_upper(value); // "616263"
        let r = single("MY_SECRET", value);
        assert_eq!(r.redact_str(&hex_u), "[REDACTED_MY_SECRET_HEX]");
    }

    // ── redact_bytes ──────────────────────────────────────────────────────────

    #[test]
    fn redact_bytes_works_on_binary_data() {
        let value: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        let r = single("BIN", value);
        let mut input = b"prefix ".to_vec();
        input.extend_from_slice(value);
        input.extend_from_slice(b" suffix");
        let out = r.redact_bytes(&input);
        assert_eq!(out, b"prefix [REDACTED_BIN] suffix");
    }

    // ── Streaming redaction ───────────────────────────────────────────────────

    #[test]
    fn redact_stream_basic() {
        let r = single("TOKEN", b"s3cr3t");
        let input_data = b"Authorization: Bearer s3cr3t\n";
        let mut input = io::Cursor::new(input_data);
        let mut output = Vec::new();
        let bytes_written = r.redact_stream(&mut input, &mut output).unwrap();
        let expected = b"Authorization: Bearer [REDACTED_TOKEN]\n";
        assert_eq!(output, expected);
        assert_eq!(bytes_written, expected.len() as u64);
    }

    #[test]
    fn redact_stream_no_match_passes_through() {
        let r = single("TOKEN", b"s3cr3t");
        let input_data = b"nothing sensitive here\n";
        let mut input = io::Cursor::new(input_data);
        let mut output = Vec::new();
        let bytes_written = r.redact_stream(&mut input, &mut output).unwrap();
        assert_eq!(output, input_data);
        assert_eq!(bytes_written, input_data.len() as u64);
    }

    #[test]
    fn redact_stream_empty_input() {
        let r = single("TOKEN", b"s3cr3t");
        let mut input = io::Cursor::new(b"");
        let mut output = Vec::new();
        let bytes_written = r.redact_stream(&mut input, &mut output).unwrap();
        assert_eq!(output, b"");
        assert_eq!(bytes_written, 0);
    }

    #[test]
    fn redact_stream_multiple_secrets() {
        let r = Redactor::new(&[("A", b"alpha"), ("B", b"beta")]).unwrap();
        let input_data = b"alpha and beta are both secrets";
        let mut input = io::Cursor::new(input_data);
        let mut output = Vec::new();
        r.redact_stream(&mut input, &mut output).unwrap();
        assert_eq!(output, b"[REDACTED_A] and [REDACTED_B] are both secrets");
    }

    // ── has_patterns ──────────────────────────────────────────────────────────

    #[test]
    fn has_patterns_true_when_secrets_present() {
        let r = single("K", b"v");
        assert!(r.has_patterns());
    }

    #[test]
    fn has_patterns_false_when_no_secrets() {
        let r = Redactor::new(&[]).unwrap();
        assert!(!r.has_patterns());
    }

    #[test]
    fn has_patterns_false_when_only_empty_secrets() {
        let r = Redactor::new(&[("K", b"")]).unwrap();
        assert!(!r.has_patterns());
    }
}
