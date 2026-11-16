//! Finding the engine's numbered tokens (`[IBAN_1]`, `[PERSON_NAME_2]`) in text the model
//! writes, and swapping them back as the text streams in.
//!
//! The grammar is `sonar-detection`'s `anyTokenScanRegex`:
//! `\[[A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)*_\d+\]`. A stream splits text anywhere (`"OK jean"`,
//! `".dupont@example.com"` for a value; `"[EMA"`, `"IL_1]"` for a token), so the stream
//! detokenizer holds back a tail that may still become a token.

use std::ops::Range;

/// Longest tail held back waiting for a token to close. Real tokens are far shorter; past
/// this, the tail is text that only looked like a token's start.
const MAX_TOKEN_LEN: usize = 64;

enum Parse {
    /// A complete token ends at this byte offset (exclusive), relative to the `[`.
    Token(usize),
    /// The input ended inside what is still a valid token prefix.
    Prefix,
    NoMatch,
}

/// Parses a token starting at `s[0] == '['`. The grammar is unambiguous: a segment starts with
/// a letter, the number with a digit, so no backtracking is needed.
fn parse(s: &[u8]) -> Parse {
    debug_assert_eq!(s.first(), Some(&b'['));
    let mut i = 1;
    let at = |i: usize| s.get(i).copied();
    // First segment: [A-Z][A-Z0-9]*
    match at(i) {
        None => return Parse::Prefix,
        Some(c) if c.is_ascii_uppercase() => i += 1,
        Some(_) => return Parse::NoMatch,
    }
    loop {
        while at(i).is_some_and(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
            i += 1;
        }
        match at(i) {
            None => return Parse::Prefix,
            Some(b'_') => i += 1,
            Some(_) => return Parse::NoMatch,
        }
        match at(i) {
            None => return Parse::Prefix,
            // Another segment.
            Some(c) if c.is_ascii_uppercase() => i += 1,
            // The number, then `]`.
            Some(c) if c.is_ascii_digit() => {
                while at(i).is_some_and(|c| c.is_ascii_digit()) {
                    i += 1;
                }
                return match at(i) {
                    None => Parse::Prefix,
                    Some(b']') => Parse::Token(i + 1),
                    Some(_) => Parse::NoMatch,
                };
            }
            Some(_) => return Parse::NoMatch,
        }
    }
}

/// Byte ranges of the complete tokens in `text`.
pub fn find(text: &str) -> Vec<Range<usize>> {
    let bytes = text.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while let Some(offset) = bytes[i..].iter().position(|&b| b == b'[') {
        let start = i + offset;
        match parse(&bytes[start..]) {
            Parse::Token(len) => {
                out.push(start..start + len);
                i = start + len;
            }
            Parse::Prefix | Parse::NoMatch => i = start + 1,
        }
    }
    out
}

/// Where a trailing, still-open token prefix starts, if any. Only the last `[` can start one:
/// a token cannot contain `[`.
fn open_prefix(text: &str) -> Option<usize> {
    let start = text.rfind('[')?;
    match parse(&text.as_bytes()[start..]) {
        Parse::Prefix if text.len() - start < MAX_TOKEN_LEN => Some(start),
        _ => None,
    }
}

/// How a resolved value is written back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escape {
    /// Plain text (`text_delta`).
    None,
    /// Inside a JSON string literal (`input_json_delta` fragments of a tool call's input).
    JsonString,
}

/// Replaces every complete token that `resolve` knows; unknown tokens stay as they are.
pub fn replace(text: &str, escape: Escape, resolve: &mut dyn FnMut(&str) -> Option<String>) -> String {
    let ranges = find(text);
    if ranges.is_empty() {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for range in ranges {
        out.push_str(&text[last..range.start]);
        let token = &text[range.clone()];
        match resolve(token) {
            Some(value) if escape == Escape::JsonString => {
                let quoted = serde_json::to_string(&value).unwrap_or_default();
                out.push_str(&quoted[1..quoted.len() - 1]);
            }
            Some(value) => out.push_str(&value),
            None => out.push_str(token),
        }
        last = range.end;
    }
    out.push_str(&text[last..]);
    out
}

/// Detokenizes one content block's text as it streams: what it returns is final, a possible
/// token prefix at the end is held until the next chunk or `finish`.
#[derive(Debug)]
pub struct StreamDetokenizer {
    escape: Escape,
    held: String,
}

impl StreamDetokenizer {
    pub fn new(escape: Escape) -> Self {
        Self { escape, held: String::new() }
    }

    pub fn escape(&self) -> Escape {
        self.escape
    }

    pub fn push(&mut self, chunk: &str, resolve: &mut dyn FnMut(&str) -> Option<String>) -> String {
        self.held.push_str(chunk);
        let ready = match open_prefix(&self.held) {
            Some(start) => {
                let tail = self.held.split_off(start);
                std::mem::replace(&mut self.held, tail)
            }
            None => std::mem::take(&mut self.held),
        };
        replace(&ready, self.escape, resolve)
    }

    /// The block ended: whatever is held is text, not a token.
    pub fn finish(&mut self) -> String {
        std::mem::take(&mut self.held)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known(token: &str) -> Option<String> {
        match token {
            "[EMAIL_1]" => Some("jean.dupont@example.com".into()),
            "[PERSON_NAME_2]" => Some("Jean \"JD\" Dupont".into()),
            _ => None,
        }
    }

    #[test]
    fn finds_tokens_as_the_engine_regex_does() {
        let text = "a [EMAIL_1] b [PERSON_NAME_2] [IBAN_12] [email_1] [EMAIL] [EMAIL_] [A1_2] [_X_1] [EMAIL_1x]";
        let found: Vec<&str> = find(text).into_iter().map(|r| &text[r]).collect();
        assert_eq!(found, ["[EMAIL_1]", "[PERSON_NAME_2]", "[IBAN_12]", "[A1_2]"]);
    }

    #[test]
    fn replaces_known_tokens_and_keeps_unknown_ones() {
        let out = replace("to [EMAIL_1], not [EMAIL_9]", Escape::None, &mut known);
        assert_eq!(out, "to jean.dupont@example.com, not [EMAIL_9]");
    }

    #[test]
    fn escapes_values_inside_json_strings() {
        let out = replace(r#"{"name": "[PERSON_NAME_2]"}"#, Escape::JsonString, &mut known);
        assert_eq!(out, r#"{"name": "Jean \"JD\" Dupont"}"#);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["name"], "Jean \"JD\" Dupont");
    }

    #[test]
    fn a_token_split_across_chunks_is_held_until_complete() {
        let mut d = StreamDetokenizer::new(Escape::None);
        let mut out = String::new();
        for chunk in ["OK ", "[EMA", "IL", "_", "1", "] done [", "x"] {
            out.push_str(&d.push(chunk, &mut known));
        }
        assert_eq!(out, "OK jean.dupont@example.com done [x");
        assert_eq!(d.finish(), "");
    }

    #[test]
    fn every_split_point_gives_the_same_text() {
        let text = "Mail [EMAIL_1] or [PERSON_NAME_2], see [link](x) and [EMAIL_9].";
        let expected = replace(text, Escape::None, &mut known);
        for a in 0..=text.len() {
            for b in a..=text.len() {
                let mut d = StreamDetokenizer::new(Escape::None);
                let mut out = d.push(&text[..a], &mut known);
                out.push_str(&d.push(&text[a..b], &mut known));
                out.push_str(&d.push(&text[b..], &mut known));
                out.push_str(&d.finish());
                assert_eq!(out, expected, "split at {a}, {b}");
            }
        }
    }

    #[test]
    fn a_block_ending_on_an_open_prefix_flushes_it_as_text() {
        let mut d = StreamDetokenizer::new(Escape::None);
        assert_eq!(d.push("array[IDX_", &mut known), "array");
        assert_eq!(d.finish(), "[IDX_");
    }

    #[test]
    fn an_overlong_prefix_is_not_held() {
        let mut d = StreamDetokenizer::new(Escape::None);
        let long = format!("[{}", "A".repeat(MAX_TOKEN_LEN));
        assert_eq!(d.push(&long, &mut known), long);
    }
}
