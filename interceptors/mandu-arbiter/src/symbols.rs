//! symbols — a dependency-free `$MDU:*` token scanner.
//!
//! PURE. Mirrors the regex in `arbiter/symbol-table/symbol-format.ts` /
//! `fs-sync/src/arbiter-client.ts` `SYMBOL_PATTERN`:
//!
//!   \$MDU:[a-zA-Z_][a-zA-Z0-9_]*\[[0-9a-f]{4,8}\](?:\.[field path])*
//!
//! i.e. the prefix `$MDU:`, a tool identifier, a `[hex]` hash of 4–8 hex
//! digits, then zero-or-more `.field` segments. We hand-roll the scan (rather
//! than pull the `regex` crate) so the build is dependency-light and works
//! offline; the interceptors only need the COARSE shape (find/extract tokens),
//! and the arbiter remains the authority on resolution.

pub const SYMBOL_PREFIX: &str = "$MDU:";

/// True if `text` contains at least one symbol token. Fast prefix pre-check.
pub fn has_symbols(text: &str) -> bool {
    text.contains(SYMBOL_PREFIX) && !extract_symbols(text).is_empty()
}

/// Return every distinct symbol token in `text`, in first-seen order.
pub fn extract_symbols(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (start, end) in symbol_spans(text) {
        let tok = &text[start..end];
        if seen.insert(tok.to_string()) {
            out.push(tok.to_string());
        }
    }
    out
}

/// Return the byte-span `(start, end)` of every symbol token in `text`.
pub fn symbol_spans(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0;
    while let Some(rel) = text[i..].find(SYMBOL_PREFIX) {
        let start = i + rel;
        match scan_one(bytes, start) {
            Some(end) => {
                spans.push((start, end));
                i = end;
            }
            None => {
                // Not a valid token here; advance past the prefix to keep scanning.
                i = start + SYMBOL_PREFIX.len();
            }
        }
    }
    spans
}

/// Try to match one full symbol token starting at `start` (which is known to be
/// the SYMBOL_PREFIX). Returns the exclusive end index, or None if malformed.
fn scan_one(bytes: &[u8], start: usize) -> Option<usize> {
    let mut p = start + SYMBOL_PREFIX.len();
    let n = bytes.len();

    // tool: [a-zA-Z_][a-zA-Z0-9_]*
    if p >= n || !(bytes[p].is_ascii_alphabetic() || bytes[p] == b'_') {
        return None;
    }
    p += 1;
    while p < n && (bytes[p].is_ascii_alphanumeric() || bytes[p] == b'_') {
        p += 1;
    }

    // '[' [0-9a-f]{4,8} ']'
    if p >= n || bytes[p] != b'[' {
        return None;
    }
    p += 1;
    let hex_start = p;
    while p < n && is_lower_hex(bytes[p]) {
        p += 1;
    }
    let hex_len = p - hex_start;
    if !(4..=8).contains(&hex_len) {
        return None;
    }
    if p >= n || bytes[p] != b']' {
        return None;
    }
    p += 1;

    // (?:\.[a-zA-Z_][a-zA-Z0-9_[\].]*)*  — zero or more dotted field segments.
    loop {
        if p < n && bytes[p] == b'.' {
            // A field segment must start with a letter/underscore.
            if p + 1 < n && (bytes[p + 1].is_ascii_alphabetic() || bytes[p + 1] == b'_') {
                p += 2;
                while p < n
                    && (bytes[p].is_ascii_alphanumeric()
                        || matches!(bytes[p], b'_' | b'[' | b']' | b'.'))
                {
                    // Stop a trailing '.' from greedily consuming the next token's
                    // prefix: a '.' is only part of a field if followed by another
                    // field char (handled by the outer loop re-entry).
                    if bytes[p] == b'.' {
                        break;
                    }
                    p += 1;
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }

    Some(p)
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_bare_symbol() {
        let t = "see $MDU:web_fetch[a1b2] now";
        assert!(has_symbols(t));
        assert_eq!(extract_symbols(t), vec!["$MDU:web_fetch[a1b2]"]);
    }

    #[test]
    fn detects_fielded_symbol() {
        let t = "x=$MDU:Read[abcd1234].content.title;";
        assert_eq!(
            extract_symbols(t),
            vec!["$MDU:Read[abcd1234].content.title"]
        );
    }

    #[test]
    fn rejects_malformed() {
        // hash too short
        assert!(!has_symbols("$MDU:x[ab]"));
        // no brackets
        assert!(!has_symbols("$MDU:x"));
        // uppercase hex not allowed (matches JS [0-9a-f])
        assert!(!has_symbols("$MDU:x[ABCD]"));
    }

    #[test]
    fn extracts_multiple_distinct_in_order() {
        let t = "$MDU:a[0000] and $MDU:b[1111] and $MDU:a[0000]";
        assert_eq!(
            extract_symbols(t),
            vec!["$MDU:a[0000]", "$MDU:b[1111]"]
        );
    }

    #[test]
    fn adjacent_tokens_separate() {
        let t = "$MDU:a[0000].f $MDU:b[1111]";
        let spans = symbol_spans(t);
        assert_eq!(spans.len(), 2);
        assert_eq!(&t[spans[0].0..spans[0].1], "$MDU:a[0000].f");
        assert_eq!(&t[spans[1].0..spans[1].1], "$MDU:b[1111]");
    }

    #[test]
    fn no_false_positive_on_plain_text() {
        assert!(!has_symbols("just normal text, $5 dollars"));
        assert_eq!(extract_symbols("nothing here"), Vec::<String>::new());
    }
}
