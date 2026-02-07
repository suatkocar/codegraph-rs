//! Token budget utilities for context assembly.
//!
//! Ports the TypeScript `context/budget.ts` to Rust. Provides lightweight
//! token estimation and text-shaping helpers that let the assembler pack
//! as much relevant code as possible into a fixed token budget without
//! exceeding it.

// ---------------------------------------------------------------------------
// Token estimation
// ---------------------------------------------------------------------------

/// Estimate the number of tokens in `text` using the ~4-chars-per-token
/// heuristic.
///
/// This is intentionally simple: a proper tokenizer (tiktoken, sentencepiece)
/// would be more accurate, but the 4-char rule is surprisingly close for
/// English-heavy source code and avoids pulling in a heavy dependency.
pub fn estimate_tokens(text: &str) -> usize {
    let len = text.len();
    // Integer ceiling division: (len + 3) / 4
    (len + 3) / 4
}

// ---------------------------------------------------------------------------
// Truncation
// ---------------------------------------------------------------------------

/// Truncate `text` to fit within `max_tokens`, preserving whole lines.
///
/// Walks the text line by line, accumulating tokens until adding the next
/// line would exceed the budget. Returns everything up to (and including)
/// the last line that fits. If even the first line exceeds the budget, it
/// is included anyway so the caller always gets *something*.
pub fn truncate_to_fit(text: &str, max_tokens: usize) -> String {
    if max_tokens == 0 {
        return String::new();
    }

    if estimate_tokens(text) <= max_tokens {
        return text.to_string();
    }

    let mut result = String::new();
    let mut current_tokens: usize = 0;

    for (i, line) in text.lines().enumerate() {
        // +1 for the newline character that `lines()` strips.
        let line_tokens = estimate_tokens(line) + 1;

        if current_tokens + line_tokens > max_tokens && i > 0 {
            break;
        }

        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str(line);
        current_tokens += line_tokens;
    }

    result
}

// ---------------------------------------------------------------------------
// Signature extraction
// ---------------------------------------------------------------------------

/// Extract the function/class signature from a full source body.
///
/// Strategies (tried in order):
///
/// 1. **Opening brace** -- find the first `{` and return everything before
///    it (trimmed), which captures `function foo(x: number): boolean` from
///    the full body.
/// 2. **Arrow function** -- find `=>` and return everything up to and
///    including the arrow.
/// 3. **First line fallback** -- return just the first line of the body.
///
/// Multi-line signatures (e.g. parameter lists that span lines) are
/// compacted into a single line with normalised whitespace.
pub fn signature_only(body: &str) -> String {
    let body = body.trim();
    if body.is_empty() {
        return String::new();
    }

    // Strategy 1: find the opening brace.
    if let Some(brace_pos) = body.find('{') {
        let before_brace = body[..brace_pos].trim();
        if !before_brace.is_empty() {
            return compact_multiline(before_brace);
        }
    }

    // Strategy 2: arrow function (`=>`).
    if let Some(arrow_pos) = body.find("=>") {
        let through_arrow = &body[..arrow_pos + 2];
        return compact_multiline(through_arrow.trim());
    }

    // Strategy 3: first line.
    let first_line = body.lines().next().unwrap_or(body);
    compact_multiline(first_line.trim())
}

/// Collapse multi-line text into a single line with normalised whitespace.
///
/// Replaces every run of whitespace (including newlines) with a single
/// space, producing a compact one-liner suitable for summary display.
fn compact_multiline(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- estimate_tokens ---------------------------------------------------

    #[test]
    fn estimate_tokens_empty() {
        assert_eq!(estimate_tokens(""), 0);
    }

    #[test]
    fn estimate_tokens_short() {
        // 4 chars -> 1 token
        assert_eq!(estimate_tokens("abcd"), 1);
    }

    #[test]
    fn estimate_tokens_rounds_up() {
        // 5 chars -> ceil(5/4) = 2
        assert_eq!(estimate_tokens("abcde"), 2);
    }

    #[test]
    fn estimate_tokens_longer_text() {
        let text = "function hello(name: string): void";
        // 34 chars -> ceil(34/4) = 9
        assert_eq!(estimate_tokens(text), 9);
    }

    // -- truncate_to_fit ---------------------------------------------------

    #[test]
    fn truncate_fits_entirely() {
        let text = "short text";
        assert_eq!(truncate_to_fit(text, 100), text);
    }

    #[test]
    fn truncate_zero_budget() {
        assert_eq!(truncate_to_fit("anything", 0), "");
    }

    #[test]
    fn truncate_preserves_whole_lines() {
        let text = "line one\nline two\nline three\nline four";
        let result = truncate_to_fit(text, 6);
        // Each line ~2-3 tokens + 1 for newline.
        // The result should contain some lines but not all.
        assert!(result.lines().count() < text.lines().count());
        // Every line in the result should be a complete line from the input.
        for line in result.lines() {
            assert!(text.contains(line));
        }
    }

    #[test]
    fn truncate_always_includes_first_line() {
        let text = "this is a very long first line that exceeds any reasonable token budget by far";
        let result = truncate_to_fit(text, 1);
        assert_eq!(result, text);
    }

    #[test]
    fn truncate_multiline_budget_exact() {
        // Two short lines, budget that fits both exactly-ish.
        let text = "ab\ncd";
        // "ab" = 1 token + 1 newline = 2; "cd" = 1 token + 1 newline = 2; total ~4
        let result = truncate_to_fit(text, 100);
        assert_eq!(result, text);
    }

    // -- signature_only ----------------------------------------------------

    #[test]
    fn signature_from_function_body() {
        let body = "function greet(name: string): void {\n  console.log(name);\n}";
        assert_eq!(signature_only(body), "function greet(name: string): void");
    }

    #[test]
    fn signature_from_class_body() {
        let body = "class Foo extends Bar {\n  method() {}\n}";
        assert_eq!(signature_only(body), "class Foo extends Bar");
    }

    #[test]
    fn signature_from_arrow_function() {
        let body = "const add = (a: number, b: number) => a + b;";
        assert_eq!(
            signature_only(body),
            "const add = (a: number, b: number) =>"
        );
    }

    #[test]
    fn signature_multiline_params() {
        let body = "function create(\n  name: string,\n  age: number\n): Person {\n  return {};\n}";
        let sig = signature_only(body);
        // Should be compacted to a single line.
        assert!(!sig.contains('\n'));
        assert!(sig.contains("name: string,"));
        assert!(sig.contains("age: number"));
        assert!(sig.contains("): Person"));
    }

    #[test]
    fn signature_empty_body() {
        assert_eq!(signature_only(""), "");
    }

    #[test]
    fn signature_first_line_fallback() {
        // No brace, no arrow -- just returns the first line.
        let body = "const x = 42;";
        assert_eq!(signature_only(body), "const x = 42;");
    }

    // -- compact_multiline -------------------------------------------------

    #[test]
    fn compact_multiline_collapses_whitespace() {
        assert_eq!(
            compact_multiline("  hello\n  world  "),
            "hello world"
        );
    }

    #[test]
    fn compact_multiline_single_line() {
        assert_eq!(compact_multiline("already compact"), "already compact");
    }
}
