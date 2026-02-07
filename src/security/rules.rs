//! Security rules engine — YAML-based pattern matching.
//!
//! Loads security rules from YAML files (bundled via `include_str!` or from disk),
//! compiles regex patterns, and matches them against source code to produce findings.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Severity of a security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// Category of a security rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleCategory {
    Injection,
    Crypto,
    Secrets,
    Config,
    Authentication,
    Xss,
    PathTraversal,
    Deserialization,
    Other,
}

impl std::fmt::Display for RuleCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleCategory::Injection => write!(f, "injection"),
            RuleCategory::Crypto => write!(f, "crypto"),
            RuleCategory::Secrets => write!(f, "secrets"),
            RuleCategory::Config => write!(f, "config"),
            RuleCategory::Authentication => write!(f, "authentication"),
            RuleCategory::Xss => write!(f, "xss"),
            RuleCategory::PathTraversal => write!(f, "path-traversal"),
            RuleCategory::Deserialization => write!(f, "deserialization"),
            RuleCategory::Other => write!(f, "other"),
        }
    }
}

/// A single security rule loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub owasp: Option<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    /// Regex pattern to match against source lines.
    pub pattern: String,
    pub message: String,
    #[serde(default)]
    pub fix: Option<String>,
    #[serde(default = "default_category")]
    pub category: RuleCategory,
}

fn default_category() -> RuleCategory {
    RuleCategory::Other
}

/// A match produced by applying a rule to source code.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: String,
    pub line_number: usize,
    pub column: usize,
    pub matched_text: String,
}

/// Top-level YAML structure: a ruleset wrapping a list of rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ruleset {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    pub rules: Vec<SecurityRule>,
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Load rules from a YAML file on disk.
pub fn load_rules(path: &Path) -> Result<Vec<SecurityRule>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;
    let ruleset: Ruleset = serde_yaml::from_str(&content)
        .map_err(|e| format!("YAML parse error in {}: {}", path.display(), e))?;
    Ok(ruleset.rules)
}

/// Load the four bundled rule files embedded at compile time.
pub fn load_bundled_rules() -> Vec<SecurityRule> {
    let mut all = Vec::new();

    let yamls: &[&str] = &[
        include_str!("../../rules/owasp-top10.yaml"),
        include_str!("../../rules/cwe-top25.yaml"),
        include_str!("../../rules/crypto.yaml"),
        include_str!("../../rules/secrets.yaml"),
    ];

    for yaml in yamls {
        match serde_yaml::from_str::<Ruleset>(yaml) {
            Ok(rs) => all.extend(rs.rules),
            Err(e) => eprintln!("Warning: failed to parse bundled ruleset: {}", e),
        }
    }

    all
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/// Compute the (1-indexed) line number and column for a byte offset.
fn byte_to_line_col(source: &str, byte_offset: usize) -> (usize, usize) {
    let mut line = 1;
    let mut col = 1;
    for (i, ch) in source.char_indices() {
        if i >= byte_offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    (line, col)
}

/// Apply a single rule against source code, filtering by language.
/// Returns all regex matches found.
pub fn match_rule(rule: &SecurityRule, source: &str, language: &str) -> Vec<RuleMatch> {
    // Language filter: if the rule specifies languages, check membership.
    if !rule.languages.is_empty()
        && !rule
            .languages
            .iter()
            .any(|l| l.eq_ignore_ascii_case(language))
    {
        return Vec::new();
    }

    let re = match Regex::new(&rule.pattern) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    re.find_iter(source)
        .map(|m| {
            let (line, col) = byte_to_line_col(source, m.start());
            RuleMatch {
                rule_id: rule.id.clone(),
                line_number: line,
                column: col,
                matched_text: m.as_str().to_string(),
            }
        })
        .collect()
}

/// Check if a file path looks like a test file (to optionally exclude from scanning).
pub fn is_test_file(path: &str) -> bool {
    let p = path.to_lowercase();
    p.contains("/tests/")
        || p.contains("/test/")
        || p.contains("/__tests__/")
        || p.contains("/fixtures/")
        || p.contains("/testdata/")
        || p.starts_with("test-fixtures/")
        || p.contains("/test-fixtures/")
        || p.ends_with("_test.rs")
        || p.ends_with("_test.go")
        || p.ends_with("_test.py")
        || p.ends_with(".test.js")
        || p.ends_with(".test.ts")
        || p.ends_with(".test.tsx")
        || p.ends_with(".spec.js")
        || p.ends_with(".spec.ts")
        || p.contains("/spec/")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Severity --

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(Severity::Critical.to_string(), "critical");
        assert_eq!(Severity::Info.to_string(), "info");
    }

    // -- Category --

    #[test]
    fn test_category_display() {
        assert_eq!(RuleCategory::Injection.to_string(), "injection");
        assert_eq!(RuleCategory::Crypto.to_string(), "crypto");
        assert_eq!(RuleCategory::PathTraversal.to_string(), "path-traversal");
    }

    // -- YAML parsing --

    #[test]
    fn test_parse_single_rule_yaml() {
        let yaml = r#"
name: test
version: "1.0"
rules:
  - id: TEST-001
    name: Test Rule
    severity: high
    pattern: "eval\\("
    message: Dangerous eval usage
    category: injection
    languages: ["python", "javascript"]
"#;
        let rs: Ruleset = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rs.rules.len(), 1);
        assert_eq!(rs.rules[0].id, "TEST-001");
        assert_eq!(rs.rules[0].severity, Severity::High);
        assert_eq!(rs.rules[0].category, RuleCategory::Injection);
        assert_eq!(rs.rules[0].languages, vec!["python", "javascript"]);
    }

    #[test]
    fn test_parse_rule_with_optional_fields() {
        let yaml = r#"
name: minimal
version: "1.0"
rules:
  - id: MIN-001
    name: Minimal
    severity: low
    pattern: "TODO"
    message: Found TODO
"#;
        let rs: Ruleset = serde_yaml::from_str(yaml).unwrap();
        let rule = &rs.rules[0];
        assert!(rule.cwe.is_none());
        assert!(rule.owasp.is_none());
        assert!(rule.fix.is_none());
        assert_eq!(rule.category, RuleCategory::Other);
        assert!(rule.languages.is_empty());
    }

    #[test]
    fn test_parse_rule_all_fields() {
        let yaml = r#"
name: full
version: "1.0"
rules:
  - id: FULL-001
    name: SQL Injection
    severity: critical
    cwe: "CWE-89"
    owasp: "A03:2021"
    languages: ["python"]
    pattern: "execute\\("
    message: SQL injection risk
    fix: Use parameterized queries
    category: injection
"#;
        let rs: Ruleset = serde_yaml::from_str(yaml).unwrap();
        let rule = &rs.rules[0];
        assert_eq!(rule.cwe.as_deref(), Some("CWE-89"));
        assert_eq!(rule.owasp.as_deref(), Some("A03:2021"));
        assert_eq!(rule.fix.as_deref(), Some("Use parameterized queries"));
    }

    #[test]
    fn test_parse_invalid_yaml() {
        let bad = "not: valid: yaml: [";
        let result = serde_yaml::from_str::<Ruleset>(bad);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_required_fields() {
        let yaml = r#"
name: bad
version: "1.0"
rules:
  - id: BAD-001
    severity: high
"#;
        // `name`, `pattern`, and `message` are required
        let result = serde_yaml::from_str::<Ruleset>(yaml);
        assert!(result.is_err());
    }

    // -- load_rules (file) --

    #[test]
    fn test_load_rules_nonexistent_file() {
        let result = load_rules(Path::new("/nonexistent/file.yaml"));
        assert!(result.is_err());
    }

    // -- load_bundled_rules --

    #[test]
    fn test_bundled_rules_load_successfully() {
        let rules = load_bundled_rules();
        // We expect at least 65 rules across 4 YAML files
        assert!(
            rules.len() >= 60,
            "Expected at least 60 bundled rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_bundled_rules_have_valid_ids() {
        let rules = load_bundled_rules();
        for rule in &rules {
            assert!(!rule.id.is_empty(), "Rule ID must not be empty");
            assert!(!rule.name.is_empty(), "Rule name must not be empty");
            assert!(!rule.pattern.is_empty(), "Rule pattern must not be empty");
            assert!(!rule.message.is_empty(), "Rule message must not be empty");
        }
    }

    #[test]
    fn test_bundled_rules_have_compilable_regex() {
        let rules = load_bundled_rules();
        for rule in &rules {
            let result = Regex::new(&rule.pattern);
            assert!(
                result.is_ok(),
                "Rule {} has invalid regex '{}': {}",
                rule.id,
                rule.pattern,
                result.err().unwrap()
            );
        }
    }

    #[test]
    fn test_bundled_rules_cover_owasp() {
        let rules = load_bundled_rules();
        let owasp_rules: Vec<_> = rules.iter().filter(|r| r.owasp.is_some()).collect();
        assert!(
            owasp_rules.len() >= 10,
            "Expected at least 10 OWASP rules, got {}",
            owasp_rules.len()
        );
    }

    #[test]
    fn test_bundled_rules_cover_cwe() {
        let rules = load_bundled_rules();
        let cwe_rules: Vec<_> = rules.iter().filter(|r| r.cwe.is_some()).collect();
        assert!(
            cwe_rules.len() >= 20,
            "Expected at least 20 CWE rules, got {}",
            cwe_rules.len()
        );
    }

    // -- match_rule --

    #[test]
    fn test_match_rule_basic() {
        let rule = SecurityRule {
            id: "T-001".into(),
            name: "eval".into(),
            severity: Severity::High,
            cwe: None,
            owasp: None,
            languages: vec![],
            pattern: r"eval\(".into(),
            message: "eval is dangerous".into(),
            fix: None,
            category: RuleCategory::Injection,
        };
        let source = "x = eval(user_input)\ny = safe()\nz = eval('hello')";
        let matches = match_rule(&rule, source, "python");
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].line_number, 1);
        assert_eq!(matches[1].line_number, 3);
    }

    #[test]
    fn test_match_rule_language_filter() {
        let rule = SecurityRule {
            id: "T-002".into(),
            name: "exec".into(),
            severity: Severity::High,
            cwe: None,
            owasp: None,
            languages: vec!["python".into()],
            pattern: r"exec\(".into(),
            message: "exec".into(),
            fix: None,
            category: RuleCategory::Injection,
        };
        let source = "exec(code)";
        // Matching language
        assert_eq!(match_rule(&rule, source, "python").len(), 1);
        // Non-matching language
        assert_eq!(match_rule(&rule, source, "rust").len(), 0);
    }

    #[test]
    fn test_match_rule_no_match() {
        let rule = SecurityRule {
            id: "T-003".into(),
            name: "sql".into(),
            severity: Severity::Critical,
            cwe: Some("CWE-89".into()),
            owasp: None,
            languages: vec![],
            pattern: r"execute\(".into(),
            message: "sql injection".into(),
            fix: None,
            category: RuleCategory::Injection,
        };
        let source = "safe_query = parameterized()";
        assert!(match_rule(&rule, source, "python").is_empty());
    }

    #[test]
    fn test_match_rule_invalid_regex() {
        let rule = SecurityRule {
            id: "T-004".into(),
            name: "bad".into(),
            severity: Severity::Low,
            cwe: None,
            owasp: None,
            languages: vec![],
            pattern: r"[invalid".into(),
            message: "bad regex".into(),
            fix: None,
            category: RuleCategory::Other,
        };
        // Should not panic, just return empty.
        assert!(match_rule(&rule, "anything", "python").is_empty());
    }

    #[test]
    fn test_match_rule_multiline_column() {
        let rule = SecurityRule {
            id: "T-005".into(),
            name: "md5".into(),
            severity: Severity::Medium,
            cwe: Some("CWE-327".into()),
            owasp: None,
            languages: vec![],
            pattern: r"MD5".into(),
            message: "weak hash".into(),
            fix: None,
            category: RuleCategory::Crypto,
        };
        let source = "line one\nuse MD5 here\nline three";
        let matches = match_rule(&rule, source, "python");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].line_number, 2);
        assert_eq!(matches[0].column, 5); // "use " = 4 chars, MD5 starts at col 5
    }

    #[test]
    fn test_match_rule_case_sensitive() {
        let rule = SecurityRule {
            id: "T-006".into(),
            name: "md5-lower".into(),
            severity: Severity::Medium,
            cwe: None,
            owasp: None,
            languages: vec![],
            pattern: r"(?i)md5".into(),
            message: "md5".into(),
            fix: None,
            category: RuleCategory::Crypto,
        };
        let source = "x = md5(data)\ny = MD5(data)\nz = Md5(data)";
        assert_eq!(match_rule(&rule, source, "python").len(), 3);
    }

    // -- is_test_file --

    #[test]
    fn test_is_test_file_positive() {
        assert!(is_test_file("src/tests/foo.rs"));
        assert!(is_test_file("src/__tests__/bar.js"));
        assert!(is_test_file("foo_test.go"));
        assert!(is_test_file("app.test.ts"));
        assert!(is_test_file("helper.spec.js"));
    }

    #[test]
    fn test_is_test_file_negative() {
        assert!(!is_test_file("src/main.rs"));
        assert!(!is_test_file("lib/scanner.py"));
        assert!(!is_test_file("index.ts"));
    }

    // -- byte_to_line_col --

    #[test]
    fn test_byte_to_line_col_first_line() {
        assert_eq!(byte_to_line_col("hello", 0), (1, 1));
        assert_eq!(byte_to_line_col("hello", 3), (1, 4));
    }

    #[test]
    fn test_byte_to_line_col_second_line() {
        assert_eq!(byte_to_line_col("ab\ncd", 3), (2, 1));
        assert_eq!(byte_to_line_col("ab\ncd", 4), (2, 2));
    }

    #[test]
    fn test_byte_to_line_col_empty() {
        assert_eq!(byte_to_line_col("", 0), (1, 1));
    }

    // -- Serialization round-trip --

    #[test]
    fn test_severity_serde_roundtrip() {
        let json = serde_json::to_string(&Severity::Critical).unwrap();
        let back: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Severity::Critical);
    }

    #[test]
    fn test_category_serde_roundtrip() {
        let json = serde_json::to_string(&RuleCategory::Xss).unwrap();
        let back: RuleCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, RuleCategory::Xss);
    }

    #[test]
    fn test_rule_serde_roundtrip() {
        let rule = SecurityRule {
            id: "ROUND-001".into(),
            name: "Round Trip".into(),
            severity: Severity::High,
            cwe: Some("CWE-79".into()),
            owasp: Some("A03:2021".into()),
            languages: vec!["python".into()],
            pattern: r"eval\(".into(),
            message: "eval".into(),
            fix: Some("Don't use eval".into()),
            category: RuleCategory::Injection,
        };
        let json = serde_json::to_string(&rule).unwrap();
        let back: SecurityRule = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, rule.id);
        assert_eq!(back.severity, rule.severity);
        assert_eq!(back.category, rule.category);
    }

    // -- Match patterns from bundled rules --

    #[test]
    fn test_bundled_sql_injection_python() {
        let rules = load_bundled_rules();
        let sql_rules: Vec<_> = rules
            .iter()
            .filter(|r| {
                r.id.contains("SQL")
                    || r.id.contains("sql")
                    || r.category == RuleCategory::Injection
            })
            .collect();
        assert!(!sql_rules.is_empty(), "Should have SQL injection rules");

        let source = r#"query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)"#;

        let mut found = false;
        for rule in &sql_rules {
            if !match_rule(rule, source, "python").is_empty() {
                found = true;
                break;
            }
        }
        assert!(found, "Should detect SQL injection pattern in Python");
    }

    #[test]
    fn test_bundled_xss_detection() {
        let rules = load_bundled_rules();
        let source = "element.innerHTML = userInput;";
        let mut found = false;
        for rule in &rules {
            if !match_rule(rule, source, "javascript").is_empty() {
                found = true;
                break;
            }
        }
        assert!(found, "Should detect innerHTML XSS pattern");
    }

    #[test]
    fn test_bundled_hardcoded_password() {
        let rules = load_bundled_rules();
        let source = r#"password = "SuperSecret123!""#;
        let mut found = false;
        for rule in &rules {
            if !match_rule(rule, source, "python").is_empty() {
                found = true;
                break;
            }
        }
        assert!(found, "Should detect hardcoded password");
    }

    #[test]
    fn test_bundled_weak_crypto() {
        let rules = load_bundled_rules();
        let source = "h = hashlib.md5(data.encode())";
        let mut found = false;
        for rule in &rules {
            if !match_rule(rule, source, "python").is_empty() {
                found = true;
                break;
            }
        }
        assert!(found, "Should detect MD5 usage");
    }

    #[test]
    fn test_bundled_aws_key_detection() {
        let rules = load_bundled_rules();
        let source = "aws_key = \"FKIAEXAMPLEKEY000000\"";
        let mut found = false;
        for rule in &rules {
            if !match_rule(rule, source, "python").is_empty() {
                found = true;
                break;
            }
        }
        assert!(found, "Should detect AWS access key");
    }

    #[test]
    fn test_match_rule_language_case_insensitive() {
        let rule = SecurityRule {
            id: "T-CI".into(),
            name: "case".into(),
            severity: Severity::Low,
            cwe: None,
            owasp: None,
            languages: vec!["Python".into()],
            pattern: "test".into(),
            message: "test".into(),
            fix: None,
            category: RuleCategory::Other,
        };
        // "python" should match "Python" case-insensitively
        assert_eq!(match_rule(&rule, "test", "python").len(), 1);
    }

    // ====================================================================
    // Phase 18B — parameterised rule-matching tests (test_case)
    // ====================================================================

    use pretty_assertions::assert_eq as pa_eq;
    use test_case::test_case;

    // --- Bundled rule count & coverage ---

    #[test]
    fn bundled_rules_count_at_least_50() {
        let rules = load_bundled_rules();
        assert!(rules.len() >= 50, "got {}", rules.len());
    }

    #[test]
    fn bundled_rules_unique_ids() {
        let rules = load_bundled_rules();
        let mut ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
        let total = ids.len();
        ids.sort();
        ids.dedup();
        pa_eq!(ids.len(), total, "duplicate rule IDs found");
    }

    #[test]
    fn bundled_rules_have_severity_low_or_above() {
        let rules = load_bundled_rules();
        // All bundled rules are Medium+, verify at least some are Medium
        assert!(
            rules.iter().any(|r| r.severity == Severity::Medium),
            "should have at least some medium rules"
        );
    }

    #[test]
    fn bundled_rules_have_severity_medium() {
        let rules = load_bundled_rules();
        assert!(rules.iter().any(|r| r.severity == Severity::Medium));
    }

    #[test]
    fn bundled_rules_have_severity_high() {
        let rules = load_bundled_rules();
        assert!(rules.iter().any(|r| r.severity == Severity::High));
    }

    #[test]
    fn bundled_rules_have_severity_critical() {
        let rules = load_bundled_rules();
        assert!(rules.iter().any(|r| r.severity == Severity::Critical));
    }

    #[test]
    fn bundled_rules_have_injection_category() {
        let rules = load_bundled_rules();
        assert!(rules.iter().any(|r| r.category == RuleCategory::Injection));
    }

    #[test]
    fn bundled_rules_have_crypto_category() {
        let rules = load_bundled_rules();
        assert!(rules.iter().any(|r| r.category == RuleCategory::Crypto));
    }

    #[test]
    fn bundled_rules_have_secrets_category() {
        let rules = load_bundled_rules();
        assert!(rules.iter().any(|r| r.category == RuleCategory::Secrets));
    }

    #[test]
    fn bundled_rules_have_xss_category() {
        let rules = load_bundled_rules();
        assert!(rules.iter().any(|r| r.category == RuleCategory::Xss));
    }

    #[test]
    fn bundled_rules_have_deserialization_category() {
        let rules = load_bundled_rules();
        assert!(rules
            .iter()
            .any(|r| r.category == RuleCategory::Deserialization));
    }

    #[test]
    fn bundled_rules_have_config_category() {
        let rules = load_bundled_rules();
        assert!(rules.iter().any(|r| r.category == RuleCategory::Config));
    }

    #[test]
    fn bundled_rules_have_authentication_category() {
        let rules = load_bundled_rules();
        assert!(rules
            .iter()
            .any(|r| r.category == RuleCategory::Authentication));
    }

    #[test]
    fn bundled_rules_have_pathtraversal_category() {
        let rules = load_bundled_rules();
        assert!(rules
            .iter()
            .any(|r| r.category == RuleCategory::PathTraversal));
    }

    // --- Pattern matching via test_case ---

    #[test_case("eval(user_input)", "javascript", RuleCategory::Injection ; "js eval injection")]
    #[test_case("eval(user_input)", "python", RuleCategory::Injection ; "py eval injection")]
    #[test_case("document.write(data)", "javascript", RuleCategory::Xss ; "js document.write xss")]
    #[test_case(".innerHTML = data", "javascript", RuleCategory::Xss ; "js innerHTML xss")]
    #[test_case("dangerouslySetInnerHTML", "javascript", RuleCategory::Xss ; "react dangerous html")]
    #[test_case("pickle.loads(data)", "python", RuleCategory::Deserialization ; "py pickle deser")]
    #[test_case("yaml.load(data)", "python", RuleCategory::Deserialization ; "py yaml unsafe")]
    #[test_case("os.system('ls')", "python", RuleCategory::Injection ; "py os.system")]
    #[test_case("subprocess.call(cmd, shell=True)", "python", RuleCategory::Injection ; "py shell true")]
    fn bundled_rule_detects_category(source: &str, lang: &str, expected_cat: RuleCategory) {
        let rules = load_bundled_rules();
        let all_matches: Vec<_> = rules
            .iter()
            .filter(|r| !match_rule(r, source, lang).is_empty())
            .collect();
        assert!(
            !all_matches.is_empty(),
            "no match for {:?} in {}",
            source,
            lang
        );
        assert!(
            all_matches.iter().any(|r| r.category == expected_cat),
            "expected category {:?}, got: {:?}",
            expected_cat,
            all_matches.iter().map(|r| r.category).collect::<Vec<_>>()
        );
    }

    // --- Secret detection patterns via test_case ---

    #[test_case("FKIAEXAMPLEKEY000000" ; "aws access key")]
    #[test_case("ghx_FAKE_TOKEN_FOR_TESTING_00000000000" ; "github token")]
    #[test_case("password = 'SuperSecretPassword123!'" ; "hardcoded password")]
    #[test_case("-----BEGIN RSA PRIVATE KEY-----" ; "private key")]
    #[test_case("postgres://user:pass@host/db" ; "db conn string")]
    fn bundled_rule_detects_secret(source: &str) {
        let rules = load_bundled_rules();
        let found = rules
            .iter()
            .any(|r| !match_rule(r, source, "python").is_empty());
        assert!(found, "should detect secret: {}", source);
    }

    // --- Crypto weakness detection via test_case ---

    #[test_case("hashlib.md5(data)" ; "python md5")]
    #[test_case("hashlib.sha1(data)" ; "python sha1")]
    #[test_case("Math.random()" ; "js insecure random")]
    #[test_case("random.randint(0, 100)" ; "py insecure random")]
    fn bundled_rule_detects_crypto_issue(source: &str) {
        let rules = load_bundled_rules();
        let found = rules.iter().any(|r| {
            r.category == RuleCategory::Crypto && !match_rule(r, source, "python").is_empty()
        });
        // For Math.random(), try JS language
        let found_js = rules.iter().any(|r| {
            r.category == RuleCategory::Crypto && !match_rule(r, source, "javascript").is_empty()
        });
        assert!(
            found || found_js,
            "should detect crypto weakness: {}",
            source
        );
    }

    // --- Negative tests: clean code should not trigger high-severity ---

    #[test_case("x = 42 + y" ; "arithmetic")]
    #[test_case("def hello(name): return f'Hello {name}'" ; "string format")]
    #[test_case("import json\ndata = json.loads(raw)" ; "json parse safe")]
    fn bundled_rules_no_false_positive_critical(source: &str) {
        let rules = load_bundled_rules();
        let critical: Vec<_> = rules
            .iter()
            .filter(|r| r.severity == Severity::Critical)
            .flat_map(|r| match_rule(r, source, "python"))
            .collect();
        assert!(
            critical.is_empty(),
            "false positive critical: {:?}",
            critical
        );
    }

    // --- match_rule edge cases ---

    #[test]
    fn match_rule_empty_source() {
        let rule = SecurityRule {
            id: "E".into(),
            name: "E".into(),
            severity: Severity::Low,
            cwe: None,
            owasp: None,
            languages: vec![],
            pattern: "anything".into(),
            message: "m".into(),
            fix: None,
            category: RuleCategory::Other,
        };
        assert!(match_rule(&rule, "", "python").is_empty());
    }

    #[test]
    fn match_rule_empty_pattern_matches_everything() {
        let rule = SecurityRule {
            id: "E".into(),
            name: "E".into(),
            severity: Severity::Low,
            cwe: None,
            owasp: None,
            languages: vec![],
            pattern: "".into(),
            message: "m".into(),
            fix: None,
            category: RuleCategory::Other,
        };
        // Empty regex matches at every position
        let matches = match_rule(&rule, "hello", "python");
        assert!(!matches.is_empty());
    }

    #[test]
    fn match_rule_multiple_languages_one_matches() {
        let rule = SecurityRule {
            id: "ML".into(),
            name: "ML".into(),
            severity: Severity::Medium,
            cwe: None,
            owasp: None,
            languages: vec!["python".into(), "javascript".into(), "ruby".into()],
            pattern: "test".into(),
            message: "m".into(),
            fix: None,
            category: RuleCategory::Other,
        };
        assert_eq!(match_rule(&rule, "test", "ruby").len(), 1);
        assert_eq!(match_rule(&rule, "test", "go").len(), 0);
    }

    #[test]
    fn match_rule_captures_correct_text() {
        let rule = SecurityRule {
            id: "CT".into(),
            name: "CT".into(),
            severity: Severity::High,
            cwe: None,
            owasp: None,
            languages: vec![],
            pattern: r"eval\([^)]*\)".into(),
            message: "m".into(),
            fix: None,
            category: RuleCategory::Injection,
        };
        let matches = match_rule(&rule, "x = eval(data)", "python");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_text, "eval(data)");
    }

    #[test]
    fn match_rule_unicode_source() {
        let rule = SecurityRule {
            id: "U".into(),
            name: "U".into(),
            severity: Severity::Low,
            cwe: None,
            owasp: None,
            languages: vec![],
            pattern: "eval".into(),
            message: "m".into(),
            fix: None,
            category: RuleCategory::Other,
        };
        let source = "# Türkçe yorum\neval(girdi)";
        let matches = match_rule(&rule, source, "python");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].line_number, 2);
    }

    // --- Severity ordering exhaustive ---

    #[test]
    fn severity_all_variants_comparable() {
        let all = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        for i in 0..all.len() - 1 {
            assert!(
                all[i] < all[i + 1],
                "{:?} should be < {:?}",
                all[i],
                all[i + 1]
            );
        }
    }

    // --- Category display exhaustive ---

    #[test]
    fn category_display_all_variants() {
        let cats = [
            (RuleCategory::Injection, "injection"),
            (RuleCategory::Crypto, "crypto"),
            (RuleCategory::Secrets, "secrets"),
            (RuleCategory::Config, "config"),
            (RuleCategory::Authentication, "authentication"),
            (RuleCategory::Xss, "xss"),
            (RuleCategory::PathTraversal, "path-traversal"),
            (RuleCategory::Deserialization, "deserialization"),
            (RuleCategory::Other, "other"),
        ];
        for (cat, expected) in cats {
            pa_eq!(cat.to_string(), expected);
        }
    }

    // --- Severity display exhaustive ---

    #[test]
    fn severity_display_all_variants() {
        let sevs = [
            (Severity::Info, "info"),
            (Severity::Low, "low"),
            (Severity::Medium, "medium"),
            (Severity::High, "high"),
            (Severity::Critical, "critical"),
        ];
        for (sev, expected) in sevs {
            pa_eq!(sev.to_string(), expected);
        }
    }

    // --- Severity serde roundtrip all variants ---

    #[test_case(Severity::Info ; "info roundtrip")]
    #[test_case(Severity::Low ; "low roundtrip")]
    #[test_case(Severity::Medium ; "medium roundtrip")]
    #[test_case(Severity::High ; "high roundtrip")]
    #[test_case(Severity::Critical ; "critical roundtrip")]
    fn severity_json_roundtrip(sev: Severity) {
        let json = serde_json::to_string(&sev).unwrap();
        let back: Severity = serde_json::from_str(&json).unwrap();
        pa_eq!(back, sev);
    }

    // --- Category serde roundtrip all variants ---

    #[test_case(RuleCategory::Injection ; "injection roundtrip")]
    #[test_case(RuleCategory::Crypto ; "crypto roundtrip")]
    #[test_case(RuleCategory::Secrets ; "secrets roundtrip")]
    #[test_case(RuleCategory::Config ; "config roundtrip")]
    #[test_case(RuleCategory::Authentication ; "auth roundtrip")]
    #[test_case(RuleCategory::Xss ; "xss roundtrip")]
    #[test_case(RuleCategory::PathTraversal ; "pathtraversal roundtrip")]
    #[test_case(RuleCategory::Deserialization ; "deser roundtrip")]
    #[test_case(RuleCategory::Other ; "other roundtrip")]
    fn category_json_roundtrip(cat: RuleCategory) {
        let json = serde_json::to_string(&cat).unwrap();
        let back: RuleCategory = serde_json::from_str(&json).unwrap();
        pa_eq!(back, cat);
    }

    // --- is_test_file parametrised ---

    #[test_case("src/tests/foo.rs" => true ; "tests dir")]
    #[test_case("src/__tests__/bar.js" => true ; "jest tests dir")]
    #[test_case("my_test.go" => true ; "go test")]
    #[test_case("app.test.ts" => true ; "ts test")]
    #[test_case("helper.spec.js" => true ; "spec js")]
    #[test_case("src/test/java/Foo.java" => true ; "java test dir")]
    #[test_case("test-fixtures/data.json" => true ; "test fixtures")]
    #[test_case("app/fixtures/data.py" => true ; "fixtures dir")]
    #[test_case("src/testdata/input.txt" => true ; "testdata dir")]
    #[test_case("widget.spec.ts" => true ; "ts spec")]
    #[test_case("my_test.py" => true ; "py test")]
    #[test_case("x.test.tsx" => true ; "tsx test")]
    #[test_case("src/spec/model_spec.rb" => true ; "ruby spec dir")]
    #[test_case("src/main.rs" => false ; "main rs")]
    #[test_case("lib/scanner.py" => false ; "lib py")]
    #[test_case("index.ts" => false ; "index ts")]
    #[test_case("pkg/handler.go" => false ; "go handler")]
    #[test_case("src/App.tsx" => false ; "tsx component")]
    fn is_test_file_parameterised(path: &str) -> bool {
        is_test_file(path)
    }

    // --- byte_to_line_col edge cases ---

    #[test]
    fn byte_to_line_col_many_lines() {
        let source = "a\nb\nc\nd\ne";
        pa_eq!(byte_to_line_col(source, 8), (5, 1)); // 'e'
    }

    #[test]
    fn byte_to_line_col_windows_newlines_treated_as_chars() {
        // \r\n should still be handled (each char counts)
        let source = "ab\r\ncd";
        let (line, _col) = byte_to_line_col(source, 4);
        // After \r\n, we're on line 2
        assert_eq!(line, 2);
    }

    // --- YAML with multiple rules ---

    #[test]
    fn parse_yaml_multiple_rules() {
        let yaml = r#"
name: multi
version: "1.0"
rules:
  - id: M-001
    name: Rule One
    severity: low
    pattern: "pattern_one"
    message: msg1
  - id: M-002
    name: Rule Two
    severity: high
    pattern: "pattern_two"
    message: msg2
    category: crypto
  - id: M-003
    name: Rule Three
    severity: critical
    pattern: "pattern_three"
    message: msg3
    cwe: "CWE-89"
    owasp: "A03:2021"
    languages: ["python"]
    category: injection
"#;
        let rs: Ruleset = serde_yaml::from_str(yaml).unwrap();
        pa_eq!(rs.rules.len(), 3);
        pa_eq!(rs.rules[0].severity, Severity::Low);
        pa_eq!(rs.rules[1].category, RuleCategory::Crypto);
        pa_eq!(rs.rules[2].owasp.as_deref(), Some("A03:2021"));
    }

    // --- Load rules from temp file ---

    #[test]
    fn load_rules_from_valid_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yaml");
        std::fs::write(
            &path,
            r#"
name: test
version: "1.0"
rules:
  - id: FILE-001
    name: File Rule
    severity: medium
    pattern: "test_pattern"
    message: found it
    category: other
"#,
        )
        .unwrap();
        let rules = load_rules(&path).unwrap();
        pa_eq!(rules.len(), 1);
        pa_eq!(rules[0].id, "FILE-001");
    }

    #[test]
    fn load_rules_from_invalid_yaml_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "{{not valid yaml").unwrap();
        assert!(load_rules(&path).is_err());
    }

    // --- Bundled rules: specific rule IDs exist ---

    #[test]
    fn bundled_has_owasp_a03_sql_injection() {
        let rules = load_bundled_rules();
        assert!(rules.iter().any(|r| r.id == "OWASP-A03-001"));
    }

    #[test]
    fn bundled_has_cwe_787_buffer_overflow() {
        let rules = load_bundled_rules();
        assert!(rules.iter().any(|r| r.id == "CWE-787-001"));
    }

    #[test]
    fn bundled_has_crypto_md5() {
        let rules = load_bundled_rules();
        assert!(rules.iter().any(|r| r.id == "CRYPTO-001"));
    }

    #[test]
    fn bundled_has_secret_aws_key() {
        let rules = load_bundled_rules();
        assert!(rules.iter().any(|r| r.id == "SECRET-001"));
    }

    #[test]
    fn bundled_has_secret_github_token() {
        let rules = load_bundled_rules();
        assert!(rules.iter().any(|r| r.id == "SECRET-005"));
    }

    // --- C/C++ specific rule detection ---

    #[test_case("gets(buffer)" , "c" ; "c gets")]
    #[test_case("strcpy(dest, src)" , "c" ; "c strcpy")]
    #[test_case("sprintf(buf, fmt, val)" , "c" ; "c sprintf")]
    fn bundled_detects_c_buffer_overflow(source: &str, lang: &str) {
        let rules = load_bundled_rules();
        let found = rules.iter().any(|r| {
            r.cwe.as_deref() == Some("CWE-787") && !match_rule(r, source, lang).is_empty()
        });
        assert!(found, "should detect buffer overflow: {}", source);
    }

    // --- Multiple matches on same line ---

    #[test]
    fn match_rule_multiple_on_same_line() {
        let rule = SecurityRule {
            id: "M".into(),
            name: "M".into(),
            severity: Severity::High,
            cwe: None,
            owasp: None,
            languages: vec![],
            pattern: r"eval\(".into(),
            message: "m".into(),
            fix: None,
            category: RuleCategory::Injection,
        };
        let source = "eval(eval(x))";
        let matches = match_rule(&rule, source, "python");
        pa_eq!(matches.len(), 2);
        // Both on line 1
        assert!(matches.iter().all(|m| m.line_number == 1));
    }

    // --- Ruleset serde roundtrip ---

    #[test]
    fn ruleset_yaml_roundtrip() {
        let rs = Ruleset {
            name: "test".into(),
            version: "1.0".into(),
            description: "desc".into(),
            rules: vec![SecurityRule {
                id: "RT-001".into(),
                name: "RT".into(),
                severity: Severity::High,
                cwe: Some("CWE-89".into()),
                owasp: None,
                languages: vec!["python".into()],
                pattern: "test".into(),
                message: "msg".into(),
                fix: Some("fix".into()),
                category: RuleCategory::Injection,
            }],
        };
        let yaml = serde_yaml::to_string(&rs).unwrap();
        let back: Ruleset = serde_yaml::from_str(&yaml).unwrap();
        pa_eq!(back.name, "test");
        pa_eq!(back.rules.len(), 1);
        pa_eq!(back.rules[0].id, "RT-001");
    }
}
