//! Security scanner — OWASP Top 10, CWE Top 25, directory scanning, explanations.
//!
//! Builds on the rules engine to scan files and directories, aggregate findings
//! into summaries, and provide vulnerability explanations and fix suggestions.

use std::collections::HashMap;
use std::path::Path;

use super::rules::{self, load_bundled_rules, match_rule, RuleCategory, SecurityRule, Severity};
use crate::types::Language;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A single security finding produced by scanning source code.
#[derive(Debug, Clone)]
pub struct SecurityFinding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub file_path: String,
    pub line_number: usize,
    pub column: usize,
    pub matched_text: String,
    pub message: String,
    pub fix: Option<String>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub category: RuleCategory,
}

/// Aggregate statistics for a scan.
#[derive(Debug, Clone)]
pub struct SecuritySummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
    pub files_scanned: usize,
    pub rules_applied: usize,
    pub findings: Vec<SecurityFinding>,
    pub top_issues: Vec<(String, usize)>,
}

impl SecuritySummary {
    fn new() -> Self {
        SecuritySummary {
            total_findings: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            files_scanned: 0,
            rules_applied: 0,
            findings: Vec::new(),
            top_issues: Vec::new(),
        }
    }

    fn add_finding(&mut self, f: SecurityFinding) {
        match f.severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
        self.total_findings += 1;
        self.findings.push(f);
    }

    fn finalize(&mut self) {
        // Build top issues: count by rule_name.
        let mut counts: HashMap<String, usize> = HashMap::new();
        for f in &self.findings {
            *counts.entry(f.rule_name.clone()).or_insert(0) += 1;
        }
        let mut top: Vec<_> = counts.into_iter().collect();
        top.sort_by(|a, b| b.1.cmp(&a.1));
        top.truncate(10);
        self.top_issues = top;

        // Sort findings: Critical first.
        self.findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    }
}

/// Detailed explanation of a vulnerability, keyed by CWE ID.
#[derive(Debug, Clone)]
pub struct VulnerabilityExplanation {
    pub cwe_id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub impact: String,
    pub remediation: String,
    pub references: Vec<String>,
}

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// Scan a single source string with the given rules.
pub fn scan_file(
    path: &Path,
    source: &str,
    language: &str,
    rules: &[SecurityRule],
) -> Vec<SecurityFinding> {
    let path_str = path.display().to_string();
    let mut findings = Vec::new();

    for rule in rules {
        for m in match_rule(rule, source, language) {
            findings.push(SecurityFinding {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: rule.severity,
                file_path: path_str.clone(),
                line_number: m.line_number,
                column: m.column,
                matched_text: m.matched_text,
                message: rule.message.clone(),
                fix: rule.fix.clone(),
                cwe: rule.cwe.clone(),
                owasp: rule.owasp.clone(),
                category: rule.category,
            });
        }
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings
}

/// Recursively scan a directory, loading bundled rules.
pub fn scan_directory(
    dir: &Path,
    rules: &[SecurityRule],
    exclude_tests: bool,
) -> SecuritySummary {
    let mut summary = SecuritySummary::new();
    summary.rules_applied = rules.len();

    scan_dir_recursive(dir, rules, exclude_tests, &mut summary);
    summary.finalize();
    summary
}

fn scan_dir_recursive(
    dir: &Path,
    rules: &[SecurityRule],
    exclude_tests: bool,
    summary: &mut SecuritySummary,
) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();

        // Skip hidden dirs and common non-source dirs.
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('.')
                || name == "node_modules"
                || name == "target"
                || name == "vendor"
                || name == "__pycache__"
                || name == "build"
                || name == "dist"
            {
                continue;
            }
        }

        if path.is_dir() {
            scan_dir_recursive(&path, rules, exclude_tests, summary);
            continue;
        }

        let path_str = path.display().to_string();

        // Optionally skip test files.
        if exclude_tests && rules::is_test_file(&path_str) {
            continue;
        }

        // Determine language from extension.
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| format!(".{}", e))
            .unwrap_or_default();
        let language = match Language::from_extension(&ext) {
            Some(lang) => lang.as_str().to_string(),
            None => continue,
        };

        // Read and scan.
        let source = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let file_findings = scan_file(&path, &source, &language, rules);
        for f in file_findings {
            summary.add_finding(f);
        }
        summary.files_scanned += 1;
    }
}

/// Scan for OWASP Top 10 issues only.
pub fn check_owasp_top10(dir: &Path) -> SecuritySummary {
    let all_rules = load_bundled_rules();
    let owasp_rules: Vec<_> = all_rules.into_iter().filter(|r| r.owasp.is_some()).collect();
    scan_directory(dir, &owasp_rules, true)
}

/// Scan for CWE Top 25 issues only.
pub fn check_cwe_top25(dir: &Path) -> SecuritySummary {
    let all_rules = load_bundled_rules();
    let cwe_rules: Vec<_> = all_rules.into_iter().filter(|r| r.cwe.is_some()).collect();
    scan_directory(dir, &cwe_rules, true)
}

/// Return a detailed explanation for a CWE ID.
pub fn explain_vulnerability(cwe_id: &str) -> Option<VulnerabilityExplanation> {
    CWE_EXPLANATIONS.iter().find(|e| e.0 == cwe_id).map(|e| {
        VulnerabilityExplanation {
            cwe_id: e.0.to_string(),
            name: e.1.to_string(),
            description: e.2.to_string(),
            severity: e.3,
            impact: e.4.to_string(),
            remediation: e.5.to_string(),
            references: vec![format!("https://cwe.mitre.org/data/definitions/{}.html", &cwe_id[4..])],
        }
    })
}

/// Suggest a fix string for a finding.
pub fn suggest_fix(finding: &SecurityFinding) -> String {
    if let Some(ref fix) = finding.fix {
        return fix.clone();
    }

    match finding.category {
        RuleCategory::Injection => {
            "Use parameterized queries or prepared statements. Never concatenate user input into queries or commands.".to_string()
        }
        RuleCategory::Crypto => {
            "Replace with modern algorithms: AES-256-GCM for encryption, SHA-256/SHA-512 for hashing, Argon2/bcrypt for passwords.".to_string()
        }
        RuleCategory::Secrets => {
            "Move secrets to environment variables or a secrets manager. Never hard-code credentials in source.".to_string()
        }
        RuleCategory::Xss => {
            "Sanitize user input before rendering in HTML. Use context-aware output encoding or a library like DOMPurify.".to_string()
        }
        RuleCategory::PathTraversal => {
            "Validate and sanitize file paths. Use allowlists and canonicalize paths before use.".to_string()
        }
        RuleCategory::Deserialization => {
            "Use safe deserialization methods (e.g. yaml.safe_load, JSON). Validate data before deserializing.".to_string()
        }
        RuleCategory::Authentication => {
            "Ensure all sensitive endpoints require authentication. Use established auth middleware.".to_string()
        }
        RuleCategory::Config => {
            "Review configuration for production hardening. Disable debug mode, restrict CORS, enable TLS.".to_string()
        }
        RuleCategory::Other => finding.message.clone(),
    }
}

// ---------------------------------------------------------------------------
// CWE explanation database
// ---------------------------------------------------------------------------

/// (cwe_id, name, description, severity, impact, remediation)
const CWE_EXPLANATIONS: &[(&str, &str, &str, Severity, &str, &str)] = &[
    (
        "CWE-79",
        "Cross-site Scripting (XSS)",
        "The application includes untrusted data in web page output without proper validation or encoding, allowing attackers to execute scripts in victim browsers.",
        Severity::High,
        "Session hijacking, credential theft, defacement, malware distribution.",
        "Use context-aware output encoding. Apply Content Security Policy headers. Sanitize with DOMPurify.",
    ),
    (
        "CWE-89",
        "SQL Injection",
        "The application constructs SQL queries using unsanitized user input, allowing attackers to modify query logic.",
        Severity::Critical,
        "Full database compromise, data exfiltration, authentication bypass, data destruction.",
        "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
    ),
    (
        "CWE-78",
        "OS Command Injection",
        "The application passes unsanitized user input to a shell command, allowing arbitrary command execution.",
        Severity::Critical,
        "Full system compromise, data theft, lateral movement.",
        "Avoid shell commands. If necessary, use APIs that accept argument arrays, not shell strings. Validate input strictly.",
    ),
    (
        "CWE-22",
        "Path Traversal",
        "The application uses user input to construct file paths without proper validation, allowing access to files outside the intended directory.",
        Severity::High,
        "Unauthorized file access, source code disclosure, configuration exposure.",
        "Canonicalize paths, use allowlists, validate against a base directory.",
    ),
    (
        "CWE-327",
        "Use of Broken Cryptographic Algorithm",
        "The application uses weak or obsolete cryptographic algorithms (MD5, SHA1, DES, RC4) that do not provide adequate security.",
        Severity::High,
        "Confidentiality breach, authentication bypass, data tampering.",
        "Use AES-256-GCM for encryption, SHA-256+ for hashing, Argon2/bcrypt for passwords.",
    ),
    (
        "CWE-798",
        "Hard-coded Credentials",
        "The application contains hard-coded passwords, API keys, or cryptographic keys in source code.",
        Severity::Critical,
        "Unauthorized access, credential compromise, difficult rotation.",
        "Use environment variables, secrets managers (Vault, AWS Secrets Manager), or configuration files excluded from version control.",
    ),
    (
        "CWE-502",
        "Deserialization of Untrusted Data",
        "The application deserializes data from untrusted sources without validation, potentially allowing arbitrary code execution.",
        Severity::Critical,
        "Remote code execution, denial of service, data tampering.",
        "Use safe deserialization (JSON, yaml.safe_load). Validate schemas. Avoid native serialization for untrusted input.",
    ),
    (
        "CWE-20",
        "Improper Input Validation",
        "The application does not validate or incorrectly validates input, enabling various attack vectors.",
        Severity::Medium,
        "Injection attacks, buffer overflows, logic bypasses.",
        "Validate all input against expected formats, lengths, and ranges. Use allowlists over denylists.",
    ),
    (
        "CWE-352",
        "Cross-Site Request Forgery (CSRF)",
        "The application does not verify that requests originate from the application, allowing attackers to submit requests on behalf of users.",
        Severity::Medium,
        "Unauthorized state changes, data modification, privilege escalation.",
        "Use anti-CSRF tokens. Verify Origin/Referer headers. Use SameSite cookie attribute.",
    ),
    (
        "CWE-787",
        "Out-of-bounds Write",
        "The application writes data past the end or before the beginning of a buffer.",
        Severity::Critical,
        "Code execution, system crash, data corruption.",
        "Use bounds-checked APIs. Validate buffer sizes. Use memory-safe languages.",
    ),
    (
        "CWE-125",
        "Out-of-bounds Read",
        "The application reads data past the end of a buffer, potentially leaking sensitive information.",
        Severity::Medium,
        "Information disclosure, crashes.",
        "Validate array indices and buffer lengths before access.",
    ),
    (
        "CWE-416",
        "Use After Free",
        "The application references memory after it has been freed, leading to undefined behavior.",
        Severity::Critical,
        "Code execution, crashes.",
        "Use smart pointers or memory-safe languages. Nullify pointers after free.",
    ),
    (
        "CWE-94",
        "Code Injection",
        "The application constructs code from user input and executes it (eval, exec).",
        Severity::Critical,
        "Arbitrary code execution, full system compromise.",
        "Never eval user input. Use safe alternatives like JSON parsing, template engines with sandboxing.",
    ),
    (
        "CWE-330",
        "Insufficient Random Values",
        "The application uses non-cryptographic random number generators for security-sensitive operations.",
        Severity::High,
        "Predictable tokens, session hijacking, bypass of security controls.",
        "Use cryptographically secure PRNGs: secrets (Python), crypto.randomBytes (Node), getrandom (Rust).",
    ),
    (
        "CWE-611",
        "XML External Entity (XXE)",
        "The application processes XML with external entity references enabled, allowing file disclosure or SSRF.",
        Severity::High,
        "File disclosure, SSRF, denial of service.",
        "Disable DTD processing and external entities. Use defusedxml (Python) or equivalent.",
    ),
    (
        "CWE-918",
        "Server-Side Request Forgery (SSRF)",
        "The application fetches remote resources using user-controlled URLs without validation.",
        Severity::High,
        "Internal network scanning, cloud metadata exposure, data exfiltration.",
        "Validate and allowlist URLs. Block internal/private IP ranges. Use network-level controls.",
    ),
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn make_rule(id: &str, pattern: &str, severity: Severity, category: RuleCategory) -> SecurityRule {
        SecurityRule {
            id: id.into(),
            name: id.into(),
            severity,
            cwe: None,
            owasp: None,
            languages: vec![],
            pattern: pattern.into(),
            message: "test".into(),
            fix: Some("fix it".into()),
            category,
        }
    }

    // -- scan_file --

    #[test]
    fn test_scan_file_finds_eval() {
        let rules = vec![make_rule("R1", r"eval\(", Severity::High, RuleCategory::Injection)];
        let source = "x = eval(input())";
        let findings = scan_file(Path::new("test.py"), source, "python", &rules);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "R1");
        assert_eq!(findings[0].line_number, 1);
        assert_eq!(findings[0].file_path, "test.py");
    }

    #[test]
    fn test_scan_file_no_findings() {
        let rules = vec![make_rule("R1", r"eval\(", Severity::High, RuleCategory::Injection)];
        let source = "safe_function()";
        let findings = scan_file(Path::new("test.py"), source, "python", &rules);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_file_multiple_rules() {
        let rules = vec![
            make_rule("R1", r"eval\(", Severity::High, RuleCategory::Injection),
            make_rule("R2", r"exec\(", Severity::High, RuleCategory::Injection),
        ];
        let source = "eval(x)\nexec(y)";
        let findings = scan_file(Path::new("test.py"), source, "python", &rules);
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_scan_file_findings_sorted_by_severity() {
        let rules = vec![
            make_rule("R1", r"info_pattern", Severity::Info, RuleCategory::Other),
            make_rule("R2", r"critical_pattern", Severity::Critical, RuleCategory::Injection),
        ];
        let source = "info_pattern\ncritical_pattern";
        let findings = scan_file(Path::new("t.py"), source, "python", &rules);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::Info);
    }

    // -- scan_directory --

    #[test]
    fn test_scan_directory_with_python_file() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("vuln.py");
        let mut f = std::fs::File::create(&file).unwrap();
        writeln!(f, "x = eval(input())").unwrap();

        let rules = vec![make_rule("R1", r"eval\(", Severity::High, RuleCategory::Injection)];
        let summary = scan_directory(dir.path(), &rules, false);
        assert_eq!(summary.total_findings, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.files_scanned, 1);
    }

    #[test]
    fn test_scan_directory_excludes_tests() {
        let dir = TempDir::new().unwrap();
        let tests_dir = dir.path().join("tests");
        std::fs::create_dir_all(&tests_dir).unwrap();
        let file = tests_dir.join("test_vuln.py");
        let mut f = std::fs::File::create(&file).unwrap();
        writeln!(f, "eval(input())").unwrap();

        let rules = vec![make_rule("R1", r"eval\(", Severity::High, RuleCategory::Injection)];
        let summary = scan_directory(dir.path(), &rules, true);
        assert_eq!(summary.total_findings, 0);
    }

    #[test]
    fn test_scan_directory_includes_tests_when_not_excluded() {
        let dir = TempDir::new().unwrap();
        let tests_dir = dir.path().join("tests");
        std::fs::create_dir_all(&tests_dir).unwrap();
        let file = tests_dir.join("test_vuln.py");
        let mut f = std::fs::File::create(&file).unwrap();
        writeln!(f, "eval(input())").unwrap();

        let rules = vec![make_rule("R1", r"eval\(", Severity::High, RuleCategory::Injection)];
        let summary = scan_directory(dir.path(), &rules, false);
        assert!(summary.total_findings >= 1);
    }

    #[test]
    fn test_scan_directory_skips_node_modules() {
        let dir = TempDir::new().unwrap();
        let nm = dir.path().join("node_modules").join("pkg");
        std::fs::create_dir_all(&nm).unwrap();
        let file = nm.join("index.js");
        let mut f = std::fs::File::create(&file).unwrap();
        writeln!(f, "eval(x)").unwrap();

        let rules = vec![make_rule("R1", r"eval\(", Severity::High, RuleCategory::Injection)];
        let summary = scan_directory(dir.path(), &rules, false);
        assert_eq!(summary.total_findings, 0);
    }

    #[test]
    fn test_scan_directory_multiple_files() {
        let dir = TempDir::new().unwrap();
        for name in &["a.py", "b.py", "c.py"] {
            let file = dir.path().join(name);
            let mut f = std::fs::File::create(&file).unwrap();
            writeln!(f, "eval(x)").unwrap();
        }

        let rules = vec![make_rule("R1", r"eval\(", Severity::High, RuleCategory::Injection)];
        let summary = scan_directory(dir.path(), &rules, false);
        assert_eq!(summary.total_findings, 3);
        assert_eq!(summary.files_scanned, 3);
    }

    #[test]
    fn test_scan_directory_empty() {
        let dir = TempDir::new().unwrap();
        let rules = vec![make_rule("R1", r"eval\(", Severity::High, RuleCategory::Injection)];
        let summary = scan_directory(dir.path(), &rules, false);
        assert_eq!(summary.total_findings, 0);
        assert_eq!(summary.files_scanned, 0);
    }

    // -- SecuritySummary --

    #[test]
    fn test_summary_severity_counts() {
        let mut summary = SecuritySummary::new();
        summary.add_finding(SecurityFinding {
            rule_id: "R".into(), rule_name: "R".into(), severity: Severity::Critical,
            file_path: "f".into(), line_number: 1, column: 1, matched_text: "x".into(),
            message: "m".into(), fix: None, cwe: None, owasp: None, category: RuleCategory::Other,
        });
        summary.add_finding(SecurityFinding {
            rule_id: "R".into(), rule_name: "R".into(), severity: Severity::Low,
            file_path: "f".into(), line_number: 2, column: 1, matched_text: "y".into(),
            message: "m".into(), fix: None, cwe: None, owasp: None, category: RuleCategory::Other,
        });
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.low, 1);
        assert_eq!(summary.total_findings, 2);
    }

    #[test]
    fn test_summary_top_issues() {
        let mut summary = SecuritySummary::new();
        for _ in 0..5 {
            summary.add_finding(SecurityFinding {
                rule_id: "R1".into(), rule_name: "Frequent".into(), severity: Severity::Medium,
                file_path: "f".into(), line_number: 1, column: 1, matched_text: "x".into(),
                message: "m".into(), fix: None, cwe: None, owasp: None, category: RuleCategory::Other,
            });
        }
        summary.add_finding(SecurityFinding {
            rule_id: "R2".into(), rule_name: "Rare".into(), severity: Severity::Low,
            file_path: "f".into(), line_number: 1, column: 1, matched_text: "y".into(),
            message: "m".into(), fix: None, cwe: None, owasp: None, category: RuleCategory::Other,
        });
        summary.finalize();
        assert_eq!(summary.top_issues[0].0, "Frequent");
        assert_eq!(summary.top_issues[0].1, 5);
    }

    // -- check_owasp_top10 / check_cwe_top25 --

    #[test]
    fn test_check_owasp_top10_smoke() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("app.py");
        let mut f = std::fs::File::create(&file).unwrap();
        writeln!(f, "password = \"hunter2hunter2\"").unwrap();

        let summary = check_owasp_top10(dir.path());
        // At least the hardcoded password rule should fire.
        assert!(summary.total_findings >= 1);
    }

    #[test]
    fn test_check_cwe_top25_smoke() {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("app.py");
        let mut f = std::fs::File::create(&file).unwrap();
        writeln!(f, "cursor.execute(\"SELECT * FROM users WHERE id=\" + user_id)").unwrap();

        let summary = check_cwe_top25(dir.path());
        assert!(summary.total_findings >= 1);
    }

    // -- explain_vulnerability --

    #[test]
    fn test_explain_sql_injection() {
        let expl = explain_vulnerability("CWE-89");
        assert!(expl.is_some());
        let expl = expl.unwrap();
        assert_eq!(expl.cwe_id, "CWE-89");
        assert!(expl.name.contains("SQL"));
        assert!(expl.severity == Severity::Critical);
        assert!(!expl.references.is_empty());
    }

    #[test]
    fn test_explain_xss() {
        let expl = explain_vulnerability("CWE-79");
        assert!(expl.is_some());
        assert!(expl.unwrap().name.contains("XSS"));
    }

    #[test]
    fn test_explain_unknown_cwe() {
        assert!(explain_vulnerability("CWE-99999").is_none());
    }

    #[test]
    fn test_explain_all_known_cwes() {
        let known = [
            "CWE-79", "CWE-89", "CWE-78", "CWE-22", "CWE-327", "CWE-798",
            "CWE-502", "CWE-20", "CWE-352", "CWE-787", "CWE-125", "CWE-416",
            "CWE-94", "CWE-330", "CWE-611", "CWE-918",
        ];
        for cwe in &known {
            assert!(
                explain_vulnerability(cwe).is_some(),
                "Missing explanation for {}",
                cwe
            );
        }
    }

    // -- suggest_fix --

    #[test]
    fn test_suggest_fix_with_rule_fix() {
        let finding = SecurityFinding {
            rule_id: "R".into(), rule_name: "R".into(), severity: Severity::High,
            file_path: "f".into(), line_number: 1, column: 1, matched_text: "x".into(),
            message: "m".into(), fix: Some("specific fix".into()),
            cwe: None, owasp: None, category: RuleCategory::Injection,
        };
        assert_eq!(suggest_fix(&finding), "specific fix");
    }

    #[test]
    fn test_suggest_fix_by_category() {
        let categories = [
            (RuleCategory::Injection, "parameterized"),
            (RuleCategory::Crypto, "AES-256"),
            (RuleCategory::Secrets, "environment"),
            (RuleCategory::Xss, "Sanitize"),
            (RuleCategory::PathTraversal, "canonicalize"),
            (RuleCategory::Deserialization, "safe"),
            (RuleCategory::Authentication, "authentication"),
            (RuleCategory::Config, "debug"),
        ];
        for (cat, expected_substr) in &categories {
            let finding = SecurityFinding {
                rule_id: "R".into(), rule_name: "R".into(), severity: Severity::Medium,
                file_path: "f".into(), line_number: 1, column: 1, matched_text: "x".into(),
                message: "m".into(), fix: None, cwe: None, owasp: None, category: *cat,
            };
            let fix = suggest_fix(&finding);
            assert!(
                fix.to_lowercase().contains(&expected_substr.to_lowercase()),
                "Fix for {:?} should contain '{}', got: {}",
                cat, expected_substr, fix
            );
        }
    }

    // -- Bundled rules integration --

    #[test]
    fn test_scan_file_python_sql_injection() {
        let rules = load_bundled_rules();
        let source = r#"
def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
"#;
        let findings = scan_file(Path::new("test.py"), source, "python", &rules);
        assert!(
            findings.iter().any(|f| f.category == RuleCategory::Injection
                || f.cwe.as_deref() == Some("CWE-89")),
            "Should detect SQL injection pattern"
        );
    }

    #[test]
    fn test_scan_file_javascript_xss() {
        let rules = load_bundled_rules();
        let source = "document.getElementById('output').innerHTML = userInput;";
        let findings = scan_file(Path::new("app.js"), source, "javascript", &rules);
        assert!(
            findings.iter().any(|f| f.category == RuleCategory::Xss
                || f.cwe.as_deref() == Some("CWE-79")),
            "Should detect XSS via innerHTML"
        );
    }

    #[test]
    fn test_scan_file_hardcoded_password() {
        let rules = load_bundled_rules();
        let source = r#"db_password = "MyS3cretP@ssw0rd!""#;
        let findings = scan_file(Path::new("config.py"), source, "python", &rules);
        assert!(
            findings.iter().any(|f| f.category == RuleCategory::Secrets
                || f.cwe.as_deref() == Some("CWE-798")),
            "Should detect hardcoded password"
        );
    }

    #[test]
    fn test_scan_file_weak_hash() {
        let rules = load_bundled_rules();
        let source = "import hashlib\nh = hashlib.md5(data)";
        let findings = scan_file(Path::new("hash.py"), source, "python", &rules);
        assert!(
            findings.iter().any(|f| f.category == RuleCategory::Crypto),
            "Should detect MD5 usage"
        );
    }

    #[test]
    fn test_scan_file_command_injection() {
        let rules = load_bundled_rules();
        let source = "import os\nos.system('rm -rf ' + user_input)";
        let findings = scan_file(Path::new("cmd.py"), source, "python", &rules);
        assert!(
            findings.iter().any(|f| f.category == RuleCategory::Injection
                || f.cwe.as_deref() == Some("CWE-78")),
            "Should detect command injection"
        );
    }

    #[test]
    fn test_scan_file_deserialization() {
        let rules = load_bundled_rules();
        let source = "import pickle\ndata = pickle.loads(user_data)";
        let findings = scan_file(Path::new("deser.py"), source, "python", &rules);
        assert!(
            findings.iter().any(|f| f.category == RuleCategory::Deserialization
                || f.cwe.as_deref() == Some("CWE-502")),
            "Should detect insecure deserialization"
        );
    }

    #[test]
    fn test_scan_file_aws_key() {
        let rules = load_bundled_rules();
        let source = "AWS_KEY = \"FKIAEXAMPLEKEY000000\"";
        let findings = scan_file(Path::new("creds.py"), source, "python", &rules);
        assert!(
            !findings.is_empty(),
            "Should detect AWS access key"
        );
    }

    #[test]
    fn test_scan_file_debug_mode() {
        let rules = load_bundled_rules();
        let source = "DEBUG = True\napp.run(debug=True)";
        let findings = scan_file(Path::new("settings.py"), source, "python", &rules);
        assert!(
            findings.iter().any(|f| f.category == RuleCategory::Config),
            "Should detect debug mode enabled"
        );
    }

    #[test]
    fn test_scan_file_clean_code() {
        let rules = load_bundled_rules();
        let source = r#"
def get_user(user_id: int):
    """Fetch user by ID safely."""
    return db.session.query(User).filter_by(id=user_id).first()
"#;
        let findings = scan_file(Path::new("safe.py"), source, "python", &rules);
        // Clean code should produce zero or very few low-severity findings.
        let critical = findings.iter().filter(|f| f.severity >= Severity::High).count();
        assert_eq!(critical, 0, "Clean code should not trigger high/critical findings");
    }
}
