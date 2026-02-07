//! Security analysis module — YAML rules engine, taint tracking, vulnerability scanning.
//!
//! This module provides:
//! - YAML-based security rule definitions with pattern, crypto, secret, and taint rule types
//! - Code scanning engine for OWASP Top 10 and CWE Top 25 coverage
//! - Taint analysis: source→sink tracking with sanitizer awareness
//! - Vulnerability explanation and fix suggestion

pub mod rules;
pub mod scanner;
pub mod taint;

// Re-export the primary public API so callers can use `security::*` directly.
pub use rules::{
    load_bundled_rules, load_rules, match_rule, RuleCategory, RuleMatch, SecurityRule, Severity,
};
pub use scanner::{
    check_cwe_top25, check_owasp_top10, explain_vulnerability, scan_directory, scan_file,
    suggest_fix, SecurityFinding, SecuritySummary, VulnerabilityExplanation,
};
pub use taint::{
    find_injection_vulnerabilities, find_taint_sources, trace_taint, TaintFlow, TaintSink,
    TaintSource, TaintSourceKind, TaintStep,
};
