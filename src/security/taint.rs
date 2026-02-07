//! Taint analysis — source-to-sink data flow tracking.
//!
//! Identifies taint sources (user input, file reads, env vars), traces data flow
//! through assignments and function calls, and reports unsanitized flows into
//! dangerous sinks (SQL queries, command execution, HTML output, etc.).

use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Kind of taint source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintSourceKind {
    UserInput,
    FileRead,
    NetworkRequest,
    Environment,
    Database,
    CommandArgs,
}

impl std::fmt::Display for TaintSourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaintSourceKind::UserInput => write!(f, "User Input"),
            TaintSourceKind::FileRead => write!(f, "File Read"),
            TaintSourceKind::NetworkRequest => write!(f, "Network Request"),
            TaintSourceKind::Environment => write!(f, "Environment Variable"),
            TaintSourceKind::Database => write!(f, "Database Query"),
            TaintSourceKind::CommandArgs => write!(f, "Command Arguments"),
        }
    }
}

/// A taint source: a point where untrusted data enters the program.
#[derive(Debug, Clone)]
pub struct TaintSource {
    pub kind: TaintSourceKind,
    pub file_path: String,
    pub line_number: usize,
    pub expression: String,
    pub variable: String,
}

/// A taint sink: a dangerous operation that should not receive unsanitized data.
#[derive(Debug, Clone)]
pub struct TaintSink {
    pub kind: String,
    pub file_path: String,
    pub line_number: usize,
    pub expression: String,
    pub function: String,
}

/// An intermediate step in a taint flow.
#[derive(Debug, Clone)]
pub struct TaintStep {
    pub file_path: String,
    pub line_number: usize,
    pub code: String,
    pub variable: String,
    pub operation: String,
}

/// A complete taint flow from source to sink.
#[derive(Debug, Clone)]
pub struct TaintFlow {
    pub source: TaintSource,
    pub sink: TaintSink,
    pub path: Vec<TaintStep>,
    pub vulnerability_type: String,
    pub is_sanitized: bool,
}

// ---------------------------------------------------------------------------
// Source patterns per language
// ---------------------------------------------------------------------------

struct SourcePattern {
    language: &'static str,
    patterns: &'static [&'static str],
    kind: TaintSourceKind,
}

const SOURCE_PATTERNS: &[SourcePattern] = &[
    // Python
    SourcePattern { language: "python", patterns: &[
        "request.args", "request.form", "request.data", "request.json",
        "request.values", "request.cookies", "request.headers",
        "request.GET", "request.POST", "request.COOKIES", "request.META",
    ], kind: TaintSourceKind::UserInput },
    SourcePattern { language: "python", patterns: &[
        "input(", "sys.argv", "sys.stdin",
    ], kind: TaintSourceKind::CommandArgs },
    SourcePattern { language: "python", patterns: &[
        "os.environ", "os.getenv(",
    ], kind: TaintSourceKind::Environment },
    SourcePattern { language: "python", patterns: &[
        "open(", ".read(", "read_to_string",
    ], kind: TaintSourceKind::FileRead },
    // JavaScript / TypeScript
    SourcePattern { language: "javascript", patterns: &[
        "req.query", "req.body", "req.params", "req.cookies", "req.headers",
        "request.query", "request.body", "request.params",
    ], kind: TaintSourceKind::UserInput },
    SourcePattern { language: "typescript", patterns: &[
        "req.query", "req.body", "req.params", "req.cookies", "req.headers",
    ], kind: TaintSourceKind::UserInput },
    SourcePattern { language: "javascript", patterns: &[
        "process.argv", "process.env",
    ], kind: TaintSourceKind::Environment },
    SourcePattern { language: "javascript", patterns: &[
        "fs.readFile", "fs.readFileSync", "readFile(",
    ], kind: TaintSourceKind::FileRead },
    // Go
    SourcePattern { language: "go", patterns: &[
        "r.URL.Query", "r.FormValue(", "r.PostFormValue(", "r.Header.Get(",
        "r.Body",
    ], kind: TaintSourceKind::UserInput },
    SourcePattern { language: "go", patterns: &[
        "os.Getenv(", "os.Args",
    ], kind: TaintSourceKind::Environment },
    // Java / Kotlin
    SourcePattern { language: "java", patterns: &[
        "getParameter(", "getParameterValues(", "getInputStream(",
        "getReader(", "getHeader(", "getCookies(", "getQueryString(",
    ], kind: TaintSourceKind::UserInput },
    SourcePattern { language: "kotlin", patterns: &[
        "getParameter(", "getParameterValues(",
    ], kind: TaintSourceKind::UserInput },
    // PHP
    SourcePattern { language: "php", patterns: &[
        "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES",
    ], kind: TaintSourceKind::UserInput },
    SourcePattern { language: "php", patterns: &[
        "file_get_contents(", "fread(", "fgets(",
    ], kind: TaintSourceKind::FileRead },
    // Ruby
    SourcePattern { language: "ruby", patterns: &[
        "params[", "request.params", "request.body",
    ], kind: TaintSourceKind::UserInput },
    // Rust
    SourcePattern { language: "rust", patterns: &[
        "web::Query", "web::Form", "web::Json", "web::Path",
    ], kind: TaintSourceKind::UserInput },
    SourcePattern { language: "rust", patterns: &[
        "std::env::var(", "env::var(",
    ], kind: TaintSourceKind::Environment },
    // C / C++
    SourcePattern { language: "c", patterns: &[
        "scanf(", "gets(", "fgets(", "getenv(",
    ], kind: TaintSourceKind::UserInput },
    SourcePattern { language: "cpp", patterns: &[
        "std::cin", "getline(", "getenv(",
    ], kind: TaintSourceKind::UserInput },
];

// ---------------------------------------------------------------------------
// Sink patterns per language
// ---------------------------------------------------------------------------

struct SinkPattern {
    language: &'static str,
    patterns: &'static [&'static str],
    kind: &'static str,
    vuln_type: &'static str,
}

const SINK_PATTERNS: &[SinkPattern] = &[
    // SQL sinks
    SinkPattern { language: "python", patterns: &[
        "cursor.execute(", ".execute(", "raw(", "extra(",
    ], kind: "sql_query", vuln_type: "SQL Injection" },
    SinkPattern { language: "javascript", patterns: &[
        ".query(", ".execute(", "knex.raw(",
    ], kind: "sql_query", vuln_type: "SQL Injection" },
    SinkPattern { language: "java", patterns: &[
        "executeQuery(", "executeUpdate(", "execute(",
        "createQuery(", "createNativeQuery(",
    ], kind: "sql_query", vuln_type: "SQL Injection" },
    SinkPattern { language: "php", patterns: &[
        "mysql_query(", "mysqli_query(", "->query(",
    ], kind: "sql_query", vuln_type: "SQL Injection" },
    SinkPattern { language: "go", patterns: &[
        "db.Query(", "db.Exec(", "db.QueryRow(",
    ], kind: "sql_query", vuln_type: "SQL Injection" },
    // Command injection sinks
    SinkPattern { language: "python", patterns: &[
        "os.system(", "subprocess.call(", "subprocess.run(",
        "subprocess.Popen(", "os.popen(",
    ], kind: "command_exec", vuln_type: "Command Injection" },
    SinkPattern { language: "javascript", patterns: &[
        "child_process.exec(", "child_process.execSync(",
        "execSync(", "exec(",
    ], kind: "command_exec", vuln_type: "Command Injection" },
    SinkPattern { language: "php", patterns: &[
        "exec(", "system(", "passthru(", "shell_exec(", "popen(",
    ], kind: "command_exec", vuln_type: "Command Injection" },
    SinkPattern { language: "ruby", patterns: &[
        "system(", "`", "exec(", "IO.popen(",
    ], kind: "command_exec", vuln_type: "Command Injection" },
    // XSS sinks
    SinkPattern { language: "javascript", patterns: &[
        "innerHTML", "document.write(", "dangerouslySetInnerHTML",
    ], kind: "html_output", vuln_type: "Cross-Site Scripting (XSS)" },
    SinkPattern { language: "python", patterns: &[
        "Markup(", "render_template_string(",
    ], kind: "html_output", vuln_type: "Cross-Site Scripting (XSS)" },
    // Path traversal sinks
    SinkPattern { language: "python", patterns: &[
        "open(", "os.path.join(",
    ], kind: "file_path", vuln_type: "Path Traversal" },
    SinkPattern { language: "javascript", patterns: &[
        "fs.readFile(", "fs.writeFile(", "path.join(",
    ], kind: "file_path", vuln_type: "Path Traversal" },
    // Eval sinks
    SinkPattern { language: "python", patterns: &["eval(", "exec("], kind: "code_eval", vuln_type: "Code Injection" },
    SinkPattern { language: "javascript", patterns: &["eval(", "Function("], kind: "code_eval", vuln_type: "Code Injection" },
    SinkPattern { language: "php", patterns: &["eval(", "assert("], kind: "code_eval", vuln_type: "Code Injection" },
    // Deserialization sinks
    SinkPattern { language: "python", patterns: &["pickle.loads(", "pickle.load(", "yaml.load("], kind: "deserialization", vuln_type: "Insecure Deserialization" },
    SinkPattern { language: "java", patterns: &["readObject(", "ObjectInputStream("], kind: "deserialization", vuln_type: "Insecure Deserialization" },
    SinkPattern { language: "php", patterns: &["unserialize("], kind: "deserialization", vuln_type: "Insecure Deserialization" },
];

// ---------------------------------------------------------------------------
// Sanitizer patterns
// ---------------------------------------------------------------------------

struct SanitizerPattern {
    kind: &'static str,
    patterns: &'static [&'static str],
}

const SANITIZER_PATTERNS: &[SanitizerPattern] = &[
    SanitizerPattern { kind: "sql_query", patterns: &[
        "parameterized", "prepared", "sanitize", "escape", "quote",
        "bind", "placeholder", "%s", "?",
    ]},
    SanitizerPattern { kind: "command_exec", patterns: &[
        "shlex.quote", "escapeshellarg", "shellescape",
    ]},
    SanitizerPattern { kind: "html_output", patterns: &[
        "escape(", "html.escape", "cgi.escape", "bleach.clean",
        "DOMPurify.sanitize", "encodeURIComponent", "escapeHtml",
        "sanitize", "strip_tags",
    ]},
    SanitizerPattern { kind: "file_path", patterns: &[
        "realpath", "abspath", "canonicalize", "normalize",
        "basename", "secure_filename",
    ]},
    SanitizerPattern { kind: "code_eval", patterns: &[
        "ast.literal_eval", "json.loads", "JSON.parse",
    ]},
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Find taint sources in source code for a given language.
pub fn find_taint_sources(source: &str, language: &str) -> Vec<TaintSource> {
    let mut sources = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let line_num = line_num + 1;

        for sp in SOURCE_PATTERNS {
            if !sp.language.eq_ignore_ascii_case(language) {
                continue;
            }
            for pattern in sp.patterns {
                if line.contains(pattern) {
                    let variable = extract_variable(line);
                    sources.push(TaintSource {
                        kind: sp.kind.clone(),
                        file_path: String::new(),
                        line_number: line_num,
                        expression: line.trim().to_string(),
                        variable,
                    });
                }
            }
        }
    }

    sources
}

/// Find injection vulnerabilities by tracing taint from sources to sinks.
pub fn find_injection_vulnerabilities(source: &str, language: &str) -> Vec<TaintFlow> {
    let sources = find_taint_sources(source, language);
    let sinks = find_sinks(source, language);

    if sources.is_empty() || sinks.is_empty() {
        return Vec::new();
    }

    let lines: Vec<&str> = source.lines().collect();
    let mut flows = Vec::new();

    for src in &sources {
        let mut tainted_vars: HashSet<String> = HashSet::new();
        tainted_vars.insert(src.variable.clone());

        // Forward propagation.
        for line_num in src.line_number..=lines.len() {
            let idx = line_num - 1;
            if idx >= lines.len() {
                break;
            }
            let line = lines[idx];

            // Propagate through assignments.
            if let Some((lhs, rhs)) = parse_assignment(line) {
                for tv in tainted_vars.clone() {
                    if rhs.contains(&tv) {
                        tainted_vars.insert(lhs.clone());
                    }
                }
            }

            // Check for collection methods propagating taint.
            propagate_method_taint(line, &mut tainted_vars);

            // Check sinks.
            for sink in &sinks {
                if sink.line_number == line_num {
                    for tv in &tainted_vars {
                        if sink.expression.contains(tv) {
                            let is_sanitized = check_sanitization(
                                &lines,
                                src.line_number,
                                sink.line_number,
                                &sink.kind,
                            );
                            let path = build_path(
                                &lines,
                                src,
                                sink,
                                tv,
                            );
                            flows.push(TaintFlow {
                                source: src.clone(),
                                sink: sink.clone(),
                                path,
                                vulnerability_type: sink_to_vuln_type(&sink.kind),
                                is_sanitized,
                            });
                        }
                    }
                }
            }
        }
    }

    // Only return unsanitized flows.
    flows.into_iter().filter(|f| !f.is_sanitized).collect()
}

/// Trace taint from a specific line number.
pub fn trace_taint(source: &str, language: &str, from_line: usize) -> Vec<TaintFlow> {
    let all_sources = find_taint_sources(source, language);
    let relevant: Vec<_> = all_sources
        .into_iter()
        .filter(|s| s.line_number == from_line)
        .collect();

    if relevant.is_empty() {
        return Vec::new();
    }

    let sinks = find_sinks(source, language);
    let lines: Vec<&str> = source.lines().collect();
    let mut flows = Vec::new();

    for src in &relevant {
        let mut tainted_vars: HashSet<String> = HashSet::new();
        tainted_vars.insert(src.variable.clone());

        for line_num in src.line_number..=lines.len() {
            let idx = line_num - 1;
            if idx >= lines.len() {
                break;
            }
            let line = lines[idx];

            if let Some((lhs, rhs)) = parse_assignment(line) {
                for tv in tainted_vars.clone() {
                    if rhs.contains(&tv) {
                        tainted_vars.insert(lhs.clone());
                    }
                }
            }

            propagate_method_taint(line, &mut tainted_vars);

            for sink in &sinks {
                if sink.line_number == line_num {
                    for tv in &tainted_vars {
                        if sink.expression.contains(tv) {
                            let is_sanitized = check_sanitization(
                                &lines,
                                src.line_number,
                                sink.line_number,
                                &sink.kind,
                            );
                            let path = build_path(&lines, src, sink, tv);
                            flows.push(TaintFlow {
                                source: src.clone(),
                                sink: sink.clone(),
                                path,
                                vulnerability_type: sink_to_vuln_type(&sink.kind),
                                is_sanitized,
                            });
                        }
                    }
                }
            }
        }
    }

    flows
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn find_sinks(source: &str, language: &str) -> Vec<TaintSink> {
    let mut sinks = Vec::new();

    for (line_num, line) in source.lines().enumerate() {
        let line_num = line_num + 1;

        for sp in SINK_PATTERNS {
            if !sp.language.eq_ignore_ascii_case(language) {
                continue;
            }
            for pattern in sp.patterns {
                if line.contains(pattern) {
                    sinks.push(TaintSink {
                        kind: sp.kind.to_string(),
                        file_path: String::new(),
                        line_number: line_num,
                        expression: line.trim().to_string(),
                        function: pattern.trim_end_matches('(').to_string(),
                    });
                }
            }
        }
    }

    sinks
}

fn extract_variable(line: &str) -> String {
    let line = line.trim();
    if let Some(eq_pos) = line.find('=') {
        if eq_pos > 0 {
            let before = line.as_bytes().get(eq_pos.wrapping_sub(1));
            let after = line.as_bytes().get(eq_pos + 1);
            if before == Some(&b'=') || before == Some(&b'!') || after == Some(&b'=') {
                return "unknown".to_string();
            }
        }
        let lhs = line[..eq_pos].trim();
        // Strip Go := operator
        let lhs = lhs.trim_end_matches(':');
        let lhs = lhs
            .trim_start_matches("let ")
            .trim_start_matches("const ")
            .trim_start_matches("var ")
            .trim_start_matches("mut ")
            .trim();
        // For PHP variables ($name), handle the $ prefix
        if lhs.starts_with('$') {
            let var: String = lhs
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            if !var.is_empty() {
                return var;
            }
        }
        // For typed declarations (e.g. "String name"), take the last word
        let words: Vec<&str> = lhs.split_whitespace().collect();
        if words.len() > 1 {
            let last = words.last().unwrap();
            let var: String = last
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            if !var.is_empty() {
                return var;
            }
        }
        let var: String = lhs
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !var.is_empty() {
            return var;
        }
    }
    "unknown".to_string()
}

fn parse_assignment(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if let Some(eq_pos) = line.find('=') {
        if eq_pos > 0 {
            let before = line.as_bytes().get(eq_pos.wrapping_sub(1));
            let after = line.as_bytes().get(eq_pos + 1);
            if before == Some(&b'=') || before == Some(&b'!') || after == Some(&b'=') {
                return None;
            }
        }
        let lhs = line[..eq_pos].trim();
        let rhs = line[eq_pos + 1..].trim();
        // Strip Go := operator
        let lhs = lhs.trim_end_matches(':');
        let lhs = lhs
            .trim_start_matches("let ")
            .trim_start_matches("const ")
            .trim_start_matches("var ")
            .trim_start_matches("mut ")
            .trim();
        // For PHP variables ($name)
        if lhs.starts_with('$') {
            let var: String = lhs
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            if !var.is_empty() {
                return Some((var, rhs.to_string()));
            }
        }
        // For typed declarations (e.g. "String name"), take the last word
        let words: Vec<&str> = lhs.split_whitespace().collect();
        if words.len() > 1 {
            let last = words.last().unwrap();
            let var: String = last
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            if !var.is_empty() {
                return Some((var, rhs.to_string()));
            }
        }
        let var: String = lhs
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !var.is_empty() {
            return Some((var, rhs.to_string()));
        }
    }
    None
}

fn propagate_method_taint(line: &str, tainted_vars: &mut HashSet<String>) {
    let methods = [".append(", ".push(", ".add(", ".insert(", ".extend(", ".concat("];
    for method in &methods {
        if let Some(pos) = line.find(method) {
            let base: String = line[..pos]
                .trim()
                .chars()
                .rev()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            if base.is_empty() {
                continue;
            }
            let after = &line[pos + method.len()..];
            if let Some(close) = after.find(')') {
                let args = &after[..close];
                for tv in tainted_vars.clone() {
                    if args.contains(&tv) {
                        tainted_vars.insert(base.clone());
                        break;
                    }
                }
            }
        }
    }
}

fn check_sanitization(lines: &[&str], source_line: usize, sink_line: usize, sink_kind: &str) -> bool {
    let sanitizers = SANITIZER_PATTERNS.iter().find(|s| s.kind == sink_kind);
    if let Some(sp) = sanitizers {
        for line_num in source_line..sink_line {
            if line_num > 0 && line_num <= lines.len() {
                let line = lines[line_num - 1];
                for pattern in sp.patterns {
                    if line.contains(pattern) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn build_path(lines: &[&str], src: &TaintSource, sink: &TaintSink, variable: &str) -> Vec<TaintStep> {
    let mut path = Vec::new();

    path.push(TaintStep {
        file_path: src.file_path.clone(),
        line_number: src.line_number,
        code: src.expression.clone(),
        variable: src.variable.clone(),
        operation: "source".to_string(),
    });

    for line_num in (src.line_number + 1)..sink.line_number {
        if line_num > 0 && line_num <= lines.len() {
            let line = lines[line_num - 1];
            if line.contains(variable) {
                let op = if line.contains('=') && !line.contains("==") {
                    "assignment"
                } else if line.contains('(') {
                    "function_call"
                } else {
                    "propagation"
                };
                path.push(TaintStep {
                    file_path: src.file_path.clone(),
                    line_number: line_num,
                    code: line.trim().to_string(),
                    variable: variable.to_string(),
                    operation: op.to_string(),
                });
            }
        }
    }

    path.push(TaintStep {
        file_path: sink.file_path.clone(),
        line_number: sink.line_number,
        code: sink.expression.clone(),
        variable: variable.to_string(),
        operation: "sink".to_string(),
    });

    path
}

fn sink_to_vuln_type(sink_kind: &str) -> String {
    for sp in SINK_PATTERNS {
        if sp.kind == sink_kind {
            return sp.vuln_type.to_string();
        }
    }
    format!("Taint flow to {}", sink_kind)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- TaintSourceKind --

    #[test]
    fn test_source_kind_display() {
        assert_eq!(TaintSourceKind::UserInput.to_string(), "User Input");
        assert_eq!(TaintSourceKind::FileRead.to_string(), "File Read");
        assert_eq!(TaintSourceKind::Environment.to_string(), "Environment Variable");
    }

    // -- find_taint_sources --

    #[test]
    fn test_find_sources_python_flask() {
        let source = r#"
from flask import request
username = request.args.get('name')
"#;
        let sources = find_taint_sources(source, "python");
        assert!(!sources.is_empty(), "Should find Flask request.args source");
        assert_eq!(sources[0].kind, TaintSourceKind::UserInput);
        assert_eq!(sources[0].variable, "username");
    }

    #[test]
    fn test_find_sources_python_django() {
        let source = "data = request.POST['key']";
        let sources = find_taint_sources(source, "python");
        assert!(!sources.is_empty());
        assert_eq!(sources[0].kind, TaintSourceKind::UserInput);
    }

    #[test]
    fn test_find_sources_python_input() {
        let source = "name = input('Enter name: ')";
        let sources = find_taint_sources(source, "python");
        assert!(!sources.is_empty());
        assert_eq!(sources[0].kind, TaintSourceKind::CommandArgs);
    }

    #[test]
    fn test_find_sources_python_env() {
        let source = "secret = os.environ.get('SECRET')";
        let sources = find_taint_sources(source, "python");
        assert!(!sources.is_empty());
        assert_eq!(sources[0].kind, TaintSourceKind::Environment);
    }

    #[test]
    fn test_find_sources_javascript_express() {
        let source = "const name = req.query.name;";
        let sources = find_taint_sources(source, "javascript");
        assert!(!sources.is_empty());
        assert_eq!(sources[0].kind, TaintSourceKind::UserInput);
    }

    #[test]
    fn test_find_sources_javascript_body() {
        let source = "const data = req.body;";
        let sources = find_taint_sources(source, "javascript");
        assert!(!sources.is_empty());
    }

    #[test]
    fn test_find_sources_go_http() {
        let source = "name := r.URL.Query().Get(\"name\")";
        let sources = find_taint_sources(source, "go");
        assert!(!sources.is_empty());
        assert_eq!(sources[0].kind, TaintSourceKind::UserInput);
    }

    #[test]
    fn test_find_sources_java_servlet() {
        let source = "String name = request.getParameter(\"name\");";
        let sources = find_taint_sources(source, "java");
        assert!(!sources.is_empty());
        assert_eq!(sources[0].kind, TaintSourceKind::UserInput);
    }

    #[test]
    fn test_find_sources_php_superglobals() {
        let source = "$name = $_GET['name'];";
        let sources = find_taint_sources(source, "php");
        assert!(!sources.is_empty());
        assert_eq!(sources[0].kind, TaintSourceKind::UserInput);
    }

    #[test]
    fn test_find_sources_ruby_params() {
        let source = "name = params[:name]";
        let sources = find_taint_sources(source, "ruby");
        assert!(!sources.is_empty());
    }

    #[test]
    fn test_find_sources_rust_actix() {
        let source = "let query = web::Query::<Params>::extract(&req);";
        let sources = find_taint_sources(source, "rust");
        assert!(!sources.is_empty());
    }

    #[test]
    fn test_find_sources_c_scanf() {
        let source = "scanf(\"%s\", buffer);";
        let sources = find_taint_sources(source, "c");
        assert!(!sources.is_empty());
    }

    #[test]
    fn test_find_sources_no_match() {
        let source = "x = 42\ny = compute(x)";
        let sources = find_taint_sources(source, "python");
        assert!(sources.is_empty());
    }

    #[test]
    fn test_find_sources_wrong_language() {
        let source = "name = request.args.get('name')";
        let sources = find_taint_sources(source, "rust");
        assert!(sources.is_empty());
    }

    // -- find_injection_vulnerabilities --

    #[test]
    fn test_detect_sql_injection_python() {
        let source = r#"
username = request.args.get('name')
query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)
"#;
        let vulns = find_injection_vulnerabilities(source, "python");
        assert!(!vulns.is_empty(), "Should detect SQL injection");
        assert!(vulns[0].vulnerability_type.contains("SQL"));
    }

    #[test]
    fn test_detect_sql_injection_javascript() {
        let source = r#"
const name = req.query.name;
const query = "SELECT * FROM users WHERE name = '" + name + "'";
db.query(query);
"#;
        let vulns = find_injection_vulnerabilities(source, "javascript");
        assert!(!vulns.is_empty(), "Should detect SQL injection in JS");
    }

    #[test]
    fn test_detect_command_injection_python() {
        let source = r#"
user_cmd = request.args.get('cmd')
os.system('echo ' + user_cmd)
"#;
        let vulns = find_injection_vulnerabilities(source, "python");
        assert!(
            vulns.iter().any(|v| v.vulnerability_type.contains("Command")),
            "Should detect command injection"
        );
    }

    #[test]
    fn test_detect_xss_javascript() {
        let source = r#"
const input = req.query.input;
document.innerHTML = input;
"#;
        let vulns = find_injection_vulnerabilities(source, "javascript");
        assert!(
            vulns.iter().any(|v| v.vulnerability_type.contains("XSS")),
            "Should detect XSS via innerHTML"
        );
    }

    #[test]
    fn test_detect_eval_injection_python() {
        let source = r#"
code = request.form.get('code')
result = eval(code)
"#;
        let vulns = find_injection_vulnerabilities(source, "python");
        assert!(
            vulns.iter().any(|v| v.vulnerability_type.contains("Code")),
            "Should detect code injection via eval"
        );
    }

    #[test]
    fn test_sanitized_flow_not_reported() {
        let _source = r#"
username = request.args.get('name')
safe_name = html.escape(username)
document.innerHTML = safe_name
"#;
        // Note: this tests Python source → JS sink, which won't match
        // because find_sinks checks language. But within python:
        let source2 = r#"
username = request.args.get('name')
safe_name = sanitize(username)
cursor.execute(safe_name)
"#;
        let vulns = find_injection_vulnerabilities(source2, "python");
        // The sanitize call should break the taint flow.
        assert!(
            vulns.is_empty(),
            "Sanitized flow should not be reported as vulnerable, got {:?}",
            vulns.iter().map(|v| &v.vulnerability_type).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_taint_propagation_through_assignment() {
        let source = r#"
user_data = request.args.get('data')
processed = user_data.strip()
query = "SELECT * FROM t WHERE x='" + processed + "'"
cursor.execute(query)
"#;
        let vulns = find_injection_vulnerabilities(source, "python");
        assert!(!vulns.is_empty(), "Should track taint through assignment chain");
    }

    #[test]
    fn test_no_vulns_in_clean_code() {
        let source = r#"
x = 42
y = x + 1
print(y)
"#;
        let vulns = find_injection_vulnerabilities(source, "python");
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_multiple_sources_multiple_sinks() {
        let source = r#"
name = request.args.get('name')
cmd = request.form.get('cmd')
cursor.execute("SELECT * FROM t WHERE name='" + name + "'")
os.system(cmd)
"#;
        let vulns = find_injection_vulnerabilities(source, "python");
        assert!(vulns.len() >= 2, "Should detect multiple vulnerabilities");
    }

    // -- trace_taint --

    #[test]
    fn test_trace_taint_from_line() {
        let source = r#"
username = request.args.get('name')
query = "SELECT * FROM users WHERE name = '" + username + "'"
cursor.execute(query)
"#;
        let flows = trace_taint(source, "python", 2);
        assert!(!flows.is_empty(), "Should trace taint from line 2");
    }

    #[test]
    fn test_trace_taint_nonexistent_line() {
        let source = "x = 42";
        let flows = trace_taint(source, "python", 1);
        assert!(flows.is_empty(), "No taint source at line 1");
    }

    // -- Taint flow path --

    #[test]
    fn test_taint_flow_has_path() {
        let source = r#"
user_input = request.args.get('q')
query = "SELECT * FROM t WHERE x='" + user_input + "'"
cursor.execute(query)
"#;
        let vulns = find_injection_vulnerabilities(source, "python");
        assert!(!vulns.is_empty());
        let flow = &vulns[0];
        assert!(flow.path.len() >= 2, "Path should have at least source and sink");
        assert_eq!(flow.path.first().unwrap().operation, "source");
        assert_eq!(flow.path.last().unwrap().operation, "sink");
    }

    // -- extract_variable --

    #[test]
    fn test_extract_variable_simple() {
        assert_eq!(extract_variable("x = foo()"), "x");
    }

    #[test]
    fn test_extract_variable_let() {
        assert_eq!(extract_variable("let name = req.query.name"), "name");
    }

    #[test]
    fn test_extract_variable_const() {
        assert_eq!(extract_variable("const data = req.body"), "data");
    }

    #[test]
    fn test_extract_variable_comparison() {
        assert_eq!(extract_variable("if x == y:"), "unknown");
    }

    // -- parse_assignment --

    #[test]
    fn test_parse_assignment_simple() {
        assert_eq!(
            parse_assignment("x = foo()"),
            Some(("x".to_string(), "foo()".to_string()))
        );
    }

    #[test]
    fn test_parse_assignment_comparison() {
        assert!(parse_assignment("if x == y:").is_none());
    }

    #[test]
    fn test_parse_assignment_not_equal() {
        assert!(parse_assignment("if x != y:").is_none());
    }

    // -- PHP SQL injection --

    #[test]
    fn test_detect_sql_injection_php() {
        let source = r#"
$name = $_GET['name'];
$query = "SELECT * FROM users WHERE name = '" . $name . "'";
mysql_query($query);
"#;
        let vulns = find_injection_vulnerabilities(source, "php");
        assert!(!vulns.is_empty(), "Should detect SQL injection in PHP");
    }

    // -- Java SQL injection --

    #[test]
    fn test_detect_sql_injection_java() {
        let source = r#"
String name = request.getParameter("name");
String query = "SELECT * FROM users WHERE name = '" + name + "'";
stmt.executeQuery(query);
"#;
        let vulns = find_injection_vulnerabilities(source, "java");
        assert!(!vulns.is_empty(), "Should detect SQL injection in Java");
    }

    // -- Go SQL injection --

    #[test]
    fn test_detect_sql_injection_go() {
        let source = r#"
name := r.URL.Query().Get("name")
query := "SELECT * FROM users WHERE name = '" + name + "'"
db.Query(query)
"#;
        let vulns = find_injection_vulnerabilities(source, "go");
        assert!(!vulns.is_empty(), "Should detect SQL injection in Go");
    }

    // -- PHP command injection --

    #[test]
    fn test_detect_command_injection_php() {
        let source = r#"
$cmd = $_POST['cmd'];
system($cmd);
"#;
        let vulns = find_injection_vulnerabilities(source, "php");
        assert!(
            vulns.iter().any(|v| v.vulnerability_type.contains("Command")),
            "Should detect command injection in PHP"
        );
    }
}
