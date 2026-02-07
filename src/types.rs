//! Core domain types for CodeGraph.
//!
//! Faithfully mirrors the TypeScript `types.ts` to ensure database and
//! API compatibility between the TS and Rust versions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Language
// ---------------------------------------------------------------------------

/// Supported source languages (32 languages, 35 variants counting JSX/TSX).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    TypeScript,
    Tsx,
    JavaScript,
    Jsx,
    Python,
    Go,
    Rust,
    Java,
    C,
    Cpp,
    CSharp,
    Php,
    Ruby,
    Swift,
    Kotlin,
    // Phase 11: 17 new languages
    Bash,
    Scala,
    Dart,
    Zig,
    Lua,
    Verilog,
    Haskell,
    Elixir,
    Groovy,
    PowerShell,
    Clojure,
    Julia,
    R,
    Erlang,
    Elm,
    Fortran,
    Nix,
}

impl Language {
    /// Map a file extension (including the dot) to a language.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            ".ts" => Some(Self::TypeScript),
            ".tsx" => Some(Self::Tsx),
            ".js" | ".mjs" | ".cjs" => Some(Self::JavaScript),
            ".jsx" => Some(Self::Jsx),
            ".py" => Some(Self::Python),
            ".go" => Some(Self::Go),
            ".rs" => Some(Self::Rust),
            ".java" => Some(Self::Java),
            ".c" | ".h" => Some(Self::C),
            ".cpp" | ".cc" | ".cxx" | ".hpp" | ".hxx" | ".hh" => Some(Self::Cpp),
            ".cs" => Some(Self::CSharp),
            ".php" => Some(Self::Php),
            ".rb" => Some(Self::Ruby),
            ".swift" => Some(Self::Swift),
            ".kt" | ".kts" => Some(Self::Kotlin),
            // Phase 11
            ".sh" | ".bash" | ".zsh" => Some(Self::Bash),
            ".scala" | ".sc" => Some(Self::Scala),
            ".dart" => Some(Self::Dart),
            ".zig" => Some(Self::Zig),
            ".lua" => Some(Self::Lua),
            ".v" | ".vh" | ".sv" | ".svh" => Some(Self::Verilog),
            ".hs" | ".lhs" => Some(Self::Haskell),
            ".ex" | ".exs" => Some(Self::Elixir),
            ".groovy" | ".gradle" => Some(Self::Groovy),
            ".ps1" | ".psm1" | ".psd1" => Some(Self::PowerShell),
            ".clj" | ".cljs" | ".cljc" | ".edn" => Some(Self::Clojure),
            ".jl" => Some(Self::Julia),
            ".r" | ".R" | ".Rmd" => Some(Self::R),
            ".erl" | ".hrl" => Some(Self::Erlang),
            ".elm" => Some(Self::Elm),
            ".f90" | ".f95" | ".f03" | ".f08" | ".f" | ".for" | ".fpp" => Some(Self::Fortran),
            ".nix" => Some(Self::Nix),
            _ => None,
        }
    }

    /// The tree-sitter grammar name for loading the correct language.
    pub fn grammar_name(&self) -> &'static str {
        match self {
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
            Self::JavaScript | Self::Jsx => "javascript",
            Self::Python => "python",
            Self::Go => "go",
            Self::Rust => "rust",
            Self::Java => "java",
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::CSharp => "c_sharp",
            Self::Php => "php",
            Self::Ruby => "ruby",
            Self::Swift => "swift",
            Self::Kotlin => "kotlin",
            // Phase 11
            Self::Bash => "bash",
            Self::Scala => "scala",
            Self::Dart => "dart",
            Self::Zig => "zig",
            Self::Lua => "lua",
            Self::Verilog => "verilog",
            Self::Haskell => "haskell",
            Self::Elixir => "elixir",
            Self::Groovy => "groovy",
            Self::PowerShell => "powershell",
            Self::Clojure => "clojure",
            Self::Julia => "julia",
            Self::R => "r",
            Self::Erlang => "erlang",
            Self::Elm => "elm",
            Self::Fortran => "fortran",
            Self::Nix => "nix",
        }
    }

    /// Embedded `.scm` query source for this language.
    pub fn query_source(&self) -> &'static str {
        match self {
            Self::TypeScript | Self::Tsx => include_str!("../queries/typescript.scm"),
            Self::JavaScript | Self::Jsx => include_str!("../queries/javascript.scm"),
            Self::Python => include_str!("../queries/python.scm"),
            Self::Go => include_str!("../queries/go.scm"),
            Self::Rust => include_str!("../queries/rust.scm"),
            Self::Java => include_str!("../queries/java.scm"),
            Self::C => include_str!("../queries/c.scm"),
            Self::Cpp => include_str!("../queries/cpp.scm"),
            Self::CSharp => include_str!("../queries/csharp.scm"),
            Self::Php => include_str!("../queries/php.scm"),
            Self::Ruby => include_str!("../queries/ruby.scm"),
            Self::Swift => include_str!("../queries/swift.scm"),
            Self::Kotlin => include_str!("../queries/kotlin.scm"),
            // Phase 11
            Self::Bash => include_str!("../queries/bash.scm"),
            Self::Scala => include_str!("../queries/scala.scm"),
            Self::Dart => include_str!("../queries/dart.scm"),
            Self::Zig => include_str!("../queries/zig.scm"),
            Self::Lua => include_str!("../queries/lua.scm"),
            Self::Verilog => include_str!("../queries/verilog.scm"),
            Self::Haskell => include_str!("../queries/haskell.scm"),
            Self::Elixir => include_str!("../queries/elixir.scm"),
            Self::Groovy => include_str!("../queries/groovy.scm"),
            Self::PowerShell => include_str!("../queries/powershell.scm"),
            Self::Clojure => include_str!("../queries/clojure.scm"),
            Self::Julia => include_str!("../queries/julia.scm"),
            Self::R => include_str!("../queries/r.scm"),
            Self::Erlang => include_str!("../queries/erlang.scm"),
            Self::Elm => include_str!("../queries/elm.scm"),
            Self::Fortran => include_str!("../queries/fortran.scm"),
            Self::Nix => include_str!("../queries/nix.scm"),
        }
    }

    /// String representation matching the TS version's serialization.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
            Self::JavaScript => "javascript",
            Self::Jsx => "jsx",
            Self::Python => "python",
            Self::Go => "go",
            Self::Rust => "rust",
            Self::Java => "java",
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::CSharp => "csharp",
            Self::Php => "php",
            Self::Ruby => "ruby",
            Self::Swift => "swift",
            Self::Kotlin => "kotlin",
            // Phase 11
            Self::Bash => "bash",
            Self::Scala => "scala",
            Self::Dart => "dart",
            Self::Zig => "zig",
            Self::Lua => "lua",
            Self::Verilog => "verilog",
            Self::Haskell => "haskell",
            Self::Elixir => "elixir",
            Self::Groovy => "groovy",
            Self::PowerShell => "powershell",
            Self::Clojure => "clojure",
            Self::Julia => "julia",
            Self::R => "r",
            Self::Erlang => "erlang",
            Self::Elm => "elm",
            Self::Fortran => "fortran",
            Self::Nix => "nix",
        }
    }

    /// Parse from a string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "typescript" => Some(Self::TypeScript),
            "tsx" => Some(Self::Tsx),
            "javascript" => Some(Self::JavaScript),
            "jsx" => Some(Self::Jsx),
            "python" => Some(Self::Python),
            "go" | "golang" => Some(Self::Go),
            "rust" => Some(Self::Rust),
            "java" => Some(Self::Java),
            "c" => Some(Self::C),
            "cpp" | "c++" => Some(Self::Cpp),
            "csharp" | "c#" | "c_sharp" => Some(Self::CSharp),
            "php" => Some(Self::Php),
            "ruby" => Some(Self::Ruby),
            "swift" => Some(Self::Swift),
            "kotlin" => Some(Self::Kotlin),
            // Phase 11
            "bash" | "shell" | "sh" => Some(Self::Bash),
            "scala" => Some(Self::Scala),
            "dart" => Some(Self::Dart),
            "zig" => Some(Self::Zig),
            "lua" => Some(Self::Lua),
            "verilog" | "systemverilog" | "sv" => Some(Self::Verilog),
            "haskell" | "hs" => Some(Self::Haskell),
            "elixir" | "ex" => Some(Self::Elixir),
            "groovy" => Some(Self::Groovy),
            "powershell" | "ps1" => Some(Self::PowerShell),
            "clojure" | "clj" => Some(Self::Clojure),
            "julia" | "jl" => Some(Self::Julia),
            "r" => Some(Self::R),
            "erlang" | "erl" => Some(Self::Erlang),
            "elm" => Some(Self::Elm),
            "fortran" | "f90" => Some(Self::Fortran),
            "nix" => Some(Self::Nix),
            _ => None,
        }
    }
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// NodeKind
// ---------------------------------------------------------------------------

/// Kinds of symbol nodes in the code graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Function,
    Class,
    Method,
    Interface,
    TypeAlias,
    Enum,
    Variable,
    Struct,
    Trait,
    Module,
    Property,
    Namespace,
    Constant,
}

impl NodeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Class => "class",
            Self::Method => "method",
            Self::Interface => "interface",
            Self::TypeAlias => "type_alias",
            Self::Enum => "enum",
            Self::Variable => "variable",
            Self::Struct => "struct",
            Self::Trait => "trait",
            Self::Module => "module",
            Self::Property => "property",
            Self::Namespace => "namespace",
            Self::Constant => "constant",
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s {
            "function" => Some(Self::Function),
            "class" => Some(Self::Class),
            "method" => Some(Self::Method),
            "interface" => Some(Self::Interface),
            "type_alias" => Some(Self::TypeAlias),
            "enum" => Some(Self::Enum),
            "variable" => Some(Self::Variable),
            "struct" => Some(Self::Struct),
            "trait" => Some(Self::Trait),
            "module" => Some(Self::Module),
            "property" | "field" => Some(Self::Property),
            "namespace" | "package" => Some(Self::Namespace),
            "constant" | "const" => Some(Self::Constant),
            _ => None,
        }
    }
}

impl std::fmt::Display for NodeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// EdgeKind
// ---------------------------------------------------------------------------

/// Kinds of edges (relationships) between nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Imports,
    Calls,
    Contains,
    Extends,
    Implements,
    References,
}

impl EdgeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Imports => "imports",
            Self::Calls => "calls",
            Self::Contains => "contains",
            Self::Extends => "extends",
            Self::Implements => "implements",
            Self::References => "references",
        }
    }

    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s {
            "imports" => Some(Self::Imports),
            "calls" => Some(Self::Calls),
            "contains" => Some(Self::Contains),
            "extends" => Some(Self::Extends),
            "implements" => Some(Self::Implements),
            "references" => Some(Self::References),
            _ => None,
        }
    }
}

impl std::fmt::Display for EdgeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CodeNode
// ---------------------------------------------------------------------------

/// A symbol node in the code graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeNode {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qualified_name: Option<String>,
    pub kind: NodeKind,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub start_column: u32,
    pub end_column: u32,
    pub language: Language,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub documentation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exported: Option<bool>,
}

// ---------------------------------------------------------------------------
// CodeEdge
// ---------------------------------------------------------------------------

/// A relationship edge between two nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeEdge {
    pub source: String,
    pub target: String,
    pub kind: EdgeKind,
    pub file_path: String,
    pub line: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Build a deterministic node ID: `{kind}:{filePath}:{name}:{startLine}`
///
/// Matches the TS version's `makeNodeId()` exactly.
pub fn make_node_id(kind: NodeKind, file_path: &str, name: &str, start_line: u32) -> String {
    format!("{}:{}:{}:{}", kind.as_str(), file_path, name, start_line)
}

// ---------------------------------------------------------------------------
// ParseResult
// ---------------------------------------------------------------------------

/// Result of parsing and extracting symbols from a single file.
pub struct ParseResult {
    pub file_path: String,
    pub language: Language,
    pub nodes: Vec<CodeNode>,
    pub edges: Vec<CodeEdge>,
    pub content_hash: String,
}

// ---------------------------------------------------------------------------
// FileRecord
// ---------------------------------------------------------------------------

/// File indexing metadata stored in the file_hashes table.
pub struct FileRecord {
    pub file_path: String,
    pub language: Language,
    pub content_hash: String,
    pub indexed_at: i64,
    pub node_count: usize,
    pub edge_count: usize,
}

// ---------------------------------------------------------------------------
// UnresolvedRef
// ---------------------------------------------------------------------------

/// An import or reference that could not be resolved to a known symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnresolvedRef {
    pub id: i64,
    pub source_id: String,
    pub specifier: String,
    pub ref_type: String,
    pub file_path: String,
    pub line: u32,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_node_id() {
        let id = make_node_id(NodeKind::Function, "src/main.ts", "hello", 10);
        assert_eq!(id, "function:src/main.ts:hello:10");
    }

    #[test]
    fn test_language_from_extension() {
        // Original 15 languages
        assert_eq!(Language::from_extension(".ts"), Some(Language::TypeScript));
        assert_eq!(Language::from_extension(".tsx"), Some(Language::Tsx));
        assert_eq!(Language::from_extension(".js"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension(".jsx"), Some(Language::Jsx));
        assert_eq!(Language::from_extension(".py"), Some(Language::Python));
        assert_eq!(Language::from_extension(".go"), Some(Language::Go));
        assert_eq!(Language::from_extension(".rs"), Some(Language::Rust));
        assert_eq!(Language::from_extension(".java"), Some(Language::Java));
        assert_eq!(Language::from_extension(".c"), Some(Language::C));
        assert_eq!(Language::from_extension(".h"), Some(Language::C));
        assert_eq!(Language::from_extension(".cpp"), Some(Language::Cpp));
        assert_eq!(Language::from_extension(".hpp"), Some(Language::Cpp));
        assert_eq!(Language::from_extension(".cs"), Some(Language::CSharp));
        assert_eq!(Language::from_extension(".php"), Some(Language::Php));
        assert_eq!(Language::from_extension(".rb"), Some(Language::Ruby));
        assert_eq!(Language::from_extension(".kt"), Some(Language::Kotlin));
        assert_eq!(Language::from_extension(".kts"), Some(Language::Kotlin));
        assert_eq!(Language::from_extension(".swift"), Some(Language::Swift));
        assert_eq!(Language::from_extension(".mjs"), Some(Language::JavaScript));
        assert_eq!(Language::from_extension(".cjs"), Some(Language::JavaScript));
        // Phase 11: 17 new languages
        assert_eq!(Language::from_extension(".sh"), Some(Language::Bash));
        assert_eq!(Language::from_extension(".bash"), Some(Language::Bash));
        assert_eq!(Language::from_extension(".zsh"), Some(Language::Bash));
        assert_eq!(Language::from_extension(".scala"), Some(Language::Scala));
        assert_eq!(Language::from_extension(".sc"), Some(Language::Scala));
        assert_eq!(Language::from_extension(".dart"), Some(Language::Dart));
        assert_eq!(Language::from_extension(".zig"), Some(Language::Zig));
        assert_eq!(Language::from_extension(".lua"), Some(Language::Lua));
        assert_eq!(Language::from_extension(".v"), Some(Language::Verilog));
        assert_eq!(Language::from_extension(".sv"), Some(Language::Verilog));
        assert_eq!(Language::from_extension(".hs"), Some(Language::Haskell));
        assert_eq!(Language::from_extension(".lhs"), Some(Language::Haskell));
        assert_eq!(Language::from_extension(".ex"), Some(Language::Elixir));
        assert_eq!(Language::from_extension(".exs"), Some(Language::Elixir));
        assert_eq!(Language::from_extension(".groovy"), Some(Language::Groovy));
        assert_eq!(Language::from_extension(".gradle"), Some(Language::Groovy));
        assert_eq!(Language::from_extension(".ps1"), Some(Language::PowerShell));
        assert_eq!(Language::from_extension(".psm1"), Some(Language::PowerShell));
        assert_eq!(Language::from_extension(".clj"), Some(Language::Clojure));
        assert_eq!(Language::from_extension(".cljs"), Some(Language::Clojure));
        assert_eq!(Language::from_extension(".jl"), Some(Language::Julia));
        assert_eq!(Language::from_extension(".r"), Some(Language::R));
        assert_eq!(Language::from_extension(".R"), Some(Language::R));
        assert_eq!(Language::from_extension(".erl"), Some(Language::Erlang));
        assert_eq!(Language::from_extension(".hrl"), Some(Language::Erlang));
        assert_eq!(Language::from_extension(".elm"), Some(Language::Elm));
        assert_eq!(Language::from_extension(".f90"), Some(Language::Fortran));
        assert_eq!(Language::from_extension(".f95"), Some(Language::Fortran));
        assert_eq!(Language::from_extension(".nix"), Some(Language::Nix));
        // Unsupported
        assert_eq!(Language::from_extension(".yaml"), None);
    }

    #[test]
    fn test_node_kind_roundtrip() {
        for kind in [
            NodeKind::Function,
            NodeKind::Class,
            NodeKind::Method,
            NodeKind::Interface,
            NodeKind::TypeAlias,
            NodeKind::Enum,
            NodeKind::Variable,
            NodeKind::Struct,
            NodeKind::Trait,
            NodeKind::Module,
            NodeKind::Property,
            NodeKind::Namespace,
            NodeKind::Constant,
        ] {
            let s = kind.as_str();
            assert_eq!(NodeKind::from_str_loose(s), Some(kind));
        }
    }

    #[test]
    fn test_edge_kind_roundtrip() {
        for kind in [
            EdgeKind::Imports,
            EdgeKind::Calls,
            EdgeKind::Contains,
            EdgeKind::Extends,
            EdgeKind::Implements,
            EdgeKind::References,
        ] {
            let s = kind.as_str();
            assert_eq!(EdgeKind::from_str_loose(s), Some(kind));
        }
    }

    #[test]
    fn test_language_query_source_not_empty() {
        for lang in ALL_LANGUAGES {
            assert!(!lang.query_source().is_empty(), "{} query is empty", lang);
        }
    }

    /// All 32 language variants for exhaustive testing.
    const ALL_LANGUAGES: [Language; 32] = [
        Language::TypeScript,
        Language::Tsx,
        Language::JavaScript,
        Language::Jsx,
        Language::Python,
        Language::Go,
        Language::Rust,
        Language::Java,
        Language::C,
        Language::Cpp,
        Language::CSharp,
        Language::Php,
        Language::Ruby,
        Language::Swift,
        Language::Kotlin,
        // Phase 11
        Language::Bash,
        Language::Scala,
        Language::Dart,
        Language::Zig,
        Language::Lua,
        Language::Verilog,
        Language::Haskell,
        Language::Elixir,
        Language::Groovy,
        Language::PowerShell,
        Language::Clojure,
        Language::Julia,
        Language::R,
        Language::Erlang,
        Language::Elm,
        Language::Fortran,
        Language::Nix,
    ];

    #[test]
    fn test_language_as_str_from_str_roundtrip() {
        for lang in ALL_LANGUAGES {
            let s = lang.as_str();
            assert!(
                Language::from_str_loose(s).is_some(),
                "from_str_loose({}) returned None for {:?}",
                s,
                lang
            );
            assert_eq!(
                Language::from_str_loose(s).unwrap(),
                lang,
                "roundtrip failed for {:?}",
                lang
            );
        }
    }

    #[test]
    fn test_language_from_str_loose_aliases() {
        // Test various aliases for new languages
        assert_eq!(Language::from_str_loose("shell"), Some(Language::Bash));
        assert_eq!(Language::from_str_loose("sh"), Some(Language::Bash));
        assert_eq!(Language::from_str_loose("hs"), Some(Language::Haskell));
        assert_eq!(Language::from_str_loose("ex"), Some(Language::Elixir));
        assert_eq!(Language::from_str_loose("clj"), Some(Language::Clojure));
        assert_eq!(Language::from_str_loose("jl"), Some(Language::Julia));
        assert_eq!(Language::from_str_loose("erl"), Some(Language::Erlang));
        assert_eq!(Language::from_str_loose("ps1"), Some(Language::PowerShell));
        assert_eq!(Language::from_str_loose("f90"), Some(Language::Fortran));
        assert_eq!(Language::from_str_loose("systemverilog"), Some(Language::Verilog));
        assert_eq!(Language::from_str_loose("sv"), Some(Language::Verilog));
    }

    #[test]
    fn test_language_grammar_name_not_empty() {
        for lang in ALL_LANGUAGES {
            assert!(!lang.grammar_name().is_empty(), "{} grammar name is empty", lang);
        }
    }

    #[test]
    fn test_serde_roundtrip() {
        let node = CodeNode {
            id: "function:src/main.ts:hello:10".to_string(),
            name: "hello".to_string(),
            qualified_name: None,
            kind: NodeKind::Function,
            file_path: "src/main.ts".to_string(),
            start_line: 10,
            end_line: 15,
            start_column: 0,
            end_column: 1,
            language: Language::TypeScript,
            body: Some("function hello() {}".to_string()),
            documentation: None,
            exported: Some(true),
        };

        let json = serde_json::to_string(&node).unwrap();
        let back: CodeNode = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, node.id);
        assert_eq!(back.name, node.name);
        assert_eq!(back.qualified_name, None);
    }
}
