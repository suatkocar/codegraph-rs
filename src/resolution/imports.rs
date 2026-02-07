//! Cross-file import path resolution.
//!
//! Resolves relative import specifiers (e.g., `./utils`, `../helpers/auth`) to
//! actual file paths in the indexed codebase, then creates direct symbol-to-symbol
//! edges that connect the graph across file boundaries.
//!
//! # Strategy
//!
//! 1. For each `Imports` edge with a relative specifier (`./` or `../`):
//!    - Resolve the path relative to the importing file's directory
//!    - Try common extension patterns (.ts, .tsx, .js, .jsx, .py, /index.ts, etc.)
//!    - If the resolved file exists in indexed files, create cross-file edges
//! 2. When imported names are specified (e.g., `import { foo, bar } from './utils'`):
//!    - Create direct `Imports` edges from the importing file to each named symbol
//! 3. When no names are specified (e.g., `import * as utils from './utils'`):
//!    - Create an `Imports` edge from the file to all exported symbols in the target

use std::collections::{HashMap, HashSet};
use std::path::{Component, PathBuf};

use crate::types::{CodeEdge, CodeNode, EdgeKind, UnresolvedRef};

/// Result of import resolution: both successfully resolved edges and
/// references that could not be resolved.
pub struct ImportResolutionResult {
    pub resolved_edges: Vec<CodeEdge>,
    pub unresolved_refs: Vec<UnresolvedRef>,
}

/// Extension patterns to try when resolving import specifiers.
/// Ordered by likelihood for each language ecosystem.
const EXTENSION_PATTERNS: &[&str] = &[
    "",           // exact match (specifier already has extension)
    ".ts",        // TypeScript
    ".tsx",       // TypeScript JSX
    ".js",        // JavaScript
    ".jsx",       // JavaScript JSX
    ".mjs",       // ES Module JS
    ".cjs",       // CommonJS
    "/index.ts",  // TypeScript barrel
    "/index.tsx", // TypeScript JSX barrel
    "/index.js",  // JavaScript barrel
    "/index.jsx", // JavaScript JSX barrel
    ".py",        // Python
    ".rs",        // Rust (mod.rs pattern handled separately)
    ".go",        // Go
    ".java",      // Java
    ".rb",        // Ruby
    ".php",       // PHP
    ".swift",     // Swift
    ".kt",        // Kotlin
    ".kts",       // Kotlin Script
];

/// Resolve all import edges in the graph, creating cross-file symbol links.
///
/// Takes the existing edges (from single-file extraction), the complete set
/// of indexed file paths, and the node index, and returns additional edges
/// that link imports to their actual target symbols.
pub fn resolve_imports(
    edges: &[CodeEdge],
    indexed_files: &HashSet<String>,
    node_index: &HashMap<String, Vec<CodeNode>>,
    nodes_by_file: &HashMap<String, Vec<CodeNode>>,
) -> ImportResolutionResult {
    let mut resolved_edges = Vec::new();
    let mut unresolved_refs = Vec::new();

    for edge in edges {
        if edge.kind != EdgeKind::Imports {
            continue;
        }

        // Only process module:<specifier> targets with relative paths
        let specifier = match edge.target.strip_prefix("module:") {
            Some(s) => s,
            None => continue,
        };

        // Determine if this is a resolvable import
        let importing_file = edge.file_path.as_str();
        let resolved_path;

        if is_relative_import(specifier) {
            // Resolve relative imports (./  ../)
            resolved_path = match resolve_specifier(importing_file, specifier, indexed_files) {
                Some(p) => p,
                None => {
                    unresolved_refs.push(UnresolvedRef {
                        id: 0,
                        source_id: edge.source.clone(),
                        specifier: specifier.to_string(),
                        ref_type: "import".to_string(),
                        file_path: edge.file_path.clone(),
                        line: edge.line,
                    });
                    continue;
                }
            };
        } else if is_path_alias(specifier) {
            // Resolve path aliases (@/  ~/) by mapping to src/ prefix
            let alias_path = resolve_path_alias(specifier);
            resolved_path = match resolve_alias_path(&alias_path, indexed_files) {
                Some(p) => p,
                None => {
                    unresolved_refs.push(UnresolvedRef {
                        id: 0,
                        source_id: edge.source.clone(),
                        specifier: specifier.to_string(),
                        ref_type: "import".to_string(),
                        file_path: edge.file_path.clone(),
                        line: edge.line,
                    });
                    continue;
                }
            };
        } else {
            // Package/absolute imports — skip
            continue;
        };

        // Extract imported names from metadata
        let imported_names: Vec<&str> = edge
            .metadata
            .as_ref()
            .and_then(|m| m.get("names"))
            .map(|names| names.split(',').map(|s| s.trim()).collect())
            .unwrap_or_default();

        let target_nodes = nodes_by_file.get(&resolved_path);

        if imported_names.is_empty() {
            // Wildcard/default import: link to all exported symbols in target file
            if let Some(target_file_nodes) = target_nodes {
                for target_node in target_file_nodes {
                    if target_node.exported == Some(true) {
                        resolved_edges.push(CodeEdge {
                            source: edge.source.clone(),
                            target: target_node.id.clone(),
                            kind: EdgeKind::Imports,
                            file_path: edge.file_path.clone(),
                            line: edge.line,
                            metadata: Some(
                                [("resolved".to_string(), resolved_path.clone())]
                                    .into_iter()
                                    .collect(),
                            ),
                        });
                    }
                }
            }
        } else {
            // Named imports: link to specific symbols
            for name in &imported_names {
                // First try: find by name in the target file
                let target_node =
                    target_nodes.and_then(|nodes| nodes.iter().find(|n| n.name == *name));

                if let Some(target) = target_node {
                    resolved_edges.push(CodeEdge {
                        source: edge.source.clone(),
                        target: target.id.clone(),
                        kind: EdgeKind::Imports,
                        file_path: edge.file_path.clone(),
                        line: edge.line,
                        metadata: Some(
                            [("resolved".to_string(), resolved_path.clone())]
                                .into_iter()
                                .collect(),
                        ),
                    });
                } else {
                    // Second try: look up in global node index
                    if let Some(candidates) = node_index.get(*name) {
                        // Prefer the candidate from the resolved file
                        let best = candidates
                            .iter()
                            .find(|n| n.file_path == resolved_path)
                            .or_else(|| candidates.first());

                        if let Some(target) = best {
                            resolved_edges.push(CodeEdge {
                                source: edge.source.clone(),
                                target: target.id.clone(),
                                kind: EdgeKind::Imports,
                                file_path: edge.file_path.clone(),
                                line: edge.line,
                                metadata: Some(
                                    [("resolved".to_string(), resolved_path.clone())]
                                        .into_iter()
                                        .collect(),
                                ),
                            });
                        }
                    }
                }
            }
        }
    }

    ImportResolutionResult {
        resolved_edges,
        unresolved_refs,
    }
}

/// Check if an import specifier is a relative path.
fn is_relative_import(specifier: &str) -> bool {
    specifier.starts_with("./") || specifier.starts_with("../")
}

/// Check if an import specifier uses a path alias (`@/`, `~/`).
fn is_path_alias(specifier: &str) -> bool {
    specifier.starts_with("@/") || specifier.starts_with("~/")
}

/// Convert a path-aliased specifier to a relative path from `src/`.
///
/// `@/components/Button` -> `src/components/Button`
/// `~/utils/auth` -> `src/utils/auth`
fn resolve_path_alias(specifier: &str) -> String {
    if let Some(rest) = specifier.strip_prefix("@/") {
        format!("src/{}", rest)
    } else if let Some(rest) = specifier.strip_prefix("~/") {
        format!("src/{}", rest)
    } else {
        specifier.to_string()
    }
}

/// Resolve a relative import specifier to an actual indexed file path.
///
/// Given: importing file `src/routes/api.ts` and specifier `../utils/auth`,
/// tries: `src/utils/auth.ts`, `src/utils/auth.tsx`, `src/utils/auth/index.ts`, etc.
fn resolve_specifier(
    importing_file: &str,
    specifier: &str,
    indexed_files: &HashSet<String>,
) -> Option<String> {
    // Get the directory of the importing file
    let importing_dir = match importing_file.rfind('/') {
        Some(pos) => &importing_file[..pos],
        None => "",
    };

    // Join with specifier and normalize
    let joined = if importing_dir.is_empty() {
        specifier.to_string()
    } else {
        format!("{}/{}", importing_dir, specifier)
    };

    let normalized = normalize_path(&joined);

    // Try each extension pattern
    for ext in EXTENSION_PATTERNS {
        let candidate = format!("{}{}", normalized, ext);
        if indexed_files.contains(&candidate) {
            return Some(candidate);
        }
    }

    None
}

/// Resolve a path alias to an actual indexed file path.
///
/// Given: `src/components/Button`, tries extension patterns against
/// the indexed file set (same logic as relative imports, but starting
/// from the already-expanded alias path).
fn resolve_alias_path(expanded_path: &str, indexed_files: &HashSet<String>) -> Option<String> {
    for ext in EXTENSION_PATTERNS {
        let candidate = format!("{}{}", expanded_path, ext);
        if indexed_files.contains(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Resolve barrel exports: when a file re-exports from another file
/// (e.g., `export { foo } from './bar'` or `export * from './sub'`),
/// follow the chain to find the actual symbol definitions.
///
/// Returns additional edges that connect importers to the ultimate
/// symbol definitions through re-export chains.
pub fn resolve_barrel_exports(
    nodes_by_file: &HashMap<String, Vec<CodeNode>>,
    edges: &[CodeEdge],
    indexed_files: &HashSet<String>,
) -> Vec<CodeEdge> {
    let mut barrel_edges = Vec::new();

    // Find re-export edges (source is a file node, target is a module)
    // that also have an exported node with the same name in the source file.
    // This indicates a barrel pattern: file X exports something from file Y.
    for edge in edges {
        if edge.kind != EdgeKind::Imports {
            continue;
        }

        let specifier = match edge.target.strip_prefix("module:") {
            Some(s) => s,
            None => continue,
        };

        if !is_relative_import(specifier) {
            continue;
        }

        // Get the re-export metadata
        let is_reexport = edge
            .metadata
            .as_ref()
            .and_then(|m| m.get("reexport"))
            .is_some();

        if !is_reexport {
            continue;
        }

        // Resolve where the re-export points to
        let resolved_path = match resolve_specifier(&edge.file_path, specifier, indexed_files) {
            Some(p) => p,
            None => continue,
        };

        // Get the names being re-exported
        let reexported_names: Vec<&str> = edge
            .metadata
            .as_ref()
            .and_then(|m| m.get("names"))
            .map(|names| names.split(',').map(|s| s.trim()).collect())
            .unwrap_or_default();

        if let Some(target_nodes) = nodes_by_file.get(&resolved_path) {
            if reexported_names.is_empty() {
                // `export * from './sub'` — re-export all
                for target_node in target_nodes {
                    if target_node.exported == Some(true) {
                        barrel_edges.push(CodeEdge {
                            source: edge.source.clone(),
                            target: target_node.id.clone(),
                            kind: EdgeKind::Imports,
                            file_path: edge.file_path.clone(),
                            line: edge.line,
                            metadata: Some(
                                [
                                    ("resolved".to_string(), resolved_path.clone()),
                                    ("barrel".to_string(), "true".to_string()),
                                ]
                                .into_iter()
                                .collect(),
                            ),
                        });
                    }
                }
            } else {
                // `export { foo, bar } from './sub'` — re-export named
                for name in &reexported_names {
                    if let Some(target) = target_nodes.iter().find(|n| n.name == *name) {
                        barrel_edges.push(CodeEdge {
                            source: edge.source.clone(),
                            target: target.id.clone(),
                            kind: EdgeKind::Imports,
                            file_path: edge.file_path.clone(),
                            line: edge.line,
                            metadata: Some(
                                [
                                    ("resolved".to_string(), resolved_path.clone()),
                                    ("barrel".to_string(), "true".to_string()),
                                ]
                                .into_iter()
                                .collect(),
                            ),
                        });
                    }
                }
            }
        }
    }

    barrel_edges
}

/// Normalize a file path by resolving `.` and `..` components.
///
/// `src/routes/../utils/./auth` → `src/utils/auth`
fn normalize_path(path: &str) -> String {
    let pb = PathBuf::from(path);
    let mut components: Vec<String> = Vec::new();

    for component in pb.components() {
        match component {
            Component::CurDir => {} // skip `.`
            Component::ParentDir => {
                // Go up one level
                components.pop();
            }
            Component::Normal(s) => {
                components.push(s.to_string_lossy().to_string());
            }
            _ => {}
        }
    }

    components.join("/")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Language, NodeKind};

    fn make_node(
        id: &str,
        name: &str,
        file: &str,
        kind: NodeKind,
        exported: Option<bool>,
    ) -> CodeNode {
        CodeNode {
            id: id.to_string(),
            name: name.to_string(),
            qualified_name: None,
            kind,
            file_path: file.to_string(),
            start_line: 1,
            end_line: 10,
            start_column: 0,
            end_column: 1,
            language: Language::TypeScript,
            body: None,
            documentation: None,
            exported,
        }
    }

    fn make_import_edge(
        source_file: &str,
        module_spec: &str,
        line: u32,
        names: Option<&str>,
    ) -> CodeEdge {
        let metadata = names.map(|n| [("names".to_string(), n.to_string())].into_iter().collect());
        CodeEdge {
            source: format!("file:{}", source_file),
            target: format!("module:{}", module_spec),
            kind: EdgeKind::Imports,
            file_path: source_file.to_string(),
            line,
            metadata,
        }
    }

    // -- normalize_path -------------------------------------------------------

    #[test]
    fn normalize_resolves_dotdot() {
        assert_eq!(normalize_path("src/routes/../utils/auth"), "src/utils/auth");
    }

    #[test]
    fn normalize_resolves_dot() {
        assert_eq!(normalize_path("src/./utils/./auth"), "src/utils/auth");
    }

    #[test]
    fn normalize_handles_multiple_dotdot() {
        assert_eq!(normalize_path("src/a/b/../../c/d"), "src/c/d");
    }

    // -- resolve_specifier ----------------------------------------------------

    #[test]
    fn resolves_relative_ts_import() {
        let files: HashSet<String> = ["src/utils.ts", "src/main.ts"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let result = resolve_specifier("src/main.ts", "./utils", &files);
        assert_eq!(result, Some("src/utils.ts".to_string()));
    }

    #[test]
    fn resolves_dotdot_import() {
        let files: HashSet<String> = ["src/utils/auth.ts", "src/routes/api.ts"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let result = resolve_specifier("src/routes/api.ts", "../utils/auth", &files);
        assert_eq!(result, Some("src/utils/auth.ts".to_string()));
    }

    #[test]
    fn resolves_index_barrel() {
        let files: HashSet<String> = ["src/utils/index.ts", "src/main.ts"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let result = resolve_specifier("src/main.ts", "./utils", &files);
        assert_eq!(result, Some("src/utils/index.ts".to_string()));
    }

    #[test]
    fn resolves_exact_extension() {
        let files: HashSet<String> = ["src/config.json", "src/main.ts"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        // If specifier already has extension, exact match first
        let result = resolve_specifier("src/main.ts", "./config.json", &files);
        assert_eq!(result, Some("src/config.json".to_string()));
    }

    #[test]
    fn returns_none_for_missing_file() {
        let files: HashSet<String> = ["src/main.ts"].iter().map(|s| s.to_string()).collect();

        let result = resolve_specifier("src/main.ts", "./nonexistent", &files);
        assert_eq!(result, None);
    }

    #[test]
    fn skips_non_relative_imports() {
        assert!(!is_relative_import("express"));
        assert!(!is_relative_import("@types/node"));
        assert!(is_relative_import("./utils"));
        assert!(is_relative_import("../helpers"));
    }

    // -- resolve_imports (integration) ----------------------------------------

    #[test]
    fn resolves_named_imports_to_symbols() {
        let utils_fn = make_node(
            "fn:src/utils.ts:validate:5",
            "validate",
            "src/utils.ts",
            NodeKind::Function,
            Some(true),
        );
        let utils_class = make_node(
            "class:src/utils.ts:Parser:20",
            "Parser",
            "src/utils.ts",
            NodeKind::Class,
            Some(true),
        );

        let edges = vec![make_import_edge(
            "src/main.ts",
            "./utils",
            1,
            Some("validate,Parser"),
        )];

        let indexed_files: HashSet<String> = ["src/main.ts", "src/utils.ts"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let mut node_index: HashMap<String, Vec<CodeNode>> = HashMap::new();
        node_index
            .entry("validate".to_string())
            .or_default()
            .push(utils_fn.clone());
        node_index
            .entry("Parser".to_string())
            .or_default()
            .push(utils_class.clone());

        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();
        nodes_by_file.insert("src/utils.ts".to_string(), vec![utils_fn, utils_class]);

        let result = resolve_imports(&edges, &indexed_files, &node_index, &nodes_by_file);

        assert_eq!(result.resolved_edges.len(), 2);
        assert!(result
            .resolved_edges
            .iter()
            .any(|e| e.target == "fn:src/utils.ts:validate:5"));
        assert!(result
            .resolved_edges
            .iter()
            .any(|e| e.target == "class:src/utils.ts:Parser:20"));
        // All resolved edges should have metadata with resolved path
        assert!(result.resolved_edges.iter().all(|e| e
            .metadata
            .as_ref()
            .unwrap()
            .contains_key("resolved")));
        // No unresolved refs — both imports resolved
        assert!(result.unresolved_refs.is_empty());
    }

    #[test]
    fn resolves_wildcard_imports_to_exported_symbols() {
        let exported_fn = make_node(
            "fn:src/utils.ts:helper:1",
            "helper",
            "src/utils.ts",
            NodeKind::Function,
            Some(true),
        );
        let private_fn = make_node(
            "fn:src/utils.ts:internal:10",
            "internal",
            "src/utils.ts",
            NodeKind::Function,
            None, // not exported
        );

        let edges = vec![make_import_edge("src/main.ts", "./utils", 1, None)];

        let indexed_files: HashSet<String> = ["src/main.ts", "src/utils.ts"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let node_index: HashMap<String, Vec<CodeNode>> = HashMap::new();

        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();
        nodes_by_file.insert("src/utils.ts".to_string(), vec![exported_fn, private_fn]);

        let result = resolve_imports(&edges, &indexed_files, &node_index, &nodes_by_file);

        // Only the exported function should be linked
        assert_eq!(result.resolved_edges.len(), 1);
        assert_eq!(result.resolved_edges[0].target, "fn:src/utils.ts:helper:1");
    }

    #[test]
    fn skips_package_imports() {
        let edges = vec![make_import_edge(
            "src/main.ts",
            "express",
            1,
            Some("Router"),
        )];

        let indexed_files: HashSet<String> =
            ["src/main.ts"].iter().map(|s| s.to_string()).collect();
        let node_index: HashMap<String, Vec<CodeNode>> = HashMap::new();
        let nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();

        let result = resolve_imports(&edges, &indexed_files, &node_index, &nodes_by_file);
        assert!(result.resolved_edges.is_empty());
        // Package imports are not relative, so they don't generate unresolved refs either
        assert!(result.unresolved_refs.is_empty());
    }

    #[test]
    fn unresolved_relative_import_tracked() {
        // Import from ./missing which doesn't exist in indexed files
        let edges = vec![make_import_edge("src/main.ts", "./missing", 3, Some("Foo"))];

        let indexed_files: HashSet<String> =
            ["src/main.ts"].iter().map(|s| s.to_string()).collect();
        let node_index: HashMap<String, Vec<CodeNode>> = HashMap::new();
        let nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();

        let result = resolve_imports(&edges, &indexed_files, &node_index, &nodes_by_file);
        assert!(result.resolved_edges.is_empty());
        assert_eq!(result.unresolved_refs.len(), 1);
        assert_eq!(result.unresolved_refs[0].specifier, "./missing");
        assert_eq!(result.unresolved_refs[0].file_path, "src/main.ts");
        assert_eq!(result.unresolved_refs[0].ref_type, "import");
        assert_eq!(result.unresolved_refs[0].line, 3);
    }

    // -- path alias resolution ------------------------------------------------

    #[test]
    fn is_path_alias_detection() {
        assert!(is_path_alias("@/components/Button"));
        assert!(is_path_alias("~/utils/auth"));
        assert!(!is_path_alias("./utils"));
        assert!(!is_path_alias("../helpers"));
        assert!(!is_path_alias("express"));
        assert!(!is_path_alias("@types/node"));
    }

    #[test]
    fn resolve_path_alias_at_sign() {
        assert_eq!(
            resolve_path_alias("@/components/Button"),
            "src/components/Button"
        );
        assert_eq!(resolve_path_alias("@/utils/auth"), "src/utils/auth");
    }

    #[test]
    fn resolve_path_alias_tilde() {
        assert_eq!(resolve_path_alias("~/lib/helpers"), "src/lib/helpers");
    }

    #[test]
    fn resolves_at_alias_import() {
        let button = make_node(
            "fn:src/components/Button.tsx:Button:1",
            "Button",
            "src/components/Button.tsx",
            NodeKind::Function,
            Some(true),
        );

        let edges = vec![make_import_edge(
            "src/pages/Home.tsx",
            "@/components/Button",
            2,
            Some("Button"),
        )];

        let indexed_files: HashSet<String> = ["src/pages/Home.tsx", "src/components/Button.tsx"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let mut node_index: HashMap<String, Vec<CodeNode>> = HashMap::new();
        node_index
            .entry("Button".to_string())
            .or_default()
            .push(button.clone());

        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();
        nodes_by_file.insert("src/components/Button.tsx".to_string(), vec![button]);

        let result = resolve_imports(&edges, &indexed_files, &node_index, &nodes_by_file);

        assert_eq!(result.resolved_edges.len(), 1);
        assert_eq!(
            result.resolved_edges[0].target,
            "fn:src/components/Button.tsx:Button:1"
        );
        assert!(result.unresolved_refs.is_empty());
    }

    #[test]
    fn unresolved_alias_import_tracked() {
        let edges = vec![make_import_edge(
            "src/pages/Home.tsx",
            "@/components/Missing",
            5,
            Some("Missing"),
        )];

        let indexed_files: HashSet<String> = ["src/pages/Home.tsx"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let node_index: HashMap<String, Vec<CodeNode>> = HashMap::new();
        let nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();

        let result = resolve_imports(&edges, &indexed_files, &node_index, &nodes_by_file);
        assert!(result.resolved_edges.is_empty());
        assert_eq!(result.unresolved_refs.len(), 1);
        assert_eq!(result.unresolved_refs[0].specifier, "@/components/Missing");
    }

    // -- barrel export resolution ---------------------------------------------

    #[test]
    fn resolve_barrel_wildcard_reexport() {
        let helper = make_node(
            "fn:src/utils/helpers.ts:formatDate:1",
            "formatDate",
            "src/utils/helpers.ts",
            NodeKind::Function,
            Some(true),
        );

        // Barrel: index.ts re-exports everything from helpers
        let reexport_edge = CodeEdge {
            source: "file:src/utils/index.ts".to_string(),
            target: "module:./helpers".to_string(),
            kind: EdgeKind::Imports,
            file_path: "src/utils/index.ts".to_string(),
            line: 1,
            metadata: Some(
                [("reexport".to_string(), "true".to_string())]
                    .into_iter()
                    .collect(),
            ),
        };

        let indexed_files: HashSet<String> = ["src/utils/index.ts", "src/utils/helpers.ts"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();
        nodes_by_file.insert("src/utils/helpers.ts".to_string(), vec![helper]);

        let barrel_edges = resolve_barrel_exports(&nodes_by_file, &[reexport_edge], &indexed_files);

        assert_eq!(barrel_edges.len(), 1);
        assert_eq!(
            barrel_edges[0].target,
            "fn:src/utils/helpers.ts:formatDate:1"
        );
        assert_eq!(
            barrel_edges[0]
                .metadata
                .as_ref()
                .unwrap()
                .get("barrel")
                .unwrap(),
            "true"
        );
    }

    #[test]
    fn resolve_barrel_named_reexport() {
        let foo = make_node(
            "fn:src/lib/impl.ts:foo:1",
            "foo",
            "src/lib/impl.ts",
            NodeKind::Function,
            Some(true),
        );
        let bar = make_node(
            "fn:src/lib/impl.ts:bar:10",
            "bar",
            "src/lib/impl.ts",
            NodeKind::Function,
            Some(true),
        );
        let baz = make_node(
            "fn:src/lib/impl.ts:baz:20",
            "baz",
            "src/lib/impl.ts",
            NodeKind::Function,
            Some(true),
        );

        // Named re-export: only foo and bar
        let reexport_edge = CodeEdge {
            source: "file:src/lib/index.ts".to_string(),
            target: "module:./impl".to_string(),
            kind: EdgeKind::Imports,
            file_path: "src/lib/index.ts".to_string(),
            line: 1,
            metadata: Some(
                [
                    ("reexport".to_string(), "true".to_string()),
                    ("names".to_string(), "foo,bar".to_string()),
                ]
                .into_iter()
                .collect(),
            ),
        };

        let indexed_files: HashSet<String> = ["src/lib/index.ts", "src/lib/impl.ts"]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();
        nodes_by_file.insert("src/lib/impl.ts".to_string(), vec![foo, bar, baz]);

        let barrel_edges = resolve_barrel_exports(&nodes_by_file, &[reexport_edge], &indexed_files);

        // Should only re-export foo and bar, not baz
        assert_eq!(barrel_edges.len(), 2);
        assert!(barrel_edges
            .iter()
            .any(|e| e.target == "fn:src/lib/impl.ts:foo:1"));
        assert!(barrel_edges
            .iter()
            .any(|e| e.target == "fn:src/lib/impl.ts:bar:10"));
        assert!(!barrel_edges
            .iter()
            .any(|e| e.target == "fn:src/lib/impl.ts:baz:20"));
    }
}
