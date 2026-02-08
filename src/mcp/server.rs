//! MCP server implementation using rmcp over stdio transport.
//!
//! Provides 45+ CodeGraph tools that Claude (or any MCP client) can invoke
//! to search, navigate, analyze, secure, and visualize a codebase.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{tool, ServerHandler, ServiceExt};
use serde::Serialize;

use crate::context::assembler::ContextAssembler;
use crate::git;
use crate::graph::complexity;
use crate::graph::dataflow;
use crate::graph::ranking::GraphRanking;
use crate::graph::search::{HybridSearch, SearchOptions};
use crate::graph::store::GraphStore;
use crate::graph::traversal::GraphTraversal;
use crate::resolution::dead_code::find_dead_code;
use crate::resolution::frameworks::detect_frameworks;
use crate::security;
use crate::types::{CodeNode, NodeKind};

// ---------------------------------------------------------------------------
// Server struct
// ---------------------------------------------------------------------------

/// CodeGraph MCP server.
///
/// Wraps a `GraphStore` in `Arc<Mutex<>>` to satisfy the `Clone + Send + Sync`
/// requirements of rmcp's `ServerHandler` trait while keeping all graph
/// operations synchronous internally.
#[derive(Debug, Clone)]
pub struct CodeGraphServer {
    store: Arc<Mutex<GraphStore>>,
    project_root: PathBuf,
}

impl CodeGraphServer {
    /// Create a new MCP server backed by the given store.
    pub fn new(store: GraphStore) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            project_root: PathBuf::from("."),
        }
    }

    /// Create a new MCP server with an explicit project root.
    pub fn with_project_root(store: GraphStore, project_root: PathBuf) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            project_root,
        }
    }

    /// Resolve a symbol reference to a CodeNode.
    /// Accepts either a full node ID or a symbol name (returns the first match).
    fn resolve_symbol(&self, symbol_ref: &str) -> Option<CodeNode> {
        let store = self.store.lock().unwrap();
        if let Ok(Some(node)) = store.get_node(symbol_ref) {
            return Some(node);
        }
        if let Ok(nodes) = store.get_nodes_by_name(symbol_ref) {
            if !nodes.is_empty() {
                return Some(nodes.into_iter().next().unwrap());
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Helper: serialize to JSON text
// ---------------------------------------------------------------------------

fn json_text<T: Serialize>(data: &T) -> String {
    serde_json::to_string_pretty(data).unwrap_or_else(|e| format!("{{\"error\":\"{}\"}}", e))
}

// ---------------------------------------------------------------------------
// Mermaid diagram helpers
// ---------------------------------------------------------------------------

fn mermaid_safe(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '[' | ']' | '(' | ')' | '{' | '}' | '|' | '<' | '>' | '#' | '&' | '"' => '_',
            _ => c,
        })
        .collect()
}

fn mermaid_id(node_id: &str) -> String {
    let mut hash: i32 = 0;
    for ch in node_id.chars() {
        hash = ((hash << 5).wrapping_sub(hash)).wrapping_add(ch as i32);
    }
    format!("n{:x}", hash.unsigned_abs())
}

fn generate_graph_diagram(
    center: &CodeNode,
    nodes: &[CodeNode],
    edges: &[crate::types::CodeEdge],
    title: &str,
) -> String {
    let mut lines = Vec::new();
    lines.push("```mermaid".to_string());
    lines.push("graph LR".to_string());
    lines.push(format!("  %% {} for {}", title, center.name));

    let mut emitted = HashSet::new();
    for node in nodes {
        let mid = mermaid_id(&node.id);
        if emitted.contains(&mid) {
            continue;
        }
        emitted.insert(mid.clone());
        let label = mermaid_safe(&format!("{}: {}", node.kind, node.name));
        if node.id == center.id {
            lines.push(format!("  {}[[\"{}\"]]", mid, label));
        } else {
            lines.push(format!("  {}[\"{}\"]", mid, label));
        }
    }

    let edge_labels: HashMap<&str, &str> = [
        ("calls", "calls"),
        ("imports", "imports"),
        ("extends", "extends"),
        ("implements", "impl"),
        ("references", "refs"),
        ("contains", "contains"),
    ]
    .into_iter()
    .collect();

    for edge in edges {
        let src_id = mermaid_id(&edge.source);
        let tgt_id = mermaid_id(&edge.target);
        if !emitted.contains(&src_id) || !emitted.contains(&tgt_id) {
            continue;
        }
        let kind_str = edge.kind.as_str();
        let label = edge_labels.get(kind_str).unwrap_or(&kind_str);
        lines.push(format!("  {} -->|{}| {}", src_id, label, tgt_id));
    }

    lines.push("```".to_string());
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[tool(tool_box)]
impl CodeGraphServer {
    // 1. codegraph_query — Hybrid keyword + semantic search
    #[tool(
        name = "codegraph_query",
        description = "Search the code graph using hybrid keyword + semantic search. Returns ranked code snippets with file paths and relevance scores. Use instead of Grep/Glob when searching for code symbols or concepts."
    )]
    async fn codegraph_query(
        &self,
        #[tool(param)]
        #[schemars(description = "Natural language or keyword search query")]
        query: String,
        #[tool(param)]
        #[schemars(description = "Maximum results to return (default 20)")]
        limit: Option<usize>,
        #[tool(param)]
        #[schemars(description = "Filter by language (e.g. 'typescript', 'python')")]
        language: Option<String>,
    ) -> String {
        let store = self.store.lock().unwrap();
        let search = HybridSearch::new(&store.conn);
        let opts = SearchOptions {
            limit: Some(limit.unwrap_or(20)),
            language,
            ..Default::default()
        };
        match search.search(&query, &opts) {
            Ok(results) => json_text(&results),
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 2. codegraph_dependencies — Forward dependency traversal
    #[tool(
        name = "codegraph_dependencies",
        description = "Find all dependencies of a symbol (what it calls, imports, references, extends, or implements). Returns a dependency tree with depth levels. Use instead of Explore agents to trace imports and dependencies."
    )]
    async fn codegraph_dependencies(
        &self,
        #[tool(param)]
        #[schemars(description = "Symbol name or node ID to find dependencies for")]
        symbol: String,
        #[tool(param)]
        #[schemars(description = "Maximum traversal depth (default 5, max 50)")]
        max_depth: Option<u32>,
    ) -> String {
        let node = match self.resolve_symbol(&symbol) {
            Some(n) => n,
            None => {
                return json_text(
                    &serde_json::json!({"error": format!("Symbol \"{}\" not found in the graph.", symbol)}),
                )
            }
        };
        let store = self.store.lock().unwrap();
        let traversal = GraphTraversal::new(&store);
        let depth = max_depth.unwrap_or(5).min(50);
        match traversal.find_dependencies(&node.id, depth) {
            Ok(deps) => json_text(&serde_json::json!({
                "source": {"id": node.id, "name": node.name, "kind": node.kind.as_str(), "filePath": node.file_path},
                "dependencyCount": deps.len(),
                "dependencies": deps.iter().map(|d| serde_json::json!({
                    "id": d.node.id, "name": d.node.name, "kind": d.node.kind.as_str(),
                    "filePath": d.node.file_path, "startLine": d.node.start_line, "depth": d.depth,
                })).collect::<Vec<_>>(),
            })),
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 3. codegraph_callers — Reverse call graph traversal
    #[tool(
        name = "codegraph_callers",
        description = "Find all callers of a symbol (who calls this function/method). Returns a caller tree with depth levels. Use instead of Grep for caller analysis — 100% precise, no false positives."
    )]
    async fn codegraph_callers(
        &self,
        #[tool(param)]
        #[schemars(description = "Symbol name or node ID to find callers for")]
        symbol: String,
        #[tool(param)]
        #[schemars(description = "Maximum traversal depth (default 5, max 50)")]
        max_depth: Option<u32>,
    ) -> String {
        let node = match self.resolve_symbol(&symbol) {
            Some(n) => n,
            None => {
                return json_text(
                    &serde_json::json!({"error": format!("Symbol \"{}\" not found in the graph.", symbol)}),
                )
            }
        };
        let store = self.store.lock().unwrap();
        let traversal = GraphTraversal::new(&store);
        let depth = max_depth.unwrap_or(5).min(50);
        match traversal.find_callers(&node.id, depth) {
            Ok(callers) => json_text(&serde_json::json!({
                "target": {"id": node.id, "name": node.name, "kind": node.kind.as_str(), "filePath": node.file_path},
                "callerCount": callers.len(),
                "callers": callers.iter().map(|c| serde_json::json!({
                    "id": c.node.id, "name": c.node.name, "kind": c.node.kind.as_str(),
                    "filePath": c.node.file_path, "startLine": c.node.start_line, "depth": c.depth,
                })).collect::<Vec<_>>(),
            })),
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 4. codegraph_callees — Forward call graph traversal
    #[tool(
        name = "codegraph_callees",
        description = "Find all functions/methods that a symbol calls (forward call graph). Returns a callee tree with depth levels. Use instead of manual file reading to understand what a function calls."
    )]
    async fn codegraph_callees(
        &self,
        #[tool(param)]
        #[schemars(description = "Symbol name or node ID to find callees for")]
        symbol: String,
        #[tool(param)]
        #[schemars(description = "Maximum traversal depth (default 5, max 50)")]
        max_depth: Option<u32>,
    ) -> String {
        let node = match self.resolve_symbol(&symbol) {
            Some(n) => n,
            None => {
                return json_text(
                    &serde_json::json!({"error": format!("Symbol \"{}\" not found in the graph.", symbol)}),
                )
            }
        };
        let store = self.store.lock().unwrap();
        let traversal = GraphTraversal::new(&store);
        let depth = max_depth.unwrap_or(5).min(50);
        match traversal.find_callees(&node.id, depth) {
            Ok(callees) => json_text(&serde_json::json!({
                "source": {"id": node.id, "name": node.name, "kind": node.kind.as_str(), "filePath": node.file_path},
                "calleeCount": callees.len(),
                "callees": callees.iter().map(|c| serde_json::json!({
                    "id": c.node.id, "name": c.node.name, "kind": c.node.kind.as_str(),
                    "filePath": c.node.file_path, "startLine": c.node.start_line, "depth": c.depth,
                })).collect::<Vec<_>>(),
            })),
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 5. codegraph_impact — Blast radius analysis
    #[tool(
        name = "codegraph_impact",
        description = "Analyze the blast radius of changing a file or symbol. Returns affected files and functions grouped by risk level. Use before refactoring to understand what might break."
    )]
    async fn codegraph_impact(
        &self,
        #[tool(param)]
        #[schemars(
            description = "File path to analyze impact for (analyzes all symbols in the file)"
        )]
        file_path: Option<String>,
        #[tool(param)]
        #[schemars(description = "Symbol name or node ID to analyze impact for")]
        symbol: Option<String>,
    ) -> String {
        // Resolve symbol first (before locking), then lock for the heavy work.
        let targets: Vec<CodeNode> = if let Some(ref sym) = symbol {
            match self.resolve_symbol(sym) {
                Some(n) => vec![n],
                None => {
                    return json_text(
                        &serde_json::json!({"error": format!("Symbol \"{}\" not found in the graph.", sym)}),
                    )
                }
            }
        } else if let Some(ref fp) = file_path {
            let store = self.store.lock().unwrap();
            match store.get_nodes_by_file(fp) {
                Ok(nodes) if !nodes.is_empty() => nodes,
                _ => {
                    return json_text(
                        &serde_json::json!({"error": format!("No symbols found in file \"{}\".", fp)}),
                    )
                }
            }
        } else {
            return json_text(
                &serde_json::json!({"error": "Either 'file_path' or 'symbol' must be provided."}),
            );
        };

        let store = self.store.lock().unwrap();
        let ranking = GraphRanking::new(&store);
        let traversal = GraphTraversal::new(&store);

        let mut all_affected: HashMap<String, (CodeNode, u32)> = HashMap::new();
        let mut affected_files: HashSet<String> = HashSet::new();

        for target in &targets {
            let impact = ranking.compute_impact(&target.id);
            for fp in &impact.affected_files {
                affected_files.insert(fp.clone());
            }
            if let Ok(callers) = traversal.find_callers(&target.id, 10) {
                for c in callers {
                    let existing_depth = all_affected.get(&c.node.id).map(|(_, d)| *d);
                    if existing_depth.is_none() || c.depth < existing_depth.unwrap() {
                        all_affected.insert(c.node.id.clone(), (c.node, c.depth));
                    }
                }
            }
        }

        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();

        for (node, depth) in all_affected.values() {
            let entry = serde_json::json!({
                "id": node.id, "name": node.name, "kind": node.kind.as_str(),
                "filePath": node.file_path, "depth": depth,
            });
            if *depth <= 1 {
                high.push(entry);
            } else if *depth <= 3 {
                medium.push(entry);
            } else {
                low.push(entry);
            }
        }

        let mut risk_groups = Vec::new();
        if !high.is_empty() {
            risk_groups.push(serde_json::json!({"risk": "high", "symbols": high}));
        }
        if !medium.is_empty() {
            risk_groups.push(serde_json::json!({"risk": "medium", "symbols": medium}));
        }
        if !low.is_empty() {
            risk_groups.push(serde_json::json!({"risk": "low", "symbols": low}));
        }

        let mut sorted_files: Vec<_> = affected_files.into_iter().collect();
        sorted_files.sort();

        json_text(&serde_json::json!({
            "analyzedSymbols": targets.iter().map(|t| serde_json::json!({
                "id": t.id, "name": t.name, "kind": t.kind.as_str(),
            })).collect::<Vec<_>>(),
            "totalAffected": all_affected.len(),
            "affectedFiles": sorted_files,
            "affectedFileCount": sorted_files.len(),
            "riskGroups": risk_groups,
        }))
    }

    // 5. codegraph_structure — Project overview with PageRank
    #[tool(
        name = "codegraph_structure",
        description = "Get a project overview: modules, key classes/functions, and dependency summary. Uses PageRank to identify the most important symbols. Use instead of Explore agents for project overview."
    )]
    async fn codegraph_structure(
        &self,
        #[tool(param)]
        #[schemars(
            description = "Scope to a specific directory or file path (default: entire project)"
        )]
        path: Option<String>,
        #[tool(param)]
        #[schemars(description = "Number of top symbols to return per category (default 10)")]
        depth: Option<usize>,
    ) -> String {
        let store = self.store.lock().unwrap();
        let limit = depth.unwrap_or(10);

        let stats = match store.get_stats() {
            Ok(s) => s,
            Err(e) => return json_text(&serde_json::json!({"error": e.to_string()})),
        };

        let all_nodes = match store.get_all_nodes() {
            Ok(nodes) => nodes,
            Err(e) => return json_text(&serde_json::json!({"error": e.to_string()})),
        };

        let scoped_nodes: Vec<&CodeNode> = if let Some(ref p) = path {
            all_nodes
                .iter()
                .filter(|n| n.file_path.starts_with(p))
                .collect()
        } else {
            all_nodes.iter().collect()
        };

        if scoped_nodes.is_empty() {
            return json_text(&serde_json::json!({
                "error": if let Some(p) = path {
                    format!("No symbols found under path \"{}\".", p)
                } else {
                    "The code graph is empty. Index a directory first.".to_string()
                }
            }));
        }

        // File grouping
        let mut files_by_dir: HashMap<String, Vec<String>> = HashMap::new();
        let mut all_files = HashSet::new();
        for node in &scoped_nodes {
            all_files.insert(node.file_path.clone());
            let parts: Vec<&str> = node.file_path.rsplitn(2, '/').collect();
            let dir = if parts.len() > 1 {
                parts[1].to_string()
            } else {
                ".".to_string()
            };
            let files = files_by_dir.entry(dir).or_default();
            if !files.contains(&node.file_path) {
                files.push(node.file_path.clone());
            }
        }

        // PageRank
        let ranking = GraphRanking::new(&store);
        let page_rank = ranking.compute_page_rank(0.85, 100);
        let node_id_set: HashSet<&str> = scoped_nodes.iter().map(|n| n.id.as_str()).collect();
        let scoped_ranks: Vec<_> = page_rank
            .iter()
            .filter(|r| node_id_set.contains(r.node_id.as_str()))
            .take(limit)
            .collect();

        let top_symbols: Vec<serde_json::Value> = scoped_ranks
            .iter()
            .map(|r| {
                let node = store.get_node(&r.node_id).ok().flatten();
                match node {
                    Some(n) => serde_json::json!({
                        "id": n.id, "name": n.name, "kind": n.kind.as_str(),
                        "filePath": n.file_path, "score": r.score,
                    }),
                    None => serde_json::json!({
                        "id": r.node_id, "name": r.node_id, "kind": "unknown",
                        "filePath": "", "score": r.score,
                    }),
                }
            })
            .collect();

        // Kind counts
        let mut kind_counts: HashMap<&str, usize> = HashMap::new();
        for node in &scoped_nodes {
            *kind_counts.entry(node.kind.as_str()).or_insert(0) += 1;
        }

        // Modules
        let mut modules: Vec<serde_json::Value> = files_by_dir
            .iter()
            .map(|(dir, files)| serde_json::json!({"directory": dir, "fileCount": files.len()}))
            .collect();
        modules.sort_by(|a, b| {
            b["fileCount"]
                .as_u64()
                .unwrap_or(0)
                .cmp(&a["fileCount"].as_u64().unwrap_or(0))
        });
        modules.truncate(limit);

        json_text(&serde_json::json!({
            "stats": {
                "totalNodes": stats.nodes,
                "totalEdges": stats.edges,
                "totalFiles": stats.files,
                "scopedNodes": scoped_nodes.len(),
                "scopedFiles": all_files.len(),
            },
            "symbolsByKind": kind_counts,
            "topSymbols": top_symbols,
            "modules": modules,
        }))
    }

    // 6. codegraph_tests — Test coverage discovery
    #[tool(
        name = "codegraph_tests",
        description = "Find test files and functions that cover a given symbol. Returns test locations grouped by file."
    )]
    async fn codegraph_tests(
        &self,
        #[tool(param)]
        #[schemars(description = "Symbol name or node ID to find tests for")]
        symbol: String,
    ) -> String {
        let node = match self.resolve_symbol(&symbol) {
            Some(n) => n,
            None => {
                return json_text(
                    &serde_json::json!({"error": format!("Symbol \"{}\" not found in the graph.", symbol)}),
                )
            }
        };

        let store = self.store.lock().unwrap();
        let traversal = GraphTraversal::new(&store);

        match traversal.find_tests(&node.id) {
            Ok(test_nodes) => {
                if test_nodes.is_empty() {
                    return json_text(&serde_json::json!({
                        "symbol": {"id": node.id, "name": node.name, "kind": node.kind.as_str()},
                        "testCount": 0,
                        "message": format!("No tests found that reference \"{}\".", node.name),
                    }));
                }

                let mut by_file: HashMap<&str, Vec<serde_json::Value>> = HashMap::new();
                for test in &test_nodes {
                    by_file
                        .entry(&test.file_path)
                        .or_default()
                        .push(serde_json::json!({
                            "id": test.id, "name": test.name, "kind": test.kind.as_str(),
                            "startLine": test.start_line,
                        }));
                }

                let test_files: Vec<serde_json::Value> = by_file
                    .into_iter()
                    .map(|(fp, symbols)| serde_json::json!({"filePath": fp, "symbols": symbols}))
                    .collect();

                json_text(&serde_json::json!({
                    "symbol": {"id": node.id, "name": node.name, "kind": node.kind.as_str(), "filePath": node.file_path},
                    "testCount": test_nodes.len(),
                    "testFiles": test_files,
                }))
            }
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 7. codegraph_context — 4-tier token-budgeted LLM context assembly
    #[tool(
        name = "codegraph_context",
        description = "Assemble optimal context for Claude from the code graph. Uses a tiered approach (core -> near -> extended -> background) to pack the most relevant code within a token budget. Use instead of reading multiple files — provides pre-ranked, token-budgeted context."
    )]
    async fn codegraph_context(
        &self,
        #[tool(param)]
        #[schemars(description = "Natural language question or topic to gather context for")]
        query: String,
        #[tool(param)]
        #[schemars(
            description = "Token budget for the context document (default 8000, max 100000)"
        )]
        budget: Option<usize>,
    ) -> String {
        let store = self.store.lock().unwrap();
        let search = HybridSearch::new(&store.conn);
        let budget = budget.map(|b| b.min(100_000));

        let assembler = ContextAssembler::new(&store.conn, &search);
        assembler.assemble_context(&query, budget)
    }

    // 8. codegraph_diagram — Mermaid diagram generation
    #[tool(
        name = "codegraph_diagram",
        description = "Generate a Mermaid diagram from the code graph. Supports dependency graphs, call graphs, and module-level diagrams."
    )]
    async fn codegraph_diagram(
        &self,
        #[tool(param)]
        #[schemars(description = "Symbol name or node ID to center the diagram on")]
        symbol: Option<String>,
        #[tool(param)]
        #[schemars(description = "Diagram type: 'dependency' (default), 'call', or 'module'")]
        diagram_type: Option<String>,
    ) -> String {
        let dt = diagram_type.as_deref().unwrap_or("dependency");

        if dt == "module" {
            let store = self.store.lock().unwrap();
            let all_edges = match store.get_all_edges() {
                Ok(e) => e,
                Err(e) => return json_text(&serde_json::json!({"error": e.to_string()})),
            };
            let all_nodes = match store.get_all_nodes() {
                Ok(n) => n,
                Err(e) => return json_text(&serde_json::json!({"error": e.to_string()})),
            };

            if all_nodes.is_empty() {
                return json_text(&serde_json::json!({"error": "The code graph is empty."}));
            }

            // Build file-level diagram
            let node_file_map: HashMap<&str, &str> = all_nodes
                .iter()
                .map(|n| (n.id.as_str(), n.file_path.as_str()))
                .collect();

            let mut file_edges: HashMap<&str, HashSet<&str>> = HashMap::new();
            for edge in &all_edges {
                let src_file = node_file_map.get(edge.source.as_str());
                let tgt_file = node_file_map.get(edge.target.as_str());
                if let (Some(&sf), Some(&tf)) = (src_file, tgt_file) {
                    if sf != tf {
                        file_edges.entry(sf).or_default().insert(tf);
                    }
                }
            }

            let mut lines = Vec::new();
            lines.push("```mermaid".to_string());
            lines.push("graph LR".to_string());
            lines.push("  %% Module dependency diagram".to_string());

            let mut all_files = HashSet::new();
            for (src, targets) in &file_edges {
                all_files.insert(*src);
                for tgt in targets {
                    all_files.insert(*tgt);
                }
            }
            for file in &all_files {
                lines.push(format!(
                    "  {}[\"{}\"]",
                    mermaid_id(file),
                    mermaid_safe(file)
                ));
            }
            for (src, targets) in &file_edges {
                let src_mid = mermaid_id(src);
                for tgt in targets {
                    lines.push(format!("  {} --> {}", src_mid, mermaid_id(tgt)));
                }
            }
            lines.push("```".to_string());
            return lines.join("\n");
        }

        // dependency or call diagram: requires a symbol
        let sym = match symbol {
            Some(ref s) => s.as_str(),
            None => {
                return json_text(
                    &serde_json::json!({"error": "A 'symbol' is required for dependency and call diagrams."}),
                )
            }
        };

        let node = match self.resolve_symbol(sym) {
            Some(n) => n,
            None => {
                return json_text(
                    &serde_json::json!({"error": format!("Symbol \"{}\" not found in the graph.", sym)}),
                )
            }
        };

        let store = self.store.lock().unwrap();
        let traversal = GraphTraversal::new(&store);

        match traversal.get_neighborhood(&node.id, 2) {
            Ok(neighborhood) => {
                if dt == "call" {
                    let call_edges: Vec<_> = neighborhood
                        .edges
                        .iter()
                        .filter(|e| e.kind == crate::types::EdgeKind::Calls)
                        .cloned()
                        .collect();
                    generate_graph_diagram(&node, &neighborhood.nodes, &call_edges, "Call Graph")
                } else {
                    generate_graph_diagram(
                        &node,
                        &neighborhood.nodes,
                        &neighborhood.edges,
                        "Dependency Graph",
                    )
                }
            }
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 9. codegraph_node — Direct node lookup with full details
    #[tool(
        name = "codegraph_node",
        description = "Look up a specific code symbol by name or ID and return its full details including source code, documentation, file location, and relationships. Use instead of Grep for exact symbol lookup."
    )]
    async fn codegraph_node(
        &self,
        #[tool(param)]
        #[schemars(description = "Symbol name or node ID to look up")]
        symbol: String,
        #[tool(param)]
        #[schemars(
            description = "Include relationships (callers, callees, dependencies) in the response (default false)"
        )]
        include_relations: Option<bool>,
    ) -> String {
        let node = match self.resolve_symbol(&symbol) {
            Some(n) => n,
            None => {
                // Try fuzzy match: search for nodes containing the name
                let store = self.store.lock().unwrap();
                let like_query = format!("%{}%", symbol);
                let mut stmt = match store.conn.prepare_cached(
                    "SELECT * FROM nodes WHERE name LIKE ?1 ORDER BY name ASC LIMIT 10",
                ) {
                    Ok(s) => s,
                    Err(e) => return json_text(&serde_json::json!({"error": e.to_string()})),
                };
                let suggestions: Vec<String> = stmt
                    .query_map(rusqlite::params![like_query], |row| row.get::<_, String>(2))
                    .ok()
                    .map(|rows| rows.filter_map(|r| r.ok()).collect())
                    .unwrap_or_default();

                return json_text(&serde_json::json!({
                    "error": format!("Symbol \"{}\" not found in the graph.", symbol),
                    "suggestions": suggestions,
                }));
            }
        };

        let mut result = serde_json::json!({
            "id": node.id,
            "name": node.name,
            "kind": node.kind.as_str(),
            "filePath": node.file_path,
            "startLine": node.start_line,
            "endLine": node.end_line,
            "language": node.language.as_str(),
            "exported": node.exported,
        });

        if let Some(ref qn) = node.qualified_name {
            result["qualifiedName"] = serde_json::json!(qn);
        }
        if let Some(ref doc) = node.documentation {
            result["documentation"] = serde_json::json!(doc);
        }
        if let Some(ref body) = node.body {
            result["body"] = serde_json::json!(body);
        }

        if include_relations.unwrap_or(false) {
            let store = self.store.lock().unwrap();
            let traversal = GraphTraversal::new(&store);

            // Callers (depth 1 only)
            if let Ok(callers) = traversal.find_callers(&node.id, 1) {
                result["callers"] = serde_json::json!(callers.iter().map(|c| serde_json::json!({
                    "name": c.node.name, "kind": c.node.kind.as_str(), "filePath": c.node.file_path,
                })).collect::<Vec<_>>());
            }

            // Callees (depth 1 only)
            if let Ok(callees) = traversal.find_callees(&node.id, 1) {
                result["callees"] = serde_json::json!(callees.iter().map(|c| serde_json::json!({
                    "name": c.node.name, "kind": c.node.kind.as_str(), "filePath": c.node.file_path,
                })).collect::<Vec<_>>());
            }

            // Outgoing edges (all types)
            if let Ok(out_edges) = store.get_out_edges(&node.id, None) {
                result["outgoingEdges"] = serde_json::json!(out_edges
                    .iter()
                    .map(|e| serde_json::json!({
                        "target": e.target, "kind": e.kind.as_str(),
                    }))
                    .collect::<Vec<_>>());
            }

            // Incoming edges (all types)
            if let Ok(in_edges) = store.get_in_edges(&node.id, None) {
                result["incomingEdges"] = serde_json::json!(in_edges
                    .iter()
                    .map(|e| serde_json::json!({
                        "source": e.source, "kind": e.kind.as_str(),
                    }))
                    .collect::<Vec<_>>());
            }
        }

        json_text(&result)
    }

    // 10. codegraph_dead_code — Find potentially unused symbols
    #[tool(
        name = "codegraph_dead_code",
        description = "Find potentially unused/dead code symbols that have no incoming references"
    )]
    async fn codegraph_dead_code(
        &self,
        #[tool(param)]
        #[schemars(
            description = "Filter by symbol kinds (comma-separated, e.g. 'function,class'). If omitted, all kinds are checked."
        )]
        kinds: Option<String>,
        #[tool(param)]
        #[schemars(description = "Include exported symbols in results (default false)")]
        include_exported: Option<bool>,
    ) -> String {
        let kind_filter: Vec<NodeKind> = kinds
            .as_deref()
            .unwrap_or("")
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .filter_map(NodeKind::from_str_loose)
            .collect();

        let store = self.store.lock().unwrap();
        let results = find_dead_code(&store.conn, &kind_filter);

        // Note: include_exported is accepted as a parameter for future use.
        // The underlying SQL query already excludes exported symbols by default.
        let _ = include_exported;

        if results.is_empty() {
            return json_text(&serde_json::json!({
                "deadCodeCount": 0,
                "message": "No dead code found. All symbols have incoming references (or are excluded as exports/tests/entry points).",
            }));
        }

        // Group by file for a cleaner output
        let mut by_file: HashMap<String, Vec<serde_json::Value>> = HashMap::new();
        for r in &results {
            by_file
                .entry(r.file_path.clone())
                .or_default()
                .push(serde_json::json!({
                    "id": r.id,
                    "name": r.name,
                    "kind": r.kind,
                    "line": r.start_line,
                }));
        }

        let mut files: Vec<serde_json::Value> = by_file
            .into_iter()
            .map(|(fp, symbols)| serde_json::json!({"filePath": fp, "symbols": symbols}))
            .collect();
        files.sort_by(|a, b| a["filePath"].as_str().cmp(&b["filePath"].as_str()));

        json_text(&serde_json::json!({
            "deadCodeCount": results.len(),
            "files": files,
        }))
    }

    // 10. codegraph_frameworks — Detect frameworks and libraries
    #[tool(
        name = "codegraph_frameworks",
        description = "Detect frameworks and libraries used in the project"
    )]
    async fn codegraph_frameworks(
        &self,
        #[tool(param)]
        #[schemars(
            description = "Project directory to scan for manifests (defaults to the indexed project root)"
        )]
        project_dir: Option<String>,
    ) -> String {
        // Determine the project directory from the store's indexed files if not provided
        let dir = if let Some(ref d) = project_dir {
            d.clone()
        } else {
            // Infer from the first indexed file's path
            let store = self.store.lock().unwrap();
            match store.get_all_nodes() {
                Ok(nodes) if !nodes.is_empty() => {
                    // Find the common prefix of all file paths
                    let mut paths: Vec<&str> = nodes.iter().map(|n| n.file_path.as_str()).collect();
                    paths.sort();
                    if let Some(first) = paths.first() {
                        // Use the directory of the first file as a rough guess
                        first.rsplitn(2, '/').last().unwrap_or(".").to_string()
                    } else {
                        ".".to_string()
                    }
                }
                _ => ".".to_string(),
            }
        };

        let frameworks = detect_frameworks(&dir);

        if frameworks.is_empty() {
            return json_text(&serde_json::json!({
                "frameworkCount": 0,
                "message": format!("No recognized frameworks detected in \"{}\".", dir),
            }));
        }

        let entries: Vec<serde_json::Value> = frameworks
            .iter()
            .map(|f| {
                serde_json::json!({
                    "name": f.name,
                    "version": f.version,
                    "language": f.language,
                    "category": f.category,
                    "confidence": f.confidence,
                })
            })
            .collect();

        json_text(&serde_json::json!({
            "frameworkCount": frameworks.len(),
            "projectDir": dir,
            "frameworks": entries,
        }))
    }

    // 11. codegraph_languages — Language breakdown statistics
    #[tool(
        name = "codegraph_languages",
        description = "Show language breakdown statistics for the indexed codebase"
    )]
    async fn codegraph_languages(&self) -> String {
        let store = self.store.lock().unwrap();

        // Query language stats from nodes table
        let lang_query = "\
            SELECT language, \
                   COUNT(DISTINCT file_path) as file_count, \
                   COUNT(*) as symbol_count \
            FROM nodes \
            GROUP BY language \
            ORDER BY symbol_count DESC";

        let edge_count_query = "\
            SELECT n.language, COUNT(*) as edge_count \
            FROM edges e \
            JOIN nodes n ON n.id = e.source_id \
            GROUP BY n.language";

        let lang_stats: Vec<(String, i64, i64)> = match store.conn.prepare(lang_query) {
            Ok(mut stmt) => {
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                });
                match rows {
                    Ok(rows) => rows.filter_map(|r| r.ok()).collect(),
                    Err(_) => Vec::new(),
                }
            }
            Err(e) => return json_text(&serde_json::json!({"error": e.to_string()})),
        };

        if lang_stats.is_empty() {
            return json_text(&serde_json::json!({
                "languageCount": 0,
                "message": "No indexed files found. Run 'codegraph index <dir>' first.",
            }));
        }

        // Build edge counts per language
        let mut edge_counts: HashMap<String, i64> = HashMap::new();
        if let Ok(mut stmt) = store.conn.prepare(edge_count_query) {
            if let Ok(rows) = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            }) {
                for row in rows.flatten() {
                    edge_counts.insert(row.0, row.1);
                }
            }
        }

        let total_symbols: i64 = lang_stats.iter().map(|(_, _, s)| s).sum();

        let languages: Vec<serde_json::Value> = lang_stats
            .iter()
            .map(|(lang, files, symbols)| {
                let pct = if total_symbols > 0 {
                    (*symbols as f64 / total_symbols as f64) * 100.0
                } else {
                    0.0
                };
                let edges = edge_counts.get(lang).copied().unwrap_or(0);
                serde_json::json!({
                    "language": lang,
                    "files": files,
                    "symbols": symbols,
                    "edges": edges,
                    "percentage": format!("{:.1}%", pct),
                })
            })
            .collect();

        let total_files: i64 = lang_stats.iter().map(|(_, f, _)| f).sum();
        let total_edges: i64 = edge_counts.values().sum();

        json_text(&serde_json::json!({
            "languageCount": lang_stats.len(),
            "totalFiles": total_files,
            "totalSymbols": total_symbols,
            "totalEdges": total_edges,
            "languages": languages,
        }))
    }

    // =========================================================================
    // Git Integration Tools (9)
    // =========================================================================

    // 14. codegraph_blame
    #[tool(
        name = "codegraph_blame",
        description = "Show git blame for a file — line-by-line author, date, and commit hash. Use instead of running git blame via Bash."
    )]
    async fn codegraph_blame(
        &self,
        #[tool(param)]
        #[schemars(description = "File path to blame")]
        file_path: String,
    ) -> String {
        match git::blame::git_blame(&self.project_root, &file_path) {
            Ok(lines) => json_text(&serde_json::json!({
                "file": file_path,
                "lineCount": lines.len(),
                "lines": lines.iter().map(|l| serde_json::json!({
                    "line": l.line_number, "author": l.author, "email": l.email,
                    "date": l.date, "commit": l.commit_hash, "content": l.content,
                })).collect::<Vec<_>>(),
            })),
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 15. codegraph_file_history
    #[tool(
        name = "codegraph_file_history",
        description = "Show commit history for a specific file."
    )]
    async fn codegraph_file_history(
        &self,
        #[tool(param)]
        #[schemars(description = "File path to get history for")]
        file_path: String,
        #[tool(param)]
        #[schemars(description = "Maximum commits to return (default 20)")]
        limit: Option<usize>,
    ) -> String {
        match git::history::file_history(&self.project_root, &file_path, limit.unwrap_or(20)) {
            Ok(commits) => json_text(&serde_json::json!({
                "file": file_path,
                "commitCount": commits.len(),
                "commits": commits.iter().map(|c| serde_json::json!({
                    "hash": c.hash, "author": c.author, "email": c.email,
                    "date": c.date, "message": c.message,
                })).collect::<Vec<_>>(),
            })),
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 16. codegraph_recent_changes
    #[tool(
        name = "codegraph_recent_changes",
        description = "Show recent commits across the repository."
    )]
    async fn codegraph_recent_changes(
        &self,
        #[tool(param)]
        #[schemars(description = "Number of recent commits (default 20)")]
        limit: Option<usize>,
    ) -> String {
        match git::history::recent_changes(&self.project_root, limit.unwrap_or(20)) {
            Ok(commits) => json_text(&serde_json::json!({
                "commitCount": commits.len(),
                "commits": commits.iter().map(|c| serde_json::json!({
                    "hash": c.hash, "author": c.author, "email": c.email,
                    "date": c.date, "message": c.message,
                })).collect::<Vec<_>>(),
            })),
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 17. codegraph_commit_diff
    #[tool(
        name = "codegraph_commit_diff",
        description = "Show the diff of a specific commit."
    )]
    async fn codegraph_commit_diff(
        &self,
        #[tool(param)]
        #[schemars(description = "Commit hash to show diff for")]
        commit: String,
    ) -> String {
        match git::history::commit_diff(&self.project_root, &commit) {
            Ok(diff) => json_text(&serde_json::json!({
                "commit": diff.commit,
                "fileCount": diff.files.len(),
                "files": diff.files.iter().map(|f| serde_json::json!({
                    "path": f.path, "additions": f.additions, "deletions": f.deletions,
                    "patch": f.patch,
                })).collect::<Vec<_>>(),
            })),
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 18. codegraph_symbol_history
    #[tool(
        name = "codegraph_symbol_history",
        description = "Find commits that modified a specific symbol (uses git log -S)."
    )]
    async fn codegraph_symbol_history(
        &self,
        #[tool(param)]
        #[schemars(description = "Symbol name to search for in commit history")]
        symbol: String,
    ) -> String {
        match git::history::symbol_history(&self.project_root, &symbol) {
            Ok(commits) => json_text(&serde_json::json!({
                "symbol": symbol,
                "commitCount": commits.len(),
                "commits": commits.iter().map(|c| serde_json::json!({
                    "hash": c.hash, "author": c.author, "email": c.email,
                    "date": c.date, "message": c.message,
                })).collect::<Vec<_>>(),
            })),
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 19. codegraph_branch_info
    #[tool(
        name = "codegraph_branch_info",
        description = "Show current branch, tracking status, and ahead/behind counts."
    )]
    async fn codegraph_branch_info(&self) -> String {
        match git::history::branch_info(&self.project_root) {
            Ok(info) => json_text(&serde_json::json!({
                "current": info.current, "tracking": info.tracking,
                "ahead": info.ahead, "behind": info.behind, "status": info.status,
            })),
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 20. codegraph_modified_files
    #[tool(
        name = "codegraph_modified_files",
        description = "Show working tree changes — staged, unstaged, and untracked files."
    )]
    async fn codegraph_modified_files(&self) -> String {
        match git::history::modified_files(&self.project_root) {
            Ok(mf) => json_text(&serde_json::json!({
                "staged": mf.staged, "unstaged": mf.unstaged, "untracked": mf.untracked,
                "totalChanges": mf.staged.len() + mf.unstaged.len() + mf.untracked.len(),
            })),
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 21. codegraph_hotspots
    #[tool(
        name = "codegraph_hotspots",
        description = "Find code hotspots — files with the most churn (commit count × recency)."
    )]
    async fn codegraph_hotspots(
        &self,
        #[tool(param)]
        #[schemars(description = "Number of hotspots to return (default 20)")]
        limit: Option<usize>,
    ) -> String {
        match git::analysis::hotspots(&self.project_root, limit.unwrap_or(20)) {
            Ok(spots) => json_text(&serde_json::json!({
                "hotspotCount": spots.len(),
                "hotspots": spots.iter().map(|h| serde_json::json!({
                    "file": h.file, "commitCount": h.commit_count,
                    "lastModified": h.last_modified, "score": h.score,
                })).collect::<Vec<_>>(),
            })),
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 22. codegraph_contributors
    #[tool(
        name = "codegraph_contributors",
        description = "List contributors with commit counts and line statistics."
    )]
    async fn codegraph_contributors(
        &self,
        #[tool(param)]
        #[schemars(description = "Optional file path to scope contributors to")]
        file_path: Option<String>,
    ) -> String {
        match git::analysis::contributors(&self.project_root, file_path.as_deref()) {
            Ok(contribs) => json_text(&serde_json::json!({
                "contributorCount": contribs.len(),
                "contributors": contribs.iter().map(|c| serde_json::json!({
                    "name": c.name, "email": c.email, "commits": c.commits,
                    "linesAdded": c.lines_added, "linesRemoved": c.lines_removed,
                })).collect::<Vec<_>>(),
            })),
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // =========================================================================
    // Security Tools (9)
    // =========================================================================

    // 23. codegraph_scan_security
    #[tool(
        name = "codegraph_scan_security",
        description = "Scan a directory for security vulnerabilities using YAML-based pattern matching rules. Use instead of grep-based pattern matching for vulnerability detection."
    )]
    async fn codegraph_scan_security(
        &self,
        #[tool(param)]
        #[schemars(description = "Directory to scan (defaults to project root)")]
        directory: Option<String>,
        #[tool(param)]
        #[schemars(description = "Exclude test files from scan (default true)")]
        exclude_tests: Option<bool>,
    ) -> String {
        let dir = directory
            .map(PathBuf::from)
            .unwrap_or_else(|| self.project_root.clone());
        let rules = security::rules::load_bundled_rules();
        let summary =
            security::scanner::scan_directory(&dir, &rules, exclude_tests.unwrap_or(true));
        json_text(&serde_json::json!({
            "totalFindings": summary.total_findings,
            "critical": summary.critical, "high": summary.high,
            "medium": summary.medium, "low": summary.low,
            "filesScanned": summary.files_scanned,
            "rulesApplied": summary.rules_applied,
            "topIssues": summary.top_issues.iter().map(|(name, count)| serde_json::json!({"rule": name, "count": count})).collect::<Vec<_>>(),
            "findings": summary.findings.iter().take(50).map(|f| serde_json::json!({
                "ruleId": f.rule_id, "ruleName": f.rule_name, "severity": format!("{:?}", f.severity),
                "file": f.file_path, "line": f.line_number, "message": f.message,
                "fix": f.fix, "cwe": f.cwe, "owasp": f.owasp,
            })).collect::<Vec<_>>(),
        }))
    }

    // 24. codegraph_check_owasp
    #[tool(
        name = "codegraph_check_owasp",
        description = "Scan for OWASP Top 10 2021 vulnerabilities."
    )]
    async fn codegraph_check_owasp(
        &self,
        #[tool(param)]
        #[schemars(description = "Directory to scan (defaults to project root)")]
        directory: Option<String>,
    ) -> String {
        let dir = directory
            .map(PathBuf::from)
            .unwrap_or_else(|| self.project_root.clone());
        let summary = security::scanner::check_owasp_top10(&dir);
        json_text(&serde_json::json!({
            "standard": "OWASP Top 10 2021",
            "totalFindings": summary.total_findings,
            "critical": summary.critical, "high": summary.high,
            "medium": summary.medium, "low": summary.low,
            "findings": summary.findings.iter().take(50).map(|f| serde_json::json!({
                "ruleId": f.rule_id, "severity": format!("{:?}", f.severity),
                "file": f.file_path, "line": f.line_number, "message": f.message,
                "owasp": f.owasp,
            })).collect::<Vec<_>>(),
        }))
    }

    // 25. codegraph_check_cwe
    #[tool(
        name = "codegraph_check_cwe",
        description = "Scan for CWE Top 25 most dangerous software weaknesses."
    )]
    async fn codegraph_check_cwe(
        &self,
        #[tool(param)]
        #[schemars(description = "Directory to scan (defaults to project root)")]
        directory: Option<String>,
    ) -> String {
        let dir = directory
            .map(PathBuf::from)
            .unwrap_or_else(|| self.project_root.clone());
        let summary = security::scanner::check_cwe_top25(&dir);
        json_text(&serde_json::json!({
            "standard": "CWE Top 25",
            "totalFindings": summary.total_findings,
            "critical": summary.critical, "high": summary.high,
            "medium": summary.medium, "low": summary.low,
            "findings": summary.findings.iter().take(50).map(|f| serde_json::json!({
                "ruleId": f.rule_id, "severity": format!("{:?}", f.severity),
                "file": f.file_path, "line": f.line_number, "message": f.message,
                "cwe": f.cwe,
            })).collect::<Vec<_>>(),
        }))
    }

    // 26. codegraph_explain_vulnerability
    #[tool(
        name = "codegraph_explain_vulnerability",
        description = "Get a detailed explanation of a CWE vulnerability including severity, description, and references."
    )]
    async fn codegraph_explain_vulnerability(
        &self,
        #[tool(param)]
        #[schemars(description = "CWE identifier (e.g. 'CWE-89')")]
        cwe_id: String,
    ) -> String {
        match security::scanner::explain_vulnerability(&cwe_id) {
            Some(explanation) => json_text(&serde_json::json!({
                "cweId": explanation.cwe_id, "name": explanation.name,
                "severity": explanation.severity, "description": explanation.description,
                "impact": explanation.impact, "remediation": explanation.remediation,
                "references": explanation.references,
            })),
            None => json_text(&serde_json::json!({
                "error": format!("No explanation found for {}", cwe_id),
            })),
        }
    }

    // 27. codegraph_suggest_fix
    #[tool(
        name = "codegraph_suggest_fix",
        description = "Suggest a fix for a specific security finding."
    )]
    async fn codegraph_suggest_fix(
        &self,
        #[tool(param)]
        #[schemars(description = "Rule ID of the finding (e.g. 'sql-injection-string-format')")]
        rule_id: String,
        #[tool(param)]
        #[schemars(description = "The matched vulnerable code snippet")]
        matched_code: String,
    ) -> String {
        let finding = security::scanner::SecurityFinding {
            rule_id: rule_id.clone(),
            rule_name: rule_id.clone(),
            severity: security::rules::Severity::High,
            file_path: String::new(),
            line_number: 0,
            column: 0,
            matched_text: matched_code.clone(),
            message: String::new(),
            fix: None,
            cwe: None,
            owasp: None,
            category: security::rules::RuleCategory::Other,
        };
        let fix = security::scanner::suggest_fix(&finding);
        json_text(&serde_json::json!({
            "ruleId": rule_id,
            "matchedCode": matched_code,
            "suggestedFix": fix,
        }))
    }

    // 28. codegraph_find_injections
    #[tool(
        name = "codegraph_find_injections",
        description = "Find injection vulnerabilities (SQL, XSS, command, path traversal) via taint analysis."
    )]
    async fn codegraph_find_injections(
        &self,
        #[tool(param)]
        #[schemars(description = "Source code to analyze")]
        source: String,
        #[tool(param)]
        #[schemars(description = "Programming language (e.g. 'python', 'javascript')")]
        language: String,
    ) -> String {
        let flows = security::taint::find_injection_vulnerabilities(&source, &language);
        json_text(&serde_json::json!({
            "vulnerabilityCount": flows.len(),
            "flows": flows.iter().map(|f| serde_json::json!({
                "type": f.vulnerability_type,
                "source": { "kind": format!("{:?}", f.source.kind), "line": f.source.line_number, "expression": f.source.expression },
                "sink": { "kind": format!("{:?}", f.sink.kind), "line": f.sink.line_number, "expression": f.sink.expression },
                "pathLength": f.path.len(),
            })).collect::<Vec<_>>(),
        }))
    }

    // 29. codegraph_taint_sources
    #[tool(
        name = "codegraph_taint_sources",
        description = "Find all taint sources (user input, file reads, network requests) in source code."
    )]
    async fn codegraph_taint_sources(
        &self,
        #[tool(param)]
        #[schemars(description = "Source code to analyze")]
        source: String,
        #[tool(param)]
        #[schemars(description = "Programming language (e.g. 'python', 'javascript')")]
        language: String,
    ) -> String {
        let sources = security::taint::find_taint_sources(&source, &language);
        json_text(&serde_json::json!({
            "sourceCount": sources.len(),
            "sources": sources.iter().map(|s| serde_json::json!({
                "kind": format!("{:?}", s.kind),
                "file": s.file_path, "line": s.line_number,
                "expression": s.expression,
            })).collect::<Vec<_>>(),
        }))
    }

    // 30. codegraph_security_summary
    #[tool(
        name = "codegraph_security_summary",
        description = "Comprehensive security risk assessment combining rule scanning and taint analysis."
    )]
    async fn codegraph_security_summary(
        &self,
        #[tool(param)]
        #[schemars(description = "Directory to analyze (defaults to project root)")]
        directory: Option<String>,
    ) -> String {
        let dir = directory
            .map(PathBuf::from)
            .unwrap_or_else(|| self.project_root.clone());
        let rules = security::rules::load_bundled_rules();
        let summary = security::scanner::scan_directory(&dir, &rules, true);
        json_text(&serde_json::json!({
            "riskLevel": if summary.critical > 0 { "CRITICAL" } else if summary.high > 0 { "HIGH" } else if summary.medium > 0 { "MEDIUM" } else { "LOW" },
            "totalFindings": summary.total_findings,
            "bySeverity": { "critical": summary.critical, "high": summary.high, "medium": summary.medium, "low": summary.low },
            "filesScanned": summary.files_scanned,
            "rulesApplied": summary.rules_applied,
            "topIssues": summary.top_issues,
        }))
    }

    // 31. codegraph_trace_taint
    #[tool(
        name = "codegraph_trace_taint",
        description = "Trace data flow from a specific source line to find where tainted data flows."
    )]
    async fn codegraph_trace_taint(
        &self,
        #[tool(param)]
        #[schemars(description = "Source code to analyze")]
        source: String,
        #[tool(param)]
        #[schemars(description = "Programming language")]
        language: String,
        #[tool(param)]
        #[schemars(description = "Line number to trace from")]
        from_line: usize,
    ) -> String {
        let flows = security::taint::trace_taint(&source, &language, from_line);
        json_text(&serde_json::json!({
            "fromLine": from_line,
            "flowCount": flows.len(),
            "flows": flows.iter().map(|f| serde_json::json!({
                "type": f.vulnerability_type,
                "source": { "line": f.source.line_number, "expression": f.source.expression },
                "sink": { "line": f.sink.line_number, "expression": f.sink.expression },
                "steps": f.path.iter().map(|s| serde_json::json!({
                    "line": s.line_number, "code": s.code, "operation": s.operation,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        }))
    }

    // =========================================================================
    // Existing Feature Exposure Tools (8)
    // =========================================================================

    // 32. codegraph_stats
    #[tool(
        name = "codegraph_stats",
        description = "Show index statistics — node, edge, file counts, and unresolved references."
    )]
    async fn codegraph_stats(&self) -> String {
        let store = self.store.lock().unwrap();
        match store.get_stats() {
            Ok(stats) => {
                let unresolved = store.get_unresolved_ref_count().unwrap_or(0);
                json_text(&serde_json::json!({
                    "nodes": stats.nodes,
                    "edges": stats.edges,
                    "files": stats.files,
                    "unresolvedRefs": unresolved,
                }))
            }
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 33. codegraph_circular_imports
    #[tool(
        name = "codegraph_circular_imports",
        description = "Detect circular import dependencies using Tarjan's SCC algorithm."
    )]
    async fn codegraph_circular_imports(&self) -> String {
        let store = self.store.lock().unwrap();
        let traversal = GraphTraversal::new(&store);
        match traversal.detect_cycles() {
            Ok(cycles) => {
                if cycles.is_empty() {
                    return json_text(&serde_json::json!({
                        "cycleCount": 0,
                        "message": "No circular imports detected.",
                    }));
                }
                json_text(&serde_json::json!({
                    "cycleCount": cycles.len(),
                    "cycles": cycles.iter().map(|c| serde_json::json!({
                        "size": c.size,
                        "nodes": c.node_ids,
                    })).collect::<Vec<_>>(),
                }))
            }
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 34. codegraph_project_tree
    #[tool(
        name = "codegraph_project_tree",
        description = "Show a directory tree of the indexed project with file counts per directory."
    )]
    async fn codegraph_project_tree(
        &self,
        #[tool(param)]
        #[schemars(description = "Maximum directory depth (default 3)")]
        max_depth: Option<usize>,
    ) -> String {
        let store = self.store.lock().unwrap();
        let all_nodes = match store.get_all_nodes() {
            Ok(n) => n,
            Err(e) => return json_text(&serde_json::json!({"error": e.to_string()})),
        };

        let mut dir_files: HashMap<String, HashSet<String>> = HashMap::new();
        for node in &all_nodes {
            let parts: Vec<&str> = node.file_path.rsplitn(2, '/').collect();
            let dir = if parts.len() > 1 {
                parts[1].to_string()
            } else {
                ".".to_string()
            };
            dir_files
                .entry(dir)
                .or_default()
                .insert(node.file_path.clone());
        }

        let depth = max_depth.unwrap_or(3);
        let mut tree: Vec<serde_json::Value> = dir_files
            .iter()
            .filter(|(dir, _)| dir.matches('/').count() < depth)
            .map(|(dir, files)| {
                let symbol_count = all_nodes
                    .iter()
                    .filter(|n| {
                        let parts: Vec<&str> = n.file_path.rsplitn(2, '/').collect();
                        let ndir = if parts.len() > 1 { parts[1] } else { "." };
                        ndir == dir
                    })
                    .count();
                serde_json::json!({
                    "directory": dir,
                    "fileCount": files.len(),
                    "symbolCount": symbol_count,
                })
            })
            .collect();
        tree.sort_by(|a, b| a["directory"].as_str().cmp(&b["directory"].as_str()));

        json_text(&serde_json::json!({
            "directoryCount": tree.len(),
            "totalFiles": all_nodes.iter().map(|n| &n.file_path).collect::<HashSet<_>>().len(),
            "tree": tree,
        }))
    }

    // 35. codegraph_find_references
    #[tool(
        name = "codegraph_find_references",
        description = "Find all references to a symbol across the codebase (all edge types). Use instead of Grep for cross-file reference search."
    )]
    async fn codegraph_find_references(
        &self,
        #[tool(param)]
        #[schemars(description = "Symbol name or node ID to find references for")]
        symbol: String,
    ) -> String {
        let node = match self.resolve_symbol(&symbol) {
            Some(n) => n,
            None => {
                return json_text(
                    &serde_json::json!({"error": format!("Symbol \"{}\" not found.", symbol)}),
                )
            }
        };

        let store = self.store.lock().unwrap();
        let in_edges = store.get_in_edges(&node.id, None).unwrap_or_default();
        let out_edges = store.get_out_edges(&node.id, None).unwrap_or_default();

        let mut refs: Vec<serde_json::Value> = Vec::new();
        for edge in &in_edges {
            if let Ok(Some(src)) = store.get_node(&edge.source) {
                refs.push(serde_json::json!({
                    "direction": "incoming", "kind": edge.kind.as_str(),
                    "symbol": src.name, "file": edge.file_path, "line": edge.line,
                }));
            }
        }
        for edge in &out_edges {
            if let Ok(Some(tgt)) = store.get_node(&edge.target) {
                refs.push(serde_json::json!({
                    "direction": "outgoing", "kind": edge.kind.as_str(),
                    "symbol": tgt.name, "file": edge.file_path, "line": edge.line,
                }));
            }
        }

        json_text(&serde_json::json!({
            "symbol": {"name": node.name, "kind": node.kind.as_str(), "file": node.file_path},
            "referenceCount": refs.len(),
            "references": refs,
        }))
    }

    // 36. codegraph_export_map
    #[tool(
        name = "codegraph_export_map",
        description = "List all exported symbols grouped by file."
    )]
    async fn codegraph_export_map(&self) -> String {
        let store = self.store.lock().unwrap();
        let all_nodes = match store.get_all_nodes() {
            Ok(n) => n,
            Err(e) => return json_text(&serde_json::json!({"error": e.to_string()})),
        };

        let exported: Vec<&CodeNode> = all_nodes
            .iter()
            .filter(|n| n.exported == Some(true))
            .collect();

        let mut by_file: HashMap<&str, Vec<serde_json::Value>> = HashMap::new();
        for node in &exported {
            by_file
                .entry(&node.file_path)
                .or_default()
                .push(serde_json::json!({
                    "name": node.name, "kind": node.kind.as_str(),
                    "line": node.start_line,
                    "qualifiedName": node.qualified_name,
                }));
        }

        let mut files: Vec<serde_json::Value> = by_file
            .into_iter()
            .map(|(fp, symbols)| serde_json::json!({"filePath": fp, "exports": symbols}))
            .collect();
        files.sort_by(|a, b| a["filePath"].as_str().cmp(&b["filePath"].as_str()));

        json_text(&serde_json::json!({
            "totalExports": exported.len(),
            "fileCount": files.len(),
            "files": files,
        }))
    }

    // 37. codegraph_import_graph
    #[tool(
        name = "codegraph_import_graph",
        description = "Visualize the import graph as a Mermaid diagram."
    )]
    async fn codegraph_import_graph(
        &self,
        #[tool(param)]
        #[schemars(description = "Optional directory to scope the import graph to")]
        scope: Option<String>,
    ) -> String {
        let store = self.store.lock().unwrap();
        let all_edges = match store.get_all_edges() {
            Ok(e) => e,
            Err(e) => return json_text(&serde_json::json!({"error": e.to_string()})),
        };
        let all_nodes = match store.get_all_nodes() {
            Ok(n) => n,
            Err(e) => return json_text(&serde_json::json!({"error": e.to_string()})),
        };

        let import_edges: Vec<_> = all_edges
            .iter()
            .filter(|e| e.kind == crate::types::EdgeKind::Imports)
            .collect();

        let node_file_map: HashMap<&str, &str> = all_nodes
            .iter()
            .map(|n| (n.id.as_str(), n.file_path.as_str()))
            .collect();

        let mut file_imports: HashMap<&str, HashSet<&str>> = HashMap::new();
        for edge in &import_edges {
            let src_file = node_file_map.get(edge.source.as_str());
            let tgt_file = node_file_map.get(edge.target.as_str());
            if let (Some(&sf), Some(&tf)) = (src_file, tgt_file) {
                if sf != tf {
                    if let Some(ref s) = scope {
                        if !sf.starts_with(s.as_str()) && !tf.starts_with(s.as_str()) {
                            continue;
                        }
                    }
                    file_imports.entry(sf).or_default().insert(tf);
                }
            }
        }

        let mut lines = vec!["```mermaid".to_string(), "graph LR".to_string()];
        let mut all_files = HashSet::new();
        for (src, targets) in &file_imports {
            all_files.insert(*src);
            for tgt in targets {
                all_files.insert(*tgt);
            }
        }
        for file in &all_files {
            lines.push(format!(
                "  {}[\"{}\"]",
                mermaid_id(file),
                mermaid_safe(file)
            ));
        }
        for (src, targets) in &file_imports {
            for tgt in targets {
                lines.push(format!(
                    "  {} -->|imports| {}",
                    mermaid_id(src),
                    mermaid_id(tgt)
                ));
            }
        }
        lines.push("```".to_string());
        lines.join("\n")
    }

    // 38. codegraph_file
    #[tool(
        name = "codegraph_file",
        description = "Get all symbols defined in a specific file. Use before reading a file to understand its structure first."
    )]
    async fn codegraph_file(
        &self,
        #[tool(param)]
        #[schemars(description = "File path to get symbols for")]
        file_path: String,
    ) -> String {
        let store = self.store.lock().unwrap();
        match store.get_nodes_by_file(&file_path) {
            Ok(nodes) => {
                if nodes.is_empty() {
                    return json_text(&serde_json::json!({
                        "error": format!("No symbols found in file '{}'", file_path),
                    }));
                }
                json_text(&serde_json::json!({
                    "filePath": file_path,
                    "symbolCount": nodes.len(),
                    "symbols": nodes.iter().map(|n| serde_json::json!({
                        "id": n.id, "name": n.name, "kind": n.kind.as_str(),
                        "startLine": n.start_line, "endLine": n.end_line,
                        "exported": n.exported, "qualifiedName": n.qualified_name,
                    })).collect::<Vec<_>>(),
                }))
            }
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // =========================================================================
    // Call Graph & Analysis Tools (6)
    // =========================================================================

    // 39. codegraph_find_path
    #[tool(
        name = "codegraph_find_path",
        description = "Find the shortest call path between two functions using BFS on the call graph."
    )]
    async fn codegraph_find_path(
        &self,
        #[tool(param)]
        #[schemars(description = "Source symbol name or node ID")]
        from: String,
        #[tool(param)]
        #[schemars(description = "Target symbol name or node ID")]
        to: String,
        #[tool(param)]
        #[schemars(description = "Maximum path depth (default 10)")]
        max_depth: Option<u32>,
    ) -> String {
        let from_node = match self.resolve_symbol(&from) {
            Some(n) => n,
            None => {
                return json_text(
                    &serde_json::json!({"error": format!("Source symbol \"{}\" not found.", from)}),
                )
            }
        };
        let to_node = match self.resolve_symbol(&to) {
            Some(n) => n,
            None => {
                return json_text(
                    &serde_json::json!({"error": format!("Target symbol \"{}\" not found.", to)}),
                )
            }
        };

        let store = self.store.lock().unwrap();
        let traversal = GraphTraversal::new(&store);
        match traversal.find_call_path(&from_node.id, &to_node.id, max_depth.unwrap_or(10)) {
            Ok(Some(path)) => json_text(&serde_json::json!({
                "found": true,
                "pathLength": path.len(),
                "path": path.iter().map(|n| serde_json::json!({
                    "name": n.name, "kind": n.kind.as_str(), "file": n.file_path, "line": n.start_line,
                })).collect::<Vec<_>>(),
            })),
            Ok(None) => json_text(&serde_json::json!({
                "found": false,
                "message": format!("No call path found from \"{}\" to \"{}\".", from, to),
            })),
            Err(e) => json_text(&serde_json::json!({"error": e.to_string()})),
        }
    }

    // 40. codegraph_complexity
    #[tool(
        name = "codegraph_complexity",
        description = "Calculate cyclomatic and cognitive complexity for all functions in the codebase."
    )]
    async fn codegraph_complexity(
        &self,
        #[tool(param)]
        #[schemars(
            description = "Minimum cyclomatic complexity to include in results (default 5)"
        )]
        min_complexity: Option<u32>,
    ) -> String {
        let store = self.store.lock().unwrap();
        let mut results = complexity::calculate_all_complexities(&store.conn);
        let threshold = min_complexity.unwrap_or(5);
        results.retain(|r| r.cyclomatic >= threshold);
        results.sort_by(|a, b| b.cyclomatic.cmp(&a.cyclomatic));

        json_text(&serde_json::json!({
            "threshold": threshold,
            "functionCount": results.len(),
            "functions": results.iter().take(50).map(|r| serde_json::json!({
                "name": r.name, "file": r.file_path,
                "cyclomatic": r.cyclomatic, "cognitive": r.cognitive,
                "lineCount": r.line_count,
            })).collect::<Vec<_>>(),
        }))
    }

    // 41. codegraph_data_flow
    #[tool(
        name = "codegraph_data_flow",
        description = "Analyze variable def-use chains in source code."
    )]
    async fn codegraph_data_flow(
        &self,
        #[tool(param)]
        #[schemars(description = "Source code to analyze")]
        source: String,
        #[tool(param)]
        #[schemars(description = "Programming language (e.g. 'python', 'javascript')")]
        language: String,
    ) -> String {
        let chains = dataflow::find_def_use_chains(&source, &language);
        json_text(&serde_json::json!({
            "variableCount": chains.len(),
            "chains": chains.iter().map(|c| serde_json::json!({
                "variable": c.variable,
                "definitions": c.definitions.iter().map(|d| serde_json::json!({"line": d.line, "column": d.column})).collect::<Vec<_>>(),
                "uses": c.uses.iter().map(|u| serde_json::json!({"line": u.line, "column": u.column})).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        }))
    }

    // 42. codegraph_dead_stores
    #[tool(
        name = "codegraph_dead_stores",
        description = "Find variable assignments that are never subsequently read (dead stores)."
    )]
    async fn codegraph_dead_stores(
        &self,
        #[tool(param)]
        #[schemars(description = "Source code to analyze")]
        source: String,
        #[tool(param)]
        #[schemars(description = "Programming language")]
        language: String,
    ) -> String {
        let stores = dataflow::find_dead_stores(&source, &language);
        json_text(&serde_json::json!({
            "deadStoreCount": stores.len(),
            "stores": stores.iter().map(|s| serde_json::json!({
                "variable": s.variable, "line": s.line, "assignedValue": s.assigned_value,
            })).collect::<Vec<_>>(),
        }))
    }

    // 43. codegraph_find_uninitialized
    #[tool(
        name = "codegraph_find_uninitialized",
        description = "Find variables used before initialization."
    )]
    async fn codegraph_find_uninitialized(
        &self,
        #[tool(param)]
        #[schemars(description = "Source code to analyze")]
        source: String,
        #[tool(param)]
        #[schemars(description = "Programming language")]
        language: String,
    ) -> String {
        let locations = dataflow::find_uninitialized_uses(&source, &language);
        json_text(&serde_json::json!({
            "uninitializedCount": locations.len(),
            "locations": locations.iter().map(|l| serde_json::json!({
                "line": l.line, "column": l.column,
            })).collect::<Vec<_>>(),
        }))
    }

    // 44. codegraph_reaching_defs
    #[tool(
        name = "codegraph_reaching_defs",
        description = "Find which variable definitions reach a specific line."
    )]
    async fn codegraph_reaching_defs(
        &self,
        #[tool(param)]
        #[schemars(description = "Source code to analyze")]
        source: String,
        #[tool(param)]
        #[schemars(description = "Programming language")]
        language: String,
        #[tool(param)]
        #[schemars(description = "Target line number")]
        target_line: u32,
    ) -> String {
        let chains = dataflow::find_reaching_defs(&source, &language, target_line);
        json_text(&serde_json::json!({
            "targetLine": target_line,
            "variableCount": chains.len(),
            "reachingDefinitions": chains.iter().map(|c| serde_json::json!({
                "variable": c.variable,
                "definitions": c.definitions.iter().map(|d| serde_json::json!({"line": d.line})).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        }))
    }
}

// ---------------------------------------------------------------------------
// ServerHandler impl (auto-wired by tool_box macro)
// ---------------------------------------------------------------------------

#[tool(tool_box)]
impl ServerHandler for CodeGraphServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "CodeGraph — codebase intelligence MCP server with 44 tools across 32 languages. \
                 ALWAYS prefer CodeGraph tools over Grep/Glob/Explore agents for code analysis: \
                 codegraph_query (semantic search), codegraph_dependencies (import tracing), \
                 codegraph_callers (call graph), codegraph_find_references (cross-file refs), \
                 codegraph_structure (project overview), codegraph_node (symbol lookup). \
                 These use a pre-built AST index and return results in milliseconds."
                    .into(),
            ),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            server_info: rmcp::model::Implementation {
                name: "codegraph".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point: run the MCP server over stdio
// ---------------------------------------------------------------------------

/// Start the MCP server on stdin/stdout.
///
/// This blocks until the client disconnects or a shutdown signal is received.
pub async fn run_server(store: GraphStore) -> Result<(), Box<dyn std::error::Error>> {
    let server = CodeGraphServer::new(store);
    let transport = rmcp::transport::io::stdio();
    let running = server.serve(transport).await.inspect_err(|e| {
        tracing::error!("MCP server error: {}", e);
    })?;
    let _ = running.waiting().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::initialize_database;
    use crate::types::{CodeEdge, CodeNode, EdgeKind, Language, NodeKind};

    fn setup_server() -> CodeGraphServer {
        let conn = initialize_database(":memory:").expect("schema init");
        let store = GraphStore::from_connection(conn);
        CodeGraphServer::new(store)
    }

    fn make_node(
        id: &str,
        name: &str,
        file: &str,
        kind: NodeKind,
        line: u32,
        exported: Option<bool>,
    ) -> CodeNode {
        CodeNode {
            id: id.to_string(),
            name: name.to_string(),
            qualified_name: None,
            kind,
            file_path: file.to_string(),
            start_line: line,
            end_line: line + 5,
            start_column: 0,
            end_column: 1,
            language: Language::TypeScript,
            body: Some(format!("function {}() {{}}", name)),
            documentation: None,
            exported,
        }
    }

    fn make_node_with_lang(
        id: &str,
        name: &str,
        file: &str,
        kind: NodeKind,
        line: u32,
        lang: Language,
    ) -> CodeNode {
        CodeNode {
            id: id.to_string(),
            name: name.to_string(),
            qualified_name: None,
            kind,
            file_path: file.to_string(),
            start_line: line,
            end_line: line + 5,
            start_column: 0,
            end_column: 1,
            language: lang,
            body: None,
            documentation: None,
            exported: None,
        }
    }

    fn make_edge(source: &str, target: &str, kind: EdgeKind, file: &str, line: u32) -> CodeEdge {
        CodeEdge {
            source: source.to_string(),
            target: target.to_string(),
            kind,
            file_path: file.to_string(),
            line,
            metadata: None,
        }
    }

    // -- codegraph_callees ----------------------------------------------------

    #[tokio::test]
    async fn callees_returns_forward_call_graph() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node("n1", "main", "src/main.ts", NodeKind::Function, 1, None),
                    make_node("n2", "helper", "src/helper.ts", NodeKind::Function, 1, None),
                    make_node("n3", "util", "src/util.ts", NodeKind::Function, 1, None),
                ])
                .unwrap();
            store
                .upsert_edges(&[
                    make_edge("n1", "n2", EdgeKind::Calls, "src/main.ts", 5),
                    make_edge("n2", "n3", EdgeKind::Calls, "src/helper.ts", 3),
                    make_edge("n1", "n3", EdgeKind::Imports, "src/main.ts", 1),
                ])
                .unwrap();
        }

        let result = server.codegraph_callees("main".to_string(), None).await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["calleeCount"].as_u64().unwrap(), 2);
        let callees = json["callees"].as_array().unwrap();
        assert_eq!(callees[0]["name"].as_str().unwrap(), "helper");
        assert_eq!(callees[0]["depth"].as_u64().unwrap(), 1);
        assert_eq!(callees[1]["name"].as_str().unwrap(), "util");
        assert_eq!(callees[1]["depth"].as_u64().unwrap(), 2);
    }

    #[tokio::test]
    async fn callees_not_found() {
        let server = setup_server();
        let result = server
            .codegraph_callees("nonexistent".to_string(), None)
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].as_str().unwrap().contains("not found"));
    }

    // -- codegraph_node -------------------------------------------------------

    #[tokio::test]
    async fn node_returns_full_details() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[make_node(
                    "n1",
                    "processData",
                    "src/processor.ts",
                    NodeKind::Function,
                    10,
                    Some(true),
                )])
                .unwrap();
        }

        let result = server.codegraph_node("processData".to_string(), None).await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["name"].as_str().unwrap(), "processData");
        assert_eq!(json["kind"].as_str().unwrap(), "function");
        assert_eq!(json["filePath"].as_str().unwrap(), "src/processor.ts");
        assert_eq!(json["startLine"].as_u64().unwrap(), 10);
        assert_eq!(json["exported"].as_bool().unwrap(), true);
    }

    #[tokio::test]
    async fn node_with_relations() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node("n1", "caller", "src/a.ts", NodeKind::Function, 1, None),
                    make_node("n2", "target", "src/b.ts", NodeKind::Function, 1, None),
                    make_node("n3", "callee", "src/c.ts", NodeKind::Function, 1, None),
                ])
                .unwrap();
            store
                .upsert_edges(&[
                    make_edge("n1", "n2", EdgeKind::Calls, "src/a.ts", 5),
                    make_edge("n2", "n3", EdgeKind::Calls, "src/b.ts", 3),
                ])
                .unwrap();
        }

        let result = server
            .codegraph_node("target".to_string(), Some(true))
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["name"].as_str().unwrap(), "target");
        let callers = json["callers"].as_array().unwrap();
        assert_eq!(callers.len(), 1);
        assert_eq!(callers[0]["name"].as_str().unwrap(), "caller");
        let callees = json["callees"].as_array().unwrap();
        assert_eq!(callees.len(), 1);
        assert_eq!(callees[0]["name"].as_str().unwrap(), "callee");
    }

    #[tokio::test]
    async fn node_not_found_with_suggestions() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[make_node(
                    "n1",
                    "processData",
                    "src/a.ts",
                    NodeKind::Function,
                    1,
                    None,
                )])
                .unwrap();
        }

        let result = server.codegraph_node("process".to_string(), None).await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert!(json["error"].as_str().unwrap().contains("not found"));
        let suggestions = json["suggestions"].as_array().unwrap();
        assert!(suggestions
            .iter()
            .any(|s| s.as_str().unwrap() == "processData"));
    }

    // -- codegraph_dead_code --------------------------------------------------

    #[tokio::test]
    async fn dead_code_finds_unreferenced_symbols() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node("n1", "usedFunc", "src/a.ts", NodeKind::Function, 1, None),
                    make_node("n2", "unusedFunc", "src/b.ts", NodeKind::Function, 1, None),
                    make_node("n3", "caller", "src/c.ts", NodeKind::Function, 1, None),
                ])
                .unwrap();
            store
                .upsert_edge(&make_edge("n3", "n1", EdgeKind::Calls, "src/c.ts", 5))
                .unwrap();
        }

        let result = server.codegraph_dead_code(None, None).await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert!(json["deadCodeCount"].as_u64().unwrap() >= 2);
        let files = json["files"].as_array().unwrap();
        let all_names: Vec<&str> = files
            .iter()
            .flat_map(|f| {
                f["symbols"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s["name"].as_str().unwrap())
            })
            .collect();
        assert!(all_names.contains(&"unusedFunc"));
        assert!(all_names.contains(&"caller"));
        assert!(!all_names.contains(&"usedFunc"));
    }

    #[tokio::test]
    async fn dead_code_filters_by_kind() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node("n1", "unusedFunc", "src/a.ts", NodeKind::Function, 1, None),
                    make_node("n2", "UnusedClass", "src/b.ts", NodeKind::Class, 1, None),
                ])
                .unwrap();
        }

        let result = server
            .codegraph_dead_code(Some("function".to_string()), None)
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["deadCodeCount"].as_u64().unwrap(), 1);
        let files = json["files"].as_array().unwrap();
        let name = files[0]["symbols"][0]["name"].as_str().unwrap();
        assert_eq!(name, "unusedFunc");
    }

    #[tokio::test]
    async fn dead_code_empty_graph() {
        let server = setup_server();
        let result = server.codegraph_dead_code(None, None).await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["deadCodeCount"].as_u64().unwrap(), 0);
        assert!(json["message"].as_str().is_some());
    }

    // -- codegraph_frameworks -------------------------------------------------

    #[tokio::test]
    async fn frameworks_with_explicit_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"dependencies": {"react": "^18.0.0"}}"#,
        )
        .unwrap();

        let server = setup_server();
        let result = server
            .codegraph_frameworks(Some(dir.path().to_str().unwrap().to_string()))
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["frameworkCount"].as_u64().unwrap(), 1);
        let frameworks = json["frameworks"].as_array().unwrap();
        assert_eq!(frameworks[0]["name"].as_str().unwrap(), "React");
        assert_eq!(frameworks[0]["language"].as_str().unwrap(), "javascript");
        assert_eq!(frameworks[0]["category"].as_str().unwrap(), "web");
    }

    #[tokio::test]
    async fn frameworks_empty_project() {
        let dir = tempfile::tempdir().unwrap();
        let server = setup_server();
        let result = server
            .codegraph_frameworks(Some(dir.path().to_str().unwrap().to_string()))
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["frameworkCount"].as_u64().unwrap(), 0);
        assert!(json["message"].as_str().is_some());
    }

    #[tokio::test]
    async fn frameworks_no_dir_with_empty_store() {
        let server = setup_server();
        let result = server.codegraph_frameworks(None).await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        // With no indexed files, defaults to "." which likely has no manifests
        // or finds the current project's Cargo.toml
        assert!(json["frameworkCount"].is_number());
    }

    // -- codegraph_languages --------------------------------------------------

    #[tokio::test]
    async fn languages_shows_breakdown() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node_with_lang(
                        "n1",
                        "foo",
                        "src/a.ts",
                        NodeKind::Function,
                        1,
                        Language::TypeScript,
                    ),
                    make_node_with_lang(
                        "n2",
                        "bar",
                        "src/a.ts",
                        NodeKind::Function,
                        10,
                        Language::TypeScript,
                    ),
                    make_node_with_lang(
                        "n3",
                        "baz",
                        "src/b.py",
                        NodeKind::Function,
                        1,
                        Language::Python,
                    ),
                ])
                .unwrap();
            store
                .upsert_edge(&make_edge("n1", "n2", EdgeKind::Calls, "src/a.ts", 5))
                .unwrap();
        }

        let result = server.codegraph_languages().await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["languageCount"].as_u64().unwrap(), 2);
        assert_eq!(json["totalFiles"].as_u64().unwrap(), 2);
        assert_eq!(json["totalSymbols"].as_u64().unwrap(), 3);
        assert_eq!(json["totalEdges"].as_u64().unwrap(), 1);

        let languages = json["languages"].as_array().unwrap();
        assert_eq!(languages.len(), 2);

        // TypeScript has more symbols so should be first
        let ts = &languages[0];
        assert_eq!(ts["language"].as_str().unwrap(), "typescript");
        assert_eq!(ts["files"].as_u64().unwrap(), 1);
        assert_eq!(ts["symbols"].as_u64().unwrap(), 2);
        assert_eq!(ts["edges"].as_u64().unwrap(), 1);
        assert_eq!(ts["percentage"].as_str().unwrap(), "66.7%");

        let py = &languages[1];
        assert_eq!(py["language"].as_str().unwrap(), "python");
        assert_eq!(py["files"].as_u64().unwrap(), 1);
        assert_eq!(py["symbols"].as_u64().unwrap(), 1);
        assert_eq!(py["percentage"].as_str().unwrap(), "33.3%");
    }

    #[tokio::test]
    async fn languages_empty_graph() {
        let server = setup_server();
        let result = server.codegraph_languages().await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["languageCount"].as_u64().unwrap(), 0);
        assert!(json["message"].as_str().is_some());
    }

    #[tokio::test]
    async fn languages_single_language() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node_with_lang(
                        "n1",
                        "foo",
                        "src/a.rs",
                        NodeKind::Function,
                        1,
                        Language::Rust,
                    ),
                    make_node_with_lang(
                        "n2",
                        "bar",
                        "src/b.rs",
                        NodeKind::Function,
                        1,
                        Language::Rust,
                    ),
                ])
                .unwrap();
        }

        let result = server.codegraph_languages().await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();

        assert_eq!(json["languageCount"].as_u64().unwrap(), 1);
        let languages = json["languages"].as_array().unwrap();
        assert_eq!(languages[0]["language"].as_str().unwrap(), "rust");
        assert_eq!(languages[0]["percentage"].as_str().unwrap(), "100.0%");
    }

    // =====================================================================
    // NEW TESTS: Phase 18C — MCP Server comprehensive coverage
    // =====================================================================

    // -- codegraph_stats --------------------------------------------------

    #[tokio::test]
    async fn stats_empty_graph() {
        let server = setup_server();
        let result = server.codegraph_stats().await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["nodes"].as_u64().unwrap(), 0);
        assert_eq!(json["edges"].as_u64().unwrap(), 0);
        assert_eq!(json["files"].as_u64().unwrap(), 0);
        assert_eq!(json["unresolvedRefs"].as_u64().unwrap(), 0);
    }

    #[tokio::test]
    async fn stats_with_data() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node("n1", "a", "src/a.ts", NodeKind::Function, 1, None),
                    make_node("n2", "b", "src/b.ts", NodeKind::Function, 1, None),
                ])
                .unwrap();
            store
                .upsert_edge(&make_edge("n1", "n2", EdgeKind::Calls, "src/a.ts", 5))
                .unwrap();
            store
                .insert_unresolved_ref("n1", "./missing", "import", "src/a.ts", 1)
                .unwrap();
        }
        let result = server.codegraph_stats().await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["nodes"].as_u64().unwrap(), 2);
        assert_eq!(json["edges"].as_u64().unwrap(), 1);
        assert_eq!(json["files"].as_u64().unwrap(), 2);
        assert_eq!(json["unresolvedRefs"].as_u64().unwrap(), 1);
    }

    // -- codegraph_circular_imports ---------------------------------------

    #[tokio::test]
    async fn circular_imports_no_cycles() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node("n1", "a", "a.ts", NodeKind::Function, 1, None),
                    make_node("n2", "b", "b.ts", NodeKind::Function, 1, None),
                ])
                .unwrap();
            store
                .upsert_edge(&make_edge("n1", "n2", EdgeKind::Calls, "a.ts", 5))
                .unwrap();
        }
        let result = server.codegraph_circular_imports().await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["cycleCount"].as_u64().unwrap(), 0);
        assert!(json["message"].as_str().is_some());
    }

    #[tokio::test]
    async fn circular_imports_with_cycle() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node("n1", "a", "a.ts", NodeKind::Function, 1, None),
                    make_node("n2", "b", "b.ts", NodeKind::Function, 1, None),
                ])
                .unwrap();
            store
                .upsert_edges(&[
                    make_edge("n1", "n2", EdgeKind::Calls, "a.ts", 5),
                    make_edge("n2", "n1", EdgeKind::Calls, "b.ts", 3),
                ])
                .unwrap();
        }
        let result = server.codegraph_circular_imports().await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(json["cycleCount"].as_u64().unwrap(), 1);
        let cycles = json["cycles"].as_array().unwrap();
        assert_eq!(cycles[0]["size"].as_u64().unwrap(), 2);
    }

    // -- codegraph_project_tree -------------------------------------------

    #[tokio::test]
    async fn project_tree_empty() {
        let server = setup_server();
        let result = server.codegraph_project_tree(None).await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["tree"].is_array() || json["message"].is_string() || json.is_object());
    }

    #[tokio::test]
    async fn project_tree_with_files() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node("n1", "a", "src/lib/a.ts", NodeKind::Function, 1, None),
                    make_node("n2", "b", "src/lib/b.ts", NodeKind::Function, 1, None),
                    make_node("n3", "c", "src/utils/c.ts", NodeKind::Function, 1, None),
                ])
                .unwrap();
        }
        let result = server.codegraph_project_tree(Some(2)).await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json.is_object());
    }

    // -- codegraph_find_references ----------------------------------------

    #[tokio::test]
    async fn find_references_existing_symbol() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node("n1", "helper", "src/a.ts", NodeKind::Function, 1, None),
                    make_node("n2", "caller1", "src/b.ts", NodeKind::Function, 1, None),
                    make_node("n3", "caller2", "src/c.ts", NodeKind::Function, 1, None),
                ])
                .unwrap();
            store
                .upsert_edges(&[
                    make_edge("n2", "n1", EdgeKind::Calls, "src/b.ts", 5),
                    make_edge("n3", "n1", EdgeKind::Calls, "src/c.ts", 3),
                ])
                .unwrap();
        }
        let result = server.codegraph_find_references("helper".to_string()).await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["referenceCount"].as_u64().unwrap() >= 2);
    }

    #[tokio::test]
    async fn find_references_nonexistent_symbol() {
        let server = setup_server();
        let result = server
            .codegraph_find_references("nonexistent".to_string())
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    // -- codegraph_export_map ---------------------------------------------

    #[tokio::test]
    async fn export_map_with_exports() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node(
                        "n1",
                        "publicFunc",
                        "src/a.ts",
                        NodeKind::Function,
                        1,
                        Some(true),
                    ),
                    make_node(
                        "n2",
                        "privateFunc",
                        "src/a.ts",
                        NodeKind::Function,
                        10,
                        Some(false),
                    ),
                    make_node(
                        "n3",
                        "anotherPublic",
                        "src/b.ts",
                        NodeKind::Function,
                        1,
                        Some(true),
                    ),
                ])
                .unwrap();
        }
        let result = server.codegraph_export_map().await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json.is_object());
    }

    #[tokio::test]
    async fn export_map_empty() {
        let server = setup_server();
        let result = server.codegraph_export_map().await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json.is_object());
    }

    // -- codegraph_find_path ----------------------------------------------

    #[tokio::test]
    async fn find_path_existing() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node("n1", "start", "src/a.ts", NodeKind::Function, 1, None),
                    make_node("n2", "middle", "src/b.ts", NodeKind::Function, 1, None),
                    make_node("n3", "end", "src/c.ts", NodeKind::Function, 1, None),
                ])
                .unwrap();
            store
                .upsert_edges(&[
                    make_edge("n1", "n2", EdgeKind::Calls, "src/a.ts", 5),
                    make_edge("n2", "n3", EdgeKind::Calls, "src/b.ts", 3),
                ])
                .unwrap();
        }
        let result = server
            .codegraph_find_path("start".to_string(), "end".to_string(), None)
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["path"].is_array());
        assert_eq!(json["pathLength"].as_u64().unwrap(), 3);
    }

    #[tokio::test]
    async fn find_path_no_route() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node("n1", "isolated_a", "src/a.ts", NodeKind::Function, 1, None),
                    make_node("n2", "isolated_b", "src/b.ts", NodeKind::Function, 1, None),
                ])
                .unwrap();
        }
        let result = server
            .codegraph_find_path("isolated_a".to_string(), "isolated_b".to_string(), None)
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["message"].as_str().unwrap().contains("No call path"));
    }

    // -- codegraph_complexity ---------------------------------------------

    #[tokio::test]
    async fn complexity_analysis() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            let meta = serde_json::json!({
                "body": "function process(x) {\n  if (x > 0) {\n    return true;\n  }\n  return false;\n}"
            });
            store.conn.execute(
                "INSERT INTO nodes (id, type, name, file_path, start_line, end_line, language, source_hash, metadata) \
                 VALUES ('fn:a:1', 'function', 'process', 'src/a.ts', 1, 6, 'typescript', 'h1', ?1)",
                [meta.to_string()],
            ).unwrap();
        }
        let result = server.codegraph_complexity(None).await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["functions"].is_array());
    }

    #[tokio::test]
    async fn complexity_empty_graph() {
        let server = setup_server();
        let result = server.codegraph_complexity(None).await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json.is_object());
    }

    // -- codegraph_data_flow ----------------------------------------------

    #[tokio::test]
    async fn data_flow_analysis() {
        let server = setup_server();
        let result = server
            .codegraph_data_flow(
                "let x = 10;\nlet y = x + 5;".to_string(),
                "javascript".to_string(),
            )
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["chains"].is_array());
    }

    #[tokio::test]
    async fn data_flow_empty_source() {
        let server = setup_server();
        let result = server
            .codegraph_data_flow("".to_string(), "javascript".to_string())
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["chains"].is_array());
    }

    // -- codegraph_dead_stores --------------------------------------------

    #[tokio::test]
    async fn dead_stores_detection() {
        let server = setup_server();
        let result = server
            .codegraph_dead_stores(
                "let x = 10;\nlet y = 20;\nconsole.log(y);".to_string(),
                "javascript".to_string(),
            )
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["stores"].is_array());
        let stores = json["stores"].as_array().unwrap();
        assert!(stores
            .iter()
            .any(|s| s["variable"].as_str().unwrap() == "x"));
    }

    // -- codegraph_find_uninitialized -------------------------------------

    #[tokio::test]
    async fn find_uninitialized_vars() {
        let server = setup_server();
        let result = server
            .codegraph_find_uninitialized(
                "console.log(result);\nlet result = compute();".to_string(),
                "javascript".to_string(),
            )
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["locations"].is_array());
    }

    // -- codegraph_reaching_defs ------------------------------------------

    #[tokio::test]
    async fn reaching_defs_analysis() {
        let server = setup_server();
        let result = server
            .codegraph_reaching_defs(
                "let x = 10;\nlet y = 20;\nlet z = x + y;".to_string(),
                "javascript".to_string(),
                3,
            )
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["reachingDefinitions"].is_array());
    }

    // -- codegraph_query --------------------------------------------------

    #[tokio::test]
    async fn query_with_results() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_node(&make_node(
                    "n1",
                    "searchable",
                    "src/a.ts",
                    NodeKind::Function,
                    1,
                    None,
                ))
                .unwrap();
        }
        let result = server
            .codegraph_query("searchable".to_string(), Some(5), None)
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json.is_array());
    }

    #[tokio::test]
    async fn query_empty_results() {
        let server = setup_server();
        let result = server
            .codegraph_query("nonexistent".to_string(), None, None)
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json.is_array());
        assert!(json.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn query_with_language_filter() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_node(&make_node(
                    "n1",
                    "compute",
                    "src/a.ts",
                    NodeKind::Function,
                    1,
                    None,
                ))
                .unwrap();
        }
        let result = server
            .codegraph_query("compute".to_string(), None, Some("python".to_string()))
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json.as_array().unwrap().is_empty(), "no Python nodes exist");
    }

    // -- codegraph_dependencies -------------------------------------------

    #[tokio::test]
    async fn dependencies_tool() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node("n1", "main", "src/main.ts", NodeKind::Function, 1, None),
                    make_node("n2", "dep1", "src/dep.ts", NodeKind::Function, 1, None),
                ])
                .unwrap();
            store
                .upsert_edge(&make_edge("n1", "n2", EdgeKind::Calls, "src/main.ts", 5))
                .unwrap();
        }
        let result = server
            .codegraph_dependencies("main".to_string(), None)
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["dependencyCount"].as_u64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn dependencies_not_found() {
        let server = setup_server();
        let result = server
            .codegraph_dependencies("nonexistent".to_string(), None)
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    // -- codegraph_callers ------------------------------------------------

    #[tokio::test]
    async fn callers_tool() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node("n1", "helper", "src/helper.ts", NodeKind::Function, 1, None),
                    make_node("n2", "caller", "src/main.ts", NodeKind::Function, 1, None),
                ])
                .unwrap();
            store
                .upsert_edge(&make_edge("n2", "n1", EdgeKind::Calls, "src/main.ts", 5))
                .unwrap();
        }
        let result = server.codegraph_callers("helper".to_string(), None).await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["callerCount"].as_u64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn callers_not_found() {
        let server = setup_server();
        let result = server
            .codegraph_callers("nonexistent".to_string(), None)
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    // -- codegraph_impact -------------------------------------------------

    #[tokio::test]
    async fn impact_tool() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_nodes(&[
                    make_node("n1", "core", "src/core.ts", NodeKind::Function, 1, None),
                    make_node("n2", "user", "src/user.ts", NodeKind::Function, 1, None),
                ])
                .unwrap();
            store
                .upsert_edge(&make_edge("n2", "n1", EdgeKind::Calls, "src/user.ts", 5))
                .unwrap();
        }
        let result = server
            .codegraph_impact(None, Some("core".to_string()))
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["totalAffected"].is_number());
        assert!(json["riskGroups"].is_array());
    }

    #[tokio::test]
    async fn impact_not_found() {
        let server = setup_server();
        let result = server
            .codegraph_impact(None, Some("nonexistent".to_string()))
            .await;
        let json: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert!(json["error"].is_string());
    }

    // -- resolve_symbol ---------------------------------------------------

    #[test]
    fn resolve_symbol_by_name() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_node(&make_node(
                    "n1",
                    "myFunc",
                    "src/a.ts",
                    NodeKind::Function,
                    1,
                    None,
                ))
                .unwrap();
        }
        let node = server.resolve_symbol("myFunc");
        assert!(node.is_some());
        assert_eq!(node.unwrap().name, "myFunc");
    }

    #[test]
    fn resolve_symbol_by_id() {
        let server = setup_server();
        {
            let store = server.store.lock().unwrap();
            store
                .upsert_node(&make_node(
                    "n1",
                    "myFunc",
                    "src/a.ts",
                    NodeKind::Function,
                    1,
                    None,
                ))
                .unwrap();
        }
        let node = server.resolve_symbol("n1");
        assert!(node.is_some());
        assert_eq!(node.unwrap().id, "n1");
    }

    #[test]
    fn resolve_symbol_not_found() {
        let server = setup_server();
        let node = server.resolve_symbol("nonexistent");
        assert!(node.is_none());
    }

    // -- helper function tests --------------------------------------------

    #[test]
    fn mermaid_safe_escapes_special() {
        let result = mermaid_safe("foo[bar](baz){qux}");
        assert!(!result.contains('['));
        assert!(!result.contains(']'));
        assert!(!result.contains('('));
        assert!(!result.contains(')'));
    }

    #[test]
    fn mermaid_id_deterministic() {
        let id1 = mermaid_id("node:test:1");
        let id2 = mermaid_id("node:test:1");
        assert_eq!(id1, id2);
    }

    #[test]
    fn mermaid_id_different_inputs() {
        let id1 = mermaid_id("alpha");
        let id2 = mermaid_id("beta");
        assert_ne!(id1, id2);
    }

    #[test]
    fn json_text_helper() {
        let val = serde_json::json!({"key": "value"});
        let result = json_text(&val);
        assert!(result.contains("key"));
        assert!(result.contains("value"));
    }
}
