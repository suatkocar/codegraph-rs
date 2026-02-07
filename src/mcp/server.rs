//! MCP server implementation using rmcp over stdio transport.
//!
//! Provides all 13 CodeGraph tools that Claude (or any MCP client) can invoke
//! to search, navigate, analyze, and visualize a codebase.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::{tool, ServerHandler, ServiceExt};
use serde::Serialize;

use crate::context::assembler::ContextAssembler;
use crate::graph::ranking::GraphRanking;
use crate::graph::search::{HybridSearch, SearchOptions};
use crate::graph::store::GraphStore;
use crate::graph::traversal::GraphTraversal;
use crate::resolution::dead_code::find_dead_code;
use crate::resolution::frameworks::detect_frameworks;
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
}

impl CodeGraphServer {
    /// Create a new MCP server backed by the given store.
    pub fn new(store: GraphStore) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
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
        description = "Search the code graph using hybrid keyword + semantic search. Returns ranked code snippets with file paths and relevance scores."
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
        description = "Find all dependencies of a symbol (what it calls, imports, references, extends, or implements). Returns a dependency tree with depth levels."
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
        description = "Find all callers of a symbol (who calls this function/method). Returns a caller tree with depth levels."
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
        description = "Find all functions/methods that a symbol calls (forward call graph). Returns a callee tree with depth levels."
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
        description = "Analyze the blast radius of changing a file or symbol. Returns affected files and functions grouped by risk level."
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
        description = "Get a project overview: modules, key classes/functions, and dependency summary. Uses PageRank to identify the most important symbols."
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
        description = "Assemble optimal context for Claude from the code graph. Uses a tiered approach (core -> near -> extended -> background) to pack the most relevant code within a token budget."
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
        description = "Look up a specific code symbol by name or ID and return its full details including source code, documentation, file location, and relationships."
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
}

// ---------------------------------------------------------------------------
// ServerHandler impl (auto-wired by tool_box macro)
// ---------------------------------------------------------------------------

#[tool(tool_box)]
impl ServerHandler for CodeGraphServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some(
                "CodeGraph — codebase intelligence MCP server. Search, navigate, and analyze code with semantic graph queries.".into(),
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
        eprintln!("[codegraph] MCP server error: {}", e);
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
}
