//! Context assembler — packs ranked code snippets into an LLM prompt.
//!
//! Ports the TypeScript `context/assembler.ts` to Rust. Given a natural
//! language query, the assembler searches the code graph for relevant
//! symbols, loads their source from SQLite, and arranges them into a
//! structured Markdown document that fits within a configurable token
//! budget.
//!
//! The output is partitioned into four tiers so the most important
//! information always appears first:
//!
//! | Tier       | Budget | Content                                    |
//! |------------|--------|--------------------------------------------|
//! | Core       | ~40%   | Full source of top-ranked search results    |
//! | Near       | ~25%   | Signatures of direct callers/callees        |
//! | Extended   | ~20%   | Related tests and sibling functions         |
//! | Background | ~15%   | Project structure overview                  |

use std::collections::HashSet;

use rusqlite::{params, Connection};

use crate::context::budget::{estimate_tokens, signature_only, truncate_to_fit};
use crate::db::converters::row_to_code_node;
use crate::graph::search::{HybridSearch, SearchOptions};
use crate::types::CodeNode;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default token budget when the caller doesn't specify one.
const DEFAULT_BUDGET: usize = 8_000;

// ---------------------------------------------------------------------------
// Context assembler
// ---------------------------------------------------------------------------

/// Assembles LLM-ready context from the code graph.
///
/// Holds references to the underlying database connection and search
/// engine so it can query both the structured graph and the full-text /
/// vector indexes in a single pass.
pub struct ContextAssembler<'a> {
    conn: &'a Connection,
    search: &'a HybridSearch<'a>,
}

impl<'a> ContextAssembler<'a> {
    /// Create a new assembler backed by `conn` and `search`.
    pub fn new(conn: &'a Connection, search: &'a HybridSearch<'a>) -> Self {
        Self { conn, search }
    }

    /// Assemble a Markdown context document for `query`.
    ///
    /// `budget` defaults to [`DEFAULT_BUDGET`] tokens when `None`.
    pub fn assemble_context(&self, query: &str, budget: Option<usize>) -> String {
        let budget = budget.unwrap_or(DEFAULT_BUDGET);

        // Allocate across the four tiers.
        let core_budget = budget * 40 / 100;
        let near_budget = budget * 25 / 100;
        let extended_budget = budget * 20 / 100;
        let background_budget = budget * 15 / 100;

        // -- 1. Core: top search results with full source -----------------
        let search_opts = SearchOptions {
            limit: Some(10),
            ..Default::default()
        };
        let search_results = self
            .search
            .search(query, &search_opts)
            .unwrap_or_default();

        let mut core_nodes: Vec<CodeNode> = Vec::new();
        let mut seen_ids: HashSet<String> = HashSet::new();

        for result in &search_results {
            if let Some(node) = self.load_node(&result.node_id) {
                seen_ids.insert(node.id.clone());
                core_nodes.push(node);
            }
        }

        let core_section = self.build_core_section(&core_nodes, core_budget);

        // -- 2. Near: signatures of direct callers/callees ----------------
        let mut near_ids: Vec<String> = Vec::new();
        for node in &core_nodes {
            let neighbor_ids = self.get_neighbor_ids(&node.id);
            for nid in neighbor_ids {
                if !seen_ids.contains(&nid) {
                    seen_ids.insert(nid.clone());
                    near_ids.push(nid);
                }
            }
        }

        let mut near_nodes: Vec<CodeNode> = Vec::new();
        for nid in &near_ids {
            if let Some(node) = self.load_node(nid) {
                near_nodes.push(node);
            }
        }

        let near_section = self.build_near_section(&near_nodes, near_budget);

        // -- 3. Extended: related tests and siblings ----------------------
        let mut extended_nodes: Vec<CodeNode> = Vec::new();

        // 3a. Tests: nodes whose name contains "test" or "spec" and that
        //     reference one of the core symbols.
        let test_nodes = self.find_related_tests(&core_nodes, &seen_ids);
        for node in &test_nodes {
            seen_ids.insert(node.id.clone());
        }
        extended_nodes.extend(test_nodes);

        // 3b. Siblings: other nodes in the same file as core nodes.
        let sibling_nodes = self.find_siblings(&core_nodes, &seen_ids);
        for node in &sibling_nodes {
            seen_ids.insert(node.id.clone());
        }
        extended_nodes.extend(sibling_nodes);

        let extended_section =
            self.build_extended_section(&extended_nodes, extended_budget);

        // -- 4. Background: project structure overview --------------------
        let background_section = self.build_background_section(background_budget);

        // -- Assemble the final document ----------------------------------
        let mut sections: Vec<String> = Vec::new();

        if !core_section.is_empty() {
            sections.push(format!("## Core Context\n\n{}", core_section));
        }
        if !near_section.is_empty() {
            sections.push(format!("## Related Symbols\n\n{}", near_section));
        }
        if !extended_section.is_empty() {
            sections.push(format!(
                "## Tests & Siblings\n\n{}",
                extended_section
            ));
        }
        if !background_section.is_empty() {
            sections.push(format!(
                "## Project Structure\n\n{}",
                background_section
            ));
        }

        if sections.is_empty() {
            return String::from("No relevant context found.");
        }

        sections.join("\n\n---\n\n")
    }

    // -------------------------------------------------------------------
    // Section builders
    // -------------------------------------------------------------------

    /// Build the **Core** section: full source of top-ranked nodes.
    fn build_core_section(&self, nodes: &[CodeNode], budget: usize) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut used = 0;

        for node in nodes {
            let formatted = format_node_full(node);
            let tokens = estimate_tokens(&formatted);
            if used + tokens > budget && !parts.is_empty() {
                break;
            }
            parts.push(formatted);
            used += tokens;
        }

        parts.join("\n\n")
    }

    /// Build the **Near** section: compact signatures of neighbors.
    fn build_near_section(&self, nodes: &[CodeNode], budget: usize) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut used = 0;

        for node in nodes {
            let formatted = format_node_signature(node);
            let tokens = estimate_tokens(&formatted);
            if used + tokens > budget && !parts.is_empty() {
                break;
            }
            parts.push(formatted);
            used += tokens;
        }

        parts.join("\n")
    }

    /// Build the **Extended** section: tests and siblings as signatures.
    fn build_extended_section(&self, nodes: &[CodeNode], budget: usize) -> String {
        let mut parts: Vec<String> = Vec::new();
        let mut used = 0;

        for node in nodes {
            let formatted = format_node_signature(node);
            let tokens = estimate_tokens(&formatted);
            if used + tokens > budget && !parts.is_empty() {
                break;
            }
            parts.push(formatted);
            used += tokens;
        }

        parts.join("\n")
    }

    /// Build the **Background** section: file listing overview.
    fn build_background_section(&self, budget: usize) -> String {
        let files = self.get_distinct_files();
        if files.is_empty() {
            return String::new();
        }

        let mut listing = String::from("Files in project:\n");
        for file in &files {
            let line = format!("- {}\n", file);
            if estimate_tokens(&listing) + estimate_tokens(&line) > budget {
                break;
            }
            listing.push_str(&line);
        }

        truncate_to_fit(&listing, budget)
    }

    // -------------------------------------------------------------------
    // Data loaders
    // -------------------------------------------------------------------

    /// Load a single [`CodeNode`] by ID from the database.
    fn load_node(&self, id: &str) -> Option<CodeNode> {
        self.conn
            .query_row("SELECT * FROM nodes WHERE id = ?1", params![id], |row| {
                row_to_code_node(row)
            })
            .ok()
    }

    /// Get the IDs of all direct callers and callees of `node_id`.
    fn get_neighbor_ids(&self, node_id: &str) -> Vec<String> {
        let mut ids: Vec<String> = Vec::new();

        // Outgoing edges: node_id -> target.
        if let Ok(mut stmt) = self
            .conn
            .prepare_cached("SELECT target_id FROM edges WHERE source_id = ?1")
        {
            if let Ok(rows) = stmt.query_map(params![node_id], |row| row.get::<_, String>(0)) {
                for row in rows.flatten() {
                    ids.push(row);
                }
            }
        }

        // Incoming edges: source -> node_id.
        if let Ok(mut stmt) = self
            .conn
            .prepare_cached("SELECT source_id FROM edges WHERE target_id = ?1")
        {
            if let Ok(rows) = stmt.query_map(params![node_id], |row| row.get::<_, String>(0)) {
                for row in rows.flatten() {
                    ids.push(row);
                }
            }
        }

        ids
    }

    /// Find test-related nodes that reference one of `core_nodes`.
    ///
    /// A node is considered test-related if its name contains "test" or
    /// "spec" (case-insensitive) **and** it has an edge connecting it to
    /// one of the core symbols.
    fn find_related_tests(
        &self,
        core_nodes: &[CodeNode],
        seen: &HashSet<String>,
    ) -> Vec<CodeNode> {
        let mut tests: Vec<CodeNode> = Vec::new();

        // Collect all core IDs for fast lookup.
        let core_ids: HashSet<&str> = core_nodes.iter().map(|n| n.id.as_str()).collect();

        // Query for test/spec nodes.
        let sql = "SELECT * FROM nodes WHERE LOWER(name) LIKE '%test%' OR LOWER(name) LIKE '%spec%'";
        let mut stmt = match self.conn.prepare(sql) {
            Ok(s) => s,
            Err(_) => return tests,
        };

        let rows = match stmt.query_and_then([], row_to_code_node) {
            Ok(r) => r,
            Err(_) => return tests,
        };

        for row_result in rows {
            let node = match row_result {
                Ok(n) => n,
                Err(_) => continue,
            };

            if seen.contains(&node.id) {
                continue;
            }

            // Check if this test node has an edge to/from any core node.
            let references_core = self.node_references_any(&node.id, &core_ids);
            if references_core {
                tests.push(node);
            }
        }

        tests
    }

    /// Check whether `node_id` has any edge connecting it to one of the
    /// `target_ids`.
    fn node_references_any(&self, node_id: &str, target_ids: &HashSet<&str>) -> bool {
        // Check outgoing.
        if let Ok(mut stmt) = self
            .conn
            .prepare_cached("SELECT target_id FROM edges WHERE source_id = ?1")
        {
            if let Ok(rows) = stmt.query_map(params![node_id], |row| row.get::<_, String>(0)) {
                for row in rows.flatten() {
                    if target_ids.contains(row.as_str()) {
                        return true;
                    }
                }
            }
        }

        // Check incoming.
        if let Ok(mut stmt) = self
            .conn
            .prepare_cached("SELECT source_id FROM edges WHERE target_id = ?1")
        {
            if let Ok(rows) = stmt.query_map(params![node_id], |row| row.get::<_, String>(0)) {
                for row in rows.flatten() {
                    if target_ids.contains(row.as_str()) {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Find sibling nodes: other nodes in the same files as `core_nodes`.
    fn find_siblings(
        &self,
        core_nodes: &[CodeNode],
        seen: &HashSet<String>,
    ) -> Vec<CodeNode> {
        let files: HashSet<&str> = core_nodes.iter().map(|n| n.file_path.as_str()).collect();
        let mut siblings: Vec<CodeNode> = Vec::new();

        for file in files {
            let sql = "SELECT * FROM nodes WHERE file_path = ?1";
            let mut stmt = match self.conn.prepare(sql) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let rows = match stmt.query_and_then(params![file], row_to_code_node) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for row_result in rows {
                if let Ok(node) = row_result {
                    if !seen.contains(&node.id) {
                        siblings.push(node);
                    }
                }
            }
        }

        siblings
    }

    /// Get all distinct file paths from the nodes table, sorted.
    fn get_distinct_files(&self) -> Vec<String> {
        let sql = "SELECT DISTINCT file_path FROM nodes ORDER BY file_path";
        let mut stmt = match self.conn.prepare(sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = match stmt.query_map([], |row| row.get::<_, String>(0)) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        rows.flatten().collect()
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/// Format a node with its full body inside a fenced code block.
///
/// ```text
/// ### `function` **greet** (`src/hello.ts:10-15`)
///
/// ```ts
/// function greet(name: string): void {
///   console.log(`Hello, ${name}`);
/// }
/// ```
/// ```
fn format_node_full(node: &CodeNode) -> String {
    let tag = language_tag(node.language.as_str());
    let location = format!(
        "{}:{}-{}",
        node.file_path, node.start_line, node.end_line
    );
    let header = format!(
        "### `{}` **{}** (`{}`)",
        node.kind.as_str(),
        node.name,
        location,
    );

    let body = node
        .body
        .as_deref()
        .unwrap_or("// source not available");

    // Include documentation if present.
    let doc_line = node
        .documentation
        .as_deref()
        .map(|d| format!("\n> {}\n", d.lines().next().unwrap_or("")))
        .unwrap_or_default();

    format!(
        "{}{}\n\n```{}\n{}\n```",
        header, doc_line, tag, body
    )
}

/// Format a node as a compact one-line signature.
///
/// ```text
/// - `function` **greet** (`src/hello.ts:10`) — `function greet(name: string): void`
/// ```
fn format_node_signature(node: &CodeNode) -> String {
    let sig = node
        .body
        .as_deref()
        .map(signature_only)
        .unwrap_or_else(|| node.name.clone());

    format!(
        "- `{}` **{}** (`{}:{}`) -- `{}`",
        node.kind.as_str(),
        node.name,
        node.file_path,
        node.start_line,
        sig,
    )
}

/// Map a language string to the appropriate Markdown fence tag.
fn language_tag(lang: &str) -> &str {
    match lang {
        "typescript" | "tsx" => "ts",
        "javascript" | "jsx" => "js",
        "python" => "py",
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::initialize_database;
    use crate::graph::store::GraphStore;
    use crate::types::{CodeEdge, CodeNode, EdgeKind, Language, NodeKind};

    /// Spin up an in-memory store with the full schema applied.
    fn setup() -> GraphStore {
        let conn =
            initialize_database(":memory:").expect("schema init should succeed on :memory:");
        GraphStore::from_connection(conn)
    }

    /// Build a minimal test node.
    fn make_node(
        id: &str,
        name: &str,
        file: &str,
        kind: NodeKind,
        line: u32,
        body: Option<&str>,
        doc: Option<&str>,
    ) -> CodeNode {
        CodeNode {
            id: id.to_string(),
            name: name.to_string(),
            kind,
            file_path: file.to_string(),
            start_line: line,
            end_line: line + 5,
            start_column: 0,
            end_column: 1,
            language: Language::TypeScript,
            body: body.map(|s| s.to_string()),
            documentation: doc.map(|d| d.to_string()),
            exported: Some(true),
        }
    }

    /// Build a minimal test edge.
    fn make_edge(source: &str, target: &str, kind: EdgeKind) -> CodeEdge {
        CodeEdge {
            source: source.to_string(),
            target: target.to_string(),
            kind,
            file_path: String::new(),
            line: 0,
            metadata: None,
        }
    }

    // -- format_node_full -------------------------------------------------

    #[test]
    fn format_node_full_with_body_and_docs() {
        let node = make_node(
            "fn:a.ts:greet:1",
            "greet",
            "a.ts",
            NodeKind::Function,
            1,
            Some("function greet(name: string) {\n  console.log(name);\n}"),
            Some("Say hello to someone."),
        );

        let formatted = format_node_full(&node);
        assert!(formatted.contains("### `function` **greet**"));
        assert!(formatted.contains("```ts"));
        assert!(formatted.contains("function greet(name: string)"));
        assert!(formatted.contains("> Say hello to someone."));
    }

    #[test]
    fn format_node_full_without_body() {
        let node = make_node(
            "fn:a.ts:greet:1",
            "greet",
            "a.ts",
            NodeKind::Function,
            1,
            None,
            None,
        );

        let formatted = format_node_full(&node);
        assert!(formatted.contains("// source not available"));
    }

    // -- format_node_signature --------------------------------------------

    #[test]
    fn format_node_signature_with_body() {
        let node = make_node(
            "fn:a.ts:greet:1",
            "greet",
            "a.ts",
            NodeKind::Function,
            1,
            Some("function greet(name: string) {\n  console.log(name);\n}"),
            None,
        );

        let sig = format_node_signature(&node);
        assert!(sig.contains("**greet**"));
        assert!(sig.contains("function greet(name: string)"));
        // Should NOT contain the body.
        assert!(!sig.contains("console.log"));
    }

    #[test]
    fn format_node_signature_without_body() {
        let node = make_node(
            "fn:a.ts:greet:1",
            "greet",
            "a.ts",
            NodeKind::Function,
            1,
            None,
            None,
        );

        let sig = format_node_signature(&node);
        // Falls back to the node name.
        assert!(sig.contains("greet"));
    }

    // -- language_tag -----------------------------------------------------

    #[test]
    fn language_tag_mappings() {
        assert_eq!(language_tag("typescript"), "ts");
        assert_eq!(language_tag("tsx"), "ts");
        assert_eq!(language_tag("javascript"), "js");
        assert_eq!(language_tag("jsx"), "js");
        assert_eq!(language_tag("python"), "py");
        assert_eq!(language_tag("rust"), "rust");
    }

    // -- assemble_context (integration) -----------------------------------

    #[test]
    fn assemble_context_returns_something_for_matching_query() {
        let store = setup();

        store
            .upsert_node(&make_node(
                "fn:a.ts:greet:1",
                "greet",
                "a.ts",
                NodeKind::Function,
                1,
                Some("function greet(name: string) {\n  console.log(name);\n}"),
                Some("Say hello."),
            ))
            .unwrap();

        let search = HybridSearch::new(&store.conn);
        let assembler = ContextAssembler::new(&store.conn, &search);

        let ctx = assembler.assemble_context("greet", None);
        assert!(ctx.contains("greet"));
        assert!(ctx.contains("## Core Context"));
    }

    #[test]
    fn assemble_context_returns_fallback_for_no_match() {
        let store = setup();
        let search = HybridSearch::new(&store.conn);
        let assembler = ContextAssembler::new(&store.conn, &search);

        let ctx = assembler.assemble_context("nonexistent", None);
        assert_eq!(ctx, "No relevant context found.");
    }

    #[test]
    fn assemble_context_includes_near_section() {
        let store = setup();

        // Create two nodes with an edge between them.
        store
            .upsert_node(&make_node(
                "fn:a.ts:greet:1",
                "greet",
                "a.ts",
                NodeKind::Function,
                1,
                Some("function greet() {}"),
                None,
            ))
            .unwrap();
        store
            .upsert_node(&make_node(
                "fn:a.ts:helper:10",
                "helper",
                "a.ts",
                NodeKind::Function,
                10,
                Some("function helper() {}"),
                None,
            ))
            .unwrap();
        store.upsert_edge(&make_edge("fn:a.ts:greet:1", "fn:a.ts:helper:10", EdgeKind::Calls)).unwrap();

        let search = HybridSearch::new(&store.conn);
        let assembler = ContextAssembler::new(&store.conn, &search);

        let ctx = assembler.assemble_context("greet", None);
        // The "helper" node should appear in the related symbols section.
        assert!(ctx.contains("helper"));
    }

    #[test]
    fn assemble_context_includes_tests_section() {
        let store = setup();

        store
            .upsert_node(&make_node(
                "fn:a.ts:greet:1",
                "greet",
                "a.ts",
                NodeKind::Function,
                1,
                Some("function greet() {}"),
                None,
            ))
            .unwrap();
        store
            .upsert_node(&make_node(
                "fn:a.test.ts:test_greet:1",
                "test_greet",
                "a.test.ts",
                NodeKind::Function,
                1,
                Some("function test_greet() {}"),
                None,
            ))
            .unwrap();
        store
            .upsert_edge(&make_edge(
                "fn:a.test.ts:test_greet:1",
                "fn:a.ts:greet:1",
                EdgeKind::Calls,
            ))
            .unwrap();

        let search = HybridSearch::new(&store.conn);
        let assembler = ContextAssembler::new(&store.conn, &search);

        let ctx = assembler.assemble_context("greet", None);
        assert!(ctx.contains("test_greet"));
    }

    #[test]
    fn assemble_context_includes_siblings() {
        let store = setup();

        store
            .upsert_node(&make_node(
                "fn:a.ts:greet:1",
                "greet",
                "a.ts",
                NodeKind::Function,
                1,
                Some("function greet() {}"),
                None,
            ))
            .unwrap();
        store
            .upsert_node(&make_node(
                "fn:a.ts:farewell:20",
                "farewell",
                "a.ts",
                NodeKind::Function,
                20,
                Some("function farewell() {}"),
                None,
            ))
            .unwrap();

        let search = HybridSearch::new(&store.conn);
        let assembler = ContextAssembler::new(&store.conn, &search);

        let ctx = assembler.assemble_context("greet", None);
        // "farewell" is a sibling in the same file.
        assert!(ctx.contains("farewell"));
    }

    #[test]
    fn assemble_context_includes_project_structure() {
        let store = setup();

        store
            .upsert_node(&make_node(
                "fn:a.ts:greet:1",
                "greet",
                "a.ts",
                NodeKind::Function,
                1,
                Some("function greet() {}"),
                None,
            ))
            .unwrap();
        store
            .upsert_node(&make_node(
                "fn:b.ts:other:1",
                "other",
                "b.ts",
                NodeKind::Function,
                1,
                Some("function other() {}"),
                None,
            ))
            .unwrap();

        let search = HybridSearch::new(&store.conn);
        let assembler = ContextAssembler::new(&store.conn, &search);

        let ctx = assembler.assemble_context("greet", None);
        assert!(ctx.contains("## Project Structure"));
        assert!(ctx.contains("a.ts"));
        assert!(ctx.contains("b.ts"));
    }

    #[test]
    fn assemble_context_respects_budget() {
        let store = setup();

        // Insert many nodes to create a large graph.
        for i in 0..50 {
            store
                .upsert_node(&make_node(
                    &format!("fn:a.ts:func{}:{}", i, i),
                    &format!("func{}", i),
                    "a.ts",
                    NodeKind::Function,
                    i,
                    Some(&format!(
                        "function func{}() {{\n  // body line 1\n  // body line 2\n  // body line 3\n}}",
                        i
                    )),
                    None,
                ))
                .unwrap();
        }

        let search = HybridSearch::new(&store.conn);
        let assembler = ContextAssembler::new(&store.conn, &search);

        // Very small budget.
        let ctx = assembler.assemble_context("func", Some(100));
        let tokens = estimate_tokens(&ctx);
        // The output should be reasonably bounded. We allow some overshoot
        // because the first item in each tier is always included, but it
        // should not be wildly over budget.
        assert!(
            tokens < 300,
            "Expected output tokens < 300, got {}",
            tokens
        );
    }
}
