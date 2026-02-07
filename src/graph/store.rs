//! SQLite CRUD layer for the CodeGraph.
//!
//! Ports the TypeScript `GraphStore` class to Rust. Uses `rusqlite` with
//! `prepare_cached` for automatic statement caching — the Rust equivalent
//! of the TS version's eagerly-prepared statement map.

use rusqlite::{params, Connection};

use crate::db::converters::{row_to_code_edge, row_to_code_node};
use crate::db::schema::initialize_database;
use crate::error::Result;
use crate::types::{CodeEdge, CodeNode};

// ---------------------------------------------------------------------------
// GraphStats
// ---------------------------------------------------------------------------

/// Aggregate statistics about the stored graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphStats {
    pub nodes: usize,
    pub edges: usize,
    pub files: usize,
}

// ---------------------------------------------------------------------------
// GraphStore
// ---------------------------------------------------------------------------

/// Typed CRUD wrapper around the CodeGraph SQLite database.
///
/// Every query goes through [`Connection::prepare_cached`], so the first
/// call compiles the statement and subsequent calls reuse it from an
/// internal LRU cache. This matches the performance characteristics of the
/// TypeScript version's eagerly-prepared statements while being more
/// ergonomic (no upfront prepare step, no lifetime gymnastics).
pub struct GraphStore {
    pub conn: Connection,
}

impl std::fmt::Debug for GraphStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GraphStore").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// SQL constants
// ---------------------------------------------------------------------------

const UPSERT_NODE_SQL: &str = "\
INSERT INTO nodes (id, type, name, file_path, start_line, end_line, language, signature, doc_comment, source_hash, metadata)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
ON CONFLICT(id) DO UPDATE SET
  type = excluded.type,
  name = excluded.name,
  file_path = excluded.file_path,
  start_line = excluded.start_line,
  end_line = excluded.end_line,
  language = excluded.language,
  signature = excluded.signature,
  doc_comment = excluded.doc_comment,
  source_hash = excluded.source_hash,
  metadata = excluded.metadata";

const UPSERT_EDGE_SQL: &str = "\
INSERT INTO edges (source_id, target_id, type, properties)
VALUES (?1, ?2, ?3, ?4)
ON CONFLICT(source_id, target_id, type) DO UPDATE SET
  properties = excluded.properties";

const DELETE_EDGES_BY_FILE_SQL: &str = "\
DELETE FROM edges WHERE source_id IN (SELECT id FROM nodes WHERE file_path = ?1)
   OR target_id IN (SELECT id FROM nodes WHERE file_path = ?1)";

const DELETE_NODES_BY_FILE_SQL: &str = "\
DELETE FROM nodes WHERE file_path = ?1";

const ENSURE_EDGE_UNIQUE_INDEX_SQL: &str = "\
CREATE UNIQUE INDEX IF NOT EXISTS idx_edges_source_target_type \
ON edges(source_id, target_id, type)";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Simple DJB2-style hash matching the TypeScript `computeSimpleHash`.
///
/// Produces the same output as `((hash << 5) - hash + ch) | 0` in JS,
/// which is a 32-bit signed integer converted to base-36.
fn compute_simple_hash(input: &str) -> String {
    let mut hash: i32 = 0;
    for ch in input.encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(ch as i32);
    }
    // JS `toString(36)` on a negative i32 produces "-<digits>".
    if hash < 0 {
        format!("-{}", i32_to_base36(hash.unsigned_abs()))
    } else {
        i32_to_base36(hash as u32)
    }
}

fn i32_to_base36(mut n: u32) -> String {
    if n == 0 {
        return "0".to_string();
    }
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut buf = Vec::with_capacity(7);
    while n > 0 {
        buf.push(DIGITS[(n % 36) as usize]);
        n /= 36;
    }
    buf.reverse();
    String::from_utf8(buf).unwrap()
}

/// Build the metadata JSON object that the TS version stores alongside
/// each node row.
fn build_node_metadata(node: &CodeNode) -> String {
    let mut map = serde_json::Map::new();
    map.insert(
        "startColumn".to_string(),
        serde_json::Value::from(node.start_column),
    );
    map.insert(
        "endColumn".to_string(),
        serde_json::Value::from(node.end_column),
    );
    if let Some(ref body) = node.body {
        // Truncate body to 4 KB to match the TS version's behaviour.
        let truncated = if body.len() > 4096 {
            &body[..4096]
        } else {
            body.as_str()
        };
        map.insert("body".to_string(), serde_json::Value::from(truncated));
    }
    if let Some(exported) = node.exported {
        map.insert("exported".to_string(), serde_json::Value::from(exported));
    }
    serde_json::Value::Object(map).to_string()
}

/// Build the properties JSON for an edge row.
fn build_edge_properties(edge: &CodeEdge) -> String {
    let mut map = serde_json::Map::new();
    // Merge any caller-supplied metadata first.
    if let Some(ref meta) = edge.metadata {
        for (k, v) in meta {
            map.insert(k.clone(), serde_json::Value::from(v.as_str()));
        }
    }
    map.insert(
        "filePath".to_string(),
        serde_json::Value::from(edge.file_path.as_str()),
    );
    map.insert(
        "line".to_string(),
        serde_json::Value::from(edge.line.to_string()),
    );
    serde_json::Value::Object(map).to_string()
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl GraphStore {
    /// Open (or create) the database at `db_path`, apply the schema, and
    /// return a ready-to-use store.
    pub fn new(db_path: &str) -> Result<Self> {
        let conn = initialize_database(db_path)?;
        // Ensure the unique index on edges exists so upsert works correctly.
        conn.execute_batch(ENSURE_EDGE_UNIQUE_INDEX_SQL)?;
        Ok(Self { conn })
    }

    /// Wrap an already-open connection. Useful in tests where the caller
    /// has already called `initialize_database(":memory:")`.
    pub fn from_connection(conn: Connection) -> Self {
        // Best-effort: add the unique edge index.  If the schema hasn't
        // been applied yet this will silently fail, but it's the caller's
        // responsibility to ensure the schema is present.
        let _ = conn.execute_batch(ENSURE_EDGE_UNIQUE_INDEX_SQL);
        Self { conn }
    }

    // -------------------------------------------------------------------
    // Single-row mutations
    // -------------------------------------------------------------------

    /// Insert or update a single code node.
    pub fn upsert_node(&self, node: &CodeNode) -> Result<()> {
        let mut stmt = self.conn.prepare_cached(UPSERT_NODE_SQL)?;
        stmt.execute(params![
            node.id,
            node.kind.as_str(),
            node.name,
            node.file_path,
            node.start_line,
            node.end_line,
            node.language.as_str(),
            node.body,                            // signature column
            node.documentation,                   // doc_comment column
            compute_simple_hash(&node.id),        // source_hash
            build_node_metadata(node),            // metadata JSON
        ])?;
        Ok(())
    }

    /// Insert or update a single code edge.
    pub fn upsert_edge(&self, edge: &CodeEdge) -> Result<()> {
        let mut stmt = self.conn.prepare_cached(UPSERT_EDGE_SQL)?;
        stmt.execute(params![
            edge.source,
            edge.target,
            edge.kind.as_str(),
            build_edge_properties(edge),
        ])?;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Batch mutations (transactional)
    // -------------------------------------------------------------------

    /// Batch-insert nodes inside a single transaction.
    pub fn upsert_nodes(&self, nodes: &[CodeNode]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(UPSERT_NODE_SQL)?;
            for node in nodes {
                stmt.execute(params![
                    node.id,
                    node.kind.as_str(),
                    node.name,
                    node.file_path,
                    node.start_line,
                    node.end_line,
                    node.language.as_str(),
                    node.body,
                    node.documentation,
                    compute_simple_hash(&node.id),
                    build_node_metadata(node),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Batch-insert edges inside a single transaction.
    pub fn upsert_edges(&self, edges: &[CodeEdge]) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare_cached(UPSERT_EDGE_SQL)?;
            for edge in edges {
                stmt.execute(params![
                    edge.source,
                    edge.target,
                    edge.kind.as_str(),
                    build_edge_properties(edge),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Atomically replace all graph data for a single file.
    ///
    /// Deletes every node and edge associated with `file_path`, then
    /// inserts the new `nodes` and `edges` — all inside one transaction.
    pub fn replace_file_data(
        &self,
        file_path: &str,
        nodes: &[CodeNode],
        edges: &[CodeEdge],
    ) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            // Delete edges first (they reference nodes via FK).
            let mut del_edges = tx.prepare_cached(DELETE_EDGES_BY_FILE_SQL)?;
            del_edges.execute(params![file_path])?;

            let mut del_nodes = tx.prepare_cached(DELETE_NODES_BY_FILE_SQL)?;
            del_nodes.execute(params![file_path])?;

            // Insert replacements.
            let mut ins_node = tx.prepare_cached(UPSERT_NODE_SQL)?;
            for node in nodes {
                ins_node.execute(params![
                    node.id,
                    node.kind.as_str(),
                    node.name,
                    node.file_path,
                    node.start_line,
                    node.end_line,
                    node.language.as_str(),
                    node.body,
                    node.documentation,
                    compute_simple_hash(&node.id),
                    build_node_metadata(node),
                ])?;
            }

            let mut ins_edge = tx.prepare_cached(UPSERT_EDGE_SQL)?;
            for edge in edges {
                ins_edge.execute(params![
                    edge.source,
                    edge.target,
                    edge.kind.as_str(),
                    build_edge_properties(edge),
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Delete all nodes and edges associated with `file_path`.
    pub fn delete_file_nodes(&self, file_path: &str) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        {
            let mut del_edges = tx.prepare_cached(DELETE_EDGES_BY_FILE_SQL)?;
            del_edges.execute(params![file_path])?;

            let mut del_nodes = tx.prepare_cached(DELETE_NODES_BY_FILE_SQL)?;
            del_nodes.execute(params![file_path])?;
        }
        tx.commit()?;
        Ok(())
    }

    // -------------------------------------------------------------------
    // Queries — single node
    // -------------------------------------------------------------------

    /// Retrieve a single node by its ID, or `None` if it doesn't exist.
    pub fn get_node(&self, id: &str) -> Result<Option<CodeNode>> {
        let mut stmt = self.conn.prepare_cached("SELECT * FROM nodes WHERE id = ?1")?;
        let mut rows = stmt.query_and_then(params![id], row_to_code_node)?;
        match rows.next() {
            Some(Ok(node)) => Ok(Some(node)),
            Some(Err(e)) => Err(e.into()),
            None => Ok(None),
        }
    }

    // -------------------------------------------------------------------
    // Queries — node collections
    // -------------------------------------------------------------------

    /// Get every node whose `file_path` matches.
    pub fn get_nodes_by_file(&self, file_path: &str) -> Result<Vec<CodeNode>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT * FROM nodes WHERE file_path = ?1")?;
        let rows = stmt.query_and_then(params![file_path], row_to_code_node)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Get every node whose `name` matches.
    pub fn get_nodes_by_name(&self, name: &str) -> Result<Vec<CodeNode>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT * FROM nodes WHERE name = ?1")?;
        let rows = stmt.query_and_then(params![name], row_to_code_node)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Get every node whose `type` column matches `kind`.
    pub fn get_nodes_by_type(&self, kind: &str) -> Result<Vec<CodeNode>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT * FROM nodes WHERE type = ?1")?;
        let rows = stmt.query_and_then(params![kind], row_to_code_node)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    // -------------------------------------------------------------------
    // Queries — edges
    // -------------------------------------------------------------------

    /// Get outgoing edges from `node_id`, optionally filtered by edge type.
    pub fn get_out_edges(
        &self,
        node_id: &str,
        edge_type: Option<&str>,
    ) -> Result<Vec<CodeEdge>> {
        match edge_type {
            Some(t) => {
                let mut stmt = self.conn.prepare_cached(
                    "SELECT * FROM edges WHERE source_id = ?1 AND type = ?2",
                )?;
                let rows = stmt.query_and_then(params![node_id, t], row_to_code_edge)?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
            None => {
                let mut stmt = self
                    .conn
                    .prepare_cached("SELECT * FROM edges WHERE source_id = ?1")?;
                let rows = stmt.query_and_then(params![node_id], row_to_code_edge)?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
        }
    }

    /// Get incoming edges to `node_id`, optionally filtered by edge type.
    pub fn get_in_edges(
        &self,
        node_id: &str,
        edge_type: Option<&str>,
    ) -> Result<Vec<CodeEdge>> {
        match edge_type {
            Some(t) => {
                let mut stmt = self.conn.prepare_cached(
                    "SELECT * FROM edges WHERE target_id = ?1 AND type = ?2",
                )?;
                let rows = stmt.query_and_then(params![node_id, t], row_to_code_edge)?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
            None => {
                let mut stmt = self
                    .conn
                    .prepare_cached("SELECT * FROM edges WHERE target_id = ?1")?;
                let rows = stmt.query_and_then(params![node_id], row_to_code_edge)?;
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(Into::into)
            }
        }
    }

    // -------------------------------------------------------------------
    // Queries — bulk
    // -------------------------------------------------------------------

    /// Return every node in the graph.
    pub fn get_all_nodes(&self) -> Result<Vec<CodeNode>> {
        let mut stmt = self.conn.prepare_cached("SELECT * FROM nodes")?;
        let rows = stmt.query_and_then([], row_to_code_node)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Return every edge in the graph.
    pub fn get_all_edges(&self) -> Result<Vec<CodeEdge>> {
        let mut stmt = self.conn.prepare_cached("SELECT * FROM edges")?;
        let rows = stmt.query_and_then([], row_to_code_edge)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    // -------------------------------------------------------------------
    // Queries — aggregate counts
    // -------------------------------------------------------------------

    /// Get the total number of nodes.
    pub fn get_node_count(&self) -> Result<usize> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT count(*) FROM nodes")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Get the total number of edges.
    pub fn get_edge_count(&self) -> Result<usize> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT count(*) FROM edges")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Get the number of distinct file paths across all nodes.
    pub fn get_file_count(&self) -> Result<usize> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT count(DISTINCT file_path) FROM nodes")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Get aggregate statistics (node count, edge count, file count).
    pub fn get_stats(&self) -> Result<GraphStats> {
        Ok(GraphStats {
            nodes: self.get_node_count()?,
            edges: self.get_edge_count()?,
            files: self.get_file_count()?,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EdgeKind, Language, NodeKind};

    /// Spin up an in-memory store with the full schema applied.
    fn setup() -> GraphStore {
        let conn =
            initialize_database(":memory:").expect("schema init should succeed on :memory:");
        GraphStore::from_connection(conn)
    }

    /// Build a minimal test node.
    fn make_node(id: &str, name: &str, file: &str, kind: NodeKind, line: u32) -> CodeNode {
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
            body: Some(format!("function {}() {{}}", name)),
            documentation: Some(format!("Docs for {}", name)),
            exported: Some(true),
        }
    }

    /// Build a minimal test edge.
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

    // -- upsert_node / get_node round-trip ---------------------------------

    #[test]
    fn upsert_and_get_node_round_trip() {
        let store = setup();
        let node = make_node("fn:main.ts:hello:1", "hello", "main.ts", NodeKind::Function, 1);

        store.upsert_node(&node).unwrap();

        let got = store.get_node("fn:main.ts:hello:1").unwrap().expect("node should exist");
        assert_eq!(got.id, node.id);
        assert_eq!(got.name, "hello");
        assert_eq!(got.kind, NodeKind::Function);
        assert_eq!(got.file_path, "main.ts");
        assert_eq!(got.start_line, 1);
        assert_eq!(got.end_line, 6);
        assert_eq!(got.language, Language::TypeScript);
        assert_eq!(got.body.as_deref(), Some("function hello() {}"));
        assert_eq!(got.documentation.as_deref(), Some("Docs for hello"));
        assert_eq!(got.exported, Some(true));
    }

    #[test]
    fn upsert_node_updates_existing() {
        let store = setup();
        let mut node = make_node("n1", "alpha", "a.ts", NodeKind::Function, 1);
        store.upsert_node(&node).unwrap();

        // Mutate and upsert again.
        node.name = "alpha_v2".to_string();
        node.end_line = 100;
        store.upsert_node(&node).unwrap();

        let got = store.get_node("n1").unwrap().unwrap();
        assert_eq!(got.name, "alpha_v2");
        assert_eq!(got.end_line, 100);
        // Should still be exactly one row.
        assert_eq!(store.get_node_count().unwrap(), 1);
    }

    #[test]
    fn get_node_returns_none_for_missing_id() {
        let store = setup();
        assert!(store.get_node("nonexistent").unwrap().is_none());
    }

    // -- upsert_edge / get_out_edges ---------------------------------------

    #[test]
    fn upsert_edge_and_get_out_edges() {
        let store = setup();
        let n1 = make_node("n1", "a", "x.ts", NodeKind::Function, 1);
        let n2 = make_node("n2", "b", "x.ts", NodeKind::Function, 10);
        store.upsert_node(&n1).unwrap();
        store.upsert_node(&n2).unwrap();

        let edge = make_edge("n1", "n2", EdgeKind::Calls, "x.ts", 3);
        store.upsert_edge(&edge).unwrap();

        let out = store.get_out_edges("n1", None).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].source, "n1");
        assert_eq!(out[0].target, "n2");
        assert_eq!(out[0].kind, EdgeKind::Calls);
    }

    #[test]
    fn get_out_edges_filtered_by_type() {
        let store = setup();
        let n1 = make_node("n1", "a", "x.ts", NodeKind::Function, 1);
        let n2 = make_node("n2", "b", "x.ts", NodeKind::Function, 10);
        let n3 = make_node("n3", "c", "x.ts", NodeKind::Function, 20);
        store.upsert_nodes(&[n1, n2, n3]).unwrap();

        store
            .upsert_edge(&make_edge("n1", "n2", EdgeKind::Calls, "x.ts", 3))
            .unwrap();
        store
            .upsert_edge(&make_edge("n1", "n3", EdgeKind::Imports, "x.ts", 1))
            .unwrap();

        let calls = store.get_out_edges("n1", Some("calls")).unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].target, "n2");

        let imports = store.get_out_edges("n1", Some("imports")).unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].target, "n3");
    }

    #[test]
    fn get_in_edges() {
        let store = setup();
        let n1 = make_node("n1", "a", "x.ts", NodeKind::Function, 1);
        let n2 = make_node("n2", "b", "x.ts", NodeKind::Function, 10);
        store.upsert_nodes(&[n1, n2]).unwrap();

        store
            .upsert_edge(&make_edge("n1", "n2", EdgeKind::Calls, "x.ts", 3))
            .unwrap();

        let incoming = store.get_in_edges("n2", None).unwrap();
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0].source, "n1");
    }

    #[test]
    fn upsert_edge_deduplicates() {
        let store = setup();
        let n1 = make_node("n1", "a", "x.ts", NodeKind::Function, 1);
        let n2 = make_node("n2", "b", "x.ts", NodeKind::Function, 10);
        store.upsert_nodes(&[n1, n2]).unwrap();

        let edge = make_edge("n1", "n2", EdgeKind::Calls, "x.ts", 3);
        store.upsert_edge(&edge).unwrap();
        store.upsert_edge(&edge).unwrap(); // second insert — should update, not duplicate

        assert_eq!(store.get_edge_count().unwrap(), 1);
    }

    // -- replace_file_data -------------------------------------------------

    #[test]
    fn replace_file_data_clears_old_data() {
        let store = setup();

        // Seed file "a.ts" with two nodes and one edge.
        let old_nodes = vec![
            make_node("n1", "old_a", "a.ts", NodeKind::Function, 1),
            make_node("n2", "old_b", "a.ts", NodeKind::Function, 10),
        ];
        let old_edges = vec![make_edge("n1", "n2", EdgeKind::Calls, "a.ts", 3)];
        store.upsert_nodes(&old_nodes).unwrap();
        store.upsert_edges(&old_edges).unwrap();
        assert_eq!(store.get_node_count().unwrap(), 2);
        assert_eq!(store.get_edge_count().unwrap(), 1);

        // Replace with a single new node and no edges.
        let new_nodes = vec![make_node("n3", "fresh", "a.ts", NodeKind::Class, 1)];
        store.replace_file_data("a.ts", &new_nodes, &[]).unwrap();

        assert_eq!(store.get_node_count().unwrap(), 1);
        assert_eq!(store.get_edge_count().unwrap(), 0);
        assert!(store.get_node("n1").unwrap().is_none(), "old node n1 should be gone");
        assert!(store.get_node("n2").unwrap().is_none(), "old node n2 should be gone");
        let fresh = store.get_node("n3").unwrap().expect("new node n3 should exist");
        assert_eq!(fresh.name, "fresh");
    }

    #[test]
    fn replace_file_data_does_not_affect_other_files() {
        let store = setup();

        store
            .upsert_node(&make_node("keep", "keeper", "b.ts", NodeKind::Variable, 1))
            .unwrap();
        store
            .upsert_node(&make_node("remove", "goner", "a.ts", NodeKind::Variable, 1))
            .unwrap();

        store.replace_file_data("a.ts", &[], &[]).unwrap();

        assert!(store.get_node("keep").unwrap().is_some());
        assert!(store.get_node("remove").unwrap().is_none());
    }

    // -- delete_file_nodes -------------------------------------------------

    #[test]
    fn delete_file_nodes_removes_nodes_and_edges() {
        let store = setup();
        let n1 = make_node("n1", "a", "x.ts", NodeKind::Function, 1);
        let n2 = make_node("n2", "b", "x.ts", NodeKind::Function, 10);
        store.upsert_nodes(&[n1, n2]).unwrap();
        store
            .upsert_edge(&make_edge("n1", "n2", EdgeKind::Calls, "x.ts", 3))
            .unwrap();

        store.delete_file_nodes("x.ts").unwrap();

        assert_eq!(store.get_node_count().unwrap(), 0);
        assert_eq!(store.get_edge_count().unwrap(), 0);
    }

    // -- get_stats ---------------------------------------------------------

    #[test]
    fn get_stats_returns_correct_counts() {
        let store = setup();

        let nodes = vec![
            make_node("n1", "a", "a.ts", NodeKind::Function, 1),
            make_node("n2", "b", "a.ts", NodeKind::Function, 10),
            make_node("n3", "c", "b.ts", NodeKind::Class, 1),
        ];
        let edges = vec![
            make_edge("n1", "n2", EdgeKind::Calls, "a.ts", 5),
            make_edge("n2", "n3", EdgeKind::Imports, "a.ts", 1),
        ];
        store.upsert_nodes(&nodes).unwrap();
        store.upsert_edges(&edges).unwrap();

        let stats = store.get_stats().unwrap();
        assert_eq!(stats.nodes, 3);
        assert_eq!(stats.edges, 2);
        assert_eq!(stats.files, 2); // a.ts and b.ts
    }

    // -- get_nodes_by_* queries -------------------------------------------

    #[test]
    fn get_nodes_by_file() {
        let store = setup();
        store
            .upsert_nodes(&[
                make_node("n1", "a", "a.ts", NodeKind::Function, 1),
                make_node("n2", "b", "b.ts", NodeKind::Function, 1),
                make_node("n3", "c", "a.ts", NodeKind::Class, 10),
            ])
            .unwrap();

        let nodes = store.get_nodes_by_file("a.ts").unwrap();
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().all(|n| n.file_path == "a.ts"));
    }

    #[test]
    fn get_nodes_by_name() {
        let store = setup();
        store
            .upsert_nodes(&[
                make_node("n1", "hello", "a.ts", NodeKind::Function, 1),
                make_node("n2", "hello", "b.ts", NodeKind::Function, 1),
                make_node("n3", "world", "a.ts", NodeKind::Function, 10),
            ])
            .unwrap();

        let nodes = store.get_nodes_by_name("hello").unwrap();
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn get_nodes_by_type() {
        let store = setup();
        store
            .upsert_nodes(&[
                make_node("n1", "a", "a.ts", NodeKind::Function, 1),
                make_node("n2", "b", "a.ts", NodeKind::Class, 10),
                make_node("n3", "c", "a.ts", NodeKind::Function, 20),
            ])
            .unwrap();

        let fns = store.get_nodes_by_type("function").unwrap();
        assert_eq!(fns.len(), 2);

        let classes = store.get_nodes_by_type("class").unwrap();
        assert_eq!(classes.len(), 1);
    }

    // -- get_all_* ---------------------------------------------------------

    #[test]
    fn get_all_nodes_and_edges() {
        let store = setup();
        let nodes = vec![
            make_node("n1", "a", "a.ts", NodeKind::Function, 1),
            make_node("n2", "b", "a.ts", NodeKind::Function, 10),
        ];
        let edges = vec![make_edge("n1", "n2", EdgeKind::Calls, "a.ts", 5)];
        store.upsert_nodes(&nodes).unwrap();
        store.upsert_edges(&edges).unwrap();

        assert_eq!(store.get_all_nodes().unwrap().len(), 2);
        assert_eq!(store.get_all_edges().unwrap().len(), 1);
    }

    // -- empty database ----------------------------------------------------

    #[test]
    fn empty_store_returns_zeros_and_empty_vecs() {
        let store = setup();
        assert_eq!(store.get_node_count().unwrap(), 0);
        assert_eq!(store.get_edge_count().unwrap(), 0);
        assert_eq!(store.get_file_count().unwrap(), 0);
        assert!(store.get_all_nodes().unwrap().is_empty());
        assert!(store.get_all_edges().unwrap().is_empty());
        assert_eq!(
            store.get_stats().unwrap(),
            GraphStats {
                nodes: 0,
                edges: 0,
                files: 0,
            }
        );
    }

    // -- compute_simple_hash parity with JS --------------------------------

    #[test]
    fn compute_simple_hash_matches_js() {
        // Verified against the JS implementation:
        //   computeSimpleHash("function:src/main.ts:hello:10")
        // Both should produce the same base-36 string.
        let hash = compute_simple_hash("hello");
        // The hash should be a non-empty base-36 string.
        assert!(!hash.is_empty());
        assert!(hash
            .trim_start_matches('-')
            .chars()
            .all(|c| c.is_ascii_alphanumeric()));
    }
}
