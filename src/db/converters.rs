//! Row-to-struct converters for CodeGraph database queries.
//!
//! Mirrors the TypeScript `db/converters.ts` — converts raw `rusqlite::Row`
//! values into the domain types defined in `crate::types`.

use std::collections::HashMap;

use rusqlite::Row;

use crate::types::{CodeEdge, CodeNode, EdgeKind, Language, NodeKind};

// ---------------------------------------------------------------------------
// Node conversion
// ---------------------------------------------------------------------------

/// Convert a `rusqlite::Row` from a `SELECT * FROM nodes` query into a
/// [`CodeNode`].
///
/// The expected column order is:
/// `id, type, name, file_path, start_line, end_line, start_column,
///  end_column, language, signature, doc_comment, source_hash, metadata`
///
/// The `metadata` column is a JSON string; `body` and `exported` are
/// extracted from it (matching the TypeScript converter behaviour).
pub fn row_to_code_node(row: &Row<'_>) -> rusqlite::Result<CodeNode> {
    let id: String = row.get("id")?;
    let kind_str: String = row.get("type")?;
    let name: String = row.get("name")?;
    let file_path: String = row.get("file_path")?;
    let start_line: u32 = row.get("start_line")?;
    let end_line: u32 = row.get("end_line")?;
    let start_column: u32 = row.get("start_column").unwrap_or(0);
    let end_column: u32 = row.get("end_column").unwrap_or(0);
    let language_str: String = row.get("language")?;
    let doc_comment: Option<String> = row.get("doc_comment")?;
    let metadata_json: Option<String> = row.get("metadata")?;

    // Parse the metadata JSON to extract body / exported, matching the TS
    // converter which reads startColumn, endColumn, body, exported from
    // metadata.
    let meta: HashMap<String, serde_json::Value> = metadata_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let body = meta
        .get("body")
        .and_then(|v| v.as_str())
        .map(String::from);

    let exported = meta.get("exported").and_then(|v| v.as_bool());

    let kind = NodeKind::from_str_loose(&kind_str).unwrap_or(NodeKind::Variable);
    let language = Language::from_str_loose(&language_str).unwrap_or(Language::TypeScript);

    Ok(CodeNode {
        id,
        name,
        kind,
        file_path,
        start_line,
        end_line,
        start_column,
        end_column,
        language,
        body,
        documentation: doc_comment,
        exported,
    })
}

// ---------------------------------------------------------------------------
// Edge conversion
// ---------------------------------------------------------------------------

/// Convert a `rusqlite::Row` from a `SELECT * FROM edges` query into a
/// [`CodeEdge`].
///
/// The expected column order is:
/// `id, source_id, target_id, type, properties`
///
/// The `properties` column is a JSON string; `filePath` and `line` are
/// extracted from it (matching the TypeScript converter behaviour).
pub fn row_to_code_edge(row: &Row<'_>) -> rusqlite::Result<CodeEdge> {
    let source: String = row.get("source_id")?;
    let target: String = row.get("target_id")?;
    let kind_str: String = row.get("type")?;
    let properties_json: Option<String> = row.get("properties")?;

    let props: HashMap<String, String> = properties_json
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    let file_path = props.get("filePath").cloned().unwrap_or_default();
    let line: u32 = props
        .get("line")
        .and_then(|l| l.parse().ok())
        .unwrap_or(0);

    let kind = EdgeKind::from_str_loose(&kind_str).unwrap_or(EdgeKind::References);

    let metadata = if props.is_empty() {
        None
    } else {
        Some(props)
    };

    Ok(CodeEdge {
        source,
        target,
        kind,
        file_path,
        line,
        metadata,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::initialize_database;

    /// Helper: spin up an in-memory DB and return a connection.
    fn setup() -> rusqlite::Connection {
        initialize_database(":memory:").expect("schema init should succeed")
    }

    #[test]
    fn round_trip_node() {
        let conn = setup();

        let meta = serde_json::json!({
            "body": "function hello() {}",
            "exported": true,
        });

        conn.execute(
            "INSERT INTO nodes \
             (id, type, name, file_path, start_line, end_line, start_column, end_column, language, signature, doc_comment, source_hash, metadata) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                "function:src/main.ts:hello:1",
                "function",
                "hello",
                "src/main.ts",
                1,
                5,
                0,
                1,
                "typescript",
                "hello(): void",
                "Says hello",
                "abc123",
                meta.to_string(),
            ],
        )
        .unwrap();

        let node = conn
            .query_row("SELECT * FROM nodes WHERE id = ?1", ["function:src/main.ts:hello:1"], |row| {
                row_to_code_node(row)
            })
            .unwrap();

        assert_eq!(node.id, "function:src/main.ts:hello:1");
        assert_eq!(node.name, "hello");
        assert_eq!(node.kind, NodeKind::Function);
        assert_eq!(node.file_path, "src/main.ts");
        assert_eq!(node.start_line, 1);
        assert_eq!(node.end_line, 5);
        assert_eq!(node.start_column, 0);
        assert_eq!(node.end_column, 1);
        assert_eq!(node.language, Language::TypeScript);
        assert_eq!(node.body.as_deref(), Some("function hello() {}"));
        assert_eq!(node.documentation.as_deref(), Some("Says hello"));
        assert_eq!(node.exported, Some(true));
    }

    #[test]
    fn round_trip_edge() {
        let conn = setup();

        // Insert two nodes first (foreign key targets).
        for (id, name) in &[("n1", "alpha"), ("n2", "beta")] {
            conn.execute(
                "INSERT INTO nodes (id, type, name, file_path, start_line, end_line, language, source_hash) \
                 VALUES (?1, 'function', ?2, 'src/lib.ts', 1, 10, 'typescript', 'hash')",
                rusqlite::params![id, name],
            )
            .unwrap();
        }

        let props = serde_json::json!({
            "filePath": "src/lib.ts",
            "line": "7",
        });

        conn.execute(
            "INSERT INTO edges (source_id, target_id, type, properties) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["n1", "n2", "calls", props.to_string()],
        )
        .unwrap();

        let edge = conn
            .query_row(
                "SELECT * FROM edges WHERE source_id = 'n1' AND target_id = 'n2'",
                [],
                |row| row_to_code_edge(row),
            )
            .unwrap();

        assert_eq!(edge.source, "n1");
        assert_eq!(edge.target, "n2");
        assert_eq!(edge.kind, EdgeKind::Calls);
        assert_eq!(edge.file_path, "src/lib.ts");
        assert_eq!(edge.line, 7);
        assert!(edge.metadata.is_some());
    }

    #[test]
    fn node_with_null_metadata() {
        let conn = setup();

        conn.execute(
            "INSERT INTO nodes (id, type, name, file_path, start_line, end_line, language, source_hash) \
             VALUES ('n1', 'class', 'Foo', 'src/foo.ts', 1, 20, 'typescript', 'hash')",
            [],
        )
        .unwrap();

        let node = conn
            .query_row("SELECT * FROM nodes WHERE id = 'n1'", [], |row| {
                row_to_code_node(row)
            })
            .unwrap();

        assert_eq!(node.kind, NodeKind::Class);
        assert!(node.body.is_none());
        assert!(node.exported.is_none());
    }

    #[test]
    fn edge_with_null_properties() {
        let conn = setup();

        for (id, name) in &[("n1", "a"), ("n2", "b")] {
            conn.execute(
                "INSERT INTO nodes (id, type, name, file_path, start_line, end_line, language, source_hash) \
                 VALUES (?1, 'function', ?2, 'x.ts', 1, 2, 'typescript', 'h')",
                rusqlite::params![id, name],
            )
            .unwrap();
        }

        conn.execute(
            "INSERT INTO edges (source_id, target_id, type) VALUES ('n1', 'n2', 'imports')",
            [],
        )
        .unwrap();

        let edge = conn
            .query_row(
                "SELECT * FROM edges WHERE source_id = 'n1'",
                [],
                |row| row_to_code_edge(row),
            )
            .unwrap();

        assert_eq!(edge.kind, EdgeKind::Imports);
        assert_eq!(edge.file_path, "");
        assert_eq!(edge.line, 0);
        assert!(edge.metadata.is_none());
    }
}
