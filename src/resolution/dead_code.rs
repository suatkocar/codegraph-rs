//! Dead code detection — finds symbols with no incoming references.
//!
//! A symbol is considered "dead" if no other node in the graph references,
//! calls, imports, extends, or implements it. Exported symbols, entry points,
//! and test functions are excluded by default.

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::types::NodeKind;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A symbol identified as potentially dead code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadCodeResult {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub file_path: String,
    pub start_line: u32,
}

// ---------------------------------------------------------------------------
// SQL
// ---------------------------------------------------------------------------

/// Find nodes with no incoming edges, excluding:
/// 1. Exported symbols (metadata contains `"exported":true`)
/// 2. Entry points (name = 'main')
/// 3. Test functions (name starts with 'test' or file in test paths)
/// 4. Module nodes (modules are structural, not callable)
///
/// Kind filtering is applied in Rust after the query for simplicity,
/// since rusqlite doesn't support rarray out of the box.
const DEAD_CODE_ALL_SQL: &str = "\
SELECT n.id, n.name, n.type, n.file_path, n.start_line
FROM nodes n
LEFT JOIN edges e ON e.target_id = n.id
WHERE e.id IS NULL
  AND (n.metadata IS NULL OR json_extract(n.metadata, '$.exported') IS NOT true)
  AND n.name != 'main'
  AND n.name NOT LIKE 'test%'
  AND n.file_path NOT LIKE '%test%'
  AND n.file_path NOT LIKE '%spec%'
  AND n.file_path NOT LIKE '%__tests__%'
  AND n.type != 'module'
ORDER BY n.file_path ASC, n.start_line ASC";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Find symbols with no incoming edges (potentially dead code).
///
/// If `kinds` is empty, all node kinds are checked (except modules).
/// Otherwise, only nodes matching the specified kinds are returned.
///
/// Exclusions applied automatically:
/// - Exported symbols (`exported: true` in metadata)
/// - Entry points (`main`)
/// - Test functions (name starting with `test`)
/// - Symbols in test directories
/// - Module nodes
pub fn find_dead_code(conn: &Connection, kinds: &[NodeKind]) -> Vec<DeadCodeResult> {
    let all_results = match find_dead_code_inner(conn) {
        Ok(results) => results,
        Err(_) => return Vec::new(),
    };

    if kinds.is_empty() {
        return all_results;
    }

    // Filter by requested kinds
    let kind_strs: Vec<&str> = kinds.iter().map(|k| k.as_str()).collect();
    all_results
        .into_iter()
        .filter(|r| kind_strs.contains(&r.kind.as_str()))
        .collect()
}

fn find_dead_code_inner(conn: &Connection) -> crate::error::Result<Vec<DeadCodeResult>> {
    let mut stmt = conn.prepare_cached(DEAD_CODE_ALL_SQL)?;
    let rows = stmt.query_map([], |row| {
        Ok(DeadCodeResult {
            id: row.get(0)?,
            name: row.get(1)?,
            kind: row.get(2)?,
            file_path: row.get(3)?,
            start_line: row.get(4)?,
        })
    })?;

    let mut results = Vec::new();
    for row in rows {
        if let Ok(r) = row {
            results.push(r);
        }
    }
    Ok(results)
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

    fn setup() -> GraphStore {
        let conn = initialize_database(":memory:").expect("schema init");
        GraphStore::from_connection(conn)
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

    #[test]
    fn finds_unreferenced_function() {
        let store = setup();
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

        let dead = find_dead_code(&store.conn, &[]);

        // n2 (unusedFunc) and n3 (caller) have no incoming edges,
        // but n1 (usedFunc) is called by n3 so it should not appear
        let names: Vec<&str> = dead.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"unusedFunc"), "unusedFunc should be dead code");
        assert!(names.contains(&"caller"), "caller has no incoming edges");
        assert!(!names.contains(&"usedFunc"), "usedFunc is referenced");
    }

    #[test]
    fn excludes_exported_symbols() {
        let store = setup();
        store
            .upsert_nodes(&[
                make_node("n1", "publicApi", "src/api.ts", NodeKind::Function, 1, Some(true)),
                make_node("n2", "privateHelper", "src/api.ts", NodeKind::Function, 10, None),
            ])
            .unwrap();

        let dead = find_dead_code(&store.conn, &[]);

        let names: Vec<&str> = dead.iter().map(|d| d.name.as_str()).collect();
        assert!(!names.contains(&"publicApi"), "exported symbols should be excluded");
        assert!(names.contains(&"privateHelper"), "non-exported should be found");
    }

    #[test]
    fn excludes_main_entry_point() {
        let store = setup();
        store
            .upsert_node(&make_node("n1", "main", "src/main.ts", NodeKind::Function, 1, None))
            .unwrap();

        let dead = find_dead_code(&store.conn, &[]);
        assert!(dead.is_empty(), "main should be excluded");
    }

    #[test]
    fn excludes_test_functions() {
        let store = setup();
        store
            .upsert_nodes(&[
                make_node("n1", "testSomething", "src/a.ts", NodeKind::Function, 1, None),
                make_node("n2", "helper", "src/__tests__/a.test.ts", NodeKind::Function, 1, None),
            ])
            .unwrap();

        let dead = find_dead_code(&store.conn, &[]);
        assert!(dead.is_empty(), "test functions and test files should be excluded");
    }

    #[test]
    fn excludes_module_nodes() {
        let store = setup();
        store
            .upsert_node(&make_node("m1", "utils", "src/utils.ts", NodeKind::Module, 1, None))
            .unwrap();

        let dead = find_dead_code(&store.conn, &[]);
        assert!(dead.is_empty(), "module nodes should be excluded");
    }

    #[test]
    fn filters_by_kind() {
        let store = setup();
        store
            .upsert_nodes(&[
                make_node("n1", "unusedFunc", "src/a.ts", NodeKind::Function, 1, None),
                make_node("n2", "UnusedClass", "src/b.ts", NodeKind::Class, 1, None),
                make_node("n3", "unusedVar", "src/c.ts", NodeKind::Variable, 1, None),
            ])
            .unwrap();

        let dead_funcs = find_dead_code(&store.conn, &[NodeKind::Function]);
        assert_eq!(dead_funcs.len(), 1);
        assert_eq!(dead_funcs[0].name, "unusedFunc");

        let dead_classes = find_dead_code(&store.conn, &[NodeKind::Class]);
        assert_eq!(dead_classes.len(), 1);
        assert_eq!(dead_classes[0].name, "UnusedClass");

        let dead_fn_class = find_dead_code(&store.conn, &[NodeKind::Function, NodeKind::Class]);
        assert_eq!(dead_fn_class.len(), 2);
    }

    #[test]
    fn returns_correct_fields() {
        let store = setup();
        store
            .upsert_node(&make_node(
                "function:src/lib.ts:orphan:42",
                "orphan",
                "src/lib.ts",
                NodeKind::Function,
                42,
                None,
            ))
            .unwrap();

        let dead = find_dead_code(&store.conn, &[]);
        assert_eq!(dead.len(), 1);
        assert_eq!(dead[0].id, "function:src/lib.ts:orphan:42");
        assert_eq!(dead[0].name, "orphan");
        assert_eq!(dead[0].kind, "function");
        assert_eq!(dead[0].file_path, "src/lib.ts");
        assert_eq!(dead[0].start_line, 42);
    }

    #[test]
    fn empty_graph_returns_empty() {
        let store = setup();
        let dead = find_dead_code(&store.conn, &[]);
        assert!(dead.is_empty());
    }

    #[test]
    fn all_referenced_means_no_dead_code() {
        let store = setup();
        store
            .upsert_nodes(&[
                make_node("n1", "alpha", "src/a.ts", NodeKind::Function, 1, None),
                make_node("n2", "beta", "src/b.ts", NodeKind::Function, 1, None),
            ])
            .unwrap();
        // Mutual references — both have incoming edges
        store.upsert_edge(&make_edge("n1", "n2", EdgeKind::Calls, "src/a.ts", 5)).unwrap();
        store.upsert_edge(&make_edge("n2", "n1", EdgeKind::Calls, "src/b.ts", 5)).unwrap();

        let dead = find_dead_code(&store.conn, &[]);
        assert!(dead.is_empty(), "mutually referenced nodes should not be dead");
    }

    #[test]
    fn ordered_by_file_then_line() {
        let store = setup();
        store
            .upsert_nodes(&[
                make_node("n3", "gamma", "src/z.ts", NodeKind::Function, 1, None),
                make_node("n1", "alpha", "src/a.ts", NodeKind::Function, 10, None),
                make_node("n2", "beta", "src/a.ts", NodeKind::Function, 5, None),
            ])
            .unwrap();

        let dead = find_dead_code(&store.conn, &[]);
        assert_eq!(dead.len(), 3);
        // src/a.ts should come before src/z.ts
        assert_eq!(dead[0].file_path, "src/a.ts");
        assert_eq!(dead[1].file_path, "src/a.ts");
        assert_eq!(dead[2].file_path, "src/z.ts");
        // Within src/a.ts, line 5 before line 10
        assert_eq!(dead[0].start_line, 5);
        assert_eq!(dead[1].start_line, 10);
    }

    #[test]
    fn serializes_to_json() {
        let result = DeadCodeResult {
            id: "function:src/a.ts:foo:1".to_string(),
            name: "foo".to_string(),
            kind: "function".to_string(),
            file_path: "src/a.ts".to_string(),
            start_line: 1,
        };

        let json = serde_json::to_string(&result).unwrap();
        let back: DeadCodeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "foo");
        assert_eq!(back.start_line, 1);
    }
}
