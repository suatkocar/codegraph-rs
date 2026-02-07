//! Hybrid search engine for the CodeGraph.
//!
//! Faithfully ports the TypeScript `graph/search.ts` to Rust. Combines
//! SQLite FTS5 keyword search with vector cosine similarity (via
//! sqlite-vec), merging results through Reciprocal Rank Fusion (RRF).
//!
//! Vector search is stubbed as a placeholder — actual embedding
//! integration lands in Phase 5.

use std::collections::HashMap;

use rusqlite::{params, Connection};

use crate::error::Result;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single search result with composite scoring.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SearchResult {
    /// The unique node ID from the `nodes` table.
    pub node_id: String,
    /// Human-readable symbol name.
    pub name: String,
    /// Node kind/type (e.g. "function", "class").
    pub kind: String,
    /// Path to the source file containing this symbol.
    pub file_path: String,
    /// Combined RRF score (higher is better).
    pub score: f64,
    /// Raw FTS5 BM25 score (inverted so higher = better), if present.
    pub fts_score: Option<f64>,
    /// Vector cosine similarity score (0..1), if present.
    pub vec_score: Option<f64>,
    /// Short display snippet derived from docs or signature.
    pub snippet: Option<String>,
}

/// Options that control search behaviour.
#[derive(Debug, Clone, Default)]
pub struct SearchOptions {
    /// Maximum results to return (default 20).
    pub limit: Option<usize>,
    /// Filter to a specific programming language.
    pub language: Option<String>,
    /// Filter to a specific node type/kind.
    pub node_type: Option<String>,
    /// Discard results below this RRF score (default 0).
    pub min_score: Option<f64>,
}

// ---------------------------------------------------------------------------
// Internal row shapes
// ---------------------------------------------------------------------------

/// A row returned by the FTS5 keyword query.
struct FtsRow {
    id: String,
    name: String,
    kind: String,
    file_path: String,
    rank: f64,
    #[allow(dead_code)]
    language: String,
    signature: Option<String>,
    doc_comment: Option<String>,
}

// ---------------------------------------------------------------------------
// SQL constants
// ---------------------------------------------------------------------------

const FTS_SEARCH_SQL: &str = "\
SELECT n.id, n.name, n.type, n.file_path, n.language,
       n.signature, n.doc_comment,
       fts.rank
FROM fts_nodes fts
JOIN nodes n ON n.rowid = fts.rowid
WHERE fts_nodes MATCH ?1
ORDER BY fts.rank
LIMIT ?2";

const GET_NODE_LANGUAGE_SQL: &str = "\
SELECT language FROM nodes WHERE id = ?1";

// ---------------------------------------------------------------------------
// Hybrid search engine
// ---------------------------------------------------------------------------

/// HybridSearch combines SQLite FTS5 keyword search with sqlite-vec
/// cosine similarity to deliver results that are both lexically precise
/// and semantically rich.
///
/// Results from each system are merged using Reciprocal Rank Fusion
/// (RRF), a rank-aggregation method that doesn't require score
/// normalization and gracefully handles result lists of different
/// lengths.
pub struct HybridSearch<'a> {
    conn: &'a Connection,
}

impl<'a> HybridSearch<'a> {
    /// Create a new search engine backed by `conn`.
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Execute a hybrid search: FTS5 keyword + vector similarity, fused
    /// via RRF.
    ///
    /// For short single-token queries the vector signal tends to
    /// dominate; for multi-word natural language questions both signals
    /// contribute.
    pub fn search(
        &self,
        query: &str,
        options: &SearchOptions,
    ) -> Result<Vec<SearchResult>> {
        let limit = options.limit.unwrap_or(20);
        // Fetch more candidates than needed so fusion has room to merge.
        let fetch_limit = limit * 3;

        let fts_results = self.search_by_keyword(query, fetch_limit)?;
        let vec_results = self.search_by_similarity(query, fetch_limit);

        let mut fused = fuse_results(&fts_results, &vec_results, 60);

        // Apply optional filters.
        if let Some(ref lang) = options.language {
            fused.retain(|r| {
                self.get_node_language(&r.node_id)
                    .as_deref() == Some(lang.as_str())
            });
        }
        if let Some(ref node_type) = options.node_type {
            fused.retain(|r| r.kind == *node_type);
        }
        if let Some(min_score) = options.min_score {
            if min_score > 0.0 {
                fused.retain(|r| r.score >= min_score);
            }
        }

        fused.truncate(limit);
        Ok(fused)
    }

    /// FTS5 keyword search on the `fts_nodes` virtual table.
    ///
    /// Uses the built-in BM25 ranking (exposed as `rank`). Queries are
    /// sanitized: special FTS5 syntax characters are quoted to prevent
    /// user input from breaking the query.
    pub fn search_by_keyword(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<SearchResult>> {
        let safe_query = sanitize_fts_query(query);
        if safe_query.is_empty() {
            return Ok(Vec::new());
        }

        let mut stmt = self.conn.prepare_cached(FTS_SEARCH_SQL)?;
        let rows = stmt.query_map(params![safe_query, limit as i64], |row| {
            Ok(FtsRow {
                id: row.get(0)?,
                name: row.get(1)?,
                kind: row.get(2)?,
                file_path: row.get(3)?,
                language: row.get(4)?,
                signature: row.get(5)?,
                doc_comment: row.get(6)?,
                rank: row.get(7)?,
            })
        })?;

        let mut results = Vec::new();
        for row_result in rows {
            let row = row_result?;
            let snippet = build_snippet(&row.name, row.signature.as_deref(), row.doc_comment.as_deref());
            results.push(SearchResult {
                node_id: row.id,
                name: row.name,
                kind: row.kind,
                file_path: row.file_path,
                score: 0.0, // will be set by fusion
                fts_score: Some(-row.rank), // FTS5 rank is negative; invert for display
                vec_score: None,
                snippet: Some(snippet),
            });
        }

        Ok(results)
    }

    /// Vector similarity search via sqlite-vec.
    ///
    /// Embeds the query text, finds nearest neighbors by cosine distance
    /// in the `vec_embeddings` virtual table, and decorates each result
    /// with node metadata.
    ///
    /// Returns an empty `Vec` if no embedder is provided or if the
    /// `vec_embeddings` table has no data.
    pub fn search_by_similarity(
        &self,
        query: &str,
        limit: usize,
    ) -> Vec<SearchResult> {
        #[cfg(feature = "embedding")]
        {
            // Try to get embedder; if unavailable, return empty
            let embedder = match crate::indexer::embedder::EmbeddingEngine::try_new() {
                Ok(e) => e,
                Err(_) => return Vec::new(),
            };

            let query_vec = match embedder.embed(query) {
                Ok(v) => v,
                Err(_) => return Vec::new(),
            };

            // Convert to JSON array for sqlite-vec MATCH
            let vec_json = match serde_json::to_string(&query_vec) {
                Ok(j) => j,
                Err(_) => return Vec::new(),
            };

            // Query vec_embeddings for nearest neighbors
            let sql = "SELECT v.node_id, v.distance, n.name, n.type, n.file_path
                        FROM vec_embeddings v
                        JOIN nodes n ON n.id = v.node_id
                        WHERE v.embedding MATCH ?1
                        ORDER BY v.distance
                        LIMIT ?2";

            let mut stmt = match self.conn.prepare_cached(sql) {
                Ok(s) => s,
                Err(_) => return Vec::new(),
            };

            let rows = match stmt.query_map(params![vec_json, limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, f64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            }) {
                Ok(r) => r,
                Err(_) => return Vec::new(),
            };

            let mut results = Vec::new();
            for row in rows.flatten() {
                let (node_id, distance, name, kind, file_path) = row;
                // Convert distance to similarity score (1.0 - distance for cosine)
                let similarity = 1.0 - distance;
                results.push(SearchResult {
                    node_id,
                    name: name.clone(),
                    kind,
                    file_path,
                    score: 0.0, // Will be set by fusion
                    fts_score: None,
                    vec_score: Some(similarity),
                    snippet: Some(name),
                });
            }
            results
        }

        #[cfg(not(feature = "embedding"))]
        {
            let _ = (query, limit);
            Vec::new()
        }
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    /// Look up the language for a node (used for post-fusion filtering).
    fn get_node_language(&self, node_id: &str) -> Option<String> {
        let mut stmt = self
            .conn
            .prepare_cached(GET_NODE_LANGUAGE_SQL)
            .ok()?;
        stmt.query_row(params![node_id], |row| row.get::<_, String>(0))
            .ok()
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Reciprocal Rank Fusion (RRF).
///
/// Merges two ranked result lists into a single list using:
///
///   `score(d) = SUM( 1 / (k + rank_i(d)) )`
///
/// where `k` (default 60) is the standard constant that prevents
/// top-ranked items from dominating. This is a score-agnostic fusion
/// method -- it only cares about rank position, so heterogeneous
/// scoring functions (BM25 vs cosine distance) work naturally.
pub fn fuse_results(
    fts_results: &[SearchResult],
    vec_results: &[SearchResult],
    k: u32,
) -> Vec<SearchResult> {
    let k = k as f64;
    let mut score_map: HashMap<String, (SearchResult, f64)> = HashMap::new();

    // Score from FTS rankings (0-indexed internally, 1-indexed for RRF).
    for (rank, r) in fts_results.iter().enumerate() {
        let rrf_score = 1.0 / (k + (rank as f64) + 1.0);
        match score_map.get_mut(&r.node_id) {
            Some((existing, total)) => {
                *total += rrf_score;
                existing.fts_score = r.fts_score;
            }
            None => {
                score_map.insert(r.node_id.clone(), (r.clone(), rrf_score));
            }
        }
    }

    // Score from vector rankings.
    for (rank, r) in vec_results.iter().enumerate() {
        let rrf_score = 1.0 / (k + (rank as f64) + 1.0);
        match score_map.get_mut(&r.node_id) {
            Some((existing, total)) => {
                *total += rrf_score;
                existing.vec_score = r.vec_score;
            }
            None => {
                score_map.insert(r.node_id.clone(), (r.clone(), rrf_score));
            }
        }
    }

    // Sort by combined RRF score descending.
    let mut fused: Vec<(SearchResult, f64)> = score_map.into_values().collect();
    fused.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    fused
        .into_iter()
        .map(|(mut result, score)| {
            result.score = score;
            result
        })
        .collect()
}

/// Sanitize a user query for FTS5 MATCH syntax.
///
/// FTS5 has its own query grammar where characters like `*`, `"`, `-`,
/// `(`, `)` carry meaning. We strip those special characters from each
/// token and wrap it in double quotes for exact matching, then join
/// tokens with `OR` for broadest recall. RRF will rank appropriately.
pub fn sanitize_fts_query(query: &str) -> String {
    let tokens: Vec<String> = query
        .split_whitespace()
        .filter_map(|token| {
            let clean: String = token
                .chars()
                .filter(|c| !matches!(c, '*' | '"' | '(' | ')' | '{' | '}' | '[' | ']' | '^' | '~' | ':'))
                .collect();
            if clean.is_empty() {
                None
            } else {
                Some(format!("\"{}\"", clean))
            }
        })
        .collect();

    if tokens.is_empty() {
        return String::new();
    }

    tokens.join(" OR ")
}

/// Build a short display snippet from a node's name, signature, and
/// doc comment.
///
/// Prefers the first line of documentation. Falls back to a compacted
/// signature (truncated at 120 chars). As a last resort, returns the
/// bare name.
pub fn build_snippet(
    name: &str,
    signature: Option<&str>,
    doc_comment: Option<&str>,
) -> String {
    if let Some(doc) = doc_comment {
        let first_line = doc.lines().next().unwrap_or("").trim();
        if !first_line.is_empty() {
            return first_line.to_string();
        }
    }
    if let Some(sig) = signature {
        // Show a compacted signature, truncated at 120 characters.
        let compacted: String = sig
            .chars()
            .take(120)
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if sig.len() > 120 {
            return format!("{}...", compacted);
        }
        return compacted;
    }
    name.to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::initialize_database;
    use crate::graph::store::GraphStore;
    use crate::types::{CodeNode, Language, NodeKind};

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
        sig: Option<&str>,
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
            body: sig.map(|s| s.to_string()),
            documentation: doc.map(|d| d.to_string()),
            exported: Some(true),
        }
    }

    // -- sanitize_fts_query ------------------------------------------------

    #[test]
    fn sanitize_fts_query_basic_tokens() {
        let result = sanitize_fts_query("hello world");
        assert_eq!(result, r#""hello" OR "world""#);
    }

    #[test]
    fn sanitize_fts_query_strips_special_chars() {
        let result = sanitize_fts_query("foo* (bar) baz:qux");
        assert_eq!(result, r#""foo" OR "bar" OR "bazqux""#);
    }

    #[test]
    fn sanitize_fts_query_empty_input() {
        assert_eq!(sanitize_fts_query(""), "");
        assert_eq!(sanitize_fts_query("   "), "");
    }

    #[test]
    fn sanitize_fts_query_all_special_chars() {
        // When every character is a special char, the result should be empty.
        assert_eq!(sanitize_fts_query("*** \"\" ()"), "");
    }

    #[test]
    fn sanitize_fts_query_single_token() {
        assert_eq!(sanitize_fts_query("search"), r#""search""#);
    }

    // -- build_snippet -----------------------------------------------------

    #[test]
    fn build_snippet_prefers_doc_comment() {
        let snippet = build_snippet("foo", Some("fn foo(x: i32) -> bool"), Some("Check something.\nMore details."));
        assert_eq!(snippet, "Check something.");
    }

    #[test]
    fn build_snippet_falls_back_to_signature() {
        let snippet = build_snippet("foo", Some("fn foo(x: i32) -> bool"), None);
        assert_eq!(snippet, "fn foo(x: i32) -> bool");
    }

    #[test]
    fn build_snippet_truncates_long_signature() {
        let long_sig = "a".repeat(200);
        let snippet = build_snippet("foo", Some(&long_sig), None);
        // Should be 120 chars + "..."
        assert!(snippet.ends_with("..."));
        assert_eq!(snippet.len(), 123); // 120 'a' chars + 3 dots
    }

    #[test]
    fn build_snippet_falls_back_to_name() {
        let snippet = build_snippet("myFunction", None, None);
        assert_eq!(snippet, "myFunction");
    }

    #[test]
    fn build_snippet_skips_empty_doc_comment() {
        // A doc comment that's just whitespace should fall through.
        let snippet = build_snippet("bar", Some("fn bar()"), Some("  \n  "));
        assert_eq!(snippet, "fn bar()");
    }

    // -- fuse_results (RRF math) -------------------------------------------

    #[test]
    fn fuse_results_combines_scores_from_both_lists() {
        let fts = vec![
            SearchResult {
                node_id: "a".to_string(),
                name: "alpha".to_string(),
                kind: "function".to_string(),
                file_path: "a.ts".to_string(),
                score: 0.0,
                fts_score: Some(5.0),
                vec_score: None,
                snippet: None,
            },
            SearchResult {
                node_id: "b".to_string(),
                name: "beta".to_string(),
                kind: "class".to_string(),
                file_path: "b.ts".to_string(),
                score: 0.0,
                fts_score: Some(3.0),
                vec_score: None,
                snippet: None,
            },
        ];
        let vec_results = vec![
            SearchResult {
                node_id: "a".to_string(),
                name: "alpha".to_string(),
                kind: "function".to_string(),
                file_path: "a.ts".to_string(),
                score: 0.0,
                fts_score: None,
                vec_score: Some(0.95),
                snippet: None,
            },
            SearchResult {
                node_id: "c".to_string(),
                name: "gamma".to_string(),
                kind: "variable".to_string(),
                file_path: "c.ts".to_string(),
                score: 0.0,
                fts_score: None,
                vec_score: Some(0.80),
                snippet: None,
            },
        ];

        let fused = fuse_results(&fts, &vec_results, 60);

        // "a" appears in both lists so it should have the highest score.
        assert_eq!(fused[0].node_id, "a");
        // Verify the RRF math:
        //   FTS rank 0 -> 1/(60+1) = 1/61
        //   Vec rank 0 -> 1/(60+1) = 1/61
        //   Combined  -> 2/61
        let expected_a_score = 2.0 / 61.0;
        assert!(
            (fused[0].score - expected_a_score).abs() < 1e-10,
            "expected {}, got {}",
            expected_a_score,
            fused[0].score,
        );

        // "a" should carry both fts_score and vec_score.
        assert!(fused[0].fts_score.is_some());
        assert!(fused[0].vec_score.is_some());

        // Total results: 3 unique node IDs.
        assert_eq!(fused.len(), 3);
    }

    #[test]
    fn fuse_results_empty_inputs() {
        let fused = fuse_results(&[], &[], 60);
        assert!(fused.is_empty());
    }

    #[test]
    fn fuse_results_single_list_only() {
        let fts = vec![SearchResult {
            node_id: "x".to_string(),
            name: "x".to_string(),
            kind: "function".to_string(),
            file_path: "x.ts".to_string(),
            score: 0.0,
            fts_score: Some(1.0),
            vec_score: None,
            snippet: None,
        }];
        let fused = fuse_results(&fts, &[], 60);
        assert_eq!(fused.len(), 1);
        assert_eq!(fused[0].node_id, "x");
        let expected = 1.0 / 61.0;
        assert!((fused[0].score - expected).abs() < 1e-10);
    }

    #[test]
    fn fuse_results_preserves_rank_ordering() {
        // Three items in FTS, none in vec. Their order should be preserved.
        let fts: Vec<SearchResult> = (0..3)
            .map(|i| SearchResult {
                node_id: format!("n{}", i),
                name: format!("name{}", i),
                kind: "function".to_string(),
                file_path: "f.ts".to_string(),
                score: 0.0,
                fts_score: Some((3 - i) as f64),
                vec_score: None,
                snippet: None,
            })
            .collect();

        let fused = fuse_results(&fts, &[], 60);
        assert_eq!(fused[0].node_id, "n0");
        assert_eq!(fused[1].node_id, "n1");
        assert_eq!(fused[2].node_id, "n2");
        // Scores must be strictly decreasing.
        assert!(fused[0].score > fused[1].score);
        assert!(fused[1].score > fused[2].score);
    }

    // -- keyword search (integration with FTS5) ----------------------------

    #[test]
    fn keyword_search_finds_matching_nodes() {
        let store = setup();
        store
            .upsert_node(&make_node(
                "fn:a.ts:greet:1",
                "greet",
                "a.ts",
                NodeKind::Function,
                1,
                Some("function greet(name: string)"),
                Some("Say hello to someone."),
            ))
            .unwrap();
        store
            .upsert_node(&make_node(
                "fn:a.ts:farewell:10",
                "farewell",
                "a.ts",
                NodeKind::Function,
                10,
                Some("function farewell()"),
                None,
            ))
            .unwrap();

        let search = HybridSearch::new(&store.conn);
        let results = search.search_by_keyword("greet", 10).unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].node_id, "fn:a.ts:greet:1");
        assert_eq!(results[0].name, "greet");
        assert_eq!(results[0].kind, "function");
        assert_eq!(results[0].snippet.as_deref(), Some("Say hello to someone."));
    }

    #[test]
    fn keyword_search_returns_empty_for_no_match() {
        let store = setup();
        store
            .upsert_node(&make_node(
                "fn:a.ts:greet:1",
                "greet",
                "a.ts",
                NodeKind::Function,
                1,
                None,
                None,
            ))
            .unwrap();

        let search = HybridSearch::new(&store.conn);
        let results = search.search_by_keyword("nonexistent", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn keyword_search_respects_limit() {
        let store = setup();
        for i in 0..10 {
            store
                .upsert_node(&make_node(
                    &format!("fn:a.ts:func{}:{}", i, i),
                    &format!("func{}", i),
                    "a.ts",
                    NodeKind::Function,
                    i,
                    Some(&format!("function func{}()", i)),
                    None,
                ))
                .unwrap();
        }

        let search = HybridSearch::new(&store.conn);
        // All nodes have "func" in their name; ask for at most 3.
        let results = search.search_by_keyword("func", 3).unwrap();
        assert!(results.len() <= 3);
    }

    #[test]
    fn keyword_search_with_special_chars_in_query() {
        let store = setup();
        store
            .upsert_node(&make_node(
                "fn:a.ts:create:1",
                "create",
                "a.ts",
                NodeKind::Function,
                1,
                None,
                None,
            ))
            .unwrap();

        let search = HybridSearch::new(&store.conn);
        // Special chars should be stripped, leaving just "create".
        let results = search.search_by_keyword("*create*", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "create");
    }

    // -- hybrid search (integration) ---------------------------------------

    #[test]
    fn hybrid_search_applies_node_type_filter() {
        let store = setup();
        store
            .upsert_node(&make_node(
                "fn:a.ts:hello:1",
                "hello",
                "a.ts",
                NodeKind::Function,
                1,
                None,
                None,
            ))
            .unwrap();
        store
            .upsert_node(&make_node(
                "cls:a.ts:Hello:10",
                "Hello",
                "a.ts",
                NodeKind::Class,
                10,
                None,
                None,
            ))
            .unwrap();

        let search = HybridSearch::new(&store.conn);
        let opts = SearchOptions {
            node_type: Some("class".to_string()),
            ..Default::default()
        };
        let results = search.search("Hello", &opts).unwrap();
        assert!(results.iter().all(|r| r.kind == "class"));
    }

    #[test]
    fn hybrid_search_applies_language_filter() {
        let store = setup();
        store
            .upsert_node(&make_node(
                "fn:a.ts:compute:1",
                "compute",
                "a.ts",
                NodeKind::Function,
                1,
                None,
                None,
            ))
            .unwrap();

        let search = HybridSearch::new(&store.conn);
        let opts = SearchOptions {
            language: Some("python".to_string()),
            ..Default::default()
        };
        // The node is TypeScript; filtering by Python should exclude it.
        let results = search.search("compute", &opts).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn hybrid_search_applies_min_score_filter() {
        let store = setup();
        store
            .upsert_node(&make_node(
                "fn:a.ts:tiny:1",
                "tiny",
                "a.ts",
                NodeKind::Function,
                1,
                None,
                None,
            ))
            .unwrap();

        let search = HybridSearch::new(&store.conn);
        let opts = SearchOptions {
            min_score: Some(1.0), // impossibly high for a single RRF contribution
            ..Default::default()
        };
        let results = search.search("tiny", &opts).unwrap();
        // Max single-list RRF for rank 0 is 1/61 ~ 0.016, well below 1.0.
        assert!(results.is_empty());
    }
}
