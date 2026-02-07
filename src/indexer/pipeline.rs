//! Indexing pipeline — the heart of CodeGraph.
//!
//! Orchestrates file discovery, parsing, node/edge extraction, and
//! incremental storage. Uses rayon for parallel parsing (the killer
//! Rust advantage over the sequential TypeScript version).
//!
//! # Two-pass architecture
//!
//! - **Pass 1**: Parse every file and extract nodes (embarrassingly parallel —
//!   each file is independent). tree-sitter `Parser` is not Send/Sync, so we
//!   create one per rayon task.
//! - **Pass 2**: Build a cross-file node index, then extract edges. Edge
//!   extraction needs the global symbol table, but each file is still
//!   independent once the index is built.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use ignore::WalkBuilder;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::error::{CodeGraphError, Result};
use crate::graph::store::GraphStore;
use crate::indexer::extractor::Extractor;
use crate::indexer::parser::CodeParser;
use crate::resolution::imports::resolve_imports;
use crate::types::{CodeEdge, CodeNode, Language};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Skip files larger than 2 MB (generated files, minified bundles, etc.)
const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Options controlling an indexing run.
pub struct IndexOptions {
    pub root_dir: PathBuf,
    pub incremental: bool,
}

/// Summary of an indexing run.
#[derive(Debug, Clone)]
pub struct IndexResult {
    pub files_indexed: usize,
    pub files_skipped: usize,
    pub nodes_created: usize,
    pub edges_created: usize,
    pub duration_ms: u128,
}

impl std::fmt::Display for IndexResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Indexed {} files ({} skipped): {} nodes, {} edges in {}ms",
            self.files_indexed,
            self.files_skipped,
            self.nodes_created,
            self.edges_created,
            self.duration_ms,
        )
    }
}

/// Per-file state carried between Pass 1 and Pass 2.
struct FileParseState {
    relative_path: String,
    language: Language,
    content_hash: String,
    source_text: String,
    nodes: Vec<CodeNode>,
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

/// The two-pass indexing pipeline.
pub struct IndexingPipeline<'a> {
    store: &'a GraphStore,
}

impl<'a> IndexingPipeline<'a> {
    pub fn new(store: &'a GraphStore) -> Self {
        Self { store }
    }

    /// Index an entire directory tree.
    pub fn index_directory(&self, options: &IndexOptions) -> Result<IndexResult> {
        let start = Instant::now();
        let root = &options.root_dir;

        // ---- Collect files ----
        let file_paths = collect_files(root);

        // Pre-fetch all file hashes for incremental checks (before rayon).
        // This avoids touching the non-Sync Connection from parallel threads.
        let stored_hashes: HashMap<String, String> = if options.incremental {
            self.load_all_file_hashes()
        } else {
            HashMap::new()
        };

        let files_skipped = AtomicUsize::new(0);

        // ---- Pass 1: parse & extract nodes (parallel via rayon) ----
        // The closure only captures `root`, `stored_hashes`, `files_skipped`,
        // and `options.incremental` — all are Sync. No DB access here.
        let parsed: Vec<FileParseState> = file_paths
            .par_iter()
            .filter_map(|abs_path| {
                // Compute relative path
                let rel_path = match abs_path.strip_prefix(root) {
                    Ok(r) => r.to_string_lossy().to_string(),
                    Err(_) => {
                        files_skipped.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                };

                // Check file size
                let metadata = match fs::metadata(abs_path) {
                    Ok(m) => m,
                    Err(_) => {
                        files_skipped.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                };
                if metadata.len() > MAX_FILE_SIZE {
                    files_skipped.fetch_add(1, Ordering::Relaxed);
                    return None;
                }

                // Read source text
                let source_text = match fs::read_to_string(abs_path) {
                    Ok(s) => s,
                    Err(_) => {
                        files_skipped.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                };

                // Content hash for incremental indexing
                let content_hash = sha256_hex(&source_text);

                // Incremental: skip if unchanged (using pre-fetched hash map)
                if options.incremental {
                    if let Some(stored) = stored_hashes.get(&rel_path) {
                        if stored == &content_hash {
                            files_skipped.fetch_add(1, Ordering::Relaxed);
                            return None;
                        }
                    }
                }

                // Detect language
                let language = match CodeParser::detect_language(&rel_path) {
                    Some(l) => l,
                    None => {
                        files_skipped.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                };

                // Parse with a thread-local Parser (Parser is NOT Send/Sync)
                let parser = CodeParser::new();
                let tree = match parser.parse(&source_text, language) {
                    Ok(t) => t,
                    Err(_) => {
                        files_skipped.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                };

                // Extract nodes
                let nodes = match Extractor::extract_nodes(&tree, &rel_path, language, &source_text)
                {
                    Ok(n) => n,
                    Err(_) => {
                        files_skipped.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                };

                Some(FileParseState {
                    relative_path: rel_path,
                    language,
                    content_hash,
                    source_text,
                    nodes,
                })
            })
            .collect();

        // ---- Build cross-file node index ----
        let mut all_nodes: Vec<&CodeNode> = Vec::new();
        for state in &parsed {
            for node in &state.nodes {
                all_nodes.push(node);
            }
        }

        // In incremental mode, include existing nodes from files we didn't re-parse.
        let existing_nodes: Vec<CodeNode>;
        if options.incremental {
            existing_nodes = self.store.get_all_nodes()?;
            let reindexed_paths: std::collections::HashSet<&str> =
                parsed.iter().map(|s| s.relative_path.as_str()).collect();
            for node in &existing_nodes {
                if !reindexed_paths.contains(node.file_path.as_str()) {
                    all_nodes.push(node);
                }
            }
        }

        let node_index = build_node_index(&all_nodes);

        // ---- Pass 2: extract edges & persist (parallel edge extraction) ----
        #[allow(clippy::type_complexity)]
        let edge_results: Vec<
            Result<(String, Language, String, Vec<CodeNode>, Vec<CodeEdge>)>,
        > = parsed
            .par_iter()
            .map(|state| {
                // Each thread creates its own Parser (not Send/Sync)
                let parser = CodeParser::new();
                let tree = parser.parse(&state.source_text, state.language)?;

                let edges = Extractor::extract_edges(
                    &tree,
                    &state.relative_path,
                    state.language,
                    &state.source_text,
                    &state.nodes,
                    &node_index,
                )?;

                Ok((
                    state.relative_path.clone(),
                    state.language,
                    state.content_hash.clone(),
                    state.nodes.clone(),
                    edges,
                ))
            })
            .collect();

        // ---- Collect edge results ----
        let mut file_data: Vec<(String, Language, String, Vec<CodeNode>, Vec<CodeEdge>)> =
            Vec::new();
        for result in edge_results {
            file_data.push(result?);
        }

        // ---- Cross-file import resolution ----
        // Build the set of indexed file paths and a nodes-by-file lookup.
        let indexed_files: HashSet<String> = file_data
            .iter()
            .map(|(path, _, _, _, _)| path.clone())
            .collect();
        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();
        for (path, _, _, nodes, _) in &file_data {
            nodes_by_file.insert(path.clone(), nodes.clone());
        }
        // Include existing nodes from incremental runs
        if options.incremental {
            for node in &all_nodes {
                if !indexed_files.contains(&node.file_path) {
                    nodes_by_file
                        .entry(node.file_path.clone())
                        .or_default()
                        .push((*node).clone());
                }
            }
        }

        // Collect all edges across all files for resolution
        let all_edges: Vec<&CodeEdge> = file_data
            .iter()
            .flat_map(|(_, _, _, _, edges)| edges.iter())
            .collect();
        let all_edges_owned: Vec<CodeEdge> = all_edges.iter().map(|e| (*e).clone()).collect();

        let resolution_result = resolve_imports(
            &all_edges_owned,
            &indexed_files,
            &node_index,
            &nodes_by_file,
        );

        // Group resolved edges by their source file for merging
        let mut resolved_by_file: HashMap<String, Vec<CodeEdge>> = HashMap::new();
        for edge in resolution_result.resolved_edges {
            resolved_by_file
                .entry(edge.file_path.clone())
                .or_default()
                .push(edge);
        }

        // ---- Persist to SQLite (sequential — single connection) ----
        let mut files_indexed = 0usize;
        let mut nodes_created = 0usize;
        let mut edges_created = 0usize;

        for (rel_path, language, content_hash, nodes, mut edges) in file_data {
            // Merge resolved import edges into this file's edges
            if let Some(extra_edges) = resolved_by_file.remove(&rel_path) {
                edges.extend(extra_edges);
            }

            // Clear and persist unresolved refs for this file
            self.store.clear_unresolved_refs_for_file(&rel_path)?;

            self.store.replace_file_data(&rel_path, &nodes, &edges)?;
            self.upsert_file_hash(&rel_path, &content_hash, language)?;

            nodes_created += nodes.len();
            edges_created += edges.len();
            files_indexed += 1;
        }

        // Persist unresolved refs
        for uref in &resolution_result.unresolved_refs {
            self.store.insert_unresolved_ref(
                &uref.source_id,
                &uref.specifier,
                &uref.ref_type,
                &uref.file_path,
                uref.line,
            )?;
        }

        // ---- Optional: generate embeddings ----
        #[cfg(feature = "embedding")]
        if files_indexed > 0 {
            if let Ok(engine) = crate::indexer::embedder::EmbeddingEngine::try_new() {
                let batch_size = 64;
                let mut embedded = 0usize;
                for chunk in all_nodes.chunks(batch_size) {
                    let chunk_owned: Vec<CodeNode> = chunk.iter().map(|n| (*n).clone()).collect();
                    match engine.embed_and_store(&self.store.conn, &chunk_owned) {
                        Ok(n) => embedded += n,
                        Err(e) => {
                            eprintln!("[codegraph] WARNING: embedding batch failed: {e}");
                            break;
                        }
                    }
                }
                if embedded > 0 {
                    eprintln!("[codegraph] Generated embeddings for {embedded} nodes");
                }
            }
        }

        Ok(IndexResult {
            files_indexed,
            files_skipped: files_skipped.load(Ordering::Relaxed),
            nodes_created,
            edges_created,
            duration_ms: start.elapsed().as_millis(),
        })
    }

    /// Index (or re-index) a single file. Used by the file watcher.
    pub fn index_file(&self, file_path: &Path, root_dir: &Path) -> Result<Option<IndexResult>> {
        let start = Instant::now();

        let abs_path = if file_path.is_absolute() {
            file_path.to_path_buf()
        } else {
            root_dir.join(file_path)
        };

        let language = match CodeParser::detect_language(&abs_path.to_string_lossy()) {
            Some(l) => l,
            None => return Ok(None),
        };

        let metadata = fs::metadata(&abs_path).map_err(CodeGraphError::Io)?;
        if metadata.len() > MAX_FILE_SIZE {
            return Ok(None);
        }

        let source_text = fs::read_to_string(&abs_path).map_err(CodeGraphError::Io)?;
        let content_hash = sha256_hex(&source_text);

        let rel_path = abs_path
            .strip_prefix(root_dir)
            .unwrap_or(&abs_path)
            .to_string_lossy()
            .to_string();

        let parser = CodeParser::new();
        let tree = parser.parse(&source_text, language)?;
        let nodes = Extractor::extract_nodes(&tree, &rel_path, language, &source_text)?;

        // Build node index: existing DB nodes + this file's new nodes
        let existing = self.store.get_all_nodes()?;
        let mut all_nodes: Vec<&CodeNode> = existing
            .iter()
            .filter(|n| n.file_path != rel_path)
            .collect();
        for n in &nodes {
            all_nodes.push(n);
        }
        let node_index = build_node_index(&all_nodes);

        let mut edges = Extractor::extract_edges(
            &tree,
            &rel_path,
            language,
            &source_text,
            &nodes,
            &node_index,
        )?;

        // Cross-file import resolution for single file re-index
        let mut indexed_files: HashSet<String> =
            existing.iter().map(|n| n.file_path.clone()).collect();
        indexed_files.insert(rel_path.clone());

        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();
        for node in &existing {
            nodes_by_file
                .entry(node.file_path.clone())
                .or_default()
                .push(node.clone());
        }
        nodes_by_file.insert(rel_path.clone(), nodes.clone());

        let resolution_result =
            resolve_imports(&edges, &indexed_files, &node_index, &nodes_by_file);
        edges.extend(resolution_result.resolved_edges);

        // Clear and persist unresolved refs for this file
        self.store.clear_unresolved_refs_for_file(&rel_path)?;
        for uref in &resolution_result.unresolved_refs {
            self.store.insert_unresolved_ref(
                &uref.source_id,
                &uref.specifier,
                &uref.ref_type,
                &uref.file_path,
                uref.line,
            )?;
        }

        self.store.replace_file_data(&rel_path, &nodes, &edges)?;
        self.upsert_file_hash(&rel_path, &content_hash, language)?;

        Ok(Some(IndexResult {
            files_indexed: 1,
            files_skipped: 0,
            nodes_created: nodes.len(),
            edges_created: edges.len(),
            duration_ms: start.elapsed().as_millis(),
        }))
    }

    /// Remove a file from the index entirely.
    pub fn remove_file(&self, relative_path: &str) -> Result<()> {
        self.store.delete_file_nodes(relative_path)?;
        self.delete_file_hash(relative_path)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // File hash helpers (incremental indexing)
    // -----------------------------------------------------------------------

    /// Load all stored file hashes into memory for fast incremental lookups.
    /// Called once before the parallel section to avoid DB access from rayon threads.
    fn load_all_file_hashes(&self) -> HashMap<String, String> {
        let mut map = HashMap::new();
        let result = self
            .store
            .conn
            .prepare("SELECT file_path, content_hash FROM file_hashes");
        if let Ok(mut stmt) = result {
            let _ = stmt
                .query_map([], |row| {
                    let path: String = row.get(0)?;
                    let hash: String = row.get(1)?;
                    Ok((path, hash))
                })
                .map(|rows| {
                    for row in rows.flatten() {
                        map.insert(row.0, row.1);
                    }
                });
        }
        map
    }

    fn upsert_file_hash(
        &self,
        file_path: &str,
        content_hash: &str,
        language: Language,
    ) -> Result<()> {
        self.store
            .conn
            .prepare_cached(
                "INSERT INTO file_hashes (file_path, content_hash, language)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(file_path) DO UPDATE SET
               content_hash = excluded.content_hash,
               indexed_at = datetime('now'),
               language = excluded.language",
            )?
            .execute(rusqlite::params![
                file_path,
                content_hash,
                language.as_str()
            ])?;
        Ok(())
    }

    fn delete_file_hash(&self, file_path: &str) -> Result<()> {
        self.store
            .conn
            .prepare_cached("DELETE FROM file_hashes WHERE file_path = ?1")?
            .execute([file_path])?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// File collection (using the `ignore` crate for gitignore awareness)
// ---------------------------------------------------------------------------

/// Collect all supported source files under `root`, respecting `.gitignore`.
fn collect_files(root: &Path) -> Vec<PathBuf> {
    let walker = WalkBuilder::new(root)
        .standard_filters(true) // respects .gitignore, .ignore, hidden files
        .build();

    let mut files = Vec::new();
    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let path = entry.path();
        if CodeParser::is_supported(&path.to_string_lossy()) {
            files.push(path.to_path_buf());
        }
    }
    files
}

// ---------------------------------------------------------------------------
// Node index builder
// ---------------------------------------------------------------------------

/// Build a lookup from symbol name -> all CodeNodes with that name.
fn build_node_index(nodes: &[&CodeNode]) -> HashMap<String, Vec<CodeNode>> {
    let mut index: HashMap<String, Vec<CodeNode>> = HashMap::new();
    for &node in nodes {
        index
            .entry(node.name.clone())
            .or_default()
            .push(node.clone());
    }
    index
}

// ---------------------------------------------------------------------------
// SHA-256 hashing
// ---------------------------------------------------------------------------

fn sha256_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::initialize_database;
    use crate::types::EdgeKind;
    use std::fs;

    fn setup_test_project() -> (tempfile::TempDir, GraphStore) {
        let tmp = tempfile::tempdir().unwrap();

        // Create a simple TypeScript file
        let ts_file = tmp.path().join("hello.ts");
        fs::write(
            &ts_file,
            r#"
export function greet(name: string): string {
    return `Hello, ${name}!`;
}

export class Greeter {
    greet(name: string): string {
        return greet(name);
    }
}
"#,
        )
        .unwrap();

        // Create a Python file
        let py_file = tmp.path().join("util.py");
        fs::write(
            &py_file,
            r#"
def helper():
    return 42

class Calculator:
    def add(self, a, b):
        return a + b
"#,
        )
        .unwrap();

        // Create a file that should be ignored
        let txt_file = tmp.path().join("readme.txt");
        fs::write(&txt_file, "This should be ignored").unwrap();

        let conn = initialize_database(":memory:").unwrap();
        let store = GraphStore::from_connection(conn);

        (tmp, store)
    }

    #[test]
    fn sha256_produces_hex_string() {
        let hash = sha256_hex("hello world");
        assert_eq!(hash.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn collect_files_finds_supported_files() {
        let (tmp, _store) = setup_test_project();
        let files = collect_files(tmp.path());

        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();

        assert!(names.contains(&"hello.ts".to_string()));
        assert!(names.contains(&"util.py".to_string()));
        assert!(!names.contains(&"readme.txt".to_string()));
    }

    #[test]
    fn index_directory_full_pipeline() {
        let (tmp, store) = setup_test_project();
        let pipeline = IndexingPipeline::new(&store);

        let result = pipeline
            .index_directory(&IndexOptions {
                root_dir: tmp.path().to_path_buf(),
                incremental: false,
            })
            .unwrap();

        assert_eq!(result.files_indexed, 2);
        assert!(result.nodes_created > 0, "should have extracted nodes");
        // edges_created is usize, always >= 0; just verify pipeline completed

        // Verify data persisted in store
        let stats = store.get_stats().unwrap();
        assert_eq!(stats.nodes, result.nodes_created);
        assert_eq!(stats.files, 2);
    }

    #[test]
    fn incremental_indexing_skips_unchanged_files() {
        let (tmp, store) = setup_test_project();
        let pipeline = IndexingPipeline::new(&store);

        // First full index
        let r1 = pipeline
            .index_directory(&IndexOptions {
                root_dir: tmp.path().to_path_buf(),
                incremental: true,
            })
            .unwrap();
        assert_eq!(r1.files_indexed, 2);

        // Second index — nothing changed, everything skipped
        let r2 = pipeline
            .index_directory(&IndexOptions {
                root_dir: tmp.path().to_path_buf(),
                incremental: true,
            })
            .unwrap();
        assert_eq!(r2.files_indexed, 0);
        assert_eq!(r2.files_skipped, 2);
    }

    #[test]
    fn incremental_reindexes_modified_file() {
        let (tmp, store) = setup_test_project();
        let pipeline = IndexingPipeline::new(&store);

        // First full index
        pipeline
            .index_directory(&IndexOptions {
                root_dir: tmp.path().to_path_buf(),
                incremental: true,
            })
            .unwrap();

        // Modify one file
        let ts_file = tmp.path().join("hello.ts");
        fs::write(
            &ts_file,
            r#"
export function greetV2(name: string): string {
    return `Hey, ${name}!`;
}
"#,
        )
        .unwrap();

        // Second index — only the modified file should be re-indexed
        let r2 = pipeline
            .index_directory(&IndexOptions {
                root_dir: tmp.path().to_path_buf(),
                incremental: true,
            })
            .unwrap();
        assert_eq!(r2.files_indexed, 1);
        assert_eq!(r2.files_skipped, 1);
    }

    #[test]
    fn index_single_file() {
        let (tmp, store) = setup_test_project();
        let pipeline = IndexingPipeline::new(&store);

        let ts_file = tmp.path().join("hello.ts");
        let result = pipeline
            .index_file(&ts_file, tmp.path())
            .unwrap()
            .expect("should index TypeScript file");

        assert_eq!(result.files_indexed, 1);
        assert!(result.nodes_created > 0);
    }

    #[test]
    fn index_unsupported_file_returns_none() {
        let (tmp, store) = setup_test_project();
        let pipeline = IndexingPipeline::new(&store);

        let txt_file = tmp.path().join("readme.txt");
        let result = pipeline.index_file(&txt_file, tmp.path()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn cross_file_import_resolution() {
        let tmp = tempfile::tempdir().unwrap();

        // Create src/ directory
        fs::create_dir_all(tmp.path().join("src")).unwrap();

        // utils.ts — exports functions
        fs::write(
            tmp.path().join("src/utils.ts"),
            r#"
export function validate(input: string): boolean {
    return input.length > 0;
}

export function sanitize(input: string): string {
    return input.trim();
}

function internal(): void {}
"#,
        )
        .unwrap();

        // main.ts — imports from utils
        fs::write(
            tmp.path().join("src/main.ts"),
            r#"
import { validate, sanitize } from './utils';

function processInput(input: string): string {
    if (validate(input)) {
        return sanitize(input);
    }
    return '';
}
"#,
        )
        .unwrap();

        let conn = initialize_database(":memory:").unwrap();
        let store = GraphStore::from_connection(conn);
        let pipeline = IndexingPipeline::new(&store);

        let result = pipeline
            .index_directory(&IndexOptions {
                root_dir: tmp.path().to_path_buf(),
                incremental: false,
            })
            .unwrap();

        assert_eq!(result.files_indexed, 2);

        // Check that we have cross-file import edges
        // The import resolution should create edges from file:src/main.ts
        // to the actual validate and sanitize nodes in src/utils.ts
        let all_edges = store.get_all_edges().unwrap();
        let resolved_imports: Vec<_> = all_edges
            .iter()
            .filter(|e| {
                e.kind == EdgeKind::Imports
                    && e.file_path == "src/main.ts"
                    && !e.target.starts_with("module:")
            })
            .collect();

        assert!(
            resolved_imports.len() >= 2,
            "Expected at least 2 resolved import edges (validate, sanitize), got {}. \
             All import edges: {:?}",
            resolved_imports.len(),
            all_edges
                .iter()
                .filter(|e| e.kind == EdgeKind::Imports)
                .map(|e| format!("{} -> {}", e.source, e.target))
                .collect::<Vec<_>>()
        );

        // Verify the resolved edges point to actual nodes (not module: targets)
        for edge in &resolved_imports {
            assert!(
                !edge.target.starts_with("module:"),
                "Resolved edge should not target module: prefix, got: {}",
                edge.target
            );
        }
    }

    #[test]
    fn remove_file_clears_data() {
        let (tmp, store) = setup_test_project();
        let pipeline = IndexingPipeline::new(&store);

        // Index everything
        pipeline
            .index_directory(&IndexOptions {
                root_dir: tmp.path().to_path_buf(),
                incremental: false,
            })
            .unwrap();

        let before = store.get_stats().unwrap();
        assert!(before.nodes > 0);

        // Remove one file
        pipeline.remove_file("hello.ts").unwrap();

        let after = store.get_stats().unwrap();
        assert!(after.nodes < before.nodes);
        assert_eq!(after.files, 1); // only util.py remains
    }
}
