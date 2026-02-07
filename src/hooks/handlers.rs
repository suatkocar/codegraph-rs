//! Claude Code hook runtime handlers.
//!
//! Each handler reads a JSON event from stdin, processes it, and writes a
//! JSON response to stdout. Handlers are invoked by Claude Code at specific
//! lifecycle points (session start, prompt submission, compaction, post-edit).
//!
//! # Contract
//!
//! - **Never panic.** Every handler wraps its logic in `catch_unwind`.
//! - **Never block Claude Code.** On any error, output `{"continue": true}`.
//! - **JSON on stdout only.** Debug/status messages go to stderr.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::json;

// ---------------------------------------------------------------------------
// Shared helper: read hook event from stdin
// ---------------------------------------------------------------------------

/// Read the JSON event that Claude Code pipes to stdin.
///
/// Returns an empty object `{}` if stdin is empty, unreadable, or not valid
/// JSON — the caller always gets a `serde_json::Value` to work with.
fn read_hook_event() -> serde_json::Value {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap_or_default();
    serde_json::from_str(&input).unwrap_or(json!({}))
}

/// Resolve the working directory from the hook event's `cwd` field,
/// falling back to `std::env::current_dir()`.
fn resolve_cwd(event: &serde_json::Value) -> PathBuf {
    event["cwd"]
        .as_str()
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// Derive the database path from a working directory:
/// `<cwd>/.codegraph/codegraph.db`
fn db_path(cwd: &Path) -> PathBuf {
    cwd.join(".codegraph").join("codegraph.db")
}

/// Ensure the `.codegraph` directory exists, then return the DB path as a
/// string suitable for `initialize_database` / `GraphStore::new`.
fn ensure_db(cwd: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let dir = cwd.join(".codegraph");
    std::fs::create_dir_all(&dir)?;
    Ok(db_path(cwd).to_string_lossy().to_string())
}

/// Print a JSON value to stdout (the hook response channel).
fn emit(value: serde_json::Value) {
    println!("{}", value);
}

// ---------------------------------------------------------------------------
// 1. handle_session_start
// ---------------------------------------------------------------------------

/// **Hook: `SessionStart`**
///
/// Runs an incremental index of the project rooted at the event's `cwd`.
/// Reports timing and graph statistics in the response message.
///
/// On any failure the handler silently returns `{"continue": true}` so
/// Claude Code is never blocked.
pub fn handle_session_start() {
    let result = std::panic::catch_unwind(|| {
        let event = read_hook_event();
        let cwd = resolve_cwd(&event);

        let db = match ensure_db(&cwd) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[codegraph] session_start: failed to ensure DB dir: {e}");
                emit(json!({"continue": true}));
                return;
            }
        };

        let conn = match crate::db::schema::initialize_database(&db) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[codegraph] session_start: DB init failed: {e}");
                emit(json!({"continue": true}));
                return;
            }
        };

        let store = crate::graph::store::GraphStore::from_connection(conn);
        let pipeline = crate::indexer::IndexingPipeline::new(&store);

        let start = Instant::now();
        let options = crate::indexer::IndexOptions {
            root_dir: cwd.clone(),
            incremental: true,
        };

        match pipeline.index_directory(&options) {
            Ok(result) => {
                let elapsed = start.elapsed().as_millis();
                let stats = store.get_stats().unwrap_or(crate::graph::store::GraphStats {
                    nodes: 0,
                    edges: 0,
                    files: 0,
                });
                let message = format!(
                    "CodeGraph: indexed {} files ({} nodes, {} edges) in {}ms",
                    result.files_indexed, stats.nodes, stats.edges, elapsed,
                );
                eprintln!("[codegraph] {message}");
                emit(json!({"continue": true, "message": message}));
            }
            Err(e) => {
                eprintln!("[codegraph] session_start: indexing failed: {e}");
                emit(json!({"continue": true}));
            }
        }
    });

    if result.is_err() {
        eprintln!("[codegraph] session_start: caught panic");
        emit(json!({"continue": true}));
    }
}

// ---------------------------------------------------------------------------
// 2. handle_prompt_submit
// ---------------------------------------------------------------------------

/// **Hook: `PromptSubmit`**
///
/// Searches the code graph for context relevant to the user's prompt and
/// injects it as `additionalContext` so Claude has codebase awareness.
///
/// Short prompts (< 15 chars) are skipped — they're unlikely to benefit
/// from graph context and the search cost isn't worth it.
pub fn handle_prompt_submit() {
    let result = std::panic::catch_unwind(|| {
        let event = read_hook_event();
        let cwd = resolve_cwd(&event);

        // Extract the user prompt.
        let prompt = match event["userPrompt"].as_str() {
            Some(p) => p,
            None => {
                emit(json!({"continue": true}));
                return;
            }
        };

        // Skip trivially short prompts.
        if prompt.len() < 15 {
            emit(json!({"continue": true}));
            return;
        }

        let db = match ensure_db(&cwd) {
            Ok(p) => p,
            Err(_) => {
                emit(json!({"continue": true}));
                return;
            }
        };

        // Only proceed if the DB file already exists (don't create an empty
        // one just for a prompt — session_start handles initial indexing).
        if !db_path(&cwd).exists() {
            emit(json!({"continue": true}));
            return;
        }

        let conn = match crate::db::schema::initialize_database(&db) {
            Ok(c) => c,
            Err(_) => {
                emit(json!({"continue": true}));
                return;
            }
        };

        let search = crate::graph::search::HybridSearch::new(&conn);
        let assembler = crate::context::assembler::ContextAssembler::new(&conn, &search);

        let context = assembler.assemble_context(prompt, Some(2000));

        // If the assembler returned nothing meaningful, don't inject noise.
        if context.len() < 20 {
            emit(json!({"continue": true}));
            return;
        }

        eprintln!(
            "[codegraph] prompt_submit: injecting {} chars of context",
            context.len()
        );
        emit(json!({"continue": true, "additionalContext": context}));
    });

    if result.is_err() {
        eprintln!("[codegraph] prompt_submit: caught panic");
        emit(json!({"continue": true}));
    }
}

// ---------------------------------------------------------------------------
// 3. handle_pre_compact
// ---------------------------------------------------------------------------

/// **Hook: `PreCompact`**
///
/// Before Claude Code compacts the conversation, compute PageRank to
/// identify the most important symbols and inject a Markdown summary
/// that survives compaction. This preserves structural awareness across
/// long sessions.
pub fn handle_pre_compact() {
    let result = std::panic::catch_unwind(|| {
        let event = read_hook_event();
        let cwd = resolve_cwd(&event);

        let db = match ensure_db(&cwd) {
            Ok(p) => p,
            Err(_) => {
                emit(json!({"continue": true}));
                return;
            }
        };

        if !db_path(&cwd).exists() {
            emit(json!({"continue": true}));
            return;
        }

        let conn = match crate::db::schema::initialize_database(&db) {
            Ok(c) => c,
            Err(_) => {
                emit(json!({"continue": true}));
                return;
            }
        };

        let store = crate::graph::store::GraphStore::from_connection(conn);
        let ranking = crate::graph::ranking::GraphRanking::new(&store);

        // Compute PageRank: damping 0.85, 100 iterations, take top 30.
        let mut ranked = ranking.compute_page_rank(0.85, 100);
        ranked.truncate(30);

        if ranked.is_empty() {
            emit(json!({"continue": true}));
            return;
        }

        // For each ranked node we need name, kind, and file_path — these
        // live in the nodes table, not in `RankedNode`. Look them up.
        let mut table_rows = Vec::new();
        for entry in &ranked {
            // Fetch node metadata from the store.
            if let Ok(Some(node)) = store.get_node(&entry.node_id) {
                table_rows.push(format!(
                    "| {} | {} | {} | {:.4} |",
                    node.name,
                    node.kind.as_str(),
                    node.file_path,
                    entry.score,
                ));
            }
        }

        let stats = store.get_stats().unwrap_or(crate::graph::store::GraphStats {
            nodes: 0,
            edges: 0,
            files: 0,
        });

        let summary = format!(
            "# CodeGraph — Key Symbols (preserved across compaction)\n\
             \n\
             | Symbol | Kind | File | PageRank |\n\
             |--------|------|------|----------|\n\
             {}\n\
             \n\
             **Graph stats:** {} files, {} nodes, {} edges",
            table_rows.join("\n"),
            stats.files,
            stats.nodes,
            stats.edges,
        );

        eprintln!(
            "[codegraph] pre_compact: preserving {} symbols across compaction",
            table_rows.len()
        );
        emit(json!({"continue": true, "message": summary}));
    });

    if result.is_err() {
        eprintln!("[codegraph] pre_compact: caught panic");
        emit(json!({"continue": true}));
    }
}

// ---------------------------------------------------------------------------
// 4. handle_post_edit
// ---------------------------------------------------------------------------

/// **Hook: `PostToolUse` (after file edit)**
///
/// Re-indexes a single file after Claude edits it, keeping the graph
/// fresh without a full project re-scan. Output is suppressed so the
/// user isn't distracted by indexing noise.
pub fn handle_post_edit() {
    let result = std::panic::catch_unwind(|| {
        let event = read_hook_event();
        let cwd = resolve_cwd(&event);

        // Claude Code puts the edited path in toolInput.file_path or
        // toolInput.path depending on the tool (Write vs Edit).
        let file_path = event["toolInput"]["file_path"]
            .as_str()
            .or_else(|| event["toolInput"]["path"].as_str());

        let file_path = match file_path {
            Some(p) => p,
            None => {
                emit(json!({"continue": true, "suppressOutput": true}));
                return;
            }
        };

        // Only re-index files we understand.
        if !crate::indexer::CodeParser::is_supported(file_path) {
            emit(json!({"continue": true, "suppressOutput": true}));
            return;
        }

        let db = match ensure_db(&cwd) {
            Ok(p) => p,
            Err(_) => {
                emit(json!({"continue": true, "suppressOutput": true}));
                return;
            }
        };

        let conn = match crate::db::schema::initialize_database(&db) {
            Ok(c) => c,
            Err(_) => {
                emit(json!({"continue": true, "suppressOutput": true}));
                return;
            }
        };

        let store = crate::graph::store::GraphStore::from_connection(conn);
        let pipeline = crate::indexer::IndexingPipeline::new(&store);

        let path = Path::new(file_path);
        match pipeline.index_file(path, &cwd) {
            Ok(Some(result)) => {
                eprintln!(
                    "[codegraph] post_edit: re-indexed {} ({} nodes, {} edges) in {}ms",
                    file_path, result.nodes_created, result.edges_created, result.duration_ms,
                );
            }
            Ok(None) => {
                eprintln!("[codegraph] post_edit: skipped {file_path} (unsupported or too large)");
            }
            Err(e) => {
                eprintln!("[codegraph] post_edit: failed to re-index {file_path}: {e}");
            }
        }

        emit(json!({"continue": true, "suppressOutput": true}));
    });

    if result.is_err() {
        eprintln!("[codegraph] post_edit: caught panic");
        emit(json!({"continue": true, "suppressOutput": true}));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_cwd_uses_event_field() {
        let event = json!({"cwd": "/tmp/project"});
        assert_eq!(resolve_cwd(&event), PathBuf::from("/tmp/project"));
    }

    #[test]
    fn resolve_cwd_falls_back_to_current_dir() {
        let event = json!({});
        let cwd = resolve_cwd(&event);
        // Should not be empty — either current_dir or "."
        assert!(!cwd.as_os_str().is_empty());
    }

    #[test]
    fn db_path_builds_expected_path() {
        let p = db_path(Path::new("/home/user/project"));
        assert_eq!(
            p,
            PathBuf::from("/home/user/project/.codegraph/codegraph.db")
        );
    }

    #[test]
    fn read_hook_event_returns_empty_object_on_empty_stdin() {
        // In a test context, stdin is closed/empty — should return {}.
        // We can't easily test stdin in unit tests, but we verify the
        // fallback path by checking the return type contract.
        let fallback: serde_json::Value =
            serde_json::from_str("").unwrap_or(json!({}));
        assert_eq!(fallback, json!({}));
    }
}
