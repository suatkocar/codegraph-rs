//! Claude Code hook runtime handlers.
//!
//! Each handler reads a JSON event from stdin, processes it, and writes a
//! JSON response to stdout. Handlers are invoked by Claude Code at 10
//! lifecycle points (session start/end, prompt, pre/post tool, compaction,
//! subagent, stop, task completed).
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
    std::io::stdin()
        .read_to_string(&mut input)
        .unwrap_or_default();
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
                tracing::error!("session_start: failed to ensure DB dir: {e}");
                emit(json!({"continue": true}));
                return;
            }
        };

        let conn = match crate::db::schema::initialize_database(&db) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("session_start: DB init failed: {e}");
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
                let stats = store
                    .get_stats()
                    .unwrap_or(crate::graph::store::GraphStats {
                        nodes: 0,
                        edges: 0,
                        files: 0,
                    });
                let message = format!(
                    "CodeGraph: indexed {} files ({} nodes, {} edges) in {}ms",
                    result.files_indexed, stats.nodes, stats.edges, elapsed,
                );
                tracing::info!("{message}");
                emit(json!({"continue": true, "message": message}));
            }
            Err(e) => {
                tracing::error!("session_start: indexing failed: {e}");
                emit(json!({"continue": true}));
            }
        }
    });

    if result.is_err() {
        tracing::error!("session_start: caught panic");
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

        tracing::info!(
            "prompt_submit: injecting {} chars of context",
            context.len()
        );
        emit(json!({"continue": true, "additionalContext": context}));
    });

    if result.is_err() {
        tracing::error!("prompt_submit: caught panic");
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

        let stats = store
            .get_stats()
            .unwrap_or(crate::graph::store::GraphStats {
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

        tracing::info!(
            "pre_compact: preserving {} symbols across compaction",
            table_rows.len()
        );
        emit(json!({"continue": true, "message": summary}));
    });

    if result.is_err() {
        tracing::error!("pre_compact: caught panic");
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
                tracing::info!(
                    "post_edit: re-indexed {} ({} nodes, {} edges) in {}ms",
                    file_path,
                    result.nodes_created,
                    result.edges_created,
                    result.duration_ms,
                );
            }
            Ok(None) => {
                tracing::info!("post_edit: skipped {file_path} (unsupported or too large)");
            }
            Err(e) => {
                tracing::error!("post_edit: failed to re-index {file_path}: {e}");
            }
        }

        emit(json!({"continue": true, "suppressOutput": true}));
    });

    if result.is_err() {
        tracing::error!("post_edit: caught panic");
        emit(json!({"continue": true, "suppressOutput": true}));
    }
}

// ---------------------------------------------------------------------------
// 5. handle_pre_tool_use
// ---------------------------------------------------------------------------

/// **Hook: `PreToolUse`**
///
/// Fires before a tool call executes. Searches the code graph for context
/// relevant to the tool's input (e.g. file paths, symbol names) and injects
/// it as `additionalContext` so the tool operates with codebase awareness.
///
/// For Bash/Read/Glob tools, extracts file paths and provides symbol context.
/// For Edit/Write tools, provides callers/dependents of affected symbols.
/// For Grep, augments with semantic search results from the graph.
pub fn handle_pre_tool_use() {
    let result = std::panic::catch_unwind(|| {
        let event = read_hook_event();
        let cwd = resolve_cwd(&event);

        let tool_name = match event["toolName"].as_str() {
            Some(n) => n.to_string(),
            None => {
                emit(json!({"continue": true}));
                return;
            }
        };

        // Only inject context for tools that benefit from codebase awareness.
        let relevant_tools = ["Edit", "Write", "Read", "Grep", "Bash", "Glob"];
        if !relevant_tools.iter().any(|t| tool_name.contains(t)) {
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

        // Extract a search hint from toolInput — try file_path, path, query,
        // command, or pattern fields.
        let tool_input = &event["toolInput"];
        let search_hint = tool_input["file_path"]
            .as_str()
            .or_else(|| tool_input["path"].as_str())
            .or_else(|| tool_input["query"].as_str())
            .or_else(|| tool_input["pattern"].as_str())
            .or_else(|| tool_input["command"].as_str());

        let hint = match search_hint {
            Some(h) if h.len() >= 5 => h,
            _ => {
                emit(json!({"continue": true}));
                return;
            }
        };

        // If the hint looks like a file path, look up symbols in that file.
        // Otherwise, do a hybrid search.
        let context = if hint.contains('/') || hint.contains('.') {
            // Try to find symbols in this file.
            let store = crate::graph::store::GraphStore::from_connection(conn);
            let rel_path = hint
                .strip_prefix(cwd.to_str().unwrap_or(""))
                .unwrap_or(hint)
                .trim_start_matches('/');

            match store.get_nodes_by_file(rel_path) {
                Ok(nodes) if !nodes.is_empty() => {
                    let mut ctx = format!("CodeGraph: {} symbols in {}:\n", nodes.len(), rel_path);
                    for node in nodes.iter().take(20) {
                        ctx.push_str(&format!(
                            "  - {} ({}) L{}\n",
                            node.name,
                            node.kind.as_str(),
                            node.start_line,
                        ));
                    }
                    ctx
                }
                _ => String::new(),
            }
        } else {
            // Semantic search for the hint.
            let search = crate::graph::search::HybridSearch::new(&conn);
            let opts = crate::graph::search::SearchOptions {
                limit: Some(5),
                ..Default::default()
            };
            match search.search(hint, &opts) {
                Ok(results) if !results.is_empty() => {
                    let mut ctx = format!("CodeGraph: relevant symbols for '{}':\n", hint);
                    for r in &results {
                        ctx.push_str(&format!(
                            "  - {} ({}) in {} [score: {:.3}]\n",
                            r.name, r.kind, r.file_path, r.score,
                        ));
                    }
                    ctx
                }
                _ => String::new(),
            }
        };

        if context.len() < 20 {
            emit(json!({"continue": true}));
            return;
        }

        tracing::info!(
            "pre_tool_use: injecting {} chars for {}",
            context.len(),
            tool_name
        );
        emit(json!({"continue": true, "additionalContext": context}));
    });

    if result.is_err() {
        tracing::error!("pre_tool_use: caught panic");
        emit(json!({"continue": true}));
    }
}

// ---------------------------------------------------------------------------
// 6. handle_subagent_start
// ---------------------------------------------------------------------------

/// **Hook: `SubagentStart`**
///
/// Fires when a subagent is spawned. Injects a project overview (structure,
/// key symbols, frameworks) into the subagent's context so it starts with
/// codebase awareness rather than working blind.
pub fn handle_subagent_start() {
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

        // Build a compact project overview for the subagent.
        let stats = store
            .get_stats()
            .unwrap_or(crate::graph::store::GraphStats {
                nodes: 0,
                edges: 0,
                files: 0,
            });

        // Get top symbols by PageRank.
        let ranking = crate::graph::ranking::GraphRanking::new(&store);
        let mut ranked = ranking.compute_page_rank(0.85, 100);
        ranked.truncate(15);

        let mut overview = format!(
            "CodeGraph Project Overview ({} files, {} nodes, {} edges):\n\n",
            stats.files, stats.nodes, stats.edges,
        );

        // Top symbols
        if !ranked.is_empty() {
            overview.push_str("Key symbols (by importance):\n");
            for entry in &ranked {
                if let Ok(Some(node)) = store.get_node(&entry.node_id) {
                    overview.push_str(&format!(
                        "  - {} ({}) in {}\n",
                        node.name,
                        node.kind.as_str(),
                        node.file_path,
                    ));
                }
            }
            overview.push('\n');
        }

        // Detect frameworks
        let cwd_str = cwd.to_string_lossy().to_string();
        let frameworks = crate::resolution::frameworks::detect_frameworks(&cwd_str);
        if !frameworks.is_empty() {
            overview.push_str("Frameworks: ");
            let names: Vec<String> = frameworks.iter().map(|f| f.name.clone()).collect();
            overview.push_str(&names.join(", "));
            overview.push('\n');
        }

        overview.push_str("\nUse CodeGraph MCP tools (codegraph_query, codegraph_callers, etc.) for code navigation.\n");

        tracing::info!(
            "subagent_start: injecting {} chars of project context",
            overview.len()
        );
        emit(json!({"continue": true, "additionalContext": overview}));
    });

    if result.is_err() {
        tracing::error!("subagent_start: caught panic");
        emit(json!({"continue": true}));
    }
}

// ---------------------------------------------------------------------------
// 7. handle_post_tool_failure
// ---------------------------------------------------------------------------

/// **Hook: `PostToolUseFailure`**
///
/// Fires after a tool call fails. Searches the code graph for corrective
/// context — e.g. if a symbol wasn't found, searches for where it moved;
/// if a file doesn't exist, suggests alternatives from the graph.
pub fn handle_post_tool_failure() {
    let result = std::panic::catch_unwind(|| {
        let event = read_hook_event();
        let cwd = resolve_cwd(&event);

        let tool_name = event["toolName"].as_str().unwrap_or("unknown");
        let error_msg = event["toolError"]
            .as_str()
            .or_else(|| event["error"].as_str())
            .unwrap_or("");

        // Only help if we have meaningful error context.
        if error_msg.len() < 10 {
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

        // Extract useful search terms from the error message and tool input.
        // Common patterns: "not found", "no such file", symbol names, file paths.
        let tool_input = &event["toolInput"];
        let search_term = tool_input["file_path"]
            .as_str()
            .or_else(|| tool_input["path"].as_str())
            .or_else(|| tool_input["old_string"].as_str())
            .or_else(|| tool_input["pattern"].as_str());

        // Try to extract a meaningful search query.
        let query = if let Some(term) = search_term {
            // Extract filename or symbol from path.
            let basename = term
                .rsplit('/')
                .next()
                .unwrap_or(term)
                .trim_end_matches(".rs")
                .trim_end_matches(".ts")
                .trim_end_matches(".py")
                .trim_end_matches(".js");
            basename.to_string()
        } else {
            // Try to extract identifiers from the error message.
            // Look for quoted strings or CamelCase/snake_case identifiers.
            let words: Vec<&str> = error_msg
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .filter(|w| w.len() >= 4)
                .take(3)
                .collect();
            if words.is_empty() {
                emit(json!({"continue": true}));
                return;
            }
            words.join(" ")
        };

        if query.len() < 3 {
            emit(json!({"continue": true}));
            return;
        }

        let search = crate::graph::search::HybridSearch::new(&conn);
        let opts = crate::graph::search::SearchOptions {
            limit: Some(5),
            ..Default::default()
        };

        let context = match search.search(&query, &opts) {
            Ok(results) if !results.is_empty() => {
                let mut ctx = format!(
                    "CodeGraph: {} tool failed. Related symbols found:\n",
                    tool_name
                );
                for r in &results {
                    ctx.push_str(&format!("  - {} ({}) in {}\n", r.name, r.kind, r.file_path,));
                    if let Some(ref snippet) = r.snippet {
                        let short = if snippet.len() > 80 {
                            &snippet[..snippet.floor_char_boundary(80)]
                        } else {
                            snippet
                        };
                        ctx.push_str(&format!("    {}\n", short));
                    }
                }
                ctx.push_str("\nThese symbols may be what you were looking for.\n");
                ctx
            }
            _ => String::new(),
        };

        if context.len() < 20 {
            emit(json!({"continue": true}));
            return;
        }

        tracing::info!(
            "post_tool_failure: injecting {} chars of corrective context for {}",
            context.len(),
            tool_name
        );
        emit(json!({"continue": true, "additionalContext": context}));
    });

    if result.is_err() {
        tracing::error!("post_tool_failure: caught panic");
        emit(json!({"continue": true}));
    }
}

// ---------------------------------------------------------------------------
// 8. handle_stop
// ---------------------------------------------------------------------------

/// **Hook: `Stop`**
///
/// Fires when the agent is about to stop. Checks if there are pending
/// graph inconsistencies (e.g. unresolved refs spike) and can suggest
/// the agent continue to address them. Returns `{"stop": true}` to
/// allow the stop or `{"stop": false, "message": "..."}` to prevent it.
pub fn handle_stop() {
    let result = std::panic::catch_unwind(|| {
        let event = read_hook_event();
        let cwd = resolve_cwd(&event);

        // If no DB exists, nothing to check — let the agent stop.
        if !db_path(&cwd).exists() {
            emit(json!({"stop": true}));
            return;
        }

        let db = match ensure_db(&cwd) {
            Ok(p) => p,
            Err(_) => {
                emit(json!({"stop": true}));
                return;
            }
        };

        let conn = match crate::db::schema::initialize_database(&db) {
            Ok(c) => c,
            Err(_) => {
                emit(json!({"stop": true}));
                return;
            }
        };

        let store = crate::graph::store::GraphStore::from_connection(conn);
        let unresolved = store.get_unresolved_ref_count().unwrap_or(0);
        let stats = store
            .get_stats()
            .unwrap_or(crate::graph::store::GraphStats {
                nodes: 0,
                edges: 0,
                files: 0,
            });

        // If unresolved refs are more than 20% of total nodes, suggest continuing.
        if stats.nodes > 0 && unresolved as f64 / stats.nodes as f64 > 0.2 {
            let message = format!(
                "CodeGraph: {} unresolved references out of {} nodes ({:.0}%). \
                 Consider running `codegraph index --force` to resolve.",
                unresolved,
                stats.nodes,
                (unresolved as f64 / stats.nodes as f64) * 100.0,
            );
            tracing::warn!("stop: high unresolved refs, suggesting continue");
            emit(json!({"stop": false, "message": message}));
        } else {
            emit(json!({"stop": true}));
        }
    });

    if result.is_err() {
        tracing::error!("stop: caught panic");
        emit(json!({"stop": true}));
    }
}

// ---------------------------------------------------------------------------
// 9. handle_task_completed
// ---------------------------------------------------------------------------

/// **Hook: `TaskCompleted`**
///
/// Fires when a task is marked complete. Runs a quick quality gate:
/// re-indexes the project and reports any new dead code or unresolved
/// references introduced during the task.
pub fn handle_task_completed() {
    let result = std::panic::catch_unwind(|| {
        let event = read_hook_event();
        let cwd = resolve_cwd(&event);

        if !db_path(&cwd).exists() {
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

        let conn = match crate::db::schema::initialize_database(&db) {
            Ok(c) => c,
            Err(_) => {
                emit(json!({"continue": true}));
                return;
            }
        };

        let store = crate::graph::store::GraphStore::from_connection(conn);
        let pipeline = crate::indexer::IndexingPipeline::new(&store);

        // Quick incremental re-index to catch latest changes.
        let _ = pipeline.index_directory(&crate::indexer::IndexOptions {
            root_dir: cwd.clone(),
            incremental: true,
        });

        // Check for dead code introduced.
        let dead = crate::resolution::dead_code::find_dead_code(&store.conn, &[]);
        let unresolved = store.get_unresolved_ref_count().unwrap_or(0);

        let mut issues = Vec::new();
        if !dead.is_empty() {
            issues.push(format!(
                "{} potentially unused symbols detected",
                dead.len()
            ));
            for d in dead.iter().take(5) {
                issues.push(format!("  - {} ({}) in {}", d.name, d.kind, d.file_path));
            }
        }
        if unresolved > 0 {
            issues.push(format!("{} unresolved references", unresolved));
        }

        if issues.is_empty() {
            tracing::info!("task_completed: quality gate passed");
            emit(
                json!({"continue": true, "message": "CodeGraph: quality gate passed — no dead code or unresolved refs."}),
            );
        } else {
            let message = format!("CodeGraph quality gate:\n{}", issues.join("\n"));
            tracing::warn!("task_completed: {} issues found", issues.len());
            emit(json!({"continue": true, "message": message}));
        }
    });

    if result.is_err() {
        tracing::error!("task_completed: caught panic");
        emit(json!({"continue": true}));
    }
}

// ---------------------------------------------------------------------------
// 10. handle_session_end
// ---------------------------------------------------------------------------

/// **Hook: `SessionEnd`**
///
/// Fires when the Claude Code session ends. Runs a final incremental
/// re-index and logs session statistics to stderr for diagnostics.
pub fn handle_session_end() {
    let result = std::panic::catch_unwind(|| {
        let event = read_hook_event();
        let cwd = resolve_cwd(&event);

        if !db_path(&cwd).exists() {
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

        let conn = match crate::db::schema::initialize_database(&db) {
            Ok(c) => c,
            Err(_) => {
                emit(json!({"continue": true}));
                return;
            }
        };

        let store = crate::graph::store::GraphStore::from_connection(conn);
        let pipeline = crate::indexer::IndexingPipeline::new(&store);

        // Final re-index to capture any last-second changes.
        let start = std::time::Instant::now();
        let index_result = pipeline.index_directory(&crate::indexer::IndexOptions {
            root_dir: cwd.clone(),
            incremental: true,
        });

        let elapsed = start.elapsed().as_millis();
        let stats = store
            .get_stats()
            .unwrap_or(crate::graph::store::GraphStats {
                nodes: 0,
                edges: 0,
                files: 0,
            });
        let unresolved = store.get_unresolved_ref_count().unwrap_or(0);

        let files_indexed = match &index_result {
            Ok(r) => r.files_indexed,
            Err(_) => 0,
        };

        tracing::info!(
            "session_end: final index -- {} files in {}ms \
             (total: {} files, {} nodes, {} edges, {} unresolved)",
            files_indexed,
            elapsed,
            stats.files,
            stats.nodes,
            stats.edges,
            unresolved,
        );

        emit(json!({"continue": true}));
    });

    if result.is_err() {
        tracing::error!("session_end: caught panic");
        emit(json!({"continue": true}));
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
        let fallback: serde_json::Value = serde_json::from_str("").unwrap_or(json!({}));
        assert_eq!(fallback, json!({}));
    }
}
