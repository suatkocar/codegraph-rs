use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

use codegraph_mcp::db::schema::initialize_database;
use codegraph_mcp::graph::ranking::GraphRanking;
use codegraph_mcp::graph::search::{HybridSearch, SearchOptions};
use codegraph_mcp::graph::store::GraphStore;
use codegraph_mcp::indexer::{IndexOptions, IndexingPipeline};

#[derive(Parser)]
#[command(name = "codegraph-mcp")]
#[command(version, about = "Codebase intelligence MCP server — semantic code graph with vector search")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Set up CodeGraph: index codebase, configure MCP server, install hooks
    Init {
        /// Project directory (default: current dir)
        #[arg(default_value = ".")]
        directory: String,
    },
    /// Index a codebase
    Index {
        /// Directory to index (default: current dir)
        #[arg(default_value = ".")]
        directory: String,
        /// Force full re-index
        #[arg(long)]
        force: bool,
    },
    /// Search the code graph
    Query {
        /// Search query
        query: String,
        /// Maximum results
        #[arg(short = 'n', long, default_value_t = 10)]
        limit: usize,
    },
    /// Show blast radius of changing a file or symbol
    Impact {
        /// File path or symbol name
        target: String,
        /// Database path
        #[arg(long, default_value = ".codegraph/codegraph.db")]
        db: String,
    },
    /// Watch for file changes and re-index incrementally
    Watch {
        /// Directory to watch (default: current dir)
        #[arg(default_value = ".")]
        directory: String,
    },
    /// Start the CodeGraph MCP server (stdio transport)
    Serve {
        /// Database path
        #[arg(long, default_value = ".codegraph/codegraph.db")]
        db: String,
    },
    /// Show index statistics
    Stats {
        /// Database path
        #[arg(long, default_value = ".codegraph/codegraph.db")]
        db: String,
    },
    /// Install CodeGraph hooks into Claude Code settings
    InstallHooks {
        /// Project directory
        #[arg(default_value = ".")]
        directory: String,
    },
    /// Find potentially unused/dead code symbols
    DeadCode {
        /// Database path
        #[arg(long, default_value = ".codegraph/codegraph.db")]
        db: String,
        /// Filter by node kind (e.g., function, class, method)
        #[arg(long)]
        kind: Option<String>,
    },
    /// Detect frameworks and libraries used in the project
    Frameworks {
        /// Project directory
        #[arg(default_value = ".")]
        directory: String,
    },
    /// Show language breakdown statistics
    Languages {
        /// Database path
        #[arg(long, default_value = ".codegraph/codegraph.db")]
        db: String,
    },
    /// Install or manage git hooks
    GitHooks {
        /// Action: install or uninstall
        #[arg(default_value = "install")]
        action: String,
        /// Project directory
        #[arg(long, default_value = ".")]
        directory: String,
    },
    /// Internal: SessionStart hook handler
    HookSessionStart,
    /// Internal: UserPromptSubmit hook handler
    HookPromptSubmit,
    /// Internal: PreCompact hook handler
    HookPreCompact,
    /// Internal: PostToolUse hook handler
    HookPostEdit,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { directory } => {
            cmd_init(&directory);
        }
        Commands::Index { directory, force } => {
            cmd_index(&directory, force);
        }
        Commands::Query { query, limit } => {
            cmd_query(&query, limit);
        }
        Commands::Impact { target, db } => {
            cmd_impact(&target, &db);
        }
        Commands::Watch { directory } => {
            println!("Watch: {directory}");
            // TODO: Phase 6 — notify-based incremental re-index
        }
        Commands::Serve { db } => {
            cmd_serve(&db);
        }
        Commands::Stats { db } => {
            cmd_stats(&db);
        }
        Commands::InstallHooks { directory } => {
            cmd_install_hooks(&directory);
        }
        Commands::DeadCode { db, kind } => {
            cmd_dead_code(&db, kind.as_deref());
        }
        Commands::Frameworks { directory } => {
            cmd_frameworks(&directory);
        }
        Commands::Languages { db } => {
            cmd_languages(&db);
        }
        Commands::GitHooks { action, directory } => {
            cmd_git_hooks(&action, &directory);
        }
        Commands::HookSessionStart => {
            codegraph_mcp::hooks::handlers::handle_session_start();
        }
        Commands::HookPromptSubmit => {
            codegraph_mcp::hooks::handlers::handle_prompt_submit();
        }
        Commands::HookPreCompact => {
            codegraph_mcp::hooks::handlers::handle_pre_compact();
        }
        Commands::HookPostEdit => {
            codegraph_mcp::hooks::handlers::handle_post_edit();
        }
    }
}

// ---------------------------------------------------------------------------
// CLI command implementations
// ---------------------------------------------------------------------------

fn open_store(db_path: &str) -> GraphStore {
    let conn = initialize_database(db_path).unwrap_or_else(|e| {
        eprintln!("Error: cannot open database: {}", e);
        process::exit(1);
    });
    GraphStore::from_connection(conn)
}

fn cmd_init(directory: &str) {
    cmd_index(directory, false);
    cmd_install_hooks(directory);

    // Install git post-commit hook if in a git repo
    if codegraph_mcp::hooks::git_hooks::is_git_repo(directory) {
        if let Err(e) = codegraph_mcp::hooks::git_hooks::install_git_post_commit_hook(directory) {
            eprintln!("[codegraph] Warning: git hook install failed: {}", e);
        } else {
            eprintln!("[codegraph] Git post-commit hook installed.");
        }
    }

    // Generate CLAUDE.md template
    let db_path = PathBuf::from(directory).join(".codegraph/codegraph.db");
    if db_path.exists() {
        let store = open_store(db_path.to_str().unwrap());
        let stats_data = store.get_stats().unwrap_or_else(|_| codegraph_mcp::graph::store::GraphStats { files: 0, nodes: 0, edges: 0 });
        let proj_stats = codegraph_mcp::hooks::claude_template::ProjectStats {
            total_nodes: stats_data.nodes,
            total_edges: stats_data.edges,
            ..Default::default()
        };
        if let Err(e) = codegraph_mcp::hooks::claude_template::generate_claude_md(directory, &proj_stats) {
            eprintln!("[codegraph] Warning: CLAUDE.md generation failed: {}", e);
        } else {
            eprintln!("[codegraph] CLAUDE.md template generated.");
        }
    }

    eprintln!("[codegraph] Ready. MCP server + hooks configured.");
}

fn cmd_install_hooks(directory: &str) {
    let root = PathBuf::from(directory)
        .canonicalize()
        .unwrap_or_else(|e| {
            eprintln!("Error: cannot resolve directory '{}': {}", directory, e);
            process::exit(1);
        });

    // Use the current binary's path as the default binary reference
    let binary_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "codegraph-mcp".to_string());

    codegraph_mcp::hooks::install::install_hooks(&root, &binary_path).unwrap_or_else(|e| {
        eprintln!("Error: failed to install hooks: {}", e);
        process::exit(1);
    });

    eprintln!("[codegraph] Hooks installed in {}", root.display());
}

fn cmd_index(directory: &str, force: bool) {
    let root = PathBuf::from(directory)
        .canonicalize()
        .unwrap_or_else(|e| {
            eprintln!("Error: cannot resolve directory '{}': {}", directory, e);
            process::exit(1);
        });

    let db_dir = root.join(".codegraph");
    std::fs::create_dir_all(&db_dir).unwrap_or_else(|e| {
        eprintln!("Error: cannot create .codegraph directory: {}", e);
        process::exit(1);
    });

    let db_path = db_dir.join("codegraph.db");
    let store = open_store(db_path.to_str().unwrap());
    let pipeline = IndexingPipeline::new(&store);

    let result = pipeline
        .index_directory(&IndexOptions {
            root_dir: root.clone(),
            incremental: !force,
        })
        .unwrap_or_else(|e| {
            eprintln!("Error: indexing failed: {}", e);
            process::exit(1);
        });

    println!("{}", result);

    let stats = store.get_stats().unwrap();
    println!(
        "Database totals: {} files, {} nodes, {} edges",
        stats.files, stats.nodes, stats.edges,
    );
}

fn cmd_query(query: &str, limit: usize) {
    let store = open_store(".codegraph/codegraph.db");
    let search = HybridSearch::new(&store.conn);
    let opts = SearchOptions {
        limit: Some(limit),
        ..Default::default()
    };

    match search.search(query, &opts) {
        Ok(results) => {
            if results.is_empty() {
                println!("No results found for \"{}\".", query);
                return;
            }
            for (i, r) in results.iter().enumerate() {
                println!(
                    "{}. {} ({}) — {} [score: {:.4}]",
                    i + 1,
                    r.name,
                    r.kind,
                    r.file_path,
                    r.score
                );
                if let Some(ref snippet) = r.snippet {
                    println!("   {}", snippet);
                }
            }
        }
        Err(e) => {
            eprintln!("Error: search failed: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_impact(target: &str, db_path: &str) {
    let store = open_store(db_path);
    let ranking = GraphRanking::new(&store);
    let impact = ranking.compute_impact(target);

    println!("Impact Analysis: {}", impact.node_id);
    println!("  Risk:                 {}", impact.risk);
    println!("  Direct dependents:    {}", impact.direct_dependents);
    println!("  Transitive dependents:{}", impact.transitive_dependents);
    println!("  Affected files:       {}", impact.affected_files.len());
    for f in &impact.affected_files {
        println!("    - {}", f);
    }
}

fn cmd_serve(db_path: &str) {
    let db = PathBuf::from(db_path);
    if !db.exists() {
        eprintln!("Error: database not found at '{}'", db_path);
        eprintln!("Run `codegraph-mcp index <dir>` first to create an index.");
        process::exit(1);
    }

    let store = open_store(db_path);

    // Build a minimal tokio runtime for the MCP server
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|e| {
            eprintln!("Error: cannot create async runtime: {}", e);
            process::exit(1);
        });

    rt.block_on(async {
        if let Err(e) = codegraph_mcp::mcp::server::run_server(store).await {
            eprintln!("Error: MCP server failed: {}", e);
            process::exit(1);
        }
    });
}

fn cmd_dead_code(db_path: &str, kind_filter: Option<&str>) {
    let store = open_store(db_path);
    let kinds: Vec<codegraph_mcp::types::NodeKind> = match kind_filter {
        Some(k) => k
            .split(',')
            .filter_map(|s| codegraph_mcp::types::NodeKind::from_str_loose(s.trim()))
            .collect(),
        None => Vec::new(),
    };

    let results = codegraph_mcp::resolution::dead_code::find_dead_code(&store.conn, &kinds);
    if results.is_empty() {
        println!("No dead code found.");
        return;
    }

    println!("Potentially unused symbols ({} found):", results.len());
    for r in &results {
        println!("  {} ({}) — {}:{}", r.name, r.kind, r.file_path, r.start_line);
    }
}

fn cmd_frameworks(directory: &str) {
    let frameworks = codegraph_mcp::resolution::frameworks::detect_frameworks(directory);
    if frameworks.is_empty() {
        println!("No frameworks detected.");
        return;
    }

    println!("Detected frameworks:");
    for f in &frameworks {
        let version = f.version.as_deref().unwrap_or("?");
        println!(
            "  {} v{} ({}, {}) — confidence: {:.0}%",
            f.name, version, f.language, f.category, f.confidence * 100.0
        );
    }
}

fn cmd_languages(db_path: &str) {
    let store = open_store(db_path);
    let stats = store.get_stats().unwrap_or_else(|_| codegraph_mcp::graph::store::GraphStats { files: 0, nodes: 0, edges: 0 });

    // Query language breakdown from file_hashes
    let mut stmt = store
        .conn
        .prepare("SELECT language, COUNT(*) FROM file_hashes GROUP BY language ORDER BY COUNT(*) DESC")
        .unwrap();
    let rows: Vec<(String, i64)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();

    println!("Language breakdown ({} total files):", stats.files);
    for (lang, count) in &rows {
        println!("  {:12} — {} files", lang, count);
    }
    println!("\nTotal: {} nodes, {} edges", stats.nodes, stats.edges);
}

fn cmd_git_hooks(action: &str, directory: &str) {
    match action {
        "install" => {
            if let Err(e) = codegraph_mcp::hooks::git_hooks::install_git_post_commit_hook(directory) {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
            println!("Git post-commit hook installed.");
        }
        "uninstall" => {
            if let Err(e) = codegraph_mcp::hooks::git_hooks::uninstall_git_post_commit_hook(directory) {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
            println!("Git post-commit hook removed.");
        }
        other => {
            eprintln!("Unknown action '{}'. Use 'install' or 'uninstall'.", other);
            process::exit(1);
        }
    }
}

fn cmd_stats(db_path: &str) {
    let db = PathBuf::from(db_path);
    if !db.exists() {
        eprintln!("Error: database not found at '{}'", db_path);
        eprintln!("Run `codegraph-mcp index <dir>` first to create an index.");
        process::exit(1);
    }

    let store = open_store(db_path);
    let stats = store.get_stats().unwrap_or_else(|e| {
        eprintln!("Error: cannot read stats: {}", e);
        process::exit(1);
    });

    println!("CodeGraph Statistics");
    println!("  Files:  {}", stats.files);
    println!("  Nodes:  {}", stats.nodes);
    println!("  Edges:  {}", stats.edges);
}
