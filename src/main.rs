use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

use codegraph::cli::installer;
use codegraph::db::schema::initialize_database;
use codegraph::graph::ranking::GraphRanking;
use codegraph::graph::search::{HybridSearch, SearchOptions};
use codegraph::graph::store::GraphStore;
use codegraph::indexer::{CodeParser, IndexOptions, IndexingPipeline};
use codegraph::types::Language;

#[derive(Parser)]
#[command(name = "codegraph")]
#[command(
    version,
    about = "Codebase intelligence MCP server — semantic code graph with vector search"
)]
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
        /// Non-interactive mode (assume yes to all prompts)
        #[arg(short = 'y', long = "yes")]
        non_interactive: bool,
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
        Commands::Init {
            directory,
            non_interactive,
        } => {
            cmd_init(&directory, non_interactive);
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
            codegraph::hooks::handlers::handle_session_start();
        }
        Commands::HookPromptSubmit => {
            codegraph::hooks::handlers::handle_prompt_submit();
        }
        Commands::HookPreCompact => {
            codegraph::hooks::handlers::handle_pre_compact();
        }
        Commands::HookPostEdit => {
            codegraph::hooks::handlers::handle_post_edit();
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

fn cmd_init(directory: &str, non_interactive: bool) {
    // Step 1: Print banner
    installer::print_banner();

    // Step 2: Resolve project directory
    let root = PathBuf::from(directory).canonicalize().unwrap_or_else(|e| {
        eprintln!("Error: cannot resolve directory '{}': {}", directory, e);
        process::exit(1);
    });
    let root_str = root.to_string_lossy().to_string();

    // Step 3: Scan directory to detect languages
    let file_paths = walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| {
            let path = e.path().to_string_lossy().to_string();
            CodeParser::detect_language(&path).map(|lang| (lang, path))
        })
        .collect::<Vec<(Language, String)>>();

    // Build language counts
    let mut lang_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (lang, _) in &file_paths {
        *lang_counts.entry(lang.to_string()).or_default() += 1;
    }
    let mut lang_sorted: Vec<(String, usize)> = lang_counts.into_iter().collect();
    lang_sorted.sort_by(|a, b| b.1.cmp(&a.1));

    // Detect frameworks
    let detected_frameworks =
        codegraph::resolution::frameworks::detect_frameworks(directory);
    let framework_names: Vec<String> = detected_frameworks
        .iter()
        .map(|f| f.name.clone())
        .collect();

    // Step 4: Print detection results
    installer::print_project_detection(&root_str, &lang_sorted, &framework_names);

    // Step 5: Confirm indexing
    if !installer::confirm("Index this project?", non_interactive) {
        println!("  Aborted.");
        return;
    }

    // Step 6: Index with progress
    let total_files = file_paths.len() as u64;
    let spinner = installer::create_spinner(&format!("Indexing {} files...", total_files));
    cmd_index(directory, false);
    spinner.finish_and_clear();

    // Get stats for summary
    let db_path = root.join(".codegraph/codegraph.db");
    let stats_data = if db_path.exists() {
        let store = open_store(db_path.to_str().unwrap());
        store
            .get_stats()
            .unwrap_or(codegraph::graph::store::GraphStats {
                files: 0,
                nodes: 0,
                edges: 0,
            })
    } else {
        codegraph::graph::store::GraphStats {
            files: 0,
            nodes: 0,
            edges: 0,
        }
    };

    // Step 7: Confirm hooks installation
    let mut hooks_installed = false;
    if installer::confirm("Install Claude Code hooks?", non_interactive) {
        cmd_install_hooks(directory);
        hooks_installed = true;
    }

    // Step 8: Git hook (only if .git exists)
    let mut git_hook_installed = false;
    let is_git = codegraph::hooks::git_hooks::is_git_repo(directory);
    if is_git && installer::confirm("Install git post-commit hook?", non_interactive) {
        match codegraph::hooks::git_hooks::install_git_post_commit_hook(directory) {
            Ok(()) => git_hook_installed = true,
            Err(e) => eprintln!("  Warning: git hook install failed: {}", e),
        }
    }

    // Step 9: Generate CLAUDE.md
    let mut claude_md_generated = false;
    if db_path.exists() {
        let store = open_store(db_path.to_str().unwrap());
        let s = store
            .get_stats()
            .unwrap_or(codegraph::graph::store::GraphStats {
                files: 0,
                nodes: 0,
                edges: 0,
            });
        let proj_stats = codegraph::hooks::claude_template::ProjectStats {
            total_nodes: s.nodes,
            total_edges: s.edges,
            ..Default::default()
        };
        if codegraph::hooks::claude_template::generate_claude_md(directory, &proj_stats)
            .is_ok()
        {
            claude_md_generated = true;
        }
    }

    // Step 10: Print summary
    installer::print_summary(
        stats_data.files,
        stats_data.nodes,
        stats_data.edges,
        hooks_installed,
        hooks_installed, // MCP is registered as part of hooks
        claude_md_generated,
        git_hook_installed,
    );
}

fn cmd_install_hooks(directory: &str) {
    let root = PathBuf::from(directory).canonicalize().unwrap_or_else(|e| {
        eprintln!("Error: cannot resolve directory '{}': {}", directory, e);
        process::exit(1);
    });

    // Use the current binary's path as the default binary reference
    let binary_path = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "codegraph".to_string());

    codegraph::hooks::install::install_hooks(&root, &binary_path).unwrap_or_else(|e| {
        eprintln!("Error: failed to install hooks: {}", e);
        process::exit(1);
    });

    eprintln!("[codegraph] Hooks installed in {}", root.display());
}

fn cmd_index(directory: &str, force: bool) {
    let root = PathBuf::from(directory).canonicalize().unwrap_or_else(|e| {
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
        eprintln!("Run `codegraph index <dir>` first to create an index.");
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
        if let Err(e) = codegraph::mcp::server::run_server(store).await {
            eprintln!("Error: MCP server failed: {}", e);
            process::exit(1);
        }
    });
}

fn cmd_dead_code(db_path: &str, kind_filter: Option<&str>) {
    let store = open_store(db_path);
    let kinds: Vec<codegraph::types::NodeKind> = match kind_filter {
        Some(k) => k
            .split(',')
            .filter_map(|s| codegraph::types::NodeKind::from_str_loose(s.trim()))
            .collect(),
        None => Vec::new(),
    };

    let results = codegraph::resolution::dead_code::find_dead_code(&store.conn, &kinds);
    if results.is_empty() {
        println!("No dead code found.");
        return;
    }

    println!("Potentially unused symbols ({} found):", results.len());
    for r in &results {
        println!(
            "  {} ({}) — {}:{}",
            r.name, r.kind, r.file_path, r.start_line
        );
    }
}

fn cmd_frameworks(directory: &str) {
    let frameworks = codegraph::resolution::frameworks::detect_frameworks(directory);
    if frameworks.is_empty() {
        println!("No frameworks detected.");
        return;
    }

    println!("Detected frameworks:");
    for f in &frameworks {
        let version = f.version.as_deref().unwrap_or("?");
        println!(
            "  {} v{} ({}, {}) — confidence: {:.0}%",
            f.name,
            version,
            f.language,
            f.category,
            f.confidence * 100.0
        );
    }
}

fn cmd_languages(db_path: &str) {
    let store = open_store(db_path);
    let stats = store
        .get_stats()
        .unwrap_or(codegraph::graph::store::GraphStats {
            files: 0,
            nodes: 0,
            edges: 0,
        });

    // Query language breakdown from file_hashes
    let mut stmt = store
        .conn
        .prepare(
            "SELECT language, COUNT(*) FROM file_hashes GROUP BY language ORDER BY COUNT(*) DESC",
        )
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
            if let Err(e) = codegraph::hooks::git_hooks::install_git_post_commit_hook(directory)
            {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
            println!("Git post-commit hook installed.");
        }
        "uninstall" => {
            if let Err(e) =
                codegraph::hooks::git_hooks::uninstall_git_post_commit_hook(directory)
            {
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
        eprintln!("Run `codegraph index <dir>` first to create an index.");
        process::exit(1);
    }

    let store = open_store(db_path);
    let stats = store.get_stats().unwrap_or_else(|e| {
        eprintln!("Error: cannot read stats: {}", e);
        process::exit(1);
    });

    let unresolved = store.get_unresolved_ref_count().unwrap_or(0);

    println!("CodeGraph Statistics");
    println!("  Files:       {}", stats.files);
    println!("  Nodes:       {}", stats.nodes);
    println!("  Edges:       {}", stats.edges);
    println!("  Unresolved:  {}", unresolved);
}
