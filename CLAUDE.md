# CodeGraph — Codebase Intelligence MCP Server (Rust)

## What This Is
High-performance Rust codebase intelligence engine. Builds a semantic code graph from source code using native tree-sitter (15 languages), stores symbols and relationships in SQLite with FTS5 and sqlite-vec, generates 768-dim code-specific embeddings via fastembed (Jina v2 Base Code), and exposes 13 MCP tools. Features cross-file import resolution, qualified names (`Class.method`), framework-specific route resolution, unresolved reference tracking, and a built-in evaluation framework.

## Architecture
- **src/main.rs** — CLI entry point (clap derive, 16 commands, interactive installer)
- **src/mcp/server.rs** — MCP server with 13 tools (rmcp stdio transport)
- **src/db/schema.rs** — SQLite schema (nodes, edges, file_hashes, embedding_cache, unresolved_refs, FTS5, vec)
- **src/indexer/** — Native tree-sitter parsing (15 langs), parallel extraction (rayon), fastembed embeddings, qualified name population
- **src/graph/** — Graph store, traversal (recursive CTEs), ranking (PageRank), hybrid search (FTS5 + vector + RRF)
- **src/context/** — Token-budgeted context assembly for LLM prompts (4-tier: 40/25/20/15)
- **src/hooks/** — Claude Code hooks, git hooks, CLAUDE.md template
- **src/resolution/** — Cross-file import resolution, path alias support, framework-specific route resolvers, framework detection (18+), dead code analysis
- **src/eval/** — Evaluation harness (precision/recall/F1), token reduction benchmarks
- **src/cli/** — Interactive installer with ASCII banner, progress bars, confirmations

## Key Commands
- `cargo build --release` — Build optimized binary (~45MB with embeddings, ~29MB without)
- `cargo test` — Run all 314 tests
- `./target/release/codegraph init <dir>` — Interactive setup (index + hooks + MCP + git hooks + CLAUDE.md)
- `./target/release/codegraph init <dir> --yes` — Non-interactive setup (CI/scripting)
- `./target/release/codegraph index <dir>` — Index a codebase
- `./target/release/codegraph serve` — Start MCP server (stdio)
- `./target/release/codegraph query <text>` — CLI search
- `./target/release/codegraph stats` — Show index statistics (includes unresolved refs)
- `./target/release/codegraph impact <symbol>` — Blast radius analysis
- `./target/release/codegraph dead-code` — Find unused symbols
- `./target/release/codegraph frameworks <dir>` — Detect frameworks
- `./target/release/codegraph languages` — Language breakdown
- `./target/release/codegraph git-hooks install|uninstall` — Git hook management

## Supported Languages (15)
TypeScript, TSX, JavaScript, JSX, Python, Go, Rust, Java, C, C++, C#, PHP, Ruby, Swift, Kotlin

## Performance
- 68% average token reduction vs reading all files (measured via evaluation framework)
- 20x faster indexing than TypeScript version (230ms vs ~5s for 54 files, without embeddings)
- Incremental no-op: 13ms
- 606%+ CPU utilization via rayon parallel parsing
- Caller detection: 100% precision, 100% recall
- Dead code detection: 75% precision, 100% recall

## MCP Tools (13)
1. `codegraph_query` — Hybrid keyword + semantic search
2. `codegraph_dependencies` — Forward dependency traversal
3. `codegraph_callers` — Reverse call graph traversal
4. `codegraph_callees` — Forward call graph (what does this function call?)
5. `codegraph_impact` — Blast radius analysis
6. `codegraph_structure` — Project overview with PageRank
7. `codegraph_tests` — Test coverage discovery
8. `codegraph_context` — LLM context assembly (68% fewer tokens)
9. `codegraph_node` — Direct symbol lookup with qualified names + relationships
10. `codegraph_diagram` — Mermaid diagram generation
11. `codegraph_dead_code` — Find potentially unused symbols
12. `codegraph_frameworks` — Detect project frameworks
13. `codegraph_languages` — Language breakdown statistics

## Claude Code Hooks
- **SessionStart** — Incremental re-index on session open
- **UserPromptSubmit** — Inject graph-aware context into prompts
- **PreCompact** — Save PageRank summary before compaction
- **PostToolUse** — Re-index modified file after Write/Edit

## Conventions
- Sync core, async only at MCP boundary (rmcp + tokio)
- `prepare_cached` for all SQL queries
- Feature-gated embeddings (`fastembed` behind `embedding` feature)
- Embedding model: jina-embeddings-v2-base-code (768-dim, code-specific)
- tree-sitter 0.25 with 15 statically linked grammars
- Cross-file import resolution for relative imports (./ ../) and path aliases (@/ ~/)
- Framework-specific route resolution (React, Express, Django, Rails, Laravel, Spring Boot)
- Qualified names: `ClassName.methodName` for methods/properties via line-range containment
- Unresolved references tracked in dedicated table for visibility
- All hooks use `panic::catch_unwind()` — never block Claude Code
