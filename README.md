# CodeGraph

**Codebase intelligence as an MCP server. Native Rust. Sub-second indexing. Zero runtime dependencies.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-243%20passing-brightgreen)]()
[![Languages](https://img.shields.io/badge/languages-15-blue)]()

---

## What is this?

CodeGraph builds a complete semantic graph of your codebase — every function, class, import, and call relationship across 15 programming languages — and makes it instantly available to AI coding agents through the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP).

When Claude Code, Codex, or any MCP-compatible agent enters your project, CodeGraph gives it an immediate, deep understanding of your entire codebase: what calls what, what depends on what, what breaks if you change something. Not file-level grep — **graph-aware, semantically-ranked, token-budgeted context**.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/suatkocar/codegraph-rs/main/install.sh | bash
```

Or build from source:

```bash
cargo install --git https://github.com/suatkocar/codegraph-rs
```

## Quick Start

```bash
# One command sets up everything
codegraph-mcp init .
```

That's it. This single command:

1. **Indexes your codebase** — Parses every source file, extracts symbols and relationships
2. **Registers the MCP server** — Writes `.mcp.json` so Claude Code auto-discovers it
3. **Installs lifecycle hooks** — Keeps the graph in sync as you work
4. **Generates CLAUDE.md** — Teaches the agent to prefer CodeGraph tools over raw search
5. **Sets up git hooks** — Re-indexes on every commit

Open Claude Code and your project is already graph-aware.

## What happens after init?

### On every session start
The SessionStart hook triggers an incremental re-index (~12ms when nothing changed). Your graph is always fresh.

### On every prompt you send
The UserPromptSubmit hook searches the graph for context relevant to your message and injects it automatically. The agent sees the right code before it even starts thinking.

### On every file Claude edits
The PostToolUse hook re-indexes the modified file instantly. The graph stays in sync with changes as they happen.

### Before conversation compaction
The PreCompact hook saves a PageRank summary of the most important symbols. Structural awareness survives even when conversation history gets compressed.

## Performance

| Metric | Without CodeGraph | With CodeGraph | Improvement |
|---|---|---|---|
| Index 30 files | N/A | **127ms** | Sub-second |
| Incremental no-op | N/A | **12ms** | Instant |
| Binary size | N/A | **29 MB** | Single file, no runtime |
| CPU utilization | N/A | **600%+** | Parallel parsing via rayon |

Embedding generation (Jina v2 Base Code, 768-dim ONNX) runs on first index. Subsequent incremental runs skip unchanged files entirely.

## Supported Languages

| Language | Extensions | Grammar |
|---|---|---|
| TypeScript | `.ts` | tree-sitter-typescript |
| TSX | `.tsx` | tree-sitter-typescript |
| JavaScript | `.js` `.mjs` `.cjs` | tree-sitter-javascript |
| JSX | `.jsx` | tree-sitter-javascript |
| Python | `.py` | tree-sitter-python |
| Go | `.go` | tree-sitter-go |
| Rust | `.rs` | tree-sitter-rust |
| Java | `.java` | tree-sitter-java |
| C | `.c` `.h` | tree-sitter-c |
| C++ | `.cpp` `.cc` `.hpp` | tree-sitter-cpp |
| C# | `.cs` | tree-sitter-c-sharp |
| PHP | `.php` | tree-sitter-php |
| Ruby | `.rb` | tree-sitter-ruby |
| Swift | `.swift` | tree-sitter-swift |
| Kotlin | `.kt` `.kts` | tree-sitter-kotlin-ng |

All grammars are statically linked at compile time via native tree-sitter 0.25. No WASM, no runtime downloads, no initialization delay.

## MCP Tools

CodeGraph exposes 11 tools through MCP. Any compatible client (Claude Code, Claude Desktop, Cursor, etc.) can invoke them.

| Tool | Purpose | Technique |
|---|---|---|
| `codegraph_query` | Hybrid keyword + semantic search | FTS5 BM25 + sqlite-vec cosine + RRF fusion |
| `codegraph_dependencies` | Forward dependency traversal | Recursive CTEs with configurable depth |
| `codegraph_callers` | Reverse call graph | Recursive CTEs on incoming edges |
| `codegraph_impact` | Blast radius analysis | Transitive closure + risk classification |
| `codegraph_structure` | Project overview | PageRank-ranked symbol statistics |
| `codegraph_tests` | Test coverage discovery | Edge traversal to test-annotated nodes |
| `codegraph_context` | LLM context assembly | 4-tier token budget (Core/Near/Extended/Background) |
| `codegraph_diagram` | Mermaid diagram generation | Dependency and call graph rendering |
| `codegraph_dead_code` | Find unused symbols | LEFT JOIN analysis, excludes exported/main/test |
| `codegraph_frameworks` | Detect project frameworks | Manifest file analysis (18+ frameworks) |
| `codegraph_languages` | Language breakdown | Per-language file and symbol statistics |

### Example: Find what breaks if you change a file

```bash
codegraph-mcp impact src/auth/middleware.ts
```

```
Impact Analysis: src/auth/middleware.ts
  Risk:                 high
  Direct dependents:    12
  Transitive dependents:47
  Affected files:       8
    - src/routes/api.ts
    - src/routes/admin.ts
    - src/middleware/cors.ts
    ...
```

### Example: Get LLM-optimized context for a task

```bash
codegraph-mcp query "authentication flow"
```

Returns ranked results combining keyword relevance (BM25) with semantic similarity (768-dim code-specific embeddings), fused via Reciprocal Rank Fusion.

## Architecture

```
Source Files ──→ tree-sitter ──→ Extractor ──→ SQLite DB
  (15 langs)     (native parse)   (nodes+edges)   ├── FTS5 (keyword index)
                                                   ├── sqlite-vec (vector index)
                                                   └── edges (graph structure)
                                       ↓
                               Query Engine
                         ├── Hybrid Search (BM25 + cosine + RRF)
                         ├── Graph Traversal (recursive CTEs)
                         ├── PageRank (symbol importance)
                         └── Context Assembly (4-tier budget)
                                       ↓
                              MCP Server (stdio)
                         ├── 11 tools via rmcp
                         └── 4 Claude Code hooks
```

### Module Layout

```
src/
  main.rs                 CLI entry point (16 commands, clap derive)
  mcp/server.rs           MCP server — 11 tools via rmcp #[tool] macros
  db/schema.rs            SQLite schema — FTS5 + sqlite-vec virtual tables
  indexer/
    parser.rs             15 tree-sitter grammars, statically linked
    extractor.rs          AST → nodes and edges for all languages
    pipeline.rs           Parallel indexing with rayon + incremental SHA-256 hashing
    embedder.rs           Jina v2 Base Code embeddings (768-dim, ONNX)
  graph/
    store.rs              CRUD operations with prepare_cached
    traversal.rs          Dependency/caller traversal via recursive CTEs
    ranking.rs            PageRank, personalized PageRank, blast radius
    search.rs             Hybrid FTS5 + vector search, RRF fusion (k=60)
  context/
    assembler.rs          4-tier token-budgeted LLM context assembly
    budget.rs             Token estimation, truncation, signature extraction
  resolution/
    frameworks.rs         Framework detection (18+ frameworks from manifests)
    dead_code.rs          Unused symbol detection via edge analysis
  hooks/
    install.rs            .mcp.json + .claude/settings.json + shell scripts
    handlers.rs           4 runtime handlers with catch_unwind safety
    git_hooks.rs          Git post-commit hook (idempotent, marker-based)
    claude_template.rs    CLAUDE.md generation with tool instructions
```

## CLI Reference

```
codegraph-mcp init <dir>              Full setup: index + hooks + MCP + git hooks + CLAUDE.md
codegraph-mcp index <dir>             Index a codebase (incremental by default)
codegraph-mcp index <dir> --force     Force full re-index
codegraph-mcp serve                   Start MCP server (stdio transport)
codegraph-mcp query <text>            Search the code graph
codegraph-mcp impact <target>         Blast radius analysis
codegraph-mcp stats                   Show index statistics
codegraph-mcp dead-code               Find potentially unused symbols
codegraph-mcp frameworks <dir>        Detect frameworks and libraries
codegraph-mcp languages               Language breakdown
codegraph-mcp install-hooks <dir>     Install Claude Code hooks
codegraph-mcp git-hooks install       Install git post-commit hook
codegraph-mcp git-hooks uninstall     Remove git post-commit hook
```

## How It Works

### Indexing

Files are discovered via the `ignore` crate (respects `.gitignore`), hashed with SHA-256 for change detection, and parsed in parallel using rayon. Each file passes through a native tree-sitter grammar that produces a concrete syntax tree. The extractor identifies functions, classes, interfaces, methods, structs, traits, enums, imports, and their relationships (calls, imports, extends, implements, references, contains).

Nodes and edges are upserted into SQLite with content-hash deduplication. On incremental runs, unchanged files are skipped entirely.

### Search

The hybrid search engine runs two parallel paths:

1. **FTS5 keyword search** — BM25-ranked full-text search over symbol names, signatures, and documentation
2. **Vector similarity search** — The query is embedded into a 768-dimensional vector via Jina v2 Base Code (a model specifically trained on programming languages), then matched against pre-computed node embeddings using sqlite-vec

Results are merged using **Reciprocal Rank Fusion** (RRF, k=60), a score-agnostic method that combines rank positions without needing score normalization.

### Context Assembly

The context assembler builds structured Markdown that fits within a configurable token budget:

| Tier | Budget | Contents |
|---|---|---|
| **Core** | 40% | Full source code of the top-ranked results |
| **Near** | 25% | Signatures of direct callers and callees |
| **Extended** | 20% | Related tests and sibling declarations |
| **Background** | 15% | Project file listing for structural orientation |

### Framework Detection

CodeGraph analyzes manifest files (package.json, Cargo.toml, go.mod, requirements.txt, pom.xml, build.gradle, composer.json, Gemfile) to detect 18+ frameworks: React, Next.js, Vue, Angular, Express, NestJS, Django, Flask, FastAPI, Rails, Laravel, Symfony, Spring Boot, Actix, Axum, Rocket, Gin, Echo.

### Dead Code Analysis

Symbols with zero incoming edges (excluding exported symbols, main functions, and test functions) are flagged as potentially unused. Filter by kind (function, class, method, etc.) to focus on what matters.

## Building from Source

```bash
# Prerequisites: Rust 1.75+, C compiler (for tree-sitter + SQLite)

# Full build with embeddings (~45MB binary)
cargo build --release

# Without embeddings (keyword-only search, ~29MB binary)
cargo build --release --no-default-features

# Run the test suite (243 tests)
cargo test
```

## Design Decisions

- **Sync core, async only at the MCP boundary.** tree-sitter and rusqlite are synchronous. Tokio is used only for the rmcp stdio transport.
- **Native tree-sitter, not WASM.** 15 grammars statically linked. No initialization delay, no runtime downloads.
- **Code-specific embeddings.** Jina v2 Base Code (768-dim) understands programming language semantics, not just natural language.
- **Feature-gated embeddings.** Build with `--no-default-features` for a leaner binary that does keyword-only search.
- **Hooks never panic.** Every handler uses `catch_unwind` and always returns valid JSON. CodeGraph never blocks your agent.
- **Idempotent everything.** Running `init` twice produces the same result. Hooks are marker-based. Config merges are additive.

## License

MIT

---

*Built with native Rust, tree-sitter, and a deep belief that AI coding agents deserve better context than grep.*
