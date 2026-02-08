# CodeGraph

**Codebase intelligence as an MCP server. Native Rust. Sub-second indexing. Zero runtime dependencies.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-2064%20passing-brightgreen)]()
[![Languages](https://img.shields.io/badge/languages-32-blue)]()
[![MCP Tools](https://img.shields.io/badge/MCP%20tools-44-purple)]()

---

## What is this?

CodeGraph builds a complete semantic graph of your codebase — every function, class, import, and call relationship across **32 programming languages** — and makes it instantly available to AI coding agents through the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP).

When Claude Code, Codex, or any MCP-compatible agent enters your project, CodeGraph gives it an immediate, deep understanding of your entire codebase: what calls what, what depends on what, what breaks if you change something. Not file-level grep — **graph-aware, semantically-ranked, token-budgeted context**.

**v0.2.3** adds git integration, security scanning (OWASP/CWE), call graph analysis, data flow analysis, a YAML configuration system, structured logging, and robust multi-byte character handling.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/suatkocar/codegraph/main/install.sh | bash
```

Or via npm:

```bash
npx @suatkocar/codegraph init
```

Or via Homebrew:

```bash
brew tap suatkocar/codegraph && brew install codegraph
```

Or build from source:

```bash
cargo build --release --no-default-features
```

## Quick Start

```bash
# One command sets up everything
codegraph init
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

### Before every tool call
The PreToolUse hook injects relevant codebase context before Edit, Write, Read, Grep, Glob, and Bash calls. The agent knows which symbols are in the file before it even opens it.

### On every file Claude edits
The PostToolUse hook re-indexes the modified file instantly. The graph stays in sync with changes as they happen.

### When a tool fails
The PostToolUseFailure hook provides corrective context — if a function was renamed or moved, CodeGraph tells the agent where to find it now.

### When subagents spawn
The SubagentStart hook injects a compact project overview (top symbols, frameworks, file counts) into every subagent. They start with full codebase awareness from turn one.

### Before conversation compaction
The PreCompact hook saves a PageRank summary of the most important symbols. Structural awareness survives even when conversation history gets compressed.

### Before the agent stops
The Stop hook checks for graph inconsistencies (high unresolved reference ratio) and can suggest the agent continue to address them before stopping.

### When a task completes
The TaskCompleted hook runs a quality gate — re-indexes the project and reports any new dead code or unresolved references introduced during the task.

### When a session ends
The SessionEnd hook runs a final incremental re-index and logs session-level diagnostics (file count, node count, edge count, unresolved refs).

## Performance

| Metric | Without CodeGraph | With CodeGraph | Improvement |
|---|---|---|---|
| Tokens per task | ~5,000 | ~1,550 | **68% fewer** |
| Files examined | 11 (all) | 3 avg | **73% fewer** |
| Index 54 files | N/A | **230ms** | Sub-second |
| Incremental no-op | N/A | **13ms** | Instant |
| CPU utilization | N/A | **600%+** | Parallel parsing via rayon |

### Token Reduction Benchmarks

Measured on a real 11-file TypeScript project with ground truth evaluation:

| Task Query | Baseline Tokens | CodeGraph Tokens | Reduction |
|---|---|---|---|
| Authentication login | 4,962 | 1,997 | **59.8%** |
| Database connection | 4,962 | 1,305 | **73.7%** |
| User repository | 4,962 | 2,108 | **57.5%** |
| API routes handlers | 4,962 | 935 | **81.2%** |
| Password hashing | 4,962 | 1,522 | **69.3%** |
| **Average** | | | **68.3%** |

### Quality Metrics (Evaluation Framework)

| Category | Precision | Recall | F1 Score |
|---|---|---|---|
| Caller detection | 1.00 | 1.00 | **1.00** |
| Dead code detection | 0.75 | 1.00 | **0.86** |
| Search relevance | 0.27 | 0.58 | **0.37** |

Caller detection achieves perfect precision and recall — CodeGraph never misses a caller and never hallucinates one.

## Supported Languages (32)

| Language | Extensions | Language | Extensions |
|---|---|---|---|
| TypeScript | `.ts` | Haskell | `.hs` `.lhs` |
| TSX | `.tsx` | Elixir | `.ex` `.exs` |
| JavaScript | `.js` `.mjs` `.cjs` | Groovy | `.groovy` `.gradle` |
| JSX | `.jsx` | PowerShell | `.ps1` `.psm1` |
| Python | `.py` | Perl | `.pl` `.pm` |
| Go | `.go` | Clojure | `.clj` `.cljs` |
| Rust | `.rs` | Julia | `.jl` |
| Java | `.java` | R | `.R` `.r` |
| C | `.c` `.h` | Erlang | `.erl` `.hrl` |
| C++ | `.cpp` `.cc` `.hpp` | Elm | `.elm` |
| C# | `.cs` | Fortran | `.f90` `.f95` |
| PHP | `.php` | Nix | `.nix` |
| Ruby | `.rb` | Bash | `.sh` `.bash` |
| Swift | `.swift` | Scala | `.scala` `.sc` |
| Kotlin | `.kt` `.kts` | Dart | `.dart` |
| Verilog | `.v` `.sv` | Zig | `.zig` |
| Lua | `.lua` | | |

All grammars are statically linked at compile time via native tree-sitter 0.25. No WASM, no runtime downloads, no initialization delay.

## MCP Tools (44)

### Core (13)

| Tool | Purpose |
|---|---|
| `codegraph_query` | Hybrid keyword + semantic search (FTS5 + sqlite-vec + RRF) |
| `codegraph_dependencies` | Forward dependency traversal (recursive CTEs) |
| `codegraph_callers` | Reverse call graph |
| `codegraph_callees` | Forward call graph |
| `codegraph_impact` | Blast radius analysis with risk classification |
| `codegraph_structure` | Project overview with PageRank-ranked symbols |
| `codegraph_tests` | Test coverage discovery |
| `codegraph_context` | LLM context assembly (4-tier token budget) |
| `codegraph_node` | Direct symbol lookup with relationships |
| `codegraph_diagram` | Mermaid diagram generation |
| `codegraph_dead_code` | Find unused symbols |
| `codegraph_frameworks` | Detect project frameworks (18+) |
| `codegraph_languages` | Language breakdown statistics |

### Git Integration (9)

| Tool | Purpose |
|---|---|
| `codegraph_blame` | Line-by-line git blame |
| `codegraph_file_history` | File commit history |
| `codegraph_recent_changes` | Recent repository commits |
| `codegraph_commit_diff` | Commit diff details |
| `codegraph_symbol_history` | Symbol modification history |
| `codegraph_branch_info` | Branch status and tracking info |
| `codegraph_modified_files` | Working tree changes (staged/unstaged) |
| `codegraph_hotspots` | Churn-based hotspot detection |
| `codegraph_contributors` | Contributor statistics |

### Security (9)

| Tool | Purpose |
|---|---|
| `codegraph_scan_security` | YAML rule-based vulnerability scan |
| `codegraph_check_owasp` | OWASP Top 10 2021 scan |
| `codegraph_check_cwe` | CWE Top 25 scan |
| `codegraph_explain_vulnerability` | CWE explanation + remediation guidance |
| `codegraph_suggest_fix` | Fix suggestion for findings |
| `codegraph_find_injections` | SQL/XSS/command injection via taint analysis |
| `codegraph_taint_sources` | Identify taint sources in code |
| `codegraph_security_summary` | Comprehensive risk assessment |
| `codegraph_trace_taint` | Data flow tracing from source to sink |

### Repository & Analysis (7)

| Tool | Purpose |
|---|---|
| `codegraph_stats` | Index statistics (nodes, edges, files) |
| `codegraph_circular_imports` | Cycle detection (Tarjan SCC) |
| `codegraph_project_tree` | Directory tree with symbol counts |
| `codegraph_find_references` | Cross-reference search |
| `codegraph_export_map` | Module export listing |
| `codegraph_import_graph` | Import graph visualization |
| `codegraph_file` | File symbol listing |

### Call Graph & Data Flow (6)

| Tool | Purpose |
|---|---|
| `codegraph_find_path` | Shortest call path between two functions (BFS) |
| `codegraph_complexity` | Cyclomatic + cognitive complexity per function |
| `codegraph_data_flow` | Variable def-use chains |
| `codegraph_dead_stores` | Assignments never read |
| `codegraph_find_uninitialized` | Variables used before initialization |
| `codegraph_reaching_defs` | Reaching definition analysis |

## Security Scanning

CodeGraph includes a built-in security scanner with YAML-based rules:

- **4 bundled rule sets**: OWASP Top 10, CWE Top 25, cryptographic weaknesses, secret detection
- **50+ rules** covering SQL injection, XSS, command injection, hardcoded secrets, weak crypto, and more
- **Taint analysis**: Source-to-sink data flow tracking for injection vulnerabilities
- **Custom rules**: Write your own YAML rules with regex patterns, severity, CWE/OWASP mappings

```bash
codegraph scan-security        # Full scan with all rules
codegraph check-owasp          # OWASP Top 10 only
codegraph check-cwe            # CWE Top 25 only
```

## Configuration

CodeGraph supports layered YAML configuration:

```yaml
# .codegraph.yaml (project-level) or ~/.config/codegraph/config.yaml (user-level)
version: "1.0"
preset: balanced  # minimal | balanced | full | security-focused

tools:
  overrides:
    codegraph_dead_code:
      enabled: false
      reason: "Too noisy for this project"

performance:
  exclude_tests: true
```

**4 presets**: `minimal` (15 tools), `balanced` (30 tools), `full` (all 44), `security-focused`

**Auto editor detection**: Claude Code → full, VS Code → balanced, Zed → minimal

**Environment overrides**: `CODEGRAPH_PRESET`, `CODEGRAPH_DISABLED_TOOLS`

## Architecture

```
Source Files ──→ tree-sitter ──→ Extractor ──→ SQLite DB
  (32 langs)     (native parse)   (nodes+edges)   ├── FTS5 (keyword index)
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
                         ├── 44 tools via rmcp
                         └── 10 Claude Code hooks
```

### Module Layout

```
src/
  main.rs                 CLI entry point (16 commands, clap derive)
  mcp/server.rs           MCP server — 44 tools via rmcp #[tool] macros
  db/schema.rs            SQLite schema — FTS5 + sqlite-vec + unresolved_refs
  indexer/
    parser.rs             32 tree-sitter grammars, statically linked
    extractor.rs          AST → nodes, edges, qualified names for all languages
    pipeline.rs           Parallel indexing with rayon + incremental SHA-256 hashing
    embedder.rs           Jina v2 Base Code embeddings (768-dim, ONNX)
  graph/
    store.rs              CRUD operations with prepare_cached
    traversal.rs          Dependency/caller/callee traversal via recursive CTEs
    ranking.rs            PageRank, personalized PageRank, blast radius
    search.rs             Hybrid FTS5 + vector search, RRF fusion (k=60)
    complexity.rs         Cyclomatic + cognitive complexity analysis
    dataflow.rs           Def-use chains, reaching definitions, dead stores
  context/
    assembler.rs          4-tier token-budgeted LLM context assembly
    budget.rs             Token estimation, truncation, signature extraction
  resolution/
    imports.rs            Cross-file import resolution + path alias support
    routes.rs             Framework-specific route/component resolvers
    frameworks.rs         Framework detection (18+ frameworks from manifests)
    dead_code.rs          Unused symbol detection via edge analysis
  git/
    blame.rs              Git blame integration
    history.rs            File/symbol history, commit diffs
    analysis.rs           Hotspots, contributors, branch info
  security/
    scanner.rs            Directory/file scanning engine
    rules.rs              YAML rule parser + bundled rule loader
    taint.rs              Source-to-sink taint analysis
  config/
    schema.rs             Configuration data model + validation
    loader.rs             Layered config loading (user → project → env → CLI)
    preset.rs             4 presets with tool/category filtering
  observability/
    mod.rs                Structured logging (tracing), path validation, secret redaction
  eval/
    harness.rs            Evaluation framework (precision/recall/F1)
    token_benchmark.rs    Token reduction measurement vs baseline
  cli/
    installer.rs          Interactive installer with ASCII banner + progress bars
  hooks/
    install.rs            .mcp.json + .claude/settings.json + shell scripts
    handlers.rs           10 runtime handlers with catch_unwind safety
    git_hooks.rs          Git post-commit hook (idempotent, marker-based)
    claude_template.rs    CLAUDE.md generation with tool instructions
```

## CLI Reference

```
codegraph init <dir>              Full interactive setup (banner, prompts, progress bars)
codegraph init <dir> --yes        Non-interactive setup (CI/scripting)
codegraph index <dir>             Index a codebase (incremental by default)
codegraph index <dir> --force     Force full re-index
codegraph serve                   Start MCP server (stdio transport)
codegraph query <text>            Search the code graph
codegraph impact <target>         Blast radius analysis
codegraph stats                   Show index statistics
codegraph dead-code               Find potentially unused symbols
codegraph frameworks <dir>        Detect frameworks and libraries
codegraph languages               Language breakdown
codegraph install-hooks <dir>     Install Claude Code hooks
codegraph git-hooks install       Install git post-commit hook
codegraph git-hooks uninstall     Remove git post-commit hook
```

## Building from Source

```bash
# Prerequisites: Rust 1.75+, C compiler (for tree-sitter + SQLite)

# Full build with embeddings
cargo build --release

# Without embeddings (keyword-only search, leaner binary)
cargo build --release --no-default-features

# Run the test suite (2064 tests)
cargo test
```

## Uninstall

```bash
# Remove the binary
rm ~/.local/bin/codegraph

# Remove project data (run inside each project you initialized)
rm -rf .codegraph/
codegraph git-hooks uninstall

# Remove Claude Code integration files (optional, check before deleting)
rm .mcp.json
rm -rf .claude/
```

## Design Decisions

- **Sync core, async only at the MCP boundary.** tree-sitter and rusqlite are synchronous. Tokio is used only for the rmcp stdio transport.
- **Native tree-sitter, not WASM.** 32 grammars statically linked. No initialization delay, no runtime downloads.
- **Code-specific embeddings.** Jina v2 Base Code (768-dim) understands programming language semantics, not just natural language.
- **Feature-gated embeddings.** Build with `--no-default-features` for a leaner binary that does keyword-only search.
- **Hooks never panic.** Every handler uses `catch_unwind` and always returns valid JSON. CodeGraph never blocks your agent.
- **Idempotent everything.** Running `init` twice produces the same result. Hooks are marker-based. Config merges are additive.
- **Qualified names by containment.** `Class.method` names are derived from line-range enclosure — works across all 32 languages without language-specific logic.
- **Structured logging.** Uses the `tracing` crate with `RUST_LOG` support. Path traversal protection and secret redaction on all MCP tool inputs/outputs.

## License

MIT

---

*Built with native Rust, tree-sitter, and a deep belief that AI coding agents deserve better context than grep.*
