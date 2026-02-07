# @suatkocar/codegraph

**Codebase intelligence as an MCP server.** Native Rust. Sub-second indexing. Zero runtime dependencies.

## Install

```bash
npx @suatkocar/codegraph init
```

One command: downloads the binary, indexes your codebase, registers MCP server, installs hooks.

Or install globally:

```bash
npm install -g @suatkocar/codegraph
codegraph init
```

Or install without npm:

```bash
curl -fsSL https://raw.githubusercontent.com/suatkocar/codegraph/main/install.sh | bash
codegraph init
```

## What It Does

CodeGraph builds a semantic graph of your codebase (15 languages, 13 MCP tools) and makes it instantly available to AI coding agents. **68% fewer tokens** per task compared to reading all files.

See [GitHub](https://github.com/suatkocar/codegraph) for full documentation.
