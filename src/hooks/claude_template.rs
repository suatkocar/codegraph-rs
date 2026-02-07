//! CLAUDE.md template generation — teaches Claude Code about CodeGraph tools.
//!
//! When CodeGraph indexes a project, this module generates (or updates) a
//! `CLAUDE.md` file with instructions that guide Claude Code to prefer
//! CodeGraph MCP tools over raw grep/glob for code navigation.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::error::Result;

// ---------------------------------------------------------------------------
// Project stats
// ---------------------------------------------------------------------------

/// Summary statistics about an indexed project, used to populate the
/// CLAUDE.md template.
#[derive(Debug, Clone, Default)]
pub struct ProjectStats {
    /// Language → file count (e.g. "TypeScript" → 42).
    pub languages: HashMap<String, usize>,
    /// Total number of symbol nodes in the graph.
    pub total_nodes: usize,
    /// Total number of relationship edges in the graph.
    pub total_edges: usize,
}

impl ProjectStats {
    /// Format the language breakdown as a comma-separated string.
    ///
    /// Example: `"TypeScript (42), Rust (18), Python (5)"`
    pub fn language_breakdown(&self) -> String {
        if self.languages.is_empty() {
            return "N/A".to_string();
        }

        let mut pairs: Vec<_> = self.languages.iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(a.1)); // descending by count

        pairs
            .iter()
            .map(|(lang, count)| format!("{lang} ({count})"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

// ---------------------------------------------------------------------------
// Template
// ---------------------------------------------------------------------------

/// Section header we use to identify the CodeGraph block inside CLAUDE.md.
const SECTION_HEADER: &str = "## CodeGraph \u{2014} Codebase Intelligence";

/// Render the CodeGraph section body.
fn render_section(stats: &ProjectStats) -> String {
    format!(
        r#"{SECTION_HEADER}

This project is indexed by CodeGraph. Use the following MCP tools for code navigation:

- `codegraph_query "search term"` — Find symbols by keyword + semantic search
- `codegraph_dependencies "SymbolName"` — What does this symbol depend on?
- `codegraph_callers "functionName"` — Who calls this function?
- `codegraph_impact "file.ts"` — What breaks if you change this file?
- `codegraph_structure` — Get project overview with PageRank-ranked symbols
- `codegraph_tests "SymbolName"` — Find test coverage for a symbol
- `codegraph_context "task description"` — Get optimal context for a task
- `codegraph_diagram "SymbolName"` — Generate Mermaid dependency diagram
- `codegraph_dead_code` — Find potentially unused/dead code symbols
- `codegraph_frameworks` — Detect frameworks and libraries in the project
- `codegraph_languages` — Show language breakdown statistics

**Prefer CodeGraph tools over grep/glob** for finding code. They understand your project's structure, dependencies, and call graphs — not just text matches.

### Project Stats
- Languages: {languages}
- Symbols: {nodes}
- Relationships: {edges}
"#,
        languages = stats.language_breakdown(),
        nodes = stats.total_nodes,
        edges = stats.total_edges,
    )
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate or update the `CLAUDE.md` file in `project_dir`.
///
/// - If `CLAUDE.md` does not exist, it is created with the CodeGraph section.
/// - If it exists and already contains the CodeGraph section, that section is
///   replaced in-place with updated stats.
/// - If it exists but has no CodeGraph section, the section is appended.
pub fn generate_claude_md(project_dir: &str, stats: &ProjectStats) -> Result<()> {
    let path = Path::new(project_dir).join("CLAUDE.md");
    let section = render_section(stats);

    if path.exists() {
        let content = fs::read_to_string(&path)?;

        if content.contains(SECTION_HEADER) {
            // Replace existing section.
            let updated = replace_section(&content, &section);
            fs::write(&path, updated)?;
            eprintln!("[codegraph] Updated CodeGraph section in CLAUDE.md");
        } else {
            // Append to existing file.
            let appended = format!("{}\n\n{}", content.trim_end(), section);
            fs::write(&path, appended)?;
            eprintln!("[codegraph] Appended CodeGraph section to CLAUDE.md");
        }
    } else {
        fs::write(&path, &section)?;
        eprintln!("[codegraph] Created CLAUDE.md with CodeGraph section");
    }

    Ok(())
}

/// Replace everything from `SECTION_HEADER` to the next `## ` heading (or EOF)
/// with the new section content.
fn replace_section(content: &str, new_section: &str) -> String {
    let Some(start) = content.find(SECTION_HEADER) else {
        return content.to_string();
    };

    let after_header = start + SECTION_HEADER.len();

    // Find the next second-level heading after our section.
    let end = content[after_header..]
        .find("\n## ")
        .map(|pos| after_header + pos + 1) // +1 to keep the newline before the next heading
        .unwrap_or(content.len());

    let mut result = String::with_capacity(content.len());
    result.push_str(&content[..start]);
    result.push_str(new_section.trim_end());
    result.push('\n');
    if end < content.len() {
        result.push('\n');
        result.push_str(&content[end..]);
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_stats() -> ProjectStats {
        let mut languages = HashMap::new();
        languages.insert("TypeScript".to_string(), 42);
        languages.insert("Rust".to_string(), 18);
        ProjectStats {
            languages,
            total_nodes: 500,
            total_edges: 1200,
        }
    }

    #[test]
    fn language_breakdown_formatting() {
        let stats = sample_stats();
        let breakdown = stats.language_breakdown();
        // Higher count first.
        assert!(breakdown.starts_with("TypeScript (42)"));
        assert!(breakdown.contains("Rust (18)"));
    }

    #[test]
    fn language_breakdown_empty() {
        let stats = ProjectStats::default();
        assert_eq!(stats.language_breakdown(), "N/A");
    }

    #[test]
    fn generate_creates_new_claude_md() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();

        generate_claude_md(dir, &sample_stats()).unwrap();

        let path = tmp.path().join("CLAUDE.md");
        assert!(path.exists());

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains(SECTION_HEADER));
        assert!(content.contains("codegraph_query"));
        assert!(content.contains("Symbols: 500"));
        assert!(content.contains("Relationships: 1200"));
        assert!(content.contains("TypeScript (42)"));
    }

    #[test]
    fn generate_appends_to_existing_claude_md_without_section() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();
        let path = tmp.path().join("CLAUDE.md");

        let existing = "# My Project\n\nSome existing instructions.\n";
        fs::write(&path, existing).unwrap();

        generate_claude_md(dir, &sample_stats()).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("# My Project"), "original content preserved");
        assert!(content.contains("Some existing instructions."), "original content preserved");
        assert!(content.contains(SECTION_HEADER), "CodeGraph section appended");
        assert!(content.contains("Symbols: 500"));
    }

    #[test]
    fn generate_updates_existing_section() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();

        // First generation.
        let mut stats = sample_stats();
        generate_claude_md(dir, &stats).unwrap();

        // Second generation with different stats.
        stats.total_nodes = 999;
        stats.total_edges = 2500;
        generate_claude_md(dir, &stats).unwrap();

        let content = fs::read_to_string(tmp.path().join("CLAUDE.md")).unwrap();

        // Should have the new stats, not the old ones.
        assert!(content.contains("Symbols: 999"));
        assert!(content.contains("Relationships: 2500"));
        assert!(!content.contains("Symbols: 500"), "old stats should be replaced");

        // Section header should appear exactly once.
        let header_count = content.matches(SECTION_HEADER).count();
        assert_eq!(header_count, 1, "section header should appear once");
    }

    #[test]
    fn generate_updates_section_in_middle_of_file() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();
        let path = tmp.path().join("CLAUDE.md");

        // Simulate a file where the CodeGraph section sits between two other sections.
        let existing = format!(
            "# My Project\n\nIntro text.\n\n{}\n\nOld content here.\n\n## Other Section\n\nKeep this.\n",
            SECTION_HEADER
        );
        fs::write(&path, &existing).unwrap();

        generate_claude_md(dir, &sample_stats()).unwrap();

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("# My Project"), "header preserved");
        assert!(content.contains("## Other Section"), "subsequent section preserved");
        assert!(content.contains("Keep this."), "subsequent section body preserved");
        assert!(content.contains("Symbols: 500"), "new stats injected");
        assert!(!content.contains("Old content here."), "old section body removed");
    }

    #[test]
    fn render_section_contains_all_tools() {
        let section = render_section(&sample_stats());
        let expected_tools = [
            "codegraph_query",
            "codegraph_dependencies",
            "codegraph_callers",
            "codegraph_impact",
            "codegraph_structure",
            "codegraph_tests",
            "codegraph_context",
            "codegraph_diagram",
            "codegraph_dead_code",
            "codegraph_frameworks",
            "codegraph_languages",
        ];
        for tool in expected_tools {
            assert!(section.contains(tool), "missing tool: {tool}");
        }
    }
}
