//! Token reduction measurement for evaluating CodeGraph's context efficiency.
//!
//! Compares the token count of naive file reading (baseline) against
//! CodeGraph's `assemble_context` output for the same query. Measures
//! how much more efficient graph-aware context assembly is.

use std::collections::HashSet;

use crate::context::assembler::ContextAssembler;
use crate::context::budget::estimate_tokens;
use crate::graph::search::{HybridSearch, SearchOptions};
use crate::graph::store::GraphStore;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of a single token benchmark run.
#[derive(Debug, Clone)]
pub struct TokenBenchmarkResult {
    pub task: String,
    pub baseline_tokens: usize,
    pub codegraph_tokens: usize,
    pub reduction_pct: f64,
    pub files_baseline: usize,
    pub files_codegraph: usize,
}

/// Summary of all benchmark runs.
#[derive(Debug)]
pub struct TokenBenchmarkSummary {
    pub results: Vec<TokenBenchmarkResult>,
    pub avg_reduction_pct: f64,
}

// ---------------------------------------------------------------------------
// Benchmark execution
// ---------------------------------------------------------------------------

/// Run a token benchmark for a single query.
///
/// **Baseline**: Read ALL source bodies from the entire indexed codebase.
/// This simulates "dump the whole project into the LLM prompt" — the naive
/// approach when you don't have a code graph to tell you what's relevant.
///
/// **CodeGraph**: Use `ContextAssembler::assemble_context()` for the same
/// query with a token budget. The graph selects only relevant symbols.
pub fn benchmark_query(store: &GraphStore, query: &str, budget: usize) -> TokenBenchmarkResult {
    // --- Baseline: read ALL files in the project ---
    let baseline_files = get_all_files(store);
    let baseline_text = load_all_file_content(store, &baseline_files);
    let baseline_tokens = estimate_tokens(&baseline_text);

    // --- CodeGraph: use the context assembler ---
    let search = HybridSearch::new(&store.conn);
    let assembler = ContextAssembler::new(&store.conn, &search);
    let context = assembler.assemble_context(query, Some(budget));
    let codegraph_tokens = estimate_tokens(&context);

    // Count unique files mentioned in the codegraph context
    let codegraph_files = count_files_in_context(store, query);

    let reduction_pct = if baseline_tokens == 0 {
        0.0
    } else {
        (1.0 - (codegraph_tokens as f64 / baseline_tokens as f64)) * 100.0
    };

    TokenBenchmarkResult {
        task: query.to_string(),
        baseline_tokens,
        codegraph_tokens,
        reduction_pct,
        files_baseline: baseline_files.len(),
        files_codegraph: codegraph_files,
    }
}

/// Run benchmarks for a set of queries and produce a summary.
pub fn run_benchmarks(
    store: &GraphStore,
    queries: &[&str],
    budget: usize,
) -> TokenBenchmarkSummary {
    let results: Vec<TokenBenchmarkResult> = queries
        .iter()
        .map(|q| benchmark_query(store, q, budget))
        .collect();

    let avg_reduction_pct = if results.is_empty() {
        0.0
    } else {
        results.iter().map(|r| r.reduction_pct).sum::<f64>() / results.len() as f64
    };

    TokenBenchmarkSummary {
        results,
        avg_reduction_pct,
    }
}

/// Format benchmark results as a readable table.
pub fn format_benchmark_table(summary: &TokenBenchmarkSummary) -> String {
    let mut output = String::new();
    output.push_str(&format!(
        "{:<30} {:>10} {:>10} {:>10} {:>8} {:>8}\n",
        "Query", "Baseline", "CodeGraph", "Reduction", "Files-B", "Files-CG"
    ));
    output.push_str(&"-".repeat(86));
    output.push('\n');

    for r in &summary.results {
        output.push_str(&format!(
            "{:<30} {:>10} {:>10} {:>9.1}% {:>8} {:>8}\n",
            truncate_str(&r.task, 30),
            r.baseline_tokens,
            r.codegraph_tokens,
            r.reduction_pct,
            r.files_baseline,
            r.files_codegraph,
        ));
    }

    output.push_str(&"-".repeat(86));
    output.push('\n');
    output.push_str(&format!(
        "{:<30} {:>10} {:>10} {:>9.1}%\n",
        "AVERAGE", "", "", summary.avg_reduction_pct,
    ));

    output
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Get all unique file paths from the indexed graph.
/// Represents the naive baseline: reading the entire codebase.
fn get_all_files(store: &GraphStore) -> HashSet<String> {
    let mut files = HashSet::new();
    if let Ok(all_nodes) = store.get_all_nodes() {
        for node in &all_nodes {
            files.insert(node.file_path.clone());
        }
    }
    files
}

/// Load all source bodies from nodes in the given files.
fn load_all_file_content(store: &GraphStore, files: &HashSet<String>) -> String {
    let mut content = String::new();
    for file in files {
        if let Ok(nodes) = store.get_nodes_by_file(file) {
            for node in &nodes {
                if let Some(ref body) = node.body {
                    content.push_str(body);
                    content.push('\n');
                }
            }
        }
    }
    content
}

/// Count how many unique files are referenced in the search results for a query.
fn count_files_in_context(store: &GraphStore, query: &str) -> usize {
    let search = HybridSearch::new(&store.conn);
    let opts = SearchOptions {
        limit: Some(10),
        ..Default::default()
    };
    let results = search.search(query, &opts).unwrap_or_default();
    let files: HashSet<&str> = results.iter().map(|r| r.file_path.as_str()).collect();
    files.len()
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_str_long() {
        let result = truncate_str("this is a long string", 10);
        assert_eq!(result.len(), 10);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn token_benchmark_result_fields() {
        let r = TokenBenchmarkResult {
            task: "test query".to_string(),
            baseline_tokens: 1000,
            codegraph_tokens: 200,
            reduction_pct: 80.0,
            files_baseline: 10,
            files_codegraph: 3,
        };
        assert_eq!(r.reduction_pct, 80.0);
        assert!(r.codegraph_tokens < r.baseline_tokens);
    }
}
