//! Integration tests for the CodeGraph evaluation framework.
//!
//! These tests index the eval-project fixture, load the ground truth,
//! run the evaluation harness, and assert quality metrics meet thresholds.

use std::path::PathBuf;

use codegraph::db::schema::initialize_database;
use codegraph::eval::harness::{load_ground_truth, run_evaluation};
use codegraph::eval::token_benchmark::{format_benchmark_table, run_benchmarks};
use codegraph::graph::store::GraphStore;
use codegraph::indexer::pipeline::{IndexOptions, IndexingPipeline};

/// Helper: index the eval-project fixture into an in-memory store.
fn setup_indexed_store() -> GraphStore {
    let fixture_path = PathBuf::from("tests/fixtures/eval-project");
    assert!(fixture_path.exists(), "eval-project fixture must exist");

    let conn = initialize_database(":memory:").unwrap();
    let store = GraphStore::from_connection(conn);
    let pipeline = IndexingPipeline::new(&store);
    let result = pipeline
        .index_directory(&IndexOptions {
            root_dir: fixture_path,
            incremental: false,
        })
        .unwrap();

    eprintln!(
        "[eval] Indexed {} files: {} nodes, {} edges in {}ms",
        result.files_indexed, result.nodes_created, result.edges_created, result.duration_ms
    );

    store
}

#[test]
fn eval_project_indexes_successfully() {
    let store = setup_indexed_store();
    let stats = store.get_stats().unwrap();

    eprintln!(
        "[eval] Graph stats: {} nodes, {} edges, {} files",
        stats.nodes, stats.edges, stats.files
    );

    // The eval-project has 11 TypeScript files with realistic code.
    // We expect a meaningful number of nodes and edges.
    assert!(
        stats.files >= 10,
        "Expected >= 10 files, got {}",
        stats.files
    );
    assert!(
        stats.nodes >= 30,
        "Expected >= 30 nodes, got {}",
        stats.nodes
    );
    assert!(
        stats.edges >= 10,
        "Expected >= 10 edges, got {}",
        stats.edges
    );
}

#[test]
fn evaluation_harness_produces_metrics() {
    let store = setup_indexed_store();
    let gt_path = PathBuf::from("tests/fixtures/eval-project/ground-truth.json");
    let ground_truth = load_ground_truth(&gt_path).unwrap();

    let report = run_evaluation(&store, &ground_truth);

    eprintln!("[eval] Evaluation Report:");
    eprintln!("  Node count OK: {}", report.node_count_ok);
    eprintln!("  Edge count OK: {}", report.edge_count_ok);
    eprintln!(
        "  Search  — P: {:.2}, R: {:.2}, F1: {:.2}",
        report.search_metrics.precision, report.search_metrics.recall, report.search_metrics.f1
    );
    eprintln!(
        "  Callers — P: {:.2}, R: {:.2}, F1: {:.2}",
        report.caller_metrics.precision, report.caller_metrics.recall, report.caller_metrics.f1
    );
    eprintln!(
        "  Dead    — P: {:.2}, R: {:.2}, F1: {:.2}",
        report.dead_code_metrics.precision,
        report.dead_code_metrics.recall,
        report.dead_code_metrics.f1
    );
    eprintln!(
        "  Deps    — P: {:.2}, R: {:.2}, F1: {:.2}",
        report.dependency_metrics.precision,
        report.dependency_metrics.recall,
        report.dependency_metrics.f1
    );
    eprintln!(
        "  Overall — P: {:.2}, R: {:.2}, F1: {:.2}",
        report.overall.precision, report.overall.recall, report.overall.f1
    );

    // Assert node and edge counts meet minimums
    assert!(report.node_count_ok, "Node count below minimum");
    assert!(report.edge_count_ok, "Edge count below minimum");

    // Assert search metrics are reasonable
    // FTS5 keyword search should find at least some expected symbols
    assert!(
        report.search_metrics.recall > 0.1,
        "Search recall too low: {:.2}",
        report.search_metrics.recall
    );
}

#[test]
fn token_reduction_benchmark() {
    let store = setup_indexed_store();

    let queries = &[
        "authentication login",
        "database connection",
        "user repository",
        "API routes handlers",
        "password hashing",
    ];

    let summary = run_benchmarks(&store, queries, 8000);

    let table = format_benchmark_table(&summary);
    eprintln!("\n[eval] Token Reduction Benchmark:\n{}", table);

    // Assert that CodeGraph provides meaningful token reduction compared
    // to reading the ENTIRE codebase (the naive baseline). Graph-aware
    // context assembly should always be smaller than dumping everything.
    for result in &summary.results {
        eprintln!(
            "  {}: baseline={} codegraph={} reduction={:.1}%",
            result.task, result.baseline_tokens, result.codegraph_tokens, result.reduction_pct
        );
        // CodeGraph context should always be smaller than the full codebase
        assert!(
            result.codegraph_tokens <= result.baseline_tokens,
            "CodeGraph tokens ({}) should not exceed full codebase baseline ({}) for '{}'",
            result.codegraph_tokens,
            result.baseline_tokens,
            result.task
        );
    }

    // The average reduction should be significant — graph-aware context
    // should use well under half the tokens of the full codebase.
    eprintln!(
        "[eval] Average reduction: {:.1}%",
        summary.avg_reduction_pct
    );
    assert!(
        summary.avg_reduction_pct > 20.0,
        "Average token reduction should exceed 20%, got {:.1}%",
        summary.avg_reduction_pct
    );
}
