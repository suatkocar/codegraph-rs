//! Evaluation harness for measuring CodeGraph quality.
//!
//! Loads a ground-truth JSON file and compares it against the actual
//! graph produced by the indexing pipeline. Produces precision, recall,
//! and F1 metrics for search, callers, dead code, and file dependencies.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::error::Result;
use crate::graph::search::{HybridSearch, SearchOptions};
use crate::graph::store::GraphStore;

// ---------------------------------------------------------------------------
// Ground truth types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct GroundTruth {
    pub description: String,
    pub expected_node_count_min: usize,
    pub expected_edge_count_min: usize,
    pub search_queries: Vec<SearchQuery>,
    pub callers: HashMap<String, Vec<String>>,
    pub dead_code: Vec<String>,
    pub file_dependencies: HashMap<String, Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SearchQuery {
    pub query: String,
    pub expected_top5_symbols: Vec<String>,
    pub expected_top5_files: Vec<String>,
}

// ---------------------------------------------------------------------------
// Eval metrics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct EvalMetrics {
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

#[derive(Debug, Serialize)]
pub struct EvalReport {
    pub search_metrics: EvalMetrics,
    pub caller_metrics: EvalMetrics,
    pub dead_code_metrics: EvalMetrics,
    pub dependency_metrics: EvalMetrics,
    pub overall: EvalMetrics,
    pub node_count_ok: bool,
    pub edge_count_ok: bool,
}

impl EvalMetrics {
    /// Compute precision, recall, and F1 from expected vs actual sets.
    pub fn compute(expected: &HashSet<String>, actual: &HashSet<String>) -> Self {
        if expected.is_empty() && actual.is_empty() {
            return Self {
                precision: 1.0,
                recall: 1.0,
                f1: 1.0,
            };
        }
        let true_positives = expected.intersection(actual).count() as f64;
        let precision = if actual.is_empty() {
            0.0
        } else {
            true_positives / actual.len() as f64
        };
        let recall = if expected.is_empty() {
            0.0
        } else {
            true_positives / expected.len() as f64
        };
        let f1 = if precision + recall == 0.0 {
            0.0
        } else {
            2.0 * precision * recall / (precision + recall)
        };
        Self {
            precision,
            recall,
            f1,
        }
    }

    /// Average multiple metrics into one.
    pub fn average(metrics: &[EvalMetrics]) -> Self {
        if metrics.is_empty() {
            return Self {
                precision: 0.0,
                recall: 0.0,
                f1: 0.0,
            };
        }
        let n = metrics.len() as f64;
        let precision = metrics.iter().map(|m| m.precision).sum::<f64>() / n;
        let recall = metrics.iter().map(|m| m.recall).sum::<f64>() / n;
        let f1 = metrics.iter().map(|m| m.f1).sum::<f64>() / n;
        Self {
            precision,
            recall,
            f1,
        }
    }
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

pub fn load_ground_truth(path: &Path) -> Result<GroundTruth> {
    let content = std::fs::read_to_string(path)?;
    let gt: GroundTruth = serde_json::from_str(&content)?;
    Ok(gt)
}

// ---------------------------------------------------------------------------
// Evaluation functions
// ---------------------------------------------------------------------------

/// Evaluate search quality: for each ground truth query, run a keyword search
/// and compare the returned symbol names against expected symbols.
pub fn evaluate_search(store: &GraphStore, queries: &[SearchQuery]) -> EvalMetrics {
    let search = HybridSearch::new(&store.conn);
    let mut all_metrics: Vec<EvalMetrics> = Vec::new();

    for sq in queries {
        let opts = SearchOptions {
            limit: Some(10),
            ..Default::default()
        };
        let results = search.search(&sq.query, &opts).unwrap_or_default();

        let actual_symbols: HashSet<String> = results.iter().map(|r| r.name.clone()).collect();
        let expected_symbols: HashSet<String> = sq.expected_top5_symbols.iter().cloned().collect();

        let metrics = EvalMetrics::compute(&expected_symbols, &actual_symbols);
        all_metrics.push(metrics);
    }

    EvalMetrics::average(&all_metrics)
}

/// Evaluate caller detection: for each expected callee -> callers mapping,
/// check if the graph has corresponding incoming "calls" edges.
pub fn evaluate_callers(
    store: &GraphStore,
    expected_callers: &HashMap<String, Vec<String>>,
) -> EvalMetrics {
    let mut all_metrics: Vec<EvalMetrics> = Vec::new();

    for (callee_name, expected_caller_names) in expected_callers {
        let expected: HashSet<String> = expected_caller_names.iter().cloned().collect();

        // Find all nodes matching the callee name
        let callee_nodes = store.get_nodes_by_name(callee_name).unwrap_or_default();

        // Collect actual callers via incoming "calls" edges
        let mut actual: HashSet<String> = HashSet::new();
        for callee_node in &callee_nodes {
            let in_edges = store
                .get_in_edges(&callee_node.id, Some("calls"))
                .unwrap_or_default();
            for edge in &in_edges {
                if let Some(caller_node) = store.get_node(&edge.source).unwrap_or(None) {
                    actual.insert(caller_node.name.clone());
                }
            }
        }

        let metrics = EvalMetrics::compute(&expected, &actual);
        all_metrics.push(metrics);
    }

    EvalMetrics::average(&all_metrics)
}

/// Evaluate dead code detection: compare expected dead code symbols against
/// nodes that have no incoming edges (excluding entry points and modules).
pub fn evaluate_dead_code(store: &GraphStore, expected_dead: &[String]) -> EvalMetrics {
    let sql = "SELECT n.name FROM nodes n
               LEFT JOIN edges e ON e.target_id = n.id
               WHERE e.id IS NULL
               AND n.type NOT IN ('module', 'namespace')
               AND n.file_path NOT LIKE '%index.ts'";

    let actual_dead: HashSet<String> = match store.conn.prepare(sql) {
        Ok(mut stmt) => stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map(|rows| rows.filter_map(|r| r.ok()).collect())
            .unwrap_or_default(),
        Err(_) => HashSet::new(),
    };

    let expected: HashSet<String> = expected_dead.iter().cloned().collect();
    EvalMetrics::compute(&expected, &actual_dead)
}

/// Evaluate file dependency detection: for each file, check which other
/// files it has resolved import edges to.
pub fn evaluate_dependencies(
    store: &GraphStore,
    expected_deps: &HashMap<String, Vec<String>>,
) -> EvalMetrics {
    let mut all_metrics: Vec<EvalMetrics> = Vec::new();

    for (file, expected_dep_files) in expected_deps {
        let expected: HashSet<String> = expected_dep_files.iter().cloned().collect();

        // Find import edges originating from nodes in this file
        // that target nodes in other files (resolved cross-file imports)
        let sql = "SELECT DISTINCT n2.file_path
                   FROM edges e
                   JOIN nodes n1 ON n1.id = e.source_id
                   JOIN nodes n2 ON n2.id = e.target_id
                   WHERE n1.file_path = ?1
                   AND e.type = 'imports'
                   AND n2.file_path != ?1";

        let actual: HashSet<String> = match store.conn.prepare(sql) {
            Ok(mut stmt) => stmt
                .query_map(rusqlite::params![file], |row| row.get::<_, String>(0))
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
                .unwrap_or_default(),
            Err(_) => HashSet::new(),
        };

        let metrics = EvalMetrics::compute(&expected, &actual);
        all_metrics.push(metrics);
    }

    EvalMetrics::average(&all_metrics)
}

/// Run the full evaluation suite and produce an EvalReport.
pub fn run_evaluation(store: &GraphStore, ground_truth: &GroundTruth) -> EvalReport {
    let node_count = store.get_node_count().unwrap_or(0);
    let edge_count = store.get_edge_count().unwrap_or(0);

    let search_metrics = evaluate_search(store, &ground_truth.search_queries);
    let caller_metrics = evaluate_callers(store, &ground_truth.callers);
    let dead_code_metrics = evaluate_dead_code(store, &ground_truth.dead_code);
    let dependency_metrics = evaluate_dependencies(store, &ground_truth.file_dependencies);

    let overall = EvalMetrics::average(&[
        search_metrics.clone(),
        caller_metrics.clone(),
        dead_code_metrics.clone(),
        dependency_metrics.clone(),
    ]);

    EvalReport {
        search_metrics,
        caller_metrics,
        dead_code_metrics,
        dependency_metrics,
        overall,
        node_count_ok: node_count >= ground_truth.expected_node_count_min,
        edge_count_ok: edge_count >= ground_truth.expected_edge_count_min,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eval_metrics_both_empty() {
        let m = EvalMetrics::compute(&HashSet::new(), &HashSet::new());
        assert_eq!(m.precision, 1.0);
        assert_eq!(m.recall, 1.0);
        assert_eq!(m.f1, 1.0);
    }

    #[test]
    fn eval_metrics_perfect_match() {
        let expected: HashSet<String> = ["a", "b", "c"].iter().map(|s| s.to_string()).collect();
        let actual = expected.clone();
        let m = EvalMetrics::compute(&expected, &actual);
        assert_eq!(m.precision, 1.0);
        assert_eq!(m.recall, 1.0);
        assert_eq!(m.f1, 1.0);
    }

    #[test]
    fn eval_metrics_partial_overlap() {
        let expected: HashSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let actual: HashSet<String> = ["a", "c"].iter().map(|s| s.to_string()).collect();
        let m = EvalMetrics::compute(&expected, &actual);
        assert!((m.precision - 0.5).abs() < 1e-10);
        assert!((m.recall - 0.5).abs() < 1e-10);
        assert!((m.f1 - 0.5).abs() < 1e-10);
    }

    #[test]
    fn eval_metrics_no_overlap() {
        let expected: HashSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let actual: HashSet<String> = ["c", "d"].iter().map(|s| s.to_string()).collect();
        let m = EvalMetrics::compute(&expected, &actual);
        assert_eq!(m.precision, 0.0);
        assert_eq!(m.recall, 0.0);
        assert_eq!(m.f1, 0.0);
    }

    #[test]
    fn eval_metrics_average() {
        let m1 = EvalMetrics {
            precision: 1.0,
            recall: 0.5,
            f1: 0.667,
        };
        let m2 = EvalMetrics {
            precision: 0.5,
            recall: 1.0,
            f1: 0.667,
        };
        let avg = EvalMetrics::average(&[m1, m2]);
        assert!((avg.precision - 0.75).abs() < 1e-10);
        assert!((avg.recall - 0.75).abs() < 1e-10);
    }

    #[test]
    fn load_ground_truth_from_fixture() {
        let path = Path::new("tests/fixtures/eval-project/ground-truth.json");
        if path.exists() {
            let gt = load_ground_truth(path).unwrap();
            assert!(!gt.description.is_empty());
            assert!(gt.expected_node_count_min > 0);
            assert!(!gt.search_queries.is_empty());
            assert!(!gt.callers.is_empty());
            assert!(!gt.dead_code.is_empty());
        }
    }
}
