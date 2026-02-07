use criterion::{criterion_group, criterion_main, Criterion};
use std::path::PathBuf;

use codegraph::db::schema::initialize_database;
use codegraph::graph::store::GraphStore;
use codegraph::indexer::pipeline::{IndexOptions, IndexingPipeline};

fn bench_index_eval_project(c: &mut Criterion) {
    let fixture_path = PathBuf::from("tests/fixtures/eval-project");
    if !fixture_path.exists() {
        eprintln!("Fixture path does not exist, skipping benchmark");
        return;
    }

    c.bench_function("index_eval_project", |b| {
        b.iter(|| {
            let conn = initialize_database(":memory:").unwrap();
            let store = GraphStore::from_connection(conn);
            let pipeline = IndexingPipeline::new(&store);
            pipeline
                .index_directory(&IndexOptions {
                    root_dir: fixture_path.clone(),
                    incremental: false,
                })
                .unwrap();
        });
    });
}

fn bench_incremental_noop(c: &mut Criterion) {
    let fixture_path = PathBuf::from("tests/fixtures/eval-project");
    if !fixture_path.exists() {
        eprintln!("Fixture path does not exist, skipping benchmark");
        return;
    }

    // Pre-index once
    let conn = initialize_database(":memory:").unwrap();
    let store = GraphStore::from_connection(conn);
    let pipeline = IndexingPipeline::new(&store);
    pipeline
        .index_directory(&IndexOptions {
            root_dir: fixture_path.clone(),
            incremental: false,
        })
        .unwrap();

    c.bench_function("incremental_noop", |b| {
        b.iter(|| {
            pipeline
                .index_directory(&IndexOptions {
                    root_dir: fixture_path.clone(),
                    incremental: true,
                })
                .unwrap();
        });
    });
}

criterion_group!(benches, bench_index_eval_project, bench_incremental_noop);
criterion_main!(benches);
