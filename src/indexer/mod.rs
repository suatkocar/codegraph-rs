//! Indexer pipeline: parse source files, extract symbols, and build the code graph.

pub mod parser;
pub mod extractor;
pub mod pipeline;
pub mod embedder;

pub use parser::CodeParser;
pub use extractor::Extractor;
pub use pipeline::{IndexingPipeline, IndexOptions, IndexResult};
pub use embedder::EmbeddingEngine;
