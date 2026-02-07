//! Unified error type for CodeGraph.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CodeGraphError {
    #[error("SQLite error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Tree-sitter error: {0}")]
    Parse(String),

    #[error("Embedding error: {0}")]
    Embedding(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("MCP protocol error: {0}")]
    Mcp(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CodeGraphError>;
