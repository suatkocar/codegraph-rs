//! CodeGraph — codebase intelligence library.
//!
//! Provides semantic code graph construction, vector search, and MCP server
//! capabilities for AI-assisted development workflows.

pub mod types;
pub mod error;
pub mod db;
pub mod indexer;
pub mod graph;
pub mod context;
pub mod mcp;
pub mod hooks;
pub mod resolution;
