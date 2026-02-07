//! CodeGraph — codebase intelligence library.
//!
//! Provides semantic code graph construction, vector search, and MCP server
//! capabilities for AI-assisted development workflows.

pub mod cli;
pub mod config;
pub mod context;
pub mod db;
pub mod error;
pub mod eval;
pub mod git;
pub mod graph;
pub mod hooks;
pub mod indexer;
pub mod mcp;
pub mod resolution;
pub mod security;
pub mod types;
