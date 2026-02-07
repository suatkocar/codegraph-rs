//! Database layer for CodeGraph.
//!
//! - [`schema`] — DDL and initialization (`initialize_database`).
//! - [`converters`] — Row-to-struct conversions (`row_to_code_node`, `row_to_code_edge`).

pub mod converters;
pub mod schema;

// Re-export the most commonly used items at the `db` level for convenience.
pub use converters::{row_to_code_edge, row_to_code_node};
pub use schema::{create_vec_table, initialize_database};
