//! Configuration system — YAML config, presets, auto editor detection.

pub mod loader;
pub mod preset;
pub mod schema;

// Re-export the most commonly used types.
pub use loader::{detect_editor, filter_tools, load_config};
pub use preset::{get_preset, PresetDefinition};
pub use schema::{CodeGraphConfig, PresetName, ToolMetadata};
