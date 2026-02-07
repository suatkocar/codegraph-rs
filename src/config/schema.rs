//! Configuration data structures for CodeGraph.
//!
//! Defines the YAML config format: presets, tool overrides, category toggles,
//! and performance budgets. Designed for multi-source loading with serde.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Top-level config
// ---------------------------------------------------------------------------

/// Root configuration for CodeGraph.
///
/// Loaded from YAML files, environment variables, and CLI flags.
/// Multiple sources are merged with well-defined priority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeGraphConfig {
    /// Config format version (currently "1.0").
    #[serde(default = "default_version")]
    pub version: String,

    /// Active preset name.
    #[serde(default = "default_preset")]
    pub preset: PresetName,

    /// Per-tool and per-category overrides.
    #[serde(default)]
    pub tools: ToolsConfig,

    /// Performance tuning knobs.
    #[serde(default)]
    pub performance: PerformanceConfig,
}

impl Default for CodeGraphConfig {
    fn default() -> Self {
        Self {
            version: default_version(),
            preset: PresetName::Full,
            tools: ToolsConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl CodeGraphConfig {
    /// Check whether a specific category is enabled (defaults to true).
    pub fn is_category_enabled(&self, category: &str) -> bool {
        self.tools
            .categories
            .get(category)
            .map(|c| c.enabled)
            .unwrap_or(true)
    }

    /// Check whether a specific tool is enabled (defaults to true).
    pub fn is_tool_enabled(&self, tool_name: &str) -> bool {
        self.tools
            .overrides
            .get(tool_name)
            .map(|o| o.enabled)
            .unwrap_or(true)
    }
}

// ---------------------------------------------------------------------------
// PresetName
// ---------------------------------------------------------------------------

/// Named presets that control which tool categories are active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresetName {
    /// Essential tools only (~15 tools, ~3 000 tokens).
    Minimal,
    /// Good defaults for most editors (~30 tools, ~6 000 tokens).
    Balanced,
    /// All tools enabled (~50+ tools, ~10 000 tokens).
    Full,
    /// Security and analysis tools prioritized.
    #[serde(rename = "security-focused")]
    SecurityFocused,
}

impl PresetName {
    /// Parse from a loose string (case-insensitive, underscores accepted).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "minimal" => Some(Self::Minimal),
            "balanced" => Some(Self::Balanced),
            "full" => Some(Self::Full),
            "security-focused" | "security_focused" | "securityfocused" => {
                Some(Self::SecurityFocused)
            }
            _ => None,
        }
    }

    /// Canonical string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Balanced => "balanced",
            Self::Full => "full",
            Self::SecurityFocused => "security-focused",
        }
    }
}

impl std::fmt::Display for PresetName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ToolsConfig
// ---------------------------------------------------------------------------

/// Per-tool and per-category configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolsConfig {
    /// Individual tool overrides (enable/disable specific tools).
    #[serde(default)]
    pub overrides: HashMap<String, ToolOverride>,

    /// Category-level toggles (enable/disable entire groups).
    #[serde(default)]
    pub categories: HashMap<String, CategoryConfig>,
}

// ---------------------------------------------------------------------------
// ToolOverride
// ---------------------------------------------------------------------------

/// Override the enabled state of a single tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOverride {
    /// Whether this tool is enabled.
    pub enabled: bool,

    /// Human-readable reason for the override.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ToolOverride {
    /// Create a disabled override with a reason.
    pub fn disabled(reason: impl Into<String>) -> Self {
        Self {
            enabled: false,
            reason: Some(reason.into()),
        }
    }

    /// Create an enabled override.
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            reason: None,
        }
    }
}

// ---------------------------------------------------------------------------
// CategoryConfig
// ---------------------------------------------------------------------------

/// Enable or disable an entire tool category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryConfig {
    /// Whether this category is enabled.
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// PerformanceConfig
// ---------------------------------------------------------------------------

/// Performance tuning knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Maximum number of tools to expose to the MCP client.
    /// Tools beyond this limit are dropped (lowest-priority first).
    #[serde(default = "default_max_tool_count")]
    pub max_tool_count: Option<usize>,

    /// Whether to exclude test files from indexing.
    #[serde(default)]
    pub exclude_tests: bool,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_tool_count: None,
            exclude_tests: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ToolMetadata (for filtering)
// ---------------------------------------------------------------------------

/// Lightweight metadata about a single MCP tool, used for filtering.
#[derive(Debug, Clone)]
pub struct ToolMetadata {
    /// Tool name as registered in the MCP server.
    pub name: String,
    /// Category this tool belongs to.
    pub category: String,
    /// Human-readable description.
    pub description: String,
    /// Estimated token cost of this tool's schema in the system prompt.
    pub estimated_tokens: usize,
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_version() -> String {
    "1.0".to_string()
}

fn default_preset() -> PresetName {
    PresetName::Full
}

fn default_max_tool_count() -> Option<usize> {
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CodeGraphConfig::default();
        assert_eq!(config.version, "1.0");
        assert_eq!(config.preset, PresetName::Full);
        assert!(config.tools.overrides.is_empty());
        assert!(config.tools.categories.is_empty());
        assert_eq!(config.performance.max_tool_count, None);
        assert!(!config.performance.exclude_tests);
    }

    #[test]
    fn test_preset_name_roundtrip() {
        for preset in [
            PresetName::Minimal,
            PresetName::Balanced,
            PresetName::Full,
            PresetName::SecurityFocused,
        ] {
            let s = preset.as_str();
            assert_eq!(PresetName::from_str_loose(s), Some(preset), "roundtrip failed for {s}");
        }
    }

    #[test]
    fn test_preset_name_loose_parsing() {
        assert_eq!(PresetName::from_str_loose("MINIMAL"), Some(PresetName::Minimal));
        assert_eq!(PresetName::from_str_loose("  balanced  "), Some(PresetName::Balanced));
        assert_eq!(PresetName::from_str_loose("security_focused"), Some(PresetName::SecurityFocused));
        assert_eq!(PresetName::from_str_loose("securityfocused"), Some(PresetName::SecurityFocused));
        assert_eq!(PresetName::from_str_loose("unknown"), None);
        assert_eq!(PresetName::from_str_loose(""), None);
    }

    #[test]
    fn test_preset_name_display() {
        assert_eq!(format!("{}", PresetName::Minimal), "minimal");
        assert_eq!(format!("{}", PresetName::Full), "full");
        assert_eq!(format!("{}", PresetName::SecurityFocused), "security-focused");
    }

    #[test]
    fn test_serde_yaml_roundtrip() {
        let config = CodeGraphConfig {
            version: "1.0".to_string(),
            preset: PresetName::Balanced,
            tools: ToolsConfig::default(),
            performance: PerformanceConfig {
                max_tool_count: Some(30),
                exclude_tests: true,
            },
        };

        let yaml = serde_yaml::to_string(&config).unwrap();
        let back: CodeGraphConfig = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(back.version, "1.0");
        assert_eq!(back.preset, PresetName::Balanced);
        assert_eq!(back.performance.max_tool_count, Some(30));
        assert!(back.performance.exclude_tests);
    }

    #[test]
    fn test_serde_json_roundtrip() {
        let config = CodeGraphConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: CodeGraphConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.preset, PresetName::Full);
    }

    #[test]
    fn test_preset_only_yaml() {
        let yaml = r#"preset: "minimal""#;
        let config: CodeGraphConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.preset, PresetName::Minimal);
        assert_eq!(config.version, "1.0"); // default
    }

    #[test]
    fn test_full_yaml_config() {
        let yaml = r#"
version: "1.0"
preset: balanced
tools:
  overrides:
    codegraph_dead_code:
      enabled: false
      reason: "Too slow for interactive use"
  categories:
    Security:
      enabled: true
    Git:
      enabled: false
performance:
  max_tool_count: 25
  exclude_tests: true
"#;
        let config: CodeGraphConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.preset, PresetName::Balanced);
        assert!(!config.is_tool_enabled("codegraph_dead_code"));
        assert!(config.is_tool_enabled("codegraph_query")); // not overridden
        assert!(config.is_category_enabled("Security"));
        assert!(!config.is_category_enabled("Git"));
        assert!(config.is_category_enabled("Unknown")); // default true
        assert_eq!(config.performance.max_tool_count, Some(25));
        assert!(config.performance.exclude_tests);
    }

    #[test]
    fn test_invalid_yaml_returns_error() {
        let yaml = "{{invalid yaml}}";
        let result: Result<CodeGraphConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_tool_override_disabled() {
        let ov = ToolOverride::disabled("too slow");
        assert!(!ov.enabled);
        assert_eq!(ov.reason.as_deref(), Some("too slow"));
    }

    #[test]
    fn test_tool_override_enabled() {
        let ov = ToolOverride::enabled();
        assert!(ov.enabled);
        assert!(ov.reason.is_none());
    }

    #[test]
    fn test_category_config_serde() {
        let yaml = r#"enabled: false"#;
        let cat: CategoryConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!cat.enabled);
    }

    #[test]
    fn test_performance_defaults() {
        let perf = PerformanceConfig::default();
        assert_eq!(perf.max_tool_count, None);
        assert!(!perf.exclude_tests);
    }

    #[test]
    fn test_security_focused_preset_yaml() {
        let yaml = r#"preset: "security-focused""#;
        let config: CodeGraphConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.preset, PresetName::SecurityFocused);
    }
}
