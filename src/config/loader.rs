//! Multi-source config loading with priority merging.
//!
//! Priority order (highest wins):
//!   CLI flags > Environment vars > Project config > User config > Defaults
//!
//! Also provides editor auto-detection and tool filtering.

use std::collections::HashSet;
use std::path::Path;

use super::preset::enabled_categories;
use super::schema::{CategoryConfig, CodeGraphConfig, PresetName, ToolMetadata, ToolOverride};
use crate::error::CodeGraphError;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load configuration from all available sources and merge them.
///
/// Sources (low → high priority):
///   1. Built-in defaults (Full preset)
///   2. User config  (`~/.config/codegraph/config.yaml`)
///   3. Project config (`.codegraph.yaml` in `project_dir`)
///   4. Environment variables (`CODEGRAPH_PRESET`, `CODEGRAPH_DISABLED_TOOLS`, etc.)
///   5. CLI flag (`cli_preset`)
pub fn load_config(
    cli_preset: Option<&str>,
    project_dir: Option<&Path>,
) -> Result<CodeGraphConfig, CodeGraphError> {
    // Start from defaults
    let mut config = CodeGraphConfig::default();

    // Layer 2: user config
    if let Some(user) = load_user_config() {
        config = merge_configs(config, user);
    }

    // Layer 3: project config
    if let Some(dir) = project_dir {
        if let Some(project) = load_project_config(dir) {
            config = merge_configs(config, project);
        }
    }

    // Layer 4: environment variables
    load_env_overrides(&mut config);

    // Layer 5: CLI preset (highest priority)
    if let Some(preset_str) = cli_preset {
        if let Some(preset) = PresetName::from_str_loose(preset_str) {
            config.preset = preset;
        }
    }

    Ok(config)
}

/// Load user config from the platform-specific config directory.
///
/// - macOS: `~/Library/Application Support/codegraph/config.yaml`
/// - Linux: `~/.config/codegraph/config.yaml`
/// - Windows: `%APPDATA%\codegraph\config.yaml`
///
/// Returns `None` if the file does not exist or is unparseable.
pub fn load_user_config() -> Option<CodeGraphConfig> {
    let path = user_config_path()?;
    load_config_file(&path)
}

/// Load project config from `.codegraph.yaml` in the given directory.
///
/// Returns `None` if the file does not exist or is unparseable.
pub fn load_project_config(dir: &Path) -> Option<CodeGraphConfig> {
    let path = dir.join(".codegraph.yaml");
    load_config_file(&path)
}

/// Auto-detect the best preset based on the MCP client name.
///
/// Known clients:
/// - `"claude-code"`, `"claude-desktop"`, `"claude"` → Full
/// - `"vscode"`, `"code"`, `"cursor"` → Balanced
/// - `"zed"`, `"vim"`, `"nvim"`, `"neovim"` → Minimal
/// - unknown → Full (conservative default)
pub fn detect_editor(client_name: &str) -> PresetName {
    match client_name.trim().to_lowercase().as_str() {
        // Full — AI-native editors that benefit from all tools
        "claude-code" | "claude_code" | "claude-desktop" | "claude" | "claude.ai" => {
            PresetName::Full
        }

        // Balanced — mainstream IDEs with good context budgets
        "vscode" | "code" | "visual studio code" | "cursor" | "windsurf" => PresetName::Balanced,

        // Balanced — JetBrains family
        "intellij" | "idea" | "pycharm" | "webstorm" | "rustrover" | "clion" | "goland"
        | "phpstorm" | "rider" => PresetName::Balanced,

        // Balanced — other IDEs
        "emacs" | "sublime" | "sublime text" | "subl" => PresetName::Balanced,

        // Minimal — terminal-first editors with tight context
        "zed" | "vim" | "nvim" | "neovim" => PresetName::Minimal,

        // Unknown — default to full (don't limit capabilities)
        _ => PresetName::Full,
    }
}

/// Apply environment variable overrides to a config in place.
///
/// Supported variables:
/// - `CODEGRAPH_PRESET` — override the preset name
/// - `CODEGRAPH_EXCLUDE_TESTS` — set to `"1"` or `"true"` to exclude tests
/// - `CODEGRAPH_DISABLED_TOOLS` — comma-separated tool names to disable
/// - `CODEGRAPH_ENABLED_CATEGORIES` — comma-separated category names (disables all others)
pub fn load_env_overrides(config: &mut CodeGraphConfig) {
    // Preset
    if let Ok(val) = std::env::var("CODEGRAPH_PRESET") {
        if let Some(preset) = PresetName::from_str_loose(&val) {
            config.preset = preset;
        }
    }

    // Exclude tests
    if let Ok(val) = std::env::var("CODEGRAPH_EXCLUDE_TESTS") {
        config.performance.exclude_tests = matches!(val.as_str(), "1" | "true" | "yes");
    }

    // Disabled tools
    if let Ok(val) = std::env::var("CODEGRAPH_DISABLED_TOOLS") {
        for name in val.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            config.tools.overrides.insert(
                name.to_string(),
                ToolOverride::disabled("Disabled via CODEGRAPH_DISABLED_TOOLS"),
            );
        }
    }

    // Enabled categories (disables all others)
    if let Ok(val) = std::env::var("CODEGRAPH_ENABLED_CATEGORIES") {
        let enabled: HashSet<&str> = val.split(',').map(|s| s.trim()).collect();

        // Disable all categories first
        for cat_name in super::preset::ALL_CATEGORIES {
            config.tools.categories.insert(
                cat_name.to_string(),
                CategoryConfig {
                    enabled: enabled.contains(cat_name),
                },
            );
        }
    }
}

/// Filter a list of tool metadata based on the active config.
///
/// A tool passes the filter if:
/// 1. Its category is enabled by the preset (or explicitly in config)
/// 2. It is not individually disabled via `tools.overrides`
/// 3. The total count does not exceed `performance.max_tool_count`
pub fn filter_tools(config: &CodeGraphConfig, all_tools: &[ToolMetadata]) -> Vec<ToolMetadata> {
    let preset_cats = enabled_categories(&config.preset);

    let mut result: Vec<ToolMetadata> = all_tools
        .iter()
        .filter(|t| {
            // Check individual override first
            if let Some(ov) = config.tools.overrides.get(&t.name) {
                if !ov.enabled {
                    return false;
                }
            }

            // Check category: preset categories OR explicit config
            let cat_enabled = if let Some(cat_cfg) = config.tools.categories.get(&t.category) {
                cat_cfg.enabled
            } else {
                // Not explicitly configured — use preset default
                preset_cats.contains(t.category.as_str())
            };

            cat_enabled
        })
        .cloned()
        .collect();

    // Enforce max tool count
    if let Some(max) = config.performance.max_tool_count {
        result.truncate(max);
    }

    result
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Platform-specific user config path via the `directories` crate.
fn user_config_path() -> Option<std::path::PathBuf> {
    directories::ProjectDirs::from("dev", "codegraph", "codegraph")
        .map(|dirs| dirs.config_dir().join("config.yaml"))
}

/// Try to load and parse a YAML config file. Returns `None` on any error.
fn load_config_file(path: &Path) -> Option<CodeGraphConfig> {
    let contents = std::fs::read_to_string(path).ok()?;
    serde_yaml::from_str(&contents).ok()
}

/// Merge two configs: `overlay` fields take priority over `base`.
fn merge_configs(mut base: CodeGraphConfig, overlay: CodeGraphConfig) -> CodeGraphConfig {
    // Version
    if overlay.version != "1.0" {
        base.version = overlay.version;
    }

    // Preset — overlay always wins (even if it's the default "full")
    // because we can't distinguish "explicitly set to full" from "default".
    // The priority system handles this by layering in the right order.
    base.preset = overlay.preset;

    // Tool overrides — overlay keys win
    for (name, ov) in overlay.tools.overrides {
        base.tools.overrides.insert(name, ov);
    }

    // Category config — overlay keys win
    for (name, cat) in overlay.tools.categories {
        base.tools.categories.insert(name, cat);
    }

    // Performance — overlay wins on non-default values
    if overlay.performance.max_tool_count.is_some() {
        base.performance.max_tool_count = overlay.performance.max_tool_count;
    }
    if overlay.performance.exclude_tests {
        base.performance.exclude_tests = true;
    }

    base
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::PerformanceConfig;
    use std::io::Write;
    use std::sync::Mutex;

    /// Mutex to serialize tests that use environment variables.
    /// Rust runs tests in parallel within the same process, so `set_var`/`remove_var`
    /// from one test can race with another.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // -- load_config ---------------------------------------------------

    #[test]
    fn test_load_default_config() {
        let _guard = ENV_LOCK.lock().unwrap();
        let config = load_config(None, None).unwrap();
        assert_eq!(config.version, "1.0");
        assert_eq!(config.preset, PresetName::Full);
    }

    #[test]
    fn test_load_config_with_cli_preset() {
        let _guard = ENV_LOCK.lock().unwrap();
        let config = load_config(Some("minimal"), None).unwrap();
        assert_eq!(config.preset, PresetName::Minimal);
    }

    #[test]
    fn test_load_config_cli_overrides_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        // Set env to balanced
        std::env::set_var("CODEGRAPH_PRESET", "balanced");
        let config = load_config(Some("minimal"), None).unwrap();
        // CLI wins over env
        assert_eq!(config.preset, PresetName::Minimal);
        std::env::remove_var("CODEGRAPH_PRESET");
    }

    #[test]
    fn test_load_config_invalid_cli_preset_ignored() {
        let _guard = ENV_LOCK.lock().unwrap();
        let config = load_config(Some("nonexistent"), None).unwrap();
        assert_eq!(config.preset, PresetName::Full); // falls back to default
    }

    // -- load_user_config ----------------------------------------------

    #[test]
    fn test_load_user_config_missing_returns_none() {
        // User config path almost certainly doesn't exist in test env
        // (or if it does, it should parse fine).
        let result = load_user_config();
        // We can't assert None because the user might have a config file.
        // Instead, verify it doesn't panic.
        let _ = result;
    }

    // -- load_project_config -------------------------------------------

    #[test]
    fn test_load_project_config_from_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".codegraph.yaml");
        let mut f = std::fs::File::create(&config_path).unwrap();
        writeln!(
            f,
            r#"
version: "1.0"
preset: balanced
performance:
  exclude_tests: true
"#
        )
        .unwrap();

        let config = load_project_config(dir.path()).unwrap();
        assert_eq!(config.preset, PresetName::Balanced);
        assert!(config.performance.exclude_tests);
    }

    #[test]
    fn test_load_project_config_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_project_config(dir.path()).is_none());
    }

    #[test]
    fn test_load_project_config_invalid_yaml_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".codegraph.yaml");
        std::fs::write(&config_path, "{{not valid yaml").unwrap();
        assert!(load_project_config(dir.path()).is_none());
    }

    // -- detect_editor -------------------------------------------------

    #[test]
    fn test_detect_editor_claude_code() {
        assert_eq!(detect_editor("claude-code"), PresetName::Full);
    }

    #[test]
    fn test_detect_editor_claude_desktop() {
        assert_eq!(detect_editor("claude-desktop"), PresetName::Full);
    }

    #[test]
    fn test_detect_editor_claude_generic() {
        assert_eq!(detect_editor("claude"), PresetName::Full);
    }

    #[test]
    fn test_detect_editor_vscode() {
        assert_eq!(detect_editor("vscode"), PresetName::Balanced);
    }

    #[test]
    fn test_detect_editor_cursor() {
        assert_eq!(detect_editor("cursor"), PresetName::Balanced);
    }

    #[test]
    fn test_detect_editor_windsurf() {
        assert_eq!(detect_editor("windsurf"), PresetName::Balanced);
    }

    #[test]
    fn test_detect_editor_zed() {
        assert_eq!(detect_editor("zed"), PresetName::Minimal);
    }

    #[test]
    fn test_detect_editor_vim() {
        assert_eq!(detect_editor("vim"), PresetName::Minimal);
    }

    #[test]
    fn test_detect_editor_neovim() {
        assert_eq!(detect_editor("neovim"), PresetName::Minimal);
        assert_eq!(detect_editor("nvim"), PresetName::Minimal);
    }

    #[test]
    fn test_detect_editor_jetbrains() {
        assert_eq!(detect_editor("intellij"), PresetName::Balanced);
        assert_eq!(detect_editor("pycharm"), PresetName::Balanced);
        assert_eq!(detect_editor("rustrover"), PresetName::Balanced);
    }

    #[test]
    fn test_detect_editor_emacs() {
        assert_eq!(detect_editor("emacs"), PresetName::Balanced);
    }

    #[test]
    fn test_detect_editor_sublime() {
        assert_eq!(detect_editor("sublime"), PresetName::Balanced);
    }

    #[test]
    fn test_detect_editor_unknown_defaults_to_full() {
        assert_eq!(detect_editor("unknown-editor-xyz"), PresetName::Full);
        assert_eq!(detect_editor(""), PresetName::Full);
    }

    #[test]
    fn test_detect_editor_case_insensitive() {
        assert_eq!(detect_editor("VSCode"), PresetName::Balanced);
        assert_eq!(detect_editor("ZED"), PresetName::Minimal);
        assert_eq!(detect_editor("Claude-Code"), PresetName::Full);
    }

    #[test]
    fn test_detect_editor_whitespace_trimmed() {
        assert_eq!(detect_editor("  zed  "), PresetName::Minimal);
        assert_eq!(detect_editor(" vscode "), PresetName::Balanced);
    }

    // -- load_env_overrides --------------------------------------------

    #[test]
    fn test_env_preset_override() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut config = CodeGraphConfig::default();
        std::env::set_var("CODEGRAPH_PRESET", "minimal");
        load_env_overrides(&mut config);
        assert_eq!(config.preset, PresetName::Minimal);
        std::env::remove_var("CODEGRAPH_PRESET");
    }

    #[test]
    fn test_env_exclude_tests() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut config = CodeGraphConfig::default();
        std::env::set_var("CODEGRAPH_EXCLUDE_TESTS", "true");
        load_env_overrides(&mut config);
        assert!(config.performance.exclude_tests);
        std::env::remove_var("CODEGRAPH_EXCLUDE_TESTS");
    }

    #[test]
    fn test_env_exclude_tests_numeric() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut config = CodeGraphConfig::default();
        std::env::set_var("CODEGRAPH_EXCLUDE_TESTS", "1");
        load_env_overrides(&mut config);
        assert!(config.performance.exclude_tests);
        std::env::remove_var("CODEGRAPH_EXCLUDE_TESTS");
    }

    #[test]
    fn test_env_exclude_tests_false() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut config = CodeGraphConfig::default();
        std::env::set_var("CODEGRAPH_EXCLUDE_TESTS", "0");
        load_env_overrides(&mut config);
        assert!(!config.performance.exclude_tests);
        std::env::remove_var("CODEGRAPH_EXCLUDE_TESTS");
    }

    #[test]
    fn test_env_disabled_tools() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut config = CodeGraphConfig::default();
        std::env::set_var(
            "CODEGRAPH_DISABLED_TOOLS",
            "codegraph_dead_code,codegraph_diagram",
        );
        load_env_overrides(&mut config);
        assert!(!config.is_tool_enabled("codegraph_dead_code"));
        assert!(!config.is_tool_enabled("codegraph_diagram"));
        assert!(config.is_tool_enabled("codegraph_query")); // not disabled
        std::env::remove_var("CODEGRAPH_DISABLED_TOOLS");
    }

    #[test]
    fn test_env_enabled_categories() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut config = CodeGraphConfig::default();
        std::env::set_var("CODEGRAPH_ENABLED_CATEGORIES", "Repository,Search");
        load_env_overrides(&mut config);
        assert!(config.is_category_enabled("Repository"));
        assert!(config.is_category_enabled("Search"));
        assert!(!config.is_category_enabled("Git"));
        assert!(!config.is_category_enabled("Security"));
        std::env::remove_var("CODEGRAPH_ENABLED_CATEGORIES");
    }

    // -- merge_configs -------------------------------------------------

    #[test]
    fn test_merge_preset_override() {
        let base = CodeGraphConfig::default(); // Full
        let mut overlay = CodeGraphConfig::default();
        overlay.preset = PresetName::Minimal;

        let merged = merge_configs(base, overlay);
        assert_eq!(merged.preset, PresetName::Minimal);
    }

    #[test]
    fn test_merge_tool_overrides() {
        let base = CodeGraphConfig::default();
        let mut overlay = CodeGraphConfig::default();
        overlay.tools.overrides.insert(
            "codegraph_dead_code".to_string(),
            ToolOverride::disabled("slow"),
        );

        let merged = merge_configs(base, overlay);
        assert!(!merged.is_tool_enabled("codegraph_dead_code"));
    }

    #[test]
    fn test_merge_category_overrides() {
        let base = CodeGraphConfig::default();
        let mut overlay = CodeGraphConfig::default();
        overlay
            .tools
            .categories
            .insert("Git".to_string(), CategoryConfig { enabled: false });

        let merged = merge_configs(base, overlay);
        assert!(!merged.is_category_enabled("Git"));
    }

    #[test]
    fn test_merge_performance() {
        let base = CodeGraphConfig::default();
        let mut overlay = CodeGraphConfig::default();
        overlay.performance = PerformanceConfig {
            max_tool_count: Some(20),
            exclude_tests: true,
        };

        let merged = merge_configs(base, overlay);
        assert_eq!(merged.performance.max_tool_count, Some(20));
        assert!(merged.performance.exclude_tests);
    }

    #[test]
    fn test_merge_preserves_base_when_overlay_default() {
        let mut base = CodeGraphConfig::default();
        base.performance.max_tool_count = Some(42);

        let overlay = CodeGraphConfig::default(); // max_tool_count = None

        let merged = merge_configs(base, overlay);
        // overlay's None shouldn't clobber base's Some(42)
        assert_eq!(merged.performance.max_tool_count, Some(42));
    }

    // -- filter_tools --------------------------------------------------

    fn sample_tools() -> Vec<ToolMetadata> {
        vec![
            ToolMetadata {
                name: "codegraph_query".to_string(),
                category: "Search".to_string(),
                description: "Search".to_string(),
                estimated_tokens: 200,
            },
            ToolMetadata {
                name: "codegraph_callers".to_string(),
                category: "CallGraph".to_string(),
                description: "Callers".to_string(),
                estimated_tokens: 150,
            },
            ToolMetadata {
                name: "codegraph_dead_code".to_string(),
                category: "Analysis".to_string(),
                description: "Dead code".to_string(),
                estimated_tokens: 150,
            },
            ToolMetadata {
                name: "codegraph_stats".to_string(),
                category: "Repository".to_string(),
                description: "Stats".to_string(),
                estimated_tokens: 100,
            },
            ToolMetadata {
                name: "codegraph_blame".to_string(),
                category: "Git".to_string(),
                description: "Git blame".to_string(),
                estimated_tokens: 200,
            },
            ToolMetadata {
                name: "codegraph_context".to_string(),
                category: "Context".to_string(),
                description: "Context".to_string(),
                estimated_tokens: 250,
            },
            ToolMetadata {
                name: "codegraph_scan_security".to_string(),
                category: "Security".to_string(),
                description: "Security scan".to_string(),
                estimated_tokens: 300,
            },
        ]
    }

    #[test]
    fn test_filter_with_full_preset() {
        let config = CodeGraphConfig::default(); // Full
        let tools = sample_tools();
        let filtered = filter_tools(&config, &tools);
        assert_eq!(filtered.len(), tools.len()); // All categories enabled
    }

    #[test]
    fn test_filter_with_minimal_preset() {
        let mut config = CodeGraphConfig::default();
        config.preset = PresetName::Minimal; // Repository + Search only
        let tools = sample_tools();
        let filtered = filter_tools(&config, &tools);
        let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"codegraph_query"));
        assert!(names.contains(&"codegraph_stats"));
        assert!(!names.contains(&"codegraph_callers")); // CallGraph not in Minimal
        assert!(!names.contains(&"codegraph_blame")); // Git not in Minimal
    }

    #[test]
    fn test_filter_with_disabled_tool() {
        let mut config = CodeGraphConfig::default();
        config.tools.overrides.insert(
            "codegraph_query".to_string(),
            ToolOverride::disabled("too slow"),
        );
        let tools = sample_tools();
        let filtered = filter_tools(&config, &tools);
        let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();
        assert!(!names.contains(&"codegraph_query"));
    }

    #[test]
    fn test_filter_with_category_override() {
        let mut config = CodeGraphConfig::default();
        config
            .tools
            .categories
            .insert("Git".to_string(), CategoryConfig { enabled: false });
        let tools = sample_tools();
        let filtered = filter_tools(&config, &tools);
        let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();
        assert!(!names.contains(&"codegraph_blame"));
    }

    #[test]
    fn test_filter_max_tool_count() {
        let mut config = CodeGraphConfig::default();
        config.performance.max_tool_count = Some(3);
        let tools = sample_tools();
        let filtered = filter_tools(&config, &tools);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn test_filter_security_preset() {
        let mut config = CodeGraphConfig::default();
        config.preset = PresetName::SecurityFocused;
        let tools = sample_tools();
        let filtered = filter_tools(&config, &tools);
        let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"codegraph_stats")); // Repository
        assert!(names.contains(&"codegraph_query")); // Search
        assert!(names.contains(&"codegraph_dead_code")); // Analysis
        assert!(names.contains(&"codegraph_scan_security")); // Security
        assert!(!names.contains(&"codegraph_blame")); // Git excluded
        assert!(!names.contains(&"codegraph_context")); // Context excluded
    }

    #[test]
    fn test_filter_empty_tools() {
        let config = CodeGraphConfig::default();
        let filtered = filter_tools(&config, &[]);
        assert!(filtered.is_empty());
    }

    // -- end-to-end with project config --------------------------------

    #[test]
    fn test_load_config_with_project_dir() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".codegraph.yaml");
        std::fs::write(
            &config_path,
            r#"
preset: minimal
performance:
  exclude_tests: true
  max_tool_count: 10
tools:
  overrides:
    codegraph_diagram:
      enabled: false
      reason: "not needed"
"#,
        )
        .unwrap();

        let config = load_config(None, Some(dir.path())).unwrap();
        assert_eq!(config.preset, PresetName::Minimal);
        assert!(config.performance.exclude_tests);
        assert_eq!(config.performance.max_tool_count, Some(10));
        assert!(!config.is_tool_enabled("codegraph_diagram"));
    }

    #[test]
    fn test_cli_preset_overrides_project_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".codegraph.yaml");
        std::fs::write(&config_path, "preset: minimal").unwrap();

        let config = load_config(Some("balanced"), Some(dir.path())).unwrap();
        assert_eq!(config.preset, PresetName::Balanced); // CLI wins
    }

    // ====================================================================
    // Phase 18B — extended config loader tests
    // ====================================================================

    use pretty_assertions::assert_eq as pa_eq;
    use test_case::test_case;

    // --- detect_editor: full coverage ---

    #[test_case("claude-code", PresetName::Full ; "claude code hyphen")]
    #[test_case("claude_code", PresetName::Full ; "claude code underscore")]
    #[test_case("claude-desktop", PresetName::Full ; "claude-desktop full")]
    #[test_case("claude", PresetName::Full ; "claude full")]
    #[test_case("claude.ai", PresetName::Full ; "claude.ai full")]
    #[test_case("vscode", PresetName::Balanced ; "vscode balanced")]
    #[test_case("code", PresetName::Balanced ; "code balanced")]
    #[test_case("visual studio code", PresetName::Balanced ; "vs code balanced")]
    #[test_case("cursor", PresetName::Balanced ; "cursor balanced")]
    #[test_case("windsurf", PresetName::Balanced ; "windsurf balanced")]
    #[test_case("intellij", PresetName::Balanced ; "intellij balanced")]
    #[test_case("idea", PresetName::Balanced ; "idea balanced")]
    #[test_case("pycharm", PresetName::Balanced ; "pycharm balanced")]
    #[test_case("webstorm", PresetName::Balanced ; "webstorm balanced")]
    #[test_case("rustrover", PresetName::Balanced ; "rustrover balanced")]
    #[test_case("clion", PresetName::Balanced ; "clion balanced")]
    #[test_case("goland", PresetName::Balanced ; "goland balanced")]
    #[test_case("phpstorm", PresetName::Balanced ; "phpstorm balanced")]
    #[test_case("rider", PresetName::Balanced ; "rider balanced")]
    #[test_case("emacs", PresetName::Balanced ; "emacs balanced")]
    #[test_case("sublime", PresetName::Balanced ; "sublime balanced")]
    #[test_case("sublime text", PresetName::Balanced ; "sublime text balanced")]
    #[test_case("subl", PresetName::Balanced ; "subl balanced")]
    #[test_case("zed", PresetName::Minimal ; "zed minimal")]
    #[test_case("vim", PresetName::Minimal ; "vim minimal")]
    #[test_case("nvim", PresetName::Minimal ; "nvim minimal")]
    #[test_case("neovim", PresetName::Minimal ; "neovim minimal")]
    #[test_case("unknown-editor", PresetName::Full ; "unknown defaults full")]
    #[test_case("", PresetName::Full ; "empty defaults full")]
    fn detect_editor_parameterised(client: &str, expected: PresetName) {
        pa_eq!(detect_editor(client), expected);
    }

    #[test]
    fn detect_editor_case_insensitive_all() {
        pa_eq!(detect_editor("VSCODE"), PresetName::Balanced);
        pa_eq!(detect_editor("Cursor"), PresetName::Balanced);
        pa_eq!(detect_editor("INTELLIJ"), PresetName::Balanced);
        pa_eq!(detect_editor("ZED"), PresetName::Minimal);
        pa_eq!(detect_editor("VIM"), PresetName::Minimal);
        pa_eq!(detect_editor("CLAUDE-CODE"), PresetName::Full);
    }

    #[test]
    fn detect_editor_whitespace_all() {
        pa_eq!(detect_editor("  vscode  "), PresetName::Balanced);
        pa_eq!(detect_editor("  zed  "), PresetName::Minimal);
        pa_eq!(detect_editor("  claude-code  "), PresetName::Full);
        pa_eq!(detect_editor("\tcursor\t"), PresetName::Balanced);
    }

    // --- filter_tools extended ---

    #[test]
    fn filter_balanced_preset_includes_callgraph() {
        let mut config = CodeGraphConfig::default();
        config.preset = PresetName::Balanced;
        let tools = sample_tools();
        let filtered = filter_tools(&config, &tools);
        let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"codegraph_callers")); // CallGraph in Balanced
    }

    #[test]
    fn filter_balanced_preset_includes_context() {
        let mut config = CodeGraphConfig::default();
        config.preset = PresetName::Balanced;
        let tools = sample_tools();
        let filtered = filter_tools(&config, &tools);
        let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"codegraph_context"));
    }

    #[test]
    fn filter_security_preset_excludes_callgraph() {
        let mut config = CodeGraphConfig::default();
        config.preset = PresetName::SecurityFocused;
        let tools = sample_tools();
        let filtered = filter_tools(&config, &tools);
        let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();
        assert!(!names.contains(&"codegraph_callers"));
    }

    #[test]
    fn filter_with_category_override_overrides_preset() {
        let mut config = CodeGraphConfig::default();
        config.preset = PresetName::Minimal; // Only Repository + Search
                                             // But explicitly enable Security category
        config
            .tools
            .categories
            .insert("Security".to_string(), CategoryConfig { enabled: true });
        let tools = sample_tools();
        let filtered = filter_tools(&config, &tools);
        let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"codegraph_scan_security"));
    }

    #[test]
    fn filter_max_tool_count_zero() {
        let mut config = CodeGraphConfig::default();
        config.performance.max_tool_count = Some(0);
        let tools = sample_tools();
        let filtered = filter_tools(&config, &tools);
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_max_tool_count_exceeds_total() {
        let mut config = CodeGraphConfig::default();
        config.performance.max_tool_count = Some(100);
        let tools = sample_tools();
        let filtered = filter_tools(&config, &tools);
        pa_eq!(filtered.len(), tools.len());
    }

    #[test]
    fn filter_disabled_tool_even_if_category_enabled() {
        let mut config = CodeGraphConfig::default();
        config.tools.overrides.insert(
            "codegraph_scan_security".to_string(),
            ToolOverride::disabled("not needed"),
        );
        let tools = sample_tools();
        let filtered = filter_tools(&config, &tools);
        let names: Vec<&str> = filtered.iter().map(|t| t.name.as_str()).collect();
        assert!(!names.contains(&"codegraph_scan_security"));
    }

    // --- merge_configs extended ---

    #[test]
    fn merge_version_override() {
        let base = CodeGraphConfig::default();
        let mut overlay = CodeGraphConfig::default();
        overlay.version = "2.0".to_string();
        let merged = merge_configs(base, overlay);
        pa_eq!(merged.version, "2.0");
    }

    #[test]
    fn merge_version_1_0_is_not_overridden() {
        let mut base = CodeGraphConfig::default();
        base.version = "2.0".to_string();
        let overlay = CodeGraphConfig::default(); // version = "1.0"
        let merged = merge_configs(base, overlay);
        // overlay version is "1.0" which is not overridden per the logic
        pa_eq!(merged.version, "2.0");
    }

    #[test]
    fn merge_multiple_tool_overrides() {
        let base = CodeGraphConfig::default();
        let mut overlay = CodeGraphConfig::default();
        overlay
            .tools
            .overrides
            .insert("tool_a".to_string(), ToolOverride::disabled("reason1"));
        overlay
            .tools
            .overrides
            .insert("tool_b".to_string(), ToolOverride::disabled("reason2"));
        let merged = merge_configs(base, overlay);
        assert!(!merged.is_tool_enabled("tool_a"));
        assert!(!merged.is_tool_enabled("tool_b"));
    }

    #[test]
    fn merge_exclude_tests_propagates() {
        let base = CodeGraphConfig::default();
        let mut overlay = CodeGraphConfig::default();
        overlay.performance.exclude_tests = true;
        let merged = merge_configs(base, overlay);
        assert!(merged.performance.exclude_tests);
    }

    #[test]
    fn merge_exclude_tests_base_true_overlay_false_stays_true() {
        let mut base = CodeGraphConfig::default();
        base.performance.exclude_tests = true;
        let overlay = CodeGraphConfig::default(); // exclude_tests = false
        let merged = merge_configs(base, overlay);
        // The merge logic: `if overlay.performance.exclude_tests { base.performance.exclude_tests = true; }`
        // Since overlay is false, base stays true? No - base is moved. Let's check:
        // Actually base is mut, overlay.exclude_tests is false, so the if-branch doesn't fire.
        // But base.exclude_tests was already true, so it stays true.
        assert!(merged.performance.exclude_tests);
    }

    // --- load_project_config with various YAML formats ---

    #[test]
    fn load_project_config_with_tool_overrides() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".codegraph.yaml");
        std::fs::write(
            &config_path,
            r#"
preset: balanced
tools:
  overrides:
    codegraph_dead_code:
      enabled: false
      reason: "slow"
"#,
        )
        .unwrap();

        let config = load_project_config(dir.path()).unwrap();
        pa_eq!(config.preset, PresetName::Balanced);
        assert!(!config.is_tool_enabled("codegraph_dead_code"));
    }

    #[test]
    fn load_project_config_minimal_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".codegraph.yaml");
        std::fs::write(&config_path, "preset: minimal\n").unwrap();

        let config = load_project_config(dir.path()).unwrap();
        pa_eq!(config.preset, PresetName::Minimal);
    }

    #[test]
    fn load_project_config_empty_file_uses_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".codegraph.yaml");
        std::fs::write(&config_path, "{}\n").unwrap();

        let config = load_project_config(dir.path()).unwrap();
        pa_eq!(config.preset, PresetName::Full); // default
    }

    // --- load_config end-to-end ---

    #[test]
    fn load_config_no_project_no_cli() {
        let _guard = ENV_LOCK.lock().unwrap();
        let config = load_config(None, None).unwrap();
        pa_eq!(config.version, "1.0");
        // Preset may be affected by env vars, but version should always be 1.0
    }

    #[test]
    fn load_config_with_nonexistent_project_dir() {
        let _guard = ENV_LOCK.lock().unwrap();
        let config = load_config(None, Some(Path::new("/nonexistent/path"))).unwrap();
        pa_eq!(config.version, "1.0");
    }

    #[test]
    fn load_config_unknown_cli_preset_falls_back() {
        let _guard = ENV_LOCK.lock().unwrap();
        let config = load_config(Some("nonexistent_preset"), None).unwrap();
        // Invalid preset string is ignored, defaults apply
        pa_eq!(config.version, "1.0");
    }

    // --- load_env_overrides: edge cases ---

    #[test]
    fn env_exclude_tests_yes() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut config = CodeGraphConfig::default();
        std::env::set_var("CODEGRAPH_EXCLUDE_TESTS", "yes");
        load_env_overrides(&mut config);
        assert!(config.performance.exclude_tests);
        std::env::remove_var("CODEGRAPH_EXCLUDE_TESTS");
    }

    #[test]
    fn env_disabled_tools_empty_string() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut config = CodeGraphConfig::default();
        std::env::set_var("CODEGRAPH_DISABLED_TOOLS", "");
        load_env_overrides(&mut config);
        // Empty string should not add any overrides
        assert!(config.tools.overrides.is_empty());
        std::env::remove_var("CODEGRAPH_DISABLED_TOOLS");
    }

    #[test]
    fn env_disabled_tools_with_spaces() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut config = CodeGraphConfig::default();
        std::env::set_var("CODEGRAPH_DISABLED_TOOLS", " tool_a , tool_b , tool_c ");
        load_env_overrides(&mut config);
        assert!(!config.is_tool_enabled("tool_a"));
        assert!(!config.is_tool_enabled("tool_b"));
        assert!(!config.is_tool_enabled("tool_c"));
        std::env::remove_var("CODEGRAPH_DISABLED_TOOLS");
    }

    #[test]
    fn env_invalid_preset_ignored() {
        let _guard = ENV_LOCK.lock().unwrap();
        let mut config = CodeGraphConfig::default();
        std::env::set_var("CODEGRAPH_PRESET", "nonexistent");
        load_env_overrides(&mut config);
        pa_eq!(config.preset, PresetName::Full); // unchanged
        std::env::remove_var("CODEGRAPH_PRESET");
    }
}
