//! Hook installation — writes shell scripts and config files for Claude Code integration.
//!
//! The [`install_hooks`] function performs three non-destructive operations:
//!
//! 1. **Shell scripts** — Writes four executable bash scripts into `.claude/hooks/`
//!    that delegate to `codegraph-mcp hook-*` subcommands.
//! 2. **`settings.json`** — Merges hook entries into `.claude/settings.json` so
//!    Claude Code invokes the scripts at the right lifecycle points.
//! 3. **`.mcp.json`** — Merges the CodeGraph MCP server entry so Claude Code
//!    can discover and launch it automatically.
//!
//! All JSON merges are additive: existing keys outside the CodeGraph namespace
//! are preserved verbatim.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::{json, Map, Value};

use crate::error::Result;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Install CodeGraph hooks, scripts, and MCP configuration into `project_dir`.
///
/// - `project_dir` — Root of the project (where `.claude/` lives).
/// - `binary_path` — Path or name of the `codegraph-mcp` binary (e.g. `"codegraph-mcp"`
///   or `"/usr/local/bin/codegraph-mcp"`).
///
/// This function is idempotent: running it twice produces the same result.
pub fn install_hooks(project_dir: &Path, binary_path: &str) -> Result<()> {
    let hooks_dir = project_dir.join(".claude").join("hooks");
    let settings_path = project_dir.join(".claude").join("settings.json");
    let mcp_path = project_dir.join(".mcp.json");

    // 1. Write shell scripts
    write_shell_scripts(&hooks_dir, binary_path)?;

    // 2. Merge hook entries into settings.json
    merge_settings(&settings_path)?;

    // 3. Merge MCP server entry into .mcp.json
    merge_mcp_config(&mcp_path, binary_path)?;

    eprintln!("[codegraph] Hooks installed successfully.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Shell scripts
// ---------------------------------------------------------------------------

/// Metadata for a single hook script.
struct HookScript {
    filename: &'static str,
    subcommand: &'static str,
    comment: &'static str,
}

/// All hook scripts to install.
const HOOK_SCRIPTS: &[HookScript] = &[
    HookScript {
        filename: "session-start.sh",
        subcommand: "hook-session-start",
        comment: "CodeGraph session-start hook — re-index codebase",
    },
    HookScript {
        filename: "prompt-submit.sh",
        subcommand: "hook-prompt-submit",
        comment: "CodeGraph prompt-submit hook — inject relevant context",
    },
    HookScript {
        filename: "pre-compact.sh",
        subcommand: "hook-pre-compact",
        comment: "CodeGraph pre-compact hook — save graph summary",
    },
    HookScript {
        filename: "post-tool-use.sh",
        subcommand: "hook-post-edit",
        comment: "CodeGraph post-edit hook — re-index modified file",
    },
];

/// Render a hook script body.
fn render_script(hook: &HookScript, binary_path: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
# {comment}
CODEGRAPH_BIN="${{CODEGRAPH_BIN:-{binary_path}}}"
"$CODEGRAPH_BIN" {subcommand} 2>/dev/null || echo '{{"continue":true}}'
"#,
        comment = hook.comment,
        binary_path = binary_path,
        subcommand = hook.subcommand,
    )
}

/// Write all hook shell scripts into `hooks_dir`, creating the directory if needed.
fn write_shell_scripts(hooks_dir: &Path, binary_path: &str) -> Result<()> {
    fs::create_dir_all(hooks_dir)?;

    for hook in HOOK_SCRIPTS {
        let path = hooks_dir.join(hook.filename);
        let body = render_script(hook, binary_path);
        fs::write(&path, body)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        eprintln!("[codegraph] Wrote {}", path.display());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// settings.json merge
// ---------------------------------------------------------------------------

/// Build the hooks value that gets merged into settings.json.
fn build_hooks_value() -> Value {
    json!({
        "SessionStart": [{
            "hooks": [{
                "type": "command",
                "command": "bash .claude/hooks/session-start.sh"
            }]
        }],
        "UserPromptSubmit": [{
            "hooks": [{
                "type": "command",
                "command": "bash .claude/hooks/prompt-submit.sh"
            }]
        }],
        "PreCompact": [{
            "hooks": [{
                "type": "command",
                "command": "bash .claude/hooks/pre-compact.sh"
            }]
        }],
        "PostToolUse": [{
            "matcher": "Write|Edit",
            "hooks": [{
                "type": "command",
                "command": "bash .claude/hooks/post-tool-use.sh"
            }]
        }]
    })
}

/// Read, merge, and write `.claude/settings.json`.
///
/// If the file exists, its JSON is parsed and the `"hooks"` key is merged
/// (our entries overwrite per-event, but unrelated keys are preserved).
/// If the file doesn't exist, it is created with only the hooks key.
fn merge_settings(settings_path: &Path) -> Result<()> {
    let mut root = read_json_or_empty_object(settings_path)?;
    let hooks_value = build_hooks_value();

    merge_object_key(&mut root, "hooks", hooks_value);

    // Ensure parent directory exists
    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let pretty = serde_json::to_string_pretty(&root)?;
    fs::write(settings_path, pretty)?;
    eprintln!("[codegraph] Merged hooks into {}", settings_path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// .mcp.json merge
// ---------------------------------------------------------------------------

/// Build the `mcpServers.codegraph` value.
fn build_mcp_server_value(binary_path: &str) -> Value {
    json!({
        "command": binary_path,
        "args": ["serve"],
        "env": {
            "CODEGRAPH_DB": ".codegraph/codegraph.db"
        }
    })
}

/// Read, merge, and write `.mcp.json`.
///
/// The `"mcpServers"` map is extended with a `"codegraph"` entry. Other
/// server entries are left untouched.
fn merge_mcp_config(mcp_path: &Path, binary_path: &str) -> Result<()> {
    let mut root = read_json_or_empty_object(mcp_path)?;
    let server_value = build_mcp_server_value(binary_path);

    // Ensure mcpServers exists as an object, then insert codegraph
    let servers = root
        .as_object_mut()
        .expect("root is always an object")
        .entry("mcpServers")
        .or_insert_with(|| json!({}));

    if let Some(map) = servers.as_object_mut() {
        map.insert("codegraph".to_string(), server_value);
    }

    let pretty = serde_json::to_string_pretty(&root)?;
    fs::write(mcp_path, pretty)?;
    eprintln!("[codegraph] Merged MCP config into {}", mcp_path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a JSON file and parse it as `Value`, returning an empty object if
/// the file doesn't exist or is empty.
fn read_json_or_empty_object(path: &Path) -> Result<Value> {
    match fs::read_to_string(path) {
        Ok(contents) if !contents.trim().is_empty() => {
            let val: Value = serde_json::from_str(&contents)?;
            Ok(val)
        }
        _ => Ok(Value::Object(Map::new())),
    }
}

/// Merge `value` into the top-level `key` of `root`.
///
/// If `root[key]` already exists as an object and `value` is also an object,
/// the entries from `value` are inserted into the existing object (overwriting
/// collisions but preserving non-colliding keys). Otherwise `root[key]` is
/// replaced entirely.
fn merge_object_key(root: &mut Value, key: &str, value: Value) {
    let map = root
        .as_object_mut()
        .expect("root is always an object");

    match (map.get_mut(key), &value) {
        (Some(existing), Value::Object(new_entries)) if existing.is_object() => {
            let existing_map = existing.as_object_mut().unwrap();
            for (k, v) in new_entries {
                existing_map.insert(k.clone(), v.clone());
            }
        }
        _ => {
            map.insert(key.to_string(), value);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // -- Shell script tests ------------------------------------------------

    #[test]
    fn shell_scripts_are_created_with_correct_content() {
        let tmp = TempDir::new().unwrap();
        let hooks_dir = tmp.path().join(".claude").join("hooks");

        write_shell_scripts(&hooks_dir, "codegraph-mcp").unwrap();

        for hook in HOOK_SCRIPTS {
            let path = hooks_dir.join(hook.filename);
            assert!(path.exists(), "missing: {}", hook.filename);

            let content = fs::read_to_string(&path).unwrap();
            assert!(content.starts_with("#!/usr/bin/env bash"));
            assert!(content.contains(hook.subcommand));
            assert!(content.contains("codegraph-mcp"));

            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755, "wrong permissions on {}", hook.filename);
        }
    }

    #[test]
    fn shell_scripts_use_custom_binary_path() {
        let tmp = TempDir::new().unwrap();
        let hooks_dir = tmp.path().join("hooks");

        write_shell_scripts(&hooks_dir, "/opt/bin/codegraph-mcp").unwrap();

        let content = fs::read_to_string(hooks_dir.join("session-start.sh")).unwrap();
        assert!(content.contains("/opt/bin/codegraph-mcp"));
    }

    // -- merge_object_key tests -------------------------------------------

    #[test]
    fn merge_into_empty_object() {
        let mut root = json!({});
        merge_object_key(&mut root, "hooks", json!({"A": 1}));
        assert_eq!(root, json!({"hooks": {"A": 1}}));
    }

    #[test]
    fn merge_preserves_existing_keys() {
        let mut root = json!({"hooks": {"Existing": true}, "other": 42});
        merge_object_key(&mut root, "hooks", json!({"New": false}));

        assert_eq!(root["hooks"]["Existing"], json!(true));
        assert_eq!(root["hooks"]["New"], json!(false));
        assert_eq!(root["other"], json!(42));
    }

    #[test]
    fn merge_overwrites_colliding_keys() {
        let mut root = json!({"hooks": {"A": "old"}});
        merge_object_key(&mut root, "hooks", json!({"A": "new"}));

        assert_eq!(root["hooks"]["A"], json!("new"));
    }

    #[test]
    fn merge_replaces_non_object_value() {
        let mut root = json!({"hooks": "not an object"});
        merge_object_key(&mut root, "hooks", json!({"A": 1}));

        assert_eq!(root["hooks"], json!({"A": 1}));
    }

    // -- settings.json merge tests ----------------------------------------

    #[test]
    fn settings_created_from_scratch() {
        let tmp = TempDir::new().unwrap();
        let settings = tmp.path().join(".claude").join("settings.json");

        merge_settings(&settings).unwrap();

        let parsed: Value = serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
        assert!(parsed["hooks"]["SessionStart"].is_array());
        assert!(parsed["hooks"]["UserPromptSubmit"].is_array());
        assert!(parsed["hooks"]["PreCompact"].is_array());
        assert!(parsed["hooks"]["PostToolUse"].is_array());
    }

    #[test]
    fn settings_preserves_unrelated_keys() {
        let tmp = TempDir::new().unwrap();
        let claude_dir = tmp.path().join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let settings = claude_dir.join("settings.json");
        fs::write(
            &settings,
            serde_json::to_string_pretty(&json!({
                "theme": "dark",
                "hooks": {
                    "Custom": [{"hooks": [{"type": "command", "command": "echo hi"}]}]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        merge_settings(&settings).unwrap();

        let parsed: Value = serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(parsed["theme"], json!("dark"));
        assert!(parsed["hooks"]["Custom"].is_array(), "Custom hook preserved");
        assert!(parsed["hooks"]["SessionStart"].is_array(), "SessionStart added");
    }

    // -- .mcp.json merge tests --------------------------------------------

    #[test]
    fn mcp_config_created_from_scratch() {
        let tmp = TempDir::new().unwrap();
        let mcp = tmp.path().join(".mcp.json");

        merge_mcp_config(&mcp, "codegraph-mcp").unwrap();

        let parsed: Value = serde_json::from_str(&fs::read_to_string(&mcp).unwrap()).unwrap();
        let cg = &parsed["mcpServers"]["codegraph"];
        assert_eq!(cg["command"], json!("codegraph-mcp"));
        assert_eq!(cg["args"], json!(["serve"]));
        assert_eq!(cg["env"]["CODEGRAPH_DB"], json!(".codegraph/codegraph.db"));
    }

    #[test]
    fn mcp_config_preserves_other_servers() {
        let tmp = TempDir::new().unwrap();
        let mcp = tmp.path().join(".mcp.json");
        fs::write(
            &mcp,
            serde_json::to_string_pretty(&json!({
                "mcpServers": {
                    "other-tool": {
                        "command": "other-bin",
                        "args": ["run"]
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        merge_mcp_config(&mcp, "codegraph-mcp").unwrap();

        let parsed: Value = serde_json::from_str(&fs::read_to_string(&mcp).unwrap()).unwrap();
        assert!(parsed["mcpServers"]["other-tool"].is_object(), "other-tool preserved");
        assert!(parsed["mcpServers"]["codegraph"].is_object(), "codegraph added");
    }

    // -- Full integration test --------------------------------------------

    #[test]
    fn install_hooks_end_to_end() {
        let tmp = TempDir::new().unwrap();

        install_hooks(tmp.path(), "codegraph-mcp").unwrap();

        // Shell scripts exist
        let hooks_dir = tmp.path().join(".claude").join("hooks");
        assert!(hooks_dir.join("session-start.sh").exists());
        assert!(hooks_dir.join("prompt-submit.sh").exists());
        assert!(hooks_dir.join("pre-compact.sh").exists());
        assert!(hooks_dir.join("post-tool-use.sh").exists());

        // settings.json has hooks
        let settings: Value = serde_json::from_str(
            &fs::read_to_string(tmp.path().join(".claude").join("settings.json")).unwrap(),
        )
        .unwrap();
        assert!(settings["hooks"]["SessionStart"].is_array());
        assert!(settings["hooks"]["PostToolUse"][0]["matcher"] == "Write|Edit");

        // .mcp.json has codegraph server
        let mcp: Value = serde_json::from_str(
            &fs::read_to_string(tmp.path().join(".mcp.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(mcp["mcpServers"]["codegraph"]["command"], "codegraph-mcp");
    }

    #[test]
    fn install_hooks_is_idempotent() {
        let tmp = TempDir::new().unwrap();

        install_hooks(tmp.path(), "codegraph-mcp").unwrap();
        install_hooks(tmp.path(), "codegraph-mcp").unwrap();

        let settings: Value = serde_json::from_str(
            &fs::read_to_string(tmp.path().join(".claude").join("settings.json")).unwrap(),
        )
        .unwrap();

        // SessionStart should still be an array with exactly one entry (not duplicated)
        assert_eq!(settings["hooks"]["SessionStart"].as_array().unwrap().len(), 1);
    }
}
