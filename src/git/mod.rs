//! Git integration module — blame, history, contributors, hotspots.
//!
//! Uses `std::process::Command` to call git CLI (no git2 dependency).
//! All functions take a `repo_path` and return `Result<T, CodeGraphError>`.

pub mod analysis;
pub mod blame;
pub mod history;

use serde::Serialize;
use std::path::Path;
use std::process::Command;

use crate::error::CodeGraphError;

// ── Data types ──────────────────────────────────────────────────────────

/// A single line from `git blame --porcelain`.
#[derive(Debug, Clone, Serialize)]
pub struct BlameLine {
    pub line_number: usize,
    pub commit_hash: String,
    pub author: String,
    pub email: String,
    pub date: String,
    pub content: String,
}

/// Metadata for a single commit.
#[derive(Debug, Clone, Serialize)]
pub struct CommitInfo {
    pub hash: String,
    pub author: String,
    pub email: String,
    pub date: String,
    pub message: String,
    pub files_changed: Vec<String>,
}

/// Structured diff for a single commit.
#[derive(Debug, Clone, Serialize)]
pub struct DiffInfo {
    pub commit: String,
    pub files: Vec<FileDiff>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FileDiff {
    pub path: String,
    pub additions: usize,
    pub deletions: usize,
    pub patch: String,
}

/// Branch status information.
#[derive(Debug, Clone, Serialize)]
pub struct BranchInfo {
    pub current: String,
    pub tracking: Option<String>,
    pub ahead: usize,
    pub behind: usize,
    pub status: String,
}

/// Working-tree file status.
#[derive(Debug, Clone, Serialize)]
pub struct ModifiedFiles {
    pub staged: Vec<String>,
    pub unstaged: Vec<String>,
    pub untracked: Vec<String>,
}

/// A file that changes frequently.
#[derive(Debug, Clone, Serialize)]
pub struct Hotspot {
    pub file: String,
    pub commit_count: usize,
    pub last_modified: String,
    pub score: f64,
}

/// A contributor to the repository.
#[derive(Debug, Clone, Serialize)]
pub struct Contributor {
    pub name: String,
    pub email: String,
    pub commits: usize,
    pub lines_added: usize,
    pub lines_removed: usize,
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Validate user-supplied input to prevent git argument injection.
pub(crate) fn validate_input(input: &str, name: &str) -> Result<(), CodeGraphError> {
    if input.starts_with('-') {
        return Err(CodeGraphError::Other(format!(
            "Invalid {name}: cannot start with '-'"
        )));
    }
    if input.contains('\0') {
        return Err(CodeGraphError::Other(format!(
            "Invalid {name}: cannot contain null bytes"
        )));
    }
    Ok(())
}

/// Run a git command in `repo_path`, returning stdout on success.
pub(crate) fn run_git(repo_path: &Path, args: &[&str]) -> Result<String, CodeGraphError> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_path)
        .output()
        .map_err(|e| CodeGraphError::Other(format!("Failed to run git: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CodeGraphError::Other(format!(
            "git {} failed: {}",
            args.first().unwrap_or(&""),
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Verify that `repo_path` is inside a git repository.
pub(crate) fn ensure_git_repo(repo_path: &Path) -> Result<(), CodeGraphError> {
    run_git(repo_path, &["rev-parse", "--git-dir"])?;
    Ok(())
}

// Re-export all public functions for convenient access.
pub use analysis::{contributors, hotspots};
pub use blame::git_blame;
pub use history::{
    branch_info, commit_diff, file_history, modified_files, recent_changes, symbol_history,
};
