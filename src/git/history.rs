//! Git history — file history, recent changes, commit diff, symbol history,
//! branch info, modified files.

use std::path::Path;

use super::{run_git, validate_input, BranchInfo, CommitInfo, DiffInfo, FileDiff, ModifiedFiles};
use crate::error::CodeGraphError;

// ── Commit log format shared by several functions ───────────────────────

const LOG_FORMAT: &str = "%H|%an|%ae|%aI|%s";

/// Parse `git log --format=<LOG_FORMAT> --name-only` output into `CommitInfo`.
fn parse_log_with_files(output: &str) -> Vec<CommitInfo> {
    let mut commits = Vec::new();
    let mut current: Option<CommitInfo> = None;

    for line in output.lines() {
        if line.is_empty() {
            continue;
        }
        // A commit line has at least 40 hex chars followed by '|'
        if line.len() > 41
            && line.as_bytes()[40] == b'|'
            && line[..40].bytes().all(|b| b.is_ascii_hexdigit())
        {
            if let Some(c) = current.take() {
                commits.push(c);
            }
            let parts: Vec<&str> = line.splitn(5, '|').collect();
            if parts.len() == 5 {
                current = Some(CommitInfo {
                    hash: parts[0].to_string(),
                    author: parts[1].to_string(),
                    email: parts[2].to_string(),
                    date: parts[3].to_string(),
                    message: parts[4].to_string(),
                    files_changed: Vec::new(),
                });
            }
        } else if let Some(ref mut c) = current {
            // This is a filename from --name-only
            c.files_changed.push(line.to_string());
        }
    }
    if let Some(c) = current {
        commits.push(c);
    }
    commits
}

// ── Public API ──────────────────────────────────────────────────────────

/// Get the commit history for a specific file, newest first.
pub fn file_history(
    repo_path: &Path,
    file: &str,
    limit: usize,
) -> Result<Vec<CommitInfo>, CodeGraphError> {
    validate_input(file, "file_path")?;

    let limit_str = format!("-{limit}");
    let output = run_git(
        repo_path,
        &[
            "log",
            &format!("--format={LOG_FORMAT}"),
            "--name-only",
            &limit_str,
            "--",
            file,
        ],
    )?;

    Ok(parse_log_with_files(&output))
}

/// Get the most recent commits across the entire repository.
pub fn recent_changes(repo_path: &Path, limit: usize) -> Result<Vec<CommitInfo>, CodeGraphError> {
    let limit_str = format!("-{limit}");
    let output = run_git(
        repo_path,
        &[
            "log",
            &format!("--format={LOG_FORMAT}"),
            "--name-only",
            &limit_str,
        ],
    )?;

    Ok(parse_log_with_files(&output))
}

/// Get the diff for a specific commit, with per-file addition/deletion counts.
pub fn commit_diff(repo_path: &Path, commit_hash: &str) -> Result<DiffInfo, CodeGraphError> {
    validate_input(commit_hash, "commit_hash")?;

    // Get the stat summary
    let stat_output = run_git(
        repo_path,
        &[
            "diff-tree",
            "--no-commit-id",
            "--numstat",
            "-r",
            commit_hash,
        ],
    )?;

    // Get the full patch
    let patch_output = run_git(
        repo_path,
        &["diff-tree", "--no-commit-id", "-p", commit_hash],
    )?;

    // Parse numstat lines: "added\tremoved\tfile"
    let mut files = Vec::new();
    for line in stat_output.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 3 {
            let additions = parts[0].parse().unwrap_or(0);
            let deletions = parts[1].parse().unwrap_or(0);
            let path = parts[2].to_string();

            // Extract the patch section for this file from the full patch
            let file_patch = extract_file_patch(&patch_output, &path);

            files.push(FileDiff {
                path,
                additions,
                deletions,
                patch: file_patch,
            });
        }
    }

    Ok(DiffInfo {
        commit: commit_hash.to_string(),
        files,
    })
}

/// Extract the unified diff hunk for a single file from a full patch.
fn extract_file_patch(full_patch: &str, file_path: &str) -> String {
    let mut collecting = false;
    let mut patch = String::new();
    let marker = format!("diff --git a/{file_path}");

    for line in full_patch.lines() {
        if line.starts_with("diff --git ") {
            if collecting {
                break; // hit the next file
            }
            if line.starts_with(&marker) {
                collecting = true;
            }
        }
        if collecting {
            patch.push_str(line);
            patch.push('\n');
        }
    }
    patch
}

/// Find commits that added or removed `symbol_name` (via `git log -S`).
///
/// Searches across common source-code extensions.
pub fn symbol_history(
    repo_path: &Path,
    symbol_name: &str,
) -> Result<Vec<CommitInfo>, CodeGraphError> {
    validate_input(symbol_name, "symbol_name")?;

    let s_flag = format!("-S{symbol_name}");
    let output = run_git(
        repo_path,
        &[
            "log",
            &format!("--format={LOG_FORMAT}"),
            "--name-only",
            &s_flag,
            "--",
            "*.rs",
            "*.ts",
            "*.tsx",
            "*.js",
            "*.jsx",
            "*.py",
            "*.go",
            "*.java",
            "*.c",
            "*.cpp",
            "*.h",
            "*.cs",
            "*.php",
            "*.rb",
            "*.swift",
            "*.kt",
        ],
    )?;

    Ok(parse_log_with_files(&output))
}

/// Get current branch name, tracking remote, and ahead/behind counts.
pub fn branch_info(repo_path: &Path) -> Result<BranchInfo, CodeGraphError> {
    // Current branch name
    let current = run_git(repo_path, &["branch", "--show-current"])?
        .trim()
        .to_string();

    let current_display = if current.is_empty() {
        "HEAD (detached)".to_string()
    } else {
        current.clone()
    };

    // Try to get tracking info
    let tracking_result = run_git(
        repo_path,
        &[
            "rev-parse",
            "--abbrev-ref",
            &format!("{current}@{{upstream}}"),
        ],
    );

    let (tracking, ahead, behind) = match tracking_result {
        Ok(upstream) => {
            let upstream = upstream.trim().to_string();
            // Get ahead/behind counts
            let ab = run_git(
                repo_path,
                &[
                    "rev-list",
                    "--left-right",
                    "--count",
                    &format!("{current}...{upstream}"),
                ],
            )
            .unwrap_or_default();
            let parts: Vec<&str> = ab.trim().split('\t').collect();
            let ahead = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
            let behind = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
            (Some(upstream), ahead, behind)
        }
        Err(_) => (None, 0, 0),
    };

    let status = match (ahead, behind) {
        (0, 0) => "up-to-date".to_string(),
        (a, 0) => format!("ahead {a}"),
        (0, b) => format!("behind {b}"),
        (a, b) => format!("ahead {a}, behind {b}"),
    };

    Ok(BranchInfo {
        current: current_display,
        tracking,
        ahead,
        behind,
        status,
    })
}

/// Get staged, unstaged, and untracked files from the working tree.
pub fn modified_files(repo_path: &Path) -> Result<ModifiedFiles, CodeGraphError> {
    let output = run_git(repo_path, &["status", "--porcelain"])?;

    let mut staged = Vec::new();
    let mut unstaged = Vec::new();
    let mut untracked = Vec::new();

    for line in output.lines() {
        if line.len() < 4 {
            continue;
        }
        let index_status = line.as_bytes()[0];
        let worktree_status = line.as_bytes()[1];
        let file = line[3..].to_string();

        if index_status == b'?' && worktree_status == b'?' {
            untracked.push(file);
        } else {
            // Staged changes: anything in the index column that isn't ' ' or '?'
            if index_status != b' ' && index_status != b'?' {
                staged.push(file.clone());
            }
            // Unstaged changes: anything in the worktree column that isn't ' ' or '?'
            if worktree_status != b' ' && worktree_status != b'?' {
                unstaged.push(file);
            }
        }
    }

    Ok(ModifiedFiles {
        staged,
        unstaged,
        untracked,
    })
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Create a temporary git repo with a few commits for testing history.
    fn create_test_repo() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();

        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(&path)
                .env("GIT_AUTHOR_NAME", "Test Author")
                .env("GIT_AUTHOR_EMAIL", "test@example.com")
                .env("GIT_COMMITTER_NAME", "Test Author")
                .env("GIT_COMMITTER_EMAIL", "test@example.com")
                .output()
                .unwrap()
        };

        git(&["init"]);
        git(&["config", "user.email", "test@example.com"]);
        git(&["config", "user.name", "Test Author"]);

        // Commit 1
        std::fs::write(path.join("main.rs"), "fn main() {}\n").unwrap();
        git(&["add", "main.rs"]);
        git(&["commit", "-m", "first commit"]);

        // Commit 2
        std::fs::write(
            path.join("main.rs"),
            "fn main() {\n    println!(\"hi\");\n}\n",
        )
        .unwrap();
        std::fs::write(
            path.join("lib.rs"),
            "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
        )
        .unwrap();
        git(&["add", "main.rs", "lib.rs"]);
        git(&["commit", "-m", "add println and lib"]);

        // Commit 3
        std::fs::write(path.join("lib.rs"), "pub fn add(a: i32, b: i32) -> i32 { a + b }\npub fn sub(a: i32, b: i32) -> i32 { a - b }\n").unwrap();
        git(&["add", "lib.rs"]);
        git(&["commit", "-m", "add sub function"]);

        (dir, path)
    }

    // ── file_history ────────────────────────────────────────────────────

    #[test]
    fn test_file_history_basic() {
        let (_dir, path) = create_test_repo();
        let history = file_history(&path, "main.rs", 10).unwrap();

        assert_eq!(history.len(), 2);
        // Newest first
        assert_eq!(history[0].message, "add println and lib");
        assert_eq!(history[1].message, "first commit");
        assert_eq!(history[0].author, "Test Author");
        assert!(!history[0].hash.is_empty());
    }

    #[test]
    fn test_file_history_limit() {
        let (_dir, path) = create_test_repo();
        let history = file_history(&path, "main.rs", 1).unwrap();
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_file_history_nonexistent() {
        let (_dir, path) = create_test_repo();
        let history = file_history(&path, "nope.rs", 10).unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn test_file_history_injection() {
        let (_dir, path) = create_test_repo();
        assert!(file_history(&path, "--exec=rm", 10).is_err());
    }

    // ── recent_changes ──────────────────────────────────────────────────

    #[test]
    fn test_recent_changes() {
        let (_dir, path) = create_test_repo();
        let changes = recent_changes(&path, 10).unwrap();

        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].message, "add sub function");
    }

    #[test]
    fn test_recent_changes_limit() {
        let (_dir, path) = create_test_repo();
        let changes = recent_changes(&path, 2).unwrap();
        assert_eq!(changes.len(), 2);
    }

    // ── commit_diff ─────────────────────────────────────────────────────

    #[test]
    fn test_commit_diff() {
        let (_dir, path) = create_test_repo();
        let changes = recent_changes(&path, 1).unwrap();
        let hash = &changes[0].hash;

        let diff = commit_diff(&path, hash).unwrap();
        assert_eq!(diff.commit, *hash);
        assert!(!diff.files.is_empty());

        // The last commit touched lib.rs
        let lib_diff = diff.files.iter().find(|f| f.path == "lib.rs");
        assert!(lib_diff.is_some());
        let lib_diff = lib_diff.unwrap();
        assert!(lib_diff.additions > 0);
        assert!(!lib_diff.patch.is_empty());
    }

    #[test]
    fn test_commit_diff_injection() {
        let (_dir, path) = create_test_repo();
        assert!(commit_diff(&path, "--exec=id").is_err());
    }

    #[test]
    fn test_commit_diff_invalid_hash() {
        let (_dir, path) = create_test_repo();
        assert!(commit_diff(&path, "0000000000000000000000000000000000000000").is_err());
    }

    // ── symbol_history ──────────────────────────────────────────────────

    #[test]
    fn test_symbol_history() {
        let (_dir, path) = create_test_repo();
        let history = symbol_history(&path, "sub").unwrap();

        // "sub" was added in the last commit
        assert!(!history.is_empty());
        assert!(history.iter().any(|c| c.message.contains("sub")));
    }

    #[test]
    fn test_symbol_history_not_found() {
        let (_dir, path) = create_test_repo();
        let history = symbol_history(&path, "nonexistent_xyz_symbol").unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn test_symbol_history_injection() {
        let (_dir, path) = create_test_repo();
        assert!(symbol_history(&path, "--exec=id").is_err());
    }

    // ── branch_info ─────────────────────────────────────────────────────

    #[test]
    fn test_branch_info() {
        let (_dir, path) = create_test_repo();
        let info = branch_info(&path).unwrap();

        // Default branch is either "main" or "master" depending on git config
        assert!(
            info.current == "main" || info.current == "master",
            "Expected main or master, got: {}",
            info.current
        );
        // No remote tracking in a local-only repo
        assert!(info.tracking.is_none());
        assert_eq!(info.ahead, 0);
        assert_eq!(info.behind, 0);
    }

    // ── modified_files ──────────────────────────────────────────────────

    #[test]
    fn test_modified_files_clean() {
        let (_dir, path) = create_test_repo();
        let mods = modified_files(&path).unwrap();

        assert!(mods.staged.is_empty());
        assert!(mods.unstaged.is_empty());
        assert!(mods.untracked.is_empty());
    }

    #[test]
    fn test_modified_files_untracked() {
        let (_dir, path) = create_test_repo();
        std::fs::write(path.join("new_file.txt"), "hello").unwrap();

        let mods = modified_files(&path).unwrap();
        assert!(mods.untracked.contains(&"new_file.txt".to_string()));
    }

    #[test]
    fn test_modified_files_staged() {
        let (_dir, path) = create_test_repo();
        std::fs::write(path.join("staged.txt"), "staged content").unwrap();
        std::process::Command::new("git")
            .args(["add", "staged.txt"])
            .current_dir(&path)
            .output()
            .unwrap();

        let mods = modified_files(&path).unwrap();
        assert!(mods.staged.contains(&"staged.txt".to_string()));
    }

    #[test]
    fn test_modified_files_unstaged() {
        let (_dir, path) = create_test_repo();
        // Modify an already-tracked file without staging
        std::fs::write(path.join("main.rs"), "fn main() { /* changed */ }\n").unwrap();

        let mods = modified_files(&path).unwrap();
        assert!(mods.unstaged.contains(&"main.rs".to_string()));
    }

    // ── parse_log_with_files ────────────────────────────────────────────

    #[test]
    fn test_parse_log_empty() {
        let result = parse_log_with_files("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_files_changed_populated() {
        let (_dir, path) = create_test_repo();
        let changes = recent_changes(&path, 1).unwrap();
        // Last commit touched lib.rs
        assert!(changes[0].files_changed.contains(&"lib.rs".to_string()));
    }
}
