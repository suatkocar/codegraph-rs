//! Git hook integration — installs a `post-commit` hook that triggers
//! incremental re-indexing after every commit.
//!
//! The hook runs `codegraph index <project_dir>` in the background so
//! it never slows down the commit workflow. Installation is additive: if a
//! `post-commit` hook already exists, the codegraph line is appended.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::error::Result;

/// Marker comment embedded in the hook script so we can find (and remove)
/// our line without disturbing user-written hooks.
const MARKER: &str = "# codegraph-auto-index";

/// Check whether `project_dir` is (or is inside) a git repository.
pub fn is_git_repo(project_dir: &str) -> bool {
    Path::new(project_dir).join(".git").is_dir()
}

/// Install a `post-commit` hook that re-indexes the project in the background.
///
/// - If `.git/hooks/post-commit` does not exist, a new script is created.
/// - If it exists but does not contain our marker, the codegraph line is appended.
/// - If it already contains our marker, the file is left untouched (idempotent).
///
/// The hook invokes `codegraph index <project_dir>` with stderr redirected
/// to `/dev/null` and backgrounded (`&`) so the commit returns immediately.
pub fn install_git_post_commit_hook(project_dir: &str) -> Result<()> {
    let root = Path::new(project_dir);
    let hooks_dir = root.join(".git").join("hooks");

    if !root.join(".git").is_dir() {
        return Err(crate::error::CodeGraphError::Other(format!(
            "Not a git repository: {}",
            project_dir
        )));
    }

    fs::create_dir_all(&hooks_dir)?;

    let hook_path = hooks_dir.join("post-commit");
    let codegraph_line = format!("{MARKER}\ncodegraph index {project_dir} 2>/dev/null &");

    if hook_path.exists() {
        let content = fs::read_to_string(&hook_path)?;

        // Already installed — nothing to do.
        if content.contains(MARKER) {
            eprintln!("[codegraph] post-commit hook already installed.");
            return Ok(());
        }

        // Append to existing hook.
        let updated = format!("{}\n\n{}\n", content.trim_end(), codegraph_line);
        fs::write(&hook_path, updated)?;
    } else {
        // Create a fresh hook script.
        let script = format!("#!/usr/bin/env bash\n\n{codegraph_line}\n");
        fs::write(&hook_path, script)?;
    }

    fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755))?;
    eprintln!(
        "[codegraph] Installed post-commit hook at {}",
        hook_path.display()
    );
    Ok(())
}

/// Remove the codegraph line from the `post-commit` hook.
///
/// If the hook contains only the shebang and our codegraph block, the file
/// is deleted entirely. Otherwise only the codegraph lines are stripped.
pub fn uninstall_git_post_commit_hook(project_dir: &str) -> Result<()> {
    let hook_path = Path::new(project_dir)
        .join(".git")
        .join("hooks")
        .join("post-commit");

    if !hook_path.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(&hook_path)?;
    if !content.contains(MARKER) {
        // Our hook isn't here — nothing to remove.
        return Ok(());
    }

    // Remove our marker line and the command line that follows it.
    let filtered: Vec<&str> = content
        .lines()
        .filter(|line| !line.contains(MARKER) && !line.contains("codegraph index"))
        .collect();

    // If only the shebang (or nothing) remains, delete the file.
    let meaningful: Vec<&&str> = filtered
        .iter()
        .filter(|l| !l.trim().is_empty() && !l.starts_with("#!"))
        .collect();

    if meaningful.is_empty() {
        fs::remove_file(&hook_path)?;
        eprintln!("[codegraph] Removed post-commit hook (file deleted).");
    } else {
        let cleaned = filtered.join("\n");
        fs::write(&hook_path, format!("{}\n", cleaned.trim_end()))?;
        eprintln!("[codegraph] Removed codegraph line from post-commit hook.");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: create a fake `.git` directory so `is_git_repo` returns true.
    fn make_git_dir(tmp: &TempDir) {
        fs::create_dir_all(tmp.path().join(".git").join("hooks")).unwrap();
    }

    #[test]
    fn is_git_repo_returns_true_when_dot_git_exists() {
        let tmp = TempDir::new().unwrap();
        make_git_dir(&tmp);
        assert!(is_git_repo(tmp.path().to_str().unwrap()));
    }

    #[test]
    fn is_git_repo_returns_false_when_no_dot_git() {
        let tmp = TempDir::new().unwrap();
        assert!(!is_git_repo(tmp.path().to_str().unwrap()));
    }

    #[test]
    fn install_creates_new_post_commit_hook() {
        let tmp = TempDir::new().unwrap();
        make_git_dir(&tmp);
        let dir = tmp.path().to_str().unwrap();

        install_git_post_commit_hook(dir).unwrap();

        let hook = tmp.path().join(".git/hooks/post-commit");
        assert!(hook.exists());

        let content = fs::read_to_string(&hook).unwrap();
        assert!(content.starts_with("#!/usr/bin/env bash"));
        assert!(content.contains(MARKER));
        assert!(content.contains("codegraph index"));
        assert!(content.contains("2>/dev/null &"));

        // Check executable permission.
        let mode = fs::metadata(&hook).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
    }

    #[test]
    fn install_appends_to_existing_hook() {
        let tmp = TempDir::new().unwrap();
        make_git_dir(&tmp);
        let dir = tmp.path().to_str().unwrap();

        let hook = tmp.path().join(".git/hooks/post-commit");
        fs::write(&hook, "#!/usr/bin/env bash\necho 'existing hook'\n").unwrap();

        install_git_post_commit_hook(dir).unwrap();

        let content = fs::read_to_string(&hook).unwrap();
        assert!(
            content.contains("echo 'existing hook'"),
            "existing content preserved"
        );
        assert!(content.contains(MARKER), "codegraph marker added");
        assert!(
            content.contains("codegraph index"),
            "codegraph command added"
        );
    }

    #[test]
    fn install_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        make_git_dir(&tmp);
        let dir = tmp.path().to_str().unwrap();

        install_git_post_commit_hook(dir).unwrap();
        install_git_post_commit_hook(dir).unwrap();

        let content = fs::read_to_string(tmp.path().join(".git/hooks/post-commit")).unwrap();
        let marker_count = content.matches(MARKER).count();
        assert_eq!(marker_count, 1, "marker should appear exactly once");
    }

    #[test]
    fn install_fails_when_not_a_git_repo() {
        let tmp = TempDir::new().unwrap();
        let result = install_git_post_commit_hook(tmp.path().to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn uninstall_removes_codegraph_line_from_mixed_hook() {
        let tmp = TempDir::new().unwrap();
        make_git_dir(&tmp);
        let dir = tmp.path().to_str().unwrap();

        // Start with an existing hook + our codegraph line.
        let hook = tmp.path().join(".git/hooks/post-commit");
        let content = format!(
            "#!/usr/bin/env bash\necho 'user stuff'\n\n{MARKER}\ncodegraph index {dir} 2>/dev/null &\n"
        );
        fs::write(&hook, content).unwrap();

        uninstall_git_post_commit_hook(dir).unwrap();

        let remaining = fs::read_to_string(&hook).unwrap();
        assert!(!remaining.contains(MARKER));
        assert!(!remaining.contains("codegraph index"));
        assert!(
            remaining.contains("echo 'user stuff'"),
            "user content preserved"
        );
    }

    #[test]
    fn uninstall_deletes_file_when_only_codegraph() {
        let tmp = TempDir::new().unwrap();
        make_git_dir(&tmp);
        let dir = tmp.path().to_str().unwrap();

        install_git_post_commit_hook(dir).unwrap();
        let hook = tmp.path().join(".git/hooks/post-commit");
        assert!(hook.exists());

        uninstall_git_post_commit_hook(dir).unwrap();
        assert!(!hook.exists(), "hook file should be deleted");
    }

    #[test]
    fn uninstall_is_noop_when_no_hook_file() {
        let tmp = TempDir::new().unwrap();
        make_git_dir(&tmp);
        // No post-commit file — should succeed silently.
        uninstall_git_post_commit_hook(tmp.path().to_str().unwrap()).unwrap();
    }

    #[test]
    fn uninstall_is_noop_when_hook_has_no_marker() {
        let tmp = TempDir::new().unwrap();
        make_git_dir(&tmp);

        let hook = tmp.path().join(".git/hooks/post-commit");
        fs::write(&hook, "#!/usr/bin/env bash\necho hello\n").unwrap();

        uninstall_git_post_commit_hook(tmp.path().to_str().unwrap()).unwrap();

        let content = fs::read_to_string(&hook).unwrap();
        assert!(content.contains("echo hello"), "file should be untouched");
    }
}
