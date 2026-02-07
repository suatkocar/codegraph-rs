//! Git analysis — hotspots (high-churn files) and contributors.

use std::collections::HashMap;
use std::path::Path;

use super::{run_git, validate_input, Contributor, Hotspot};
use crate::error::CodeGraphError;

/// Identify files with the highest commit frequency ("hotspots").
///
/// Returns up to `limit` files sorted by descending commit count. The `score`
/// is a normalized value (0.0–1.0) relative to the busiest file.
pub fn hotspots(repo_path: &Path, limit: usize) -> Result<Vec<Hotspot>, CodeGraphError> {
    // Get every file touched by every commit (name-only), plus the commit date
    let output = run_git(repo_path, &["log", "--format=COMMIT|%aI", "--name-only"])?;

    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut last_modified: HashMap<String, String> = HashMap::new();
    let mut current_date = String::new();

    for line in output.lines() {
        if line.is_empty() {
            continue;
        }
        if let Some(date) = line.strip_prefix("COMMIT|") {
            current_date = date.to_string();
        } else {
            // It's a filename
            *counts.entry(line.to_string()).or_default() += 1;
            last_modified
                .entry(line.to_string())
                .or_insert_with(|| current_date.clone());
        }
    }

    if counts.is_empty() {
        return Ok(Vec::new());
    }

    let max_count = *counts.values().max().unwrap_or(&1) as f64;

    let mut hotspots: Vec<Hotspot> = counts
        .into_iter()
        .map(|(file, commit_count)| {
            let lm = last_modified.get(&file).cloned().unwrap_or_default();
            let score = commit_count as f64 / max_count;
            Hotspot {
                file,
                commit_count,
                last_modified: lm,
                score,
            }
        })
        .collect();

    hotspots.sort_by(|a, b| b.commit_count.cmp(&a.commit_count));
    hotspots.truncate(limit);

    Ok(hotspots)
}

/// Get contributor statistics for the repository, or for a specific file.
///
/// When `file` is `Some`, results are scoped to commits that touched that file.
/// Returns contributors sorted by commit count (descending).
pub fn contributors(
    repo_path: &Path,
    file: Option<&str>,
) -> Result<Vec<Contributor>, CodeGraphError> {
    if let Some(f) = file {
        validate_input(f, "file_path")?;
    }

    // Use shortlog for commit counts + names + emails
    let mut shortlog_args = vec!["shortlog", "-sne", "HEAD"];
    if let Some(f) = file {
        shortlog_args.push("--");
        shortlog_args.push(f);
    }
    let shortlog_output = run_git(repo_path, &shortlog_args)?;

    // Build base contributor list from shortlog
    let mut contribs: Vec<Contributor> = Vec::new();
    for line in shortlog_output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Format: "  123\tName <email>"
        let parts: Vec<&str> = trimmed.splitn(2, '\t').collect();
        if parts.len() != 2 {
            continue;
        }
        let commits: usize = parts[0].trim().parse().unwrap_or(0);
        let name_email = parts[1].trim();

        // Parse "Name <email>"
        let (name, email) = if let Some(lt) = name_email.rfind('<') {
            let name = name_email[..lt].trim().to_string();
            let email = name_email[lt + 1..]
                .trim_end_matches('>')
                .trim()
                .to_string();
            (name, email)
        } else {
            (name_email.to_string(), String::new())
        };

        contribs.push(Contributor {
            name,
            email,
            commits,
            lines_added: 0,
            lines_removed: 0,
        });
    }

    // Enrich with lines added/removed via git log --author --numstat
    // We do this per contributor to get accurate per-author stats.
    for contrib in &mut contribs {
        let author_filter = format!("--author={}", contrib.email);
        let mut log_args = vec!["log", &author_filter, "--numstat", "--format="];
        if let Some(f) = file {
            log_args.push("--");
            log_args.push(f);
        }
        if let Ok(log_output) = run_git(repo_path, &log_args) {
            let (added, removed) = parse_numstat_totals(&log_output);
            contrib.lines_added = added;
            contrib.lines_removed = removed;
        }
    }

    // Already sorted by commit count from shortlog (descending)
    Ok(contribs)
}

/// Sum the additions and deletions from `--numstat` output lines.
fn parse_numstat_totals(output: &str) -> (usize, usize) {
    let mut added = 0usize;
    let mut removed = 0usize;
    for line in output.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 2 {
            added += parts[0].parse::<usize>().unwrap_or(0);
            removed += parts[1].parse::<usize>().unwrap_or(0);
        }
    }
    (added, removed)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn create_test_repo() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();

        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(&path)
                .env("GIT_AUTHOR_NAME", "Alice")
                .env("GIT_AUTHOR_EMAIL", "alice@example.com")
                .env("GIT_COMMITTER_NAME", "Alice")
                .env("GIT_COMMITTER_EMAIL", "alice@example.com")
                .output()
                .unwrap()
        };

        let git_as = |args: &[&str], name: &str, email: &str| {
            std::process::Command::new("git")
                .args(args)
                .current_dir(&path)
                .env("GIT_AUTHOR_NAME", name)
                .env("GIT_AUTHOR_EMAIL", email)
                .env("GIT_COMMITTER_NAME", name)
                .env("GIT_COMMITTER_EMAIL", email)
                .output()
                .unwrap()
        };

        git(&["init"]);
        git(&["config", "user.email", "alice@example.com"]);
        git(&["config", "user.name", "Alice"]);

        // Alice: commit 1
        std::fs::write(path.join("app.rs"), "fn main() {}\n").unwrap();
        git(&["add", "app.rs"]);
        git(&["commit", "-m", "initial"]);

        // Alice: commit 2
        std::fs::write(path.join("app.rs"), "fn main() {\n    run();\n}\n").unwrap();
        git(&["add", "app.rs"]);
        git(&["commit", "-m", "add run call"]);

        // Bob: commit 3
        std::fs::write(path.join("lib.rs"), "pub fn helper() {}\n").unwrap();
        std::process::Command::new("git")
            .args(["add", "lib.rs"])
            .current_dir(&path)
            .output()
            .unwrap();
        git_as(
            &["commit", "-m", "bob adds helper"],
            "Bob",
            "bob@example.com",
        );

        // Alice: commit 4 — touch app.rs again
        std::fs::write(
            path.join("app.rs"),
            "fn main() {\n    run();\n    helper();\n}\n",
        )
        .unwrap();
        git(&["add", "app.rs"]);
        git(&["commit", "-m", "call helper from main"]);

        (dir, path)
    }

    // ── hotspots ────────────────────────────────────────────────────────

    #[test]
    fn test_hotspots_basic() {
        let (_dir, path) = create_test_repo();
        let hs = hotspots(&path, 10).unwrap();

        assert!(!hs.is_empty());
        // app.rs was touched 3 times, lib.rs once → app.rs should be #1
        assert_eq!(hs[0].file, "app.rs");
        assert_eq!(hs[0].commit_count, 3);
        assert!((hs[0].score - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_hotspots_limit() {
        let (_dir, path) = create_test_repo();
        let hs = hotspots(&path, 1).unwrap();
        assert_eq!(hs.len(), 1);
    }

    #[test]
    fn test_hotspots_scores_normalized() {
        let (_dir, path) = create_test_repo();
        let hs = hotspots(&path, 10).unwrap();
        for h in &hs {
            assert!(h.score > 0.0 && h.score <= 1.0);
        }
    }

    #[test]
    fn test_hotspots_last_modified_set() {
        let (_dir, path) = create_test_repo();
        let hs = hotspots(&path, 10).unwrap();
        for h in &hs {
            assert!(
                !h.last_modified.is_empty(),
                "last_modified should be set for {}",
                h.file
            );
        }
    }

    #[test]
    fn test_hotspots_empty_repo() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_path_buf();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(&path)
            .output()
            .unwrap();
        // No commits → hotspots should fail or return empty
        // git log on an empty repo fails, which is fine
        let result = hotspots(&path, 10);
        assert!(result.is_err() || result.unwrap().is_empty());
    }

    // ── contributors ────────────────────────────────────────────────────

    #[test]
    fn test_contributors_repo_level() {
        let (_dir, path) = create_test_repo();
        let contribs = contributors(&path, None).unwrap();

        assert_eq!(contribs.len(), 2);
        // Alice has 3 commits, Bob has 1
        let alice = contribs.iter().find(|c| c.name == "Alice").unwrap();
        let bob = contribs.iter().find(|c| c.name == "Bob").unwrap();
        assert_eq!(alice.commits, 3);
        assert_eq!(bob.commits, 1);
        assert_eq!(alice.email, "alice@example.com");
        assert_eq!(bob.email, "bob@example.com");
    }

    #[test]
    fn test_contributors_file_scoped() {
        let (_dir, path) = create_test_repo();
        let contribs = contributors(&path, Some("app.rs")).unwrap();

        // Only Alice touched app.rs
        assert_eq!(contribs.len(), 1);
        assert_eq!(contribs[0].name, "Alice");
        assert_eq!(contribs[0].commits, 3);
    }

    #[test]
    fn test_contributors_lines_counted() {
        let (_dir, path) = create_test_repo();
        let contribs = contributors(&path, None).unwrap();

        let alice = contribs.iter().find(|c| c.name == "Alice").unwrap();
        assert!(alice.lines_added > 0);
    }

    #[test]
    fn test_contributors_file_injection() {
        let (_dir, path) = create_test_repo();
        assert!(contributors(&path, Some("--exec=id")).is_err());
    }

    #[test]
    fn test_contributors_nonexistent_file() {
        let (_dir, path) = create_test_repo();
        let contribs = contributors(&path, Some("nonexistent.rs")).unwrap();
        assert!(contribs.is_empty());
    }

    // ── parse_numstat_totals ────────────────────────────────────────────

    #[test]
    fn test_parse_numstat_totals() {
        let input = "10\t5\tfile1.rs\n3\t2\tfile2.rs\n";
        let (added, removed) = parse_numstat_totals(input);
        assert_eq!(added, 13);
        assert_eq!(removed, 7);
    }

    #[test]
    fn test_parse_numstat_totals_empty() {
        let (added, removed) = parse_numstat_totals("");
        assert_eq!(added, 0);
        assert_eq!(removed, 0);
    }

    #[test]
    fn test_parse_numstat_binary() {
        // Binary files show as "-\t-\tfilename"
        let input = "-\t-\tbinary.png\n5\t3\tcode.rs\n";
        let (added, removed) = parse_numstat_totals(input);
        assert_eq!(added, 5);
        assert_eq!(removed, 3);
    }
}
