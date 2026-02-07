//! Interactive installer for CodeGraph — beautiful UX for `codegraph init`.

use console::style;
use dialoguer::Confirm;
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// Print the CodeGraph ASCII art banner.
pub fn print_banner() {
    let banner = r#"
   ██████╗ ██████╗ ██████╗ ███████╗ ██████╗ ██████╗  █████╗ ██████╗ ██╗  ██╗
  ██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██║  ██║
  ██║     ██║   ██║██║  ██║█████╗  ██║  ███╗██████╔╝███████║██████╔╝███████║
  ██║     ██║   ██║██║  ██║██╔══╝  ██║   ██║██╔══██╗██╔══██║██╔═══╝ ██╔══██║
  ╚██████╗╚██████╔╝██████╔╝███████╗╚██████╔╝██║  ██║██║  ██║██║     ██║  ██║
   ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝
"#;

    println!("{}", style(banner).cyan().bold());
    println!(
        "  {} {} {}",
        style("Codebase Intelligence").white().bold(),
        style("·").dim(),
        style("Native Rust · 32 Languages · 44 MCP Tools").dim()
    );
    println!();
}

/// Create a styled progress bar for indexing.
pub fn create_indexing_progress(total: u64) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  {spinner:.cyan} [{bar:40.cyan/dim}] {pos}/{len} files {msg}")
            .unwrap()
            .progress_chars("█▓░"),
    );
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

/// Create a spinner for indeterminate operations.
pub fn create_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("  {spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(80));
    pb
}

/// Ask for confirmation (returns true if --yes flag or user confirms).
pub fn confirm(message: &str, non_interactive: bool) -> bool {
    if non_interactive {
        return true;
    }
    Confirm::new()
        .with_prompt(message)
        .default(true)
        .interact()
        .unwrap_or(true)
}

/// Print the post-init summary.
pub fn print_summary(
    files: usize,
    nodes: usize,
    edges: usize,
    hooks: bool,
    mcp: bool,
    claude_md: bool,
    git_hook: bool,
) {
    println!();
    println!("  {}", style("Setup complete!").green().bold());
    println!();
    if files > 0 {
        println!(
            "  {} Indexed {} files ({} symbols, {} relationships)",
            style("✓").green(),
            files,
            nodes,
            edges
        );
    }
    if hooks {
        println!("  {} Installed 10 Claude Code hooks", style("✓").green());
    }
    if mcp {
        println!("  {} Registered MCP server", style("✓").green());
    }
    if claude_md {
        println!("  {} Generated CLAUDE.md", style("✓").green());
    }
    if git_hook {
        println!("  {} Installed git post-commit hook", style("✓").green());
    }
    println!();
    println!(
        "  {} Open Claude Code — your project is now graph-aware.",
        style("→").cyan().bold()
    );
    println!();
}

/// Detect project info and print it.
pub fn print_project_detection(dir: &str, languages: &[(String, usize)], frameworks: &[String]) {
    println!("  {} {}", style("Project:").bold(), dir);
    if !languages.is_empty() {
        let lang_str: Vec<String> = languages
            .iter()
            .take(5)
            .map(|(l, c)| format!("{} ({})", l, c))
            .collect();
        println!("  {} {}", style("Languages:").bold(), lang_str.join(", "));
    }
    if !frameworks.is_empty() {
        println!(
            "  {} {}",
            style("Frameworks:").bold(),
            frameworks.join(", ")
        );
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_does_not_panic() {
        // Smoke test: calling print_banner should not panic.
        print_banner();
    }

    #[test]
    fn create_spinner_does_not_panic() {
        let pb = create_spinner("testing...");
        pb.finish_and_clear();
    }

    #[test]
    fn create_indexing_progress_does_not_panic() {
        let pb = create_indexing_progress(10);
        pb.inc(1);
        pb.finish_and_clear();
    }

    #[test]
    fn confirm_non_interactive_returns_true() {
        assert!(confirm("test?", true));
    }

    #[test]
    fn print_summary_does_not_panic() {
        print_summary(10, 50, 30, true, true, true, true);
    }

    #[test]
    fn print_summary_partial_does_not_panic() {
        print_summary(0, 0, 0, false, false, false, false);
    }

    #[test]
    fn print_project_detection_does_not_panic() {
        let langs = vec![("Rust".to_string(), 5), ("Python".to_string(), 3)];
        let frameworks = vec!["tokio".to_string(), "clap".to_string()];
        print_project_detection("/tmp/test", &langs, &frameworks);
    }

    #[test]
    fn print_project_detection_empty() {
        print_project_detection("/tmp/empty", &[], &[]);
    }
}
