//! Framework detection — scans project manifests to identify frameworks.
//!
//! Inspects dependency manifests (package.json, Cargo.toml, go.mod, etc.)
//! to detect which frameworks a project uses. Returns structured results
//! with name, version, confidence, language, and category.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A detected framework with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedFramework {
    pub name: String,
    pub version: Option<String>,
    pub confidence: f64,
    pub language: String,
    pub category: String,
}

// ---------------------------------------------------------------------------
// Framework definitions
// ---------------------------------------------------------------------------

struct FrameworkDef {
    name: &'static str,
    dep_key: &'static str,
    language: &'static str,
    category: &'static str,
    confidence: f64,
}

const JS_FRAMEWORKS: &[FrameworkDef] = &[
    FrameworkDef { name: "React", dep_key: "react", language: "javascript", category: "web", confidence: 0.95 },
    FrameworkDef { name: "Next.js", dep_key: "next", language: "javascript", category: "web", confidence: 0.95 },
    FrameworkDef { name: "Vue", dep_key: "vue", language: "javascript", category: "web", confidence: 0.95 },
    FrameworkDef { name: "Angular", dep_key: "@angular/core", language: "javascript", category: "web", confidence: 0.95 },
    FrameworkDef { name: "Express", dep_key: "express", language: "javascript", category: "api", confidence: 0.90 },
    FrameworkDef { name: "Svelte", dep_key: "svelte", language: "javascript", category: "web", confidence: 0.95 },
    FrameworkDef { name: "Nest.js", dep_key: "@nestjs/core", language: "javascript", category: "api", confidence: 0.90 },
    FrameworkDef { name: "Jest", dep_key: "jest", language: "javascript", category: "testing", confidence: 0.85 },
    FrameworkDef { name: "Mocha", dep_key: "mocha", language: "javascript", category: "testing", confidence: 0.85 },
    FrameworkDef { name: "Vitest", dep_key: "vitest", language: "javascript", category: "testing", confidence: 0.85 },
];

const RUST_FRAMEWORKS: &[FrameworkDef] = &[
    FrameworkDef { name: "Actix Web", dep_key: "actix-web", language: "rust", category: "api", confidence: 0.95 },
    FrameworkDef { name: "Axum", dep_key: "axum", language: "rust", category: "api", confidence: 0.95 },
    FrameworkDef { name: "Rocket", dep_key: "rocket", language: "rust", category: "api", confidence: 0.95 },
    FrameworkDef { name: "Tokio", dep_key: "tokio", language: "rust", category: "runtime", confidence: 0.90 },
    FrameworkDef { name: "Serde", dep_key: "serde", language: "rust", category: "serialization", confidence: 0.85 },
    FrameworkDef { name: "Diesel", dep_key: "diesel", language: "rust", category: "orm", confidence: 0.90 },
    FrameworkDef { name: "SQLx", dep_key: "sqlx", language: "rust", category: "orm", confidence: 0.90 },
];

const GO_FRAMEWORKS: &[FrameworkDef] = &[
    FrameworkDef { name: "Gin", dep_key: "github.com/gin-gonic/gin", language: "go", category: "api", confidence: 0.95 },
    FrameworkDef { name: "Echo", dep_key: "github.com/labstack/echo", language: "go", category: "api", confidence: 0.95 },
    FrameworkDef { name: "Fiber", dep_key: "github.com/gofiber/fiber", language: "go", category: "api", confidence: 0.95 },
];

const PYTHON_DEPS: &[FrameworkDef] = &[
    FrameworkDef { name: "Django", dep_key: "django", language: "python", category: "web", confidence: 0.95 },
    FrameworkDef { name: "Flask", dep_key: "flask", language: "python", category: "api", confidence: 0.90 },
    FrameworkDef { name: "FastAPI", dep_key: "fastapi", language: "python", category: "api", confidence: 0.95 },
    FrameworkDef { name: "Pytest", dep_key: "pytest", language: "python", category: "testing", confidence: 0.85 },
];

const RUBY_DEPS: &[FrameworkDef] = &[
    FrameworkDef { name: "Rails", dep_key: "rails", language: "ruby", category: "web", confidence: 0.95 },
    FrameworkDef { name: "Sinatra", dep_key: "sinatra", language: "ruby", category: "api", confidence: 0.90 },
    FrameworkDef { name: "RSpec", dep_key: "rspec", language: "ruby", category: "testing", confidence: 0.85 },
];

const PHP_DEPS: &[FrameworkDef] = &[
    FrameworkDef { name: "Laravel", dep_key: "laravel/framework", language: "php", category: "web", confidence: 0.95 },
    FrameworkDef { name: "Symfony", dep_key: "symfony/framework-bundle", language: "php", category: "web", confidence: 0.95 },
];

const JAVA_DEPS: &[FrameworkDef] = &[
    FrameworkDef { name: "Spring Boot", dep_key: "spring-boot", language: "java", category: "web", confidence: 0.90 },
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Detect frameworks used in a project by inspecting dependency manifests.
///
/// Scans the project root for:
/// - `package.json` (JavaScript/TypeScript)
/// - `Cargo.toml` (Rust)
/// - `go.mod` (Go)
/// - `requirements.txt` / `pyproject.toml` (Python)
/// - `Gemfile` (Ruby)
/// - `composer.json` (PHP)
/// - `pom.xml` / `build.gradle` (Java)
pub fn detect_frameworks(project_dir: &str) -> Vec<DetectedFramework> {
    let root = Path::new(project_dir);
    let mut results = Vec::new();

    // JavaScript / TypeScript — package.json
    if let Some(frameworks) = detect_from_package_json(&root.join("package.json")) {
        results.extend(frameworks);
    }

    // Rust — Cargo.toml
    if let Some(frameworks) = detect_from_cargo_toml(&root.join("Cargo.toml")) {
        results.extend(frameworks);
    }

    // Go — go.mod
    if let Some(frameworks) = detect_from_go_mod(&root.join("go.mod")) {
        results.extend(frameworks);
    }

    // Python — requirements.txt
    if let Some(frameworks) = detect_from_requirements_txt(&root.join("requirements.txt")) {
        results.extend(frameworks);
    }

    // Python — pyproject.toml
    if let Some(frameworks) = detect_from_pyproject_toml(&root.join("pyproject.toml")) {
        results.extend(frameworks);
    }

    // Ruby — Gemfile
    if let Some(frameworks) = detect_from_gemfile(&root.join("Gemfile")) {
        results.extend(frameworks);
    }

    // PHP — composer.json
    if let Some(frameworks) = detect_from_composer_json(&root.join("composer.json")) {
        results.extend(frameworks);
    }

    // Java — pom.xml
    if let Some(frameworks) = detect_from_pom_xml(&root.join("pom.xml")) {
        results.extend(frameworks);
    }

    // Java — build.gradle
    if let Some(frameworks) = detect_from_build_gradle(&root.join("build.gradle")) {
        results.extend(frameworks);
    }

    // Deduplicate by name (same framework may appear in multiple manifests)
    let mut seen = std::collections::HashSet::new();
    results.retain(|f| seen.insert(f.name.clone()));

    results
}

// ---------------------------------------------------------------------------
// Manifest parsers
// ---------------------------------------------------------------------------

/// Parse package.json and detect JS/TS frameworks from dependencies.
fn detect_from_package_json(path: &Path) -> Option<Vec<DetectedFramework>> {
    let content = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;

    // Merge dependencies and devDependencies
    let mut all_deps: HashMap<String, String> = HashMap::new();
    for section in ["dependencies", "devDependencies"] {
        if let Some(deps) = json.get(section).and_then(|d| d.as_object()) {
            for (k, v) in deps {
                if let Some(ver) = v.as_str() {
                    all_deps.insert(k.clone(), ver.to_string());
                }
            }
        }
    }

    let mut found = Vec::new();
    for def in JS_FRAMEWORKS {
        if let Some(version) = all_deps.get(def.dep_key) {
            found.push(DetectedFramework {
                name: def.name.to_string(),
                version: Some(version.clone()),
                confidence: def.confidence,
                language: def.language.to_string(),
                category: def.category.to_string(),
            });
        }
    }

    if found.is_empty() { None } else { Some(found) }
}

/// Parse Cargo.toml and detect Rust frameworks from [dependencies].
fn detect_from_cargo_toml(path: &Path) -> Option<Vec<DetectedFramework>> {
    let content = std::fs::read_to_string(path).ok()?;

    let mut found = Vec::new();
    for def in RUST_FRAMEWORKS {
        if let Some(version) = extract_cargo_dep_version(&content, def.dep_key) {
            found.push(DetectedFramework {
                name: def.name.to_string(),
                version: Some(version),
                confidence: def.confidence,
                language: def.language.to_string(),
                category: def.category.to_string(),
            });
        }
    }

    if found.is_empty() { None } else { Some(found) }
}

/// Extract a dependency version from Cargo.toml content.
///
/// Handles both `dep = "version"` and `dep = { version = "version" }` forms.
fn extract_cargo_dep_version(content: &str, dep_name: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        // Match: dep_name = "version"
        if trimmed.starts_with(dep_name) {
            if let Some(rest) = trimmed.strip_prefix(dep_name) {
                let rest = rest.trim();
                if let Some(rest) = rest.strip_prefix('=') {
                    let rest = rest.trim();
                    // Simple form: dep = "1.0"
                    if rest.starts_with('"') {
                        return rest.trim_matches('"').to_string().into();
                    }
                    // Table form: dep = { version = "1.0", ... }
                    if rest.starts_with('{') {
                        if let Some(ver_start) = rest.find("version") {
                            let after = &rest[ver_start..];
                            if let Some(eq) = after.find('=') {
                                let ver_part = after[eq + 1..].trim();
                                if let Some(q1) = ver_part.find('"') {
                                    if let Some(q2) = ver_part[q1 + 1..].find('"') {
                                        return Some(ver_part[q1 + 1..q1 + 1 + q2].to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Parse go.mod and detect Go frameworks from require directives.
fn detect_from_go_mod(path: &Path) -> Option<Vec<DetectedFramework>> {
    let content = std::fs::read_to_string(path).ok()?;

    let mut found = Vec::new();
    for def in GO_FRAMEWORKS {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.contains(def.dep_key) {
                // go.mod lines: require github.com/gin-gonic/gin v1.9.1
                let version = trimmed
                    .split_whitespace()
                    .last()
                    .filter(|v| v.starts_with('v'))
                    .map(String::from);
                found.push(DetectedFramework {
                    name: def.name.to_string(),
                    version,
                    confidence: def.confidence,
                    language: def.language.to_string(),
                    category: def.category.to_string(),
                });
                break;
            }
        }
    }

    if found.is_empty() { None } else { Some(found) }
}

/// Parse requirements.txt and detect Python frameworks.
fn detect_from_requirements_txt(path: &Path) -> Option<Vec<DetectedFramework>> {
    let content = std::fs::read_to_string(path).ok()?;
    let content_lower = content.to_lowercase();

    let mut found = Vec::new();
    for def in PYTHON_DEPS {
        for line in content_lower.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Match package name at start: django==3.2 or django>=3.2
            let pkg = trimmed.split(&['=', '>', '<', '!', '[', ';'][..]).next().unwrap_or("").trim();
            if pkg == def.dep_key {
                let version = trimmed
                    .split(&['=', '>', '<', '!'][..])
                    .filter(|s| !s.is_empty() && s.chars().next().map_or(false, |c| c.is_ascii_digit()))
                    .next()
                    .map(|v| v.trim().to_string());
                found.push(DetectedFramework {
                    name: def.name.to_string(),
                    version,
                    confidence: def.confidence,
                    language: def.language.to_string(),
                    category: def.category.to_string(),
                });
                break;
            }
        }
    }

    if found.is_empty() { None } else { Some(found) }
}

/// Parse pyproject.toml and detect Python frameworks from dependencies.
fn detect_from_pyproject_toml(path: &Path) -> Option<Vec<DetectedFramework>> {
    let content = std::fs::read_to_string(path).ok()?;
    let content_lower = content.to_lowercase();

    let mut found = Vec::new();
    for def in PYTHON_DEPS {
        if content_lower.contains(def.dep_key) {
            found.push(DetectedFramework {
                name: def.name.to_string(),
                version: None,
                confidence: def.confidence * 0.9, // slightly lower without precise version match
                language: def.language.to_string(),
                category: def.category.to_string(),
            });
        }
    }

    if found.is_empty() { None } else { Some(found) }
}

/// Parse Gemfile and detect Ruby frameworks.
fn detect_from_gemfile(path: &Path) -> Option<Vec<DetectedFramework>> {
    let content = std::fs::read_to_string(path).ok()?;

    let mut found = Vec::new();
    for def in RUBY_DEPS {
        for line in content.lines() {
            let trimmed = line.trim();
            // gem 'rails', '~> 7.0'
            if trimmed.starts_with("gem") && trimmed.contains(def.dep_key) {
                let version = extract_ruby_gem_version(trimmed);
                found.push(DetectedFramework {
                    name: def.name.to_string(),
                    version,
                    confidence: def.confidence,
                    language: def.language.to_string(),
                    category: def.category.to_string(),
                });
                break;
            }
        }
    }

    if found.is_empty() { None } else { Some(found) }
}

/// Extract version from a Gemfile `gem` line.
fn extract_ruby_gem_version(line: &str) -> Option<String> {
    // gem 'name', '~> 1.0'
    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() >= 2 {
        let ver = parts[1].trim().trim_matches(&['\'', '"'][..]).trim();
        if !ver.is_empty() {
            return Some(ver.to_string());
        }
    }
    None
}

/// Parse composer.json and detect PHP frameworks.
fn detect_from_composer_json(path: &Path) -> Option<Vec<DetectedFramework>> {
    let content = std::fs::read_to_string(path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&content).ok()?;

    let mut all_deps: HashMap<String, String> = HashMap::new();
    for section in ["require", "require-dev"] {
        if let Some(deps) = json.get(section).and_then(|d| d.as_object()) {
            for (k, v) in deps {
                if let Some(ver) = v.as_str() {
                    all_deps.insert(k.clone(), ver.to_string());
                }
            }
        }
    }

    let mut found = Vec::new();
    for def in PHP_DEPS {
        if let Some(version) = all_deps.get(def.dep_key) {
            found.push(DetectedFramework {
                name: def.name.to_string(),
                version: Some(version.clone()),
                confidence: def.confidence,
                language: def.language.to_string(),
                category: def.category.to_string(),
            });
        }
    }

    if found.is_empty() { None } else { Some(found) }
}

/// Parse pom.xml and detect Java frameworks (Spring Boot).
fn detect_from_pom_xml(path: &Path) -> Option<Vec<DetectedFramework>> {
    let content = std::fs::read_to_string(path).ok()?;

    let mut found = Vec::new();
    for def in JAVA_DEPS {
        if content.contains(def.dep_key) {
            found.push(DetectedFramework {
                name: def.name.to_string(),
                version: None,
                confidence: def.confidence,
                language: def.language.to_string(),
                category: def.category.to_string(),
            });
        }
    }

    if found.is_empty() { None } else { Some(found) }
}

/// Parse build.gradle and detect Java frameworks (Spring Boot).
fn detect_from_build_gradle(path: &Path) -> Option<Vec<DetectedFramework>> {
    let content = std::fs::read_to_string(path).ok()?;

    let mut found = Vec::new();
    for def in JAVA_DEPS {
        if content.contains(def.dep_key) {
            found.push(DetectedFramework {
                name: def.name.to_string(),
                version: None,
                confidence: def.confidence,
                language: def.language.to_string(),
                category: def.category.to_string(),
            });
        }
    }

    if found.is_empty() { None } else { Some(found) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a temp directory with a file and return the dir path.
    fn setup_project(file_name: &str, content: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(file_name), content).unwrap();
        dir
    }

    // -- package.json ---------------------------------------------------------

    #[test]
    fn detects_react_from_package_json() {
        let dir = setup_project("package.json", r#"{
            "dependencies": {
                "react": "^18.2.0",
                "react-dom": "^18.2.0"
            }
        }"#);

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "React"));
        let react = results.iter().find(|f| f.name == "React").unwrap();
        assert_eq!(react.version.as_deref(), Some("^18.2.0"));
        assert_eq!(react.language, "javascript");
        assert_eq!(react.category, "web");
        assert!(react.confidence >= 0.9);
    }

    #[test]
    fn detects_express_from_package_json() {
        let dir = setup_project("package.json", r#"{
            "dependencies": {
                "express": "^4.18.2"
            }
        }"#);

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Express"));
        let express = results.iter().find(|f| f.name == "Express").unwrap();
        assert_eq!(express.category, "api");
    }

    #[test]
    fn detects_next_and_jest_from_package_json() {
        let dir = setup_project("package.json", r#"{
            "dependencies": {
                "next": "^14.0.0"
            },
            "devDependencies": {
                "jest": "^29.0.0"
            }
        }"#);

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Next.js"));
        assert!(results.iter().any(|f| f.name == "Jest"));
    }

    #[test]
    fn detects_angular_from_package_json() {
        let dir = setup_project("package.json", r#"{
            "dependencies": {
                "@angular/core": "^17.0.0"
            }
        }"#);

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Angular"));
    }

    #[test]
    fn detects_vue_from_package_json() {
        let dir = setup_project("package.json", r#"{
            "dependencies": {
                "vue": "^3.3.0"
            }
        }"#);

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Vue"));
    }

    // -- Cargo.toml -----------------------------------------------------------

    #[test]
    fn detects_axum_from_cargo_toml() {
        let dir = setup_project("Cargo.toml", r#"
[package]
name = "my-app"
version = "0.1.0"

[dependencies]
axum = "0.7"
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
"#);

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Axum"));
        assert!(results.iter().any(|f| f.name == "Tokio"));
        assert!(results.iter().any(|f| f.name == "Serde"));

        let axum = results.iter().find(|f| f.name == "Axum").unwrap();
        assert_eq!(axum.version.as_deref(), Some("0.7"));
        assert_eq!(axum.language, "rust");
        assert_eq!(axum.category, "api");
    }

    #[test]
    fn detects_actix_web_from_cargo_toml() {
        let dir = setup_project("Cargo.toml", r#"
[dependencies]
actix-web = "4"
"#);

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Actix Web"));
    }

    // -- go.mod ---------------------------------------------------------------

    #[test]
    fn detects_gin_from_go_mod() {
        let dir = setup_project("go.mod", r#"
module example.com/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
)
"#);

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Gin"));
        let gin = results.iter().find(|f| f.name == "Gin").unwrap();
        assert_eq!(gin.version.as_deref(), Some("v1.9.1"));
        assert_eq!(gin.language, "go");
    }

    // -- requirements.txt -----------------------------------------------------

    #[test]
    fn detects_django_from_requirements_txt() {
        let dir = setup_project("requirements.txt", "django==4.2\nrequests>=2.28\n");

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Django"));
        let django = results.iter().find(|f| f.name == "Django").unwrap();
        assert_eq!(django.language, "python");
        assert_eq!(django.category, "web");
    }

    #[test]
    fn detects_flask_from_requirements_txt() {
        let dir = setup_project("requirements.txt", "flask>=2.0\n");

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Flask"));
    }

    #[test]
    fn detects_fastapi_from_requirements_txt() {
        let dir = setup_project("requirements.txt", "fastapi==0.100.0\nuvicorn\n");

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "FastAPI"));
    }

    // -- pyproject.toml -------------------------------------------------------

    #[test]
    fn detects_django_from_pyproject_toml() {
        let dir = setup_project("pyproject.toml", r#"
[project]
dependencies = [
    "django>=4.2",
]
"#);

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Django"));
    }

    // -- Gemfile --------------------------------------------------------------

    #[test]
    fn detects_rails_from_gemfile() {
        let dir = setup_project("Gemfile", r#"
source 'https://rubygems.org'

gem 'rails', '~> 7.0'
gem 'pg'
"#);

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Rails"));
        let rails = results.iter().find(|f| f.name == "Rails").unwrap();
        assert_eq!(rails.version.as_deref(), Some("~> 7.0"));
        assert_eq!(rails.language, "ruby");
    }

    #[test]
    fn detects_sinatra_from_gemfile() {
        let dir = setup_project("Gemfile", "gem 'sinatra'\n");

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Sinatra"));
    }

    // -- composer.json --------------------------------------------------------

    #[test]
    fn detects_laravel_from_composer_json() {
        let dir = setup_project("composer.json", r#"{
            "require": {
                "laravel/framework": "^10.0"
            }
        }"#);

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Laravel"));
        let laravel = results.iter().find(|f| f.name == "Laravel").unwrap();
        assert_eq!(laravel.language, "php");
    }

    // -- pom.xml --------------------------------------------------------------

    #[test]
    fn detects_spring_boot_from_pom_xml() {
        let dir = setup_project("pom.xml", r#"
<project>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
    </parent>
</project>
"#);

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Spring Boot"));
        let spring = results.iter().find(|f| f.name == "Spring Boot").unwrap();
        assert_eq!(spring.language, "java");
    }

    // -- build.gradle ---------------------------------------------------------

    #[test]
    fn detects_spring_boot_from_build_gradle() {
        let dir = setup_project("build.gradle", r#"
plugins {
    id 'org.springframework.boot' version '3.1.0'
}
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
}
"#);

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "Spring Boot"));
    }

    // -- Edge cases -----------------------------------------------------------

    #[test]
    fn returns_empty_for_nonexistent_dir() {
        let results = detect_frameworks("/nonexistent/project/path");
        assert!(results.is_empty());
    }

    #[test]
    fn returns_empty_for_no_manifests() {
        let dir = tempfile::tempdir().unwrap();
        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.is_empty());
    }

    #[test]
    fn handles_invalid_package_json() {
        let dir = setup_project("package.json", "not valid json {{{");
        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.is_empty());
    }

    #[test]
    fn detects_multiple_ecosystems() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("package.json"), r#"{
            "dependencies": { "react": "^18.0.0" }
        }"#).unwrap();
        fs::write(dir.path().join("Cargo.toml"), r#"
[dependencies]
tokio = "1"
"#).unwrap();

        let results = detect_frameworks(dir.path().to_str().unwrap());
        assert!(results.iter().any(|f| f.name == "React"));
        assert!(results.iter().any(|f| f.name == "Tokio"));
    }

    #[test]
    fn serializes_to_json() {
        let framework = DetectedFramework {
            name: "React".to_string(),
            version: Some("^18.0.0".to_string()),
            confidence: 0.95,
            language: "javascript".to_string(),
            category: "web".to_string(),
        };

        let json = serde_json::to_string(&framework).unwrap();
        let back: DetectedFramework = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "React");
        assert_eq!(back.confidence, 0.95);
    }
}
