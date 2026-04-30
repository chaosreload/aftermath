//! Integration tests: simulate real-world AI-agent pollution and assert aftermath catches it.
//!
//! Each test builds a throwaway git repo in a temp dir, commits an authentic failure pattern
//! we have actually seen in the wild (SOUL.md entries), then shells out to the release binary
//! and asserts the Finding output matches expectations.
//!
//! Run: `cargo test --release --test integration -- --nocapture`

use std::path::{Path, PathBuf};
use std::process::Command;

// --- helpers ---------------------------------------------------------------

fn bin_path() -> PathBuf {
    // Resolve from CARGO_MANIFEST_DIR so tests work from any cwd.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.join("target").join("release").join("aftermath")
}

fn sh(cwd: &Path, cmd: &str) {
    let status = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|e| panic!("failed to run `{cmd}`: {e}"));
    assert!(status.success(), "shell command failed: {cmd}");
}

fn scan_json(repo: &Path) -> serde_json::Value {
    let out = Command::new(bin_path())
        .args(["scan", repo.to_str().unwrap(), "--format=json"])
        .output()
        .expect("failed to spawn aftermath");
    assert!(
        out.status.success(),
        "aftermath exit {}: stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("aftermath stdout is not json: {e}\n---\n{stdout}"))
}

fn init_repo(dir: &Path, author_email: &str, author_name: &str) {
    sh(dir, "git init -q -b main");
    sh(dir, &format!("git config user.email '{author_email}'"));
    sh(dir, &format!("git config user.name '{author_name}'"));
}

fn findings_matching(
    findings: &serde_json::Value,
    predicate: impl Fn(&serde_json::Value) -> bool,
) -> Vec<&serde_json::Value> {
    findings
        .as_array()
        .map(|arr| arr.iter().filter(|f| predicate(f)).collect())
        .unwrap_or_default()
}

// --- tests -----------------------------------------------------------------

/// Scenario: `git add -A` in an AI workspace commits a `.venv/` symlinked tree
/// (the exact SOUL.md 2026-04-20 opensre#694 pattern).
#[test]
fn detects_venv_pollution_from_git_add_all() {
    let dir = tempdir("venv-add-all");
    init_repo(&dir, "noreply@anthropic.com", "Claude Code");

    sh(&dir, "mkdir -p .venv/lib/python3.11/site-packages");
    sh(
        &dir,
        "echo 'stub' > .venv/lib/python3.11/site-packages/typing_extensions.py",
    );
    sh(&dir, "echo 'pyvenv' > .venv/pyvenv.cfg");
    sh(&dir, "mkdir -p app && echo 'print(1)' > app/main.py");
    // Explicitly commit via 'git add .' to emulate the 'git add -A' mistake.
    sh(
        &dir,
        "git add . && git commit -q -m 'fix: add typing_extensions'",
    );

    let findings = scan_json(&dir);
    let venv_findings = findings_matching(&findings, |f| {
        f["locator"].as_str().unwrap_or("").starts_with(".venv")
    });
    assert!(
        venv_findings.len() >= 5,
        "expected >=5 .venv findings, got {}: {:#?}",
        venv_findings.len(),
        findings
    );
    for f in &venv_findings {
        assert_eq!(f["severity"], "high");
        assert_eq!(f["suggested_action"]["kind"], "safe_to_delete");
    }
}

/// Scenario: agent drafted PR description as a working file and forgot to gitignore it.
#[test]
fn detects_pr_description_draft() {
    let dir = tempdir("pr-drafts");
    init_repo(&dir, "dev@example.com", "Dev");

    sh(&dir, "echo '# PR desc' > PR-694-description.md");
    sh(
        &dir,
        "echo '# other draft' > PR-fix-typeddict-description.md",
    );
    sh(&dir, "mkdir -p app && echo 'x=1' > app/main.py");
    sh(&dir, "git add . && git commit -q -m 'chore'");

    let findings = scan_json(&dir);
    let pr_findings = findings_matching(&findings, |f| {
        f["locator"].as_str().unwrap_or("").starts_with("PR-")
    });
    assert_eq!(
        pr_findings.len(),
        2,
        "expected 2 PR drafts, got {}: {:#?}",
        pr_findings.len(),
        findings
    );
    for f in &pr_findings {
        assert_eq!(f["severity"], "low");
    }
}

/// Scenario: AI leaks a `.env` into the tree. Must be critical severity.
#[test]
fn detects_env_leak_as_critical() {
    let dir = tempdir("env-leak");
    init_repo(&dir, "dev@example.com", "Dev");

    sh(&dir, "echo 'OPENAI_API_KEY=sk-xxx' > .env");
    sh(&dir, "echo 'print(1)' > app.py");
    sh(&dir, "git add . && git commit -q -m 'feat: add app'");

    let findings = scan_json(&dir);
    let env_findings = findings_matching(&findings, |f| f["locator"] == ".env");
    assert_eq!(
        env_findings.len(),
        1,
        "expected 1 .env finding, got {findings:#?}"
    );
    assert_eq!(env_findings[0]["severity"], "critical");
    assert_eq!(
        env_findings[0]["suggested_action"]["kind"],
        "review_and_confirm"
    );
}

/// Scenario: AI agent opened a `claude/<...>` branch, made a commit, then abandoned it.
/// Branch is behind main → must be flagged with name_matches_pattern = "claude/".
#[test]
fn detects_abandoned_ai_branch() {
    let dir = tempdir("abandoned-branch");
    init_repo(&dir, "dev@example.com", "Dev");

    sh(
        &dir,
        "echo 'v1' > app.py && git add app.py && git commit -q -m 'initial'",
    );
    sh(&dir, "git checkout -q -b claude/refactor-session");
    sh(
        &dir,
        "git config user.email 'noreply@anthropic.com' && git config user.name 'Claude Code' && \
         echo 'v1-refactor' > app.py && git commit -qam 'refactor: restructure'",
    );
    // Move main ahead of the AI branch
    sh(&dir, "git checkout -q main");
    sh(
        &dir,
        "git config user.email 'dev@example.com' && git config user.name 'Dev' && \
         echo 'v2' > app.py && git commit -qam 'legit update' && echo 'v3' >> app.py && git commit -qam 'more'",
    );

    let findings = scan_json(&dir);
    let branch_findings = findings_matching(&findings, |f| {
        f["scanner"] == "branch" && f["locator"].as_str().unwrap_or("") == "claude/refactor-session"
    });
    assert_eq!(
        branch_findings.len(),
        1,
        "expected 1 branch finding, got {findings:#?}"
    );
    let f = branch_findings[0];
    let evidence: Vec<String> = f["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["type"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(evidence.contains(&"name_matches_pattern".to_string()));
    assert!(evidence.contains(&"commits_behind_default".to_string()));
    assert!(evidence.contains(&"last_author_email".to_string()));
}

/// Scenario: large binary blob committed accidentally (AI often downloads test fixtures).
#[test]
fn detects_large_binary_blob() {
    let dir = tempdir("large-bin");
    init_repo(&dir, "dev@example.com", "Dev");

    // 2 MB binary blob (zeros with NUL bytes triggers binary heuristic)
    sh(
        &dir,
        "dd if=/dev/zero of=model-cache.bin bs=1024 count=2048 2>/dev/null",
    );
    sh(&dir, "echo 'src' > src.py");
    sh(
        &dir,
        "git add . && git commit -q -m 'accidentally add cache'",
    );

    let findings = scan_json(&dir);
    let large = findings_matching(&findings, |f| {
        f["locator"] == "model-cache.bin"
            && f["title"].as_str().unwrap_or("").contains("Large binary")
    });
    assert_eq!(
        large.len(),
        1,
        "expected large binary finding, got {findings:#?}"
    );
    assert_eq!(large[0]["severity"], "medium");
}

/// Scenario: a clean repo (just code + .gitignore) must produce zero findings.
#[test]
fn clean_repo_has_no_findings() {
    let dir = tempdir("clean");
    init_repo(&dir, "dev@example.com", "Dev");
    sh(&dir, "echo 'target/' > .gitignore");
    sh(&dir, "mkdir -p src && echo 'fn main(){}' > src/main.rs");
    sh(&dir, "git add . && git commit -q -m 'feat: initial'");

    let findings = scan_json(&dir);
    let arr = findings.as_array().unwrap();
    assert!(
        arr.is_empty(),
        "clean repo produced {} findings: {findings:#?}",
        arr.len()
    );
}

/// Stable id regression: same polluted tree must produce same finding id across runs.
#[test]
fn finding_ids_are_stable_across_runs() {
    let dir = tempdir("stable-id");
    init_repo(&dir, "dev@example.com", "Dev");
    sh(&dir, "echo 'OPENAI_API_KEY=x' > .env");
    sh(&dir, "echo 'x' > src.py");
    sh(&dir, "git add . && git commit -q -m 'c'");

    let f1 = scan_json(&dir);
    let f2 = scan_json(&dir);
    assert_eq!(
        f1, f2,
        "two scans of the same repo must produce identical output"
    );
}

// --- tempdir helper --------------------------------------------------------
//
// We don't want a tempdir crate dep for such a small need. Use /tmp + pid + test name.

fn tempdir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!(
        "aftermath-it-{}-{}-{}",
        std::process::id(),
        label,
        n
    ));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}
