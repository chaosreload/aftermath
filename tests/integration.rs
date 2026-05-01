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
    scan_json_kind(repo, None)
}

fn scan_json_kind(repo: &Path, kind: Option<&str>) -> serde_json::Value {
    let mut args = vec!["scan", repo.to_str().unwrap(), "--format=json"];
    let kind_arg;
    if let Some(k) = kind {
        kind_arg = format!("--kind={}", k);
        args.push(&kind_arg);
    }
    let out = Command::new(bin_path())
        .args(&args)
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
        f["locator"].as_str().unwrap_or("") == ".venv"
    });
    assert_eq!(
        venv_findings.len(),
        1,
        "expected 1 collapsed .venv finding, got {}: {:#?}",
        venv_findings.len(),
        findings
    );
    let f = venv_findings[0];
    assert_eq!(f["severity"], "high");
    assert_eq!(f["suggested_action"]["kind"], "safe_to_delete");
    // Check child_count evidence
    let child_count = f["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "child_count")
        .expect("missing child_count evidence");
    assert!(
        child_count["value"].as_u64().unwrap() >= 2,
        "expected child_count >= 2, got {:?}",
        child_count["value"]
    );
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
    assert_eq!(large[0]["severity"], "low");
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

/// Scenario: AI commit in reflog after `git reset --hard HEAD~1` — unreachable from any branch.
#[test]
fn detects_ai_commit_in_reflog_after_reset() {
    let dir = tempdir("reflog-reset");
    init_repo(&dir, "dev@example.com", "Dev");

    sh(
        &dir,
        "echo 'v1' > app.py && git add app.py && git commit -q -m 'initial'",
    );
    // Make an AI-authored commit
    sh(
        &dir,
        "git config user.email 'noreply@anthropic.com' && git config user.name 'Claude Code' && \
         echo 'ai change' >> app.py && git commit -qam 'feat: ai improvement'",
    );
    // Reset it away — commit is now only in reflog
    sh(&dir, "git reset --hard HEAD~1");
    // Restore human author for any future commits
    sh(
        &dir,
        "git config user.email 'dev@example.com' && git config user.name 'Dev'",
    );

    let findings = scan_json_kind(&dir, Some("reflog"));
    let reflog_findings = findings_matching(&findings, |f| f["scanner"] == "reflog");
    assert_eq!(
        reflog_findings.len(),
        1,
        "expected 1 reflog finding, got {findings:#?}"
    );
    assert_eq!(reflog_findings[0]["severity"], "low");
    // Check evidence contains commit_sha and author_email
    let evidence: Vec<String> = reflog_findings[0]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["type"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(evidence.contains(&"commit_sha".to_string()));
    assert!(evidence.contains(&"author_email".to_string()));
    assert!(evidence.contains(&"reflog_source".to_string()));
}

/// Scenario: AI commit still reachable from branch — reflog scanner must NOT flag it.
#[test]
fn reflog_scanner_ignores_commits_reachable_from_branch() {
    let dir = tempdir("reflog-reachable");
    init_repo(&dir, "noreply@anthropic.com", "Claude Code");

    sh(
        &dir,
        "echo 'ai code' > app.py && git add app.py && git commit -q -m 'feat: ai commit'",
    );

    let findings = scan_json_kind(&dir, Some("reflog"));
    let reflog_findings = findings_matching(&findings, |f| f["scanner"] == "reflog");
    assert!(
        reflog_findings.is_empty(),
        "expected 0 reflog findings for reachable commit, got {findings:#?}"
    );
}

/// Scenario: repo with 5 human + 5 AI commits — author scanner flags ai_ratio=0.50.
#[test]
fn author_scanner_flags_ai_dominated_repo() {
    let dir = tempdir("author-ratio");
    init_repo(&dir, "dev@example.com", "Dev");

    // 5 human commits
    for i in 1..=5 {
        sh(
            &dir,
            &format!(
                "echo 'human {}' >> app.py && git add app.py && git commit -q -m 'human commit {}'",
                i, i
            ),
        );
    }
    // Switch to AI author for 5 commits
    sh(
        &dir,
        "git config user.email 'noreply@anthropic.com' && git config user.name 'Claude Code'",
    );
    for i in 1..=5 {
        sh(
            &dir,
            &format!(
                "echo 'ai {}' >> app.py && git add app.py && git commit -q -m 'ai commit {}'",
                i, i
            ),
        );
    }

    let findings = scan_json_kind(&dir, Some("author"));
    let author_findings = findings_matching(&findings, |f| f["scanner"] == "author");
    assert_eq!(
        author_findings.len(),
        1,
        "expected 1 author finding, got {findings:#?}"
    );
    assert_eq!(author_findings[0]["severity"], "medium");
    // Check ai_ratio evidence
    let ratio = author_findings[0]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "ai_ratio")
        .expect("missing ai_ratio evidence");
    assert_eq!(ratio["value"], "0.50");
}

/// Collapse: commit .venv/lib/a.py + .venv/pyvenv.cfg → exactly 1 finding with child_count=2
#[test]
fn tree_nested_venv_collapsed() {
    let dir = tempdir("nested-venv-collapse");
    init_repo(&dir, "dev@example.com", "Dev");

    sh(&dir, "mkdir -p .venv/lib");
    sh(&dir, "echo 'stub' > .venv/lib/a.py");
    sh(&dir, "echo 'pyvenv' > .venv/pyvenv.cfg");
    sh(&dir, "echo 'src' > main.py");
    sh(&dir, "git add . && git commit -q -m 'add venv'");

    let findings = scan_json_kind(&dir, Some("tree"));
    let venv = findings_matching(&findings, |f| f["locator"] == ".venv");
    assert_eq!(
        venv.len(),
        1,
        "expected 1 collapsed .venv finding, got {}: {:#?}",
        venv.len(),
        findings
    );
    let child_count = venv[0]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["type"] == "child_count")
        .expect("missing child_count evidence");
    // .venv/lib (dir) + .venv/lib/a.py + .venv/pyvenv.cfg = 3 children
    assert_eq!(
        child_count["value"].as_u64().unwrap(),
        3,
        "expected child_count=3, got {:?}",
        child_count["value"]
    );
}

/// Two distinct forbidden patterns (.venv/ + node_modules/) → 2 separate findings
#[test]
fn tree_two_distinct_forbidden_patterns_not_merged() {
    let dir = tempdir("two-patterns");
    init_repo(&dir, "dev@example.com", "Dev");

    sh(&dir, "mkdir -p .venv && echo 'x' > .venv/a");
    sh(&dir, "mkdir -p node_modules && echo 'y' > node_modules/b");
    sh(&dir, "echo 'src' > main.py");
    sh(&dir, "git add . && git commit -q -m 'add both'");

    let findings = scan_json_kind(&dir, Some("tree"));
    let forbidden = findings_matching(&findings, |f| {
        let loc = f["locator"].as_str().unwrap_or("");
        loc == ".venv" || loc == "node_modules"
    });
    assert_eq!(
        forbidden.len(),
        2,
        "expected 2 distinct forbidden-path findings, got {}: {:#?}",
        forbidden.len(),
        findings
    );
}

/// Large binary under docs/ → suppressed (0 findings)
#[test]
fn tree_large_binary_in_docs_suppressed() {
    let dir = tempdir("docs-binary-skip");
    init_repo(&dir, "dev@example.com", "Dev");

    sh(&dir, "mkdir -p docs/img");
    sh(
        &dir,
        "dd if=/dev/zero of=docs/img/big.png bs=1024 count=2048 2>/dev/null",
    );
    sh(&dir, "echo 'src' > main.py");
    sh(&dir, "git add . && git commit -q -m 'add docs image'");

    let findings = scan_json_kind(&dir, Some("tree"));
    let large = findings_matching(&findings, |f| {
        f["title"].as_str().unwrap_or("").contains("Large binary")
    });
    assert_eq!(
        large.len(),
        0,
        "expected 0 large-binary findings under docs/, got {}: {:#?}",
        large.len(),
        findings
    );
}

/// Large binary at repo root → 1 finding, severity low
#[test]
fn tree_large_binary_outside_docs_still_flagged() {
    let dir = tempdir("root-binary");
    init_repo(&dir, "dev@example.com", "Dev");

    sh(
        &dir,
        "dd if=/dev/zero of=big.bin bs=1024 count=2048 2>/dev/null",
    );
    sh(&dir, "echo 'src' > main.py");
    sh(&dir, "git add . && git commit -q -m 'add binary'");

    let findings = scan_json_kind(&dir, Some("tree"));
    let large = findings_matching(&findings, |f| {
        f["title"].as_str().unwrap_or("").contains("Large binary")
    });
    assert_eq!(
        large.len(),
        1,
        "expected 1 large-binary finding, got {}: {:#?}",
        large.len(),
        findings
    );
    assert_eq!(large[0]["severity"], "low");
}

/// Custom config with empty allowlist → large binary under docs/ IS flagged
#[test]
fn tree_large_binary_with_custom_allowlist() {
    let dir = tempdir("custom-allowlist");
    init_repo(&dir, "dev@example.com", "Dev");

    // Write config that clears the skip prefixes
    std::fs::write(
        dir.join(".aftermath.toml"),
        "[tree_scanner]\nlarge_binary_skip_prefixes = []\n",
    )
    .unwrap();

    sh(&dir, "mkdir -p docs");
    sh(
        &dir,
        "dd if=/dev/zero of=docs/big.bin bs=1024 count=2048 2>/dev/null",
    );
    sh(&dir, "echo 'src' > main.py");
    sh(
        &dir,
        "git add . && git commit -q -m 'add docs binary with empty allowlist'",
    );

    let findings = scan_json_kind(&dir, Some("tree"));
    let large = findings_matching(&findings, |f| {
        f["title"].as_str().unwrap_or("").contains("Large binary")
    });
    assert_eq!(
        large.len(),
        1,
        "expected 1 large-binary finding with empty allowlist, got {}: {:#?}",
        large.len(),
        findings
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
