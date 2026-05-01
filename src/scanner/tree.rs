//! tree_scanner — scans HEAD + recent commits for forbidden paths (spec §3.1 target 3).

use anyhow::{Context, Result};
use git2::{ObjectType, Repository, TreeWalkMode, TreeWalkResult};
use glob::Pattern;
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::config::{PatternRule, TreeConfig};
use crate::finding::{Evidence, Finding, ScannerKind, Severity, SuggestedAction};

struct CompiledRule {
    raw: String,
    pattern: Pattern,
    severity: Severity,
    action_kind: String,
    is_dir_pattern: bool,
}

/// Tracks collapsed children for a directory-pattern finding root.
struct CollapsedDir {
    severity: Severity,
    action_kind: String,
    raw_pattern: String,
    context: String,
    child_paths: Vec<String>,
}

pub fn scan(repo_path: &Path, cfg: &TreeConfig) -> Result<Vec<Finding>> {
    let repo = Repository::discover(repo_path)
        .with_context(|| format!("discovering git repo at {}", repo_path.display()))?;

    let rules = compile_rules(&cfg.patterns);
    let mut findings = Vec::new();
    let mut seen_paths: HashSet<String> = HashSet::new();

    // Walk HEAD tree
    if let Ok(head) = repo.head() {
        if let Ok(commit) = head.peel_to_commit() {
            let tree = commit.tree()?;
            walk_tree(
                &repo,
                &tree,
                &rules,
                cfg,
                &mut findings,
                &mut seen_paths,
                "HEAD",
            )?;
        }
    }

    // Walk recent commits looking for files first introduced there
    if cfg.recent_commits > 0 {
        let mut revwalk = repo.revwalk()?;
        revwalk.push_head().ok();
        let limit = cfg.recent_commits as usize;
        for (i, oid_res) in revwalk.enumerate() {
            if i >= limit {
                break;
            }
            let oid = match oid_res {
                Ok(o) => o,
                Err(_) => continue,
            };
            let commit = match repo.find_commit(oid) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let tree = match commit.tree() {
                Ok(t) => t,
                Err(_) => continue,
            };
            let locator_prefix = format!("commit {}", &oid.to_string()[..8]);
            walk_tree(
                &repo,
                &tree,
                &rules,
                cfg,
                &mut findings,
                &mut seen_paths,
                &locator_prefix,
            )?;
        }
    }

    Ok(findings)
}

fn compile_rules(rules: &[PatternRule]) -> Vec<CompiledRule> {
    rules
        .iter()
        .filter_map(|r| {
            // Match by basename pattern AND directory-prefix pattern
            let compiled = Pattern::new(&r.pattern).ok()?;
            let severity = Severity::parse(&r.severity)?;
            Some(CompiledRule {
                raw: r.pattern.clone(),
                pattern: compiled,
                severity,
                action_kind: r.action.clone(),
                is_dir_pattern: r.pattern.ends_with('/'),
            })
        })
        .collect()
}

fn walk_tree(
    repo: &Repository,
    tree: &git2::Tree,
    rules: &[CompiledRule],
    cfg: &TreeConfig,
    findings: &mut Vec<Finding>,
    seen_paths: &mut HashSet<String>,
    context: &str,
) -> Result<()> {
    // collapsed_dirs: key = (pattern_raw, root_path), value = CollapsedDir
    let mut collapsed_dirs: HashMap<(String, String), CollapsedDir> = HashMap::new();

    tree.walk(TreeWalkMode::PreOrder, |root, entry| {
        let name = match entry.name() {
            Some(n) => n,
            None => return TreeWalkResult::Ok,
        };
        let full_path = format!("{}{}", root, name);
        if seen_paths.contains(&full_path) {
            return TreeWalkResult::Ok;
        }

        // Match rules
        for rule in rules {
            if matches_rule(&rule.pattern, &rule.raw, &full_path, name) {
                seen_paths.insert(full_path.clone());

                // For directory patterns, collapse children under the top-level root
                if rule.is_dir_pattern {
                    let root_path = find_dir_root(&rule.raw, &full_path);
                    let key = (rule.raw.clone(), root_path.clone());
                    let entry = collapsed_dirs.entry(key).or_insert_with(|| CollapsedDir {
                        severity: rule.severity,
                        action_kind: rule.action_kind.clone(),
                        raw_pattern: rule.raw.clone(),
                        context: context.to_string(),
                        child_paths: Vec::new(),
                    });
                    // Use max severity
                    if rule.severity > entry.severity {
                        entry.severity = rule.severity;
                    }
                    // Don't add the root itself as a child
                    if full_path != root_path {
                        entry.child_paths.push(full_path.clone());
                    }
                } else {
                    // Non-directory pattern: emit immediately as before
                    let action = build_action(&rule.action_kind, &full_path);
                    let mut evidence = vec![
                        Evidence {
                            kind: "path".into(),
                            value: serde_json::json!(full_path),
                        },
                        Evidence {
                            kind: "matched_pattern".into(),
                            value: serde_json::json!(rule.raw),
                        },
                        Evidence {
                            kind: "seen_in".into(),
                            value: serde_json::json!(context),
                        },
                    ];

                    if let Ok(obj) = entry_to_object(repo, entry) {
                        if let Some(blob) = obj.as_blob() {
                            evidence.push(Evidence {
                                kind: "size_bytes".into(),
                                value: serde_json::json!(blob.size()),
                            });
                        }
                    }
                    let filemode = entry.filemode();
                    evidence.push(Evidence {
                        kind: "filemode_octal".into(),
                        value: serde_json::json!(format!("{:o}", filemode)),
                    });

                    findings.push(Finding {
                        id: Finding::stable_id(ScannerKind::Tree, &full_path),
                        scanner: ScannerKind::Tree,
                        severity: rule.severity,
                        locator: full_path.clone(),
                        title: format!(
                            "Forbidden path tracked in repo: '{}' (matches '{}')",
                            full_path, rule.raw
                        ),
                        evidence,
                        suggested_action: action,
                    });
                }
                break;
            }
        }

        // Size check (if not already flagged)
        if !seen_paths.contains(&full_path) && entry.kind() == Some(ObjectType::Blob) {
            if let Ok(obj) = entry.to_object(repo) {
                if let Some(blob) = obj.as_blob() {
                    let size = blob.size() as u64;
                    if size > cfg.max_tracked_bytes && looks_binary(blob.content()) {
                        // Skip large-binary findings under allowlisted prefixes
                        if !cfg
                            .large_binary_skip_prefixes
                            .iter()
                            .any(|prefix| full_path.starts_with(prefix.as_str()))
                        {
                            seen_paths.insert(full_path.clone());
                            findings.push(Finding {
                                id: Finding::stable_id(ScannerKind::Tree, &full_path),
                                scanner: ScannerKind::Tree,
                                severity: Severity::Low,
                                locator: full_path.clone(),
                                title: format!(
                                    "Large binary tracked in repo: '{}' ({} bytes)",
                                    full_path, size
                                ),
                                evidence: vec![
                                    Evidence {
                                        kind: "path".into(),
                                        value: serde_json::json!(full_path),
                                    },
                                    Evidence {
                                        kind: "size_bytes".into(),
                                        value: serde_json::json!(size),
                                    },
                                    Evidence {
                                        kind: "seen_in".into(),
                                        value: serde_json::json!(context),
                                    },
                                    Evidence {
                                        kind: "reason".into(),
                                        value: serde_json::json!("exceeds max_tracked_bytes and looks binary"),
                                    },
                                ],
                                suggested_action: SuggestedAction::ReviewAndConfirm {
                                    reason: "Large binary file tracked in Git; consider git-lfs or .gitignore.".into(),
                                    suggested_command: None,
                                },
                            });
                        }
                    }
                }
            }
        }

        // Symlink check (filemode 0120000 == 0o120000)
        if cfg.flag_symlinks
            && entry.filemode() == 0o120_000
            && !seen_paths.contains(&full_path)
        {
            seen_paths.insert(full_path.clone());
            findings.push(Finding {
                id: Finding::stable_id(ScannerKind::Tree, &full_path),
                scanner: ScannerKind::Tree,
                severity: Severity::Medium,
                locator: full_path.clone(),
                title: format!("Symlink tracked in repo: '{}'", full_path),
                evidence: vec![
                    Evidence {
                        kind: "path".into(),
                        value: serde_json::json!(full_path),
                    },
                    Evidence {
                        kind: "filemode_octal".into(),
                        value: serde_json::json!("120000"),
                    },
                    Evidence {
                        kind: "seen_in".into(),
                        value: serde_json::json!(context),
                    },
                    Evidence {
                        kind: "reason".into(),
                        value: serde_json::json!("symlinks are often accidentally committed by `git add -A` on AI workspaces"),
                    },
                ],
                suggested_action: SuggestedAction::ReviewAndConfirm {
                    reason: "Symlink in Git history; often unintended from 'git add -A' on AI workspaces.".into(),
                    suggested_command: None,
                },
            });
        }

        TreeWalkResult::Ok
    })?;

    // Emit collapsed directory-pattern findings
    for ((_, root_path), collapsed) in collapsed_dirs {
        let child_count = collapsed.child_paths.len();
        let action = build_action(&collapsed.action_kind, &root_path);
        let sample_children: Vec<&str> = collapsed
            .child_paths
            .iter()
            .take(5)
            .map(|s| s.as_str())
            .collect();
        let mut evidence = vec![
            Evidence {
                kind: "path".into(),
                value: serde_json::json!(root_path),
            },
            Evidence {
                kind: "matched_pattern".into(),
                value: serde_json::json!(collapsed.raw_pattern),
            },
            Evidence {
                kind: "seen_in".into(),
                value: serde_json::json!(collapsed.context),
            },
            Evidence {
                kind: "child_count".into(),
                value: serde_json::json!(child_count),
            },
        ];
        if !sample_children.is_empty() {
            evidence.push(Evidence {
                kind: "sample_children".into(),
                value: serde_json::json!(sample_children),
            });
        }

        findings.push(Finding {
            id: Finding::stable_id(ScannerKind::Tree, &root_path),
            scanner: ScannerKind::Tree,
            severity: collapsed.severity,
            locator: root_path.clone(),
            title: format!(
                "Forbidden path tracked in repo: '{}' (matches '{}')",
                root_path, collapsed.raw_pattern
            ),
            evidence,
            suggested_action: action,
        });
    }

    Ok(())
}

/// For a directory pattern (e.g. ".venv/"), find the top-level root in a full path.
/// E.g. for pattern ".venv/" and path ".venv/lib/python3.11", returns ".venv".
fn find_dir_root(raw_pattern: &str, full_path: &str) -> String {
    let dir = raw_pattern.strip_suffix('/').unwrap_or(raw_pattern);
    let parts: Vec<&str> = full_path.split('/').collect();
    // Find the first component matching the dir name
    for (i, part) in parts.iter().enumerate() {
        if *part == dir {
            // Root is everything up to and including this component
            return parts[..=i].join("/");
        }
    }
    full_path.to_string()
}

/// Wrapper to avoid name collision with `entry` variable in the closure.
fn entry_to_object<'a>(
    repo: &'a Repository,
    entry: &git2::TreeEntry<'_>,
) -> std::result::Result<git2::Object<'a>, git2::Error> {
    entry.to_object(repo)
}

fn matches_rule(pat: &Pattern, raw: &str, full_path: &str, name: &str) -> bool {
    // Directory pattern like ".venv/" should match any path containing ".venv/" as a component
    if let Some(dir) = raw.strip_suffix('/') {
        let path_parts: Vec<&str> = full_path.split('/').collect();
        return path_parts.contains(&dir);
    }
    // Glob matches basename OR full path
    pat.matches(name) || pat.matches(full_path)
}

fn looks_binary(data: &[u8]) -> bool {
    // simple heuristic: if NUL byte in first 4KiB, assume binary
    let window = &data[..data.len().min(4096)];
    window.contains(&0)
}

fn build_action(kind: &str, path: &str) -> SuggestedAction {
    match kind {
        "report" => SuggestedAction::ReportOnly,
        "safe-to-delete" => SuggestedAction::SafeToDelete {
            reason: format!(
                "'{}' is a well-known artifact; safe to remove from tracking.",
                path
            ),
            suggested_command: format!(
                "git rm --cached -r '{}' && echo '{}' >> .gitignore",
                path, path
            ),
        },
        "review" => SuggestedAction::ReviewAndConfirm {
            reason: format!(
                "'{}' may contain secrets or environment-specific data.",
                path
            ),
            suggested_command: Some(format!("git log --all --full-history -- '{}'", path)),
        },
        "hard-veto" => SuggestedAction::HardVeto {
            reason: format!("'{}' is explicitly whitelisted; do not touch.", path),
        },
        _ => SuggestedAction::ReportOnly,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use glob::Pattern;

    #[test]
    fn matches_dir_prefix() {
        let p = Pattern::new(".venv/").unwrap();
        assert!(matches_rule(
            &p,
            ".venv/",
            "subdir/.venv/bin/python",
            "python"
        ));
        assert!(matches_rule(&p, ".venv/", ".venv/pyvenv.cfg", "pyvenv.cfg"));
    }

    #[test]
    fn matches_glob_basename() {
        let p = Pattern::new("*.tmp").unwrap();
        assert!(matches_rule(&p, "*.tmp", "tests/foo.tmp", "foo.tmp"));
        assert!(!matches_rule(&p, "*.tmp", "tests/foo.txt", "foo.txt"));
    }
}
