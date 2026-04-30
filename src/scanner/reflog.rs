//! reflog_scanner — finds AI-authored commits in reflog that are unreachable from any branch.

use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use git2::{BranchType, Repository};
use std::collections::HashSet;
use std::path::Path;

use crate::config::ReflogConfig;
use crate::finding::{Evidence, Finding, ScannerKind, Severity, SuggestedAction};

pub fn scan(repo_path: &Path, cfg: &ReflogConfig) -> Result<Vec<Finding>> {
    let repo = Repository::discover(repo_path)
        .with_context(|| format!("discovering git repo at {}", repo_path.display()))?;

    // Collect all branch tips for reachability checks.
    let branch_tips = collect_branch_tips(&repo);

    // Collect all reflog entries (HEAD + per-branch).
    let mut seen_oids: HashSet<git2::Oid> = HashSet::new();
    let mut findings = Vec::new();

    // Gather reflog names: HEAD + each local branch
    let mut reflog_names: Vec<String> = vec!["HEAD".to_string()];
    if let Ok(branches) = repo.branches(Some(BranchType::Local)) {
        for (branch, _) in branches.flatten() {
            if let Some(name) = branch.name().ok().flatten() {
                reflog_names.push(format!("refs/heads/{}", name));
            }
        }
    }

    for reflog_name in &reflog_names {
        let reflog = match repo.reflog(reflog_name) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let limit = cfg.max_entries_per_ref.min(reflog.len());
        for i in 0..limit {
            let entry = match reflog.get(i) {
                Some(e) => e,
                None => continue,
            };

            let oid = entry.id_new();
            if oid.is_zero() || !seen_oids.insert(oid) {
                continue;
            }

            let commit = match repo.find_commit(oid) {
                Ok(c) => c,
                Err(_) => continue, // object may have been GC'd
            };

            let author = commit.author();
            let email = author.email().unwrap_or("").to_string();

            // Check if author email matches AI emails
            let is_ai = cfg.ai_emails.iter().any(|e| e.eq_ignore_ascii_case(&email));
            if !is_ai {
                continue;
            }

            // Check if commit is reachable from any branch tip
            let reachable = branch_tips
                .iter()
                .any(|&tip| repo.graph_descendant_of(tip, oid).unwrap_or(false) || tip == oid);
            if reachable {
                continue;
            }

            // Unreachable AI commit found — emit finding
            let author_name = author.name().unwrap_or("").to_string();
            let commit_time = commit.time();
            let when = Utc
                .timestamp_opt(commit_time.seconds(), 0)
                .single()
                .unwrap_or_else(Utc::now);
            let message_first_line = commit
                .message()
                .unwrap_or("")
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            let sha_short = &oid.to_string()[..10];
            let reflog_source = format!("{}@{{{}}}", reflog_name, i);

            let evidence = vec![
                Evidence {
                    kind: "commit_sha".into(),
                    value: serde_json::json!(oid.to_string()),
                },
                Evidence {
                    kind: "author_email".into(),
                    value: serde_json::json!(email),
                },
                Evidence {
                    kind: "author_name".into(),
                    value: serde_json::json!(author_name),
                },
                Evidence {
                    kind: "commit_time".into(),
                    value: serde_json::json!(when.to_rfc3339()),
                },
                Evidence {
                    kind: "commit_message".into(),
                    value: serde_json::json!(message_first_line),
                },
                Evidence {
                    kind: "reflog_source".into(),
                    value: serde_json::json!(reflog_source),
                },
                Evidence {
                    kind: "reachable_from_branch".into(),
                    value: serde_json::Value::Null,
                },
            ];

            findings.push(Finding {
                id: Finding::stable_id(ScannerKind::Reflog, sha_short),
                scanner: ScannerKind::Reflog,
                severity: Severity::Low,
                locator: sha_short.to_string(),
                title: format!(
                    "Unreachable AI commit {} by {} in {}",
                    sha_short, email, reflog_source
                ),
                evidence,
                suggested_action: SuggestedAction::ReportOnly,
            });
        }
    }

    Ok(findings)
}

fn collect_branch_tips(repo: &Repository) -> Vec<git2::Oid> {
    let mut tips = Vec::new();
    for bt in [BranchType::Local, BranchType::Remote] {
        if let Ok(branches) = repo.branches(Some(bt)) {
            for (branch, _) in branches.flatten() {
                if let Ok(commit) = branch.get().peel_to_commit() {
                    tips.push(commit.id());
                }
            }
        }
    }
    tips
}
