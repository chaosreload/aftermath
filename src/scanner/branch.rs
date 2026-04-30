//! branch_scanner — detects AI-agent and stale branches (spec §3.1 target 1).

use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use git2::{BranchType, Repository};
use std::path::Path;

use crate::config::BranchConfig;
use crate::finding::{Evidence, Finding, ScannerKind, Severity, SuggestedAction};

pub fn scan(repo_path: &Path, cfg: &BranchConfig) -> Result<Vec<Finding>> {
    let repo = Repository::discover(repo_path)
        .with_context(|| format!("discovering git repo at {}", repo_path.display()))?;

    let now = Utc::now();
    let mut findings = Vec::new();

    // Find main / master / default branch tip for "behind" comparison.
    let main_oid = find_default_branch_tip(&repo);

    let branch_types: &[BranchType] = if cfg.include_remotes {
        &[BranchType::Local, BranchType::Remote]
    } else {
        &[BranchType::Local]
    };

    for bt in branch_types {
        let iter = match repo.branches(Some(*bt)) {
            Ok(i) => i,
            Err(_) => continue,
        };
        for item in iter {
            let (branch, _) = match item {
                Ok(b) => b,
                Err(_) => continue,
            };
            let name = match branch.name().ok().flatten() {
                Some(n) => n.to_string(),
                None => continue,
            };
            // Skip the default branch itself
            if name == "HEAD" || name.ends_with("/HEAD") {
                continue;
            }

            let commit = match branch.get().peel_to_commit() {
                Ok(c) => c,
                Err(_) => continue,
            };
            let commit_time = commit.time();
            let when: DateTime<Utc> = Utc
                .timestamp_opt(commit_time.seconds(), 0)
                .single()
                .unwrap_or_else(Utc::now);
            let age_days = (now - when).num_days();

            let author = commit.author();
            let email = author.email().unwrap_or("").to_string();
            let author_name = author.name().unwrap_or("").to_string();

            let matched_prefix = cfg
                .ai_prefixes
                .iter()
                .find(|p| name.starts_with(p.as_str()))
                .cloned();
            let matched_email = cfg.ai_emails.iter().any(|e| e.eq_ignore_ascii_case(&email));
            let is_stale = age_days > cfg.stale_days;

            // Default branch itself: skip
            if let Some(m) = main_oid {
                if commit.id() == m && (name == "main" || name == "master") {
                    continue;
                }
            }

            let behind = main_oid
                .and_then(|m| repo.graph_ahead_behind(m, commit.id()).ok())
                .map(|(_ahead_of_main_from_branch, behind)| behind)
                .unwrap_or(0);

            // Decision: flag if AI-prefix OR (stale AND behind>0) OR (ai email AND behind>0)
            let flag_reason = if matched_prefix.is_some() {
                Some("ai_prefix")
            } else if is_stale && behind > 0 {
                Some("stale_and_behind")
            } else if matched_email && behind > 0 {
                Some("ai_email_and_behind")
            } else {
                None
            };

            let reason = match flag_reason {
                Some(r) => r,
                None => continue,
            };

            let mut evidence = vec![
                Evidence {
                    kind: "branch_name".into(),
                    value: serde_json::json!(name),
                },
                Evidence {
                    kind: "branch_age_days".into(),
                    value: serde_json::json!(age_days),
                },
                Evidence {
                    kind: "commits_behind_default".into(),
                    value: serde_json::json!(behind),
                },
                Evidence {
                    kind: "last_author_email".into(),
                    value: serde_json::json!(email),
                },
                Evidence {
                    kind: "last_author_name".into(),
                    value: serde_json::json!(author_name),
                },
                Evidence {
                    kind: "flag_reason".into(),
                    value: serde_json::json!(reason),
                },
            ];
            if let Some(p) = &matched_prefix {
                evidence.push(Evidence {
                    kind: "name_matches_pattern".into(),
                    value: serde_json::json!(p),
                });
            }

            let severity = match (matched_prefix.is_some(), is_stale, behind) {
                (true, true, _) => Severity::Medium,
                (true, false, _) => Severity::Low,
                (_, true, b) if b > 50 => Severity::Medium,
                _ => Severity::Low,
            };

            let title = format!(
                "{} branch '{}': {}d old, behind default by {} commits",
                match bt {
                    BranchType::Local => "Local",
                    BranchType::Remote => "Remote",
                },
                name,
                age_days,
                behind
            );

            let suggested_action = if matched_prefix.is_some() {
                SuggestedAction::ReviewAndConfirm {
                    reason: "AI-agent branch; likely a finished or abandoned experiment.".into(),
                    suggested_command: Some(format!(
                        "git branch -D {}  # reversible via reflog within gc.reflogexpire",
                        name
                    )),
                }
            } else {
                SuggestedAction::ReportOnly
            };

            findings.push(Finding {
                id: Finding::stable_id(ScannerKind::Branch, &name),
                scanner: ScannerKind::Branch,
                severity,
                locator: name.clone(),
                title,
                evidence,
                suggested_action,
            });
        }
    }

    Ok(findings)
}

fn find_default_branch_tip(repo: &Repository) -> Option<git2::Oid> {
    for name in ["main", "master"] {
        if let Ok(b) = repo.find_branch(name, BranchType::Local) {
            if let Ok(c) = b.get().peel_to_commit() {
                return Some(c.id());
            }
        }
    }
    None
}
