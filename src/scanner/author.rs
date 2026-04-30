//! author_scanner — analyzes commit-author distribution, flags AI-dominated repos.

use anyhow::{Context, Result};
use git2::Repository;
use std::collections::HashMap;
use std::path::Path;

use crate::config::AuthorConfig;
use crate::finding::{Evidence, Finding, ScannerKind, Severity, SuggestedAction};

pub fn scan(repo_path: &Path, cfg: &AuthorConfig) -> Result<Vec<Finding>> {
    let repo = Repository::discover(repo_path)
        .with_context(|| format!("discovering git repo at {}", repo_path.display()))?;

    let mut revwalk = repo.revwalk()?;
    revwalk.push_head().ok();

    let mut counts: HashMap<String, u64> = HashMap::new();
    let mut total: u64 = 0;

    let limit = cfg.window_size as usize;
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
        let email = commit.author().email().unwrap_or("").to_lowercase();
        *counts.entry(email).or_insert(0) += 1;
        total += 1;
    }

    if total == 0 {
        return Ok(Vec::new());
    }

    let ai_commits: u64 = counts
        .iter()
        .filter(|(email, _)| {
            cfg.ai_emails
                .iter()
                .any(|ai| ai.eq_ignore_ascii_case(email))
        })
        .map(|(_, c)| c)
        .sum();

    let human_commits = total - ai_commits;
    let ai_ratio = ai_commits as f64 / total as f64;

    if ai_ratio < cfg.flag_if_ai_ratio_above {
        return Ok(Vec::new());
    }

    // Build top-3 authors by count
    let mut sorted: Vec<(&String, &u64)> = counts.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    let top_3: Vec<serde_json::Value> = sorted
        .iter()
        .take(3)
        .map(|(email, count)| serde_json::json!({"email": email, "count": count}))
        .collect();

    let severity = if ai_ratio >= 0.7 {
        Severity::High
    } else {
        Severity::Medium
    };

    let locator = format!("HEAD~{}..HEAD", total);
    let ai_ratio_str = format!("{:.2}", ai_ratio);

    let evidence = vec![
        Evidence {
            kind: "total_commits".into(),
            value: serde_json::json!(total),
        },
        Evidence {
            kind: "ai_commits".into(),
            value: serde_json::json!(ai_commits),
        },
        Evidence {
            kind: "human_commits".into(),
            value: serde_json::json!(human_commits),
        },
        Evidence {
            kind: "ai_ratio".into(),
            value: serde_json::json!(ai_ratio_str),
        },
        Evidence {
            kind: "top_3_authors_by_count".into(),
            value: serde_json::json!(top_3),
        },
        Evidence {
            kind: "window_size".into(),
            value: serde_json::json!(cfg.window_size),
        },
    ];

    let findings = vec![Finding {
        id: Finding::stable_id(ScannerKind::Author, &locator),
        scanner: ScannerKind::Author,
        severity,
        locator,
        title: format!(
            "AI-authored ratio {:.0}% over last {} commits ({} AI / {} human)",
            ai_ratio * 100.0,
            total,
            ai_commits,
            human_commits,
        ),
        evidence,
        suggested_action: SuggestedAction::ReportOnly,
    }];

    Ok(findings)
}
