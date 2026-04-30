//! Output renderers — summary / json / markdown.

use crate::finding::{Finding, SuggestedAction};
use anyhow::Result;

pub fn render_summary(findings: &[Finding]) {
    if findings.is_empty() {
        println!("aftermath: no findings (repo is clean or rules don't apply)");
        return;
    }
    println!("aftermath: {} findings", findings.len());
    println!();
    for f in findings {
        println!(
            "  [{}] {:<8} {:<10} {}",
            f.id,
            f.severity.as_str(),
            scanner_label(f),
            f.title
        );
    }
    println!();
    println!("Run `aftermath explain <id>` or re-run with --format=markdown for details.");
}

pub fn render_json(findings: &[Finding]) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(findings)?);
    Ok(())
}

pub fn render_markdown(findings: &[Finding]) {
    if findings.is_empty() {
        println!("# aftermath report\n\nNo findings.");
        return;
    }
    println!("# aftermath report\n");
    println!("**{}** findings.\n", findings.len());
    println!("| id | severity | scanner | title |");
    println!("|----|----------|---------|-------|");
    for f in findings {
        println!(
            "| `{}` | {} | {} | {} |",
            f.id,
            f.severity.as_str(),
            scanner_label(f),
            f.title
        );
    }
    println!();
    for f in findings {
        println!("---\n");
        println!("## {} — {}\n", f.id, f.title);
        println!("- **scanner**: {}", scanner_label(f));
        println!("- **severity**: {}", f.severity.as_str());
        println!("- **locator**: `{}`\n", f.locator);
        println!("### evidence\n");
        for e in &f.evidence {
            println!("- `{}`: {}", e.kind, e.value);
        }
        println!("\n### suggested action\n");
        match &f.suggested_action {
            SuggestedAction::ReportOnly => println!("Report only."),
            SuggestedAction::ReviewAndConfirm {
                reason,
                suggested_command,
            } => {
                println!("**Review and confirm**: {}\n", reason);
                if let Some(c) = suggested_command {
                    println!("```sh\n{}\n```", c);
                }
            }
            SuggestedAction::SafeToDelete {
                reason,
                suggested_command,
            } => {
                println!("**Safe to delete**: {}\n", reason);
                println!("```sh\n{}\n```", suggested_command);
            }
            SuggestedAction::HardVeto { reason } => {
                println!("**Hard veto (do not touch)**: {}", reason);
            }
        }
        println!();
    }
}

fn scanner_label(f: &Finding) -> &'static str {
    match f.scanner {
        crate::finding::ScannerKind::Branch => "branch",
        crate::finding::ScannerKind::Reflog => "reflog",
        crate::finding::ScannerKind::Tree => "tree",
        crate::finding::ScannerKind::Author => "author",
    }
}
