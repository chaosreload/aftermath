// aftermath v0.1 — Scan Git repos for AI-agent footprints
//
// Commands:
//   aftermath init               write default .aftermath.toml
//   aftermath scan [path]        run enabled scanners
//   aftermath explain <id>       show evidence chain for a finding
//
// v0.1 is READ-ONLY. No mutation of the target repo.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

mod config;
mod finding;
mod output;
mod scanner;

#[derive(Parser)]
#[command(
    name = "aftermath",
    version,
    about = "Scan Git repos for AI-agent footprints"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Write default .aftermath.toml to the current directory
    Init {
        /// Overwrite existing config
        #[arg(long)]
        force: bool,
    },
    /// Scan a Git repository for AI-agent footprints
    Scan {
        /// Path to the repository (defaults to cwd)
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Only run a specific scanner kind (branch, tree, reflog, author). Repeat for multiple.
        #[arg(long)]
        kind: Vec<ScannerKindArg>,
        /// Output format
        #[arg(long, value_enum, default_value_t = OutputFormat::Summary)]
        format: OutputFormat,
        /// Minimum severity to include (info, low, medium, high, critical)
        #[arg(long, default_value = "info")]
        min_severity: String,
        /// Explicit config file (defaults to .aftermath.toml in repo root)
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Explain a finding by id (reads from the last scan report)
    Explain {
        /// Finding id
        id: String,
        /// Path to a previously-saved JSON report
        #[arg(long)]
        report: Option<PathBuf>,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum ScannerKindArg {
    Branch,
    Tree,
    Reflog,
    Author,
}

#[derive(Copy, Clone, ValueEnum)]
enum OutputFormat {
    Summary,
    Json,
    Markdown,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init { force } => cmd_init(force),
        Command::Scan {
            path,
            kind,
            format,
            min_severity,
            config,
        } => cmd_scan(path, kind, format, min_severity, config),
        Command::Explain { id, report } => cmd_explain(id, report),
    }
}

fn cmd_init(force: bool) -> Result<()> {
    let path = PathBuf::from(".aftermath.toml");
    if path.exists() && !force {
        anyhow::bail!(".aftermath.toml already exists; pass --force to overwrite");
    }
    std::fs::write(&path, config::DEFAULT_CONFIG)
        .with_context(|| format!("writing {}", path.display()))?;
    println!("Wrote {}", path.display());
    Ok(())
}

fn cmd_scan(
    path: PathBuf,
    kinds: Vec<ScannerKindArg>,
    format: OutputFormat,
    min_severity: String,
    config_path: Option<PathBuf>,
) -> Result<()> {
    let cfg = config::Config::load(&path, config_path.as_deref())?;
    let min_sev = finding::Severity::parse(&min_severity)
        .ok_or_else(|| anyhow::anyhow!("invalid --min-severity: {min_severity}"))?;

    let mut findings = Vec::new();
    let run_branch = kinds.is_empty() || kinds.iter().any(|k| matches!(k, ScannerKindArg::Branch));
    let run_tree = kinds.is_empty() || kinds.iter().any(|k| matches!(k, ScannerKindArg::Tree));
    let run_reflog = kinds.is_empty() || kinds.iter().any(|k| matches!(k, ScannerKindArg::Reflog));
    let run_author = kinds.is_empty() || kinds.iter().any(|k| matches!(k, ScannerKindArg::Author));

    if run_branch {
        findings.extend(scanner::branch::scan(&path, &cfg.branch_scanner)?);
    }
    if run_tree {
        findings.extend(scanner::tree::scan(&path, &cfg.tree_scanner)?);
    }
    if run_reflog {
        findings.extend(scanner::reflog::scan(&path, &cfg.reflog_scanner)?);
    }
    if run_author {
        findings.extend(scanner::author::scan(&path, &cfg.author_scanner)?);
    }

    findings.retain(|f| f.severity as u8 >= min_sev as u8);

    // Always save last report to ~/.cache/aftermath/last-report.json
    if let Some(home) = std::env::var_os("HOME") {
        let cache_dir = PathBuf::from(home).join(".cache/aftermath");
        if let Err(e) = std::fs::create_dir_all(&cache_dir) {
            eprintln!("warning: could not create {}: {e}", cache_dir.display());
        } else {
            let report_path = cache_dir.join("last-report.json");
            match serde_json::to_string_pretty(&findings) {
                Ok(json) => {
                    if let Err(e) = std::fs::write(&report_path, json) {
                        eprintln!("warning: could not write {}: {e}", report_path.display());
                    }
                }
                Err(e) => {
                    eprintln!("warning: could not serialize findings: {e}");
                }
            }
        }
    }

    match format {
        OutputFormat::Summary => output::render_summary(&findings),
        OutputFormat::Json => output::render_json(&findings)?,
        OutputFormat::Markdown => output::render_markdown(&findings),
    }
    Ok(())
}

fn cmd_explain(id: String, report: Option<PathBuf>) -> Result<()> {
    let path = report.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/root"));
        PathBuf::from(home).join(".cache/aftermath/last-report.json")
    });
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("reading report {}", path.display()))?;
    let findings: Vec<finding::Finding> = serde_json::from_str(&data)?;
    match findings.iter().find(|f| f.id == id) {
        Some(f) => {
            println!("{}", serde_json::to_string_pretty(f)?);
            Ok(())
        }
        None => anyhow::bail!("finding id '{id}' not found in {}", path.display()),
    }
}
