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
        /// Only run a specific scanner kind (branch, tree). Repeat for multiple.
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

    if run_branch {
        findings.extend(scanner::branch::scan(&path, &cfg.branch_scanner)?);
    }
    if run_tree {
        findings.extend(scanner::tree::scan(&path, &cfg.tree_scanner)?);
    }

    findings.retain(|f| f.severity as u8 >= min_sev as u8);

    match format {
        OutputFormat::Summary => output::render_summary(&findings),
        OutputFormat::Json => output::render_json(&findings)?,
        OutputFormat::Markdown => output::render_markdown(&findings),
    }
    Ok(())
}

fn cmd_explain(id: String, report: Option<PathBuf>) -> Result<()> {
    let path = report.unwrap_or_else(|| PathBuf::from(".aftermath/last-report.json"));
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
