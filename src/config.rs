//! Config loader — .aftermath.toml with branch_scanner + tree_scanner sections.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG: &str = r#"# .aftermath.toml — aftermath v0.1 configuration
# See https://github.com/chaosreload/aftermath for docs.

[branch_scanner]
# Branch-name prefixes that signal an AI-agent branch
ai_prefixes = ["claude/", "codex/", "agent/", "aider/", "openclaw/", "ai-"]
# Author emails known to belong to AI agents
ai_emails = ["noreply@anthropic.com", "noreply@openai.com"]
# Days of inactivity before a branch is considered stale
stale_days = 30
# When scanning remote-tracking branches too, set true
include_remotes = false

[tree_scanner]
# .gitignore-style patterns. severity = info | low | medium | high | critical
# action = report | review | safe-to-delete | hard-veto
patterns = [
  { pattern = ".venv/",            severity = "high",     action = "safe-to-delete" },
  { pattern = "venv/",             severity = "high",     action = "safe-to-delete" },
  { pattern = "env/",              severity = "medium",   action = "review" },
  { pattern = "node_modules/",     severity = "high",     action = "safe-to-delete" },
  { pattern = ".env",              severity = "critical", action = "review" },
  { pattern = ".env.local",        severity = "critical", action = "review" },
  { pattern = "*.tmp",             severity = "low",      action = "safe-to-delete" },
  { pattern = "*.swp",             severity = "low",      action = "safe-to-delete" },
  { pattern = ".DS_Store",         severity = "low",      action = "safe-to-delete" },
  { pattern = "PR-*-description.md", severity = "low",    action = "report" },
  { pattern = "PR-*.md",           severity = "low",      action = "report" },
  { pattern = "CLAUDE-*.md",       severity = "info",     action = "report" },
  { pattern = "*.secret",          severity = "critical", action = "review" },
]
# Flag files larger than this (bytes) unless ignored above
max_tracked_bytes = 1048576
# Flag symlinks as suspicious
flag_symlinks = true
# How many recent commits to scan beyond HEAD
recent_commits = 20

[reflog_scanner]
# Author emails to flag in reflog (unreachable AI commits)
ai_emails = ["noreply@anthropic.com", "noreply@openai.com"]
# Max reflog entries to inspect per ref
max_entries_per_ref = 1000

[author_scanner]
# How many recent commits to analyze
window_size = 100
# Flag repo if AI-authored commit ratio exceeds this
flag_if_ai_ratio_above = 0.3
"#;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub branch_scanner: BranchConfig,
    #[serde(default)]
    pub tree_scanner: TreeConfig,
    #[serde(default)]
    pub reflog_scanner: ReflogConfig,
    #[serde(default)]
    pub author_scanner: AuthorConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BranchConfig {
    #[serde(default = "default_prefixes")]
    pub ai_prefixes: Vec<String>,
    #[serde(default = "default_emails")]
    pub ai_emails: Vec<String>,
    #[serde(default = "default_stale_days")]
    pub stale_days: i64,
    #[serde(default)]
    pub include_remotes: bool,
}

impl Default for BranchConfig {
    fn default() -> Self {
        Self {
            ai_prefixes: default_prefixes(),
            ai_emails: default_emails(),
            stale_days: default_stale_days(),
            include_remotes: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TreeConfig {
    #[serde(default = "default_tree_patterns")]
    pub patterns: Vec<PatternRule>,
    #[serde(default = "default_max_bytes")]
    pub max_tracked_bytes: u64,
    #[serde(default = "default_flag_symlinks")]
    pub flag_symlinks: bool,
    #[serde(default = "default_recent_commits")]
    pub recent_commits: u32,
}

impl Default for TreeConfig {
    fn default() -> Self {
        Self {
            patterns: default_tree_patterns(),
            max_tracked_bytes: default_max_bytes(),
            flag_symlinks: default_flag_symlinks(),
            recent_commits: default_recent_commits(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReflogConfig {
    #[serde(default = "default_emails")]
    pub ai_emails: Vec<String>,
    #[serde(default = "default_max_entries_per_ref")]
    pub max_entries_per_ref: usize,
}

impl Default for ReflogConfig {
    fn default() -> Self {
        Self {
            ai_emails: default_emails(),
            max_entries_per_ref: default_max_entries_per_ref(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthorConfig {
    #[serde(default = "default_emails")]
    pub ai_emails: Vec<String>,
    #[serde(default = "default_window_size")]
    pub window_size: u32,
    #[serde(default = "default_ai_ratio_threshold")]
    pub flag_if_ai_ratio_above: f64,
}

impl Default for AuthorConfig {
    fn default() -> Self {
        Self {
            ai_emails: default_emails(),
            window_size: default_window_size(),
            flag_if_ai_ratio_above: default_ai_ratio_threshold(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PatternRule {
    pub pattern: String,
    pub severity: String,
    pub action: String,
}

fn default_prefixes() -> Vec<String> {
    vec![
        "claude/".into(),
        "codex/".into(),
        "agent/".into(),
        "aider/".into(),
        "openclaw/".into(),
        "ai-".into(),
    ]
}

fn default_emails() -> Vec<String> {
    vec!["noreply@anthropic.com".into(), "noreply@openai.com".into()]
}

fn default_stale_days() -> i64 {
    30
}

fn default_max_bytes() -> u64 {
    1_048_576
}

fn default_flag_symlinks() -> bool {
    true
}

fn default_recent_commits() -> u32 {
    20
}

fn default_max_entries_per_ref() -> usize {
    1000
}

fn default_window_size() -> u32 {
    100
}

fn default_ai_ratio_threshold() -> f64 {
    0.3
}

fn default_tree_patterns() -> Vec<PatternRule> {
    vec![
        PatternRule {
            pattern: ".venv/".into(),
            severity: "high".into(),
            action: "safe-to-delete".into(),
        },
        PatternRule {
            pattern: "node_modules/".into(),
            severity: "high".into(),
            action: "safe-to-delete".into(),
        },
        PatternRule {
            pattern: ".env".into(),
            severity: "critical".into(),
            action: "review".into(),
        },
        PatternRule {
            pattern: "*.tmp".into(),
            severity: "low".into(),
            action: "safe-to-delete".into(),
        },
        PatternRule {
            pattern: ".DS_Store".into(),
            severity: "low".into(),
            action: "safe-to-delete".into(),
        },
        PatternRule {
            pattern: "PR-*-description.md".into(),
            severity: "low".into(),
            action: "report".into(),
        },
        PatternRule {
            pattern: "*.secret".into(),
            severity: "critical".into(),
            action: "review".into(),
        },
    ]
}

impl Config {
    pub fn load(repo_path: &Path, explicit: Option<&Path>) -> Result<Self> {
        let path = if let Some(p) = explicit {
            Some(PathBuf::from(p))
        } else {
            let candidate = repo_path.join(".aftermath.toml");
            if candidate.exists() {
                Some(candidate)
            } else {
                None
            }
        };

        match path {
            Some(p) => {
                let data = std::fs::read_to_string(&p)
                    .with_context(|| format!("reading config {}", p.display()))?;
                let cfg: Config =
                    toml::from_str(&data).with_context(|| format!("parsing {}", p.display()))?;
                Ok(cfg)
            }
            None => Ok(Self::default()),
        }
    }
}
