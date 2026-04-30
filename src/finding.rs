//! Finding data model (spec §4.2).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScannerKind {
    Branch,
    Reflog,
    Tree,
    Author,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Some(Self::Info),
            "low" => Some(Self::Low),
            "medium" | "med" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" | "crit" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SuggestedAction {
    ReportOnly,
    ReviewAndConfirm {
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        suggested_command: Option<String>,
    },
    SafeToDelete {
        reason: String,
        suggested_command: String,
    },
    HardVeto {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub scanner: ScannerKind,
    pub severity: Severity,
    pub locator: String,
    pub title: String,
    pub evidence: Vec<Evidence>,
    pub suggested_action: SuggestedAction,
}

impl Finding {
    /// Build a stable id from (scanner, locator). Short blake3 prefix.
    pub fn stable_id(scanner: ScannerKind, locator: &str) -> String {
        let label = match scanner {
            ScannerKind::Branch => "branch",
            ScannerKind::Reflog => "reflog",
            ScannerKind::Tree => "tree",
            ScannerKind::Author => "author",
        };
        let mut hasher = blake3::Hasher::new();
        hasher.update(label.as_bytes());
        hasher.update(b"|");
        hasher.update(locator.as_bytes());
        let hash = hasher.finalize();
        let hex = hash.to_hex();
        format!("aft-git-{}", &hex.as_str()[..6])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_parse_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert_eq!(Severity::parse("HIGH"), Some(Severity::High));
        assert_eq!(Severity::parse("crit"), Some(Severity::Critical));
        assert_eq!(Severity::parse("nope"), None);
    }

    #[test]
    fn stable_id_is_deterministic() {
        let a = Finding::stable_id(ScannerKind::Branch, "claude/refactor");
        let b = Finding::stable_id(ScannerKind::Branch, "claude/refactor");
        assert_eq!(a, b);
        let c = Finding::stable_id(ScannerKind::Branch, "other");
        assert_ne!(a, c);
        assert!(a.starts_with("aft-git-"));
    }
}
