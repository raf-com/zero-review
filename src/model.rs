use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatus {
    Verified,
    Partial,
    Blocked,
    OwnerGated,
    NotProven,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub source: String,
    pub severity: Severity,
    pub summary: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    pub status: EvidenceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewInput {
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    pub repository: PathBuf,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub required_controls: Vec<String>,
}

fn default_schema_version() -> String {
    "zero-review.findings.v1".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewNeed {
    pub id: String,
    pub title: String,
    pub owner: String,
    pub required_for: Vec<String>,
    pub evidence: Vec<String>,
    pub blocking: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Pass,
    NeedsReview,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewDecision {
    pub decision: Decision,
    pub reasons: Vec<String>,
    pub missing_controls: Vec<String>,
    pub finding_count: usize,
    pub blocking_count: usize,
    pub unproven_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    pub id: String,
    pub kind: String,
    pub path: String,
    pub status: EvidenceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inventory {
    pub repository: String,
    pub generated_at: String,
    pub controls: Vec<Control>,
    pub needs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub timestamp: String,
    pub operation: String,
    pub subject: String,
    pub status: EvidenceStatus,
    pub evidence: Vec<String>,
    pub previous_hash: String,
    pub hash: String,
}
