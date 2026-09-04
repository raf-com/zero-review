use crate::model::{EvidenceStatus, Receipt};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApexEventType {
    Invocation,
    Outcome,
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApexPolicyDecision {
    Allowed,
    Denied,
    ApprovalRequired,
    Suspended,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApexEvaluationStatus {
    NotRun,
    Pass,
    Partial,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApexOutcomeStatus {
    Succeeded,
    Failed,
    Abstained,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApexExpertTraceEvent {
    pub event_id: String,
    pub trace_id: String,
    pub task_id: Option<String>,
    pub expert_id: String,
    pub release_digest: String,
    pub receipt_id: String,
    pub receipt_sha256: String,
    pub event_type: ApexEventType,
    pub timestamp_utc: String,
    pub policy_decision: ApexPolicyDecision,
    pub evaluation_status: ApexEvaluationStatus,
    pub tool_name: Option<String>,
    pub tool_result_sha256: Option<String>,
    pub outcome_status: Option<ApexOutcomeStatus>,
}

impl ApexExpertTraceEvent {
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("event_id", self.event_id.as_str()),
            ("trace_id", self.trace_id.as_str()),
            ("expert_id", self.expert_id.as_str()),
            ("receipt_id", self.receipt_id.as_str()),
            ("timestamp_utc", self.timestamp_utc.as_str()),
        ] {
            validate_identifier(name, value)?;
        }
        if !self.expert_id.starts_with("expert:") {
            bail!("expert_id must use the expert: namespace");
        }
        if !self.receipt_id.starts_with("expert-manifest-") {
            bail!("receipt_id must use the expert-manifest- namespace");
        }
        validate_sha256("release_digest", &self.release_digest)?;
        validate_sha256("receipt_sha256", &self.receipt_sha256)?;
        if self.event_type == ApexEventType::Outcome && self.outcome_status.is_none() {
            bail!("outcome events require outcome_status");
        }
        Ok(())
    }
}

pub fn apex_event_from_receipt(receipt: &Receipt) -> Result<ApexExpertTraceEvent> {
    if receipt.hash.len() != 64
        || !receipt
            .hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("receipt hash must contain 64 lowercase hexadecimal digits");
    }
    let release = hex::encode(Sha256::digest(b"zero-review:0.1.0"));
    let subject = hex::encode(Sha256::digest(receipt.subject.as_bytes()));
    let (policy_decision, evaluation_status, outcome_status) = match receipt.status {
        EvidenceStatus::Verified => (
            ApexPolicyDecision::Allowed,
            ApexEvaluationStatus::Pass,
            ApexOutcomeStatus::Succeeded,
        ),
        EvidenceStatus::Blocked => (
            ApexPolicyDecision::Denied,
            ApexEvaluationStatus::Fail,
            ApexOutcomeStatus::Failed,
        ),
        EvidenceStatus::OwnerGated => (
            ApexPolicyDecision::ApprovalRequired,
            ApexEvaluationStatus::Partial,
            ApexOutcomeStatus::Abstained,
        ),
        EvidenceStatus::Partial | EvidenceStatus::NotProven => (
            ApexPolicyDecision::ApprovalRequired,
            ApexEvaluationStatus::Partial,
            ApexOutcomeStatus::Abstained,
        ),
    };
    let event = ApexExpertTraceEvent {
        event_id: format!("zero-review-{}", &receipt.hash[..16]),
        trace_id: format!("zero-review-{subject}"),
        task_id: None,
        expert_id: "expert:zero-review".into(),
        release_digest: format!("sha256:{release}"),
        receipt_id: format!("expert-manifest-zero-review-{}", &receipt.hash[..16]),
        receipt_sha256: format!("sha256:{}", receipt.hash),
        event_type: ApexEventType::Outcome,
        timestamp_utc: receipt.timestamp.clone(),
        policy_decision,
        evaluation_status,
        tool_name: Some("zero-review".into()),
        tool_result_sha256: Some(format!("sha256:{}", receipt.hash)),
        outcome_status: Some(outcome_status),
    };
    event.validate()?;
    Ok(event)
}

fn validate_identifier(name: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'-' | b'+' | b'/')
        })
    {
        bail!("{name} is not a constrained Apex identifier");
    }
    Ok(())
}

fn validate_sha256(name: &str, value: &str) -> Result<()> {
    let Some(value) = value.strip_prefix("sha256:") else {
        bail!("{name} must use the sha256: prefix");
    };
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{name} must contain 64 lowercase hexadecimal digits");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_maps_to_valid_apex_outcome() {
        let receipt = Receipt {
            timestamp: "2026-08-22T17:50:12+00:00".into(),
            operation: "inventory".into(),
            subject: r"C:\webapp_core".into(),
            status: EvidenceStatus::Verified,
            evidence: vec!["inventory.json".into()],
            previous_hash: String::new(),
            hash: "a".repeat(64),
        };
        let event = apex_event_from_receipt(&receipt).unwrap();
        assert_eq!(event.event_type, ApexEventType::Outcome);
        assert_eq!(event.policy_decision, ApexPolicyDecision::Allowed);
        event.validate().unwrap();
    }
}
