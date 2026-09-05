use crate::model::{EvidenceStatus, Receipt};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

pub trait ApexProducerVerifier {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApexProducerAssertion {
    pub producer_id: String,
    pub key_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct AuthenticatedApexEvent(ApexExpertTraceEvent);
impl AuthenticatedApexEvent {
    pub fn as_event(&self) -> &ApexExpertTraceEvent {
        &self.0
    }
}

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
    pub schema_version: String,
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
    pub producer_id: String,
    pub producer_key_id: String,
    pub producer_signature: String,
}

impl ApexExpertTraceEvent {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != "zero-review.apex-event.v2" {
            bail!("unsupported Apex event schema version");
        }
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
        validate_identifier("producer_id", &self.producer_id)?;
        validate_identifier("producer_key_id", &self.producer_key_id)?;
        if self.producer_signature.len() != 128
            || !self
                .producer_signature
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            bail!("authenticated producer signature must be a lowercase Ed25519 signature");
        }
        if self.event_type == ApexEventType::Outcome && self.outcome_status.is_none() {
            bail!("outcome events require outcome_status");
        }
        Ok(())
    }
}

pub fn apex_event_from_receipt(receipt: &Receipt) -> Result<ApexExpertTraceEvent> {
    let _ = receipt;
    bail!("Apex event generation requires a release artifact and authenticated producer")
}

pub fn apex_producer_signing_payload(
    receipt: &Receipt,
    release_artifact: &Path,
    producer_id: &str,
    key_id: &str,
) -> Result<Vec<u8>> {
    if receipt.hash.len() != 64
        || !receipt
            .hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("receipt hash must contain 64 lowercase hexadecimal digits");
    }
    validate_identifier("producer_id", producer_id)?;
    validate_identifier("producer_key_id", key_id)?;
    let release_bytes = fs::read(release_artifact)
        .with_context(|| format!("read release artifact {}", release_artifact.display()))?;
    let release_digest = format!("sha256:{}", hex::encode(Sha256::digest(release_bytes)));
    let subject = hex::encode(Sha256::digest(receipt.subject.as_bytes()));
    apex_signing_payload_from_digest(receipt, &release_digest, &subject, producer_id, key_id)
}

fn apex_signing_payload_from_digest(
    receipt: &Receipt,
    release_digest: &str,
    subject_digest: &str,
    producer_id: &str,
    key_id: &str,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct Envelope<'a> {
        domain: &'static str,
        schema_version: &'static str,
        signature_algorithm: &'static str,
        event_id: String,
        trace_id: String,
        release_digest: &'a str,
        receipt_sha256: String,
        timestamp_utc: &'a str,
        producer_id: &'a str,
        producer_key_id: &'a str,
    }
    serde_json::to_vec(&Envelope {
        domain: "zero-review.apex-producer-signature.v1",
        schema_version: "zero-review.apex-event.v2",
        signature_algorithm: "ed25519",
        event_id: format!("zero-review-{}", &receipt.hash[..16]),
        trace_id: format!("zero-review-{subject_digest}"),
        release_digest,
        receipt_sha256: format!("sha256:{}", receipt.hash),
        timestamp_utc: &receipt.timestamp,
        producer_id,
        producer_key_id: key_id,
    })
    .context("serialize Apex producer signing payload")
}

pub fn apex_event_from_receipt_authenticated(
    receipt: &Receipt,
    release_artifact: &Path,
    producer: &ApexProducerAssertion,
    verifier: &dyn ApexProducerVerifier,
) -> Result<AuthenticatedApexEvent> {
    if receipt.hash.len() != 64
        || !receipt
            .hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("receipt hash must contain 64 lowercase hexadecimal digits");
    }
    let release_bytes = fs::read(release_artifact)
        .with_context(|| format!("read release artifact {}", release_artifact.display()))?;
    let release = hex::encode(Sha256::digest(release_bytes));
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
        schema_version: "zero-review.apex-event.v2".into(),
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
        producer_id: producer.producer_id.clone(),
        producer_key_id: producer.key_id.clone(),
        producer_signature: producer.signature.clone(),
    };
    event.validate()?;
    let payload = apex_signing_payload_from_digest(
        receipt,
        &event.release_digest,
        &subject,
        &producer.producer_id,
        &producer.key_id,
    )?;
    if !verifier.verify(&producer.key_id, &payload, &producer.signature) {
        bail!("Apex producer signature verification failed");
    }
    Ok(AuthenticatedApexEvent(event))
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
        struct Yes;
        impl ApexProducerVerifier for Yes {
            fn verify(&self, _: &str, _: &[u8], signature: &str) -> bool {
                signature == "a".repeat(128)
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let artifact = directory.path().join("zero-review.exe");
        fs::write(&artifact, b"actual-release-binary").unwrap();
        let producer = ApexProducerAssertion {
            producer_id: "producer:ci".into(),
            key_id: "key-1".into(),
            signature: "a".repeat(128),
        };
        let event =
            apex_event_from_receipt_authenticated(&receipt, &artifact, &producer, &Yes).unwrap();
        assert_eq!(event.as_event().event_type, ApexEventType::Outcome);
        assert_eq!(
            event.as_event().policy_decision,
            ApexPolicyDecision::Allowed
        );
        event.as_event().validate().unwrap();
        assert_eq!(
            event.as_event().release_digest,
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest(b"actual-release-binary"))
            )
        );
    }

    #[test]
    fn legacy_unsigned_generation_fails_closed() {
        let receipt = Receipt {
            timestamp: "2026-08-22T17:50:12+00:00".into(),
            operation: "review".into(),
            subject: "repo".into(),
            status: EvidenceStatus::Verified,
            evidence: vec![],
            previous_hash: String::new(),
            hash: "a".repeat(64),
        };
        assert!(apex_event_from_receipt(&receipt).is_err());
    }
}
