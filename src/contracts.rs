use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PR_CONTEXT_SCHEMA_V1: &str = "zero-review.pr-context.v1";
pub const REVIEW_PACKET_SCHEMA_V1: &str = "zero-review.review-packet.v1";
pub const OVERRIDE_SCHEMA_V1: &str = "zero-review.override.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PullRequestContext {
    pub schema_version: String,
    pub repository: String,
    pub pull_request_number: u64,
    pub author: String,
    pub base_sha: String,
    pub head_sha: String,
    pub captured_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewEvidence {
    pub kind: String,
    pub location: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDisposition {
    Approve,
    RequestChanges,
    Abstain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewPacket {
    pub schema_version: String,
    pub context: PullRequestContext,
    pub reviewer: String,
    pub disposition: ReviewDisposition,
    pub summary: String,
    pub evidence: Vec<ReviewEvidence>,
    pub reviewed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewOverride {
    pub schema_version: String,
    pub repository: String,
    pub pull_request_number: u64,
    pub head_sha: String,
    pub requested_by: String,
    pub approved_by: String,
    pub reason: String,
    pub evidence: Vec<ReviewEvidence>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ValidationContext<'a> {
    pub expected_head_sha: &'a str,
    pub now: DateTime<Utc>,
    pub maximum_context_age: Duration,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ContractError {
    #[error("unsupported schema version for {contract}: {actual}")]
    UnknownSchemaVersion {
        contract: &'static str,
        actual: String,
    },
    #[error("{field} must not be empty")]
    MissingField { field: &'static str },
    #[error("{field} must be a 40-character hexadecimal Git SHA")]
    InvalidSha { field: &'static str },
    #[error("head SHA is stale: expected {expected}, received {actual}")]
    StaleHeadSha { expected: String, actual: String },
    #[error("PR context is stale")]
    StaleContext,
    #[error("base and head SHAs must differ")]
    IdenticalBaseAndHead,
    #[error("reviewer or override approver must be independent")]
    SelfApproval,
    #[error("at least one complete evidence item is required")]
    MissingEvidence,
    #[error("override has expired")]
    ExpiredOverride,
    #[error("override expiry must be later than its issue time")]
    InvalidOverrideWindow,
}

impl PullRequestContext {
    pub fn validate(&self, validation: &ValidationContext<'_>) -> Result<(), ContractError> {
        require_version("PR context", &self.schema_version, PR_CONTEXT_SCHEMA_V1)?;
        require_text("repository", &self.repository)?;
        require_text("author", &self.author)?;
        require_sha("base_sha", &self.base_sha)?;
        require_sha("head_sha", &self.head_sha)?;
        require_sha("expected_head_sha", validation.expected_head_sha)?;
        if self.base_sha.eq_ignore_ascii_case(&self.head_sha) {
            return Err(ContractError::IdenticalBaseAndHead);
        }
        if !self
            .head_sha
            .eq_ignore_ascii_case(validation.expected_head_sha)
        {
            return Err(ContractError::StaleHeadSha {
                expected: validation.expected_head_sha.to_owned(),
                actual: self.head_sha.clone(),
            });
        }
        let age = validation.now.signed_duration_since(self.captured_at);
        if age < Duration::zero() || age > validation.maximum_context_age {
            return Err(ContractError::StaleContext);
        }
        Ok(())
    }
}

impl ReviewPacket {
    pub fn validate(&self, validation: &ValidationContext<'_>) -> Result<(), ContractError> {
        require_version(
            "review packet",
            &self.schema_version,
            REVIEW_PACKET_SCHEMA_V1,
        )?;
        self.context.validate(validation)?;
        require_text("reviewer", &self.reviewer)?;
        require_text("summary", &self.summary)?;
        if self
            .reviewer
            .trim()
            .eq_ignore_ascii_case(self.context.author.trim())
        {
            return Err(ContractError::SelfApproval);
        }
        validate_evidence(&self.evidence)?;
        Ok(())
    }
}

impl ReviewOverride {
    pub fn validate(&self, validation: &ValidationContext<'_>) -> Result<(), ContractError> {
        require_version("override", &self.schema_version, OVERRIDE_SCHEMA_V1)?;
        require_text("repository", &self.repository)?;
        require_sha("head_sha", &self.head_sha)?;
        require_text("requested_by", &self.requested_by)?;
        require_text("approved_by", &self.approved_by)?;
        require_text("reason", &self.reason)?;
        if !self
            .head_sha
            .eq_ignore_ascii_case(validation.expected_head_sha)
        {
            return Err(ContractError::StaleHeadSha {
                expected: validation.expected_head_sha.to_owned(),
                actual: self.head_sha.clone(),
            });
        }
        if self
            .requested_by
            .trim()
            .eq_ignore_ascii_case(self.approved_by.trim())
        {
            return Err(ContractError::SelfApproval);
        }
        validate_evidence(&self.evidence)?;
        if self.expires_at <= self.issued_at {
            return Err(ContractError::InvalidOverrideWindow);
        }
        if self.expires_at <= validation.now {
            return Err(ContractError::ExpiredOverride);
        }
        Ok(())
    }
}

fn require_version(
    contract: &'static str,
    actual: &str,
    expected: &str,
) -> Result<(), ContractError> {
    if actual != expected {
        return Err(ContractError::UnknownSchemaVersion {
            contract,
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

fn require_text(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::MissingField { field });
    }
    Ok(())
}

fn require_sha(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ContractError::InvalidSha { field });
    }
    Ok(())
}

fn validate_evidence(evidence: &[ReviewEvidence]) -> Result<(), ContractError> {
    if evidence.is_empty()
        || evidence.iter().any(|item| {
            item.kind.trim().is_empty()
                || item.location.trim().is_empty()
                || item.sha256.len() != 64
                || !item.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(ContractError::MissingEvidence);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "1111111111111111111111111111111111111111";
    const HEAD: &str = "2222222222222222222222222222222222222222";
    const OTHER: &str = "3333333333333333333333333333333333333333";

    fn now() -> DateTime<Utc> {
        "2026-09-04T05:00:00Z".parse().unwrap()
    }

    fn validation() -> ValidationContext<'static> {
        ValidationContext {
            expected_head_sha: HEAD,
            now: now(),
            maximum_context_age: Duration::hours(1),
        }
    }

    fn context() -> PullRequestContext {
        PullRequestContext {
            schema_version: PR_CONTEXT_SCHEMA_V1.into(),
            repository: "owner/repo".into(),
            pull_request_number: 42,
            author: "author".into(),
            base_sha: BASE.into(),
            head_sha: HEAD.into(),
            captured_at: now() - Duration::minutes(5),
        }
    }

    fn evidence() -> Vec<ReviewEvidence> {
        vec![ReviewEvidence {
            kind: "test_receipt".into(),
            location: "artifacts/test.json".into(),
            sha256: "a".repeat(64),
        }]
    }

    fn packet() -> ReviewPacket {
        ReviewPacket {
            schema_version: REVIEW_PACKET_SCHEMA_V1.into(),
            context: context(),
            reviewer: "reviewer".into(),
            disposition: ReviewDisposition::Approve,
            summary: "Reviewed against required controls".into(),
            evidence: evidence(),
            reviewed_at: now(),
        }
    }

    #[test]
    fn accepts_complete_packet() {
        assert_eq!(packet().validate(&validation()), Ok(()));
    }

    #[test]
    fn rejects_unknown_version_and_missing_sha() {
        let mut packet = packet();
        packet.schema_version = "zero-review.review-packet.v2".into();
        assert!(matches!(
            packet.validate(&validation()),
            Err(ContractError::UnknownSchemaVersion { .. })
        ));
        let mut context = context();
        context.head_sha.clear();
        assert_eq!(
            context.validate(&validation()),
            Err(ContractError::InvalidSha { field: "head_sha" })
        );
    }

    #[test]
    fn rejects_stale_sha_and_context() {
        let mut stale_sha_context = context();
        stale_sha_context.head_sha = OTHER.into();
        assert!(matches!(
            stale_sha_context.validate(&validation()),
            Err(ContractError::StaleHeadSha { .. })
        ));
        let mut stale_time_context = context();
        stale_time_context.captured_at = now() - Duration::hours(2);
        assert_eq!(
            stale_time_context.validate(&validation()),
            Err(ContractError::StaleContext)
        );
    }

    #[test]
    fn rejects_self_approval_and_missing_evidence() {
        let mut self_approved_packet = packet();
        self_approved_packet.reviewer = "AUTHOR".into();
        assert_eq!(
            self_approved_packet.validate(&validation()),
            Err(ContractError::SelfApproval)
        );
        let mut evidence_free_packet = packet();
        evidence_free_packet.evidence.clear();
        assert_eq!(
            evidence_free_packet.validate(&validation()),
            Err(ContractError::MissingEvidence)
        );
    }

    #[test]
    fn rejects_expired_override() {
        let override_request = ReviewOverride {
            schema_version: OVERRIDE_SCHEMA_V1.into(),
            repository: "owner/repo".into(),
            pull_request_number: 42,
            head_sha: HEAD.into(),
            requested_by: "author".into(),
            approved_by: "security-owner".into(),
            reason: "Time-bounded emergency exception".into(),
            evidence: evidence(),
            issued_at: now() - Duration::hours(2),
            expires_at: now() - Duration::minutes(1),
        };
        assert_eq!(
            override_request.validate(&validation()),
            Err(ContractError::ExpiredOverride)
        );
    }
}
