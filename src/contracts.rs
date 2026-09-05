use chrono::{DateTime, Duration, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

pub const PR_CONTEXT_SCHEMA_V1: &str = "zero-review.pr-context.v1";
pub const REVIEW_PACKET_SCHEMA_V1: &str = "zero-review.review-packet.v1";
pub const OVERRIDE_SCHEMA_V1: &str = "zero-review.override.v1";
pub const REVIEW_PACKET_SCHEMA_V2: &str = "zero-review.review-packet.v2";
pub const OVERRIDE_SCHEMA_V2: &str = "zero-review.override.v2";
pub const REVIEW_PACKET_SCHEMA_V3: &str = "zero-review.review-packet.v3";
pub const REVIEW_EVIDENCE_SCHEMA_V2: &str = "zero-review.evidence.v2";
pub const PACKET_MANIFEST_SCHEMA_V1: &str = "zero-review.packet-manifest.v1";

/// A signed, content-addressed envelope for a review packet. Signature
/// verification is deliberately provided by the caller/keyring; this type
/// only defines and validates the bytes that must be signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PacketManifest {
    pub schema_version: String,
    pub packet_digest: String,
    pub repository: String,
    pub pull_request_number: u64,
    pub base_sha: String,
    pub head_sha: String,
    pub signer_key_id: String,
    pub signature_algorithm: String,
    pub signature: String,
    pub signed_at: DateTime<Utc>,
}

impl PacketManifest {
    pub fn signing_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        serde_json::to_vec(&unsigned)
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        version("packet manifest", &self.schema_version, PACKET_MANIFEST_SCHEMA_V1)?;
        let digest = self.packet_digest.strip_prefix("sha256:").unwrap_or_default();
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
            return Err(ContractError::InvalidDigest { field: "packet_digest" });
        }
        text("repository", &self.repository)?;
        if self.pull_request_number == 0 { return Err(ContractError::MissingField { field: "pull_request_number" }); }
        sha("base_sha", &self.base_sha)?;
        sha("head_sha", &self.head_sha)?;
        if self.base_sha.eq_ignore_ascii_case(&self.head_sha) { return Err(ContractError::IdenticalBaseAndHead); }
        text("signer_key_id", &self.signer_key_id)?;
        text("signature_algorithm", &self.signature_algorithm)?;
        text("signature", &self.signature)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyReviewEvidenceV1 {
    pub kind: String,
    pub location: String,
    pub sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyReviewPacketV1 {
    pub schema_version: String,
    pub context: PullRequestContext,
    pub reviewer: String,
    pub disposition: ReviewDisposition,
    pub summary: String,
    pub evidence: Vec<LegacyReviewEvidenceV1>,
    pub reviewed_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyReviewOverrideV1 {
    pub schema_version: String,
    pub repository: String,
    pub pull_request_number: u64,
    pub head_sha: String,
    pub requested_by: String,
    pub approved_by: String,
    pub reason: String,
    pub evidence: Vec<LegacyReviewEvidenceV1>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyReviewEvidenceV2 {
    pub schema_version: String,
    pub control_id: String,
    pub kind: String,
    pub status: ReviewEvidenceStatus,
    pub location: String,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyReviewPacketV2 {
    pub schema_version: String,
    pub context: PullRequestContext,
    pub reviewer: String,
    pub disposition: ReviewDisposition,
    pub summary: String,
    pub required_controls: Vec<String>,
    pub evidence: Vec<LegacyReviewEvidenceV2>,
    pub reviewed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct ReviewEvidence {
    pub schema_version: String,
    pub control_id: String,
    pub kind: String,
    pub status: ReviewEvidenceStatus,
    pub location: String,
    pub sha256: String,
    pub byte_length: u64,
    pub command: Vec<String>,
    pub executable_sha256: String,
    pub exit_code: i32,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewEvidenceStatus {
    Verified,
    Partial,
    Blocked,
    NotProven,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDisposition {
    Approve,
    RequestChanges,
    Abstain,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewPacket {
    pub schema_version: String,
    pub context: PullRequestContext,
    pub reviewer: String,
    pub disposition: ReviewDisposition,
    pub summary: String,
    pub required_controls: Vec<String>,
    pub evidence: Vec<ReviewEvidence>,
    pub reviewed_at: DateTime<Utc>,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReviewOverride {
    pub schema_version: String,
    pub repository: String,
    pub pull_request_number: u64,
    pub base_sha: String,
    pub head_sha: String,
    pub tool_release_digest: String,
    pub nonce: String,
    pub requested_by: String,
    pub approved_by: String,
    pub reason: String,
    pub evidence: Vec<LegacyReviewEvidenceV2>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signer_key_id: String,
    pub signature_algorithm: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct ExpectedPullRequest<'a> {
    pub repository: &'a str,
    pub pull_request_number: u64,
    pub base_sha: &'a str,
    pub head_sha: &'a str,
}
#[derive(Debug, Clone)]
pub struct ExpectedOverride<'a> {
    pub pull_request: ExpectedPullRequest<'a>,
    pub tool_release_digest: &'a str,
}

#[derive(Debug, Clone)]
pub struct ValidationContext<'a> {
    pub expected_head_sha: &'a str,
    pub now: DateTime<Utc>,
    pub maximum_context_age: Duration,
    pub maximum_review_age: Duration,
    pub maximum_override_duration: Duration,
}
pub trait OverrideSignatureVerifier {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceConsume {
    Consumed,
    Replay,
}
#[derive(Debug, Error)]
#[error("nonce store I/O failure: {0}")]
pub struct NonceStoreError(#[from] std::io::Error);
pub trait OverrideNonceStore {
    fn consume(&mut self, repository: &str, nonce: &str) -> Result<NonceConsume, NonceStoreError>;
}

/// Durable, process-safe replay guard. Each repository/nonce pair is consumed
/// by atomically creating a digest-named marker with `create_new` semantics.
pub struct FileOverrideNonceStore {
    directory: PathBuf,
}
impl FileOverrideNonceStore {
    pub fn new(directory: impl AsRef<Path>) -> Self {
        Self {
            directory: directory.as_ref().to_owned(),
        }
    }
}
impl OverrideNonceStore for FileOverrideNonceStore {
    fn consume(&mut self, repository: &str, nonce: &str) -> Result<NonceConsume, NonceStoreError> {
        fs::create_dir_all(&self.directory)?;
        let name = hex::encode(Sha256::digest(format!("{repository}\0{nonce}").as_bytes()));
        let path = self.directory.join(name);
        let lock_path = path.with_extension("lock");
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        lock.lock_exclusive()?;
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = fs::read_to_string(&path)?;
                let parsed: serde_json::Value = serde_json::from_str(&existing)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
                if parsed.get("schema_version").and_then(|v| v.as_str())
                    != Some("zero-review.nonce-consumption.v1")
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid nonce marker",
                    )
                    .into());
                }
                return Ok(NonceConsume::Replay);
            }
            Err(error) => return Err(error.into()),
        };
        use std::io::Write;
        let metadata = serde_json::json!({"schema_version":"zero-review.nonce-consumption.v1","repository":repository,"nonce_sha256":hex::encode(Sha256::digest(nonce.as_bytes())),"consumed_at":Utc::now()});
        file.write_all(
            serde_json::to_string(&metadata)
                .expect("nonce metadata serializes")
                .as_bytes(),
        )?;
        file.sync_all()?;
        Ok(NonceConsume::Consumed)
    }
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
    #[error("at least one complete typed evidence item is required")]
    MissingEvidence,
    #[error("required controls must be unique, non-empty, and covered by evidence")]
    MissingRequiredControl,
    #[error("evidence control identifiers must be unique")]
    DuplicateEvidenceControl,
    #[error("review timestamp is stale or inconsistent with the captured context")]
    StaleReview,
    #[error("approval disposition requires verified evidence for every control")]
    InconsistentDisposition,
    #[error("override has expired")]
    ExpiredOverride,
    #[error("override expiry must be later than its issue time")]
    InvalidOverrideWindow,
    #[error("override duration exceeds the configured maximum")]
    OverrideTooLong,
    #[error("override signature is invalid")]
    InvalidSignature,
    #[error("override nonce has already been consumed")]
    ReplayedOverride,
    #[error("override nonce store failed")]
    NonceStoreFailure,
    #[error("review contract does not match the expected repository, PR, base, and head identity")]
    PrIdentityMismatch,
    #[error("{field} must be a sha256 digest")]
    InvalidDigest { field: &'static str },
}

impl PullRequestContext {
    pub fn validate(&self, v: &ValidationContext<'_>) -> Result<(), ContractError> {
        version("PR context", &self.schema_version, PR_CONTEXT_SCHEMA_V1)?;
        text("repository", &self.repository)?;
        text("author", &self.author)?;
        if self.pull_request_number == 0 {
            return Err(ContractError::MissingField {
                field: "pull_request_number",
            });
        }
        sha("base_sha", &self.base_sha)?;
        sha("head_sha", &self.head_sha)?;
        if self.base_sha.eq_ignore_ascii_case(&self.head_sha) {
            return Err(ContractError::IdenticalBaseAndHead);
        }
        sha("expected_head_sha", v.expected_head_sha)?;
        if self.base_sha.eq_ignore_ascii_case(&self.head_sha) {
            return Err(ContractError::IdenticalBaseAndHead);
        }
        if !self.head_sha.eq_ignore_ascii_case(v.expected_head_sha) {
            return Err(ContractError::StaleHeadSha {
                expected: v.expected_head_sha.into(),
                actual: self.head_sha.clone(),
            });
        }
        let age = v.now.signed_duration_since(self.captured_at);
        if age < Duration::zero() || age > v.maximum_context_age {
            return Err(ContractError::StaleContext);
        }
        Ok(())
    }
}
impl ReviewPacket {
    pub fn validate(&self, v: &ValidationContext<'_>) -> Result<(), ContractError> {
        version(
            "review packet",
            &self.schema_version,
            REVIEW_PACKET_SCHEMA_V3,
        )?;
        self.context.validate(v)?;
        text("reviewer", &self.reviewer)?;
        text("summary", &self.summary)?;
        if self
            .reviewer
            .trim()
            .eq_ignore_ascii_case(self.context.author.trim())
        {
            return Err(ContractError::SelfApproval);
        }
        let age = v.now.signed_duration_since(self.reviewed_at);
        if self.reviewed_at < self.context.captured_at
            || age < Duration::zero()
            || age > v.maximum_review_age
        {
            return Err(ContractError::StaleReview);
        }
        validate_evidence(
            &self.evidence,
            self.context.captured_at,
            self.reviewed_at,
            v.maximum_review_age,
        )?;
        let evidence_controls: HashSet<_> = self.evidence.iter().map(|e| &e.control_id).collect();
        if evidence_controls.len() != self.evidence.len() {
            return Err(ContractError::DuplicateEvidenceControl);
        }
        let unique: HashSet<_> = self.required_controls.iter().collect();
        if self.required_controls.is_empty()
            || unique.len() != self.required_controls.len()
            || self.required_controls.iter().any(|r| {
                r.trim().is_empty()
                    || self.evidence.iter().filter(|e| e.control_id == *r).count() != 1
            })
        {
            return Err(ContractError::MissingRequiredControl);
        }
        let has_block = self
            .evidence
            .iter()
            .any(|e| e.status == ReviewEvidenceStatus::Blocked);
        let all_verified = self
            .evidence
            .iter()
            .all(|e| e.status == ReviewEvidenceStatus::Verified);
        match self.disposition {
            ReviewDisposition::Approve if !all_verified => {
                return Err(ContractError::InconsistentDisposition);
            }
            ReviewDisposition::RequestChanges if !has_block => {
                return Err(ContractError::InconsistentDisposition);
            }
            ReviewDisposition::Abstain if all_verified || has_block => {
                return Err(ContractError::InconsistentDisposition);
            }
            _ => {}
        }
        Ok(())
    }

    /// Returns the deterministic JSON bytes used to identify this packet.
    /// The signature/manifest layer can sign this digest without relying on
    /// filesystem ordering or pretty-printing choices.
    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn content_digest(&self) -> Result<String, serde_json::Error> {
        Ok(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(self.canonical_json()?.as_bytes()))
        ))
    }
    pub fn validate_bound(
        &self,
        v: &ValidationContext<'_>,
        expected: &ExpectedPullRequest<'_>,
    ) -> Result<(), ContractError> {
        self.validate(v)?;
        text("expected_repository", expected.repository)?;
        if expected.pull_request_number == 0 {
            return Err(ContractError::MissingField {
                field: "expected_pull_request_number",
            });
        }
        sha("expected_base_sha", expected.base_sha)?;
        sha("expected_head_sha", expected.head_sha)?;
        if self.context.repository != expected.repository
            || self.context.pull_request_number != expected.pull_request_number
            || !self
                .context
                .base_sha
                .eq_ignore_ascii_case(expected.base_sha)
            || !self
                .context
                .head_sha
                .eq_ignore_ascii_case(expected.head_sha)
        {
            return Err(ContractError::PrIdentityMismatch);
        }
        Ok(())
    }
}
impl ReviewOverride {
    pub fn validate(&self, v: &ValidationContext<'_>) -> Result<(), ContractError> {
        version("override", &self.schema_version, OVERRIDE_SCHEMA_V2)?;
        text("repository", &self.repository)?;
        if self.pull_request_number == 0 {
            return Err(ContractError::MissingField {
                field: "pull_request_number",
            });
        }
        sha("base_sha", &self.base_sha)?;
        sha("head_sha", &self.head_sha)?;
        digest("tool_release_digest", &self.tool_release_digest)?;
        text("nonce", &self.nonce)?;
        if self.nonce.len() < 16 || self.nonce.len() > 256 {
            return Err(ContractError::MissingField { field: "nonce" });
        }
        text("requested_by", &self.requested_by)?;
        text("approved_by", &self.approved_by)?;
        text("reason", &self.reason)?;
        text("signer_key_id", &self.signer_key_id)?;
        if self.signature_algorithm != "ed25519" {
            return Err(ContractError::InvalidSignature);
        }
        if self.signature.len() != 128
            || !self
                .signature
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            return Err(ContractError::InvalidSignature);
        }
        if !self.head_sha.eq_ignore_ascii_case(v.expected_head_sha) {
            return Err(ContractError::StaleHeadSha {
                expected: v.expected_head_sha.into(),
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
        validate_legacy_v2_evidence(&self.evidence)?;
        if self.expires_at <= self.issued_at {
            return Err(ContractError::InvalidOverrideWindow);
        }
        if self.expires_at <= v.now {
            return Err(ContractError::ExpiredOverride);
        }
        if self.expires_at - self.issued_at > v.maximum_override_duration {
            return Err(ContractError::OverrideTooLong);
        }
        Ok(())
    }
    pub fn validate_bound(
        &self,
        v: &ValidationContext<'_>,
        expected: &ExpectedOverride<'_>,
    ) -> Result<(), ContractError> {
        self.validate(v)?;
        let pr = &expected.pull_request;
        text("expected_repository", pr.repository)?;
        sha("expected_base_sha", pr.base_sha)?;
        sha("expected_head_sha", pr.head_sha)?;
        digest("expected_tool_release_digest", expected.tool_release_digest)?;
        if pr.pull_request_number == 0
            || self.repository != pr.repository
            || self.pull_request_number != pr.pull_request_number
            || !self.base_sha.eq_ignore_ascii_case(pr.base_sha)
            || !self.head_sha.eq_ignore_ascii_case(pr.head_sha)
            || self.tool_release_digest != expected.tool_release_digest
        {
            return Err(ContractError::PrIdentityMismatch);
        }
        Ok(())
    }
    pub fn signing_payload(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Envelope<'a> {
            domain: &'static str,
            schema_version: &'a str,
            signature_algorithm: &'a str,
            repository: &'a str,
            pull_request_number: u64,
            base_sha: &'a str,
            head_sha: &'a str,
            tool_release_digest: &'a str,
            nonce: &'a str,
            requested_by: &'a str,
            approved_by: &'a str,
            reason: &'a str,
            evidence: &'a [LegacyReviewEvidenceV2],
            issued_at: DateTime<Utc>,
            expires_at: DateTime<Utc>,
            signer_key_id: &'a str,
        }
        serde_json::to_vec(&Envelope {
            domain: "zero-review.override-signature.v1",
            schema_version: &self.schema_version,
            signature_algorithm: &self.signature_algorithm,
            repository: &self.repository,
            pull_request_number: self.pull_request_number,
            base_sha: &self.base_sha,
            head_sha: &self.head_sha,
            tool_release_digest: &self.tool_release_digest,
            nonce: &self.nonce,
            requested_by: &self.requested_by,
            approved_by: &self.approved_by,
            reason: &self.reason,
            evidence: &self.evidence,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            signer_key_id: &self.signer_key_id,
        })
        .expect("override fields serialize")
    }
    pub fn validate_authenticated(
        &self,
        v: &ValidationContext<'_>,
        verifier: &dyn OverrideSignatureVerifier,
        nonces: &mut dyn OverrideNonceStore,
    ) -> Result<(), ContractError> {
        self.validate(v)?;
        if !verifier.verify(
            &self.signer_key_id,
            &self.signing_payload(),
            &self.signature,
        ) {
            return Err(ContractError::InvalidSignature);
        }
        match nonces.consume(&self.repository, &self.nonce) {
            Ok(NonceConsume::Consumed) => {}
            Ok(NonceConsume::Replay) => return Err(ContractError::ReplayedOverride),
            Err(_) => return Err(ContractError::NonceStoreFailure),
        }
        Ok(())
    }
}

fn version(contract: &'static str, actual: &str, expected: &str) -> Result<(), ContractError> {
    if actual != expected {
        return Err(ContractError::UnknownSchemaVersion {
            contract,
            actual: actual.into(),
        });
    }
    Ok(())
}
fn text(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::MissingField { field });
    }
    Ok(())
}
fn sha(field: &'static str, value: &str) -> Result<(), ContractError> {
    if value.len() != 40 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ContractError::InvalidSha { field });
    }
    Ok(())
}
fn digest(field: &'static str, value: &str) -> Result<(), ContractError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ContractError::MissingField { field });
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return Err(ContractError::MissingField { field });
    }
    Ok(())
}
fn validate_evidence(
    items: &[ReviewEvidence],
    context_captured_at: DateTime<Utc>,
    reviewed_at: DateTime<Utc>,
    maximum_duration: Duration,
) -> Result<(), ContractError> {
    if items.is_empty()
        || items.iter().any(|e| {
            e.schema_version != REVIEW_EVIDENCE_SCHEMA_V2
                || e.control_id.trim().is_empty()
                || e.kind.trim().is_empty()
                || e.location.trim().is_empty()
                || e.sha256.len() != 64
                || !e
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
                || e.command.is_empty()
                || e.command.iter().any(|part| part.trim().is_empty())
                || digest("executable_sha256", &e.executable_sha256).is_err()
                || e.completed_at < e.started_at
                || e.started_at < context_captured_at
                || e.completed_at > reviewed_at
                || e.completed_at - e.started_at > maximum_duration
                || e.status == ReviewEvidenceStatus::Verified && e.exit_code != 0
        })
    {
        return Err(ContractError::MissingEvidence);
    }
    Ok(())
}

fn validate_legacy_v2_evidence(items: &[LegacyReviewEvidenceV2]) -> Result<(), ContractError> {
    if items.is_empty()
        || items.iter().any(|e| {
            e.schema_version != "zero-review.evidence.v1"
                || e.control_id.trim().is_empty()
                || e.kind.trim().is_empty()
                || e.location.trim().is_empty()
                || e.sha256.len() != 64
                || !e
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
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
    fn now() -> DateTime<Utc> {
        "2026-09-04T05:00:00Z".parse().unwrap()
    }
    fn validation() -> ValidationContext<'static> {
        ValidationContext {
            expected_head_sha: HEAD,
            now: now(),
            maximum_context_age: Duration::hours(1),
            maximum_review_age: Duration::hours(1),
            maximum_override_duration: Duration::hours(4),
        }
    }
    fn evidence() -> Vec<ReviewEvidence> {
        vec![ReviewEvidence {
            schema_version: REVIEW_EVIDENCE_SCHEMA_V2.into(),
            control_id: "correctness-tests".into(),
            kind: "verified".into(),
            status: ReviewEvidenceStatus::Verified,
            location: "test.json".into(),
            sha256: "a".repeat(64),
            byte_length: 6,
            command: vec!["cargo".into(), "test".into(), "--locked".into()],
            executable_sha256: format!("sha256:{}", "b".repeat(64)),
            exit_code: 0,
            started_at: now() - Duration::minutes(2),
            completed_at: now() - Duration::minutes(1),
        }]
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
    fn packet() -> ReviewPacket {
        ReviewPacket {
            schema_version: REVIEW_PACKET_SCHEMA_V3.into(),
            context: context(),
            reviewer: "reviewer".into(),
            disposition: ReviewDisposition::Approve,
            summary: "reviewed".into(),
            required_controls: vec!["correctness-tests".into()],
            evidence: evidence(),
            reviewed_at: now(),
        }
    }
    #[test]
    fn validates_packet_and_rejects_missing_control() {
        assert!(packet().validate(&validation()).is_ok());
        let mut p = packet();
        p.required_controls.push("security".into());
        assert_eq!(
            p.validate(&validation()),
            Err(ContractError::MissingRequiredControl)
        );
    }

    #[test]
    fn packet_digest_is_stable_and_changes_on_content_mutation() {
        let original = packet();
        let first = original.content_digest().unwrap();
        assert_eq!(first, original.content_digest().unwrap());
        let mut changed = original;
        changed.summary.push_str(" changed");
        assert_ne!(first, changed.content_digest().unwrap());
    }

    #[test]
    fn packet_manifest_validates_and_signing_payload_excludes_signature() {
        let manifest = PacketManifest {
            schema_version: PACKET_MANIFEST_SCHEMA_V1.into(),
            packet_digest: format!("sha256:{}", "a".repeat(64)),
            repository: "owner/repo".into(), pull_request_number: 42,
            base_sha: "b".repeat(40), head_sha: "c".repeat(40),
            signer_key_id: "release-key".into(), signature_algorithm: "ed25519".into(),
            signature: "deadbeef".into(), signed_at: Utc::now(),
        };
        manifest.validate().unwrap();
        let payload = String::from_utf8(manifest.signing_payload().unwrap()).unwrap();
        assert!(!payload.contains("deadbeef"));
        assert!(payload.contains("release-key"));
    }

    #[test]
    fn packet_manifest_rejects_malformed_digest() {
        let mut manifest = PacketManifest {
            schema_version: PACKET_MANIFEST_SCHEMA_V1.into(), packet_digest: "sha256:bad".into(),
            repository: "owner/repo".into(), pull_request_number: 1,
            base_sha: "a".repeat(40), head_sha: "b".repeat(40), signer_key_id: "k".into(),
            signature_algorithm: "ed25519".into(), signature: "s".into(), signed_at: Utc::now(),
        };
        assert!(matches!(manifest.validate(), Err(ContractError::InvalidDigest { .. })));
        manifest.packet_digest = format!("sha256:{}", "A".repeat(64));
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn packet_rejects_duplicate_evidence_controls() {
        let mut p = packet();
        p.evidence.push(p.evidence[0].clone());
        assert_eq!(
            p.validate(&validation()),
            Err(ContractError::DuplicateEvidenceControl)
        );
    }
    #[test]
    fn bound_packet_rejects_cross_pr_transplant() {
        let expected = ExpectedPullRequest {
            repository: "owner/repo",
            pull_request_number: 42,
            base_sha: BASE,
            head_sha: HEAD,
        };
        assert!(packet().validate_bound(&validation(), &expected).is_ok());
        let wrong = ExpectedPullRequest {
            pull_request_number: 43,
            ..expected
        };
        assert_eq!(
            packet().validate_bound(&validation(), &wrong),
            Err(ContractError::PrIdentityMismatch)
        );
    }
    #[test]
    fn rejects_stale_review_and_unverified_approval() {
        let mut p = packet();
        p.reviewed_at = now() - Duration::hours(2);
        assert_eq!(p.validate(&validation()), Err(ContractError::StaleReview));
        let mut p = packet();
        p.evidence[0].status = ReviewEvidenceStatus::Partial;
        assert_eq!(
            p.validate(&validation()),
            Err(ContractError::InconsistentDisposition)
        );
        let mut p = packet();
        p.disposition = ReviewDisposition::RequestChanges;
        assert_eq!(
            p.validate(&validation()),
            Err(ContractError::InconsistentDisposition)
        );
        p.evidence[0].status = ReviewEvidenceStatus::Blocked;
        assert!(p.validate(&validation()).is_ok());
    }
    struct Yes;
    impl OverrideSignatureVerifier for Yes {
        fn verify(&self, _: &str, _: &[u8], _: &str) -> bool {
            true
        }
    }
    #[derive(Default)]
    struct Nonces(HashSet<String>);
    impl OverrideNonceStore for Nonces {
        fn consume(&mut self, repo: &str, nonce: &str) -> Result<NonceConsume, NonceStoreError> {
            Ok(if self.0.insert(format!("{repo}:{nonce}")) {
                NonceConsume::Consumed
            } else {
                NonceConsume::Replay
            })
        }
    }
    fn override_() -> ReviewOverride {
        ReviewOverride {
            schema_version: OVERRIDE_SCHEMA_V2.into(),
            repository: "owner/repo".into(),
            pull_request_number: 42,
            base_sha: BASE.into(),
            head_sha: HEAD.into(),
            tool_release_digest: format!("sha256:{}", "d".repeat(64)),
            nonce: "unique-nonce-0001".into(),
            requested_by: "author".into(),
            approved_by: "owner".into(),
            reason: "emergency".into(),
            evidence: vec![LegacyReviewEvidenceV2 {
                schema_version: "zero-review.evidence.v1".into(),
                control_id: "correctness-tests".into(),
                kind: "verified".into(),
                status: ReviewEvidenceStatus::Verified,
                location: "test.json".into(),
                sha256: "a".repeat(64),
                byte_length: 6,
            }],
            issued_at: now(),
            expires_at: now() + Duration::hours(1),
            signer_key_id: "key-1".into(),
            signature_algorithm: "ed25519".into(),
            signature: "a".repeat(128),
        }
    }
    #[test]
    fn authenticated_override_rejects_replay() {
        let mut nonces = Nonces::default();
        assert!(
            override_()
                .validate_authenticated(&validation(), &Yes, &mut nonces)
                .is_ok()
        );
        assert_eq!(
            override_().validate_authenticated(&validation(), &Yes, &mut nonces),
            Err(ContractError::ReplayedOverride)
        );
    }
    #[test]
    fn override_signature_payload_is_domain_separated_and_bound() {
        let original = override_().signing_payload();
        assert!(String::from_utf8_lossy(&original).contains("zero-review.override-signature.v1"));
        let mut changed = override_();
        changed.repository = "other/repo".into();
        assert_ne!(original, changed.signing_payload());
    }
    #[test]
    fn file_nonce_store_is_durable_and_fail_closed_on_replay() {
        let directory = tempfile::tempdir().unwrap();
        let mut first = FileOverrideNonceStore::new(directory.path());
        assert_eq!(
            first.consume("owner/repo", "unique-nonce-0001").unwrap(),
            NonceConsume::Consumed
        );
        let mut second = FileOverrideNonceStore::new(directory.path());
        assert_eq!(
            second.consume("owner/repo", "unique-nonce-0001").unwrap(),
            NonceConsume::Replay
        );
    }
    #[test]
    fn nonce_store_distinguishes_io_failure_and_is_process_safe() {
        let directory = tempfile::tempdir().unwrap();
        let invalid = directory.path().join("file");
        fs::write(&invalid, b"not a directory").unwrap();
        assert!(
            FileOverrideNonceStore::new(&invalid)
                .consume("repo", "nonce-00000000001")
                .is_err()
        );

        let store = directory.path().join("nonces");
        let outcomes = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..12)
                .map(|_| {
                    let store = store.clone();
                    scope.spawn(move || {
                        FileOverrideNonceStore::new(store)
                            .consume("repo", "nonce-00000000001")
                            .unwrap()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(
            outcomes
                .iter()
                .filter(|&&o| o == NonceConsume::Consumed)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|&&o| o == NonceConsume::Replay)
                .count(),
            11
        );
    }
    #[test]
    fn legacy_v1_packet_shape_remains_deserializable() {
        let json = format!(
            r#"{{"schema_version":"zero-review.review-packet.v1","context":{{"schema_version":"zero-review.pr-context.v1","repository":"owner/repo","pull_request_number":42,"author":"author","base_sha":"{BASE}","head_sha":"{HEAD}","captured_at":"2026-09-04T04:55:00Z"}},"reviewer":"reviewer","disposition":"approve","summary":"legacy","evidence":[{{"kind":"test","location":"test.json","sha256":"{}"}}],"reviewed_at":"2026-09-04T05:00:00Z"}}"#,
            "a".repeat(64)
        );
        let packet: LegacyReviewPacketV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(packet.schema_version, REVIEW_PACKET_SCHEMA_V1);
    }

    #[test]
    fn current_contracts_reject_unknown_fields() {
        let mut value = serde_json::to_value(packet()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ReviewPacket>(value).is_err());

        let mut nested = serde_json::to_value(packet()).unwrap();
        nested["context"]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ReviewPacket>(nested).is_err());

        let mut evidence = serde_json::to_value(packet()).unwrap();
        evidence["evidence"][0]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ReviewPacket>(evidence).is_err());
    }

    #[test]
    fn evidence_rejects_missing_or_invalid_execution_provenance() {
        let mut p = packet();
        p.evidence[0].command.clear();
        assert_eq!(
            p.validate(&validation()),
            Err(ContractError::MissingEvidence)
        );

        let mut p = packet();
        p.evidence[0].executable_sha256 = "sha256:bad".into();
        assert_eq!(
            p.validate(&validation()),
            Err(ContractError::MissingEvidence)
        );

        let mut p = packet();
        p.evidence[0].completed_at = p.evidence[0].started_at - Duration::seconds(1);
        assert_eq!(
            p.validate(&validation()),
            Err(ContractError::MissingEvidence)
        );

        let mut p = packet();
        p.evidence[0].exit_code = 1;
        assert_eq!(
            p.validate(&validation()),
            Err(ContractError::MissingEvidence)
        );

        let mut p = packet();
        p.evidence[0].completed_at = p.reviewed_at + Duration::seconds(1);
        assert_eq!(
            p.validate(&validation()),
            Err(ContractError::MissingEvidence)
        );

        let mut p = packet();
        p.evidence[0].started_at = p.context.captured_at - Duration::seconds(1);
        assert_eq!(
            p.validate(&validation()),
            Err(ContractError::MissingEvidence)
        );
    }

    #[test]
    fn legacy_v2_packet_shape_remains_deserializable() {
        let mut value = serde_json::to_value(packet()).unwrap();
        value["schema_version"] = serde_json::json!(REVIEW_PACKET_SCHEMA_V2);
        let evidence = value["evidence"][0].as_object_mut().unwrap();
        evidence.insert(
            "schema_version".into(),
            serde_json::json!("zero-review.evidence.v1"),
        );
        for field in [
            "command",
            "executable_sha256",
            "exit_code",
            "started_at",
            "completed_at",
        ] {
            evidence.remove(field);
        }
        let decoded: LegacyReviewPacketV2 = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.schema_version, REVIEW_PACKET_SCHEMA_V2);
    }
}
