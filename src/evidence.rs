use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

pub const EVIDENCE_SCHEMA_V1: &str = "zero-review.evidence.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceArtifact {
    pub schema_version: String,
    pub kind: String,
    pub source: String,
    pub content_sha256: String,
    pub byte_length: u64,
}

impl EvidenceArtifact {
    pub fn from_bytes(kind: impl Into<String>, source: impl Into<String>, content: &[u8]) -> Self {
        Self {
            schema_version: EVIDENCE_SCHEMA_V1.into(),
            kind: kind.into(),
            source: source.into(),
            content_sha256: hex::encode(Sha256::digest(content)),
            byte_length: content.len() as u64,
        }
    }

    pub fn from_file(kind: impl Into<String>, path: &Path) -> Result<Self> {
        let content =
            fs::read(path).with_context(|| format!("read evidence artifact {}", path.display()))?;
        Ok(Self::from_bytes(kind, path.to_string_lossy(), &content))
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != EVIDENCE_SCHEMA_V1 {
            bail!(
                "unsupported evidence schema version: {}",
                self.schema_version
            );
        }
        if self.kind.trim().is_empty() || self.source.trim().is_empty() {
            bail!("evidence kind and source must not be empty");
        }
        if self.content_sha256.len() != 64
            || !self
                .content_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            bail!("evidence content_sha256 must contain 64 lowercase hexadecimal digits");
        }
        Ok(())
    }

    pub fn verify_content(&self, content: &[u8]) -> Result<()> {
        self.validate()?;
        if self.byte_length != content.len() as u64
            || self.content_sha256 != hex::encode(Sha256::digest(content))
        {
            bail!("evidence content does not match its recorded digest and length");
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string(self).context("serialize typed evidence")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_hash_detects_tampering() {
        let evidence = EvidenceArtifact::from_bytes("test_receipt", "test.json", b"passed");
        evidence.verify_content(b"passed").unwrap();
        assert!(evidence.verify_content(b"failed").is_err());
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let mut evidence = EvidenceArtifact::from_bytes("test_receipt", "test.json", b"passed");
        evidence.schema_version = "zero-review.evidence.v2".into();
        assert!(evidence.validate().is_err());
    }
}
