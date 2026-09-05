use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};

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

    /// Copies evidence into an immutable, digest-addressed store and records a
    /// relative source path. Existing blobs are verified before reuse.
    pub fn store_file(kind: impl Into<String>, path: &Path, root: &Path) -> Result<Self> {
        let content =
            fs::read(path).with_context(|| format!("read evidence artifact {}", path.display()))?;
        let mut artifact = Self::from_bytes(kind, "", &content);
        let relative = PathBuf::from("sha256").join(&artifact.content_sha256);
        let destination = root.join(&relative);
        fs::create_dir_all(destination.parent().expect("digest path has parent"))
            .with_context(|| format!("create evidence store {}", root.display()))?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
        {
            Ok(mut file) => {
                file.write_all(&content)?;
                file.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = fs::read(&destination)?;
                artifact.verify_content(&existing).with_context(|| {
                    format!("verify existing evidence blob {}", destination.display())
                })?;
            }
            Err(error) => {
                return Err(error).with_context(|| format!("create {}", destination.display()));
            }
        }
        artifact.source = relative.to_string_lossy().replace('\\', "/");
        Ok(artifact)
    }

    /// Resolves a stored evidence path under an explicit root without following
    /// traversal, absolute, UNC, or link-based escapes.
    pub fn read_from_store(&self, root: &Path) -> Result<Vec<u8>> {
        self.validate()?;
        let relative = Path::new(&self.source);
        if relative.is_absolute()
            || self.source.starts_with("//")
            || self.source.starts_with("\\\\")
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            bail!("evidence source must be a relative path inside the evidence store");
        }
        let canonical_root = fs::canonicalize(root)
            .with_context(|| format!("canonicalize evidence root {}", root.display()))?;
        let candidate = root.join(relative);
        let metadata = fs::symlink_metadata(&candidate)
            .with_context(|| format!("inspect evidence blob {}", candidate.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("evidence source must not be a symbolic link");
        }
        let canonical_candidate = fs::canonicalize(&candidate)
            .with_context(|| format!("canonicalize evidence blob {}", candidate.display()))?;
        if !canonical_candidate.starts_with(&canonical_root) {
            bail!("evidence source escapes the configured evidence store");
        }
        let content = fs::read(&canonical_candidate)?;
        self.verify_content(&content)?;
        Ok(content)
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

    #[test]
    fn content_addressed_store_survives_source_removal() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.json");
        let store = directory.path().join("store");
        fs::write(&source, b"passed").unwrap();
        let evidence = EvidenceArtifact::store_file("test", &source, &store).unwrap();
        fs::remove_file(source).unwrap();
        assert_eq!(evidence.read_from_store(&store).unwrap(), b"passed");
    }

    #[test]
    fn store_rejects_path_escape() {
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().join("store");
        fs::create_dir_all(&store).unwrap();
        let evidence = EvidenceArtifact::from_bytes("test", "../outside", b"passed");
        assert!(evidence.read_from_store(&store).is_err());
    }
}
