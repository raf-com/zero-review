use crate::{
    evidence::EvidenceArtifact,
    model::{EvidenceStatus, Receipt},
};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    thread,
    time::{Duration, Instant},
};

const LOCK_WAIT: Duration = Duration::from_secs(60);
const LOCK_RETRY: Duration = Duration::from_millis(10);

pub const LEDGER_CHECKPOINT_SCHEMA_V1: &str = "zero-review.ledger-checkpoint.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerCheckpoint {
    pub schema_version: String,
    pub ledger_id: String,
    pub entry_count: u64,
    pub last_entry_hash: String,
    pub key_id: String,
    pub created_at: DateTime<Utc>,
    pub signature_algorithm: String,
    pub signature: String,
}

pub trait LedgerCheckpointVerifier {
    fn verify_checkpoint(
        &self,
        key_id: &str,
        signed_at: DateTime<Utc>,
        payload: &[u8],
        signature: &str,
    ) -> bool;
}

pub fn ledger_checkpoint_payload(
    ledger_id: &str,
    entry_count: u64,
    last_entry_hash: &str,
    key_id: &str,
    created_at: DateTime<Utc>,
) -> Result<Vec<u8>> {
    if ledger_id.trim().is_empty() || key_id.trim().is_empty() {
        bail!("ledger checkpoint identity and key ID must not be empty");
    }
    validate_hash(last_entry_hash)?;
    serde_json::to_vec(&(
        "zero-review.ledger-checkpoint-signature.v1",
        LEDGER_CHECKPOINT_SCHEMA_V1,
        "ed25519",
        ledger_id,
        entry_count,
        last_entry_hash,
        key_id,
        created_at,
    ))
    .context("serialize ledger checkpoint payload")
}

pub fn create_ledger_checkpoint(
    path: &Path,
    ledger_id: impl Into<String>,
    key_id: impl Into<String>,
    signature: impl Into<String>,
) -> Result<LedgerCheckpoint> {
    create_ledger_checkpoint_at(path, ledger_id, key_id, Utc::now(), signature)
}

pub fn create_ledger_checkpoint_at(
    path: &Path,
    ledger_id: impl Into<String>,
    key_id: impl Into<String>,
    created_at: DateTime<Utc>,
    signature: impl Into<String>,
) -> Result<LedgerCheckpoint> {
    let (entry_count, last_entry_hash) = ledger_tip(path)?;
    if entry_count == 0 {
        bail!("cannot checkpoint an empty ledger");
    }
    let checkpoint = LedgerCheckpoint {
        schema_version: LEDGER_CHECKPOINT_SCHEMA_V1.into(),
        ledger_id: ledger_id.into(),
        entry_count: entry_count as u64,
        last_entry_hash,
        key_id: key_id.into(),
        created_at,
        signature_algorithm: "ed25519".into(),
        signature: signature.into(),
    };
    ledger_checkpoint_payload(
        &checkpoint.ledger_id,
        checkpoint.entry_count,
        &checkpoint.last_entry_hash,
        &checkpoint.key_id,
        checkpoint.created_at,
    )?;
    if checkpoint.signature.len() != 128
        || !checkpoint
            .signature
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("ledger checkpoint signature must contain 128 lowercase hexadecimal digits");
    }
    Ok(checkpoint)
}

pub fn verify_ledger_checkpoint(
    path: &Path,
    checkpoint: &LedgerCheckpoint,
    verifier: &dyn LedgerCheckpointVerifier,
) -> Result<usize> {
    if checkpoint.schema_version != LEDGER_CHECKPOINT_SCHEMA_V1
        || checkpoint.signature_algorithm != "ed25519"
    {
        bail!("unsupported ledger checkpoint contract");
    }
    if checkpoint.created_at > Utc::now() + chrono::Duration::minutes(5) {
        bail!("ledger checkpoint creation time is unacceptably far in the future");
    }
    let (count, last_hash) = ledger_tip(path)?;
    if count as u64 != checkpoint.entry_count || last_hash != checkpoint.last_entry_hash {
        bail!("ledger does not match the witnessed checkpoint");
    }
    let payload = ledger_checkpoint_payload(
        &checkpoint.ledger_id,
        checkpoint.entry_count,
        &checkpoint.last_entry_hash,
        &checkpoint.key_id,
        checkpoint.created_at,
    )?;
    if !verifier.verify_checkpoint(
        &checkpoint.key_id,
        checkpoint.created_at,
        &payload,
        &checkpoint.signature,
    ) {
        bail!("ledger checkpoint signature is invalid");
    }
    Ok(count)
}

fn validate_hash(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("ledger checkpoint hash must be 64 lowercase hexadecimal digits");
    }
    Ok(())
}

struct LedgerLock {
    file: fs::File,
}

impl LedgerLock {
    fn acquire(ledger: &Path) -> Result<Self> {
        let lock_path = ledger.with_extension(format!(
            "{}.lock",
            ledger
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or("ledger")
        ));
        let started = Instant::now();
        loop {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)
            {
                Ok(file) => match file.try_lock_exclusive() {
                    Ok(()) => {
                        return Ok(Self { file });
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            || cfg!(windows) && error.raw_os_error() == Some(33) =>
                    {
                        if started.elapsed() >= LOCK_WAIT {
                            bail!("timed out acquiring ledger lock {}", lock_path.display());
                        }
                        thread::sleep(LOCK_RETRY);
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("lock ledger sidecar {}", lock_path.display())
                        });
                    }
                },
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("create ledger lock {}", lock_path.display()));
                }
            }
        }
    }
}

impl Drop for LedgerLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

fn digest(
    timestamp: &str,
    operation: &str,
    subject: &str,
    status: &EvidenceStatus,
    evidence: &[String],
    previous: &str,
) -> String {
    let payload = serde_json::to_vec(&(timestamp, operation, subject, status, evidence, previous))
        .expect("serializable receipt fields");
    hex::encode(Sha256::digest(payload))
}

fn append_receipt(
    path: &Path,
    operation: &str,
    subject: &str,
    status: EvidenceStatus,
    evidence: Vec<String>,
) -> Result<Receipt> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("create ledger directory {}", parent.display()))?;
    }
    let _lock = LedgerLock::acquire(path)?;
    let previous_hash = if path.exists() {
        fs::read_to_string(path)?
            .lines()
            .rfind(|line| !line.trim().is_empty())
            .map(serde_json::from_str::<Receipt>)
            .transpose()?
            .map(|r| r.hash)
            .unwrap_or_default()
    } else {
        String::new()
    };
    let timestamp = Utc::now().to_rfc3339();
    let hash = digest(
        &timestamp,
        operation,
        subject,
        &status,
        &evidence,
        &previous_hash,
    );
    let receipt = Receipt {
        timestamp,
        operation: operation.into(),
        subject: subject.into(),
        status,
        evidence,
        previous_hash,
        hash,
    };
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open ledger {}", path.display()))?;
    writeln!(file, "{}", serde_json::to_string(&receipt)?)?;
    file.sync_data()
        .with_context(|| format!("sync ledger {}", path.display()))?;
    Ok(receipt)
}

pub fn append_evidence_receipt(
    path: &Path,
    operation: &str,
    subject: &str,
    status: EvidenceStatus,
    evidence: Vec<EvidenceArtifact>,
) -> Result<Receipt> {
    if evidence.is_empty() {
        bail!("typed evidence must not be empty");
    }
    let evidence = evidence
        .iter()
        .map(EvidenceArtifact::canonical_json)
        .collect::<Result<Vec<_>>>()?;
    append_receipt(path, operation, subject, status, evidence)
}

pub fn verify_ledger(path: &Path) -> Result<usize> {
    let _lock = LedgerLock::acquire(path)?;
    let content = fs::read_to_string(path)?;
    let mut previous = String::new();
    let mut count = 0;
    for (index, line) in content.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let receipt: Receipt = serde_json::from_str(line)
            .with_context(|| format!("invalid receipt at line {}", index + 1))?;
        if receipt.previous_hash != previous
            || receipt.hash
                != digest(
                    &receipt.timestamp,
                    &receipt.operation,
                    &receipt.subject,
                    &receipt.status,
                    &receipt.evidence,
                    &receipt.previous_hash,
                )
        {
            bail!("ledger chain invalid at line {}", index + 1);
        }
        previous = receipt.hash;
        count += 1;
    }
    Ok(count)
}

fn ledger_tip(path: &Path) -> Result<(usize, String)> {
    verify_ledger(path)?;
    let content = fs::read_to_string(path)?;
    let receipts = content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<Receipt>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok((
        receipts.len(),
        receipts
            .last()
            .map(|receipt| receipt.hash.clone())
            .unwrap_or_default(),
    ))
}

/// Verifies both the hash chain and every typed evidence artifact against its
/// current on-disk bytes. This is intentionally separate from chain-only
/// verification because archived ledgers may reference artifacts not mounted
/// on the current host.
pub fn verify_ledger_evidence(path: &Path) -> Result<usize> {
    let evidence_root = path.parent().unwrap_or_else(|| Path::new("."));
    verify_ledger_evidence_with_root(path, evidence_root)
}

/// Strictly verifies typed evidence from a caller-supplied content-addressed
/// root. Evidence paths are never interpreted relative to the process cwd.
pub fn verify_ledger_evidence_with_root(path: &Path, evidence_root: &Path) -> Result<usize> {
    let _lock = LedgerLock::acquire(path)?;
    let content = fs::read_to_string(path)?;
    let mut previous = String::new();
    let mut count = 0;
    for (index, line) in content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let receipt: Receipt = serde_json::from_str(line)
            .with_context(|| format!("invalid receipt at line {}", index + 1))?;
        if receipt.previous_hash != previous
            || receipt.hash
                != digest(
                    &receipt.timestamp,
                    &receipt.operation,
                    &receipt.subject,
                    &receipt.status,
                    &receipt.evidence,
                    &receipt.previous_hash,
                )
        {
            bail!("ledger chain invalid at line {}", index + 1);
        }
        for encoded in &receipt.evidence {
            let artifact: EvidenceArtifact = serde_json::from_str(encoded)
                .with_context(|| format!("receipt line {} contains untyped evidence", index + 1))?;
            artifact
                .read_from_store(evidence_root)
                .with_context(|| format!("verify evidence source {}", artifact.source))?;
        }
        previous = receipt.hash;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AcceptSignature;
    impl LedgerCheckpointVerifier for AcceptSignature {
        fn verify_checkpoint(&self, _: &str, _: DateTime<Utc>, _: &[u8], signature: &str) -> bool {
            signature == "a".repeat(128)
        }
    }

    #[test]
    fn detects_tampering() {
        let directory = tempfile::tempdir().unwrap();
        let ledger = directory.path().join("receipts.jsonl");
        append_receipt(
            &ledger,
            "inventory",
            "repo",
            EvidenceStatus::Verified,
            vec!["a".into()],
        )
        .unwrap();
        let changed = std::fs::read_to_string(&ledger)
            .unwrap()
            .replace("inventory", "invented");
        std::fs::write(&ledger, changed).unwrap();
        assert!(verify_ledger(&ledger).is_err());
    }

    #[test]
    fn typed_evidence_tampering_invalidates_ledger() {
        let directory = tempfile::tempdir().unwrap();
        let ledger = directory.path().join("receipts.jsonl");
        let evidence = EvidenceArtifact::from_bytes("test_receipt", "test.json", b"passed");
        append_evidence_receipt(
            &ledger,
            "review",
            "repo",
            EvidenceStatus::Verified,
            vec![evidence],
        )
        .unwrap();
        let changed = fs::read_to_string(&ledger)
            .unwrap()
            .replace("test.json", "other.json");
        fs::write(&ledger, changed).unwrap();
        assert!(verify_ledger(&ledger).is_err());
    }

    #[test]
    fn concurrent_appends_preserve_every_chain_link() {
        let directory = tempfile::tempdir().unwrap();
        let ledger = directory.path().join("receipts.jsonl");
        let workers = 24;
        thread::scope(|scope| {
            let mut handles = Vec::new();
            for index in 0..workers {
                let ledger = &ledger;
                handles.push(scope.spawn(move || {
                    append_receipt(
                        ledger,
                        "concurrent-review",
                        &format!("repo-{index}"),
                        EvidenceStatus::Verified,
                        vec![format!("evidence-{index}")],
                    )
                    .unwrap();
                }));
            }
            for handle in handles {
                handle.join().unwrap();
            }
        });
        assert_eq!(verify_ledger(&ledger).unwrap(), workers);
    }

    #[test]
    fn strict_verification_detects_changed_source_content() {
        let directory = tempfile::tempdir().unwrap();
        let ledger = directory.path().join("receipts.jsonl");
        let source = directory.path().join("result.json");
        let store = directory.path().join("store");
        fs::write(&source, b"passed").unwrap();
        append_evidence_receipt(
            &ledger,
            "review",
            "repo",
            EvidenceStatus::Verified,
            vec![EvidenceArtifact::store_file("test_receipt", &source, &store).unwrap()],
        )
        .unwrap();
        assert_eq!(
            verify_ledger_evidence_with_root(&ledger, &store).unwrap(),
            1
        );
        let blob = store
            .join("sha256")
            .join(hex::encode(Sha256::digest(b"passed")));
        fs::write(blob, b"failed").unwrap();
        assert!(verify_ledger_evidence_with_root(&ledger, &store).is_err());
    }

    #[test]
    fn checkpoint_detects_tail_removal_and_bad_signature() {
        let directory = tempfile::tempdir().unwrap();
        let ledger = directory.path().join("receipts.jsonl");
        for subject in ["first", "second"] {
            append_receipt(
                &ledger,
                "review",
                subject,
                EvidenceStatus::Verified,
                vec![subject.into()],
            )
            .unwrap();
        }
        let checkpoint =
            create_ledger_checkpoint(&ledger, "owner/repo", "key-1", "a".repeat(128)).unwrap();
        assert_eq!(
            verify_ledger_checkpoint(&ledger, &checkpoint, &AcceptSignature).unwrap(),
            2
        );
        let mut forged = checkpoint.clone();
        forged.signature = "forged".into();
        assert!(verify_ledger_checkpoint(&ledger, &forged, &AcceptSignature).is_err());
        let first = fs::read_to_string(&ledger)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_owned();
        fs::write(&ledger, format!("{first}\n")).unwrap();
        assert!(verify_ledger_checkpoint(&ledger, &checkpoint, &AcceptSignature).is_err());
    }

    #[test]
    fn checkpoint_creation_rejects_schema_invalid_signature() {
        let directory = tempfile::tempdir().unwrap();
        let ledger = directory.path().join("receipts.jsonl");
        append_receipt(
            &ledger,
            "review",
            "repo",
            EvidenceStatus::Verified,
            vec!["evidence".into()],
        )
        .unwrap();
        assert!(create_ledger_checkpoint(&ledger, "owner/repo", "key-1", "x").is_err());
        assert!(create_ledger_checkpoint(&ledger, "owner/repo", "key-1", "A".repeat(128)).is_err());
    }
}
