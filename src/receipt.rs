use crate::{
    evidence::EvidenceArtifact,
    model::{EvidenceStatus, Receipt},
};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use fs2::FileExt;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
