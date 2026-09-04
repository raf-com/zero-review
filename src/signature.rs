use crate::{ApexProducerVerifier, LedgerCheckpointVerifier, OverrideSignatureVerifier};
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path};

const SCHEMA: &str = "zero-review.ed25519-keyring.v1";
const SCHEMA_V2: &str = "zero-review.ed25519-keyring.v2";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringFile {
    schema_version: String,
    keys: BTreeMap<String, KeyEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum KeyEntry {
    Legacy(String),
    Policy {
        public_key: String,
        roles: Vec<String>,
        not_before: DateTime<Utc>,
        not_after: DateTime<Utc>,
        revoked: bool,
    },
}

struct TrustedKey {
    key: VerifyingKey,
    roles: Vec<String>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
    revoked: bool,
}

pub struct Ed25519Keyring {
    keys: BTreeMap<String, TrustedKey>,
    explicit_role_policy: bool,
}

impl Ed25519Keyring {
    pub fn load(path: &Path) -> Result<Self> {
        let parsed: KeyringFile = serde_json::from_slice(
            &fs::read(path).with_context(|| format!("read keyring {}", path.display()))?,
        )
        .with_context(|| format!("parse keyring {}", path.display()))?;
        if parsed.schema_version != SCHEMA && parsed.schema_version != SCHEMA_V2 {
            bail!("unsupported keyring schema: {}", parsed.schema_version);
        }
        if parsed.keys.is_empty() {
            bail!("keyring must contain at least one key");
        }
        let mut keys = BTreeMap::new();
        for (id, entry) in parsed.keys {
            if id.trim().is_empty() {
                bail!("key id must not be empty");
            }
            let (encoded, roles, not_before, not_after, revoked) = match entry {
                KeyEntry::Legacy(value) if parsed.schema_version == SCHEMA => (
                    value,
                    vec!["apex_producer".into(), "override_approver".into()],
                    None,
                    None,
                    false,
                ),
                KeyEntry::Policy {
                    public_key,
                    roles,
                    not_before,
                    not_after,
                    revoked,
                } if parsed.schema_version == SCHEMA_V2 => {
                    if roles.is_empty() || not_after <= not_before {
                        bail!("key {id} has invalid role or validity policy");
                    }
                    (
                        public_key,
                        roles,
                        Some(not_before),
                        Some(not_after),
                        revoked,
                    )
                }
                _ => bail!("key {id} shape does not match keyring schema"),
            };
            let bytes = hex::decode(&encoded).with_context(|| format!("decode key {id}"))?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("key {id} must contain 32 bytes"))?;
            let key = VerifyingKey::from_bytes(&bytes)
                .with_context(|| format!("parse Ed25519 key {id}"))?;
            keys.insert(
                id.clone(),
                TrustedKey {
                    key,
                    roles,
                    not_before,
                    not_after,
                    revoked,
                },
            );
        }
        Ok(Self {
            keys,
            explicit_role_policy: parsed.schema_version == SCHEMA_V2,
        })
    }

    fn verify_signature(&self, key_id: &str, role: &str, payload: &[u8], signature: &str) -> bool {
        self.verify_signature_at(key_id, role, Utc::now(), payload, signature)
    }

    fn verify_signature_at(
        &self,
        key_id: &str,
        role: &str,
        signed_at: DateTime<Utc>,
        payload: &[u8],
        signature: &str,
    ) -> bool {
        let Some(key) = self.keys.get(key_id) else {
            return false;
        };
        if role != "apex_producer" && !self.explicit_role_policy {
            return false;
        }
        if key.revoked
            || !key.roles.iter().any(|value| value == role)
            || key.not_before.is_some_and(|value| signed_at < value)
            || key.not_after.is_some_and(|value| signed_at >= value)
        {
            return false;
        }
        let Ok(bytes) = hex::decode(signature) else {
            return false;
        };
        let Ok(signature) = Signature::try_from(bytes.as_slice()) else {
            return false;
        };
        key.key.verify(payload, &signature).is_ok()
    }
}

impl ApexProducerVerifier for Ed25519Keyring {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        self.verify_signature(key_id, "apex_producer", payload, signature)
    }
}

impl OverrideSignatureVerifier for Ed25519Keyring {
    fn verify(&self, key_id: &str, payload: &[u8], signature: &str) -> bool {
        self.verify_signature(key_id, "override_approver", payload, signature)
    }
}

impl LedgerCheckpointVerifier for Ed25519Keyring {
    fn verify_checkpoint(
        &self,
        key_id: &str,
        _signed_at: DateTime<Utc>,
        payload: &[u8],
        signature: &str,
    ) -> bool {
        // A self-asserted signed timestamp is not a trusted timestamp. Current
        // key validity is required until an external witness/TSA is integrated.
        self.verify_signature(key_id, "ledger_checkpoint", payload, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ApexProducerVerifier, EvidenceArtifact, EvidenceStatus, append_evidence_receipt,
        create_ledger_checkpoint_at, ledger_checkpoint_payload, verify_ledger_checkpoint,
    };
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn verifies_rfc8032_vector_and_rejects_unknown_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.json");
        fs::write(
            &path,
            r#"{"schema_version":"zero-review.ed25519-keyring.v1","keys":{"rfc8032":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"}}"#,
        )
        .unwrap();
        let keyring = Ed25519Keyring::load(&path).unwrap();
        let signature = concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(ApexProducerVerifier::verify(
            &keyring, "rfc8032", b"", signature
        ));
        assert!(!ApexProducerVerifier::verify(
            &keyring, "missing", b"", signature
        ));
    }

    #[test]
    fn v2_key_policy_rejects_wrong_role_and_revoked_key() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.json");
        fs::write(&path, r#"{"schema_version":"zero-review.ed25519-keyring.v2","keys":{"restricted":{"public_key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","roles":["override_approver"],"not_before":"2020-01-01T00:00:00Z","not_after":"2099-01-01T00:00:00Z","revoked":false},"revoked":{"public_key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","roles":["apex_producer"],"not_before":"2020-01-01T00:00:00Z","not_after":"2099-01-01T00:00:00Z","revoked":true}}}"#).unwrap();
        let keyring = Ed25519Keyring::load(&path).unwrap();
        let signature = concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(!ApexProducerVerifier::verify(
            &keyring,
            "restricted",
            b"",
            signature
        ));
        assert!(!ApexProducerVerifier::verify(
            &keyring, "revoked", b"", signature
        ));
        assert!(OverrideSignatureVerifier::verify(
            &keyring,
            "restricted",
            b"",
            signature
        ));
    }

    #[test]
    fn legacy_keyring_cannot_authorize_governance_actions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("keys.json");
        fs::write(
            &path,
            r#"{"schema_version":"zero-review.ed25519-keyring.v1","keys":{"legacy":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"}}"#,
        )
        .unwrap();
        let keyring = Ed25519Keyring::load(&path).unwrap();
        let signature = concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(!OverrideSignatureVerifier::verify(
            &keyring, "legacy", b"", signature
        ));
        assert!(!LedgerCheckpointVerifier::verify_checkpoint(
            &keyring,
            "legacy",
            Utc::now(),
            b"",
            signature
        ));
    }

    #[test]
    fn real_signature_verifies_a_ledger_checkpoint() {
        let directory = tempfile::tempdir().unwrap();
        let keyring_path = directory.path().join("keys.json");
        fs::write(&keyring_path, r#"{"schema_version":"zero-review.ed25519-keyring.v2","keys":{"checkpoint":{"public_key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","roles":["ledger_checkpoint"],"not_before":"2020-01-01T00:00:00Z","not_after":"2099-01-01T00:00:00Z","revoked":false}}}"#).unwrap();
        let keyring = Ed25519Keyring::load(&keyring_path).unwrap();
        let ledger = directory.path().join("ledger.jsonl");
        let receipt = append_evidence_receipt(
            &ledger,
            "review",
            "owner/repo",
            EvidenceStatus::Verified,
            vec![EvidenceArtifact::from_bytes(
                "test",
                "sha256/blob",
                b"passed",
            )],
        )
        .unwrap();
        let created_at: DateTime<Utc> = "2026-09-04T12:00:00Z".parse().unwrap();
        let payload =
            ledger_checkpoint_payload("owner/repo", 1, &receipt.hash, "checkpoint", created_at)
                .unwrap();
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let signature = hex::encode(SigningKey::from_bytes(&seed).sign(&payload).to_bytes());
        let checkpoint =
            create_ledger_checkpoint_at(&ledger, "owner/repo", "checkpoint", created_at, signature)
                .unwrap();
        assert_eq!(
            verify_ledger_checkpoint(&ledger, &checkpoint, &keyring).unwrap(),
            1
        );
    }
}
