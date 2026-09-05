use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
    time::Duration,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemConfig {
    pub schema_version: String,
    pub roots: Vec<EcosystemRootConfig>,
    #[serde(default)]
    pub discovery: Vec<EcosystemDiscoveryConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemDiscoveryConfig {
    pub parent: String,
    pub prefixes: Vec<String>,
    #[serde(default)]
    pub exclude_name_contains: Vec<String>,
    #[serde(default = "default_candidate_limit")]
    pub max_candidates: usize,
}

fn default_candidate_limit() -> usize {
    512
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemRootConfig {
    pub id: String,
    pub path: String,
    pub family: String,
    pub capabilities: Vec<String>,
    pub review_needs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemRoot {
    #[serde(flatten)]
    pub configured: EcosystemRootConfig,
    pub exists: bool,
    pub rust_workspace: bool,
    pub git_repository: bool,
    pub git_head: Option<String>,
    pub canonical_path: Option<String>,
    pub git_common_dir: Option<String>,
    pub git_branch: Option<String>,
    pub git_remote_sha256: Option<String>,
    pub git_dirty: Option<bool>,
    pub evidence_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemInventory {
    pub schema_version: String,
    pub generated_at: String,
    pub roots: Vec<EcosystemRoot>,
    pub config_sha256: String,
    pub unregistered_candidates: Vec<String>,
    pub boundary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EcosystemDrift {
    pub stale: bool,
    pub missing_roots: Vec<String>,
    pub removed_roots: Vec<String>,
    pub renamed_roots: Vec<String>,
    pub duplicate_paths: Vec<String>,
    pub new_roots: Vec<String>,
    pub head_drift: Vec<String>,
    pub identity_drift: Vec<String>,
    pub baseline_sha256: String,
    pub current_sha256: String,
    pub config_sha256: String,
    pub observed_at: String,
    pub max_age_seconds: u64,
}

impl EcosystemDrift {
    pub fn is_clean(&self) -> bool {
        !self.stale
            && self.missing_roots.is_empty()
            && self.removed_roots.is_empty()
            && self.renamed_roots.is_empty()
            && self.duplicate_paths.is_empty()
            && self.new_roots.is_empty()
            && self.head_drift.is_empty()
            && self.identity_drift.is_empty()
    }
}

pub fn inventory_ecosystem(config_path: &Path) -> Result<EcosystemInventory> {
    let config_bytes =
        fs::read(config_path).with_context(|| format!("read {}", config_path.display()))?;
    let parsed: EcosystemConfig = serde_json::from_slice(&config_bytes)?;
    if parsed.schema_version != "zero-review.ecosystem-config.v1" {
        anyhow::bail!("unsupported ecosystem config schema")
    }
    validate_config(&parsed)?;
    let roots: Vec<EcosystemRoot> = parsed
        .roots
        .iter()
        .cloned()
        .map(|configured| {
            let path = Path::new(&configured.path);
            let exists = path.is_dir();
            let rust_workspace = exists && path.join("Cargo.toml").is_file();
            let git_head = exists.then(|| git(path, &["rev-parse", "HEAD"])).flatten();
            let canonical_path = exists
                .then(|| fs::canonicalize(path).ok())
                .flatten()
                .map(|p| p.display().to_string());
            let git_common_dir = exists
                .then(|| git(path, &["rev-parse", "--git-common-dir"]))
                .flatten();
            let git_branch = exists
                .then(|| git(path, &["symbolic-ref", "--short", "-q", "HEAD"]))
                .flatten();
            let git_remote_sha256 = exists
                .then(|| git(path, &["config", "--get", "remote.origin.url"]))
                .flatten()
                .map(|v| sha256(v.as_bytes()));
            let git_dirty = exists
                .then(|| git_allow_empty(path, &["status", "--porcelain"]))
                .flatten()
                .map(|v| !v.is_empty());
            EcosystemRoot {
                configured,
                exists,
                rust_workspace,
                git_repository: git_head.is_some(),
                git_head,
                canonical_path,
                git_common_dir,
                git_branch,
                git_remote_sha256,
                git_dirty,
                evidence_status: if exists { "source_only" } else { "not_proven" }.into(),
            }
        })
        .collect();
    let unregistered_candidates = discover_candidates(&parsed, &roots)?;
    Ok(EcosystemInventory {
        schema_version: "zero-review.ecosystem-inventory.v1".into(),
        generated_at: Utc::now().to_rfc3339(),
        roots,
        config_sha256: sha256(&config_bytes),
        unregistered_candidates,
        boundary: "Filesystem and Git discovery only; no runtime, deployment, hosted-CI, or policy-enforcement claim is implied.".into(),
    })
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn discover_candidates(config: &EcosystemConfig, roots: &[EcosystemRoot]) -> Result<Vec<String>> {
    let registered: BTreeSet<_> = roots
        .iter()
        .filter_map(|r| r.canonical_path.as_deref())
        .map(normalize_path)
        .collect();
    let mut found = BTreeSet::new();
    for rule in &config.discovery {
        if rule.max_candidates == 0 || rule.max_candidates > 4096 {
            anyhow::bail!("discovery max_candidates outside allowed range");
        }
        let parent = Path::new(&rule.parent);
        if !parent.is_dir() {
            continue;
        }
        let mut examined = 0usize;
        for entry in fs::read_dir(parent)
            .with_context(|| format!("discover ecosystem roots under {}", parent.display()))?
        {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if !rule.prefixes.iter().any(|p| name.starts_with(p))
                || rule.exclude_name_contains.iter().any(|x| name.contains(x))
            {
                continue;
            }
            examined += 1;
            if examined > rule.max_candidates {
                anyhow::bail!(
                    "ecosystem discovery exceeded candidate limit under {}",
                    parent.display()
                );
            }
            let path = fs::canonicalize(entry.path())?;
            if !registered.contains(&normalize_path(&path.display().to_string()))
                && (path.join(".git").exists() || path.join("Cargo.toml").is_file())
            {
                found.insert(path.display().to_string());
            }
        }
    }
    Ok(found.into_iter().collect())
}

fn validate_config(config: &EcosystemConfig) -> Result<()> {
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for root in &config.roots {
        if root.id.trim().is_empty() || !ids.insert(root.id.as_str()) {
            anyhow::bail!(
                "ecosystem root ids must be non-empty and unique: {}",
                root.id
            );
        }
        let normalized = normalize_path(&root.path);
        if !paths.insert(normalized.clone()) {
            anyhow::bail!("ecosystem root paths must be unique: {normalized}");
        }
    }
    Ok(())
}

/// Compares a stored snapshot with a newly generated inventory. A caller chooses
/// the acceptable snapshot age; malformed or future timestamps fail closed.
pub fn detect_drift(
    baseline: &EcosystemInventory,
    current: &EcosystemInventory,
    now: DateTime<Utc>,
    max_age: Duration,
) -> Result<EcosystemDrift> {
    let generated = DateTime::parse_from_rfc3339(&baseline.generated_at)
        .context("parse ecosystem snapshot generated_at")?
        .with_timezone(&Utc);
    let age = now
        .signed_duration_since(generated)
        .to_std()
        .context("ecosystem snapshot timestamp is in the future")?;
    let old: BTreeMap<_, _> = baseline
        .roots
        .iter()
        .map(|r| (r.configured.id.as_str(), r))
        .collect();
    let new: BTreeMap<_, _> = current
        .roots
        .iter()
        .map(|r| (r.configured.id.as_str(), r))
        .collect();
    let mut path_owners: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for root in &current.roots {
        path_owners
            .entry(normalize_path(&root.configured.path))
            .or_default()
            .push(&root.configured.id);
    }
    let baseline_sha256 = sha256(&serde_json::to_vec(baseline)?);
    let current_sha256 = sha256(&serde_json::to_vec(current)?);
    let mut drift = EcosystemDrift {
        stale: age > max_age,
        missing_roots: current
            .roots
            .iter()
            .filter(|r| !r.exists)
            .map(|r| r.configured.id.clone())
            .collect(),
        removed_roots: old
            .keys()
            .filter(|id| !new.contains_key(**id))
            .map(|id| (*id).to_owned())
            .collect(),
        renamed_roots: Vec::new(),
        duplicate_paths: path_owners
            .into_iter()
            .filter(|(_, owners)| owners.len() > 1)
            .map(|(path, _)| path)
            .collect(),
        new_roots: new
            .keys()
            .filter(|id| !old.contains_key(**id))
            .map(|id| (*id).to_owned())
            .collect(),
        head_drift: Vec::new(),
        identity_drift: Vec::new(),
        baseline_sha256,
        current_sha256,
        config_sha256: current.config_sha256.clone(),
        observed_at: now.to_rfc3339(),
        max_age_seconds: max_age.as_secs(),
    };
    for (id, before) in old {
        if let Some(after) = new.get(id) {
            if normalize_path(&before.configured.path) != normalize_path(&after.configured.path) {
                drift.renamed_roots.push(id.to_owned());
            }
            if before.git_head != after.git_head {
                drift.head_drift.push(id.to_owned());
            }
            if before.canonical_path != after.canonical_path
                || before.git_common_dir != after.git_common_dir
                || before.git_branch != after.git_branch
                || before.git_remote_sha256 != after.git_remote_sha256
                || before.git_dirty != after.git_dirty
            {
                drift.identity_drift.push(id.to_owned());
            }
        }
    }
    Ok(drift)
}

fn normalize_path(path: &str) -> String {
    path.replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase()
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    git_allow_empty(root, args).filter(|v| !v.is_empty())
}

fn git_allow_empty(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub fn render_ecosystem_diagram(inventory: &EcosystemInventory) -> String {
    let mut graph = String::from("flowchart LR\n  PR[Pull request] --> REVIEW[zero-review]\n");
    let families = ["zero", "apex", "repository"];
    for family in families {
        graph.push_str(&format!(
            "  subgraph {}[{} family]\n",
            family.to_uppercase(),
            family
        ));
        for root in inventory
            .roots
            .iter()
            .filter(|root| root.configured.family == family)
        {
            let style = if root.exists { "" } else { ":::missing" };
            graph.push_str(&format!(
                "    {}[\"{}\"]{}\n",
                node_id(&root.configured.id),
                root.configured.id,
                style
            ));
        }
        graph.push_str("  end\n");
    }
    for root in &inventory.roots {
        let node = node_id(&root.configured.id);
        if root.configured.family == "repository" {
            graph.push_str(&format!("  {} --> REVIEW\n", node));
        } else {
            graph.push_str(&format!("  REVIEW --> {}\n", node));
        }
    }
    graph.push_str("  classDef missing fill:#fee,stroke:#b00,stroke-dasharray:5 5\n");
    graph
}

fn node_id(value: &str) -> String {
    format!(
        "N_{}",
        value
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_root_is_not_proven() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("roots.json");
        fs::write(&config, r#"{"schema_version":"zero-review.ecosystem-config.v1","roots":[{"id":"missing","path":"Z:\\\\not-real","family":"zero","capabilities":[],"review_needs":[]}]}"#).unwrap();
        let result = inventory_ecosystem(&config).unwrap();
        assert!(!result.roots[0].exists);
        assert_eq!(result.roots[0].evidence_status, "not_proven");
    }

    fn inventory(at: &str, roots: Vec<(&str, &str, bool, Option<&str>)>) -> EcosystemInventory {
        EcosystemInventory {
            schema_version: "zero-review.ecosystem-inventory.v1".into(),
            generated_at: at.into(),
            roots: roots
                .into_iter()
                .map(|(id, path, exists, head)| EcosystemRoot {
                    configured: EcosystemRootConfig {
                        id: id.into(),
                        path: path.into(),
                        family: "zero".into(),
                        capabilities: vec![],
                        review_needs: vec![],
                    },
                    exists,
                    rust_workspace: false,
                    git_repository: head.is_some(),
                    git_head: head.map(str::to_owned),
                    canonical_path: Some(path.into()),
                    git_common_dir: None,
                    git_branch: None,
                    git_remote_sha256: None,
                    git_dirty: Some(false),
                    evidence_status: if exists { "source_only" } else { "not_proven" }.into(),
                })
                .collect(),
            config_sha256: format!("sha256:{}", "0".repeat(64)),
            unregistered_candidates: vec![],
            boundary: String::new(),
        }
    }

    #[test]
    fn detects_stale_missing_renamed_new_and_head_drift() {
        let baseline = inventory(
            "2026-01-01T00:00:00Z",
            vec![
                ("a", "C:\\a", true, Some("1")),
                ("gone", "C:\\gone", true, None),
            ],
        );
        let current = inventory(
            "2026-01-03T00:00:00Z",
            vec![
                ("a", "C:\\renamed", true, Some("2")),
                ("new", "C:\\new", false, None),
            ],
        );
        let now = DateTime::parse_from_rfc3339("2026-01-03T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let drift = detect_drift(&baseline, &current, now, Duration::from_secs(60)).unwrap();
        assert!(drift.stale);
        assert_eq!(drift.missing_roots, ["new"]);
        assert_eq!(drift.removed_roots, ["gone"]);
        assert_eq!(drift.renamed_roots, ["a"]);
        assert_eq!(drift.new_roots, ["new"]);
        assert_eq!(drift.head_drift, ["a"]);
        assert!(drift.baseline_sha256.starts_with("sha256:"));
        assert!(drift.current_sha256.starts_with("sha256:"));
        assert_eq!(drift.max_age_seconds, 60);
    }

    #[test]
    fn duplicate_paths_fail_config_validation_portably() {
        let config = EcosystemConfig {
            schema_version: "zero-review.ecosystem-config.v1".into(),
            discovery: vec![],
            roots: vec![
                EcosystemRootConfig {
                    id: "one".into(),
                    path: "C:/same".into(),
                    family: "zero".into(),
                    capabilities: vec![],
                    review_needs: vec![],
                },
                EcosystemRootConfig {
                    id: "two".into(),
                    path: "c:\\same\\".into(),
                    family: "zero".into(),
                    capabilities: vec![],
                    review_needs: vec![],
                },
            ],
        };
        assert!(
            validate_config(&config)
                .unwrap_err()
                .to_string()
                .contains("paths must be unique")
        );
    }

    #[test]
    fn duplicate_paths_in_external_snapshot_are_reported() {
        let baseline = inventory("2026-01-01T00:00:00Z", vec![]);
        let current = inventory(
            "2026-01-01T00:00:00Z",
            vec![
                ("one", "C:/same", true, None),
                ("two", "c:\\same", true, None),
            ],
        );
        let now = DateTime::parse_from_rfc3339("2026-01-01T00:00:01Z")
            .unwrap()
            .with_timezone(&Utc);
        let drift = detect_drift(&baseline, &current, now, Duration::from_secs(60)).unwrap();
        assert_eq!(drift.duplicate_paths, ["c:\\same"]);
    }

    #[test]
    fn bounded_discovery_reports_unregistered_candidates_and_honors_exclusions() {
        let temp = tempfile::tempdir().unwrap();
        let candidate = temp.path().join("zero-new");
        let excluded = temp.path().join("zero-new-wt");
        fs::create_dir_all(candidate.join(".git")).unwrap();
        fs::create_dir_all(excluded.join(".git")).unwrap();
        let config = EcosystemConfig {
            schema_version: "zero-review.ecosystem-config.v1".into(),
            roots: vec![],
            discovery: vec![EcosystemDiscoveryConfig {
                parent: temp.path().display().to_string(),
                prefixes: vec!["zero-".into()],
                exclude_name_contains: vec!["-wt".into()],
                max_candidates: 10,
            }],
        };
        let found = discover_candidates(&config, &[]).unwrap();
        assert_eq!(
            found,
            [fs::canonicalize(candidate).unwrap().display().to_string()]
        );
    }

    #[test]
    fn discovery_candidate_ceiling_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("zero-one")).unwrap();
        fs::create_dir(temp.path().join("zero-two")).unwrap();
        let config = EcosystemConfig {
            schema_version: "zero-review.ecosystem-config.v1".into(),
            roots: vec![],
            discovery: vec![EcosystemDiscoveryConfig {
                parent: temp.path().display().to_string(),
                prefixes: vec!["zero-".into()],
                exclude_name_contains: vec![],
                max_candidates: 1,
            }],
        };
        assert!(
            discover_candidates(&config, &[])
                .unwrap_err()
                .to_string()
                .contains("exceeded")
        );
    }
}
