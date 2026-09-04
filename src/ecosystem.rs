use anyhow::{Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, process::Command};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemConfig {
    pub schema_version: String,
    pub roots: Vec<EcosystemRootConfig>,
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
    pub evidence_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemInventory {
    pub schema_version: String,
    pub generated_at: String,
    pub roots: Vec<EcosystemRoot>,
    pub boundary: String,
}

pub fn inventory_ecosystem(config_path: &Path) -> Result<EcosystemInventory> {
    let parsed: EcosystemConfig = serde_json::from_slice(
        &fs::read(config_path).with_context(|| format!("read {}", config_path.display()))?,
    )?;
    if parsed.schema_version != "zero-review.ecosystem-config.v1" {
        anyhow::bail!("unsupported ecosystem config schema")
    }
    let roots = parsed
        .roots
        .into_iter()
        .map(|configured| {
            let path = Path::new(&configured.path);
            let exists = path.is_dir();
            let rust_workspace = exists && path.join("Cargo.toml").is_file();
            let git_head = exists.then(|| git(path, &["rev-parse", "HEAD"])).flatten();
            EcosystemRoot {
                configured,
                exists,
                rust_workspace,
                git_repository: git_head.is_some(),
                git_head,
                evidence_status: if exists { "source_only" } else { "not_proven" }.into(),
            }
        })
        .collect();
    Ok(EcosystemInventory {
        schema_version: "zero-review.ecosystem-inventory.v1".into(),
        generated_at: Utc::now().to_rfc3339(),
        roots,
        boundary: "Filesystem and Git discovery only; no runtime, deployment, hosted-CI, or policy-enforcement claim is implied.".into(),
    })
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
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
        .filter(|v| !v.is_empty())
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
}
