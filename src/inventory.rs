use crate::model::{Control, EvidenceStatus, Inventory};
use anyhow::{Context, Result};
use chrono::Utc;
use std::path::Path;
use walkdir::WalkDir;

const REVIEW_MARKERS: &[(&str, &str)] = &[
    ("pull_request", "pull_request"),
    ("pull-request", "pull_request"),
    ("security", "security"),
    ("code_review", "review"),
    ("code-review", "review"),
    ("review", "review"),
    ("lint", "lint"),
    ("phpstan", "static_analysis"),
    ("eslint", "static_analysis"),
    ("semgrep", "security"),
    ("quality", "quality_gate"),
    ("approval", "approval"),
];

pub fn inventory_repository(root: &Path) -> Result<Inventory> {
    let canonical = root
        .canonicalize()
        .with_context(|| format!("repository does not exist: {}", root.display()))?;
    let mut controls = Vec::new();
    for entry in WalkDir::new(&canonical)
        .max_depth(6)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            !matches!(
                e.file_name().to_str(),
                Some(
                    ".git"
                        | ".claude"
                        | "node_modules"
                        | "vendor"
                        | "target"
                        | "storage"
                        | "_graveyard_2026-04-19"
                )
            )
        })
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let relative = entry
            .path()
            .strip_prefix(&canonical)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        let lower = relative.to_ascii_lowercase();
        let executable_surface = lower.starts_with(".github/")
            || lower.starts_with("scripts/")
            || lower.starts_with("config/")
            || lower.starts_with("orchestration/");
        if !executable_surface {
            continue;
        }
        let contents = std::fs::metadata(entry.path())
            .ok()
            .filter(|metadata| metadata.len() <= 1_048_576)
            .and_then(|_| std::fs::read_to_string(entry.path()).ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let searchable = format!("{lower}\n{contents}");
        if let Some((_, kind)) = REVIEW_MARKERS
            .iter()
            .find(|(marker, _)| searchable.contains(marker))
        {
            controls.push(Control {
                id: format!("control-{}", controls.len() + 1),
                kind: (*kind).into(),
                path: relative,
                status: EvidenceStatus::NotProven,
            });
        }
    }
    controls.sort_by(|a, b| a.path.cmp(&b.path));
    let kinds = |k: &str| controls.iter().any(|c| c.kind == k);
    let mut needs = Vec::new();
    if !kinds("pull_request") {
        needs.push("pull-request policy/control not discovered".into());
    }
    if !kinds("static_analysis") {
        needs.push("static-analysis control not discovered".into());
    }
    if !kinds("security") {
        needs.push("security review control not discovered".into());
    }
    if !kinds("approval") {
        needs.push("approval control not discovered".into());
    }
    if !controls
        .iter()
        .any(|control| control.path.contains("zero-codereview"))
    {
        needs.push("zero-codereview is not yet referenced by repository-local automation".into());
    }
    Ok(Inventory {
        repository: canonical.display().to_string(),
        generated_at: Utc::now().to_rfc3339(),
        controls,
        needs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_worktrees_and_discovers_executable_controls() {
        let directory = tempfile::tempdir().unwrap();
        let scripts = directory.path().join("scripts");
        let worktree = directory
            .path()
            .join(".claude")
            .join("worktrees")
            .join("one");
        std::fs::create_dir_all(&scripts).unwrap();
        std::fs::create_dir_all(&worktree).unwrap();
        std::fs::write(scripts.join("security-review.ps1"), "semgrep scan").unwrap();
        std::fs::write(worktree.join("code-review.py"), "review").unwrap();

        let inventory = inventory_repository(directory.path()).unwrap();
        assert_eq!(inventory.controls.len(), 1);
        assert_eq!(inventory.controls[0].kind, "security");
        assert!(!inventory.controls[0].path.contains(".claude"));
    }
}
