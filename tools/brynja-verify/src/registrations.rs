//! Small, nonrecursive registry fragments; no runtime discovery or execution.
use crate::{Result, inputs, model::*, storage};
use serde::Deserialize;
use std::{collections::BTreeMap, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fragment {
    schema: u32,
    groups: BTreeMap<String, Group>,
    checks: Vec<Check>,
}

fn read(root: &Path, path: &str, revision: Option<&str>) -> Result<Vec<u8>> {
    let local = storage::relative(root, path)?;
    let bytes = match revision {
        Some(rev) => inputs::git(root, &["show", &format!("{rev}:{path}")])?,
        None => std::fs::read(local)?,
    };
    if bytes.len() > 32 * 1024 * 1024 {
        return Err("oversized registry fragment".into());
    }
    Ok(bytes)
}

pub fn load(root: &Path, revision: Option<&str>) -> Result<Registry> {
    let mut registry: Registry = toml::from_str(std::str::from_utf8(&read(
        root,
        "verification/checks.toml",
        revision,
    )?)?)?;
    for path in &registry.includes {
        let fragment: Fragment = serde_json::from_slice(&read(root, path, revision)?)?;
        if fragment.schema != 1 {
            return Err("unsupported registry fragment".into());
        }
        for (name, group) in fragment.groups {
            if registry.groups.insert(name, group).is_some() {
                return Err("duplicate input group in registry fragments".into());
            }
        }
        registry.checks.extend(fragment.checks);
    }
    Ok(registry)
}
