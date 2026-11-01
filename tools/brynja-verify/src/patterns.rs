//! Small fixed-depth file patterns, not repository-wide dependency discovery.
use crate::{Result, inputs, storage};
use std::{collections::BTreeSet, fs, path::Path};

pub fn validate(root: &Path, pattern: &str) -> Result<()> {
    let first = pattern.split('/').next().unwrap_or_default();
    if first.is_empty()
        || first.contains('*')
        || !pattern.contains('*')
        || pattern.contains("**")
        || pattern.contains(['?', '[', ']', '\\'])
        || pattern
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
        || inputs::excluded(pattern)
    {
        return Err(format!("invalid fixed-depth file pattern: {pattern}").into());
    }
    storage::relative(root, pattern)?;
    Ok(())
}

fn segment(pattern: &str, name: &str) -> bool {
    let parts: Vec<_> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }
    let Some(mut rest) = name.strip_prefix(parts[0]) else {
        return false;
    };
    for part in &parts[1..parts.len() - 1] {
        let Some(index) = rest.find(part) else {
            return false;
        };
        rest = &rest[index + part.len()..];
    }
    rest.ends_with(parts[parts.len() - 1])
}

fn selected(pattern: &str, name: &str) -> bool {
    let p: Vec<_> = pattern.split('/').collect();
    let n: Vec<_> = name.split('/').collect();
    p.len() == n.len() && p.iter().zip(n).all(|(p, n)| segment(p, n))
}

fn walk(root: &Path, name: &str, parts: &[&str], names: &mut BTreeSet<String>) -> Result<()> {
    if inputs::excluded(name) {
        return Ok(());
    }
    let path = storage::relative(root, name)?;
    if parts.is_empty() {
        if path.is_file() {
            names.insert(name.into());
        } else if path.exists() {
            return Err(format!("pattern selected a non-file: {name}").into());
        }
        return Ok(());
    }
    if !path.try_exists()? {
        return Ok(());
    }
    if !path.is_dir() {
        return Err(format!("pattern parent is not a directory: {name}").into());
    }
    if parts[0].contains('*') {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let filename = entry.file_name();
            let filename = filename.to_str().ok_or("non-UTF8 pattern input")?;
            if segment(parts[0], filename) {
                walk(root, &format!("{name}/{filename}"), &parts[1..], names)?;
            }
        }
    } else {
        walk(root, &format!("{name}/{}", parts[0]), &parts[1..], names)?;
    }
    Ok(())
}

pub fn files(root: &Path, pattern: &str, revision: Option<&str>) -> Result<BTreeSet<String>> {
    validate(root, pattern)?;
    let parts: Vec<_> = pattern.split('/').collect();
    let mut names = BTreeSet::new();
    if let Some(rev) = revision {
        let raw = inputs::git(root, &["ls-tree", "-r", "-z", rev, "--", parts[0]])?;
        for entry in raw.split(|b| *b == 0).filter(|b| !b.is_empty()) {
            let entry = std::str::from_utf8(entry)?;
            let (metadata, name) = entry.split_once('\t').ok_or("invalid Git tree record")?;
            if selected(pattern, name) && !inputs::excluded(name) {
                if !metadata.starts_with("100644 blob ") && !metadata.starts_with("100755 blob ") {
                    return Err(format!("historical pattern selected a non-file: {name}").into());
                }
                names.insert(name.into());
            }
        }
    } else {
        walk(root, parts[0], &parts[1..], &mut names)?;
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn patterns_are_segment_bounded_and_non_overlapping() {
        assert!(selected(
            "scripts/*sha256*batch*.py",
            "scripts/check-sha256-batch.py"
        ));
        assert!(!selected("scripts/*.py", "scripts/nested/check.py"));
        assert!(!segment("ab*bc", "abc"));
        assert!(segment("ab*bc", "abbc"));
        assert!(!segment("*abc*bc", "abc"));
    }
}
