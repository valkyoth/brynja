//! Explicit checkpoint/rotation. Archived rows never silently become live passes.
use crate::{
    Result, inputs,
    model::*,
    snapshot_store, storage,
    store_limits::{self, LIMITS},
};
use std::{collections::BTreeSet, fs, path::Path};

const MAX_ARCHIVES: usize = 1024;

fn name(id: &str) -> Result<String> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid archive content ID".into());
    }
    Ok(format!("{}/{id}.json", storage::ARCHIVES))
}

pub fn validate<S>(state: &State<S>) -> Result<()> {
    if !state.archives.is_empty() && state.schema != 3 {
        return Err("archive references require results schema 3".into());
    }
    store_limits::size(
        state.archives.len(),
        MAX_ARCHIVES,
        "archive reference count",
    )?;
    let mut seen = BTreeSet::new();
    for id in &state.archives {
        name(id)?;
        if !seen.insert(id) {
            return Err("duplicate archive reference".into());
        }
    }
    Ok(())
}

pub fn read(root: &Path, id: &str) -> Result<Vec<u8>> {
    let path = storage::relative(root, &name(id)?)?;
    let bytes = store_limits::read(&path, LIMITS.index)?;
    if inputs::hash(&bytes) != id {
        return Err("archive content hash mismatch".into());
    }
    // Validate this checkpoint and its snapshots, not its entire archive chain.
    snapshot_store::decode(root, &bytes)?;
    Ok(bytes)
}

pub fn rotate(root: &Path) -> Result<Option<String>> {
    let mut state = storage::load(root)?;
    if state
        .attempts
        .values()
        .flatten()
        .any(|r| r.outcome == "running")
    {
        return Err("cannot rotate running attempts; scan/recover interrupted state first".into());
    }
    if state.attempts.values().all(|rows| rows.len() <= 1) {
        return Ok(None);
    }
    store_limits::size(
        state.archives.len() + 1,
        MAX_ARCHIVES,
        "archive reference count",
    )?;
    let bytes = snapshot_store::index_bytes(root, &state, LIMITS)?;
    let id = inputs::hash(&bytes);
    let relative = name(&id)?;
    let path = storage::relative(root, &relative)?;
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            if store_limits::read(&path, LIMITS.index)? != bytes {
                return Err("refusing to overwrite corrupt results archive".into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    // Durable complete checkpoint first; interruption can leave an orphan, not
    // missing history. Retain all snapshots; no file deletion/garbage collection.
    storage::atomic(root, &relative, &bytes)?;
    for rows in state.attempts.values_mut() {
        if let Some(last) = rows.pop() {
            rows.clear();
            rows.push(last);
        }
    }
    // Old cached passes may have depended on now-archived matching-input rows.
    // Never carry those current-pass claims into the newly bounded live state.
    state.views.clear();
    state.schema = 3;
    state.archives.push(id.clone());
    // Invalidate derived claims before publishing the smaller live history.
    // If this write or the index write fails, the complete checkpoint remains.
    storage::atomic(root, storage::REPORT, b"# Verification results\n\nResults rotation requested. This derived report is invalidated; run a status scan to refresh it. No verification executed.\n")?;
    storage::save(root, &state)?;
    Ok(Some(id))
}

pub fn warnings(root: &Path) -> Result<Vec<String>> {
    let bytes = store_limits::read(&storage::relative(root, storage::STATE)?, LIMITS.index)?;
    let disk: State<String> = serde_json::from_slice(&bytes)?; // Called after a schema-2/3 save.
    let mut ids = BTreeSet::new();
    let mut attempts = 0;
    for row in disk.attempts.values().flatten() {
        store_limits::charge(&mut attempts, 1, LIMITS.attempts, "attempt count")?;
        ids.insert(&row.before);
        if let Some(after) = &row.after {
            ids.insert(after);
        }
    }
    let mut total = 0;
    let mut largest = 0;
    for id in ids {
        let path = storage::relative(root, &snapshot_store::name(id)?)?;
        let size = usize::try_from(fs::metadata(path)?.len())?;
        store_limits::charge(&mut total, size, LIMITS.total_objects, "snapshot bytes")?;
        largest = largest.max(size);
    }
    Ok(capacity_warnings([
        ("index bytes", bytes.len(), LIMITS.index),
        ("largest snapshot bytes", largest, LIMITS.object),
        ("unique snapshot bytes", total, LIMITS.total_objects),
        ("attempts", attempts, LIMITS.attempts),
        ("archive references", disk.archives.len(), MAX_ARCHIVES),
    ]))
}

fn capacity_warnings<const N: usize>(usage: [(&str, usize, usize); N]) -> Vec<String> {
    usage.into_iter().filter(|(_, used, limit)| *used >= limit / 4 * 3)
        .map(|(label, used, limit)| format!("Storage warning: {label} {used}/{limit} (at least 75%). Inspect capacity; rotate-results can archive older attempts, but cannot shrink a single object or the latest rows alone.")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warning_thresholds_include_exactly_three_quarters() {
        for limit in [
            LIMITS.index,
            LIMITS.object,
            LIMITS.total_objects,
            LIMITS.attempts,
            MAX_ARCHIVES,
        ] {
            let threshold = limit / 4 * 3;
            assert!(capacity_warnings([("test", threshold - 1, limit)]).is_empty());
            assert_eq!(capacity_warnings([("test", threshold, limit)]).len(), 1);
            assert_eq!(capacity_warnings([("test", limit, limit)]).len(), 1);
        }
    }

    #[test]
    fn archive_references_are_bounded_unique_and_versioned() {
        let mut state: State = State {
            archives: vec!["a".repeat(64)],
            ..State::default()
        };
        assert!(validate(&state).is_err());
        state.schema = 3;
        assert!(validate(&state).is_ok());
        state.archives.push(state.archives[0].clone());
        assert!(validate(&state).is_err());
        state.archives = vec!["../invalid".into()];
        assert!(validate(&state).is_err());
        state.archives = (0..MAX_ARCHIVES).map(|n| format!("{n:064x}")).collect();
        assert!(validate(&state).is_ok());
        state.archives.push("f".repeat(64));
        assert!(validate(&state).is_err());
    }
}
