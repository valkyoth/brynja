//! Storage-only interning. Execution and freshness continue using full snapshots.
use crate::{
    Result, inputs,
    model::*,
    storage,
    store_limits::{self, LIMITS, Limits},
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    sync::Arc,
};

#[cfg(test)]
#[path = "snapshot_store_tests.rs"]
mod tests;

fn name(id: &str) -> Result<String> {
    if id.len() != 64
        || !id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid snapshot content ID (expected lowercase SHA-256)".into());
    }
    Ok(format!("{}/{id}.json", storage::SNAPSHOTS))
}

fn read(
    root: &Path,
    id: &str,
    cache: &mut BTreeMap<String, Arc<Snapshot>>,
    total: &mut usize,
    limits: Limits,
) -> Result<Arc<Snapshot>> {
    if let Some(snapshot) = cache.get(id) {
        return Ok(snapshot.clone());
    }
    let path = storage::relative(root, &name(id)?)?;
    let remaining = limits
        .total_objects
        .checked_sub(*total)
        .ok_or("snapshot storage limit overflow")?;
    let bytes = store_limits::read(&path, limits.object.min(remaining))
        .map_err(|e| format!("cannot read snapshot {id}: {e}"))?;
    store_limits::charge(
        total,
        bytes.len(),
        limits.total_objects,
        "total snapshot bytes",
    )?;
    if inputs::hash(&bytes) != id {
        return Err(format!("snapshot content hash mismatch: {id}").into());
    }
    let snapshot = Arc::new(serde_json::from_slice::<Snapshot>(&bytes)?);
    cache.insert(id.to_owned(), snapshot.clone());
    Ok(snapshot)
}

pub fn decode(root: &Path, bytes: &[u8]) -> Result<State> {
    decode_with_limits(root, bytes, LIMITS)
}

fn check_attempts<S>(state: &State<S>, limits: Limits) -> Result<()> {
    let mut total = 0;
    for rows in state.attempts.values() {
        store_limits::charge(&mut total, rows.len(), limits.attempts, "attempt count")?;
    }
    Ok(())
}

fn decode_with_limits(root: &Path, bytes: &[u8], limits: Limits) -> Result<State> {
    store_limits::size(bytes.len(), limits.index, "index bytes")?;
    #[derive(Deserialize)]
    struct Header {
        schema: u32,
    }
    match serde_json::from_slice::<Header>(bytes)?.schema {
        1 => {
            // Inline snapshots cannot amplify references: their total serialized
            // size is already bounded by the index budget. They remain readable
            // for migration; schema 2 uses shared immutable objects below.
            let state: State = serde_json::from_slice(bytes)?;
            check_attempts(&state, limits)?;
            Ok(state)
        }
        2 => {
            let disk: State<String> = serde_json::from_slice(bytes)?;
            check_attempts(&disk, limits)?;
            let mut cache = BTreeMap::new();
            let mut total = 0;
            let mut attempts = BTreeMap::new();
            for (key, rows) in disk.attempts {
                let mut expanded = Vec::with_capacity(rows.len());
                for row in rows {
                    let before = read(root, &row.before, &mut cache, &mut total, limits)?;
                    let after = row
                        .after
                        .as_ref()
                        .map(|id| read(root, id, &mut cache, &mut total, limits))
                        .transpose()?;
                    expanded.push(row.with_snapshots(before, after));
                }
                attempts.insert(key, expanded);
            }
            Ok(State {
                schema: 2,
                attempts,
                views: disk.views,
                historical: disk.historical,
            })
        }
        _ => Err("unsupported results schema".into()),
    }
}

fn write(
    root: &Path,
    snapshot: &Snapshot,
    saved: &mut BTreeSet<String>,
    total: &mut usize,
    limits: Limits,
) -> Result<String> {
    // ID covers the entire serialized object, NOT just its recorded input
    // fingerprint. Before/after equality must still compare every input.
    let bytes = store_limits::encode(snapshot, limits.object, false)?;
    let id = inputs::hash(&bytes);
    if saved.contains(&id) {
        return Ok(id);
    }
    store_limits::charge(
        total,
        bytes.len(),
        limits.total_objects,
        "total snapshot bytes",
    )?;
    let relative = name(&id)?;
    let path = storage::relative(root, &relative)?;
    match fs::metadata(&path) {
        Ok(_) => {
            let existing = store_limits::read(&path, limits.object)?;
            if existing != bytes {
                return Err(format!("refusing to overwrite corrupt snapshot: {id}").into());
            }
            // Also complete durability of an orphan from a previously failed
            // save before publishing a reference to it in the index.
            fs::File::open(&path)?.sync_all()?;
            storage::sync_parents(root, &path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            storage::atomic(root, &relative, &bytes)?
        }
        Err(e) => return Err(e.into()),
    }
    saved.insert(id.clone());
    Ok(id)
}

pub fn save(root: &Path, state: &State) -> Result<()> {
    save_with_limits(root, state, LIMITS)
}

fn save_with_limits(root: &Path, state: &State, limits: Limits) -> Result<()> {
    if !matches!(state.schema, 1 | 2) {
        return Err("unsupported results schema".into());
    }
    check_attempts(state, limits)?;
    let mut saved = BTreeSet::new();
    let mut total = 0;
    let mut attempts = BTreeMap::new();
    for (key, rows) in &state.attempts {
        let mut compact = Vec::with_capacity(rows.len());
        for row in rows {
            let before = write(root, &row.before, &mut saved, &mut total, limits)?;
            let after = row
                .after
                .as_ref()
                .map(|s| write(root, s, &mut saved, &mut total, limits))
                .transpose()?;
            compact.push(row.with_snapshots(before, after));
        }
        attempts.insert(key, compact);
    }
    #[derive(serde::Serialize)]
    struct Index<'a> {
        schema: u32,
        attempts: BTreeMap<&'a String, Vec<Attempt<String>>>,
        views: &'a BTreeMap<String, View>,
        historical: &'a Vec<Historical>,
    }
    // Objects first, atomic index last. A failed/interrupted save can leave
    // unreferenced objects, never an index referencing a partial object. No GC.
    let disk = Index {
        schema: 2,
        attempts,
        views: &state.views,
        historical: &state.historical,
    };
    let bytes = store_limits::encode(&disk, limits.index, true)?;
    storage::atomic(root, storage::STATE, &bytes)
}
