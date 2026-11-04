//! Storage-only interning. Execution and freshness continue using full snapshots.
use crate::{Result, inputs, model::*, storage};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::ErrorKind,
    path::Path,
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

fn read(root: &Path, id: &str, cache: &mut BTreeMap<String, Snapshot>) -> Result<Snapshot> {
    if let Some(snapshot) = cache.get(id) {
        return Ok(snapshot.clone());
    }
    let path = storage::relative(root, &name(id)?)?;
    let bytes = fs::read(&path).map_err(|e| format!("cannot read snapshot {id}: {e}"))?;
    if inputs::hash(&bytes) != id {
        return Err(format!("snapshot content hash mismatch: {id}").into());
    }
    let snapshot: Snapshot = serde_json::from_slice(&bytes)?;
    cache.insert(id.to_owned(), snapshot.clone());
    Ok(snapshot)
}

pub fn decode(root: &Path, bytes: &[u8]) -> Result<State> {
    #[derive(Deserialize)]
    struct Header {
        schema: u32,
    }
    match serde_json::from_slice::<Header>(bytes)?.schema {
        1 => Ok(serde_json::from_slice(bytes)?),
        2 => {
            let disk: State<String> = serde_json::from_slice(bytes)?;
            let mut cache = BTreeMap::new();
            let mut attempts = BTreeMap::new();
            for (key, rows) in disk.attempts {
                let mut expanded = Vec::with_capacity(rows.len());
                for row in rows {
                    let before = read(root, &row.before, &mut cache)?;
                    let after = row
                        .after
                        .as_ref()
                        .map(|id| read(root, id, &mut cache))
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

fn write(root: &Path, snapshot: &Snapshot, saved: &mut BTreeSet<String>) -> Result<String> {
    // ID covers the entire serialized object, NOT just its recorded input
    // fingerprint. Before/after equality must still compare every input.
    let mut bytes = serde_json::to_vec(snapshot)?;
    bytes.push(b'\n');
    let id = inputs::hash(&bytes);
    if saved.contains(&id) {
        return Ok(id);
    }
    let relative = name(&id)?;
    let path = storage::relative(root, &relative)?;
    match fs::read(&path) {
        Ok(existing) if existing == bytes => {
            // Also complete durability of an orphan from a previously failed
            // save before publishing a reference to it in the index.
            fs::File::open(&path)?.sync_all()?;
            storage::sync_parents(root, &path)?;
        }
        Ok(_) => return Err(format!("refusing to overwrite corrupt snapshot: {id}").into()),
        Err(e) if e.kind() == ErrorKind::NotFound => storage::atomic(root, &relative, &bytes)?,
        Err(e) => return Err(e.into()),
    }
    saved.insert(id.clone());
    Ok(id)
}

pub fn save(root: &Path, state: &State) -> Result<()> {
    if !matches!(state.schema, 1 | 2) {
        return Err("unsupported results schema".into());
    }
    let mut saved = BTreeSet::new();
    let mut attempts = BTreeMap::new();
    for (key, rows) in &state.attempts {
        let mut compact = Vec::with_capacity(rows.len());
        for row in rows {
            let before = write(root, &row.before, &mut saved)?;
            let after = row
                .after
                .as_ref()
                .map(|s| write(root, s, &mut saved))
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
    let mut bytes = serde_json::to_vec_pretty(&disk)?;
    bytes.push(b'\n');
    storage::atomic(root, storage::STATE, &bytes)
}
