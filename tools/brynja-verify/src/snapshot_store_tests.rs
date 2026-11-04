use super::*;
use serde_json::{Value, json};

fn sample() -> State {
    let snapshot = json!({"fingerprint":"recorded-fingerprint", "inputs":{"file:a":"hash-a"}});
    let row = json!({
        "id":"original-id", "source":"original-source", "started":"original-start",
        "ended":"original-end", "outcome":"passed", "explanation":"original-explanation",
        "command":["fake", "arg"], "stdin":"vectors.txt", "cwd":".",
        "environment":{"SETTING":"value"}, "before":snapshot, "after":snapshot,
        "log":"verification/.runner/logs/original.log", "log_sha256":"original-log-hash"
    });
    let mut failed = row.clone();
    failed["id"] = "failed-id".into();
    failed["outcome"] = "failed".into();
    // A recorded fingerprint is not a content ID; all fields must survive.
    failed["after"]["inputs"]["file:a"] = "different-hash".into();
    let mut running = row.clone();
    running["id"] = "running-id".into();
    running["outcome"] = "running".into();
    running["ended"] = Value::Null;
    running["after"] = Value::Null;
    let mut interrupted = running.clone();
    interrupted["id"] = "interrupted-id".into();
    interrupted["outcome"] = "interrupted".into();
    serde_json::from_value(json!({"schema":1,
        "attempts":{"md5/a":[row.clone(), failed, running, interrupted], "aes/b":[row]},
        "views":{"md5/a":{"checked_at":"old-scan", "fingerprint":null,
            "result":"interrupted", "freshness":"old-freshness", "source":"old-source",
            "performed_at":"old-date", "last_success":"original-end"}},
        "historical":[{"reference":"old-reference", "explanation":"not a current pass"}]
    }))
    .unwrap()
}

fn legacy(root: &Path, state: &State) -> Vec<u8> {
    fs::create_dir_all(root.join("verification")).unwrap();
    let bytes = serde_json::to_vec_pretty(state).unwrap();
    fs::write(root.join(storage::STATE), &bytes).unwrap();
    bytes
}

fn index(root: &Path) -> Value {
    serde_json::from_slice(&fs::read(root.join(storage::STATE)).unwrap()).unwrap()
}

fn first_id(root: &Path) -> String {
    index(root)["attempts"]["md5/a"][0]["before"]
        .as_str()
        .unwrap()
        .into()
}

fn objects(root: &Path) -> Vec<std::path::PathBuf> {
    fs::read_dir(root.join(storage::SNAPSHOTS))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect()
}

fn equal_contents(left: &State, right: &State) {
    let mut left = serde_json::to_value(left).unwrap();
    let mut right = serde_json::to_value(right).unwrap();
    left["schema"] = Value::Null;
    right["schema"] = Value::Null;
    assert_eq!(left, right);
}

#[test]
fn migration_preserves_every_field_and_deduplicates_full_content() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let original = sample();
    legacy(root, &original);
    let old = storage::load(root).unwrap();
    assert!(!root.join(storage::SNAPSHOTS).exists()); // read-only compatibility
    equal_contents(&original, &old);
    storage::save(root, &old).unwrap();
    let disk = index(root);
    assert_eq!(disk["schema"], 2);
    assert_eq!(objects(root).len(), 2);
    let rows = &disk["attempts"]["md5/a"];
    assert_eq!(rows[0]["before"], rows[0]["after"]);
    assert_ne!(rows[1]["before"], rows[1]["after"]);
    assert_eq!(rows[0]["before"], disk["attempts"]["aes/b"][0]["before"]);
    assert!(rows[2]["after"].is_null());
    for path in objects(root) {
        let id = path.file_stem().unwrap().to_str().unwrap();
        assert_eq!(inputs::hash(&fs::read(&path).unwrap()), id);
    }
    let restored = storage::load(root).unwrap();
    equal_contents(&original, &restored);
    // Reversion/failure precedence, including running records, is unchanged.
    for now in [
        old.attempts["md5/a"][0].before.clone(),
        old.attempts["md5/a"][1].after.clone().unwrap(),
    ] {
        assert_eq!(
            crate::report::view(&old.attempts["md5/a"], &Ok((*now).clone())),
            crate::report::view(&restored.attempts["md5/a"], &Ok((*now).clone()))
        );
    }
    let bytes = fs::read(root.join(storage::STATE)).unwrap();
    storage::save(root, &restored).unwrap();
    assert_eq!(fs::read(root.join(storage::STATE)).unwrap(), bytes);
    assert_eq!(objects(root).len(), 2);
}

#[test]
fn missing_or_corrupt_objects_never_load_or_repair_silently() {
    for missing in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let original = sample();
        storage::save(root, &original).unwrap();
        let bytes = fs::read(root.join(storage::STATE)).unwrap();
        let path = root.join(name(&first_id(root)).unwrap());
        if missing {
            fs::remove_file(&path).unwrap();
        } else {
            fs::write(&path, b"corrupt").unwrap();
        }
        assert!(storage::load(root).is_err());
        assert_eq!(fs::read(root.join(storage::STATE)).unwrap(), bytes);
        if !missing {
            assert!(storage::save(root, &original).is_err());
            assert_eq!(fs::read(path).unwrap(), b"corrupt");
            assert_eq!(fs::read(root.join(storage::STATE)).unwrap(), bytes);
        }
    }
}

#[test]
fn invalid_references_and_schemas_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    storage::save(root, &sample()).unwrap();
    let original = index(root);
    for bad in [
        json!("../../outside"),
        json!("A".repeat(64)),
        json!("a".repeat(63)),
        json!("g".repeat(64)),
        json!({"fingerprint":"inline", "inputs":{}}),
        Value::Null,
    ] {
        let mut changed = original.clone();
        changed["attempts"]["md5/a"][0]["before"] = bad;
        assert!(decode(root, &serde_json::to_vec(&changed).unwrap()).is_err());
    }
    for schema in [0, 3, u32::MAX] {
        let mut changed = original.clone();
        changed["schema"] = schema.into();
        assert!(decode(root, &serde_json::to_vec(&changed).unwrap()).is_err());
    }
    let mut changed = original;
    changed["unknown"] = true.into();
    assert!(decode(root, &serde_json::to_vec(&changed).unwrap()).is_err());
}

#[test]
fn hash_valid_but_malformed_snapshot_is_rejected() {
    for bytes in [
        b"not-json".as_slice(),
        b"{\"fingerprint\":\"x\"}",
        b"{\"fingerprint\":\"x\",\"inputs\":{},\"unknown\":1}",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        storage::save(root, &sample()).unwrap();
        let id = inputs::hash(bytes);
        fs::write(root.join(name(&id).unwrap()), bytes).unwrap();
        let mut disk = index(root);
        disk["attempts"]["md5/a"][0]["before"] = id.into();
        assert!(decode(root, &serde_json::to_vec(&disk).unwrap()).is_err());
    }
}

#[test]
fn interrupted_object_or_index_write_leaves_legacy_index_usable() {
    for block_objects in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let state = sample();
        let old = legacy(root, &state);
        let parent = if block_objects {
            root.join(storage::SNAPSHOTS)
        } else {
            root.join("verification")
        };
        fs::create_dir_all(&parent).unwrap();
        let temporary = parent.join(format!(".verify-{}.tmp", std::process::id()));
        fs::write(&temporary, "interrupted partial write").unwrap();
        assert!(storage::save(root, &state).is_err());
        assert_eq!(fs::read(root.join(storage::STATE)).unwrap(), old);
        equal_contents(&storage::load(root).unwrap(), &state);
        assert_eq!(fs::read(&temporary).unwrap(), b"interrupted partial write");
        // Complete orphan objects after a failed index commit are safe to reuse.
        fs::remove_file(temporary).unwrap();
        storage::save(root, &state).unwrap();
        equal_contents(&storage::load(root).unwrap(), &state);
    }
}

#[cfg(unix)]
#[test]
fn symlinked_object_or_directory_is_rejected_even_if_content_matches() {
    use std::os::unix::fs::symlink;
    for directory_link in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let state = sample();
        storage::save(root, &state).unwrap();
        let path = if directory_link {
            root.join(storage::SNAPSHOTS)
        } else {
            root.join(name(&first_id(root)).unwrap())
        };
        let moved = root.join("moved");
        fs::rename(&path, &moved).unwrap();
        symlink(&moved, path).unwrap();
        assert!(storage::load(root).is_err());
        assert!(storage::save(root, &state).is_err());
    }
}

#[test]
fn ten_thousand_references_share_one_large_allocation() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    storage::save(root, &sample()).unwrap();
    let snapshot = Snapshot {
        fingerprint: "large-shared-object".into(),
        inputs: [("large".into(), "x".repeat(140 * 1024))].into(),
    };
    let bytes = store_limits::encode(&snapshot, LIMITS.object, false).unwrap();
    let id = inputs::hash(&bytes);
    fs::write(root.join(name(&id).unwrap()), bytes).unwrap();
    let mut disk: State<String> = serde_json::from_value(index(root)).unwrap();
    let mut row = disk.attempts["md5/a"][0].clone();
    row.before = id.clone();
    row.after = Some(id);
    disk.attempts = [("md5/a".into(), vec![row.clone(); LIMITS.attempts])].into();
    let bytes = store_limits::encode(&disk, LIMITS.index, false).unwrap();
    // 20,000 references would formerly deep-copy roughly 2.7 GiB.
    let loaded = decode(root, &bytes).unwrap();
    let first = &loaded.attempts["md5/a"][0].before;
    assert_eq!(first.inputs["large"].len(), 140 * 1024);
    for row in &loaded.attempts["md5/a"] {
        assert!(Arc::ptr_eq(first, &row.before));
        assert!(Arc::ptr_eq(first, row.after.as_ref().unwrap()));
    }
    // The cap applies across keys, not just within a single group.
    disk.attempts.insert("aes/b".into(), vec![row]);
    let bytes = store_limits::encode(&disk, LIMITS.index, false).unwrap();
    assert!(
        decode(root, &bytes)
            .unwrap_err()
            .to_string()
            .contains("attempt count")
    );
    // Refuse the next row before even parsing its contents (and across keys).
    let mut invalid_next = serde_json::to_value(&disk).unwrap();
    invalid_next["attempts"]
        .as_object_mut()
        .unwrap()
        .remove("aes/b");
    invalid_next["attempts"]["zz/overflow"] = json!([null]);
    let bytes = serde_json::to_vec(&invalid_next).unwrap();
    assert!(
        decode(root, &bytes)
            .unwrap_err()
            .to_string()
            .contains("attempt count")
    );
}

#[test]
fn load_budgets_accept_exact_boundaries_and_reject_excess_before_expansion() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    storage::save(root, &sample()).unwrap();
    let bytes = fs::read(root.join(storage::STATE)).unwrap();
    let sizes: Vec<_> = objects(root)
        .iter()
        .map(|p| fs::metadata(p).unwrap().len() as usize)
        .collect();
    let limits = Limits {
        index: bytes.len(),
        object: *sizes.iter().max().unwrap(),
        total_objects: sizes.iter().sum(),
        attempts: 5,
    };
    equal_contents(
        &sample(),
        &decode_with_limits(root, &bytes, limits).unwrap(),
    );
    for limited in [
        Limits {
            index: limits.index - 1,
            ..limits
        },
        Limits {
            object: limits.object - 1,
            ..limits
        },
        Limits {
            total_objects: limits.total_objects - 1,
            ..limits
        },
        Limits {
            attempts: 4,
            ..limits
        },
    ] {
        assert!(
            decode_with_limits(root, &bytes, limited)
                .unwrap_err()
                .to_string()
                .contains("storage limit")
        );
    }
    // Refuse the count before trying to read any referenced objects.
    for path in objects(root) {
        fs::remove_file(path).unwrap();
    }
    assert!(
        decode_with_limits(
            root,
            &bytes,
            Limits {
                attempts: 4,
                ..limits
            }
        )
        .unwrap_err()
        .to_string()
        .contains("attempt count")
    );
    let legacy = serde_json::to_vec(&sample()).unwrap();
    assert!(
        decode_with_limits(
            root,
            &legacy,
            Limits {
                index: legacy.len() - 1,
                ..LIMITS
            }
        )
        .is_err()
    );
    assert!(
        decode_with_limits(
            root,
            &legacy,
            Limits {
                attempts: 4,
                ..LIMITS
            }
        )
        .is_err()
    );
    equal_contents(
        &sample(),
        &decode_with_limits(
            root,
            &legacy,
            Limits {
                index: legacy.len(),
                attempts: 5,
                ..LIMITS
            },
        )
        .unwrap(),
    );
}

#[test]
fn save_budgets_never_replace_a_usable_index_with_unreadable_state() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let state = sample();
    storage::save(root, &state).unwrap();
    let original = fs::read(root.join(storage::STATE)).unwrap();
    let sizes: Vec<_> = objects(root)
        .iter()
        .map(|p| fs::metadata(p).unwrap().len() as usize)
        .collect();
    let exact = Limits {
        index: original.len(),
        object: *sizes.iter().max().unwrap(),
        total_objects: sizes.iter().sum(),
        attempts: 5,
    };
    save_with_limits(root, &state, exact).unwrap();
    for limited in [
        Limits {
            index: exact.index - 1,
            ..exact
        },
        Limits {
            object: exact.object - 1,
            ..exact
        },
        Limits {
            total_objects: exact.total_objects - 1,
            ..exact
        },
        Limits {
            attempts: 4,
            ..exact
        },
    ] {
        assert!(
            save_with_limits(root, &state, limited)
                .unwrap_err()
                .to_string()
                .contains("storage limit")
        );
        assert_eq!(fs::read(root.join(storage::STATE)).unwrap(), original);
        equal_contents(&storage::load(root).unwrap(), &state);
    }
}

#[test]
fn save_refuses_oversized_existing_object_without_repair_or_index_change() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let state = sample();
    storage::save(root, &state).unwrap();
    let original = fs::read(root.join(storage::STATE)).unwrap();
    let path = root.join(name(&first_id(root)).unwrap());
    let length = (LIMITS.object as u64) + 1;
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(length)
        .unwrap();
    assert!(
        storage::save(root, &state)
            .unwrap_err()
            .to_string()
            .contains("storage limit")
    );
    assert_eq!(fs::metadata(path).unwrap().len(), length);
    assert_eq!(fs::read(root.join(storage::STATE)).unwrap(), original);
}
