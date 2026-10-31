use crate::{Result, model::*, storage};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("git").args(args).current_dir(root).output()?;
    if !out.status.success() {
        return Err(format!("git {} unavailable", args.join(" ")).into());
    }
    Ok(out.stdout)
}

pub fn head(root: &Path) -> Result<String> {
    Ok(String::from_utf8(git(root, &["rev-parse", "HEAD"])?)?
        .trim()
        .into())
}

pub fn excluded(name: &str) -> bool {
    name == storage::STATE
        || name == storage::REPORT
        || name
            .split('/')
            .any(|p| matches!(p, ".git" | "target" | ".runner" | "__pycache__"))
}

fn read(root: &Path, path: &str, revision: Option<&str>) -> Result<Vec<u8>> {
    storage::relative(root, path)?;
    if let Some(rev) = revision {
        git(root, &["show", &format!("{rev}:{path}")])
    } else {
        Ok(fs::read(root.join(path))?)
    }
}

fn walk(root: &Path, path: &Path, names: &mut BTreeSet<String>) -> Result<()> {
    let name = path
        .strip_prefix(root)?
        .to_str()
        .ok_or("non-UTF8 input path")?
        .replace('\\', "/");
    if excluded(&name) {
        return Ok(());
    }
    if path.is_symlink() {
        return Err(format!("symlinked input: {name}").into());
    }
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            walk(root, &entry?.path(), names)?;
        }
    } else if path.is_file() {
        names.insert(name);
    } else {
        return Err(format!("missing input: {name}").into());
    }
    Ok(())
}

fn files(root: &Path, name: &str, revision: Option<&str>) -> Result<BTreeSet<String>> {
    let path = storage::relative(root, name)?;
    let mut names = BTreeSet::new();
    if let Some(rev) = revision {
        let raw = git(
            root,
            &["ls-tree", "-r", "--name-only", "-z", rev, "--", name],
        )?;
        for value in raw.split(|b| *b == 0).filter(|x| !x.is_empty()) {
            let value = String::from_utf8(value.to_vec())?;
            if !excluded(&value) {
                names.insert(value);
            }
        }
    } else {
        walk(root, &path, &mut names)?;
    }
    if names.is_empty() {
        return Err(format!("no local inputs in declared scope: {name}").into());
    }
    Ok(names)
}

fn effective(name: &str, env: &Map) -> Option<std::ffi::OsString> {
    env.get(name)
        .map(Into::into)
        .or_else(|| std::env::var_os(name))
}

fn executable(name: &str, env: &Map) -> Result<PathBuf> {
    if name.contains('/') || name.contains('\\') {
        return Err("tool must be a PATH executable name".into());
    }
    for dir in std::env::split_paths(&effective("PATH", env).ok_or("PATH unavailable")?) {
        let path = dir.join(name);
        if path.is_file() {
            return Ok(fs::canonicalize(path)?);
        }
    }
    Err(format!("tool unavailable locally: {name}").into())
}

fn tool(root: &Path, t: &Tool, env: &Map) -> Result<String> {
    let path = if let Some(version) = &t.toolchain {
        if !matches!(
            t.program.as_str(),
            "cargo" | "rustc" | "cargo-miri" | "miri" | "rustdoc"
        ) {
            return Err("unsupported rustup tool identity".into());
        }
        // `which` resolves an installed file only. Never install or invoke a
        // verifier to discover coverage during a scan.
        let out = Command::new("rustup")
            .args(["which", "--toolchain", version, &t.program])
            .envs(env)
            .env("RUSTUP_AUTO_INSTALL", "0")
            .current_dir(root)
            .output()?;
        if !out.status.success() {
            return Err(format!("local tool unavailable: {} +{version}", t.program).into());
        }
        PathBuf::from(String::from_utf8(out.stdout)?.trim())
    } else {
        executable(&t.program, env)?
    };
    Ok(hash(&fs::read(path)?))
}

pub fn environment(check: &Check) -> Map {
    let mut env = Map::new();
    for name in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTDOCFLAGS",
        "CARGO_BUILD_TARGET",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "MIRIFLAGS",
        "ASAN_OPTIONS",
        "LSAN_OPTIONS",
    ] {
        if let Ok(value) = std::env::var(name)
            && !value.is_empty()
        {
            env.insert(name.into(), value);
        }
    }
    env.extend(check.environment.clone());
    env
}

pub fn snapshot(
    root: &Path,
    registry: &Registry,
    check: &Check,
    revision: Option<&str>,
) -> Result<Snapshot> {
    let mut values = Map::new();
    let env = environment(check);
    values.insert(
        "execution semantics".into(),
        registry.execution_semantics.to_string(),
    );
    values.insert(
        "command / selected features / target / bounds".into(),
        serde_json::to_string(&check.command)?,
    );
    values.insert("working directory".into(), check.cwd.clone());
    values.insert("effective environment".into(), serde_json::to_string(&env)?);
    values.insert(
        "completion signals".into(),
        serde_json::to_string(&check.success)?,
    );
    values.insert(
        "execution limits".into(),
        format!("{}s / {} bytes", check.timeout_seconds, check.log_bytes),
    );
    // Never silently accept undeclared ambient Cargo configuration.
    if check.command.first().is_some_and(|v| v == "cargo") {
        let homes = effective("CARGO_HOME", &env)
            .map(PathBuf::from)
            .into_iter()
            .chain(effective("HOME", &env).map(|p| PathBuf::from(p).join(".cargo")));
        let dirs = root
            .join(&check.cwd)
            .ancestors()
            .map(|p| p.join(".cargo"))
            .collect::<Vec<_>>();
        for dir in dirs.into_iter().chain(homes) {
            let dir = root.join(&check.cwd).join(dir);
            for name in ["config", "config.toml"] {
                if dir.join(name).exists() {
                    return Err(format!(
                        "unresolved ambient Cargo configuration: {}",
                        dir.join(name).display()
                    )
                    .into());
                }
            }
        }
        for name in ["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"] {
            if let Some(wrapper) = env.get(name).filter(|v| !v.is_empty()) {
                let path = if wrapper.contains('/') || wrapper.contains('\\') {
                    root.join(&check.cwd).join(wrapper)
                } else {
                    executable(wrapper, &env)?
                };
                values.insert(format!("compiler wrapper {name}"), hash(&fs::read(path)?));
            }
        }
    }
    for id in &check.inputs {
        let group = registry.groups.get(id).ok_or("unknown input group")?;
        for name in &group.paths {
            for file in files(root, name, revision)? {
                values.insert(format!("{id}: {file}"), hash(&read(root, &file, revision)?));
            }
        }
        for (file, fields) in &group.toml {
            let doc: toml::Value =
                toml::from_str(std::str::from_utf8(&read(root, file, revision)?)?)?;
            for field in fields {
                let value = field.split('.').try_fold(&doc, |v, k| v.get(k));
                values.insert(
                    format!("{id}: {file} [{field}]"),
                    serde_json::to_string(&value)?,
                );
            }
        }
        for lock in &group.locks {
            let doc: toml::Value =
                toml::from_str(std::str::from_utf8(&read(root, &lock.path, revision)?)?)?;
            let rows = doc
                .get("package")
                .and_then(toml::Value::as_array)
                .ok_or("missing lock packages")?;
            for package in &lock.packages {
                let matches: Vec<_> = rows
                    .iter()
                    .filter(|r| r.get("name").and_then(toml::Value::as_str) == Some(package))
                    .collect();
                if matches.len() != 1 {
                    return Err(format!(
                        "unresolved lock identity: {package} (missing or ambiguous)"
                    )
                    .into());
                }
                let mut row = matches[0].clone();
                // Workspace release numbering is provenance, not implementation.
                if row.get("source").is_none() {
                    row.as_table_mut()
                        .ok_or("invalid lock row")?
                        .remove("version");
                }
                values.insert(
                    format!("{id}: {} package {package}", lock.path),
                    serde_json::to_string(&row)?,
                );
            }
        }
        for t in &group.tools {
            values.insert(
                format!(
                    "{id}: tool {} {}",
                    t.program,
                    t.toolchain.as_deref().unwrap_or("PATH")
                ),
                tool(root, t, &env)?,
            );
        }
    }
    let fingerprint = hash(&serde_json::to_vec(&values)?);
    Ok(Snapshot {
        fingerprint,
        inputs: values,
    })
}

pub fn source(root: &Path, check: &Check, current: &Snapshot) -> String {
    let Ok(head) = head(root) else {
        return "working tree (no Git HEAD)".into();
    };
    // The historical check definition is part of source provenance too. Do not
    // call a dirty command/configuration a clean HEAD execution.
    let historical = (|| -> Result<Snapshot> {
        let raw = git(root, &["show", &format!("{head}:verification/checks.toml")])?;
        let previous: Registry = toml::from_str(std::str::from_utf8(&raw)?)?;
        let prior = previous
            .checks
            .iter()
            .find(|c| c.key() == check.key())
            .ok_or("new check")?;
        snapshot(root, &previous, prior, Some(&head))
    })();
    match historical {
        Ok(old) if old == *current => head,
        _ => format!(
            "working tree based on {head}; scoped fingerprint {}",
            current.fingerprint
        ),
    }
}

pub fn registered_snapshot(root: &Path, key: &str) -> Result<Snapshot> {
    let current = crate::registry(root)?;
    let check = current
        .checks
        .iter()
        .find(|check| check.key() == key)
        .ok_or("selected check was removed from the registry")?;
    snapshot(root, &current, check, None)
}

pub fn difference(old: &Snapshot, new: &Snapshot) -> String {
    let keys: BTreeSet<_> = old.inputs.keys().chain(new.inputs.keys()).collect();
    let changes: Vec<_> = keys
        .into_iter()
        .filter(|k| old.inputs.get(*k) != new.inputs.get(*k))
        .take(3)
        .map(|k| {
            let verb = if !old.inputs.contains_key(k) {
                "added"
            } else if !new.inputs.contains_key(k) {
                "removed"
            } else {
                "changed"
            };
            format!("{k} {verb}")
        })
        .collect();
    format!("Outdated: {}", changes.join("; "))
}
