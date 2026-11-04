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
    let normalized = name
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect::<Vec<_>>()
        .join("/");
    let name = normalized.as_str();
    name == storage::STATE
        || name == storage::REPORT
        || name == storage::SNAPSHOTS
        || name.starts_with(&format!("{}/", storage::SNAPSHOTS))
        || name == storage::ARCHIVES
        || name.starts_with(&format!("{}/", storage::ARCHIVES))
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
    optional_executable(name, env)?
        .ok_or_else(|| format!("tool unavailable locally: {name}").into())
}

fn optional_executable(name: &str, env: &Map) -> Result<Option<PathBuf>> {
    if name.contains('/') || name.contains('\\') {
        return Err("tool must be a PATH executable name".into());
    }
    for dir in std::env::split_paths(&effective("PATH", env).ok_or("PATH unavailable")?) {
        let path = dir.join(name);
        if path.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if path.metadata()?.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }
            return Ok(Some(fs::canonicalize(path)?));
        }
    }
    Ok(None)
}

fn kani_bundle(bundle: &Path) -> Result<String> {
    let mut names = BTreeSet::new();
    for part in [
        "bin",
        "lib",
        "library",
        "rustc-version",
        "rust-toolchain-version",
    ] {
        walk(bundle, &bundle.join(part), &mut names)?;
    }
    for required in ["bin/cbmc", "bin/kani-driver", "bin/kani-compiler"] {
        if !names.contains(required) {
            return Err(format!("incomplete local Kani installation: {required}").into());
        }
    }
    let mut identity = Map::new();
    for name in names {
        identity.insert(name.clone(), hash(&fs::read(bundle.join(name))?));
    }
    // Kani's installed toolchain link is intentional; resolve its compiler
    // without invoking setup, rustup installation or the verifier itself.
    identity.insert(
        "toolchain/bin/rustc".into(),
        hash(&fs::read(bundle.join("toolchain/bin/rustc"))?),
    );
    // rustc is a small executable backed by the toolchain's driver libraries.
    // Record those files too, not merely the launcher/version text.
    for entry in fs::read_dir(bundle.join("toolchain/lib"))? {
        let path = entry?.path();
        if path.is_file() {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or("non-UTF8 tool library")?;
            identity.insert(format!("toolchain/lib/{name}"), hash(&fs::read(&path)?));
        }
    }
    Ok(hash(&serde_json::to_vec(&identity)?))
}

fn tool(root: &Path, t: &Tool, env: &Map) -> Result<String> {
    if t.optional {
        if t.toolchain.is_some() || matches!(t.program.as_str(), "kani-bundle" | "cargo-kani") {
            return Err("optional tools must be ordinary PATH executables".into());
        }
        return match optional_executable(&t.program, env)? {
            Some(path) => Ok(hash(&fs::read(path)?)),
            None => Ok("absent optional PATH tool".into()),
        };
    }
    if t.program == "kani-bundle" {
        let version = t
            .toolchain
            .as_deref()
            .ok_or("missing Kani bundle version")?;
        if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            return Err("invalid Kani bundle version".into());
        }
        let bundle = PathBuf::from(effective("HOME", env).ok_or("HOME unavailable")?)
            .join(".kani")
            .join(format!("kani-{version}"));
        return kani_bundle(&bundle);
    }
    let path = if t.program == "cargo-kani" && t.toolchain.is_none() {
        match executable(&t.program, env) {
            Ok(path) => path,
            Err(_) => {
                let home = effective("CARGO_HOME", env)
                    .map(PathBuf::from)
                    .or_else(|| effective("HOME", env).map(|p| PathBuf::from(p).join(".cargo")))
                    .ok_or("Cargo home unavailable")?;
                fs::canonicalize(home.join("bin/cargo-kani"))?
            }
        }
    } else if let Some(version) = &t.toolchain {
        if !matches!(
            t.program.as_str(),
            "cargo" | "rustc" | "cargo-miri" | "miri" | "rustdoc" | "clippy-driver" | "rustfmt"
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

fn snapshot_inner(
    root: &Path,
    registry: &Registry,
    check: &Check,
    revision: Option<&str>,
    mut cache: Option<&mut ScanCache>,
) -> Result<Snapshot> {
    let mut values = Map::new();
    let env = environment(check);
    if !check.reject_environment.is_empty() {
        for name in &check.reject_environment {
            if std::env::var_os(name).is_some_and(|v| !v.is_empty()) {
                return Err(format!("clear inherited override before this check: {name}").into());
            }
        }
        values.insert(
            "rejected ambient overrides".into(),
            serde_json::to_string(&check.reject_environment)?,
        );
    }
    if let Some(platform) = &check.platform {
        let host = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
        if *platform != host {
            return Err(format!("requires {platform}; this host is {host}").into());
        }
        values.insert("required execution platform".into(), platform.clone());
    }
    values.insert(
        "execution semantics".into(),
        registry.execution_semantics.to_string(),
    );
    values.insert(
        "command / selected features / target / bounds".into(),
        serde_json::to_string(&check.command)?,
    );
    values.insert("working directory".into(), check.cwd.clone());
    if let Some(path) = &check.stdin {
        if excluded(path) {
            return Err("generated output cannot be verification stdin".into());
        }
        values.insert(format!("stdin: {path}"), hash(&read(root, path, revision)?));
    }
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
    if check.command.first().is_some_and(|v| v == "cargo")
        || check.inputs.iter().any(|id| {
            registry
                .groups
                .get(id)
                .is_some_and(|g| g.tools.iter().any(|t| t.program == "cargo"))
        })
    {
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
        // Only tool selection can make a group's bytes depend on environment.
        // Miri runtime case selectors do not affect rustup's local tool lookup.
        let mut tool_env = env.clone();
        tool_env.remove("MIRIFLAGS");
        let key = (id.clone(), serde_json::to_string(&tool_env)?);
        if let Some(saved) = cache.as_deref_mut().and_then(|c| c.get(&key)) {
            values.extend(
                saved
                    .clone()
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?,
            );
            continue;
        }
        let group_values =
            group_snapshot(root, group, id, &env, revision).map_err(|e| e.to_string());
        if let Some(cache) = cache.as_deref_mut() {
            cache.insert(key, group_values.clone());
        }
        values.extend(
            group_values.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?,
        );
    }
    let fingerprint = hash(&serde_json::to_vec(&values)?);
    Ok(Snapshot {
        fingerprint,
        inputs: values,
    })
}

// A cache is scoped to one status scan of one immutable registry instance.
// Execution before/after snapshots NEVER use it; no cache is persisted.
pub type ScanCache = std::collections::BTreeMap<(String, String), std::result::Result<Map, String>>;

pub fn snapshot(
    root: &Path,
    registry: &Registry,
    check: &Check,
    revision: Option<&str>,
) -> Result<Snapshot> {
    snapshot_inner(root, registry, check, revision, None)
}

pub fn scan(
    root: &Path,
    registry: &Registry,
    check: &Check,
    cache: &mut ScanCache,
) -> Result<Snapshot> {
    snapshot_inner(root, registry, check, None, Some(cache))
}

fn group_snapshot(
    root: &Path,
    group: &Group,
    id: &str,
    env: &Map,
    revision: Option<&str>,
) -> Result<Map> {
    let mut values = Map::new();
    for name in &group.paths {
        for file in files(root, name, revision)? {
            values.insert(format!("{id}: {file}"), hash(&read(root, &file, revision)?));
        }
    }
    for pattern in &group.patterns {
        let names = crate::patterns::files(root, pattern, revision)?;
        // Empty matches and the selected names are inputs too. No execution
        // is implied; additions/deletions/renames change this selection.
        values.insert(
            format!("{id}: pattern {pattern}"),
            serde_json::to_string(&names)?,
        );
        for name in names {
            values.insert(format!("{id}: {name}"), hash(&read(root, &name, revision)?));
        }
    }
    for name in &group.optional_paths {
        let path = storage::relative(root, name)?;
        let present = if let Some(rev) = revision {
            !git(root, &["ls-tree", "--name-only", rev, "--", name])?.is_empty()
        } else {
            path.try_exists()?
        };
        values.insert(format!("{id}: optional path {name}"), present.to_string());
        if present {
            for file in files(root, name, revision)? {
                values.insert(format!("{id}: {file}"), hash(&read(root, &file, revision)?));
            }
        }
    }
    for (file, fields) in &group.toml {
        let doc: toml::Value = toml::from_str(std::str::from_utf8(&read(root, file, revision)?)?)?;
        for field in fields {
            let mut value = field.split('.').try_fold(&doc, |v, k| v.get(k)).cloned();
            if group.normalize_local_versions
                && let Some(value) = &mut value
            {
                normalize_local_versions(value);
            }
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
                return Err(
                    format!("unresolved lock identity: {package} (missing or ambiguous)").into(),
                );
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
            tool(root, t, env)?,
        );
    }
    Ok(values)
}

fn normalize_local_versions(value: &mut toml::Value) {
    match value {
        toml::Value::Table(table) => {
            if table.get("path").is_some_and(toml::Value::is_str)
                || table.get("workspace").and_then(toml::Value::as_bool) == Some(true)
            {
                table.remove("version");
            }
            for (_, value) in table.iter_mut() {
                normalize_local_versions(value);
            }
        }
        toml::Value::Array(values) => {
            for value in values {
                normalize_local_versions(value);
            }
        }
        _ => (),
    }
}

pub fn source(root: &Path, check: &Check, current: &Snapshot) -> String {
    let Ok(head) = head(root) else {
        return "working tree (no Git HEAD)".into();
    };
    // The historical check definition is part of source provenance too. Do not
    // call a dirty command/configuration a clean HEAD execution.
    let historical = (|| -> Result<Snapshot> {
        let previous = crate::registrations::load(root, Some(&head))?;
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

#[cfg(test)]
mod kani_tests {
    use super::*;

    #[test]
    fn installed_bundle_identity_is_content_scoped_without_execution() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        assert!(kani_bundle(root).is_err());
        for name in [
            "bin/cbmc",
            "bin/kani-driver",
            "bin/kani-compiler",
            "lib/model",
            "library/model.rs",
            "rustc-version",
            "rust-toolchain-version",
            "toolchain/bin/rustc",
            "toolchain/lib/librustc_driver.so",
        ] {
            let path = root.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, "fake tool, not executable").unwrap();
        }
        let original = kani_bundle(root).unwrap();
        fs::write(root.join("notes.md"), "irrelevant installation note").unwrap();
        assert_eq!(kani_bundle(root).unwrap(), original);
        for name in [
            "bin/cbmc",
            "lib/model",
            "library/model.rs",
            "toolchain/bin/rustc",
            "toolchain/lib/librustc_driver.so",
        ] {
            fs::write(root.join(name), "changed").unwrap();
            assert_ne!(kani_bundle(root).unwrap(), original);
            fs::write(root.join(name), "fake tool, not executable").unwrap();
        }
        fs::write(root.join("library/new.rs"), "new model").unwrap();
        assert_ne!(kani_bundle(root).unwrap(), original);
        fs::remove_file(root.join("bin/cbmc")).unwrap();
        assert!(kani_bundle(root).is_err());
    }
}
