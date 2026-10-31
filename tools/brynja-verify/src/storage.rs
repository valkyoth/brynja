use crate::{Result, model::*};
use fs2::FileExt;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Component, Path, PathBuf},
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const STATE: &str = "verification/results.json";
pub const REPORT: &str = "docs/VERIFICATION_RESULTS.md";

pub fn stamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("UTC timestamp formatting")
}

pub fn relative(root: &Path, name: &str) -> Result<PathBuf> {
    let p = Path::new(name);
    if name.is_empty()
        || p.is_absolute()
        || p.components()
            .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err(format!("not a relative repository path: {name}").into());
    }
    let mut current = root.to_path_buf();
    for part in p.components() {
        current.push(part);
        if current.is_symlink() {
            return Err(format!("symlinked repository path: {name}").into());
        }
    }
    Ok(current)
}

pub fn lock(root: &Path) -> Result<File> {
    let path = relative(root, "verification/.runner/lock")?;
    fs::create_dir_all(path.parent().ok_or("lock parent missing")?)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)?;
    file.try_lock_exclusive()
        .map_err(|_| "another brynja-verify command owns the state lock")?;
    Ok(file)
}

pub fn atomic(root: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let path = relative(root, name)?;
    if fs::read(&path).ok().as_deref() == Some(bytes) {
        return Ok(());
    }
    let parent = path.parent().ok_or("output parent missing")?;
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(".verify-{}.tmp", std::process::id()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, &path)?;
        Ok(())
    })();
    // Never remove somebody else's temporary file on create_new failure.
    if result.is_err() && temp.exists() {
        // Retain a failed write for diagnosis; PID-specific name won't be
        // silently overwritten by a subsequent attempt.
        eprintln!(
            "Output write failed; temporary file may remain: {}",
            temp.display()
        );
    }
    result
}

pub fn load(root: &Path) -> Result<State> {
    let path = relative(root, STATE)?;
    if !path.exists() {
        return Ok(State {
            schema: 1,
            ..State::default()
        });
    }
    let state: State = serde_json::from_slice(&fs::read(path)?)?;
    if state.schema != 1 {
        return Err("unsupported results schema".into());
    }
    Ok(state)
}

pub fn save(root: &Path, state: &State) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(state)?;
    bytes.push(b'\n');
    atomic(root, STATE, &bytes)
}

pub fn recover(state: &mut State, component: Option<&str>) {
    // Obtaining the OS lock proves no other cooperating runner owns state.
    // Never invent an end time or a failed/successful execution on recovery.
    for (key, rows) in &mut state.attempts {
        if component.is_some_and(|c| !key.starts_with(&format!("{c}/"))) {
            continue;
        }
        for row in rows.iter_mut().filter(|r| r.outcome == "running") {
            row.outcome = "interrupted".into();
            row.explanation =
                "runner ended without a completion record; inspect the original log".into();
        }
    }
}
