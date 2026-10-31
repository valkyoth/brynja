use crate::{Result, inputs, model::*, report, storage};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

pub fn successful(signal: &Success, output: &str) -> bool {
    if signal.contains.is_empty()
        || signal
            .contains
            .iter()
            .any(|s| s.is_empty() || !output.contains(s))
    {
        return false;
    }
    if let Some(minimum) = signal.minimum_tests {
        let mut passed = 0_u64;
        for line in output.lines() {
            if let Some(rest) = line.strip_prefix("test result: ok. ") {
                let parts: Vec<_> = rest.split(';').collect();
                if parts.len() < 3
                    || parts[1].trim() != "0 failed"
                    || parts[2].trim() != "0 ignored"
                {
                    return false;
                }
                let Some(value) = parts[0]
                    .strip_suffix(" passed")
                    .and_then(|v| v.parse::<u64>().ok())
                else {
                    return false;
                };
                let Some(sum) = passed.checked_add(value) else {
                    return false;
                };
                passed = sum;
            }
            if line.starts_with("test result: FAILED") {
                return false;
            }
        }
        if minimum == 0 || passed < minimum {
            return false;
        }
    }
    true
}

fn drain(reader: impl Read + Send + 'static, tx: mpsc::SyncSender<Vec<u8>>) {
    thread::spawn(move || {
        let mut reader = reader;
        let mut bytes = [0_u8; 4096];
        loop {
            match reader.read(&mut bytes) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(bytes[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

#[cfg(unix)]
fn terminate(child: &mut std::process::Child) {
    // The child has its own process group. Kill descendants as well; no
    // detached compiler/proof process should outlive a bounded task.
    let _ = Command::new("kill")
        .args(["-KILL", "--", &format!("-{}", child.id())])
        .status();
    let _ = child.kill();
    let _ = child.wait();
}

struct Process(std::process::Child);

impl std::ops::Deref for Process {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Process {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // An unexpected log/pipe/wait error must not leave a running compiler
        // behind when the attempt is recorded as failed.
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            terminate(&mut self.0);
        }
    }
}

#[cfg(not(unix))]
fn terminate(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

pub fn run(
    root: &Path,
    registry: &Registry,
    state: &mut State,
    check: &Check,
    interrupted: &Arc<AtomicBool>,
) -> Result<bool> {
    if !cfg!(unix) {
        return Err(
            "v1 execution supports Linux/macOS only; status/reporting remain available".into(),
        );
    }
    let before = inputs::snapshot(root, registry, check, None)?;
    if inputs::registered_snapshot(root, &check.key())? != before {
        return Err("selected check configuration changed; inspect and select again".into());
    }
    let started = storage::stamp();
    let id = format!(
        "{}-{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    let log_name = format!("verification/.runner/logs/{id}.log");
    let log_path = storage::relative(root, &log_name)?;
    std::fs::create_dir_all(log_path.parent().ok_or("log parent missing")?)?;
    let mut log = File::create(&log_path)?;
    let row = Attempt {
        id,
        source: inputs::source(root, check, &before),
        started,
        ended: None,
        outcome: "running".into(),
        explanation: "execution in progress".into(),
        command: check.command.clone(),
        cwd: check.cwd.clone(),
        environment: inputs::environment(check),
        before,
        after: None,
        log: log_name,
        log_sha256: None,
    };
    state.attempts.entry(check.key()).or_default().push(row);
    storage::save(root, state)?; // Durable before spawn.
    println!(
        "RUN {}: {:?}\nDo not edit this check's inputs while it runs.",
        check.key(),
        check.command
    );
    let attempt = state
        .attempts
        .get_mut(&check.key())
        .and_then(|rows| rows.last_mut())
        .ok_or("missing attempt")?;
    let mut command = Command::new(&check.command[0]);
    command
        .args(&check.command[1..])
        .current_dir(storage::relative(root, &check.cwd)?)
        .env_clear()
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    for name in [
        "PATH",
        "HOME",
        "TMPDIR",
        "TEMP",
        "SYSTEMROOT",
        "CARGO_HOME",
        "RUSTUP_HOME",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .env("RUSTUP_AUTO_INSTALL", "0")
        .env("CARGO_TERM_COLOR", "never")
        .env("LC_ALL", "C")
        .envs(&attempt.environment);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let outcome = (|| -> Result<(String, String)> {
        let mut child = Process(command.spawn()?);
        let (tx, rx) = mpsc::sync_channel(32);
        drain(
            child.stdout.take().ok_or("stdout pipe missing")?,
            tx.clone(),
        );
        drain(child.stderr.take().ok_or("stderr pipe missing")?, tx);
        let start = Instant::now();
        let mut output = Vec::new();
        let mut exit = None;
        loop {
            if interrupted.load(Ordering::SeqCst) {
                terminate(&mut child);
                return Ok((
                    "interrupted".into(),
                    "operator signal; child process group stopped".into(),
                ));
            }
            if start.elapsed().as_secs() >= check.timeout_seconds {
                terminate(&mut child);
                return Ok((
                    "timed_out".into(),
                    "configured execution limit reached".into(),
                ));
            }
            match rx.recv_timeout(Duration::from_millis(25)) {
                Ok(bytes) => {
                    if output.len() as u64 + bytes.len() as u64 > check.log_bytes {
                        terminate(&mut child);
                        return Ok(("log_limit".into(), "configured output limit reached".into()));
                    }
                    if let Err(error) = log.write_all(&bytes) {
                        terminate(&mut child);
                        return Err(error.into());
                    }
                    let _ = std::io::stdout().write_all(&bytes);
                    output.extend_from_slice(&bytes);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) if exit.is_some() => break,
                Err(_) => (),
            }
            if exit.is_none() {
                exit = child.try_wait()?;
            }
        }
        if exit.is_some_and(|s| s.success())
            && successful(&check.success, &String::from_utf8_lossy(&output))
        {
            Ok((
                "passed".into(),
                "completed with registered success signals".into(),
            ))
        } else {
            Ok((
                "failed".into(),
                format!("exit={exit:?}; required completion signals must all pass"),
            ))
        }
    })();
    let (mut outcome, mut explanation) =
        outcome.unwrap_or_else(|e| ("failed".into(), format!("execution unavailable: {e}")));
    // Re-read the selected definition as well as its files. Command, bounds,
    // completion criteria and input declarations may have changed while running.
    let after = inputs::registered_snapshot(root, &check.key());
    if outcome == "passed" && after.as_ref().ok() != Some(&attempt.before) {
        outcome = "input_changed".into();
        explanation = match &after {
            Ok(now) => inputs::difference(&attempt.before, now),
            Err(error) => format!("inputs became unresolved during execution: {error}"),
        };
    }
    attempt.ended = Some(storage::stamp());
    attempt.outcome = outcome;
    attempt.explanation = explanation;
    attempt.after = after.ok();
    log.sync_all()?;
    attempt.log_sha256 = Some(inputs::hash(&std::fs::read(log_path)?));
    let passed = attempt.outcome == "passed";
    storage::save(root, state)?; // Execution is recorded before rendering.
    report::refresh(root, registry, state, Some(&check.component));
    storage::save(root, state)?;
    report::write(root, registry, state)?;
    Ok(passed)
}
