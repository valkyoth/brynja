#![forbid(unsafe_code)]

mod inputs;
mod model;
mod report;
mod runner;
mod storage;

use model::*;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const HELP: &str = "brynja-verify [--root PATH] COMPONENT
brynja-verify [--root PATH] run COMPONENT CHECK
brynja-verify [--root PATH] run COMPONENT --needed|--all
brynja-verify [--root PATH] full-check
brynja-verify [--root PATH] report

COMPONENT refreshes ONLY that component's status; no tests run.
full-check is a LOCAL STATUS SCAN, NOT a verification campaign. It executes no
tests/proofs, compiles nothing, installs no tools and contacts no remote services.
report regenerates the report from saved state without scanning inputs.
run executes sequentially and stops on failure, retaining completed results.
--needed excludes current successful results; --all explicitly reruns them.
Unavailable inputs/tools are explained, never passed or broadened to other work.
No command stages, commits, tags, pushes or publishes anything.
Registry commands are trusted local code; never put secrets in argv/environment.
";

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn registry(root: &Path) -> Result<Registry> {
    let path = storage::relative(root, "verification/checks.toml")?;
    let registry: Registry = toml::from_str(&std::fs::read_to_string(path)?)?;
    if registry.schema != 1 || registry.execution_semantics == 0 {
        return Err("unsupported registry/semantics version".into());
    }
    let mut seen = BTreeSet::new();
    for check in &registry.checks {
        if !identifier(&check.component) || !identifier(&check.id) || !seen.insert(check.key()) {
            return Err("invalid or duplicate component/check identifier".into());
        }
        if check.command.is_empty()
            || check.command[0].is_empty()
            || check.inputs.is_empty()
            || check.success.contains.is_empty()
            || check.success.contains.iter().any(String::is_empty)
            || check.success.minimum_tests == Some(0)
            || check.timeout_seconds == 0
            || check.log_bytes == 0
        {
            return Err(format!("incomplete check registration: {}", check.key()).into());
        }
        storage::relative(root, &check.cwd)?;
        for id in &check.inputs {
            if !registry.groups.contains_key(id) {
                return Err(format!("unknown input group: {id}").into());
            }
        }
        for key in check.environment.keys() {
            let upper = key.to_ascii_uppercase();
            if ["PASSWORD", "TOKEN", "SECRET", "CREDENTIAL", "PRIVATE_KEY"]
                .iter()
                .any(|s| upper.contains(s))
            {
                return Err("secret-like environment fields cannot be recorded".into());
            }
        }
    }
    for (name, group) in &registry.groups {
        if !identifier(name) {
            return Err("invalid input group identifier".into());
        }
        for path in &group.paths {
            if path == "." || inputs::excluded(path) {
                return Err(format!("output or repository-wide input rejected: {path}").into());
            }
            storage::relative(root, path)?;
        }
        for path in group.toml.keys() {
            if inputs::excluded(path) {
                return Err("generated files cannot be TOML inputs".into());
            }
            storage::relative(root, path)?;
        }
    }
    Ok(registry)
}

fn main_result() -> Result<bool> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args == ["--help"] || args == ["-h"] {
        println!("{HELP}");
        return Ok(true);
    }
    let root = if args.first().is_some_and(|a| a == "--root") {
        if args.len() < 3 {
            return Err("--root requires a path and command".into());
        }
        let root = PathBuf::from(args.remove(1));
        args.remove(0);
        root
    } else {
        std::env::current_dir()?
    };
    let root = std::fs::canonicalize(root)?;
    let registry = registry(&root)?;
    let full = args == ["full-check"];
    let render_only = args == ["report"];
    let running = args.first().is_some_and(|a| a == "run");
    let component = if full || render_only {
        None
    } else {
        let index = usize::from(running);
        let component = args.get(index).ok_or("missing component")?;
        if !registry.checks.iter().any(|c| c.component == *component) {
            return Err(
                format!("unknown component {component:?}; no broader scope selected").into(),
            );
        }
        Some(component.as_str())
    };
    if (!full && !render_only && !running && args.len() != 1) || running && args.len() != 3 {
        return Err(format!("invalid arguments\n{HELP}").into());
    }
    if running
        && !matches!(args[2].as_str(), "--needed" | "--all")
        && !registry
            .checks
            .iter()
            .any(|c| Some(c.component.as_str()) == component && c.id == args[2])
    {
        return Err(format!("unknown check {:?}; no broader scope selected", args[2]).into());
    }
    let _lock = storage::lock(&root)?;
    let mut state = storage::load(&root)?;
    if render_only {
        report::write(&root, &registry, &state)?;
        return Ok(true);
    }
    storage::recover(&mut state, component);
    report::refresh(&root, &registry, &mut state, component);
    storage::save(&root, &state)?;
    report::write(&root, &registry, &state)?;
    if !running {
        println!(
            "Status scan only; no verification executed. Other components retain their previous scan."
        );
        report::terminal(&registry, &state, component);
        return Ok(true);
    }
    let interrupted = Arc::new(AtomicBool::new(false));
    let flag = interrupted.clone();
    ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))?;
    let checks: Vec<_> = registry
        .checks
        .iter()
        .filter(|c| Some(c.component.as_str()) == component)
        .filter(|c| {
            args[2] == "--all"
                || args[2] == c.id
                || args[2] == "--needed"
                    && !state.views.get(&c.key()).is_some_and(report::current_pass)
        })
        .collect();
    let mut unavailable = false;
    for (index, check) in checks.iter().enumerate() {
        if let Err(error) = inputs::snapshot(&root, &registry, check, None) {
            eprintln!("UNAVAILABLE {}: {error}; not passed", check.key());
            unavailable = true;
            continue;
        }
        if !runner::run(&root, &registry, &mut state, check, &interrupted)? {
            eprintln!("Stopped after {}. Remaining selected work:", check.key());
            for next in &checks[index + 1..] {
                eprintln!("  {} (not executed)", next.key());
            }
            report::terminal(&registry, &state, component);
            return Ok(false);
        }
    }
    report::terminal(&registry, &state, component);
    Ok(!unavailable)
}

fn main() {
    match main_result() {
        Ok(true) => (),
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("brynja-verify: {error}");
            std::process::exit(2);
        }
    }
}
