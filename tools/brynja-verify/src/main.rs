#![forbid(unsafe_code)]

mod catalog;
mod inputs;
mod model;
mod patterns;
mod registrations;
mod report;
mod rotation;
mod runner;
mod snapshot_store;
mod storage;
mod store_limits;
mod summary;

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

const HELP: &str = "brynja-verify [--root PATH] COMPONENT [--category CATEGORY]
brynja-verify [--root PATH] run COMPONENT CHECK
brynja-verify [--root PATH] run COMPONENT --needed|--all [--category CATEGORY]
brynja-verify [--root PATH] full-check
brynja-verify [--root PATH] report
brynja-verify [--root PATH] migrate-results
brynja-verify [--root PATH] rotate-results
brynja-verify [--root PATH] list-archives
brynja-verify [--root PATH] show-archive SHA256
brynja-verify [--root PATH] list COMPONENT [CATEGORY]
brynja-verify [--root PATH] show COMPONENT CHECK

COMPONENT refreshes ONLY that component's status; no tests run.
Status output groups configurations by command and category/profile. Group dates
are latest member activity, not a new execution of the whole group.
Use list COMPONENT [CATEGORY] and show COMPONENT CHECK for individual details.
full-check is a LOCAL STATUS SCAN, NOT a verification campaign. It executes no
tests/proofs, compiles nothing, installs no tools and contacts no remote services.
report regenerates the report from saved state without scanning inputs.
migrate-results losslessly upgrades saved storage; no scan, recovery or execution.
rotate-results checkpoints all history, retains only the latest attempt per check,
and clears cached views. Older scopes may need reruns; no archive is a live pass.
list-archives lists checkpoint IDs; show-archive validates and prints one index.
run executes sequentially and stops on failure, retaining completed results.
--needed excludes current successful results; --all explicitly reruns them.
--category restricts execution, for example run md5 --needed --category asan.
Miri batches require miri-routine, miri-extended or miri-existing-full; profiles
overlap. Selecting a task ID runs only that task. No automatic Miri campaign.
Supporting entry points and retired history are references, not unfinished work.
Unavailable inputs/tools are explained, never passed or broadened to other work.
No command stages, commits, tags, pushes or publishes anything.
Registry commands are trusted local code; never put secrets in argv/environment.
Catalog-only assessments are visible but unresolved, not current passes. Use
show for their exact command, prerequisites and historical observations.
";

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

fn registry(root: &Path) -> Result<Registry> {
    let registry = registrations::load(root, None)?;
    if registry.schema != 1 || registry.execution_semantics == 0 {
        return Err("unsupported registry/semantics version".into());
    }
    let mut seen = BTreeSet::new();
    for check in &registry.checks {
        if !identifier(&check.component)
            || !identifier(&check.id)
            || !identifier(&check.category)
            || !seen.insert(check.key())
        {
            return Err("invalid or duplicate component/check identifier".into());
        }
        if check.command.is_empty()
            || check.command[0].is_empty()
            || check.inputs.is_empty()
            || check.success.contains.is_empty()
            || check.success.contains.iter().any(String::is_empty)
            || check.success.minimum_tests == Some(0)
            || check.success.exact_tests == Some(0)
            || check.success.unique_lines.iter().any(String::is_empty)
            || check.success.unique_prefixes.iter().any(String::is_empty)
            || (check.success.exact_tests.is_some() && check.success.minimum_tests.is_none())
            || check.timeout_seconds == 0
            || check.log_bytes == 0
        {
            return Err(format!("incomplete check registration: {}", check.key()).into());
        }
        storage::relative(root, &check.cwd)?;
        if let Some(path) = &check.stdin {
            storage::relative(root, path)?;
        }
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
        for path in group.paths.iter().chain(&group.optional_paths) {
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
        for pattern in &group.patterns {
            patterns::validate(root, pattern)?;
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
    if args == ["rotate-results"]
        || args == ["list-archives"]
        || (args.len() == 2 && args[0] == "show-archive")
    {
        let _lock = storage::lock(&root)?;
        if args[0] == "rotate-results" {
            match rotation::rotate(&root)? {
                Some(id) => println!(
                    "Results checkpoint: {id}. Latest attempts retained; cached views cleared. Run a status scan; no verification executed. Commit the index, archive and snapshots together."
                ),
                None => println!("No older attempts to rotate; no changes."),
            }
        } else if args[0] == "show-archive" {
            let bytes = rotation::read(&root, &args[1])?;
            std::io::Write::write_all(&mut std::io::stdout().lock(), &bytes)?;
        } else {
            for id in storage::load(&root)?.archives {
                println!("{id}");
            }
        }
        return Ok(true);
    }
    if args == ["migrate-results"] {
        let _lock = storage::lock(&root)?;
        if !storage::relative(&root, storage::STATE)?.is_file() {
            return Err("no results file to migrate".into());
        }
        let state = storage::load(&root)?;
        storage::save(&root, &state)?;
        println!(
            "Results stored with content-addressed snapshots (schema 2, or 3 with archives). No attempts or views changed; no verification executed."
        );
        return Ok(true);
    }
    let registry = registry(&root)?;
    let catalog = catalog::load(&root, &registry)?;
    if args.first().is_some_and(|a| a == "list" || a == "show") {
        catalog.inspect(&root, &registry, &args)?;
        return Ok(true);
    }
    let full = args == ["full-check"];
    let render_only = args == ["report"];
    let running = args.first().is_some_and(|a| a == "run");
    let category = if (running
        && args.len() == 5
        && args[3] == "--category"
        && matches!(args[2].as_str(), "--needed" | "--all"))
        || (!running && args.len() == 3 && args[1] == "--category")
    {
        let value = args.pop().unwrap();
        args.pop();
        Some(value)
    } else {
        None
    };
    let component = if full || render_only {
        None
    } else {
        let index = usize::from(running);
        let component = args.get(index).ok_or("missing component")?;
        if !registry.checks.iter().any(|c| c.component == *component)
            && !catalog.component(component)
        {
            return Err(
                format!("unknown component {component:?}; no broader scope selected").into(),
            );
        }
        Some(component.as_str())
    };
    if (!full && !render_only && !running && args.len() != 1) || running && args.len() != 3 {
        return Err(format!("invalid arguments\n{HELP}").into());
    }
    if let Some(category) = &category
        && !registry
            .checks
            .iter()
            .any(|c| Some(c.component.as_str()) == component && c.category == *category)
        && !catalog.entries.iter().any(|c| {
            c.families.iter().any(|f| Some(f.as_str()) == component) && c.matches_category(category)
        })
    {
        return Err("unknown category; no broader scope selected".into());
    }
    if running
        && matches!(args[2].as_str(), "--needed" | "--all")
        && (category.is_none() || category.as_deref() == Some("miri"))
        && registry
            .checks
            .iter()
            .any(|c| Some(c.component.as_str()) == component && c.category.starts_with("miri-"))
    {
        return Err("Miri profiles overlap. Select one check ID or --category miri-routine, miri-extended, or miri-existing-full. No checks started; use --category portable/asan for those checks.".into());
    }
    if running
        && !matches!(args[2].as_str(), "--needed" | "--all")
        && !registry
            .checks
            .iter()
            .any(|c| Some(c.component.as_str()) == component && c.id == args[2])
    {
        if let Some(row) = catalog.entry(component.unwrap_or_default(), &args[2]) {
            return Err(format!(
                "UNAVAILABLE {}: {} Use show COMPONENT ID; no test started.",
                row.id, row.reason
            )
            .into());
        }
        return Err(format!("unknown check {:?}; no broader scope selected", args[2]).into());
    }
    let _lock = storage::lock(&root)?;
    let mut state = storage::load(&root)?;
    if render_only {
        report::write(&root, &registry, &state)?;
        return Ok(true);
    }
    storage::recover(&mut state, component);
    let selected_id = if running && !matches!(args[2].as_str(), "--needed" | "--all") {
        Some(args[2].as_str())
    } else {
        None
    };
    report::refresh(
        &root,
        &registry,
        &mut state,
        component,
        category.as_deref(),
        selected_id,
    );
    storage::save(&root, &state)?;
    report::write(&root, &registry, &state)?;
    if full {
        for warning in rotation::warnings(&root)? {
            eprintln!("{warning}");
        }
    }
    if !running {
        println!(
            "Status scan only; no verification executed. {}",
            if full {
                "All runnable registrations refreshed; catalog-only input applicability remains unresolved."
            } else {
                "Other components retain their previous scan."
            }
        );
        report::terminal(
            &registry,
            &state,
            component,
            &catalog,
            category.as_deref(),
            selected_id,
        );
        catalog.terminal(component, &registry);
        return Ok(true);
    }
    let interrupted = Arc::new(AtomicBool::new(false));
    let flag = interrupted.clone();
    ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst))?;
    let checks: Vec<_> = registry
        .checks
        .iter()
        .filter(|c| Some(c.component.as_str()) == component)
        .filter(|c| category.as_ref().is_none_or(|p| c.category == *p))
        .filter(|c| {
            args[2] == "--all"
                || args[2] == c.id
                || args[2] == "--needed"
                    && !state.views.get(&c.key()).is_some_and(report::current_pass)
        })
        .collect();
    let catalog_count = if matches!(args[2].as_str(), "--all" | "--needed") {
        catalog.count(
            component.unwrap_or_default(),
            category.as_deref(),
            &registry,
        )
    } else {
        0
    };
    let mut unavailable = catalog_count != 0;
    if unavailable {
        eprintln!(
            "UNAVAILABLE: {catalog_count} catalog-only assessments lack scoped runnable bindings. They will not execute or be counted as passed. Use list/show to inspect; no broad campaign selected."
        );
    }
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
            report::terminal(
                &registry,
                &state,
                component,
                &catalog,
                category.as_deref(),
                selected_id,
            );
            return Ok(false);
        }
    }
    report::terminal(
        &registry,
        &state,
        component,
        &catalog,
        category.as_deref(),
        selected_id,
    );
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
