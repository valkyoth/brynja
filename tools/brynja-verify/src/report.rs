use crate::{Result, inputs, model::*, storage};
use std::path::Path;

pub fn view(rows: &[Attempt], current: &Result<Snapshot>) -> View {
    let mut view = View {
        result: "Not run".into(),
        freshness: "No recorded result".into(),
        source: "—".into(),
        performed_at: "—".into(),
        ..View::default()
    };
    view.last_success = rows
        .iter()
        .rev()
        .find(|r| r.outcome == "passed")
        .and_then(|r| r.ended.clone());
    if let Ok(now) = current {
        view.fingerprint = Some(now.fingerprint.clone());
    }
    if let Some(latest) = rows.last() {
        // A later unsuccessful/incomplete attempt is never hidden by history.
        let selected = if latest.outcome == "passed" {
            current
                .as_ref()
                .ok()
                .and_then(|now| rows.iter().rev().find(|r| r.before.as_ref() == now))
                .unwrap_or(latest)
        } else {
            latest
        };
        view.source = selected.source.clone();
        view.performed_at = selected
            .ended
            .clone()
            .unwrap_or_else(|| format!("started {}; incomplete", selected.started));
        view.result = selected.outcome.clone();
        if selected.id != latest.id {
            view.result.push_str(&format!(
                " (matching-input history; latest overall attempt {} at {})",
                latest.outcome, latest.started
            ));
        }
        view.freshness = match current {
            Ok(now) if selected.before.as_ref() == now => {
                if selected.outcome == "passed" && selected.after.as_deref() == Some(now) {
                    "Up to date".into()
                } else {
                    format!(
                        "Current starting inputs; needs attention: {}",
                        selected.explanation
                    )
                }
            }
            Ok(now) => inputs::difference(&selected.before, now),
            Err(error) => format!("Unresolved: {error}"),
        };
    } else if let Err(error) = current {
        view.freshness = format!("Unresolved: {error}");
    }
    view
}

pub fn current_pass(view: &View) -> bool {
    view.result.starts_with("passed") && view.freshness == "Up to date"
}

pub fn refresh(
    root: &Path,
    registry: &Registry,
    state: &mut State,
    component: Option<&str>,
    category: Option<&str>,
    id: Option<&str>,
) {
    let mut cache = inputs::ScanCache::new();
    for check in &registry.checks {
        if component.is_some_and(|c| c != check.component)
            || category.is_some_and(|c| c != check.category)
            || id.is_some_and(|i| i != check.id)
        {
            continue;
        }
        let current = inputs::scan(root, registry, check, &mut cache);
        let mut next = view(
            state
                .attempts
                .get(&check.key())
                .map(Vec::as_slice)
                .unwrap_or(&[]),
            &current,
        );
        if let Some(old) = state.views.get(&check.key()) {
            next.checked_at = old.checked_at.clone();
            if old == &next {
                continue;
            } // No timestamp-only churn.
        }
        next.checked_at = storage::stamp();
        state.views.insert(check.key(), next);
    }
}

fn text(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .replace('|', "\\|")
}

pub fn display_view(check: &Check, state: &State, catalog: &crate::catalog::Catalog) -> View {
    let mut view = state
        .views
        .get(&check.key())
        .cloned()
        .unwrap_or_else(|| View {
            result: "Not run".into(),
            freshness: "Not scanned".into(),
            ..View::default()
        });
    // Presentation only. Never manufacture an Attempt, compatible fingerprint,
    // or new timestamp from a catalog observation. A new attempt always wins.
    if state.attempts.get(&check.key()).is_none_or(Vec::is_empty)
        && let Some(record) = catalog
            .entry(&check.component, &check.id)
            .and_then(|e| e.history.last())
    {
        view.result = format!("Historical {}", record.result);
        view.source = record.source.clone();
        view.performed_at = record.ended.clone();
        let detail = match view.freshness.as_str() {
            "No recorded result" => "No execution recorded by this runner.",
            other => other,
        };
        view.freshness = format!("Historical inputs unmapped; not a current pass. {detail}");
    }
    view
}

pub fn render(registry: &Registry, state: &State, catalog: &crate::catalog::Catalog) -> String {
    let mut out = String::from(
        "# Verification results\n\nLocal developer observations, not certification or a release gate. No unrun or outdated assessment automatically blocks release. Execution timestamps are original UTC times. Freshness is the last meaningful component scan; unchanged scans do not rewrite timestamps.\n",
    );
    let mut checks: Vec<_> = registry.checks.iter().collect();
    checks.sort_by_key(|c| (&c.component, &c.id));
    let mut component = "";
    for check in checks {
        if component != check.component {
            component = &check.component;
            out.push_str(&format!("\n## {}\n\n| Check | Source tested | Performed at | Result | Freshness | Status last changed (UTC) |\n| --- | --- | --- | --- | --- | --- |\n", text(component)));
        }
        let v = display_view(check, state, catalog);
        out.push_str(&format!(
            "| {} — {} | {} | {} | {} | {} | {} |\n",
            text(&check.id),
            text(&check.name),
            text(&v.source),
            text(&v.performed_at),
            text(&v.result),
            text(&v.freshness),
            text(&v.checked_at)
        ));
    }
    if !state.historical.is_empty() {
        out.push_str("\n## Historical / unmapped evidence\n\nThese records are retained without assigning a new execution time or a current input fingerprint.\n\n");
        for item in &state.historical {
            out.push_str(&format!(
                "- {}: {}\n",
                text(&item.reference),
                text(&item.explanation)
            ));
        }
    }
    out
}

pub fn write(root: &Path, registry: &Registry, state: &State) -> Result<()> {
    let catalog = crate::catalog::load(root, registry)?;
    let mut output = render(registry, state, &catalog);
    output.push_str(&catalog.markdown(registry));
    storage::atomic(root, storage::REPORT, output.as_bytes())
}

pub fn terminal(
    registry: &Registry,
    state: &State,
    component: Option<&str>,
    catalog: &crate::catalog::Catalog,
    category: Option<&str>,
    id: Option<&str>,
) {
    if id.is_none() {
        print!(
            "{}",
            crate::summary::render(registry, state, catalog, component, category)
        );
        return;
    }
    println!(
        "{:<14} {:<22} {:<14} FRESHNESS",
        "COMPONENT", "CHECK", "RESULT"
    );
    let mut checks: Vec<_> = registry.checks.iter().collect();
    checks.sort_by_key(|c| (&c.component, &c.id));
    for check in checks {
        if component.is_some_and(|c| c != check.component)
            || category.is_some_and(|c| c != check.category)
            || id.is_some_and(|i| i != check.id)
        {
            continue;
        }
        let v = display_view(check, state, catalog);
        println!(
            "{:<14} {:<22} {:<14} {}",
            text(&check.component),
            text(&check.id),
            text(&v.result),
            text(&v.freshness)
        );
        println!(
            "  {} | {} | {}",
            text(&check.name),
            text(&v.source),
            text(&v.performed_at)
        );
        if let Some(time) = v.last_success {
            println!("  Last successful execution: {}", text(&time));
        }
    }
}
