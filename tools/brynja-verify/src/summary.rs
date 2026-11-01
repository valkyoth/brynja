//! Terminal presentation only: grouping never changes identities or execution.
use crate::{catalog::Catalog, model::*, report};
use std::collections::{BTreeMap, BTreeSet};

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct GroupKey<'a> {
    component: &'a str,
    category: &'a str,
    command: &'a [String],
    cwd: &'a str,
    platform: &'a Option<String>,
    stdin: &'a Option<String>,
}

fn clean(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn name(check: &Check) -> &str {
    // Existing split Miri cases are named e.g. "md5-bulk:75 [extended]".
    // Only the label loses the case suffix; the full command is the group key.
    if check.category.starts_with("miri-")
        && let Some((family, case)) = check.name.split_once(':')
        && case
            .split_whitespace()
            .next()
            .is_some_and(|n| n.parse::<u64>().is_ok())
    {
        return family;
    }
    &check.name
}

// Recorded timestamps are UTC RFC3339. Compare fractional and whole seconds
// consistently while retaining the original timestamp verbatim for display.
fn time_key(value: &str) -> (&str, String) {
    let value = value.strip_suffix('Z').unwrap_or(value);
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, ""));
    (seconds, format!("{fraction:0<9}"))
}

fn latest<'a>(values: impl Iterator<Item = &'a str>) -> &'a str {
    values.max_by_key(|s| time_key(s)).unwrap_or("—")
}

fn counts(values: impl Iterator<Item = String>) -> String {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value).or_insert(0usize) += 1;
    }
    counts
        .into_iter()
        .map(|(label, n)| format!("{label}: {n}"))
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn render(
    registry: &Registry,
    state: &State,
    catalog: &Catalog,
    component: Option<&str>,
    category: Option<&str>,
) -> String {
    let mut groups: BTreeMap<GroupKey<'_>, Vec<&Check>> = BTreeMap::new();
    for check in &registry.checks {
        if component.is_some_and(|c| c != check.component)
            || category.is_some_and(|c| c != check.category)
        {
            continue;
        }
        groups
            .entry(GroupKey {
                component: &check.component,
                category: &check.category,
                command: &check.command,
                cwd: &check.cwd,
                platform: &check.platform,
                stdin: &check.stdin,
            })
            .or_default()
            .push(check);
    }
    let mut out = String::from("Grouped checks (configurations, not execution history):\n");
    let mut historical = false;
    for (key, checks) in groups {
        let names: BTreeSet<_> = checks.iter().map(|c| name(c)).collect();
        let label = if names.len() == 1 {
            (*names.first().unwrap()).to_string()
        } else {
            key.command.join(" ")
        };
        let views: Vec<_> = checks
            .iter()
            .map(|c| report::display_view(c, state, catalog))
            .collect();
        let current = views.iter().filter(|v| report::current_pass(v)).count();
        let outcomes = counts(views.iter().map(|v| {
            // The full matching-input history explanation remains in show/report.
            v.result
                .split(" (matching-input history;")
                .next()
                .unwrap()
                .to_string()
        }));
        let freshness = counts(views.iter().map(|v| {
            if v.result.starts_with("Historical ") {
                "Historical inputs unmapped"
            } else if v.freshness.starts_with("Outdated") || v.freshness.starts_with("outdated") {
                "Outdated (see show for changed inputs)"
            } else if v.freshness.starts_with("Unresolved") {
                "Unresolved (see show for cause)"
            } else if v.freshness.starts_with("Current starting inputs;") {
                "Current inputs; needs attention"
            } else {
                &v.freshness
            }
            .to_string()
        }));
        let attempts: Vec<_> = checks
            .iter()
            .filter_map(|c| state.attempts.get(&c.key()).and_then(|r| r.last()))
            .collect();
        let last_run = latest(
            attempts
                .iter()
                .map(|a| a.ended.as_deref().unwrap_or(&a.started)),
        );
        let last_success = latest(views.iter().filter_map(|v| v.last_success.as_deref()));
        let sources: BTreeSet<_> = views
            .iter()
            .map(|v| v.source.as_str())
            .filter(|s| !s.is_empty() && *s != "—")
            .collect();
        let source = match sources.len() {
            0 => "—",
            1 => sources.first().unwrap(),
            _ => "mixed snapshots; use show for each configuration",
        };
        out.push_str(&format!("\n{} / {} / {}\n  Configurations: {} | Current passes: {}/{} | {}\n  Freshness: {}\n  Latest execution activity (UTC): {} | Last successful execution (UTC): {}\n  Source tested: {}\n",
            clean(key.component), clean(key.category), clean(&label), checks.len(), current, checks.len(), clean(&outcomes), clean(&freshness), clean(last_run), clean(last_success), clean(source)));
        let history: Vec<_> = views
            .iter()
            .filter(|v| v.result.starts_with("Historical "))
            .collect();
        if !history.is_empty() {
            historical = true;
            out.push_str(&format!(
                "  Latest historical record (UTC): {}\n",
                clean(latest(history.iter().map(|v| v.performed_at.as_str())))
            ));
        }
    }
    out.push_str("\nDates are latest member activity, not a whole-group execution. Incomplete attempts use their start time.\nUse list COMPONENT [CATEGORY] for individual IDs; show COMPONENT ID for dates, sources, failures and freshness reasons.\n");
    if historical {
        out.push_str("Historical-only configurations: No execution recorded by this runner.\nHistorical inputs unmapped: not a current pass. Historical record dates can describe reuse, not a fresh execution.\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn utc_fraction_order_preserves_original_dates() {
        assert_eq!(
            latest(["2026-01-01T00:00:00Z", "2026-01-01T00:00:00.1Z"].into_iter()),
            "2026-01-01T00:00:00.1Z"
        );
        assert_eq!(
            latest(["2026-01-01T00:00:00.9Z", "2026-01-01T00:00:01Z"].into_iter()),
            "2026-01-01T00:00:01Z"
        );
    }
}
