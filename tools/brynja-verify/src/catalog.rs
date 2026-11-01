//! Visibility for existing assessments; never infer runnable/current coverage.
use crate::{Result, model::*, storage};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Default, Deserialize)]
pub struct Catalog {
    pub schema: u32,
    pub entries: Vec<Entry>,
    #[serde(skip)]
    by_id: BTreeMap<String, usize>,
    #[serde(skip)]
    bound: BTreeSet<String>,
}

#[derive(Deserialize, Serialize)]
pub struct Entry {
    pub id: String,
    pub families: Vec<String>,
    pub phase: String,
    pub label: String,
    pub command: Vec<String>,
    pub environment: Map,
    pub stdin: Option<String>,
    pub definition: serde_json::Value,
    pub reason: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub manual_diagnostic: bool,
    pub history: Vec<Observation>,
}

#[derive(Deserialize, Serialize)]
pub struct Observation {
    pub result: String,
    pub ended: String,
    pub source: String,
    pub campaign_commit: String,
    pub receipt: String,
    pub log_sha256: String,
    pub reference: String,
}

fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

pub fn load(root: &Path, registry: &Registry) -> Result<Catalog> {
    let Some(path) = &registry.catalog else {
        return Ok(Catalog::default());
    };
    let raw = std::fs::read(storage::relative(root, path)?)?;
    if raw.len() > 32 * 1024 * 1024 {
        return Err("oversized assessment catalog".into());
    }
    let mut catalog: Catalog = serde_json::from_slice(&raw)?;
    if catalog.schema != 1 || catalog.entries.len() > 20000 {
        return Err("unsupported or oversized assessment catalog".into());
    }
    let mut ids = BTreeSet::new();
    for row in &catalog.entries {
        if !crate::identifier(&row.id)
            || !ids.insert(&row.id)
            || row.families.is_empty()
            || row.families.iter().any(|f| !crate::identifier(f))
            || row.reason.is_empty()
        {
            return Err("invalid catalog identity or missing unresolved-scope explanation".into());
        }
    }
    catalog.by_id = catalog
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| (e.id.clone(), i))
        .collect();
    for check in &registry.checks {
        if let Some(row) = catalog.entry(&check.component, &check.id) {
            if row.manual_diagnostic {
                return Err("manual diagnostic cannot also be an implicit runnable check".into());
            }
            if !category_matches(&check.category, &row.phase) {
                return Err("catalog registration has inconsistent component/category".into());
            }
            catalog.bound.insert(check.id.clone());
        }
    }
    Ok(catalog)
}

impl Catalog {
    pub fn component(&self, name: &str) -> bool {
        self.entries
            .iter()
            .any(|e| e.families.iter().any(|f| f == name))
    }
    pub fn entry(&self, component: &str, id: &str) -> Option<&Entry> {
        self.by_id
            .get(id)
            .and_then(|i| self.entries.get(*i))
            .filter(|e| e.families.iter().any(|f| f == component))
    }
    pub fn count(&self, component: &str, category: Option<&str>, _registry: &Registry) -> usize {
        self.entries
            .iter()
            .filter(|e| {
                e.families.iter().any(|f| f == component)
                    && category.is_none_or(|c| e.matches_category(c))
                    && !e.reference_only()
                    && !self.bound.contains(&e.id)
            })
            .count()
    }
    fn groups(
        &self,
        component: Option<&str>,
        _registry: &Registry,
        references: bool,
    ) -> BTreeMap<(&str, &str), (usize, usize)> {
        let mut groups = BTreeMap::new();
        for row in &self.entries {
            if row.reference_only() != references || self.bound.contains(&row.id) {
                continue;
            }
            for family in &row.families {
                if component.is_some_and(|c| c != family) {
                    continue;
                }
                let count = groups
                    .entry((family.as_str(), row.phase.as_str()))
                    .or_insert((0, 0));
                count.0 += 1;
                count.1 += usize::from(!row.history.is_empty());
            }
        }
        groups
    }
    pub fn terminal(&self, component: Option<&str>, registry: &Registry) {
        let assessments = self.groups(component, registry, false);
        let references = self.groups(component, registry, true);
        if assessments.is_empty() && references.is_empty() {
            return;
        }
        if !assessments.is_empty() {
            println!("\nAssessments awaiting runnable bindings (NOT current passes):");
            println!(
                "{:<16} {:<18} {:<9} WITH HISTORY / SCOPE",
                "COMPONENT", "CATEGORY", "TOTAL"
            );
        }
        for ((family, phase), (total, history)) in assessments {
            println!(
                "{:<16} {:<18} {:<9} {} / unresolved",
                clean(family),
                clean(phase),
                total,
                history
            );
        }
        if !references.is_empty() {
            println!("\nManual diagnostics / supporting references (NOT unfinished checks):");
        }
        for ((family, phase), (total, history)) in references {
            println!(
                "{:<16} {:<18} {:<9} {} with history / reference only",
                clean(family),
                clean(phase),
                total,
                history
            );
        }
        println!(
            "Use list COMPONENT [CATEGORY] or show COMPONENT ID. Catalog-only entries never run implicitly."
        );
    }
    pub fn markdown(&self, registry: &Registry) -> String {
        if self.entries.is_empty() {
            return String::new();
        }
        let mut out = String::from(
            "\n## Complete assessment inventory\n\nSee [every assessment](VERIFICATION_CATALOG.md). Counts below are catalog entries, not current passes or additional obligations. Historical outcome and original execution time are available with `show COMPONENT ID`; input applicability is unresolved. All Miri profiles are shown and overlap.\n\n| Component | Category | Assessments | With history | Freshness |\n| --- | --- | --- | --- | --- |\n",
        );
        for ((family, phase), (total, history)) in self.groups(None, registry, false) {
            out.push_str(&format!(
                "| {} | {} | {total} | {history} | Unresolved / not assessed |\n",
                clean(family).replace('|', "\\|"),
                clean(phase).replace('|', "\\|")
            ));
        }
        out.push_str("\n### Manual diagnostics and supporting references (not unfinished checks)\n\n| Component | Category | References | With history |\n| --- | --- | --- | --- |\n");
        for ((family, phase), (total, history)) in self.groups(None, registry, true) {
            out.push_str(&format!(
                "| {} | {} | {total} | {history} |\n",
                clean(family),
                clean(phase)
            ));
        }
        out
    }
    pub fn inspect(&self, root: &Path, registry: &Registry, args: &[String]) -> Result<()> {
        if !(args.len() == 2 || args.len() == 3) || (args[0] == "show" && args.len() != 3) {
            return Err("use list COMPONENT [CATEGORY] or show COMPONENT ID".into());
        }
        let component = &args[1];
        if !self.component(component) && !registry.checks.iter().any(|c| c.component == *component)
        {
            return Err("unknown component; no broader scope selected".into());
        }
        if args[0] == "show" {
            if let Some(check) = registry.checks.iter().find(|c| {
                c.id == args[2]
                    && (c.component == *component
                        || self
                            .entry(component, &c.id)
                            .is_some_and(|row| row.families.contains(&c.component)))
            }) {
                let state = storage::load(root)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"registration": check, "attempts":state.attempts.get(&check.key()), "view":crate::report::display_view(check, &state, self), "historical_catalog": self.entry(component, &check.id)})
                    )?
                );
            } else if let Some(row) = self.entry(component, &args[2]) {
                println!(
                    "{} No execution selected.\n{}",
                    if row.manual_diagnostic {
                        "Manual diagnostic; not an unfinished component check."
                    } else {
                        "Catalog-only; current applicability UNRESOLVED."
                    },
                    serde_json::to_string_pretty(row)?
                );
            } else {
                return Err("unknown check; no broader scope selected".into());
            }
            return Ok(());
        }
        let phase = args.get(2).map(String::as_str);
        let mut lines = Vec::new();
        for check in &registry.checks {
            if check.component == *component
                && phase.is_none_or(|p| category_matches(&check.category, p))
            {
                lines.push((
                    check.id.as_str(),
                    format!(
                        "{:<28} {:<12} runnable registration | {}",
                        check.id,
                        check.category,
                        clean(&check.name)
                    ),
                ));
            }
        }
        for row in &self.entries {
            if !row.families.contains(component) || phase.is_some_and(|p| !row.matches_category(p))
            {
                continue;
            }
            if self.bound.contains(&row.id) {
                if !registry
                    .checks
                    .iter()
                    .any(|c| c.id == row.id && c.component == *component)
                    && let Some(check) = registry
                        .checks
                        .iter()
                        .find(|c| c.id == row.id && row.families.contains(&c.component))
                {
                    lines.push((
                        &row.id,
                        format!(
                            "{:<28} {:<12} shared registration: use run {} {} | {}",
                            row.id,
                            check.category,
                            check.component,
                            check.id,
                            clean(&check.name)
                        ),
                    ));
                }
                continue;
            }
            let status = row
                .history
                .last()
                .map(|h| format!("historical {} at {}", clean(&h.result), clean(&h.ended)))
                .unwrap_or_else(|| "no mapped history".into());
            lines.push((
                &row.id,
                format!(
                    "{:<28} {:<12} {} | {} | {}",
                    row.id,
                    clean(&row.phase),
                    if row.manual_diagnostic {
                        "manual diagnostic"
                    } else if row.reference_only() {
                        "reference only"
                    } else {
                        "unresolved"
                    },
                    status,
                    clean(&row.label)
                ),
            ));
        }
        if lines.is_empty() {
            return Err("unknown/empty category; no broader scope selected".into());
        }
        lines.sort_by_key(|(id, _)| *id);
        for (_, line) in lines {
            println!("{line}");
        }
        Ok(())
    }
}

fn category_matches(category: &str, phase: &str) -> bool {
    category == phase
        || (phase == "miri"
            && matches!(
                category,
                "miri-routine" | "miri-extended" | "miri-existing-full"
            ))
}

impl Entry {
    pub fn matches_category(&self, category: &str) -> bool {
        category == self.phase
            || (self.phase == "miri"
                && self
                    .definition
                    .get("profile")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|p| category == format!("miri-{p}")))
    }
    fn reference_only(&self) -> bool {
        self.manual_diagnostic
            || matches!(
                self.phase.as_str(),
                "entrypoint" | "workflow" | "retired-history" | "inventory-only"
            )
    }
}
