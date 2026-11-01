use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type Map = BTreeMap<String, String>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub schema: u32,
    pub execution_semantics: u32,
    pub catalog: Option<String>,
    #[serde(default)]
    pub includes: Vec<String>,
    #[serde(default)]
    pub groups: BTreeMap<String, Group>,
    pub checks: Vec<Check>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    #[serde(default)]
    pub normalize_local_versions: bool,
    #[serde(default)]
    pub paths: Vec<String>,
    // Absence is fingerprinted too: e.g. a newly added automatic build.rs.
    #[serde(default)]
    pub optional_paths: Vec<String>,
    // File-only, fixed-depth patterns; '*' matches within one path component.
    #[serde(default)]
    pub patterns: Vec<String>,
    // Explicit TOML projections: only the selected fields affect identity.
    #[serde(default)]
    pub toml: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub locks: Vec<LockInput>,
    #[serde(default)]
    pub tools: Vec<Tool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockInput {
    pub path: String,
    pub packages: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub program: String,
    pub toolchain: Option<String>,
    // For checkers with an existing PATH fallback. Absence is an input, not a
    // missing required tool or permission to skip the actual check.
    #[serde(default)]
    pub optional: bool,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub component: String,
    pub id: String,
    pub name: String,
    pub establishes: String,
    #[serde(default = "portable", skip_serializing_if = "is_portable")]
    pub category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
    pub cwd: String,
    pub inputs: Vec<String>,
    #[serde(default)]
    pub environment: Map,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reject_environment: Vec<String>,
    pub success: Success,
    pub timeout_seconds: u64,
    #[serde(default = "log_limit")]
    pub log_bytes: u64,
}

fn portable() -> String {
    "portable".into()
}
fn is_portable(value: &String) -> bool {
    value == "portable"
}

fn log_limit() -> u64 {
    16 * 1024 * 1024
}

impl Check {
    pub fn key(&self) -> String {
        format!("{}/{}", self.component, self.id)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Success {
    pub contains: Vec<String>,
    // Ordinary compatibility suites deliberately leave native-only tests ignored.
    // They still require nonzero executed tests and never claim those ignored lanes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_ignored: bool,
    // Use the existing libtest summary, not test discovery or a new population
    // framework. Backends/proofs should additionally require their own marker.
    pub minimum_tests: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact_tests: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unique_lines: Vec<String>,
    // Existing compiler drivers append diagnostic counts to profile markers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unique_prefixes: Vec<String>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub fingerprint: String,
    pub inputs: Map,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub id: String,
    pub source: String,
    pub started: String,
    pub ended: Option<String>,
    pub outcome: String,
    pub explanation: String,
    pub command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<String>,
    pub cwd: String,
    pub environment: Map,
    pub before: Snapshot,
    pub after: Option<Snapshot>,
    pub log: String,
    pub log_sha256: Option<String>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct View {
    pub checked_at: String,
    pub fingerprint: Option<String>,
    pub result: String,
    pub freshness: String,
    pub source: String,
    pub performed_at: String,
    pub last_success: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub schema: u32,
    #[serde(default)]
    pub attempts: BTreeMap<String, Vec<Attempt>>,
    #[serde(default)]
    pub views: BTreeMap<String, View>,
    // Evidence that cannot be mapped stays discoverable without becoming PASS.
    #[serde(default)]
    pub historical: Vec<Historical>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Historical {
    pub reference: String,
    pub explanation: String,
}
