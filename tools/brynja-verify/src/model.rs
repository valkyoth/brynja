use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type Map = BTreeMap<String, String>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub schema: u32,
    pub execution_semantics: u32,
    #[serde(default)]
    pub groups: BTreeMap<String, Group>,
    pub checks: Vec<Check>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    #[serde(default)]
    pub paths: Vec<String>,
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
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub component: String,
    pub id: String,
    pub name: String,
    pub establishes: String,
    pub command: Vec<String>,
    pub cwd: String,
    pub inputs: Vec<String>,
    #[serde(default)]
    pub environment: Map,
    pub success: Success,
    pub timeout_seconds: u64,
    #[serde(default = "log_limit")]
    pub log_bytes: u64,
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
    // Use the existing libtest summary, not test discovery or a new population
    // framework. Backends/proofs should additionally require their own marker.
    pub minimum_tests: Option<u64>,
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
