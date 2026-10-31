# v0.25.3 — Scoped verification and publication handoff

Status: candidate; scoped pentest/retest, final checks and green candidate CI are
still required. Nothing has been published from this release.

## Scope

This patch changes developer tooling and release orchestration, not the
cryptographic implementation. v0.25.2 remains a GitHub-only tag. The completed
HMAC/legacy HMAC implementation and its prior review/evidence are carried into
the intended first crates.io publication at .3 with their original provenance.
This does not relabel old tests as fresh .3 executions or claim the cancelled
.2 final gate passed.

- Standalone Rust `brynja-verify`: explicit component/check commands, scoped
  content freshness, outcome/history preservation and generated terminal/Markdown
  reports. Status scans execute no verification. Initial registrations are
  deliberately limited, with unmapped historical records identified separately.
- Routine CI uses the finite release/component list. Existing native and compiler
  matrix jobs remain available in explicitly started qualification workflows.
  Dependency audits and CodeQL remain in the normal review/publication flow.
- After clean scoped review and finite final checks, push the candidate and wait
  for green GitHub. The publisher checks identity and existing GitHub results,
  then uploads without rerunning the gate or compiling packages again.

See [component completion](../docs/assurance/component-completion.md),
[runner commands](../docs/assurance/brynja-verify.md) and
[release handoff](../docs/release/scoped-release.md).

## Verification record

Author development checks, 2026-10-31 (not independent review):

- Tracker: 16 temporary-repository/fake-command integration tests, including
  mid-run registry mutation, stale later-command rejection, effective Cargo-home
  overrides and compiler-wrapper content identity; Clippy with
  warnings denied and formatting passed.
- Release handoff: 18 fixture tests, including selector-error rejection without
  historical-gate fallback; release-package policy: 37 cases plus ten
  checkpoint tests passed. No fixture published a crate or executed cryptography.
- Four catalog/fixture regressions validate the 27 portable registrations,
  explicit dependency scopes, completion markers and facade-version pins.
  Six exact-version API fixture graphs also resolve the .3 facade with Cargo
  locked/offline metadata, without compilation. The retained manual catalog's
  seven offline-bootstrap regressions pass.
- Changed workflow consumers: push-CI (10), Rust-freshness (11), macOS-resident
  CI (6), assurance (52), zeroization (14) and constant-time (8) regressions
  passed. Dedicated SHA-512 checks used four synthetic installer cases, seven
  policy mutations and three implicit-trigger rejections, not a new SDE run.
- Release-plan, requirements, generated assurance metadata and SBOM consistency
  checks passed. The 30-crate publication order remains valid.
- The standalone tool's 59 locked dependencies passed the RustSec check against
  1,395 loaded advisories. These dependencies do not enter production crates.
- Historical reconciliation preserved 47 original dashboard files and indexed
  10,020 overlapping observation rows; no current pass was fabricated/imported
  for the 27 check registrations.

Tooling regression results are recorded during development; the release gate
and pentest are not yet claimed complete. No Miri, Kani, ASan, native crypto
collection or compiler campaign is required merely because this metadata/tooling
patch exists. Relevant new findings still require their bounded fixes and tests.
