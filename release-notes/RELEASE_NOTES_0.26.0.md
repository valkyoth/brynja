# v0.26.0 candidate — HKDF and TLS labels

Status: local development candidate for review; scoped pentest, final gate and
exact-candidate GitHub/CodeQL are pending. No tag or publication is authorized
by these notes. This is an internal milestone, with zero crates.io uploads.

## Implemented scope

- Allocation-free Extract, already-pseudorandom PRK import and reusable Expand
  for six explicit SHA-2 identities through `brynja::crypto::hkdf` and
  `brynja_crypto::hkdf`. Output is bounded to 255 full digest blocks.
- Exact TLS 1.3 Expand-Label framing, with public length rejection before
  destination admission. This is not a TLS key schedule or transcript engine.
- Caller-backed PRK/derived-key clearing owners, guarded partial initialization
  and live scratch cleanup on return or recoverable unwind.
- Separate explicitly acknowledged HKDF-SHA-1 in `brynja-legacy-hkdf`; no MD5
  HKDF, modern fallback or legacy TLS label API.

The facade advances from 0.25.3 to 0.26.0. Existing support versions remain
unchanged for this internal train; the new legacy leaf is 0.1.0 and not selected
for upload. Release inventory, fixture facade pins and SBOM follow that graph.
Packaged public-API usability acceptance remains the separate v0.26.1 scope.

## Development verification

Before candidate metadata preparation, the scoped tracker recorded 17/17
modern and 15/15 legacy checks as current passes. These cover portable vectors,
ownership/API contracts, public-bounds proofs, fault handling, optimized tests,
MSRV and Cortex-M compilation, bounded compiler dispatch, host timing screens,
and selected ASan/LSan/Miri executions. They are not all-input proofs or
independent review. Exact timestamps, source fingerprints, limits and attempts
are in the [tracker](../docs/VERIFICATION_RESULTS.md) and
[evidence index](../docs/evidence-index.md#hkdf-development-evidence-v0260).

The first modern Miri fault test passed but its runner completion check rejected
interleaved progress output. The corrected binding was rerun successfully; the
original failed attempt remains recorded. Unrelated saved observations and
historical records have not been rewritten as new results.

Qualification still excludes whole-frame/register/spill erasure, cleanup after
forget/abort, cross-target timing and independent cryptographic review. Existing
HMAC/core contracts are delegated premises. Zero alarms in the bounded timing
screen is not a constant-time certification. See the
[security contract](../docs/security-controls.md#hkdf-development-contract-v0260).

## Release handoff — pending

Candidate preparation checks (2026-11-01; not the post-review final gate):

- Facade compile and scoped formatting passed. Ten affected facade fixture
  graphs resolve locked/offline after updating their facade pins and recording
  the composition crate's core dependency; their cryptographic suites were not
  rerun for this bookkeeping change.
- 165 registry tests, 23 scoped-release tests, 37 release-policy cases and ten
  checkpoint tests passed. Workspace-policy regressions, API-profile and
  requirements/surface reproducibility checks, 16 domain-requirement tests,
  SBOM comparison and diff whitespace checks passed.
- Release-plan regressions passed, including rejection of a removed scoped
  pentest requirement. The validator now recognizes the prepared 0.26.0 exit
  without rewriting historical milestone dispositions.
- The real final-gate entry point refused the dirty candidate before executing
  checks, as required. Its PASS-review and clean-candidate guards are unchanged.
- A status-only rescan retained all 32 current HKDF passes with their original
  execution dates. Unrelated attempts/views and historical records compare
  equal to the baseline; no verification campaign was rerun.

`scripts/release/final-checks.toml` contains the finite 21-check candidate list;
routine CI uses its explicit 18-check subset plus the separate audit job.
It does not run the tracker or restart Miri/Kani/sanitizer/timing/compiler
campaigns. Preparing or listing this manifest does not mean the final gate ran.

Remaining: obtain and accurately record the candidate's scoped pentest/retest,
run the finite final gate, push and wait for that commit's
GitHub/CodeQL results, then obtain explicit signed-tag approval. No PASS report
has been fabricated for this candidate and nothing has been uploaded.
