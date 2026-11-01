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

### Review remediation (2026-11-01)

The supplied review of candidate `432b866b` reported no Critical/High issues,
two Medium findings across the two reviewers, and five Low findings. The
following dispositions preserve the compatible API policy explicitly approved
by the maintainer. These are author remediation notes, not an independent PASS
or a replacement for the scoped candidate retest.

- **Medium, dependency policy:** centralize the exact legacy HMAC workspace pin
  and inherit it from legacy HKDF and legacy HMAC std. Twelve negative controls
  reject duplicated declarations and changed version/feature policies.
- **Medium, TLS length binding:** add `expand_tls13`, rejecting mismatched label
  and destination lengths before output admission; route `expand_label` through
  it. Tests cover equal-length independent answers, shorter/longer/empty
  mismatches, unchanged rejected buffers, differing-length domain separation
  and the hash-specific output bound. Raw encoding/Expand remain low-level and
  explicitly do not provide this binding.
- **Low, long imported PRK work:** retain long imports for compatibility.
  Document re-keying/re-hashing per output block (up to 255 times) and require
  caller admission limits. Existing long-key independent vectors stay tested;
  no keyed-state caching or reduced-work guarantee is claimed.
- **Low, empty output:** retain intentional zero-length support and test it.
  Protocol-specific nonempty key requirements remain the caller's policy.
- **Low, PRK export:** retain the explicit `expose` boundary. Document and test
  that exported copies survive owner clearing and require their own cleanup.
- **Low, Drop-only cleanup:** add consuming `clear` on both PRK/output families.
  Test complete long-PRK clearing, canaries, immediate buffer reuse and the
  empty-output `None` receipt, while preserving Drop/unwind tests. Forget/leak
  remains excluded; explicit clearing is not automatic leak prevention.
- **Low, generic TLS framing:** retain all six modern SHA-2 identities, with
  tests for the checked helper on each. These are framing helpers, not cipher
  negotiation or TLS interoperability approval.

The enlarged lifecycle test also exposed Miri stdout/stderr interleaving in the
runner's completion binding. Lifecycle bindings now match the exact selected
test name plus a successful one-test summary, not adjacent name/`ok` output.
Registry controls reject restoration of the fragile adjacency requirement;
process success, exact population and instrumentation remain mandatory. The
original rejected attempt remains in the tracker.

Post-remediation validation on the working tree based on `432b866b`:

- All 17 modern and 15 legacy HKDF registrations are current passes, including
  sanitizers, selected Miri tests, public-bounds proofs, compiler cleanup,
  MSRV/no_std, optimized tests and bounded timing screens.
- All 18 finite CI check commands passed. The wrapper correctly refused release
  candidate status because this worktree is uncommitted; this is not a final
  gate or GitHub PASS. Separate `cargo deny check`, `cargo audit --deny warnings`
  and SBOM comparison also passed.
- The verifier's 50 Rust tests and 165 registry tests passed, including the
  updated completion-binding regressions. Public API documentation builds,
  formatting, Clippy and whitespace checks passed. The metadata-only legacy
  HMAC std consumer passed its four doctests and all-feature compilation.
- Historical data and saved observations outside HKDF/legacy HKDF are unchanged.

The temporary root `PENTEST.md` was removed after remediation and testing, as
requested. Findings and compatibility decisions are retained above. Independent
candidate retest and release authorization remain pending.

### Follow-up retest remediation (2026-11-01)

The supplied retest of `1a188c84` confirmed explicit clearing and the dependency
change, found no new security issues, and retained two minor corrections:

- Close the remaining public encoder route. `Tls13Label::encode` is now
  crate-private, superseding the first review's decision to leave that encoder
  public. Users of the label type derive through `expand_tls13` or
  `expand_label`. Raw HKDF Expand remains available for arbitrary info; this
  cannot prevent a caller from independently constructing malformed TLS bytes.
- Clarify the owner documentation: reuse does not **require** exporting or
  reconstructing a PRK; explicit `expose` remains available.

The six existing parameter/wire regressions move unchanged into unit-test
scope to exercise the private encoder. The tracker now selects that exact
module rather than the removed integration harness. Two external compile-fail
doctests independently cover encoder privacy (using disjoint buffers) and
overlapping label/output borrows through checked expansion. Registry regression
tests pin the new selectors, exact populations and moved source input.

The maintainer-approved policy remains: zero-length output is supported,
including matching zero-length labels; long PRK imports and explicit export
remain available, and label framing remains generic over six SHA-2 identities.
Their bounds, cleanup exclusions and caller responsibilities are unchanged and
tested. The safe u16-to-usize cast and Kani dead-code allowance need no change,
as the retest itself notes. These notes are not independent release approval.

Follow-up validation: all 17 modern registrations passed again, including the
moved six-test module and both compile-fail tests. The shared-input legacy bounds
proof passed again; the other 14 legacy observations remain current without
rerunning unchanged inputs. Both crate suites, Clippy, formatting, public docs,
facade compilation, 166 registry tests, nine owner-contract tests, five proof
adapter tests, API-profile regressions, release-plan/scoped-release regressions
and requirements/protocol-surface checks passed. The temporary follow-up
`PENTEST.md` was removed after these checks; its dispositions are retained here.

### Build hygiene and doctest evidence retest (2026-11-01)

The next supplied review reported an untracked copy of the removed integration
harness and an overstatement of compile-fail diagnostic coverage. At remediation
time `crates/brynja-crypto/tests/hkdf_parameters.rs` was already absent from the
working directory. A registry regression now checks the filesystem, including
untracked/ignored files and symlinks, so that obsolete harness cannot silently
return. The six tests remain in the internal parameter module.

The `label-aliasing` name, evidence description and security controls now state
that the examples only have to fail compilation. Stable rustdoc does not check
their annotated E0624/E0502 codes; an unrelated compilation error can satisfy
them. This corrects the diagnostic-specific implication of the previous retest
notes; no new diagnostic-matching probe or stronger assurance is claimed.
Production code and API behavior are unchanged.

Validation used a new empty target directory: both HKDF crate suites and their
doctests passed, as did all-target Clippy with warnings denied. Formatting,
168 registry tests and 23 scoped-release tests passed. The revised tracker
registration was executed and passed its exact two-example population.
The temporary `PENTEST.md` was removed after validation; these dispositions
remain recorded here. This is not independent approval or a final release gate.

### Earlier candidate preparation

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
