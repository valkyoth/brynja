# v0.25.3 — Scoped verification and publication handoff

Status: candidate; owner-supplied scoped pentest accepted on 2026-11-01 for
37d29d9e063cd3181ebabf70af1fcf414f4b75e4. All 12 finite final checks passed
on 2026-11-01 as recorded below. Green candidate CI and signed-tag/publication
handoff remain required. Nothing has been published from this release.

## Scope

This patch changes developer tooling and release orchestration, not the
cryptographic implementation. v0.25.2 remains a GitHub-only tag. The completed
HMAC/legacy HMAC implementation and its prior review/evidence are carried into
the intended first crates.io publication at .3 with their original provenance.
This does not relabel old tests as fresh .3 executions or claim the cancelled
.2 final gate passed.

- Standalone Rust `brynja-verify`: explicit component/check commands, scoped
  content freshness, outcome/history preservation and generated terminal/Markdown
  reports. Status scans execute no verification. Catalog assessment bindings are
  complete; unmapped historical records remain identified separately.
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

### Current implementation status

Registration migration is complete: 5,687 runnable configurations, 112
owner-approved manual diagnostics and zero unbound assessment rows. Historical
input mapping remains explicitly unresolved where compatibility cannot be
established; those records are not new execution requirements or current passes.

The default terminal view now groups configurations by command and category,
keeping Miri profiles separate. MD5's 1,025 Miri configurations appear as 35
named groups. Outcome/freshness counts retain failures and incomplete coverage;
group dates describe latest member activity, not a whole-group execution.
`list` and `show` retain individual details, and the Markdown report remains
per-check. Empty catalog headings are omitted.

After this presentation change, all **50 tracker tests**, Clippy with warnings
denied, formatting and diff whitespace checks passed. The added tests cover
grouping, profile isolation, preserved dates/history, mixed failures/outdated
inputs and fractional UTC ordering. Saved results and the generated report were
unchanged; no cryptographic campaign was run.

Next: push the candidate and wait for that exact commit's GitHub/CodeQL results,
then create the owner-approved signed tag and publish after the existing
identity/status guards. No tag, push or publication is claimed here.

### Final gate — PASS (2026-11-01)

The owner's supplied assessment was recorded in documentation-only commit
`fca1c7729106c225a57b21e233c4e133cef3f6a2`. The final gate ran against that clean
commit with its committed PASS review disposition. All 12 entries from
`scripts/release/final-checks.toml` passed:

- `tracker-tests`: 50 tests; `tracker-lint`; `tracker-format`.
- `registry-tests`: 160 tests; `catalog-tests`: three tests.
- `release-regressions`: 22 tests; `release-metadata`: 37 policy cases and ten
  checkpoint tests.
- `package-plan`: 30 crates; `package-contents`: 30 file lists and two root
  archives, with no verification compilation or upload.
- `dependency-policy`; `advisories`: 44 production/workspace dependencies;
  `tracker-advisories`: 59 standalone-tool dependencies, using 1,395 loaded
  RustSec advisories.

The initial full-list invocation stopped after ten successful checks because
the sandbox denied the advisory-cache lock. Only `--check advisories` was
retried with cache access (PASS), followed by the remaining
`--check tracker-advisories` (PASS). Earlier successes were retained, not rerun;
this was an environment error, not a vulnerability finding. The worktree stayed
clean throughout execution. The initial output remains in
`target/release-0.25.3-final-gate.log`; the final tracker scan is in
`target/release-0.25.3-tracker-advisories.log`. These are local, untracked logs.

This follow-up records results and updates transition wording only. It changes
no implementation, manifests, registry, acceptance conditions, gate commands or
stored evidence. The successful checks retain the execution commit above; they
are not relabeled as executions on the follow-up commit. GitHub must assess the
actual pushed commit. No Miri/Kani/ASan/native campaign or evidence refresh ran.

### Development history

### Pre-pentest publication-path check (2026-11-01)

The owner accepts the existing tested data as-is for .3. Original evidence,
including unmapped historical records, was preserved without promoting it to
fresh passes. The .3 pentest remains pending, and this preparation is not the
post-review final-gate verdict.

- Audited the publisher's metadata validation, handoff and upload path: modern
  publication does not call the old tag gate, proof/native validators, tracker
  scans or audits. Existing package version/order, clean-tree, committed review,
  signed-tag and exact-candidate GitHub guards remain in place.
- Removed a leftover pre-handoff receipt-option validation from modern
  publication. Obsolete receipt/native-approval options now warn and are ignored;
  only explicit `--evidence-check` invokes historical diagnostics. Added clear
  handling of handoff errors and honest dry-run messages (nothing uploaded).
- Passed 22 scoped-release regressions, 37 release-policy cases and ten
  checkpoint tests. New fixtures cover the complete publisher entry point with
  missing obsolete receipts, real local identity reads with fake signature/CI
  responses, pending-review rejection and non-uploading dry-run output.
- Passed all 50 Rust tracker tests, 160 registry tests, three catalog tests,
  50 affected package-helper regressions, Clippy and formatting. Both catalog
  and extra-registration exporters reconcile without executing their checks.
- Validated the 30-crate release plan and every selected package file list;
  built the two dependency-root archives with `--no-verify`. Package checks
  were run directly as preparation before the clean committed-candidate step.
  Downstream archives depend on newly indexed crates during actual publication;
  this does not claim all 30 archives were built or uploaded.
- Dependency policy, production and standalone-tool advisory scans, committed
  SBOM comparison and live GitHub release controls passed. The real publisher
  dry run listed all 30 uploads without verification or network uploads.
- Saved results and the generated report retained their original bytes. No
  cryptographic campaign, independent pentest, tag, push or publication ran.
  README now reflects scoped pentests for development releases as approved by
  the owner; the separate public-checkpoint cadence is unchanged.

### Earlier implementation steps

The entries below preserve the results at each migration step. Intermediate
counts and statements that migration was incomplete are historical, not current
gaps; the current status above supersedes them.

Author development checks, 2026-10-31 through 2026-11-01 (not independent review):

- Tracker: 47 temporary-repository/fake-command and tool-identity tests, including
  mid-run registry mutation, stale later-command rejection, effective Cargo-home
  overrides and compiler-wrapper content identity; Clippy with
  warnings denied and formatting passed.
- Release handoff: 18 fixture tests, including selector-error rejection without
  historical-gate fallback; release-package policy: 37 cases plus ten
  checkpoint tests passed. No fixture published a crate or executed cryptography.
- One hundred sixty registry/fixture regressions validate the 27 portable, 48 sanitizer,
  4,933 Miri, nine Kani, 350 compiler and 320 component fixture/script registrations,
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
- Inventory follow-up: 6,619 visible catalog entries (6,237 current declarations
  plus 382 retired historical identities), with all 10,020 original observation
  rows preserved as history. Three exporter regressions and three additional
  Rust catalog tests cover non-execution, unavailable selection, malformed
  inventory, failure preservation and unknown original reuse commits. This
  completes visibility, not runnable input/acceptance bindings for every old task.
- Sanitizer migration: 32 explicit Linux x86-64 ASan/LSan bindings, category-only
  execution, original history shown without inventing compatibility, and
  optional build-input tracking. Helpers/workflow references and retired history
  no longer count as unfinished executable work. Fixture commands tested runner
  selection and outcomes; no sanitizer campaign was launched for this migration.
- Miri migration: all cataloged task selections in three explicit
  alternative profiles; original case markers and nonzero/exact test counts,
  scoped package/tool inputs, nonrecursive registry fragments and scan-local
  input reuse. Before/after execution reads remain fresh. Seven fake-command
  tests cover profile isolation, marker rejection, provenance, mutated fragments,
  forbidden flags, cache lifetime and local-version metadata. The 18 separate
  fixture-workspace selections use reviewed source/shared-fixture closures and
  their own selected lock rows. No Miri execution was performed.
- Kani migration: nine existing proof groups, with original commands and exact
  completion counts; no repository-wide proof-inventory prerequisite. Five
  historical zero-proof selectors remain inventory-only references. Fake
  verifier regressions cover zero/wrong/duplicate/failing populations, step
  failure, version mismatch and local tool-content changes. No proofs ran.
- Historical presentation: `show` agrees with the status table, and explicitly
  distinguishes no new-runner execution from preserved historical results.
- Compiler/fixture migration: offline local-tool selections, fingerprinted vector
  stdin, and explicit compatibility-only ignored-test policy. Zero executed
  tests still fail. Shared registrations are visible from every catalog family
  without duplicate execution. One hundred twelve owner-approved manual diagnostics retain
  commands/history but are not unfinished checks. The other 59 script-based
  assessment bindings remain unresolved. All saved user execution records were
  preserved byte-for-byte as parsed records; no cryptographic campaign ran.
- Standalone-script migration: 27 source-contract, checker-regression and
  differential bindings preserve existing commands and completion signals.
  Static regressions check oracle dependencies, corpus counts, scoped inputs and
  rejection of unreviewed arguments. A real registration with a fake command
  verifies input isolation, Python assertion settings, missing/duplicate marker
  rejection and preservation of previous success and neighboring results.
- Boundary migration: eight DER/ASN.1, record-framing and CPU-backend source-policy
  checks retain their exact inputs and completion signals. PKI/protocol ownership
  replaces the old blanket repository label without changing task IDs/history.
  Static tests reconcile source lists against policy declarations; fake-command
  tests confirm parsed policy checks ignore unread package/version metadata while
  literal mutation tests retain conservative text-sensitive scopes. Fifteen
  historical native-record, ledger and capture-tool diagnostics are explicitly
  reference-only; exact-command tests prevent classifying actual native HMAC or
  sanitizer execution as a diagnostic.
- Assessment migration: twelve exact scratch-codegen/mutation, proof-inventory,
  oracle and mocked sanitizer-regression bindings. Static tests check command
  allowlists, compiler profiles, source closures and external fixture includes;
  fake-output runner tests reject every omitted profile/mode marker, duplicate
  completion, zero-test count and skipped-test summary. No oracle, compiler
  campaign, proof or sanitizer was executed to validate these registrations.
- Portable caller migration: seven modern/legacy HMAC engine-codegen and
  mutation-suite bindings preserve exact target/compiler/panic selections.
  Static tests reconcile emitted completion lines, helper imports, dependency
  closures and raw mutation fixtures. The modern suite's 27 cases include eight
  inherited constructor tests; the legacy suite requires nine. Fake-output
  regressions reject omitted/duplicate profiles, zero tests and skipped tests.
  No original caller-codegen or compiled-mutation suite was run for this migration.
- HMAC-MD5 checker migration: eighteen independently selected existing regression
  suites retain their original compiler/artifact scenarios and exact unittest
  populations. Six static binding tests check their imported helper closure,
  source-contract coverage, compiler selection and separation from native runs.
  That step expanded the fake-output runner regression to 37 assessment bindings,
  including rejection of missing/duplicate completion signals and skipped or
  zero-test summaries. Saved user attempts and historical observations remain
  unchanged; no original cryptographic or compiler campaign ran.
- Hosted/compiler migration: 59 existing hosted HMAC checker selections (171
  unittest methods), 28 HMAC compiler-profile and mutation commands, and 12 leaf
  emitted-code commands. Sixteen static regressions validate exact commands,
  inherited test populations, printed profile markers, imported helper closures
  and scoped source/fixture inputs. The fake-output regression now exercises
  136 assessment bindings, rejecting omitted/duplicate profile markers and
  skipped/zero-test summaries. Two optional-tool regressions cover absence,
  addition, content changes, removal/reuse and fail-closed required tools.
  No original crypto, native or compiler-checker execution was performed.

Tooling regression results are recorded during development; the release gate
and pentest are not yet claimed complete. No Miri, Kani, ASan, native crypto
collection or compiler campaign is required merely because this metadata/tooling
patch exists. Relevant new findings still require their bounded fixes and tests.

### Additional binding pass, 2026-11-01

- Added 39 runnable bindings: 17 shell/compiler checks, six synthetic checker
  suites, three HMAC/SHA-3 differential commands and 13 source-policy checks.
  Original command selections and compiler versions are retained; unsupported
  flags fail closed. Exact completion markers and required populations are
  tested using fake commands, not by rerunning the cryptographic campaigns.
- The focused suites pass: 43 Rust tests, 79 registry tests and three catalog
  tests; tracker Clippy and formatting also pass. The fake-output regression
  covers 172 assessment registrations. A test-module naming collision was
  corrected; the original release-policy test module is preserved unchanged.
- Twelve exact legacy orchestration selectors are visible manual diagnostics.
  There are now 5,604 runnable registrations, 107 manual diagnostics and 88
  unresolved repository/component bindings. Migration is not yet complete.
  All 10,020 historical observations and the user's six execution records retain
  their original provenance. No crypto campaign, commit, push or publication ran.
- Separately inspecting the retained legacy planner suite found its old CI
  preflight assertion incompatible with the approved scoped workflow. The nine
  isolated planner-policy tests passed before that assertion failed. This is
  recorded, not counted as a passing legacy suite or repaired by reinstating
  the blanket CI gate. The current finite CI uses scoped-release regressions.

### Legacy-policy and synthetic-checker follow-up, 2026-11-01

- Added 12 bindings: ten legacy source/model selectors, the default synthetic
  legacy timing checker and the synthetic macOS legacy package checker. Only
  the two optimized-invariant selectors invoke Rust tests; their exact two-test
  completion is required. No original check was executed during migration.
- Five explicitly named historical multi-family milestone rollups remain manual
  campaigns. Their commands/history are retained, and their individual package,
  fixture and policy-regression checks are not hidden by that classification.
- Current totals: 5,616 runnable registrations, 112 manual diagnostics and 71
  unresolved component/script bindings. The migration remains incomplete.
- Passed: 43 Rust tests (fake-output coverage now includes 184 registrations),
  87 registry regressions, three catalog tests, tracker Clippy and formatting.
  Exact positive-but-wrong Rust populations are rejected as well as zero,
  ignored, missing or duplicated completion signals. All 10,020 original
  observations and the user's six execution records retain their provenance.

### Hardened assessment binding follow-up, 2026-11-01

- Added five exact selectors: MD5/SHA-1 source and synthetic-artifact regressions,
  SHA-2 compiled finalizer mutations, and SHA-2/SHA-3 hardened API acceptance.
  The API rows require all 15/14 named Rust tests and retain the existing
  downstream bare-metal compile step, without claiming hardware execution.
- Nine new registration regressions check original policy inventories, mutation
  counts, command selection, compiler/dependency scope and named populations.
  Original subprocesses were mocked when checking orchestration; no crypto,
  compiler-qualification, sanitizer or proof campaign was run.
- Passed: 43 Rust tests, 96 registry regressions, three catalog tests, tracker
  Clippy and formatting. Fake-output acceptance covers 189 registrations.
- Current totals: 5,621 runnable registrations, 112 manual diagnostics and 66
  unresolved component/script bindings. Migration is still incomplete. Original
  historical observations and user execution records remain unchanged; no
  current historical pass was invented, and nothing was committed or pushed.

### Inventory and acceptance-checker binding follow-up, 2026-11-01

- Added four exact selectors: HMAC inventory comparison and its eleven-test
  regression suite, the twelve-test synthetic HMAC acceptance/fault-driver
  suite, and acceleration model/Clippy mutation regressions. Native/compiler
  subprocesses in the HMAC checker are mocked; the acceleration selector really
  compiles its model when explicitly requested. Their labels distinguish these
  scopes, and neither registration nor status inspection executes them.
- Passed: 107 registry regressions, three catalog tests, 43 Rust tests, tracker
  Clippy and formatting. The updated fake-output test covers 193 registrations.
  The twelve synthetic HMAC tests also passed under a guard rejecting any real
  subprocess. Acceleration orchestration used fake compiler outcomes, checking
  positive controls, compilation before mutation execution and exact lint errors.
- Current totals: 5,625 runnable registrations, 112 manual diagnostics and 62
  unresolved component/script bindings. Migration is not yet complete. Report
  regeneration is deterministic; saved state and the user's six execution
  records are unchanged. No crypto campaign, commit, push or publication ran.

### Correctness-control binding follow-up, 2026-11-01

- Added three exact selectors: the eight-test HMAC timing regression (including
  its compiled portable correctness controls), the five-test SHA-512/t CPU
  feature/rejection suite, and the ten-test mocked protected/resident HMAC
  checker. The first is not a timing campaign; the second does not execute
  candidate acceleration or QEMU; the third executes no compiler/native code.
- Source scopes include the timing fixture, SHA-512/t nested consumer and digest
  corpus, selected dependency rows, copied mutation inputs and actual helper
  imports. No whole-workspace lock or repository-commit freshness key was added.
- Passed: 113 registry regressions, three catalog tests, the focused Rust
  completion-signal test over 196 registrations, tracker Clippy and formatting.
  The ten protected/resident checker tests passed with subprocess execution
  blocked. Timing smoke/mutation orchestration was tested with fake compiler
  and process outcomes; no cryptographic qualification was rerun.
- Current totals: 5,628 runnable registrations, 112 manual diagnostics and 59
  unresolved component/script bindings. Migration remains incomplete. Generated
  report output is deterministic, original user attempts and state are preserved,
  and no commit, push or publication was performed.

### HMAC facade/package checker binding follow-up, 2026-11-01

- Added three original selectors: the five-test facade isolation suite,
  nine-test strict consumer suite and twelve-test package regression suite.
  Imported combined-graph tests are included in the required population. These
  commands mock builds, native probes and execution summaries; they do not run
  compiled HMAC or packaged-consumer qualification.
- Inputs cover imported checker helpers, the actual fixture/README text read
  by each suite and selected package name/version fields. Those fields are
  meaningful premises for archive-identity tests, not global crypto freshness
  inputs. No workspace-wide lock fingerprint or new campaign was introduced.
- Passed: 115 registry regressions, three catalog tests, the focused Rust
  completion-signal test over 199 registrations, tracker Clippy and formatting.
  All 26 original tests in the new suites passed with real subprocess launches
  blocked. No compiled package or cryptographic campaign was executed.
- Current totals: 5,631 runnable registrations, 112 manual diagnostics and 56
  unresolved component/script bindings. Migration remains incomplete. Generated
  reports are deterministic; saved state and all six user attempts are unchanged.
  No commit, push, tag or publication was performed.

### Final assessment bindings (2026-11-01)

- Registration migration is complete: **5,687 runnable configurations**, **112
  owner-approved manual diagnostics**, and **zero unbound assessment rows**.
  The 6,619-entry catalog and 10,020 original observations remain intact.
  Earlier progress sections below record intermediate totals, not current gaps.
- Added the final six HMAC/legacy-HMAC package, protected, facade and strict
  consumers and the general SHA-512/t check/regression pair. No cryptographic
  campaigns were run to initialize them; historical results remain historical.
- Fixed explicit compiler selection after environment sanitization in four
  package wrappers and aligned facade packaging with its downstream compiler.
  Original no-option behavior is preserved in the four optional-argument
  wrappers. New bindings name Rust 1.99.1; old ambient-toolchain results are not
  relabeled. No old source-policy review pins were refreshed.
- Passed: ten new static/fake-child binding tests, all 160 registry tests,
  47 Rust tracker tests (including 255 fake command completion contracts),
  three catalog tests, and 50 existing affected package-helper regressions.
  These fixtures did not run a cryptographic qualification campaign. Clippy,
  formatting and both exporters passed. Two report generations were identical,
  and the saved results file, including the six user attempts, remained
  byte-for-byte unchanged. No commit, push, tag or publication was performed.

### Owner and acceptance regression bindings (2026-11-01)

- Added ten existing selectors: the API-profile policy/regression pair,
  composed HMAC owner regressions, direct-owner compiler inspection, two
  legacy-HMAC package graph regression suites, and four legacy/SP 800-185
  acceptance regression commands. Original default selectors are retained;
  write/native/full-campaign variants are not enabled implicitly.
- Source policies, offline metadata tests, compiler-test discovery/MIR checks,
  and compiled disposable mutations are described separately. Reading linked
  evidence is not execution of it. Historical policy pins affect their own
  rows, not the separate implementation results they reference.
- Thirteen new registration tests cover original inventories, helper imports,
  exact populations, fake compiler failures, all 42 portable SP 800-185 output
  mutants, four execution corruptions, and debug/release legacy batch controls.
  The shared fake-output fixture now checks 247 command completion rules.
- Totals: 5,679 runnable registrations, 112 manual diagnostics and eight
  unresolved bindings. The remaining work is six HMAC package/hosted/facade
  commands and the general SHA-512/t check/regression pair. Migration is not
  yet complete, and no historical observation was promoted to a current pass.
- Passed: 150 registry tests, all 47 tracker tests, three catalog tests, Clippy
  with warnings denied, formatting and exporter reconciliation. Generated
  report output is deterministic; saved state and the six user attempts retain
  their original bytes. No cryptographic qualification campaign, commit, push,
  tag or publication was performed.

### Pattern-scoped policy bindings, 2026-11-01

- Added six exact selectors: offline sanitization admission and its regressions,
  SHA-256/SHA-512/Keccak batch policy regressions, and the combined-hash claim
  checker. These preserve existing acceptance markers. SHA-2 sanitizer calls
  are mocked; none of these selectors executes cryptography, a compiler or proofs.
- Added fixed-depth file patterns without dependencies or automatic discovery
  commands. Matching additions, changes, deletions and renames affect only the
  declaring rows; unrelated files remain untouched. Empty matches are recorded,
  matching symlinks/non-files are rejected, and generated outputs stay excluded.
  Historical Git snapshots and working-tree provenance use the same selections.
- Raw manifests, locks and gate/review text remain inputs where the original
  policy actually checks them. They do not become global freshness requirements
  or invalidate previous runtime/proof results. Registration does not claim that
  every historical pin/claim checker currently passes.
- Passed: all 47 tracker tests, 120 registry tests, three catalog tests, Clippy
  with warnings denied and formatting. Completion-rule fixtures cover 205
  registrations. Original batch sanitizer orchestration was exercised with real
  subprocess launches blocked, not by starting a sanitizer campaign.
- Current totals: 5,637 runnable registrations, 112 manual diagnostics and 50
  unresolved component/script bindings. Migration is not complete. Saved state
  and the six original user attempts remain unchanged; report regeneration is
  deterministic. No commit, push, tag or publication was performed.

### Package and execution-oracle binding follow-up (2026-11-01)

- Added 19 existing commands: portable legacy packages; public SHA-256/SHA-2/
  SHA-3 consumers and their regressions; ordinary execution and batch packages;
  KMAC/TupleHash/ParallelHash execution packages; and portable KMAC/TupleHash
  execution-oracle checks. Native/QEMU/write selectors remain separate.
- Package scopes include their copied archives, external test fixtures, helper
  scripts and selected dependency rows. Original policy/gate bytes affect only
  the wrappers that read them, not other cryptographic evidence.
- Eight new registration regressions use static inventories and fake compiler/
  process results. Ownership counts and mutation populations are tied to the
  original generators; missing cases, wrong bytes and missing routes are rejected
  without executing the original cryptographic campaigns.
- Current totals: 5,656 runnable registrations, 112 manual diagnostics and 31
  unresolved component/script bindings. This is registration progress, not a
  completed migration or fresh cryptographic qualification. Historical dates
  and results are preserved; no commit, push, tag or publication was performed.
- Passed: all 47 tracker tests, 128 registry tests and three catalog tests;
  completion-rule fixtures now cover 224 registrations. Clippy with warnings
  denied, formatting, exporter reconciliation and diff checks pass. Two report
  generations produced identical bytes. Saved state and the six original user
  attempts are byte-for-byte unchanged.

### Default execution binding follow-up (2026-11-01)

- Added 13 existing selectors: MD5 CPU/ordinary/hardened acceptance, SHA-1
  CPU/hardened acceptance, hardened SHA-2/Keccak packages and regressions,
  static/hosted CPU packages, and the CPU-boundary policy/regression pair.
  Native/QEMU/write options remain separate; no qualification campaign ran.
- Retained the wrappers' actual archive, helper and policy inputs, including
  explicitly selected secondary cleanup compilers. Source-only checks do not
  require compilers or hash unrelated implementation trees. Old gate/review
  bytes affect only the wrappers that actually inspect them.
- Nine new registration regressions check inventories, command selection,
  failure propagation, tool versions and ownership populations with fake
  subprocess results. The shared completion fixture now covers 237 selectors;
  compatibility checks accept explicitly allowed ignored native tests only
  alongside executed work, and reject all-skipped results and real failures.
- Current totals: 5,669 runnable registrations, 112 manual diagnostics and 18
  unresolved bindings. Migration remains incomplete; historical observations
  are preserved, not promoted to current passes.
- Passed: 47 tracker tests, 137 registry tests, three catalog tests, Clippy with
  warnings denied, formatting and exporter reconciliation. Report regeneration
  is deterministic; saved state and the six original user attempts are unchanged.
  No commit, push, tag or publication was performed.
