# Test decomposition: measured audit and implementation order

## Measured starting point (2026-10-29)

The owner stopped the v0.25.2 extended Miri campaign after approximately twenty
hours. Both hosts were gracefully cancelled, their logs/source snapshots copied
off-host and historical validation completed before shutdown. There are 2,962
disjoint passing commands out of 4,122; four in-flight commands were cancelled,
and 1,160 commands have no completed pass. This is incomplete assurance, not a
reason to label a failed/incomplete gate green.

Receipts:

- Intel partition: `9fcac6d91491d23a07ba48cefffce0eaa95ca6067731b32f973c4e498280ebfc`.
- Second x86 partition: `2beb56416607791f64642272de127d046c06a8c08771d6c65f16921090ded40a`.

Local archives and per-command observations are retained outside Git in
`../brynja-evidence/release-reports/v0252-checkpoint-20261028/`, not packaged in
crates.io archives. The local `receipt-locations.json` and `registries/` provide
relocated job paths without rewriting sealed historical manifests or logs.
Elapsed sums below are summed command wall times across concurrent workers,
not the campaign wall time, instruction counts or comparative CPU benchmarks.

| Area | Observation from saved results | Structural cause / useful split |
| --- | --- | --- |
| TupleHash | 1,111 completed tasks accumulated about 50 command-hours; longest completed case about 27.5 minutes | Already split length/tail cases, but individual tests still combine output widths and multiple public/secret/streaming routes. Separate independent scenarios; keep each owner's creation/use/drop checks together. |
| KMAC | Broad task 0 took 20,746 seconds (5h46m); total 61 tasks about 6.9 command-hours | `--tests` still sweeps unregistered additions. Streamed setup combines five key/customization lengths, five chunk sizes, two strengths and fixed/XOF modes; verification regressions are bundled too. Give independent scenarios exact identities and coverage markers. |
| ParallelHash | First three completed scoped matrix tasks each took 110–115 minutes | Even one selected case uses B=1 over 177 bytes, recomputes references and checks both public and secret lifecycles. Many leaf hashes remain inside a single scenario. Splitting a matrix by index alone does not solve this. |
| Legacy SHA-1 / MD5 | 683 / 940 completed tasks; largest completed cases about 77 / 235 seconds | Existing boundary/case splits are comparatively bounded. Do not rewrite or rerun these merely because another family is slow. |
| Other phases | Current ASan/Kani have passing results; repository/compiler checkpoint phases unstarted | Preserve separate phase receipts; do not make one failure invalidate unrelated completed checks. Audit inner script suites before labeling each command a small test. |

Reference code:
[task inventory](../../scripts/zeroization/miri_tasks.py),
[matrix registry](../../scripts/zeroization/miri_cases.py),
[streamed KMAC setup](../../crates/brynja-mac-kmac/src/setup/tests.rs),
[TupleHash XOF scenarios](../../crates/brynja-hash-tuple/src/hardened_in_place/xof/tests.rs),
[ParallelHash scoped cases](../../crates/brynja-hash-parallel/src/hardened_in_place/tests.rs).

## Implementation order

1. **Visibility and safe individual refresh:** terminal dashboard over the real
   inventory; explicit task IDs, last attempt, partial/failure states, duration,
   exact command and saved receipt import. Keep diagnostic observations separate
   from release evidence. Initial implementation is in
   [the dashboard guide](test-dashboard.md).
2. **Remove hidden bundles:** discover/assign the remaining broad KMAC tests,
   including setup and verification, to exact runnable tests. Split independent
   length/chunk/strength/fixed-XOF scenarios. Assert complete disjoint coverage,
   nonzero exact test execution and rejection of unknown/out-of-range selectors.
   Preserve ordinary native all-case tests and all existing assertions.
3. **Separate expensive scenarios:** split independent TupleHash output modes
   and widths, and ParallelHash public/secret/cancellation paths where each can
   retain complete lifecycle checks. Keep coordination/unwind/worker scenarios
   intact when splitting would remove the interaction under test. Do not claim
   a scenario is small just because only one `#[test]` runs.
4. **Bound the remaining workload honestly:** routine Miri already has bounded
   boundary/lifecycle sampling. Keep exhaustive correctness combinations in
   native tests; any change to extended coverage needs an explicit reviewed
   coverage decision, not silently reducing inputs under the same task ID.
   Measure representative new tasks before scheduling another campaign. Aim
   for minutes rather than hours per independently resumable task; this is a
   design target, not a measured performance guarantee.
5. **Interruption-tolerant scheduling:** only after the above, pilot Spot using
   durable off-host per-task records and explicit interruption recovery. The
   current resume validator requires a terminal job record; sudden host loss
   must not be treated as a gracefully completed checkpoint. Test that case
   before relying on Spot, and keep provisioning/cost authorization separate.

## Implemented first decomposition (2026-10-29)

- Streamed KMAC setup now has 100 exact cases: five key/customization length
  pairs × five chunk sizes × two strengths × fixed/XOF. Both profiles retain
  all 100; no inputs or assertions were removed. Three portable/scoped
  verification integration tests also have exact standalone commands.
- Extended scoped TupleHash comparisons now select each of five output widths
  separately. The complete extended case/width product remains present, with
  distinct completion markers and dashboard identities. Routine sampling is
  unchanged. Each case retains all of its public/secret/streaming interactions.
- Four fixed/XOF ParallelHash lifecycle entry points can run independently.
  Native cross-matrix reuse and the original Miri case-zero ordering remain
  intact; the extra standalone tasks do not replace these interactions.
  The owner subsequently approved bounded Miri plus exhaustive native tests.
  The checkpoint now selects the existing routine ParallelHash boundary/sample
  cases, including bounded input lengths, while retaining every registered
  fault, worker join, ordering and lifecycle scenario. Each selected matrix
  task is explicitly identified as `bounded-parallelhash-v1`; this is not an
  exhaustive interpreted combination claim.
- Native tests ignore interpreter selectors and still traverse their full
  matrices. Regressions check unique complete case/width populations, invalid
  selectors, completion accounting and separation from historical task IDs.

The current inventory has 697 routine and 4,125 checkpoint/extended commands
(formerly 590 and 4,122). ParallelHash now has 173 work items in either profile,
instead of 1,105 old extended items. New KMAC/TupleHash splits increase their
task counts. Counts alone do not measure aggregate cost. Historical receipts
keep their original populations and original unbounded inputs.
No historical pass has been relabeled as a redesigned test or a full campaign
pass; formal carry-forward still needs validation before scheduling.

## Saved-result comparison after decomposition (2026-10-29)

The trusted historical reader revalidated both receipts listed above after the
task changes: 1,468 and 1,494 individual passes, respectively. The comparison
then resolved each old ordinal using its hash-bound historical catalog and
compared full task definitions with the current extended catalog. Matching
ordinal numbers alone were not treated as matching tests. This was a read-only
comparison: it neither launched tests nor updated pass/approval records.

| Family | Current tasks | Same definition as a saved passing task | No same-definition pass in these two jobs |
| --- | ---: | ---: | ---: |
| MD5 | 940 | 940 | 0 |
| SHA-1 | 683 | 683 | 0 |
| SHA-2 | 26 | 26 | 0 |
| SHA-3 | 133 | 133 | 0 |
| KMAC | 164 | 58 | 106 |
| TupleHash | 1,967 | 925 | 1,042 |
| ParallelHash | 173 | 0 | 173 |
| Other registered families | 39 | 2 | 37 |
| **Total** | **4,125** | **2,767** | **1,358** |

The 195 remaining historical passes refer to definitions absent from today's
catalog. They remain preserved, not discarded or relabeled. The new bounded
ParallelHash definitions deliberately do not inherit the old unbounded IDs.
Likewise, the new KMAC setup and TupleHash width splits need a separate coverage
comparison before an old combined test could support them.

**These are definition matches, not a release reuse decision or a rerun list.**
The comparison does not establish compatibility of current source, dependencies
or tools. It also excludes other saved campaigns and new local diagnostic
smoke runs. The next reconciliation step must check that compatibility and any
proposed old-suite-to-new-task coverage, with regressions rejecting mismatched
selectors or changed assertions. Only then can the remaining execution list be
determined; there is no reason here to automatically restart all 4,125 tasks.

## Unchanged-family reuse proof (2026-10-29)

The carry-forward and interrupted-job recovery paths now resolve each Miri
ordinal against its own snapshot's reviewed catalog **before** comparing
coverage. Identical command text is insufficient: the same task number can
select another test after a split. Moved tasks can match only if their complete
definitions match, including profile, features, selectors, output-width index,
completion marker and bounded-coverage label. Whole-suite-to-new-subset reuse
is not inferred by this rule. Original receipt/index/log provenance is retained.

An exact raw-byte review binds the three 2026-10-29 Miri runner/catalog changes.
Only for that change pair, the ordinary source-scope validator can classify the
remaining delta without those three files forcing every Miri family to rerun.
Unknown runner edits, altered line endings, build/graph uncertainty and ambient
compiler overrides do not qualify. Changed Rust tests still invalidate their
family and downstream consumers; this is not an exemption for test directories.
Tool compatibility, new full-checkpoint boundaries and run approval remain
separate requirements. The normal planner is unchanged and no new run is
automatically approved by this proof.

Using the two validated interrupted receipts above, the current source proof
and selected-tool compatibility check identify these eligible saved passes:

| Family | Eligible exact-definition passes |
| --- | ---: |
| MD5 | 940 |
| SHA-1 | 683 |
| SHA-2 | 26 |
| SHA-3 | 133 |
| Core / sanitization | 2 |
| **Total** | **1,784** |

The other 2,341 current tasks are **not yet covered by this proof**, not an
instruction to rerun all of them. Further scoped analysis can consider KMAC and
TupleHash splits; new bounded ParallelHash cases are not automatically credited
from old longer runs. This comparison does not create a completed receipt,
change dashboard observations, or make the release ready.

Before constructing an interrupted-job recovery on another machine, its recorded
tool inventory must also satisfy the recovery validator. That path retains its
stricter complete-inventory equality check; the read-only candidate count above
uses the existing phase validator's selected-tool compatibility check. Matching
selected tools is not permission to fabricate a historical host inventory.

## Reviewed split coverage (2026-10-29)

The follow-up comparison validates both interrupted receipts again and adds
two narrowly reviewed coverage mappings:

- A completed old KMAC default test suite covers the 100 newly separated setup
  scenarios and the three unchanged verification-error tests. A passing line
  inside a cancelled or failed command is **not** sufficient.
- Each completed old TupleHash input case covers its five separate output-width
  tasks. The input, strength, fixed/XOF route and width selection must match.
  A single new width does not cover the old combined case in reverse.

Both mappings require exact raw-byte hashes of the old and new runner/catalog,
the edited test helper and its supporting test source. The ordinary source and
dependency checks must also allow the family. Unknown assertions, features,
selectors, markers, upstream changes or compiler-policy changes reject reuse.
This is a review of these specific splits, not a generic rule that a large test
always covers a smaller one. Broad suites remain pending because this mapping
does not prove their entire populations, including newly added regressions.
ParallelHash's new bounded tasks do not inherit old exhaustive passes.

The two receipts contain 1,468 and 1,494 completed command passes. Against the
4,125-task extended catalog, the source/coverage comparison and selected-tool
check identify **3,796 eligible tasks**: 2,763 exact-definition matches and
1,033 reviewed subsets of successful old commands.

| Family | Eligible current tasks | Not covered by these receipts and this proof |
| --- | ---: | ---: |
| MD5 | 940 | 0 |
| SHA-1 | 683 | 0 |
| SHA-2 | 26 | 0 |
| SHA-3 | 133 | 0 |
| Core / sanitization | 2 | 0 |
| KMAC | 161 | 3 |
| TupleHash | 1,851 | 116 |
| ParallelHash | 0 | 173 |
| HMAC / legacy HMAC | 0 | 28 |
| Acceleration / static CPU / legacy | 0 | 9 |
| **Total** | **3,796** | **329** |

The larger eligible-task count does not mean more tests were executed. One old
completed matrix can support several new constituent tasks. Recovery references
retain the original receipt, command index and log digest and label that result
`reused`, not a fresh execution. Regression tests cover this expansion and reject
missing successful records, altered inputs and unsupported mappings.

**This remains a read-only eligibility result, not a completed recovery job or
release PASS.** No historical receipt, dashboard observation or approval was
rewritten. The recovery tool-inventory constraint described above still needs
to be satisfied before constructing a new job. The 329 remaining tasks are not
an automatic run authorization; other saved evidence and current baseline
requirements must be reconciled before scheduling the remaining work.

## Measured bounded smoke checks

Bounded local Miri smoke checks on `nightly-2026-09-11` passed for these selected
tasks. These are author-operated diagnostic timings, not release receipts or
predictions for the entire population. Values use runner wall time, not Miri's
simulated test-harness clock:

| Selected scenario | Wall time |
| --- | --- |
| KMAC streamed setup case 0 (256-bit key, empty customization, one-bit chunks, fixed 128) | 45.2 s |
| KMAC streamed setup case 80 (8193-bit key, 8201-bit customization, one-bit chunks, fixed 128) | 210.7 s |
| TupleHash XOF-128 input case 0, output-width index 1 | 32.4 s |
| ParallelHash-128 fixed independent lifecycle | 65.7 s |
| ParallelHash-128 fixed bounded B=1/tail=1 case, including public/secret reuse and the original case-zero lifecycle sequence | 157.6 s |

The TupleHash sample was also launched through the dashboard after the code
settled and recorded a passing local diagnostic run (31 s) in
`../brynja-evidence/dashboard/`. Direct smoke commands above are not imported
as detached release evidence.

These checks do not establish a maximum task duration. The old exhaustive B=1
ParallelHash input hashed hundreds of small leaves. The approved bounded
selection reduces interpreted combinations and lengths, not native coverage;
reference/public/secret computations remain together on the same workspace.
The trusted reader recognizes the exact old catalog digest and reconstructs its
old commands without executing archived Python. Unknown historical catalogs are
rejected rather than interpreting their ordinal IDs through the current list.
Remaining work is to validate formal reuse against the final test revision and
schedule only required work. Spot interruption recovery remains planned.

## Acceptance boundaries

- No hidden full sweep from browsing or launching one task.
- Stable IDs reflect semantic command/case identity, not mutable list position.
- A failure/timeout is visible even when an older run passed; missing work is
  never inferred successful from another task's progress output.
- Logs/results survive `cargo clean`; hashes and source/tool provenance remain
  available. Cancellation and corruption have explicit regressions.
- Preserve source/native tests, safety flags, zeroization assertions, negative
  cases and quarantine/error behavior. No blanket ignores, fabricated markers,
  weakened sanitizer settings or "all green" claims based on a partial catalog.
