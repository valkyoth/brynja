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
