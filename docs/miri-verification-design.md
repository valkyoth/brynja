# Bounded and resumable Miri verification

Status: implementation approved by the owner, 2026-09-27; **partially implemented**.
This work neither qualifies v0.24.49 nor authorizes a tag. New runs select a
routine profile for internal releases and an extended profile for public
checkpoints. Miri safety settings remain enabled. Wider timing and remote
qualification remain outstanding; this is not a claim of a short full sweep.

## Implementation progress

The first stage adds streamed logs, command-level Miri scheduling with shared
per-shard build/sysroot caches, a nonzero-test completion check, schema-2
post-command source/tool checks, immutable resume into a new job, and partial
partition collection. It leaves the reviewed legacy Miri driver byte-for-byte
unchanged. See [operator instructions](detached-verification.md).

The case-splitting stage covers six families, including seven TupleHash matrices and six
ParallelHash fixed/XOF/scheduled matrices. For the initial staging/scoped matrices,
routine Miri selects 16 TupleHash cases and 48 ParallelHash cases; extended Miri
addresses all 896 and 240 original combinations respectively. Additional splits
are described below. Each case has an exact completion marker and must
run exactly one test. Native tests ignore the Miri selectors and retain all
original combinations and input lengths. ParallelHash routine inputs use at
most `2*B+1` bytes, retaining leaf transitions without hundreds of tiny leaves.
Matrix-independent fixed/XOF lifecycle checks run on case zero of each identity,
not repeatedly in every case. Scheduled lifecycle tests stay separate.

SHA-1 and MD5 each split padding lengths, bulk-update lengths and scoped-owner
combinations into separate tasks. Routine coverage retains padding/block edges,
all chunk widths and all final-bit widths, using 47 tasks per family instead of
675. KMAC framing is split by initial bit residue into eight tasks: routine
checks six representative byte values at every final-bit width (432 total
combinations); extended and native tests retain all 256 values (18,432 total).
SHA-3 hardened integration splits fixed-output rate boundaries, fixed-output
partial bits and secret-XOF partial bits into 59 routine / 107 extended cases.
Routine rate coverage uses each identity's own rate-1/rate/rate+1 plus empty,
one-byte and 339-byte multiblock messages. Every original partial-bit combination
remains selected in both profiles, including both XOF identities and clearing.
KMAC scoped fixed/XOF lifecycle tests run as 18/16 separate cases in both
profiles: cancellation, forgotten owners, unwind, invalid outputs and tag
comparison assertions remain intact. ParallelHash's scoped leaf differential
matrix runs as nine routine cases covering every original length and tail width,
or all 65 extended cases; each case checks both strengths and output clearing.
Conformance-only KMAC campaigns are unchanged and remain in native testing.
ParallelHash's buffering/final-tail differential matrix uses 16 routine cases
covering both strengths, every block size, input-length class and tail width;
extended/native retain all 672 combinations. Every selected case retains both
fixed/XOF framing checks, streamed updates and workspace/output clearing.
Scheduled-owner lifecycle checks run as 11 cases per strength, retaining every
wrong-plan/order, duplicate-leaf, incomplete-root, cancellation/forgotten-owner,
invalid-output and empty-output case in both profiles. All six official KMAC
and six KMACXOF vectors also run individually in both profiles, preserving both
ordinary and scoped-secret comparisons and destination clearing. All 12 official
ParallelHash/ParallelHashXOF vectors likewise retain their complete native
checks and run as separate cases in both profiles. Scheduled integration unwind
and reuse tests run as four cases per strength: collector unwind, reader unwind,
forgotten reader, and out-of-order computation with ordered merging. Every
unwind/forgotten-reader case retains comparison of the reused and fresh owners.
The execution-stream comparison has 16 routine cases covering both strengths,
all three block sizes and every final-bit width; extended/native retain all 48
combinations, with the same streamed/planned comparisons and cleanup assertions.
Hosted workers retain all 27 domain/output, spawn-failure, panic, cancellation,
output-slot and reversed-completion scenarios in both profiles. Each scenario
still runs its original cooperating threads, join checks and cleanup assertions.
TupleHash execution comparisons now run as 16 fixed-output cases (both strengths
and all eight final-bit widths) and two XOF cases. Both profiles retain every
case, including the original 1,025-byte fixed input, 340-byte XOF input, mixed
secret/public reads, terminal-state assertions and destination clearing.
The four scoped TupleHash/TupleHashXOF matrices use input-length/tail chunks.
Routine selects eight cases per identity and cycles output widths, covering empty,
one-byte, rate-1/rate/rate+1, multirate input, all tail widths and all five output
width classes without their Cartesian product. Extended/native retain all five
widths per chunk and cross-width workspace reuse: all 208 chunks
(1,040 combinations), including the fixed-output 1,024-byte input class; the
routine execution matrices separately retain their 1,025-byte messages.

The other 83 original Cargo invocations remain selected, excluding only those
forty-two registered matrices now run separately. Thus a complete all-family
routine catalog has 542 tasks (431 case/chunk tasks) and extended has 3,838
(3,727 case/chunk tasks). Nine existing SHA-3 lifecycle tests, four KMAC API
tests and six ParallelHash API tests additionally run as separate exact tests,
with inputs/assertions unchanged. Four TupleHash scoped lifecycle tests and five
TupleHash API tests also run separately, without sampling or changed assertions.
The original invocations keep the SHA-3 empty-owner and KMAC secret-output tests
and the ParallelHash zero-block test, and discover future tests;
only explicitly rescheduled tests are skipped there.
Each selected case starts a fresh interpreted test; native matrices retain their
original cross-case workspace-reuse sequences as well as every input combination.
Remaining grouped selections, including SHA-2/SHA-3,
have not yet been fully timed. Broad legacy selections still discover new
tests; a future complete per-test obligation inventory remains outstanding.
Legacy schema-1 partial evidence is not imported or marked successful.

Local diagnostics with the pinned interpreter passed TupleHash routine cases
in 24.1, 24.8 and 50.5 host seconds, a ParallelHash fixed case including lifecycle
checks in 169.4 seconds, an XOF case in 141.3 seconds, and a scheduled case in
192.2 seconds. The scheduled case exceeded the initial 180-second diagnostic
cap, then passed under a separately recorded 300-second cap. Full native matrices
also passed with deliberately invalid
Miri selectors in the environment. An XOF diagnostic hit its 240-second limit
before reliable interpreted-environment selectors were added; that attempt is
incomplete evidence. Cargo-Miri can cache a compiler launch environment, so
`option_env!` selectors were replaced by explicit `-Zmiri-env-set` inputs.
Additional routine probes passed KMAC framing in 1.9 seconds, SHA-1 bulk updates
in 11.0 seconds, MD5 padding in 1.5 seconds, and SHA-1/MD5 scoped-owner cases in
3.2/1.5 seconds. These measurements are not a full-suite ETA or release receipt.

Focused validation also passed 80 runner/profile/checkpoint regressions, 51
assurance tests, both crates' 92 all-feature library tests on Rust 1.98.1 and
62 hardened-execution library tests on Rust 1.90.0. Native tests with hostile
Miri selectors, scoped Clippy, formatting, scope/policy mutations, review
bindings, generated assurance evidence and documentation links passed. Two
successive interpreted TupleHash selections emitted distinct expected markers
while reusing the same Cargo cache. Historical native observations are unchanged;
rebinding a test review hash is not a claim those native lanes reran.
The additional SHA-1/MD5/KMAC native library run passed all 48 tests with invalid
Miri selectors in its environment, all 48 on Rust 1.90.0, and 106 all-feature
library tests on Rust 1.98.1. An extended KMAC chunk passed all 2,304 original
combinations for its bit residue in 26.6 host seconds. Their source/package policy checks and the
combined metadata regression suite also passed after refreshing test-source
review bindings; production implementation code was not changed.

The planner classifies the three new Miri-only task files separately from
ASan/Kani inputs. Editing those files still selects Miri conservatively and
requires full-fallback approval, but does not itself invalidate unrelated
ASan/Kani work. Real-Git regression fixtures confirm that unknown scripts and
concurrent Rust implementation edits remain in scope. No directory-wide
exemption was introduced.
The resulting full-phase selection is bound into the plan and honored by both
foreground and detached execution and evidence reuse. Approval alone no longer
expands an unrelated verifier's selection. Historical plans without per-phase
scope retain their old conservative full-run interpretation.

A further SHA-3 execution probe passed all eight selected tests in 8.2 host
seconds. Combined SHA-3 hardened integration probes hit their 180-second caps
before the matrices and lifecycle tests were fully separated. Those attempts
remain incomplete evidence, not passes. On the final split, representative
rate-boundary, fixed partial-bit and secret-XOF cases passed in 30.2, 6.5 and
12.6 seconds; an extended-only boundary case passed in 6.7 seconds. The remaining
broad invocation passed its empty-owner test in 6.5 seconds. All 13 native
integration tests passed with hostile selectors, on Rust 1.90.0, and with all
features; scoped strict Clippy and refreshed review/metadata checks also passed.
All nine separated lifecycle tests passed under Miri individually, ranging from
0.6 to 36.2 host seconds. Together with the three matrix probes, extended-only
probe and remaining broad invocation, these are 14 successful diagnostic tasks,
not a complete SHA-3 extended campaign or release receipt.

The next KMAC/ParallelHash decomposition passed representative KMAC comparison,
forgotten-owner/unwind and XOF-output tasks in 91.0, 21.7 and 42.6 host seconds,
and the longest scoped-leaf input case in 35.5 seconds. All 95 all-feature native
library tests passed on both Rust 1.90.0 and 1.98.1; 45 default-feature tests
passed with hostile Miri selectors. Scoped Clippy, 82 detached-runner tests,
planner tests and source/metadata regression checks passed. These measurements
cover the new splits, not every remaining grouped invocation.

Buffering follow-up: all four separated KMAC API tasks passed (32.2–81.9 host
seconds), retaining their original test bodies. A representative buffering case
passed on the final helper in 171.3 host seconds. ParallelHash's moved test helper
preserves every native input and both fixed/XOF comparisons; the production
prefix of `core_state.rs` is byte-identical. All 108 affected all-feature library
and API tests passed on Rust 1.90.0 and 1.98.1, along with Clippy, 84 runner
regressions, 51 assurance tests and source/review-metadata checks. A residual
ParallelHash grouped probe reached scheduled-owner lifecycle tests but hit its
180-second diagnostic cap; it is incomplete evidence, not a pass. Further
grouped timing and remote split/resume qualification remain outstanding.

Scheduled/vector follow-up: four final scheduled-owner lifecycle probes passed
in 11.3–32.7 host seconds, including duplicate-leaf rejection, forgotten XOF
ownership, invalid output and empty output. Representative long KMAC/KMACXOF
official vectors passed in 47.5/43.5 seconds; an extended short KMAC vector
passed in 32.4 seconds. All six separately scheduled ParallelHash API tests
passed in 11.2–161.1 seconds, and its representative fixed/XOF official vectors
passed in 55.8/53.8 seconds. Expected NIST digests are unchanged. The remaining
KMAC grouped invocation passed all 19 selected tests in 101.2 seconds.
The residual ParallelHash grouped probe reached the integration scheduled-unwind
test but hit its 300-second diagnostic limit; that attempt remains incomplete,
not a successful receipt. Its unwind/reuse scenarios are now separately selected
without reducing their original inputs or comparisons.
Native all-feature library/vector checks passed all 99 tests on both Rust
1.90.0 and 1.98.1, including the complete vectors and lifecycle matrices.
Hostile-selector checks, strict scoped Clippy, no-default-feature compilation,
86 runner regressions, scope/metadata policies and 51 assurance tests passed.
A local overhead diagnostic measured source hashing (2,945 files) at
0.27 seconds, tool identity at 1.83 seconds and planning at 0.17 seconds.
Per-command source/tool seals deliberately remain in place; many tiny tasks
therefore have measurable bookkeeping overhead as well as interpreter work.

Scheduled-unwind follow-up: all eight integration cases passed under the pinned
Miri in 21.8–120.2 host seconds each. Both strengths retain collector unwind,
reader unwind, forgotten-reader cleanup, reuse-versus-fresh comparisons and
ordered merging after out-of-order computation. Full ParallelHash all-feature
tests/doctests passed all 350 checks on each of Rust 1.90.0 and 1.98.1. Native
hostile-selector tests, scoped Clippy, 87 runner regressions, 51 assurance tests,
planner, scope and review-binding regressions also passed. These diagnostics
are not a completed all-family verification receipt. After this split the
remaining broad ParallelHash `--tests` command passed its 15 retained tests in
59.5 host seconds, under the same 300-second cap that previously expired.

Execution-stream follow-up: the remaining streaming-failure and collector
integration groups passed four tests each in 65.7 and 81.3 host seconds. The
library group hit its 180-second cap in the 48-case streamed/planned comparison.
After splitting that matrix, four routine cases spanning both strengths and
single/multiple leaves passed in 43.6–75.8 seconds, and an extended-only case
passed in 65.0 seconds. All original inputs, comparisons and clearing assertions
remain intact. The residual library invocation passed all 11 retained tests in
115.7 host seconds. Full native ParallelHash tests/doctests passed 350 checks on each
of Rust 1.90.0 and 1.98.1; hostile-selector tests, scoped Clippy, 88 runner
regressions, 51 assurance tests and source/scope/review-metadata checks passed.
The hosted-worker library group also hit its 180-second cap in
`scoped_execution_fixed_xof_domains_and_zero_output`; that attempt remains
incomplete. Neither timeout is a pass.

Hosted-worker follow-up: all 27 separately selected scenarios passed under the
pinned Miri in 5.9–66.3 host seconds each. The residual grouped command passed
its seven retained tests in 2.7 seconds. Splits retain the original worker counts,
channel handshakes, join assertions, output clearing and serial comparisons;
there is no sampling of these scenarios. A test-only case-accounting helper
rejects missing, duplicate and unexecuted work. The complete hosted native
tests/doctests passed 105 checks on each of Rust 1.90.0 and 1.98.1, including
hostile-selector coverage; scoped Clippy, 90 runner regressions, 51 assurance
tests and review/scope policies passed. These are diagnostic observations, not
a combined all-family release receipt.

TupleHash execution follow-up: the unsplit execution and scoped-owner groups
each exceeded a 180-second diagnostic cap. After splitting the execution
comparisons, fixed cases 0, 7, 8 and 15 passed in 133–159 host seconds apiece,
retaining both strengths and the 1/8-bit boundaries on the full input sizes.
Both XOF cases passed in 95–97 seconds; the residual execution group passed all
four lifecycle/error tests in 97.4 seconds.
Native tests/doctests passed on Rust 1.90.0 and 1.98.1 (including hostile-selector
coverage), as did scoped Clippy, packaged debug/release and mutation testing,
91 runner regressions and 51 assurance tests. At that stage the scoped-owner
group still needed decomposition; these diagnostics are not a release receipt.

Scoped TupleHash follow-up: initial five-width chunks passed in 360–381 host
seconds, motivating the dimension-covering routine sample described above.
Final largest-output probes for all four identities passed in 84–86 seconds;
empty-input probes passed in 34–36 seconds. Empty inputs require nonempty output
in the sample, so their selected bit width is actually exercised. The residual
group passed its 15 retained tests in 315 seconds. Native tests/doctests passed
255 checks per compiler on Rust 1.90.0 and 1.98.1, including hostile-selector
coverage; scoped Clippy, 93 runner regressions and review-metadata checks passed.
The new accounting regression also rejects missing/duplicate widths and overflow;
packaged mutation controls now require the resulting 16 tests rather than 15.
All four separately scheduled lifecycle tests passed in 153–170 seconds without
changing their cancellation, forgotten-owner, invalid-output or unwind checks.
All five separately scheduled API tests passed in 6–54 seconds. The final focused
run passed all 15 selected matrix/lifecycle/API probes; the other routine cases
still require their complete campaign before qualification.
These remain focused diagnostics, not a completed all-family qualification.

Unchanged-group follow-up on source `091ad3eb` (2026-09-27): all nine selected
routine tasks passed, covering 49 tests without changing inputs, assertions,
production code or scheduling rules. Commands used the pinned runner, one
interpreter at a time, with existing local build caches. Durations below are
host-clock seconds from `MIRI_TASK_PASS`, not libtest's interpreted clock.

| Group/task | Coverage retained | Tests passed | Host seconds |
| --- | --- | ---: | ---: |
| SHA-2 / 19 | All ordinary hardened identities, padding, bit tails, output failure and unwind | 8 | 42.9 |
| SHA-2 / 11 | General SHA-512/t downstream fixture | 5 | 52.5 |
| SHA-2 / 12 | General SHA-512/t dynamic lifecycle | 3 | 15.2 |
| SHA-3 / 15 | Residual hardened integration selection | 1 | 6.1 |
| SHA-3 / 14 | Curated NIST bit vectors | 1 | 47.0 |
| SHA-3 / 16 | Official cSHAKE examples | 1 | 5.8 |
| KMAC / 0 | Residual broad test selection | 19 | 104.0 |
| KMAC / 1 | Internal execution cleanup/error tests | 4 | 125.9 |
| KMAC / 2 | Public execution, verification, reader and unwind tests | 7 | 288.2 |

The KMAC public group exceeds the usual three-minute sizing goal, but completed
within the six-minute diagnostic cap; it remains intact rather than introducing
another split without a demonstrated timeout. The SHA-2 hardened group needs no
split based on this observation. All three residual KMAC commands are now timed,
but this is not completion of KMAC's separately registered case tasks or the
all-family campaign. The 93 detached-runner regressions, incremental planner,
current acceptance review bindings, generated assurance and Miri scope checks
also passed. No timeout or partial result was counted as success. These logs are
development diagnostics, not immutable detached receipts or native qualification.

Capacity observation: the current complete internal routine catalog has 1,089
commands including non-Miri phases, and has a regression check against the
existing 4,096-command bound. The combined public/extended catalog has 4,385
commands and exceeds that bound (Miri alone has 3,838). This capacity issue must
be resolved before a combined public sweep; no bound or evidence requirement
has been changed by these test splits.

## Recommendation

Use bounded, affected-family memory-safety tests for routine internal work.
Keep wide input/seed campaigns for explicit qualification checkpoints and
scheduled remote campaigns. Preserve exhaustive native cryptographic tests.
Make every completed verification task independently collectible, so a timeout
or shutdown loses only the interrupted task, not unrelated successful work.

Two decisions must remain separate:

- Splitting the same cases across processes/machines changes orchestration.
  With equivalent inputs and complete coverage it need not reduce evidence.
- Running a smaller Miri input set on an internal tag changes assurance scope.
  It requires explicit policy approval and an honest statement of that scope.
  Keeping the larger set for a later checkpoint is not evidence it passed now.

Pre-1.0/internal status supports a proportionate qualification schedule; it
does not excuse a known correctness or memory-safety defect. Native tests,
sanitizers, proofs and Miri provide complementary, not interchangeable evidence.

## What happened in v0.24.49

The cancelled job at commit `b154b38ce119ef032e481ec997cbe24f70450bd0`
preserves 553 passed command records, two cancelled commands and 15 unstarted
commands. It ran about 9h24m. Its receipt is
`0557f42349db6fc5c359b67b70ffc0bfe7f9ef31df0773f588b9a4947691993c`.
It remains cancelled, not a successful release receipt.

The Miri driver itself did not change from v0.24.48. Broad selections such as
`--lib execution` and `--tests` automatically included new tests:

- TupleHash added 896 combinations (strength, initial bit residue, final bit
  width and message length), exercising three hashing paths per combination.
- ParallelHash added scoped fixed/XOF/scheduled comparisons. Small block sizes
  multiply leaf hashing: a 177-byte message at B=1 needs 177 full-byte leaves,
  plus its final tail, for each compared path.
- The old `detached_process.py` buffered log writes until its buffer filled or the command
  finishes. The file timestamp is not a progress indicator.
- The old `detached_catalog.py` partitioned whole family commands, not cases
  inside them. Collection accepted only wholly successful terminal jobs.

Isolated diagnostics on 2026-09-26, using the same pinned nightly and temporary
test-only instrumentation, measured eight TupleHash cases passing in 265 seconds,
one B=168 ParallelHash comparison passing in 79 seconds, and a single-leaf test
passing in 6.5 seconds including startup. The B=1 comparison was unfinished when
the diagnostic's per-command limit expired. These are diagnostic observations,
not release evidence or a reliable full-suite ETA. They support excessive work
as an explanation; they do not prove the cancelled workers were making progress.

Other completed family timings were approximately KMAC 38 minutes, SHA-1 33,
MD5 25, SHA-3 21 and SHA-2 6. The redesign must review all families, not just the
two cancelled commands. Measurements are machine-specific.

## Upstream findings and limits

Miri checks particular executions, not cryptographic correctness or universal
soundness. It supports progress stack traces via `-Zmiri-report-progress`.
`-Zmiri-num-cpus` changes the emulated CPU count, not interpreter parallelism.
Multiple seeds add executions, not a shortcut for finishing one execution.
See the [official Miri documentation](https://github.com/rust-lang/miri).

Nextest runs separate Miri processes concurrently, but cannot detect races
between tests sharing one process and does not support Miri build archives.
Retain deliberate shared-process concurrency checks and separate doctests.
See the [official Nextest integration guide](https://nexte.st/docs/integrations/miri/).

Per-test invocation recompiles test crates; upstream records workloads where
that overhead dominates. Benchmark before adopting Nextest globally. See
[Miri issue 5013](https://github.com/rust-lang/miri/issues/5013).

Miri defaults to unoptimized MIR for validation. A release build is not an
automatic native-speed solution. Do not change MIR optimization or substitute
native/FFI execution just to make the checker faster. See
[Miri's default compiler arguments](https://github.com/rust-lang/miri/blob/master/src/lib.rs).

Local compatibility check: the installed Miri is
`0.1.0 (67eda617e6 2026-09-10)`, pinned by `nightly-2026-09-11`.
Its command parser accepted `-Zmiri-report-progress=1000000` with `--version`.
Actual progress output was subsequently observed in bounded execution probes
using `-Zmiri-report-progress=10000000`. Wider overhead and remote integrations
still need measurement. Upstream master documentation is not a promise
that every option works with our frozen version.

## Execution profiles and remaining target coverage

| Situation | Required Miri work | Other coverage |
| --- | --- | --- |
| Documentation/version/review metadata only | Reuse eligible unchanged tasks | Current repository, documentation and release checks |
| Internal implementation tag | Bounded lifecycle/boundary tasks for affected families and consumers | Native vectors, differential tests, applicable sanitizers/proofs/codegen |
| Memory-ownership/unsafe/concurrency fix | Bounded tasks plus the explicit bug regression and affected safety obligations | Relevant native instruction/platform and failure-path qualification |
| Registered publication checkpoint, RC or 1.0 | All-family bounded profile plus registered extended cases/targets/seeds | Existing publication requirements |
| Owner-requested assurance campaign | Explicit extended task set, normally remote | Report exact coverage; never imply certification |

Reuse the existing checkpoint register; do not introduce a second release
calendar. Unknown scope still requires review before expensive work, not an
automatic success or an unannounced day-long run. A scheduled campaign with a
confirmed defect blocks affected releases; a timeout is incomplete evidence,
not a defect and not a pass.

An internal release summary must distinguish bounded coverage passed, extended
coverage carried forward from a named snapshot, and extended coverage deferred
under the approved profile. Public checkpoint completeness is not satisfied by
an internal-profile receipt. The runner enforces routine/extended separation;
additional targets/seeds and all-family bounded sizing remain follow-up work.

## Write tests around safety obligations

Maintain one small case/task catalog, organized by family and safety obligation.
Every relevant new test must be classified; no accidental inclusion through
an ever-growing `--tests` invocation and no silent omission of new owners.
Required obligations include initialization, boundary access, partial bits,
overlap/borrowing, state transitions, overflow, output failure/clearing,
cancellation, Drop/unwind and worker ownership/join behavior where applicable.

Use the real public API and actual memory-handling path. Keep production code
unchanged. Do not replace the tested primitive with a no-op under `cfg(miri)`.
Existing Miri-specific safe models must be labelled as models, not machine-code
or register-erasure evidence. The SHA-3 hardened permutation already chooses a
safe model for Miri; native assembly, codegen and platform evidence remain needed.

Concrete test refactoring:

1. Extract reusable case helpers. Give each case or bounded case range a stable
   ID. Native exhaustive tests continue traversing the original complete matrix.
2. TupleHash: routine cases cover both strengths, all bit residues, short input,
   rate-boundary staging and reuse/cleanup without taking the full Cartesian
   product. Keep every original combination addressable in the extended profile.
3. ParallelHash: test B=1 lifecycle with only enough bytes for a few leaves.
   Test long/rate-crossing input with larger B separately. Retain actual root
   merging, public/secret output, cancellation and forgotten-owner checks.
   Do not shorten concurrency tests below the point where workers interact.
4. Avoid interpreting two reference hashes merely to check the third path's
   memory use. Where appropriate, use pinned expected bytes generated and
   cross-checked independently in native tests; still assert outputs under Miri.
   Native tests must validate fixture contents, not regenerate expectations from
   the same implementation during the Miri run.
5. Test huge counter boundaries by controlled internal state setup, not billions
   of updates. Retain small real transitions before/after the boundary.
6. Split extended loops into balanced chunks before adding machines. Case IDs,
   seed ranges and the union of chunks must prove no gaps or duplicate counting.

This preserves the full native and extended input sets, but deliberately narrows
routine Miri combinations. Review the obligation-to-case mapping and mutation
tests before accepting that trade-off. Pairwise/boundary selection is not a proof
that all omitted combinations are equivalent.

Never speed qualification up by disabling aliasing, data-race, alignment,
validity, weak-memory or leak checks. Do not switch borrow models or upgrade
the nightly implicitly. Benchmark any checker/configuration change separately.

## Parallelism, caching and observability

Start with existing Cargo/Miri commands in separate bounded processes; this
avoids an immediate new tool dependency. Benchmark pinned Nextest for expensive,
independent tests as an optional executor, not an evidence collector replacement.
Keep shared-process tests for shared-state interactions and existing doctests.

Suggested initial capacity: two Linux x86-64 hosts, two interpreter workers per
host. Increase only after measuring compile memory and throughput. Extra workers
do not split an inner loop automatically. Bind host and interpreted target
identities separately; native evidence cannot be substituted by interpretation.

Prepare a validated Miri sysroot once per pinned toolchain/target. Retain bounded
per-worker build caches, segregated by source, features and compiler settings.
Never share a mutable Cargo target directory across concurrent workers. Compile
caches are disposable performance aids, not evidence. Keep receipts and logs
outside Cargo target directories so `cargo clean` cannot erase them.

Flush incremental output at a bounded interval (for example one second); fsync
terminal records. Emit host-clock start/end times, task/case IDs and periodic
bounded progress reports, without secret bytes. Heartbeats show runner liveness;
case-completion records show work completed. Distinguish them in status output.
Use host monotonic timing, not the interpreted test harness's simulated duration.

Initial engineering targets, to be measured rather than advertised as promises:
routine tasks usually 30 seconds to 3 minutes; extended chunks usually under
10 minutes; ordinary affected-family verification around 15–30 minutes on the
reference worker allocation. Longer safety obligations receive explicit budgets.
Exceeding a budget reports timeout/needs-sizing; it never downgrades coverage or
marks work passed. Estimate remaining work from measured durations, with an
unknown category for unmeasured tasks. No credible ETA means say so.

## Independently collectible tasks

Extend the existing manifest/runner/collector rather than adding a cloud service
or changing cryptographic publication rules. SSH is transport; no credentials
belong in archives. A campaign freezes its complete required task set first.
Workers execute assigned tasks; collection validates their union.

Each task identity binds its test IDs/case range/profile, source and dependency
closure, features, target, panic settings, compiler/Miri/sysroot identity,
command, environment and seed. Include fixture and helper/driver contents.
Record original source commit, worker/host identity, start/end times, actual
test/case counts, exit status and log hashes. Use canonical bounded records.

Before and after each task, validate the frozen inputs and relevant tools.
Only after exit zero and expected nonzero coverage should the worker atomically
publish a PASS record. Resumption starts a fresh attempt for an interrupted
task; it never resumes interpreter memory or promotes a partial log to PASS.

Collection must reject missing tasks/cases, zero-test passes, unexpected skips,
duplicate coverage, changed inputs/tools/flags, mismatched targets, partial or
tampered records and path traversal/symlink/archive attacks. Identical duplicate
uploads may be deduplicated, but cannot fill missing coverage. Retain failed
attempts; a later pass must not silently hide a UB report or unresolved failure.

Successful tasks survive cancellation of another task or the campaign. Campaign
status remains incomplete until every currently required task has eligible
evidence. Source changes rerun affected tasks/consumers under the existing delta
rules; metadata does not rewrite historical results. A lower-tier receipt cannot
satisfy an extended task. Tool or semantic test-driver changes invalidate the
corresponding tasks, not every unrelated verifier by default.

These are trusted-owner receipts: hashes detect corruption/drift, not forged
results from a malicious worker/operator. Keep that existing trust boundary
explicit. Validate same-host-class Linux x86-64 transfers first; broaden host
equivalence only after tests. No remote Miri record grants native CPU admission.

## Transition from the cancelled sweep

Keep its manifest, frozen sources, 553 PASS records, two cancellations and all
logs immutable. It lacks the proposed per-task end-of-run attestations, so new
code must not silently stamp it as a modern successful receipt.

Provide an explicit legacy-import review that checks existing record/log hashes,
commands, source snapshots and available tool provenance. Map only complete
commands to obligations they actually covered. Produce a separate migration
record identifying the weaker historical provenance and require owner approval;
reject unverifiable records. Do not promise all 553 are eligible in advance.
Neither cancelled family command covers its partially finished inner tests.

New tests, changed drivers and newly required obligations still run. The 15
unstarted commands have no results from this sweep. Kani work remains outstanding
unless separately validated matching evidence exists. Debug probes never count.

## Implementation order and acceptance

1. Approve the two profile definitions and legacy-import approach. Inventory
   every current Miri invocation, classify tests and identify shared-process
   dependencies. Register the strict facade's real dependency/obligation mapping
   so it does not remain an unexplained unknown-family fallback.
2. Add progress flushing, task-local records and interrupted-task restart tests.
   Keep complete legacy receipt validation working unchanged.
3. Refactor TupleHash/ParallelHash tests into bounded and extended cases; then
   review KMAC, SHA-1, MD5, SHA-3 and the other selected families for the same
   pattern. Preserve native exhaustive execution and existing bug regressions.
4. Add multi-job collection and single-host resume first, then two-host transfer.
   Demonstrate cancellation after PASS, fresh restart and complete collection.
5. Run bounded benchmarks comparing grouped Cargo and process-per-test execution.
   Adopt Nextest only if measured gains justify its integration and version pin.
6. Update the gate/profile routing only after regression tests and owner approval.
   Generate a new v0.24.49 plan with explicit reuse, rerun and deferral decisions.

Required regression tests: lost/malformed/tampered logs; wrong source/tool/target;
zero selected tests; ignored or missing cases; overlapping/missing chunks; bad
seed ranges; changed features; cancelled tasks; sibling cancellation after PASS;
worker crash during record publication; unsafe ambient flags; stale caches;
retained failures; native coverage retention; profile downgrade; new unclassified
test; remote round-trip; receipt survival after Cargo cleanup. Seed deliberate
memory/ownership/cleanup regressions into relevant bounded fixtures to demonstrate
that the required checks remain load-bearing.

No production crypto changes, full sweep, cancellation, cloud provisioning,
commit, push or tag is authorized by this design document.
