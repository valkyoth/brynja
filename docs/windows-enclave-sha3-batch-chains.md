# Windows SHA-3 batch private-chain review

This is completion package 6's partial author review, not a release gate,
independent retest, new enclave execution or whole-image cleanup qualification.
It replays the saved, development-signed images and their original source/build
bindings. Production code and release-gate policy are unchanged.

## Bound populations

| Route | Emitted functions | Cleanup funclets | Exact prior helpers |
| --- | ---: | ---: | ---: |
| Sequential scalar | 54 | 0 | 30 |
| Sequential single-state AVX2 | 54 | 2 | 23 |
| Four-message Keccak AVX2 | 58 | 17 | Not yet reconciled |

Function counts include cleanup funclets. The checker inventories the actual
Rust object, rejects omitted/added bodies, and binds complete function bytes,
relocations, linked destinations, cleanup metadata, read-only constants and
local dispatch tables. It also replays the existing worker/transport bindings.
The four-message route has 15 indirect calls; recording their population and
callback table does **not** qualify their arguments or lifetime provenance.

The sequential helper matches require a fresh replay of the earlier scalar or
AVX2 SHA-3 semantic review followed by exact code, relocation, extent-kind and
resolved LLVM ABI equality. Similar names or an old PASS report are insufficient.
The current batch callers still need their own argument/lifetime composition.
Two AVX2 copy helpers have broader LLVM length ranges than the earlier review;
they are not included in the 23 exact matches. Their explicit widened-range
review is described below; batch caller lifetime composition is still pending.

## Scalar fallback in the SIMD executor (2026-10-09)

The complete 90-position scalar-fallback region now has a saved-instruction
contract and an independent effect-order model. It visits physical slots whose
ready byte equals one, polls the original internal cancellation target/context,
then checks and commits the one-block budget/used-work charge. Executor health
and, when present, authority health and revalidation are checked before copying
the lane state into the separate scalar owner. A failed revalidator preserves
the authority pointer needed by the shared rejection latch.

The scalar callee is checked independently of the vector session: its complete
opaque schedule is reconstructed from Keccak coordinates and LFSR-derived round
constants, with this image's actual labels, immutable linked table and resolved
four-region `noalias`/`nounwind` ABI. Its entry/return saves only pointer registers;
working-register and scratch clearing are checked. This is a review of the saved
compiler output, not a claim about arbitrary future code generation.

The caller checks the 200-byte copy into and out of the scalar owner, explicitly
clears the three scratch regions, and wipes the complete 1,040-byte owner before
checking/incrementing the scalar report counter. Counter overflow does not wrap.
Readiness and vector accounting are unchanged; the workspace, framing and ready
pointers are restored for the absorption-loop continuation. The model uses only
synthetic bytes for provenance, not a replacement cryptographic oracle.

These checks assume live, disjoint caller objects and a revalidator that obeys
its callback/ABI contract. Error cases stop at the shared rejection edges;
complete rejection-edge composition, final report serialization, incoming
pointer lifetimes/non-overlap and private-frame/exception cleanup remain open.
The [scalar-fallback observation](../assurance/windows-protection-observations/sha3-batch-simd-scalar-progress-20261009.json)
records 95 focused tests passing on Linux (91.868 seconds) and Windows
(107.605 seconds). The complete regenerated reports match, with 235 current
checker-source bindings and 88,058 rejected body-byte mutations. The eight new
tests cover 1,024 flag/effect and 288 health/accounting cases, 16 per-lane
poll/revocation/copy failures, 270 caller-instruction and 210 kernel-assembly
mutations, and 19 reached semantic mutations. The unrelated full predecessor
suite was not rerun. Package 6 remains open; production code and release-gate
policy are unchanged.

## Vector grouping, charge and lane transfer (2026-10-09)

The saved executor's 261-position vector-caller region now has a complete
emitted contract. It scans physical lane slots in order, selecting only flags
whose ready and eligible bytes both equal one. An incomplete group is left for
the scalar path. The temporary four-index array is cleared on each scan, and
every gathered/scattered state index is bounded before applying its 200-byte
stride. The separate 800-byte group buffer is cleared before gathering.

The original internal cancellation target/context is polled before a checked
budget decrement and used-work increment; both control counters are committed
only after both arithmetic checks pass. Each selected state is copied to its
group slot. The already-reviewed session receives the original authority,
group buffer and separate CPU scratch. Successful return must accompany exactly
one authority-counter increment before any result is copied back. Scatter
returns each group slot to its original physical state slot. Accelerated-slot
bits, vector-call and vector-block counters, kernel identity and readiness
retirement are checked before rescanning. Original input, control, executor and
workspace pointers must survive to the continuation.

The bounded model independently checks selection and effect ordering, including
noncanonical flag bytes, cancellation, exhausted budgets, all checked counter
boundaries and every gather/scatter copy failure. A synthetic callee transform
marks byte provenance; it is not Keccak testing and does not replace the replayed
session/transpose/kernel review. The two-lane selector is exercised, but this
x86 image rejects the other architecture's kernel instead of executing it.
Injected session failures/counter mismatches do not claim observed native faults.

These checks assume valid live caller objects and the reviewed callee/ABI
contracts. They stop at scalar fallback, finalization or the shared rejection
edges. The subsequent scalar-fallback checkpoint above closes that local caller
review. Final report serialization, complete incoming pointer lifetimes,
rejection-edge composition and private-frame/exception cleanup remain open;
no whole-worker qualification is claimed.

The [vector-caller observation](../assurance/windows-protection-observations/sha3-batch-simd-vector-progress-20261009.json)
records 87 focused SIMD/predecessor tests passing on Linux (84.050 seconds) and
Windows (97.091 seconds). Complete reports regenerated with 88,058 body-byte
mutations match after parsing; all 231 checker-source bindings are current.
The eight new tests include 3,072 compaction cases, 1,280 accounting/transfer
cases, 783 instruction-position mutations, 20 reached semantic mutations and
all eight gather/scatter copy failures. The unrelated full predecessor suite
was not rerun. This is saved-image author review, not new native execution;
production code and release gates are unchanged.

## Four-lane one-block absorption (2026-10-09)

The saved executor's complete 272-position absorption region now has an exact
emitted contract, including its nine-entry framing-part dispatch and separate
linked rate table. Each iteration consumes one rate block from the prepared
frame: encoded rate/name/customization lengths, name/customization bytes,
prefix zero padding, message, domain suffix and final padding. Empty parts are
skipped with bounded indices. Part offsets are checked before source indexing;
unaligned fragments may use two separately bounded byte accesses. The complete
checked XOR wrapper and opaque byte leaf, their private LLVM argument ranges,
fifth-argument placement and EAX/ECX erasure are reviewed separately.

A bounded instruction interpreter compares all workspace bytes and readonly
inputs against an independent concatenated-bitstream oracle. Expected helper
events additionally bind each source address, source bit offset, count,
destination byte and destination bit offset. Caller-saved registers are poisoned
after helper calls. The campaign covers all eight identities and four lane
positions, zero/partial/rate-boundary messages, fractional name/customization
lengths, and every block of maximum 8,192-bit message/name/customization cases.
It checks part/cursor advancement, one-block count retirement, readiness and
the transition out of absorption. No permutation is modeled or claimed.

Fault injection reaches each of the four distinct helper call sites and checks
that rejection occurs before block-count/readiness retirement. Corrupt part,
cursor and remaining-block metadata and truncated input buffers reject. The
shared rejection cleanup is a separate, replayed contract: these model failures
do not claim native fault injection or cleanup of every intermediate frame.
All incoming pointer lifetimes, storage non-overlap, permutation/control/work
accounting, final report and private-frame/exception composition remain open.
Live, disjoint caller objects remain explicit model assumptions.

The [absorption observation](../assurance/windows-protection-observations/sha3-batch-simd-absorb-progress-20261009.json)
records 79 focused SIMD/predecessor tests passing on Linux (72.287 seconds) and
Windows (86.536 seconds). Complete reports regenerated with 88,058 body-byte
mutations match after parsing; all 227 current checker-source bindings match.
The nine new tests include 412 bitstream/source/cursor comparisons, 89,088 XOR
metadata/byte comparisons, 816 absorption instruction mutations, 129 helper
instruction mutations, 17 reached semantic mutations and faults at all four
distinct helper call sites. The unrelated full predecessor suite was not rerun.
This is saved-artifact author review, not new native enclave execution or
package-6 completion. Production code and release gates are unchanged.

## Four-lane rate-limited squeezing (2026-10-09)

The saved executor's 37-position inner-loop setup, 24-position readiness/lane
dispatch and 72-position squeeze region now have exact emitted contracts. The
eight-identity rate table is checked against both assembly and the previously
bound object/linked-image bytes. Each copy reads the selected 200-byte state
lane, uses equal source/destination lengths bounded by that identity's rate,
and checks the accumulated staging offset and end before touching output.
The written-byte counter advances only after the reviewed copy succeeds.

A bounded instruction interpreter compares the complete workspace and staging
against an independent byte/counter oracle. It covers all identities, four lane
positions, zero/exact/over-rate output, staging boundaries, excessive counters,
u64 overflow, injected copy failure, all seven fractional-byte widths and two
caller-saved-register poison patterns. Only a successful final chunk masks its
last byte. The mask helper's complete opaque operation, register erasure, tail
wrapper and resolved LLVM ABIs are checked separately. Live lane/input/control
and frame pointers must be restored at the continuation; readiness is exactly
whether more output remains. Synthetic bytes exercise copy/mask semantics, not
Keccak permutation correctness.

The new regressions reject changes to all 133 region positions, mutations of
the mask body/markers/ABI, changed linked rates, missing predecessor reviews and
17 reached copy/counter/mask/restoration mutations. Failure injection represents
a modeled helper rejection, not an observed native failure. The model assumes
live, disjoint caller objects; it stops on the shared rejection edge and relies
on the separately reviewed cleanup contract. All incoming pointer lifetimes,
the absorption/permutation/work-accounting loop, final report and private-frame/
exception cleanup are still open. No whole-worker or whole-image qualification
is claimed.

Seventy focused SIMD/predecessor tests pass on Linux (56.291 seconds) and Windows
(69.437 seconds). Complete saved reports regenerated with 88,058 body-byte
mutations match after parsing; all 222 checker-source bindings match the current
files. The unrelated full predecessor suite was not rerun. The
[squeeze observation](../assurance/windows-protection-observations/sha3-batch-simd-squeeze-progress-20261009.json)
records the seven new tests and their 2,280 independent oracle comparisons as
saved-artifact review, not new native enclave execution. No production or
release-gate behavior changed.

## Four-lane admission and normal rejection (2026-10-09)

The saved executor now has exact contracts for its 69-position entry, the
56-position post-framing eligibility/poll region, and the 78-position shared
normal-rejection/return region. Entry binds the original output descriptors,
operation guard fields, health/revalidation check and output validator. The
post-framing check rejects totals above 1,024 bytes and counts only eligibility
bytes equal to one. Required mode rejects a missing authority or too few lanes;
the saved width computation distinguishes the four-lane and two-lane identities.
This does not claim execution of a different architecture's kernel.

The first cancellation poll is joined from the original control argument to
vtable slot 32 and its original context, in both assembly and LLVM. The caller's
replayed vtable resolves this to the internal, read-only false leaf; it does not
accept a host callback. Model-injected cancellation checks the rejection path
without pretending the actual internal leaf returned true. Later polls and
their argument lifetimes remain separate review obligations.

A bounded interpreter compares 5,248 public admission/rejection cases against
an independent decision and retirement model. These include all 14 valid error
tags, absent/present authorities, both width tags, three modes, all Boolean
eligibility masks, noncanonical eligibility bytes, zero/exact/oversized staging
totals, sparse/zero-length outputs and two caller-saved-register poison patterns.
Routine input/destination/scratch/eligibility/length/budget/cancellation errors
preserve executor reuse; backend, quarantine, selection and invariant errors
revoke it and any supplied authority. Rejection wipes the 5,260-byte workspace
and 1,024-byte staging first, then supplied nonempty outputs and output metadata.
Only the error byte and discriminant are published in the caller result.

The tests reject 609 instruction-position changes, six first-callback IR
mutations, and 22 reached decision/classification/retirement mutants. They also
execute the actual saved region with sparse output cases. The model assumes
live, disjoint caller objects and the previously checked erasure helpers; it
does not establish every incoming failure edge's pointer lifetime, exceptional
cleanup or private-frame erasure. Those obligations and the inner engine remain
open. This is saved-artifact review, not new native enclave execution.

## Four-lane public framing preparation (2026-10-09)

The executor's complete 385-position preparation region and eight-entry identity
table are now bound to the saved image. An independent arithmetic oracle checks
its emitted instructions for all SHA-3, SHAKE and cSHAKE identities: rates,
domain suffixes, encoded name/customization lengths, prefix byte-padding,
message padding, absorb/permutation counts, eligibility flags and original-slot
staging offsets. Absent lanes remain absent instead of compacting these fields.

The bounded public-metadata interpreter maps no secret input pages, rejects
uninitialized memory reads and unassigned writes/calls, and models the freshly
reviewed workspace wipe plus bounded, non-overlapping integer-encoding copies.
Caller-saved registers are poisoned across calls. Two poison patterns exercise
2,467 cases each, including empty cSHAKE equivalence, 255/256-bit integer-width
changes, exact rate-aligned prefixes and adjacent bits, padding and output-rate
boundaries, mixed lanes and eligibility thresholds. The independent oracle
compares all 5,260 workspace bytes, not only the returned counters.

Regression tests reject 1,155 instruction-position changes, eight dispatch-table
changes and 17 reached arithmetic/encoding/offset mutations. The integrated
checker also executes the actual saved region against representative oracle
cases; model-only tests cannot substitute for that artifact binding.

This closes the scoped preparation check, not the hashing core or the entire
executor. The model assumes the already-reviewed resident metadata limits and
helper contracts. It does not prove unbounded inputs, arbitrary caller frames,
whole-executor pointer lifetimes or private-frame erasure. Inner absorption,
permutation/report paths and final cleanup composition remain open.

## Four-lane executor output ownership (2026-10-09)

The executor's local 104-byte output owner now has an exhaustive LLVM address-use
review. Its first 64 bytes are imported exactly once from the four incoming
pointer/length pairs, before control-flow branching or descriptor reads. No
later scalar write or permitted call changes those fields. The checker follows
22 root/derived addresses, inventories every typed load and metadata store, and
rejects unreviewed calls, stores of descriptor addresses, pointer-to-integer
escapes and reinterpretation of pointer fields as integer loads.

Each loaded destination pointer is used only for its null check and a matching
copy, or for clearing on rejection. Copy lengths must come from the same slot.
The two shape-validator calls, exceptional destructor, metadata clearing,
lifetime markers and successful 104-byte aggregate return are the only admitted
address consumers. The destructor/zeroizer/copy-helper contracts are freshly
replayed from the preceding digest checkpoint. This is a scoped IR ownership
claim, not a proof that unrelated machine writes cannot alias its stack home.

The complete 76-position output validator checks all four presence/width pairs.
The executor's emitted 60-position source preflight and adjacent 60-position
copy/cleanup region are now bound separately from its still-unreviewed hashing
core. All four source extents are checked against the remaining 1,024-byte staging
slice before the first copy. Absent slots consume nothing; present zero-width
slots retain their nonnull pointer. Failed copies retire workspace/staging before
reaching quarantine; they do not leave an apparently successful output owner.

A bounded interpreter executes the actual public integer preflight instructions.
Its source pointers must be null for absent slots or the exact running prefix of
the original staging allocation, with no gaps, wraparound or excess extent.
The independent oracle compares the sum of present lengths against 1,024.
Tests cover 10,192 presence/width cases, including maximal unsigned lengths,
and repeat 64 cases against the region extracted from the saved machine code.
Targeted mutations show that the guards and pointer assignments are load-bearing;
unknown instructions and uninitialized memory/register reads fail the model.

The [output checkpoint observation](../assurance/windows-protection-observations/sha3-batch-simd-output-progress-20261009.json)
records the paired replay and mutations. Executor input/framing/permutation
semantics, machine-stack alias/lifetime composition, complete exception paths
and final private-frame erasure remain open. No whole-executor or package-6
completion is inferred from this output-only work.

## Four-lane resident digest and destruction review (2026-10-09)

The complete 511-position resident digest caller now has an emitted-instruction
contract, together with its five cleanup funclets and exact FH3 state/IP maps.
This adds caller coverage, not qualification of the inner executor's returned
pointers. The executor's complete body, pointer lifetimes and final private-frame
reconciliation remain open.

Admission checks each lane's three bit lengths against 8,192 and its output
against 2,048 bits. The eight-target identity table requires fixed SHA-3 widths,
empty SHAKE name/customization and the distinct cSHAKE branch. Its out-of-range
fallback is **not** an independent enum-validity check: the caller still relies
on the receiver's already-bound typed identity admission. Saved plan fields,
authority revalidation, executor arguments and all four bounded output-copy
sites are bound to the complete caller. Independently checked executor-entry
geometry separates workspace, staging, scratch, input/result descriptors,
control, destinations, authority and owner homes. This does not yet establish
their preservation across the inner executor.

The returned report must select AVX2, record nonzero vector calls and identify
all four accelerated slots. Each copy requires a nonnull source and at most
256 bytes. Output destruction precedes the final authority check; only success
publishes the retained plan and ready phase. These source-pointer checks alone
do not establish allocation validity or non-overlap. Those remain obligations
of the inner executor review, not conclusions inferred from a nonnull test.

Workspace wipe/drop, scalar-owner wipe and output destruction have complete
instruction/ABI contracts, composed with the previously checked CPU wipe and
volatile zeroizer. Workspace subobject ranges cover all 5,260 bytes without
gaps; retirement also clears 1,024 staging and 1,024 scratch bytes. The destructor
repeats some subobject clears deliberately; no claim treats every repeated
clear as independently necessary. Output destruction clears present nonempty
destinations, serialized output-bit counts and algorithm identities, but **not**
the borrowed slice pointer/length descriptors or all frame padding. Checked copy
helpers retain their actual length-range ABIs.

The exception mapping distinguishes pre-workspace authority checks from the
executor call and the later output-owning interval. Those chains respectively
quarantine; retire scratch/workspace then quarantine; or conditionally drop
output before retirement and quarantine. The final authority call runs with the
output-live flag cleared, avoiding a second output drop. Exception-dispatcher,
fatal-abort and shared runtime guarantees are not established by these tables.
The internal cancellation vtable is linked to two pure false-returning bodies;
it is not a host-supplied callback. Its invocation inside the executor remains
to be reviewed.

The [digest checkpoint observation](../assurance/windows-protection-observations/sha3-batch-simd-digest-progress-20261009.json)
records paired saved-image regressions and explicit pending claims. No production
code, native enclave capture or release gate changed; package 6 remains open.

## Four-lane Keccak leaf review (2026-10-09)

The distinct four-message route now checks both complete transpose bodies,
the kernel tail wrapper and the opaque AVX2 permutation, including their Win64
envelopes and resolved LLVM ABIs. Expected instructions are generated from the
25 Keccak coordinates: theta column parity/deltas, rho's triangular rotation
sequence, pi's coordinate permutation, chi and 24 iota rounds. The linked
192-byte round table must match an independently generated LFSR sequence.
The parent also binds the actual object relocations and linked-image bytes.

Each transpose maps lane-major `200 * lane + 8 * word` to word-major
`32 * word + 8 * lane`, or reverses that mapping, with no endian swap. Model
checks cover widths zero through four, bounds, inactive bytes and round trips;
the saved LLVM specialization only admits widths two through four. These are
not interchangeable claims, and callers still must supply valid disjoint
regions and the admitted width.

The permutation operates independently on four 64-bit lanes. State occupies
`[0, 800)`, column parity `[800, 960)`, deltas `[960, 1120)` and staging
`[1120, 1920)`. All opaque vector accesses stay within these regions. Before
return, it clears `[800, 1920)`, RAX/RCX/RDX and YMM0–3, resets flags and executes
`vzeroupper`. No stack access or call occurs inside the opaque block. The
800-byte result intentionally remains for the caller; this is not a claim that
the whole workspace is already erased.

The outer Win64 envelope saves/restores incoming XMM6–15 in a 168-byte frame.
Those incoming values and the frame require the separate outer-window cleanup
review. Inactive-lane initialization, feature authority, session error/unwind
paths, resident/input-pointer lifetimes and final output retirement remain
caller obligations. Package 6 and whole-image qualification remain open.

Focused regressions reject 698 instruction/label/envelope mutations, nine
missing markers, 192 round-table byte changes, missing/wrong-size tables,
16 argument/calling-convention changes and a target-feature change. An
integration negative confirms the main saved-image checker cannot skip this
leaf review. No production implementation or release-gate policy changed.

## Four-lane session cleanup composition (2026-10-09)

The saved `Session::permute_bytes`, CPU scratch wipe, volatile zeroizer and
three session cleanup funclets now have complete instruction contracts. The
session must call the already-reviewed pack, permutation wrapper and unpack
helpers. Exact LLVM contracts preserve the 800-byte caller state and 1,920-byte
scratch extents, exclusive borrows, positive zeroizer lengths and feature set.

An independent conservative control-flow walk checks all seven normal paths:
four health/revalidation rejections, wrong-architecture rejection, counter
overflow and success. Only success writes caller state. It does so after both
health checks/revalidation calls, AVX2 dispatch and a nonoverflowing counter
increment; the completed counter is committed after output. Every normal
rejection wipes scratch and quarantines without writing output or the counter.
Scratch clearing covers exactly `[0, 800)`, `[800, 960)`, `[960, 1120)` and
`[1120, 1920)` with positive-length volatile calls, before packing and on exit.

The authority layout is counter at offset 0, revalidator at 8, health at 16 and
kernel tag at 17. Authority and scratch pointers are saved at parent-frame
offsets -16 and -24; the state pointer stays in Win64's nonvolatile RSI. The
two callback instruction ranges are tied to the actual FH3 state/IP tables.
Each callback unwind invokes its health-quarantine funclet, then the shared
scratch-wipe/quarantine funclet. The checked table's frame-state offset is 56;
each cleanup funclet reconstructs the parent frame with an adjustment of 64.
Other functions' cleanup tables are not implicitly qualified by this check.

These claims assume valid caller allocations/authority, the callback's ABI and
nonvolatile preservation, immutable kernel identity and no callback-driven
invalidation of storage. Binding that callback to the resident's actual authority
and establishing the full caller lifetime are next, not silently assumed done.
Fatal termination, OS exception-dispatch correctness, private-frame erasure and
whole-image qualification remain outside this checkpoint.

Regressions reject 338 instruction changes, 15 broken normal-path event/order
cases, 30 cleanup-table changes/removals/duplicates, four moved callback labels,
21 ABI changes and eight weakened leaf prerequisites. The integrated checker
also rejects a failed session review. Production code and gates are unchanged.

## SIMD resident construction and owner admission (2026-10-09)

All 198 constructor instruction/label positions and the three-instruction
`Kernel::compiled` callback are checked. The constructor uses public zero-state
input, executes the reviewed four-lane permutation and compares each 200-byte
result against an independently computed Keccak-f[1600] zero-state answer. The
linked answer table, all four comparison lengths and both pre/post-kernel
compiled-tag checks are bound. Only then can the authority be initialized.

Within the exclusive 4,096-byte page, authority storage occupies `[0, 24)` and
the 1,112-byte owner `[24, 1136)`. The constructor sets the authority counter to
zero, stores the exact `Kernel::compiled` function address at page offset 8,
and writes healthy=1/kernel=0 at offsets 16/17. Owner offset 64 (page offset 88)
points back to that authority. The 1,024-byte output at page `[96, 1120)` is
initialized before sequence=0, empty phase and the returned
backing/authority/owner pointer triple are published. Absent-plan payload and
padding are not claimed initialized. This callback is not host supplied at
construction; it checks a compiled tag, not live hardware/migration support.

All nine conservative normal constructor paths are checked. The eight failure
paths clear every page byte before returning an error without publishing a
resident. The startup scratch is retired before reuse for public output
initialization. Frame allocations `[32, 832)`, `[832, 2752)`, `[2752, 3552)` and
`[3552, 4576)` have separate initial roles. Shared `memcpy`, `memset`, `memcmp`
and stack-probe behavior remains a package-8 prerequisite; these public startup
temporaries are not evidence of secret frame erasure.

The complete owner `operation`, standalone authority `check`, cancellation and
five associated cleanup funclets are also checked. `operation` compares phase
and a nonwrapping next sequence before using the authority at owner offset 64.
Successful guard publication follows two revalidations and an AVX2-tag check;
all rejected operations clear retained output, invalidate the plan and
quarantine. The exact FH3 tables bind both owner callbacks to authority
quarantine followed by owner-output cleanup/quarantine. The standalone check's
callbacks have their own quarantine handlers.

Successful cancellation uses the admitted guard, clears output/plan and returns
the owner to empty. Already-quarantined cancellation returns an error without
repeating a wipe. The standalone check returns a backend error for a wrong tag
without itself quarantining; its owner caller performs the enclosing cleanup.
These distinctions are tested rather than silently promoted into stronger
claims. The constructor establishes pointer origin. The worker admission and
retirement follow-up below composes that origin through the outer entry;
complete digest/receiver paths and final private-frame retirement remain open.

New regressions reject 402 constructor/callback instruction changes, 418
owner/check/cancel/funclet changes, 200 startup-table byte changes, 36 ABI
changes, 58 cleanup-table mutations, eight callback-label changes and 11
weakened composition prerequisites. The constructor CFG rejects 27 event/order
changes. It deliberately accepts removal of the first of two consecutive
identical failure-path wipes; the exact instruction check still rejects that
code change. No production or release-gate behavior changed.

## SIMD retained-worker admission and retirement (2026-10-09)

The complete 266-position `RetainedWork` body and both 11-instruction buffer
clear/drop bodies are now checked against the saved object/image and resolved
LLVM ABIs. The entry requires a nonnull, page-aligned 4,096-byte page and a
nonwrapping 65,536-byte worker window. Checked page-end arithmetic and the
half-open interval comparisons reject page/window overlap. On a request, the
retained page identity must match before calling the receiver. Actual allocation,
residency, serialization and exclusion of recursive entry still come from the
linked C adapter, not from these integer comparisons.

Opening zeroes the page and passes it to the reviewed constructor. The returned
page/authority/owner triple at frame `[40, 64)` is copied through `[64, 88)`
without rebinding its pointers before publishing `LIVE` and `LIVE_PAGE`.
Construction failure publishes nothing. The emitted replacement branch is also
checked: an existing owner and page would be retired before replacement, even
though the earlier no-live check makes that branch unreachable under the
required serialized, nonrecursive contract. Closing disarms `LIVE` first,
clears/quarantines the owner, erases all 4,096 page bytes, then resets page
identity before returning the close-success code. It does not free the page;
the C owner retains that responsibility after return.

Request buffers occupy `[64, 12736)` of the 12,744-byte worker frame: payload
`[64, 12352)` and header `[12352, 12736)`. The descriptor scratch used during
opening is reused only on the separate request path. Buffer initialization
precedes the bounds tests; this is public zero initialization on the already
provided worker stack, not a claim that bounds tests allocate/protect it.
Before the receiver call, both regions are checked inside the supplied window,
including overflow checks. The receiver receives the original operation and
exclusive buffer address. Its obligation not to overwrite live metadata or
retain borrowed pointers still needs composition with its inner paths.

Receiver failure clears/quarantines the resident before retiring the buffers.
The explicit clear and `Drop` both erase the 384-byte header and all 12,288
payload bytes. Successful readback traverses each byte exactly once before the
fixed observer receives the header/payload addresses and a clear receipt of 1.
Bounds, readback and observer failures quarantine and reach the buffer-drop
join; all normal request returns pass through it. The second wipe is intentional
redundancy, not evidence that both wipes are individually necessary for every
path. Independent direct-CFG checks enforce five cleanup obligations; exact
instruction checks additionally bind the pointer transfers, lengths and order.

Focused regressions cover every instruction/label position, admission/identity
boundaries, early returns, removed cleanup calls, weakened ABIs and constructor/
owner prerequisite removal. Both hosts replay the saved compiler artifacts;
this is **not** a new enclave execution or native cryptographic campaign.
The [worker observation](../assurance/windows-protection-observations/sha3-batch-simd-worker-progress-20261009.json)
records the runs and remaining scope. Digest lifetime review and complete
private-frame/exception reconciliation remain open; the receiver/descriptor
follow-up is below. Fatal abort
cleanup is not claimed; shared stack/runtime/OS boundaries remain package 8.

## SIMD receiver and descriptor construction (2026-10-09)

The complete 405-position receiver and its resolved LLVM ABI are now checked.
Its 384-byte version-22 header requires a nonzero sequence, route identity 2
and operation 100 (digest), 101 (public export) or 102 (cancel). Export/cancel
require zero budget. All four 88-byte lane records are validated before any
payload copy: identity 1–8, at most 2,048 output bits, exact fixed SHA-3 widths,
and canonical empty triples. Nonempty inputs require at most 1,024 bytes,
last-bit count 1–8, a nonzero opaque source and nonwrapping source-end
arithmetic. Only cSHAKE identities permit nonempty name/customization inputs.
Export requires zero input triples; cancellation requires all lane-record bytes
zero. The linked zero-record and fixed-output-width constants are bound too.

The public-predicate model is compared with a separately written wire policy
on 27,648 field/boundary substitutions. This is metadata validation, not an
independent cryptographic oracle. The checked byte-copy schedule transfers the
288-byte decoded record from frame `[80, 368)` into `[368, 656)`, with a
279-byte snapshot at `[784, 1063)` and explicit first-field copies. It preserves
all physical bytes, including uninterpreted padding, without asserting that
padding is initialized or erased. The raw header is no longer used when its
frame area becomes the decoded destination.

Only digest copies payload. Copy kinds 1–12 each pair one decoded length/source
with its own 1,024-byte worker slot. Host addresses remain opaque until the
fixed C copy adapter; descriptor inputs use the local worker slot instead.
The three bitstrings for lane `i` occupy 32-byte fields at
`1064 + 112*i + 32*part`. All twelve length and last-bit loads are checked
against the corresponding copy slot. Sequence, budget and the exact retained
owner pointer are passed to the resident digest. This establishes the caller's
argument origins, **not** preservation inside the still-open digest bodies.

Export checks the ready phase and next sequence through the reviewed owner
operation, compares all four stored identities and output lengths, and copies
the explicit 1,024-byte public output. It rechecks authority after the copy.
Successful export clears output/plan and sets the owner empty; rejection returns
false and reaches the enclosing worker's quarantine/retirement path. A failed
post-copy check cannot roll back bytes already copied to the host. Cancellation
calls the reviewed resident cancellation helper. These are fixed synchronous
transport boundaries, not permission to substitute arbitrary callbacks.

The 86-position four-lane initializer and 63-position bitstring constructor are
also checked, together with the six-position mask wrapper and seven-position
byte predicate. A byte-token model executes the actual initializer moves,
including overlaps and padding: all twelve initial bitstring copies and all
four nine-byte plan fields preserve their source provenance. Physical writes
cover 441 of the 448 destination bytes; the final seven padding bytes remain
unwritten. Descriptor helpers publish no input pointer to global or heap
storage; returned descriptors intentionally retain their caller-owned borrow.
Their local copies and frames are **not** thereby erased.

Bitstring admission accepts last=0 only for empty input, otherwise last=1–8.
For partial bytes it checks only the final local byte and rejects nonzero
unused high bits. Input length is bounded to 1,024 by this callsite/ABI, so the
bit count is at most 8,192. Successful result fields preserve pointer, length,
bit count and last-bit count; rejection uses a null result pointer. Exhaustive
last-byte/last-bit comparisons at four length boundaries cover 262,144 cases.

The [receiver/descriptor observation](../assurance/windows-protection-observations/sha3-batch-simd-receiver-progress-20261009.json)
records focused Linux/Windows saved-image replay and mutation checks. Remaining
package-6 work includes the resident/executor digest bodies, workspace wipe/drop
and full private-frame/normal/exceptional composition. No new native enclave
execution, production change, release-gate change or whole-image claim is made.

## Sequential plan admission

Both complete emitted plan validators and their nine identity-table entries are
checked. Eight 24-byte descriptors require valid identities, inactive zero
shapes, fixed SHA-3 widths of 28/32/48/64 bytes, and valid XOF final-bit metadata.
The validators reject an all-empty plan, reject totals above 1,024 output bytes,
and accumulate those widths with an overflow check. Their LLVM arguments retain
the full 192-byte, nonescaping, read-only descriptor contract.

This is metadata admission, not a proof that later computation preserves the
plan, frames, output pointers or authority. The full emitted validator is bound
to the saved object/image in addition to the instruction and dispatch review.

## Sequential lifecycle and widened copy review

The complete emitted `operation`, `clear`, `seal`, `cancel` and operation-guard
destructor bodies are now checked on both sequential routes: 339 scalar and
409 AVX2 instructions/branch labels. Expected paths are constructed from the
reviewed layouts and transitions, not extracted from the body being checked.
The contracts cover phase admission, nonwrapping next-sequence equality,
failure status, output clearing, logical metadata reset and quarantine.
AVX2 admission also requires the expected Keccak kernel and healthy authority
before committing the new sequence. Cancellation accepts phases 1–4 and clears
before returning to empty; sealing requires every active slot's completion bit.
An unfinished operation guard clears and quarantines. The LLVM contracts retain
the complete exclusive owner extent, disjoint operation-result storage and
bounded phase/completion representations.

These are method-body contracts, not proof of every caller or unwind path.
The state-destructor composition below joins these particular method bodies;
validity of retained pointers and cleanup-funclet reachability remain separate
work. In particular, resetting the eight slots'
logical fields does **not** individually erase their padding or moved state
copies, and this checkpoint does not qualify complete private-frame erasure.

The AVX2 `copy_bytes` and `copy_secret_region` helpers permit lengths in
`[0, 2^63)` instead of the prior `[0, 1025)`. Their complete instruction paths
are now separately reviewed and bound; the ABI comparison permits only that
specific range change, preserving every other resolved attribute. The wrapper
rejects unequal source/destination lengths. In the leaf, `offset + remaining = n`;
each eight-byte access requires at least eight remaining bytes and each byte
access requires a positive remainder. Zero length performs no memory access,
and offset cannot exceed `n <= isize::MAX`. This does not prove that a caller
supplied live, sufficiently large, nonoverlapping allocations or that the
destination is eventually erased; those remain caller-composition obligations.

## State destruction and initial plan placement

Both batch state destructors are now explicitly rebound to their previously
reviewed counterparts using complete code, relocation, extent-kind and renamed
LLVM ABI equality. Their current complete instruction paths are also checked:
61 scalar instructions/labels and 43 AVX2 instructions/labels. The scalar
dispatch table is checked for all eight entries, covering empty, fixed-output,
XOF and setup states; the ninth valid state follows the setup branch. All wipe
callees must belong to the exact helper population whose earlier semantic review
was reproduced. This joins typed payload destruction to the five checked
lifecycle methods; it does not assert that the entire state allocation,
padding, moved copies or inactive payload bytes are individually erased.

The complete `begin` methods add 70 scalar and 85 AVX2 instructions/labels.
They admit the empty phase and sequence, validate the entire plan, then copy
exactly 192 bytes into the owner before recording the budget and collecting
phase. Failed validation follows the checked cleanup/quarantine path. The
scalar copy uses the already-bound shared `memcpy` boundary (whose implementation
remains package 8); AVX2 uses six bounded 32-byte transfers. Source and destination
are disjoint under the checked private LLVM argument contract. The state, plan,
output, sequence and budget subobjects are bounded and mutually disjoint.

This composition assumes the caller provides a live, valid owner and plan.
The state spans are `[16, 1152)` inside the 2,400-byte scalar owner and
`[1216, 2208)` inside the 2,272-byte AVX2 owner. It does not yet establish the
retained owner's full lifetime, every later input/output caller, cleanup-funclet
coverage or whole-frame erasure. Those remain explicit package-6 work.

## Retained entry, resident placement and buffer retirement

Both complete sequential `RetainedWork` bodies now have explicit contracts:
202 scalar and 295 AVX2 instructions/labels. They bind page alignment, the
65,536-byte supplied stack window, initialization before publishing a live
owner, exact page identity on subsequent requests, and typed destruction before
erasing all 4,096 backing-page bytes on successful close. The scalar route
retains one owner pointer. AVX2 retains a backing/authority/owner pointer triple;
its constructor places the authority at page offset 0 and the 2,272-byte owner
at offset 32, retaining the authority pointer at offset 2,256. A successful KAT
precedes publication; failed construction erases the page.

These contracts require the linked C entry to serialize access and supply live,
resident page/window allocations. AVX2 independently rejects page/window
overlap. The scalar Rust entry does **not** perform that check and relies on the
linked C contract; this checkpoint does not promote that dependency into a new
whole-image or OS guarantee. The checked close paths remove the live handle
before completing page retirement. Nested receiver/callee behavior still needs
its own pointer-preservation and lifetime composition.

The complete buffer destructors, quarantine helpers, and AVX2 resident
constructor/destructor are checked. On normal paths after buffer construction,
an independent control-flow walk requires buffer destruction before every
return. Explicit clearing covers the 1,024-byte payload and the 288-byte scalar
or 304-byte AVX2 header. The successful readback loops visit every byte of both
regions; early error paths are not treated as successful zero receipts.
Constructor copies contain public initial metadata; their padding and moved
representations are not claimed to be individually erased. Cleanup funclets,
nested call frames and final window reclamation remain separate obligations.

## Request decoding, dispatch and explicit export

The complete scalar receiver (557 instructions/labels), AVX2 receiver (392),
AVX2 decoder (281), both eight-descriptor equality helpers (76 each), and AVX2
authority check (nine) now have reviewed instruction contracts. All four
identity/operation dispatch tables are checked entry by entry. The expected
paths are constructed independently of the candidate bodies and are also bound
to the original object bytes, references and linked image.

The scalar receiver decodes version 11 inline. AVX2 decodes version 17, requires
route identity 1 and its reserved word to be zero, and repeats decoding before
dispatch with exact payload-length equality. Both validate the copied public
header before admitting payload: operations 90–99, nonzero sequence, bounded
slot, length at most 1,024 bytes, valid final-bit metadata, operation-specific
zero fields, and nonwrapping source end. Only operations 92, 93, 95 and 96 accept
payload; only 90 and 98 accept a nonempty validated plan. The source address is
passed to the fixed OS-copy adapter, never dereferenced as a Rust input pointer.
The actual input pointer remains the worker's distinct, bounded payload buffer.

The checked dispatch passes owner, sequence, slot, lengths and input pointer to
the expected methods with their actual LLVM argument contracts. The scalar
receiver takes its owner directly; AVX2 retrieves the placed owner from the
serialized worker's live pointer triple. Temporary header, plan, empty-plan
and guard regions are bounded within their frames, with simultaneous regions
disjoint. Reused header/plan/guard storage has sequential lifetimes. These are
caller-side contracts: nested bodies require separate reviews of pointer
preservation, state transitions and cleanup. The subsequent update checkpoint
appears below, followed by setup fragments and AVX2 setup completion. `start`,
scalar setup finalization and message finish remain unfinished.

Export first admits phase 4 and the exact next sequence, then compares all 24
semantic plan fields against the retained plan. Only equality reaches the
fixed 1,024-byte output copy. AVX2 also checks authority after that copy. Success
clears the owner and returns it to empty; plan mismatch, copy failure or failed
post-copy authority check follows the operation-guard cleanup and quarantine
path. Already copied host bytes cannot be rolled back, and no such rollback is
claimed. Payload/header buffer destruction remains the outer worker's duty.

Header and descriptor semantic fields are public metadata. This neither classifies
padding as public nor claims that padding, all temporaries, compiler copies or
private frames are individually erased.
Shared transport serialization, OS copying, runtime helpers and final stack-window
cleanup remain package 8; cleanup-funclet composition remains separate work.

## Remaining package-6 work (updated 2026-10-09)

- Reconcile the checked sequential constructor, update, setup-completion,
  finalization and export contracts into complete storage/copy/cleanup lifetimes.
  Both constructor bodies now have complete instruction coverage and explicit
  state-transfer models; that does not itself close every enclosing-frame or
  exceptional-path obligation.
- Review four-lane Keccak kernel/transposes, compaction, per-lane pointers,
  authority/cancellation calls and their normal/error/unwind paths.
- Assign every private temporary and frame's cleanup responsibility, keeping
  typed erasure, backing-page retirement and enclosing-window reclamation distinct.

Shared SDK/runtime implementation, cumulative stack depth and final protected
window reclamation remain package 8. The current direct-reference graph and
individual frame sizes are not a whole-image stack or erasure proof.

## Validation checkpoint (2026-10-08)

All 12 tests pass on Linux (11.050 seconds) and Windows (29.106 seconds).
The saved-artifact regressions reject 88,058 complete-body byte mutations,
166 validator instruction/label deletions, 18 identity-table changes and
14 descriptor-ABI changes. Additional tests cover missing/added functions,
relocation/extent changes, required prior-review replay and unbound dispatch.
Parsed reports match, including 162 current checker-source hashes. The
[checkpoint observation](../assurance/windows-protection-observations/sha3-batch-inventory-progress-20261008.json)
records those results without claiming completion of package 6.

The subsequent lifecycle/copy checkpoint passes all 19 tests on Linux (18.292
seconds) and Windows (35.152 seconds), with matching parsed reports and 164
current checker-source bindings. It adds 1,496 lifecycle instruction/label
mutations, 56 operand/escape changes, 66 lifecycle ABI changes, 78 copy-loop
instruction changes and 13 copy-ABI/population changes. All preceding inventory
and plan regressions are replayed. The
[lifecycle observation](../assurance/windows-protection-observations/sha3-batch-lifecycle-progress-20261008.json)
records these results and the still-unqualified caller/unwind/frame boundaries.

The state-storage checkpoint passes all 26 tests on Linux (88.013 seconds) and
Windows (165.161 seconds). Parsed reports match, including 165 current checker
bindings. New regressions reject 518 destructor/`begin` instruction mutations,
nine dispatch-table changes, 34 ABI changes, nine missing-helper/prior-review
changes and twelve isolated rebinding changes. Tests require lifecycle, plan
and integrated storage checks to execute; previous regressions also pass.
The [storage observation](../assurance/windows-protection-observations/sha3-batch-storage-progress-20261008.json)
retains the live-owner precondition and the remaining caller/frame obligations.

The retained-worker checkpoint passes all 33 tests on Linux (163.655 seconds)
and Windows (302.955 seconds). Parsed reports match, including 167 current
checker bindings. It adds 1,616 complete worker/resident/buffer instruction
mutations, 16 admission/pointer/erase mutations, four independent control-flow
mutations and eleven ABI mutations. Additional tests enforce prerequisite
reviews, integrated execution, successful readback coverage and the explicitly
incomplete scope. All preceding regressions pass. The
[retained-worker observation](../assurance/windows-protection-observations/sha3-batch-retained-progress-20261008.json)
records these results; this is saved-artifact replay, not new enclave execution.

The request/receiver checkpoint passes all 40 tests on Linux (232.298 seconds)
and Windows (430.375 seconds). Parsed reports match with 171 current checker
bindings. New regressions reject 2,782 instruction/label mutations, 42 dispatch
mutations, 56 export-plan/lifecycle mutations, 15 input/decoder/authority
mutations and 21 argument-ABI mutations. Eighteen prerequisite-removal cases,
integration tripwires, pending-scope checks and 1,280 public-selector model cases
also pass. The
[receiver observation](../assurance/windows-protection-observations/sha3-batch-receiver-progress-20261008.json)
records the corrected test-formatting issue and comment-only clarification;
neither required changing production code or the reviewed instruction contracts.

## Sequential update caller checkpoint (2026-10-08)

The scalar and AVX2 `Owner::update` bodies now have complete expected instruction
contracts (122 and 124 instructions/labels). These are manually reviewed
expectations, not templates extracted from the candidate. The nine scalar
dispatch destinations are checked independently against their emitted table.

Both callers preserve the receiver's copied input pointer and length through
operation admission, active-slot equality and checked work-budget subtraction.
Only admitted phase-3 calls with the next sequence reach absorption. Scalar
fixed-output identities pass the owner at offset 17; SHAKE identities check
their streaming state and pass offset 18. All five rate-specific lower update
helpers must freshly replay their previous semantic review and match the
current emitted body, references, extent and resolved ABI. Their 1,040-byte
owners fit inside the placed state. The scalar dispatch requires a valid,
initialized enum; arbitrary corrupted discriminants are not treated as valid.

AVX2 checks state phase, failure/partial-bit flags, authority health, epoch and
kernel identity before passing the engine at offset 1,216 and the unchanged
input to absorption. Its 864-byte engine and nested 234-byte wipe region fit
inside the placed state. These regions overlap intentionally; they are not
claimed to be independent allocations. Its lower absorption and wipe helpers
also require fresh semantic replay and exact current artifact/ABI identity.

The fifth argument is read at `rsp+128` in both frames, accounting for each
prologue's saves and allocation. The 16-byte operation result is outside the
callee home area and within the local frame. Actual LLVM input/owner contracts
require a read-only source disjoint from the exclusive live owner, with at most
1,024 input bytes. This composes the checked caller with the lower callee's
larger length domain; it does not assume that an arbitrary host pointer is valid.

Successful absorption returns the success tag without clearing streaming state.
Rejected admission uses the reviewed operation path; later rejection follows
typed state destruction, output clearing, logical-field reset and quarantine.
AVX2's inner failure cleanup and retained authority quarantine are also checked.
The outer worker remains responsible for input-buffer cleanup. Private-frame
erasure, initial state construction, complete unwind coverage and the four-lane
SIMD route remain open. No production implementation or release gate changed.

All 46 saved-artifact tests pass on Linux (252.579 seconds) and Windows
(479.440 seconds). Parsed analysis reports match with 172 current checker-source
bindings. New tests reject 492 instruction/label mutations, ten dispatch changes,
25 pointer/budget/authority/cleanup changes, 32 argument-ABI changes and seven
lower `nounwind` removals. Required prior helpers, caller identities, payload
bounds, integrated execution and incomplete-scope flags are also exercised.
All preceding regressions pass. The
[update observation](../assurance/windows-protection-observations/sha3-batch-update-progress-20261008.json)
records this author-review checkpoint; it is not new native enclave execution
or completion of package 6.

## Setup fragments and AVX2 setup completion (2026-10-08)

Both sequential setup-fragment callers now have complete emitted instruction
contracts: 144 scalar and 158 AVX2 instructions/labels. The scalar route adds
the complete 35-instruction state adapter; its two lower rate-specific setup
helpers are reused only after fresh semantic replay and exact current-body,
reference, extent and ABI comparison. The AVX2 state setup helper is likewise
an exact replayed helper. These checks compose actual phase-2/sequence admission,
active-slot equality, checked work subtraction, slot bounds and cSHAKE identities.

An empty fragment requires a zero terminal-bit count and skips lower setup.
Nonempty input requires one through eight valid bits in its last byte. Only a
nonempty partial byte can reach the high-bit mask check, at `input + len - 1`.
The admitted 1,024-byte maximum bounds the computed bit length to 8,192. The
input pointer remains in a preserved register on scalar; AVX2 reloads it from
the original argument slot after the mask call. Both construct the same 32-byte
descriptor, including every byte of the unusual split length stores. Its 25
semantic bytes contain pointer, length, bit length and terminal-bit count;
padding is neither interpreted as public data nor claimed individually erased.

The descriptor is aligned and bounded within each frame and disjoint from the
live operation result, callee home area and saved guard/exception state. Actual
argument offsets account for the prologue: scalar uses `rsp+192/200/208`, AVX2
uses `rsp+208/216/224` (or `rbp+112/120/128`). The state and scalar setup-payload
subobjects fit their exclusive owners. Lower descriptor arguments are read-only
and nonescaping; that does not establish noncapture of all addresses contained
inside the descriptor. Rejection composes the reviewed typed-state/output
cleanup and quarantine. The outer worker still owns input-buffer retirement.

The AVX2 setup call also has a separately checked 26-instruction cleanup funclet
and 42-instruction operation drop glue. The expected FH3 header, unwind-state map
and instruction-pointer map are checked in full, including the exact protected
call interval and the parent handler selection. The funclet reloads the saved
owner and completion byte from the parent frame before calling the checked guard.
The enclosing image checker already binds these metadata and funclet targets to
the object and linked image. This composes one selected compiler cleanup path;
it does not qualify the Windows dispatcher, arbitrary exceptions or every unwind
path in the image.

AVX2 `finish_setup` now has a complete 137-instruction contract. For cSHAKE it
requires a live setup core, healthy matching authority/epoch/kernel, prefix phase
complete, zero remaining 128-bit count, no pending bits, and equality of the full
128-bit emitted/expected counts. Success clears the pending byte through the
volatile helper, resets logical prefix counts and advances the core and outer
owner to absorbing/streaming. Failure composes engine/state/output cleanup and
quarantine. Non-cSHAKE identities take their separate admitted transition.
The scalar finalizer is not covered: it moves several secret-bearing state
copies through a 5,408-byte frame and requires its own lifetime/cleanup review.

These are saved-image author checks, not new native enclave execution. Initial
state invariants, scalar setup finalization, message finish/squeeze, four-lane
SIMD and final private-frame/cleanup composition remain package-6 work. Shared
runtime/OS dispatch, cumulative stack depth and outer-window cleanup remain
package 8. Production code and release-gate policy are unchanged.

All 57 saved-artifact tests pass on Linux (275.772 seconds) and Windows
(520.421 seconds). Parsed reports match with 174 current checker-source
bindings. New checks reject 810 setup-fragment/bridge/cleanup instruction
mutations and 274 AVX2 completion instruction mutations, alongside focused
operand, ABI, unwind-table, call-interval and prerequisite regressions. Fragment
shape, canonical tail bytes and split length stores also have exhaustive or
boundary-model checks. All preceding regressions pass. The
[setup-fragment observation](../assurance/windows-protection-observations/sha3-batch-setup-fragments-progress-20261008.json)
records the exact counts and remaining scope; it does not close package 6.

## Scalar setup completion (2026-10-08)

The scalar `finish_setup` caller now has a complete 411-instruction/label
contract. The operation result at `rsp+1296` is consumed into preserved owner
and guard registers before the same storage becomes the 1,136-byte old-state
copy. Changing the destination state tag to `Empty` transfers logical ownership;
it does not erase its physical payload. The following 1,120-byte setup copy and
smaller field reads still use those live physical bytes. Valid initialized state
is a precondition until the separate `start` caller review is complete.

For both setup variants, completion requires prefix phase 2, zero remaining
128-bit length, no pending bits, all 16 bytes of the emitted/expected counts
equal, and a present inner owner. On success, the temporary inner owner at
`rsp+244` is cleared across 1,040 bytes, and the setup pending byte is cleared
through the volatile helper. The caller installs the corresponding streaming
variant (setup 7 becomes 5; setup 8 becomes 6), its absorbing lifecycle and the
outer streaming phase. Rejection runs the applicable typed cleanup and the
previously reviewed output/logical-field clearing and quarantine path.

A separate symbolic byte-origin model checks both moves into the returned
1,040-byte owner. It covers the overlapping eight-byte stores at a seven-byte
stride and vector stores at a fifteen-byte stride: their overlap contains the
same original byte. These agreeing stores can be represented in either order
without changing the byte mapping. The model also checks the two distinct
988-byte payload staging regions, their common staging destination, source
write-before-read ordering, copy non-overlap and bounds within the 5,408-byte
frame. Initial owner bytes are abstract origins under the live, valid-state
precondition, not proof that padding has initialized Rust values. Copying opaque
padding does not classify it as public or qualify its erasure. The
operation result's earlier lifetime, typed tags and exact branch predicates are
checked by the full instruction contract rather than inferred from byte values.

The original-state snapshot and other moved copies are **not** claimed erased
by this caller. The temporary owner wipe does not erase other copies. Full
protected-stack retirement, cumulative stack depth, `__chkstk`, `memcpy`,
`memset` and the enclosing runtime/OS boundaries remain separate obligations.
This is saved-image author analysis, not a new native enclave campaign, an
independent retest or completion of package 6. Production code and release-gate
policy are unchanged.

All 61 saved-artifact tests pass on Linux (293.315 seconds) and Windows
(632.576 seconds). Parsed analysis reports match, with 176 current checker-source
bindings verified. New regressions reject 822 instruction deletions/substitutions,
23 targeted predicate/copy/cleanup changes and 60 symbolic copy-source changes,
plus lifetime, region, prerequisite, ABI and integration failures. The
[scalar setup observation](../assurance/windows-protection-observations/sha3-batch-scalar-setup-progress-20261008.json)
records the counts and explicitly retains the remaining private-frame obligations.

## Final-message callers and retained output (2026-10-08)

The complete scalar and AVX2 outer `finish` callers now have explicit contracts
(221 and 239 instructions/labels). Admission requires streaming phase, the next
sequence, matching active slot, and checked subtraction from the remaining work
budget. Input length is bounded to 1,024 bytes by the receiver and argument ABI.
Empty input requires zero terminal bits; nonempty input requires one through
eight. The partial-byte mask reads only `input + len - 1`, after those bounds.
The full 32-byte descriptor preserves the copied input pointer, split length,
bit length and terminal-bit count; its padding is not claimed initialized or
erased. Unlike an empty setup fragment, an empty final message still calls the
lower finalizer.

The selected slot is bounded to seven. Every preceding output-width addition
checks carry; adding the current width checks both carry and the 1,024-byte
output bound before forming the destination. A symbolic u64 model is compared
with an unbounded-integer reference across all slots, boundary widths, prefix
overflows and seeded mixed-width plans. An empty output can legally point one
past the buffer. Fixed identities 1–4 dispatch to `finish_fixed`; identities 5–8
dispatch through `finish_xof` and terminal `squeeze`. The output region is a
bounded subrange of the owner output buffer, disjoint from its live state.

Successful lower calls precede state destruction, the selected completion-bit
update, active-slot reset and return to collecting. Output stays secret inside
the owner; this operation does not export it. Rejection follows typed state
cleanup, clears the entire output buffer, resets logical fields and quarantines
the owner/authority. The descriptor and guard/result regions are disjoint from
each other and the outgoing call home area. Incoming length/last-bit arguments
are at `rsp+176/184` on scalar and `rsp+208/216` on AVX2, accounting for the
actual prologues.

For AVX2, the three lower finalizer calls share one bound FH3 unwind state. The
header, state map, IP map, exact call intervals, 26-instruction cleanup funclet
and 42-instruction guard drop glue are checked. The saved owner/completion fields
are live before entering each protected call. Object/image metadata bindings
remain prerequisites; this does not qualify the Windows exception dispatcher.

This checkpoint deliberately does **not** claim every lower finalizer has been
composed. AVX2 `finish_xof` exactly matches the freshly replayed streaming helper.
Scalar `finish_fixed`, `finish_xof`, `squeeze`, and AVX2 `finish_fixed`, `squeeze`
have different emitted bodies or call contracts and remain named pending work.
Caller ABI checks do not prove those implementations correct. Valid initial
state and plan are preconditions until `start` is reviewed. Whole private-frame
cleanup, all unwind paths and package 6 closure remain open. These are saved
artifact checks, not new enclave execution; no production or gate policy changed.

All 67 saved-artifact tests pass on Linux (312.807 seconds) and Windows
(601.713 seconds). Parsed reports match with 178 current checker-source bindings.
The new checks reject 1,056 caller/funclet/guard instruction mutations, 46
boundary/cleanup changes, 24 unwind-table and 17 protected-interval/handler
changes, and 36 ABI changes. The output-span model passes 41,156 independent
reference comparisons, plus one-past-empty and invalid-domain cases. Prerequisite,
integration and pending-scope regressions also pass. The
[finish-caller observation](../assurance/windows-protection-observations/sha3-batch-finish-callers-progress-20261008.json)
records the exact scope and keeps the five changed lower helpers pending.

## AVX2 terminal lower helpers (2026-10-08)

The next checkpoint reviews the changed AVX2 `State::finish_fixed` and terminal
`State::squeeze` bodies in full: 126 and 182 instructions/labels. This is not
name-based reuse of their streaming counterparts. Their seven lower helpers
must match the freshly replayed body/reference/extent/ABI review, while the
broadened copy loop and wrapper are separately rechecked. The actual outer
caller supplies a live, disjoint state/output pair and a bounded descriptor.

Fixed output requires absorbing phase, healthy matching authority/epoch, the
fixed-state tag and matching output width before forwarding the descriptor and
suffix to `Engine::finish`. Squeeze requires squeezing phase and canonical
output shape: zero bytes with zero terminal bits, or 1–1,024 bytes with 1–8
terminal bits. A small model of the emitted byte predicates and wrapping
bit-length check is compared against that independent domain. This emitted
squeeze is specialized for terminal output; it does not qualify a continuing
squeeze interface.

Both helpers reserve 1,064 frame bytes. Their initialized staging array occupies
`[rsp+40, rsp+1064)`, disjoint from the outgoing home area and saved incoming
registers. Reads receive only the bounded prefix of that array. Partial output
masking touches only its nonempty final byte, at `rsp+39+length`, and retains the
low requested bits. The final copy uses equal bounded lengths, a live staging
source, and the owner's disjoint retained-output destination; it does not export
the output. Successful paths clear the core and staging before setting the state
empty. Rejection poisons the core and composes with the outer caller's whole
output clear and quarantine.

A supplemental conservative CFG analysis explores both sides of every branch.
It treats an `Engine::read` failure as potentially having written staging, and
requires a full volatile clear before every normal return following that call.
It rejects missing, shortened and shifted clears, cleanup bypasses and direct
dirty returns. Full-body checks additionally bind call arguments, pointer
preservation, phase/epoch predicates, mask arithmetic and state transitions.

This removes these two helpers from the **normal-path** review backlog; scalar
`finish_fixed`, `finish_xof` and `squeeze` remain pending. It does not close all
finalizer qualification: valid state construction, exceptional exits, other
frame bytes/copies and the shared `memset` implementation remain distinct
obligations. The existing `all_lower_finalizers_composed` flag stays false;
only the AVX2 normal-path flag becomes true. No production source or release
gate changes, new native enclave execution, independent review or package-6
closure are claimed.

All 73 saved-artifact tests pass on Linux (313.172 seconds) and Windows
(606.304 seconds). Parsed reports match with 180 current checker-source
bindings. New regressions reject 616 instruction deletions/substitutions, 29
targeted boundary/mask/cleanup changes, 15 missing/shortened/shifted staging
clears, eight CFG bypass/missing-operation cases and 14 helper ABI/binding
changes. The output-shape model passes 262,656 independent domain comparisons,
768 oversized cases and six invalid-domain rejections. Caller prerequisites,
exact helper replay and integrated review failures are also tested. The
[terminal-helper observation](../assurance/windows-protection-observations/sha3-batch-terminal-progress-20261008.json)
records these results without closing the remaining scalar or private-frame work.

## Scalar XOF final-message transition (2026-10-08)

The changed scalar `State::finish_xof` now has a complete 163-instruction/label
contract. Tags 5 and 6 select the 168- and 136-byte-rate owners respectively;
other states reject. The absorbing lifecycle must precede any mutation. Both
routes preserve the same owner at state offset 2 through update and finalization.
That owner's 1,040-byte extent is inside the 1,136-byte state and disjoint from
the separately borrowed input descriptor and payload.

The actual batch caller supplies `Some(input)`, whose slice pointer is nonnull
even for an empty slice. The emitted null-pointer `Option` branches are bound
by the whole-body contract but are not confused with zero-length input. The
descriptor supplies byte length, bit length and canonical last-byte width. A
low-word add and high-word carry check admit complete-byte growth without u128
overflow before calling update. This is a **byte-counter** check, not a claim
that the counter measures all message bits.

For a fractional final byte, the split retains the preceding complete bytes and
passes exactly the last input byte to padding. Empty and byte-aligned input use
no partial-byte pointer. The 8,193 canonical bounded input shapes are compared
against an independent bit-count-based split. Counter admission is separately
compared against unbounded arithmetic, including low-word carry and maximum
u128 boundaries. Update errors return before padding or the squeezing-phase
commit; the checked outer caller then destroys the state, clears retained output
and quarantines.

The valid customization flag selects suffix/width `(4, 3)` for cSHAKE or
`(31, 5)` for SHAKE. Width is the fifth argument, stored at caller `rsp+32`
(callee entry `rsp+40`), outside the outgoing home area and below saved
registers. Both padding helpers return `void`; no failure result is discarded.
Only after padding are the cSHAKE metadata at state `[34, 50)` and mode byte
`[1038, 1039)` cleared, followed by the squeezing lifecycle commit. The live
sponge remains retained for the subsequent squeeze; this step emits no output.

The two update helpers, two padding helpers and volatile clear helper must all
match fresh prior semantic review, complete bodies/references/extents and the
current resolved ABI. In particular, the nested owner needs no stronger
alignment than its actual offset provides, and the optional partial pointer
retains its one-byte-or-null contract. The caller checks do not qualify arbitrary
private entry or establish initial state/customization invariants.

Scalar `finish_fixed` and `squeeze` remain pending. Construction, four-lane SIMD,
exceptional exits, other private-frame copies and whole-image cleanup remain
separate work. This is saved-artifact author analysis, not new native execution,
independent review, a production change, a gate change, or package-6 closure.

All 79 saved-artifact tests pass on Linux (332.407 seconds) and Windows
(651.770 seconds), with matching reports and 181 verified current checker-source
bindings. New regressions reject 326 instruction deletions/substitutions, 30
targeted pointer/rate/suffix/failure/cleanup changes and 22 helper ABI/binding
changes. The input partition passes all 8,193 canonical bounded cases; the
counter model passes 69,640 independent reference comparisons. Thirteen invalid
model domains, eight caller prerequisite/target changes, five missing helper
reviews and integration failures are also rejected. The
[scalar-XOF observation](../assurance/windows-protection-observations/sha3-batch-scalar-xof-progress-20261008.json)
records this checkpoint and keeps scalar fixed finalization and squeeze open.

## Scalar terminal squeeze (2026-10-08)

The changed scalar `State::squeeze` now has a complete, independently written
633-instruction/label contract for both inlined rate branches. It requires the
checked outer caller's disjoint state and bounded retained-output slice, six
freshly replayed exact lower helpers, and the separately rebound typed state
destructor. It does not borrow earlier streaming caller semantics by name.

Only XOF tags 5/6 and squeezing lifecycle 1 enter work; the lifecycle is then
vacated. Output length is at most 1,024 bytes, with zero terminal bits for empty
output or 1–8 bits in a nonempty last byte. The private stack staging allocation
is `[rsp+120, rsp+1144)`, separate from outgoing home space, metadata/pointer
slots and saved registers. The original destination remains in a preserved
register for the empty case and in `rsp+104` for nonempty output.

Both branches admit complete-byte growth using low-word add and high-word carry
against the owner's 128-bit output counter. Bulk output uses chunks no larger
than the selected rate (168 or 136). The inner cursor cannot exceed that rate;
equality triggers permutation and clearing of all three permutation scratch
regions before resuming at zero. Copies read only the admitted lane interval
and fill only the current internal staging prefix. The initialized stack prefix
is checked for carry and capacity before each chunk copy. The full 168-byte
internal staging region is cleared even for the 136-byte-rate branch.

A fractional last byte consumes exactly one additional lane byte, after the
same rate-boundary checks, and masks it to the requested low bits before copying
it into the stack staging allocation. Metadata-only loop models are compared
with independent unbounded stream positions; this is not a new cryptographic
oracle. The 49,370 comparisons cover every valid cursor, rate/chunk boundaries,
all bounded output lengths at selected cursors, and partial-byte widths.

The nested owner is wiped before the final staged copy into retained output.
Success requires the entire requested extent to be initialized and copied;
typed destruction and the Empty tag follow the successful copy. Empty output
uses a zero-length copy with a nonnull dangling source, not a readable byte.
Precondition rejections and work failures are joined to the outer caller's
typed destruction, complete retained-output clearing and quarantine.

A conservative normal CFG follows both outcomes of every branch and treats
copy failure as potentially writing data. All ten copy sites and the single
normal return are reached; only the exact full 1,024-byte volatile clear
discharges staging dirtiness. `memset` initialization is not accepted as secret
erasure. This is a staging-buffer property, not whole-frame/register erasure:
other stack copies, shared runtime implementation, exceptional exits and the
enclosing private window remain separate obligations.

Scalar fixed finalization, initial state construction, the four-lane SIMD route
and final private composition remain open. No production Rust, release gate,
native execution or independent-review claim changes. Package 6 remains open.
All 85 saved-artifact tests pass on Linux (344.588 seconds) and Windows
(668.454 seconds). Parsed reports match with 183 verified current checker-source
bindings. The six new tests reject 1,266 instruction deletions/substitutions,
34 focused bound/pointer/rate/mask/counter/cleanup mutations, five normal-CFG
clear or return bypasses, 18 helper replay/ABI mutations, seven caller changes,
four replay/typed-destruction prerequisite changes and an integrated review
failure. The loop model passes 49,370 independent geometry comparisons and
rejects 12 invalid domains. The
[scalar-squeeze observation](../assurance/windows-protection-observations/sha3-batch-scalar-squeeze-progress-20261008.json)
records this bounded author checkpoint without closing the family or image.

## Scalar fixed-output finalization (2026-10-08)

The complete 1,195-instruction/label scalar `State::finish_fixed` contract now
binds all four branches and the exact four-entry jump table. Tags 1–4 select
SHA3-224/256/384/512 with output widths 28/32/48/64 and rates 144/136/104/72.
An oversized destination rejects before consuming the state. For accepted
state tags, zero or wrong-width output rejects before message processing;
complete-byte counter growth is checked with carry before absorption. The
checked outer caller supplies canonical, bounded final-input metadata and a
disjoint retained-output interval.

The first copy snapshots the 1,136-byte state into `[rsp+2160, rsp+3296)` before
tombstoning the original tag. The fixed owner is then copied from the original
state's bytes `[1, 1041)` into `[rsp+96, rsp+1136)`. Setting the original tag
to Empty does not invalidate or erase its physical payload. The working owner,
1,024-byte output staging, result descriptor and initialization descriptor all
occupy disjoint regions below saved registers. Non-fixed variants are handled
by the bound snapshot destructor.

All four absorption helpers and the delegated SHA3-256 finalizer must match
fresh prior semantic review, full emitted bodies/references/extents and resolved
ABIs. The other three padding paths are checked in full rather than classified
as helper reuse. Their buffered prefix and masked partial byte are followed by
the SHA-3 domain bits and padding, including rate-boundary flushes and the final
high bit. Each of their fifteen emitted permutation sites clears the 40/40/200
bytes of permutation scratch and the full 168-byte padding buffer before
continuing. The padding model is compared with an independently concatenated
bit string for 10,240 cases; it is not a new hash oracle.

The padding contracts require a valid absorbing owner, a buffered length below
the selected rate, canonical final-input bits and initially zero padding
storage. Under those preconditions, the ignored results of one-byte/equal-length
padding copies and fixed-width XOR helpers cannot fail: addresses are live,
non-overlapping and bounded, and bit counts are 0/8. This does not authorize
arbitrary private calls or qualify corrupted owner metadata.

After padding, the digest is transferred through the internal squeeze buffer
into exact-width stack staging. `finish_secret` receives a fully initialized
descriptor; its result tag and returned pointer/length are retained across
working-owner wiping. An error tag rejects before output access. The final copy
targets only the checked retained-output interval; successful output is not
exported here. Returned secret staging is cleared after use. Outer rejection
still destroys the remaining typed state, clears retained output and quarantines.

The conservative normal CFG follows both direct-branch outcomes and all four
bound jump-table targets. It tracks four working-owner copy sites, three owner
wipe sites, one output-commit site and one return. Every normal return must have
cleared both the working owner (if copied) and full output staging; the owner
must also be cleared before output commit. Removing a wipe, shortening the
staging clear or returning early is rejected independently of the full-body
instruction comparison.

This does **not** claim that the original payload, snapshot, other stack copies
or registers were individually erased. Original payload bytes belong to the
retained owner's backing-page retirement scope; stack snapshots/copies belong
to the enclosing private window's scope. Clearing one does not clear the other.
Shared `memcpy`/`memset`, initial state construction,
exceptional frames, four-lane SIMD and final private composition remain open.
Both sequential routes now set `all_lower_finalizers_normal_paths_composed`,
but `all_lower_finalizers_composed`, package-6 and whole-image closure stay false.
No production code, release policy, native capture or independent review changes.
Validation: seven focused tests pass (13.225 seconds); all 92 integrated tests
pass on Linux (374.370 seconds) and Windows (738.832 seconds). The Windows suite
was rerun after the interrupted session left no recoverable completion result.
Parsed reports match with 185 verified current checker-source bindings.
The new tests reject 2,390 instruction deletions/substitutions, seven dispatch
table mutations, 39 focused pointer/padding/counter/result/cleanup mutations,
eight normal-CFG cleanup bypasses, 39 helper replay/ABI mutations, eleven caller
or target changes, four replay/destruction prerequisite changes and an integrated
review failure. Alongside the 10,240 padding comparisons, input partition and
counter models pass 32,772 reference comparisons. The
[scalar-fixed observation](../assurance/windows-protection-observations/sha3-batch-scalar-fixed-progress-20261008.json)
records the bounded checkpoint, not family or whole-image closure.

## Start admission and retained-state placement (2026-10-09)

Both sequential `Owner::start` methods now have explicit instruction contracts
for their entry/admission prefix, identity dispatch, non-cSHAKE length rejection,
normal rejection cleanup, retained-state placement and epilogue. These slices
cover 254 scalar and 197 AVX2 instruction/label positions. They deliberately do
not qualify the intervening constructor implementations or the complete start
methods. The existing saved-object/image binding still covers their entire
1,361- and 597-instruction populations.

The actual receiver target and exclusive owner ABI are joined to the previously
reviewed operation helper. Phase 1 (Collecting), next-sequence validation and,
for AVX2, authority admission precede the returned live owner. The emitted scan
requires the first nonempty, unfinished slot. Equality with that selected index
is checked **before** the indexed plan read, so out-of-range supplied indices
cannot reach that read. The subsequent identity-minus-one check bounds the
eight-entry constructor table. Every table destination is bound, and the six
non-cSHAKE identities pass through a check that both 128-bit name/customization
lengths are zero. Later code may not re-enter the middle of the admission prefix.

The seven-argument Windows ABI is checked as emitted: the owner, sequence,
slot and low name half arrive in registers; the remaining three 64-bit halves
are at entry-stack offsets 40, 48 and 56. Scalar offsets are relative to its
7,192-byte local frame. AVX2 keeps the pre-alignment frame base in `rbp` while
aligning `rsp` to 32 bytes; both possible entry residues modulo 32 preserve the
same incoming argument addresses. This is a local geometry check, not shared
stack-probing or cumulative-window qualification.

On successful placement, the previous typed state is destroyed before the new
state is written. The writes cover exactly the scalar state interval
`[owner+16, owner+1152)` or AVX2 interval `[owner+1216, owner+2208)`. All eight
overwritten scalar bytes receive the same source byte from each overlapping
store. No placement write reaches the retained output. Active-slot publication
and phase 2 (Setup) follow the state transfer. These checks establish destination
coverage, not that every constructor source byte was initialized or that all
intervening register values remained valid; those constructor/lifetime joins
remain the next review task. Distinct stack-window and retained-page allocations
are still caller-boundary prerequisites.

Ordinary rejection follows the live operation guard: typed state destruction,
full 1,024-byte retained-output clearing, logical plan/active/budget reset, and
owner quarantine. AVX2 also revokes its authority. This is not a claim that plan
padding, all state backing bytes or private temporaries are individually erased.
The scalar saved XMM6 restoration and AVX2 `vzeroupper` epilogue are bound, without
claiming that restoring caller registers scrubs them. Unwind composition, complete
constructor semantics, four-lane SIMD and final private cleanup remain open.

The selector model exhausts all 65,536 availability/completion-mask combinations
with ten candidate indices each (655,360 comparisons), including index 8 and
`u64::MAX`. Regression tests reject 902 instruction deletions/substitutions,
20 table changes, 28 focused pointer/index/home/cleanup/re-entry mutations,
16 caller/lifecycle/storage prerequisite changes, 18 ABI changes and an injected
integrated-review failure. All seven focused tests pass (30.167 seconds), as
do all 99 integrated tests on Linux (396.763 seconds) and Windows (775.898 seconds).
Parsed reports match with 187 current checker-source bindings verified. The
[start-path observation](../assurance/windows-protection-observations/sha3-batch-start-progress-20261009.json)
records these results without closing either complete constructor or package 6.
No production implementation, release gate or native enclave capture changed.

## AVX2 cSHAKE constructor reconciliation (2026-10-09)

The remaining cSHAKE constructor blocks now have explicit instruction and
lifetime contracts. Together with the direct-constructor checkpoint, all **597
AVX2 `Owner::start` instruction/label positions** are checked. The scalar start
coverage remains 1,361 positions. This is constructor-path review, not completion
of package 6 or proof of whole-frame erasure.

The two cSHAKE entries map to identity/rate pairs 6/168 and 7/136. They pass the
retained authority into the rebound initial helper and reject its error tag
before reading the payload. Every byte of the 992-byte result at `[1696,2688)`
is saved into `[704,1696)` before the original result slot is reused for public
encodings. The borrowed session authority survives at local `[1280,1288)`.
The three encoding results are disjoint from the live local engine. Their
lengths are consumed before name-encoding storage is reused for prefix fields.

Both emitted paths use checked two-limb additions for the declared name/custom
bit lengths, followed by ceiling division by eight and rate rounding using the
public `__umodti3` runtime contract. Boundary/randomized comparisons against
an independent framing calculation cover 21,202 cases, including both carry
failures and the largest admitted total bit count. The 75 active prefix bytes
are initialized only after arithmetic succeeds. Empty N/S bypasses absorption;
customized paths absorb the encoded rate, encoded name length and then call the
replayed prefix-advance helper. Pending/used fields lie outside the exclusively
borrowed engine, so normal initial `used == 0` cannot become nonzero merely
through the bulk absorb call. The alternate byte-loop instructions are checked
too, without claiming that branch is reached by valid initialization.

On an initial-helper error there is no local Core to destroy. Arithmetic failure
destroys the already-created local Core without treating uninitialized prefix
fields as live. Later absorption/advance failures clear the initialized prefix
pending byte and destroy local engine memory and scratch before the existing
outer guard's clear/quarantine path. The plan pointer is restored before that
outer cleanup. Wipe-call counts distinguish explicit caller cleanup from work
inside the separately reviewed helpers; no count is promoted into a claim that
all frame copies or padding have been erased.

The empty and customized prefix snapshots now have byte-origin models through
the emitted overlapping moves: all 80 physical prefix bytes are accounted for,
75 are active, and 23 overlapping store bytes have identical origins. Five
padding bytes remain explicitly outside initialization claims. The cSHAKE
domain/width is 4/3 when either declared length is nonzero and 31/5 for empty
N/S. All 992 final physical state bytes reach retained `[1216,2208)` after old
state destruction and before slot/phase publication. Active prefix bytes land
at `[2080,2155)`, padding at `[2155,2160)`, and the original authority remains
at `[1792,1800)` without overwriting the output, plan or outer authority fields.

New regressions cover 738 instruction deletions/substitutions, 11 improper
entries, targeted ABI/pointer/domain changes, 128 initial-snapshot deletions,
240 snapshot bounds/order changes, 374 retained-transfer deletions and 126
retained-transfer provenance/order changes. The byte model deliberately accepts
58 deletions of stores superseded by identical-origin writes; the complete
instruction contract still rejects those changes. The model is not presented
as proving those redundant writes are semantically necessary.

The [observation](../assurance/windows-protection-observations/sha3-batch-avx2-cshake-progress-20261009.json)
records focused Linux/Windows validation and current report/source bindings.
Remaining package-6 work is the distinct four-lane SIMD caller/dispatch/lifetime
review and final private-frame, copy and exceptional-cleanup reconciliation.
Shared runtime/ABI and whole-image qualification remain assigned to package 8.
Production source and release-gate policy are unchanged.

## Direct AVX2 constructor caller transfers (2026-10-09)

The six non-cSHAKE identities now have an explicit saved-image caller join to
the replayed `State::initial` helper. The checked descriptor dispatch supplies
identities 0–5 only after rejecting nonzero function-name/customization lengths.
The caller imports the authority **value** from owner offset 2224, supplies the
32-byte-aligned 992-byte result at local offset 1696, and tests the returned
discriminant at offset 2640 before reading or copying the payload. Discriminant
2 takes status 6 directly to the already-reviewed operation-guard rejection:
an armed guard clears and quarantines rather than publishing a new state.

The authority join additionally checks the helper's incoming-pointer save,
session construction and returned session field at result offsets `[576,584)`.
The exact helper body, constants and resolved ABI must still pass their previous
semantic replay and current-image rebinding. These new slices do not replace
that prerequisite with a few matching instructions.

On success, all 992 physical result bytes are traced through the 943-byte
payload copies, first-byte/discriminant nonvolatile registers, and 32+8-byte
tail staging. The old retained state is destroyed before installation into
owner `[1216,2208)`. The same authority reaches `[1792,1800)` inside that state;
the output, plan and outer authority fields remain untouched by these transfers.
Slot/active/phase publication follows complete replacement. Local copies are
bounded by the realigned 4888-byte frame and are nonoverlapping; Win64 register
preservation and disjoint resident-page allocation remain explicit prerequisites.

This adds 31 checked caller/failure positions, bringing AVX2 start coverage to
228 of 597 positions. The byte model deliberately preserves opaque result
origins without declaring inactive fields or padding initialized. It does not
claim that copying erases the source, that the enclosing private frame has been
retired, or that the distinct cSHAKE prefix-setup path is complete.

Focused regression coverage rejects 62 instruction deletions/substitutions,
102 transfer deletions across six identities, 300 provenance/bounds/order
mutations, eight targeted pointer/identity/entry changes, twelve helper-offset
and ABI changes, and ten missing prerequisite contracts. The integrated checker
must propagate failure of this new review. Validation results are recorded in
[the observation](../assurance/windows-protection-observations/sha3-batch-avx2-start-progress-20261009.json).
Package 6, shared runtime qualification and whole-image cleanup remain open;
no production implementation or release-gate policy changed.

## Scalar cSHAKE retained setup transfers (2026-10-09)

The last 145 scalar `start` instruction/label positions now have explicit
contracts for empty-result extraction, both setup temporaries and common
staging. Combined with the prior admission, fixed SHA-3, SHAKE, cSHAKE
initialization and failure-path contracts, all 1,361 positions are accounted
for. This is complete scalar instruction coverage, not whole-image or complete
private-frame qualification; accelerated constructors are still separate work.

The byte-origin model follows both identities, with empty and customized
prefixes, through the 1,107-byte snapshot and the 1,120-byte setup temporary.
It preserves all 1,109 active setup bytes at retained owner offsets
`[32,1141)`, after replacing the old typed state and before publishing the new
slot/phase. Tags 7/8 are installed at offset 16 and the inner setup tag 6 at
offset 17. Eight overlapping stores must carry identical origins. The leading
setup byte travels through stack offset 301, becoming the last byte of the
overlapping qword store ending at owner offset 32; it is not lost in staging.

The model also tracks physical copies into inactive owner offsets `[18,32)`
and padding `[1141,1152)` without calling those bytes initialized. On the empty
path, padding snapshots may retain earlier stack bytes; on the customized path,
they originate in the setup's padding. Neither class may replace an active
setup byte. Copy bounds exclude callee home space, saved registers and fields
outside retained state, and memcpy source/destination spans do not overlap.
Explicit source pointers are consumed before their stack slots are reused for
payload bytes. The original setup and snapshot remain physically live and are
not reported erased by logical ownership transfer.

The [retained-transfer observation](../assurance/windows-protection-observations/sha3-batch-cshake-moves-progress-20261009.json)
records this saved-image author checkpoint. Shared runtime/ABI assumptions,
complete private-window retirement, accelerated caller lifetimes and four-lane
SIMD still prevent package-6 closure. Production and release-gate policy remain
unchanged.

All 18 selected cSHAKE constructor/integration tests passed on Linux (98.866
seconds) and Windows (207.909 seconds). Complete saved reports regenerated with
body mutations agree; all 194 checker-source bindings match. New tests reject
290 instruction mutations, 276 transfer deletions, 72 provenance/bounds/order
changes, 11 pointer/tag changes, five external entries and eight prerequisite
changes. The full predecessor suite was not rerun.

## Scalar cSHAKE prefix and normal failure joins (2026-10-09)

The next 203 instruction/label positions bind both rates' prefix sequencing,
bulk and bit-loop branches, setup-advance calls, result extraction and local
failure paths. Incoming CFG edges must originate in these checked blocks or
the previously checked initializer. The error path restores the operation
guard where its register was reused, restores the plan base before outer
rejection and returns status 6. Arithmetic overflow branches bypass local-owner
destruction because initialization has not happened yet.

The encoded rate and name are consumed from `[rsp+1390, rsp+1648)`, disjoint
from setup storage `[rsp+1680, rsp+2800)`. The complete encoding helper initializes
258 bytes and produces an encoded-name length from 2 through 17. Successful
rate absorption commits an emitted count of two; successful bulk name
absorption commits `2 + encoded_name_length` before setup advance. The pending
bit count starts at zero at offset 1745, outside the borrowed sponge extent
`[rsp+1748, rsp+2788)`. Replayed helper semantics and exclusive nonunwinding
ABIs preserve it. Consequently valid construction takes the bulk branch;
the emitted alternative bit loops are still fully instruction-checked.

After a failed initialized helper call, the checked path invokes the typed
owner wipe, clears the pending byte, removes the optional owner and resets
setup counters, phase and customization metadata before outer rejection.
The repeated wipe is retained exactly as emitted. This is normal-return typed
cleanup, not proof of erasing stack padding, stale physical copies, arbitrary
exception frames or shared runtime internals. Scalar rejection is terminal;
there is no accelerated authority to quarantine on this scalar route.

Successful advance extracts 1,107 bytes to `[rsp+6061, rsp+7168)`, immediately
below saved XMM6, with the leading byte and customization flag in preserved
registers. Eleven padding bytes are copied separately and remain explicitly
unqualified as initialized secret state. The following scatter into retained
storage is still a separate byte-origin/lifetime obligation, not closed by
checking these prefix and error paths.

The [prefix/failure observation](../assurance/windows-protection-observations/sha3-batch-cshake-flow-progress-20261009.json)
records this partial saved-image author review. No new native execution,
independent review, production change or release-gate change is implied.

All 13 selected prefix/initialization/integration tests passed on Linux (58.843
seconds) and Windows (123.303 seconds). Regenerated body-mutation reports agree;
193 current checker-source bindings match. New regressions reject 406 instruction
mutations, 16 targeted changes, four external entries, ten helper-prerequisite
changes, seven ABI changes and five initialization/cleanup-prerequisite changes.
The model covers 198 customized prefixes, two empty prefixes, 18 helper-failure
cases and four arithmetic rejections. The full predecessor suite was not rerun.

## Scalar cSHAKE initial arithmetic and fields (2026-10-09)

Both inlined cSHAKE setup entry blocks now have complete contracts covering
248 instructions/labels. Each is entered only from the already checked identity
dispatch, with admitted input lengths and the Win64 u128 home-slot mapping.
The reviewed encoding and sponge-update helpers must be in the exact replayed
helper population. This checkpoint stops at the first rate-prefix update;
subsequent name/customization setup, retained transfers and failure cleanup
still require composition.

The arithmetic model follows both checked two-word additions, the bit-to-byte
ceiling and rounding to rate 136 or 168. The rate-136 multiply/fold reduction is
bound in its current register allocation and compared with independent integer
framing calculations. Rate 168 supplies aligned u128 operands to `__umodti3`
and decodes the Win64 XMM0 result; its mathematical remainder contract remains
an assumption until package 8 qualifies the runtime implementation. A total
bit count at most `u128::MAX` gives at most `2^125` rounded-up bytes, so adding
at most 167 padding bytes cannot overflow u128. Empty N/S selects complete phase
and expected count zero; nonempty N/S selects name phase and absorbs `[1, rate]`.

The initial encoding buffers occupy `[rsp+1390, rsp+1648)` and
`[rsp+1680, rsp+1938)`. Their length fields are read before reuse. Before the
first update, all 1,109 active setup bytes at `[rsp+1680, rsp+2789)` are
initialized, including counters, pending byte, phase, optional-owner tag, the
1,040-byte zero owner and the customization flag. The public two-byte prefix
is separate from the setup metadata and owner. The eleven trailing padding
bytes are not claimed initialized or erased; neither are retired encoding
copies or the enclosing private frame.

The [cSHAKE-initialization observation](../assurance/windows-protection-observations/sha3-batch-cshake-init-progress-20261009.json)
records focused saved-image author validation, not fresh enclave execution,
independent review or package-6 completion.

All 13 selected cSHAKE/SHAKE/integration tests passed on Linux (50.554 seconds)
and Windows (103.609 seconds). Complete reports regenerated with body mutations
agree after parsing; 192 current checker-source bindings were verified. The
new tests cover 39,506 independent arithmetic comparisons, 496 instruction
mutations, 16 targeted changes, two re-entry changes and seven prerequisite
changes. The full predecessor suite was not rerun.

## Scalar SHAKE constructor result joins (2026-10-09)

The two complete SHAKE result-decode blocks, common staging block and helper
failure block now have explicit contracts covering 194 instruction/label
positions. The previously reviewed empty-descriptor paths and helper bodies
establish a fully initialized 1,041-byte successful result. Its first byte is
the empty-mode discriminant, not part of the underlying 1,040-byte owner.
The success test precedes every payload read. On error, the saved plan pointer
is restored from `rdi` to `rbp` before status 6 enters the existing rejection
cleanup/quarantine path. That saved pointer is not confused with the later
byte-sized `dil` field loaded only on the successful path.

The byte-origin model gives every returned byte a distinct identity, even though
the actual empty constructor initializes zeros. It follows all 1,041 bytes from
`[rsp+1680, rsp+2721)` through scalar/vector staging and nonvolatile registers
into `[owner+17, owner+1058)`, after installing variant tag 5 or 6 at offset 16.
This catches field swaps that a zero-only comparison could miss. The final byte
at owner offset 1057 is included: using the fixed SHA-3 payload boundary here
would omit it. Six overlapping stores preserve identical byte origins.

The model requires initialized reads, nonoverlapping copy ranges and typed
destruction before installation. It proves the original helper result remains
intact through the transfers; it does **not** claim that result copy was erased.
The inactive storage at `[owner+1058, owner+1152)` remains separate. Shared
runtime and ABI preservation, enclosing-window retirement, nonempty cSHAKE
construction, four-lane SIMD and complete private/unwind cleanup remain open.
The [SHAKE-constructor observation](../assurance/windows-protection-observations/sha3-batch-shake-start-progress-20261009.json)
records this saved-image author-review checkpoint without closing package 6.

The 20 selected constructor/integration tests passed on Linux (108.931 seconds)
and Windows (227.827 seconds). Both complete saved reports were regenerated
with body mutations; parsed reports agree and all 191 checker-source bindings
match. New regressions reject 388 instruction mutations, 134 transfer deletions,
66 origin/bounds/lifetime/order changes, nine focused mode/error/pointer changes
and 17 prerequisite mutations. The full predecessor suite was not rerun; no
production code, release gate or native-execution qualification changed.

## Scalar fixed-constructor initialization (2026-10-09)

The four fixed SHA-3 constructor blocks, their common metadata initialization and
their common staging block now have complete instruction contracts: 353
instruction/label positions in total. The already reviewed two dispatch tables
bind SHA3-224/256/384/512 to tags 1/2/3/4. Each initialization block can be entered
only from the descriptor dispatch with zero in XMM0. SHA3-256's fallthrough into
common metadata and the metadata-to-staging fallthrough are checked explicitly.

An independent byte-transfer model follows the zeroed local regions through
staging and into the retained state. It checks each read is initialized, copies
do not overlap, offsets stay outside the outgoing call area and saved XMM6, and
old typed state destruction precedes every installation write. All four variants
install the correct tag at offset 16 and exactly 1,040 zero owner bytes at
`[owner+17, owner+1057)`. Six overlapping active-payload writes agree. The
previous placement contract checks the subsequent active-slot/phase publication.
The pointer and metadata registers used across calls are nonvolatile in the
Windows ABI; shared runtime/ABI preservation remains a package-8 prerequisite.

This is deliberately an **active-payload** proof. The remaining 95 bytes of
inactive union storage at `[owner+1057, owner+1152)` are not counted as initialized
payload or individually erased storage. The actual broad placement copies were
bound in the earlier checkpoint, but neither those inactive bytes nor local
copies acquire a clearing guarantee from this constructor model. Separate stack
and retained-page allocations and eventual private-window retirement remain
required. Nonempty cSHAKE constructors, remaining constructor lifetime joins,
four-lane SIMD and complete exceptional/private cleanup are still open.

The [fixed-constructor observation](../assurance/windows-protection-observations/sha3-batch-fixed-start-progress-20261009.json)
records focused regression and saved-image validation without closing package 6.

All fifteen selected constructor and integration tests pass on Linux (89.539
seconds) and Windows (185.099 seconds). Complete three-route saved reports,
regenerated with body-byte mutations, match after parsing; 190 current checker
source bindings were verified. New tests reject 706 instruction changes, 220
deleted transfer steps, forty lifetime/bounds/tag/destruction mutations, nine
alternate-entry/zero-XMM mutations, five placement/destruction prerequisite
changes and an injected integrated failure. The unrelated full predecessor
suite was not rerun. No production implementation, gate or native capture changed.

## Scalar empty-constructor paths (2026-10-09)

The standalone `HardenedCshake128::new_bits` and `HardenedCshake256::new_bits`
helpers are used by the scalar batch image for SHAKE's empty name/customization
case. This is now checked from their actual callers rather than inferred from
their names. The complete object relocation scan permits one direct call to
each helper, plus its two runtime begin/end references. Section aliases are
included in that scan, so address-taking or an interior-entry relocation is not
silently ignored. Runtime extents are compared with the complete helper object
section, not with a function extent derived from the same runtime metadata.

The existing start admission review is replayed. A second, six-entry dispatch
table is bound, and a conservative control-flow graph includes both indirect
dispatches, conditional branches and fallthrough. Backward reachability from
each helper call stops at the empty descriptor's initialization: every path
contains only those initialization/dispatch instructions and the exact call
setup. Alternate entry, intervening writes and predecessor fallthrough reject.
The shared readonly descriptor occupies `[rsp+1648, rsp+1680)` and the disjoint
1,041-byte result occupies `[rsp+1680, rsp+2721)`. Meaningful bit-length bytes
are zero; unspecified descriptor padding is not read on this path.

Each helper's 43 reachable instruction/label positions bind the entire empty
normal path and return. The 1,040-byte local owner is zeroed, its counter copy
and mode byte remain zero, and the full owner is copied to `result+1` before
success tag zero is committed. The private, non-unwinding LLVM ABI
requires a full exclusive result and full readonly descriptors. Runtime
`memset`/`memcpy` semantics and Windows register preservation remain explicit
package-8 prerequisites. Neither temporary owner copies nor caller frames are
claimed individually erased here.

This does not review either helper's nonempty path as a general callable API,
the separate inlined nonempty cSHAKE constructors, or the subsequent state
transfer/lifetime joins. Four-lane SIMD and final private cleanup remain open.
The [empty-constructor observation](../assurance/windows-protection-observations/sha3-batch-empty-progress-20261009.json)
records focused regression and cross-platform saved-image validation separately
from native enclave execution and completion of package 6.

Five new constructor tests, the integrated saved-binding test and four previous
AVX2 constructor tests pass on Linux. The same ten tests pass on Windows
(137.006 seconds). Complete three-route saved reports regenerated with body-byte
mutations match after parsing; 189 current checker-source bindings were checked.
New regressions reject 172 helper instruction deletions/substitutions, 44 caller
instruction changes, seven table mutations, eight alternate-entry/fallthrough
changes, thirteen actual COFF relocation/extent mutations, sixteen ABI mutations,
three admission-prerequisite changes and an injected integrated-review failure.
The unrelated full predecessor suite was not rerun. No production implementation,
release gate or native enclave capture changed.

## AVX2 initial-constructor rebinding (2026-10-09)

The batch image's `State::initial` now explicitly reuses the replayed streaming
constructor review. All 1,123 machine-code bytes, the complete resolved LLVM ABI,
extent kind and 16 relocations match, except for one enumerated compiler table
rename: the output-width table suffix `.216` becomes `.189` at relocation offset
901. No general suffix stripping or relaxed relocation comparison is used.

Both saved images bind their constants to immutable, relocation-free object
data and actual linked read-only bytes. All six KAT comparison constants and
both constructor tables must agree across images. The rate table is additionally
checked against `[144,136,104,72,168,136,168,136]`, and the output-width table
against `[28,32,48,64]`. The called permutation and scratch-wipe helpers must
retain their replayed exact-body/reference/ABI review. The original exact-helper
population is unchanged; this explicit rebinding is reported separately.

Four focused tests and the integrated saved-binding test pass on Linux; the
same five tests pass on Windows (22.562 seconds). Both complete three-route
saved-image reports were regenerated with body-byte mutations enabled and match
after parsing, with 188 current checker-source bindings verified. This pass did
not rerun the unrelated full 99-test predecessor suite. New tests reject every
constructor byte mutation, 64 relocation-field mutations, extent changes, ABI
weakening, missing helper reviews and missing/changed constant bindings. Matching
corruption of the rate or width table in both images is also rejected.

The [initial-constructor observation](../assurance/windows-protection-observations/sha3-batch-initial-progress-20261009.json)
records this partial author-review checkpoint. It does not qualify the batch
caller's constructor arguments, scalar constructors, moved-copy/private-frame
erasure, four-lane SIMD or exceptional cleanup. Shared `memcpy`/`memset` review
remains in package 8. No production code, release gate or native capture changed.
