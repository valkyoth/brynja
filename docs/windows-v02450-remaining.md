# v0.24.50 remaining work

## Current completion checklist (2026-10-08)

- Finish transitive normal-return cleanup qualification inside the remaining
  distinct batch/ParallelHash workers, especially
  indirect SIMD dispatch and deepest caller/stack paths. Both scalar and AVX2
  SHA-3 inner chains are now closed for their saved images (55 scalar functions;
  53 AVX2 main functions plus eight cleanup funclets). Their named shared
  runtime/transport boundaries remain with final reconciliation. Both KMAC
  private chains are also closed, as are both TupleHash private chains.
  All four SHA-2 batch private chains are now closed under their explicit shared
  prerequisites (178 emitted functions, including 33 cleanup funclets). Next
  are the three SHA-3 batch routes, now inventoried with sequential plan,
  lifecycle, state-destructor, initial plan placement, retained-worker entry/close,
  buffer cleanup, request decoding/dispatch/export, sequential update callers
  and widened copy-helper checks,
  followed by ParallelHash; shared cumulative
  stack/runtime/platform qualification remains package 8.
  Scalar SHA-2 runtime/
  export connections are now closed; all seventeen family worker entry,
  transport and direct memory-call boundaries are bound. Those boundary reviews
  do not yet qualify every inner owner/state path.
- Reconcile final compiler/platform, runtime/SDK and loaded-image boundaries
  into the precise supported claim; finish documentation and support matrices.
- Prepare the candidate and obtain independent retest; remediate and test any
  findings. Current offline author reviews are not that retest.
- Complete the existing selected final verification, reusing valid evidence and
  refreshing native evidence only where relevant implementation changes require
  it. Then require green GitHub and explicit authorization to tag/push.

The nineteen image refreshes and scoped dump campaigns are already complete;
the main remaining work is assurance, not reimplementing every algorithm.
Consumer production signing remains a deployment responsibility, not a paid
project-signing prerequisite. Windows ARM64 remains unqualified and must not be
advertised as supported by this x64 development evidence.

## Detailed progress and review scope

The [SHA-3 batch checkpoints](windows-enclave-sha3-batch-chains.md) bind
all 166 emitted bodies across the three routes, including 19 cleanup funclets.
It replays earlier SHA-3 reviews for 30 exact scalar and 23 exact AVX2 helpers,
and check the complete sequential plan validators and identity tables. The
sequential operation/clear/seal/cancel/guard bodies and two broadened copy-helper
ABIs now have explicit instruction contracts. Both state destructors are joined
to those lifecycle methods, and complete `begin` checks bind plan validation,
copying and disjoint owner subobjects. Sequential retained entry/close bodies,
AVX2 resident construction/retirement and buffer cleanup now have full emitted
contracts, conditional on serialized C entry and valid resident allocations.
Scalar page/window non-overlap still relies on that C boundary. Both complete
receivers, decoding, dispatch tables, plan equality and explicit export now have
emitted-code contracts, including AVX2's post-copy authority check. Sequential
updates now preserve the copied input through checked budget admission into
exact, freshly replayed lower absorption helpers; rejection composes typed
cleanup and quarantine. Initial state invariants, setup/finalization operation
bodies and their pointer/lifetime preservation, and the four-message
route's 15 indirect calls, remain
explicit family work. Package 6 is not closed; these method contracts do not
establish whole-worker cleanup, unwind coverage or private-frame erasure.

The final SHA-2 batch composition assigns every private function and frame,
requires the preceding caller/cleanup contracts, binds all indirect transfers
and cleanup metadata, and records distinct typed-field, backing-page and
enclosing-window cleanup responsibilities. It explicitly reproduces both
SHA-NI scalar fallback kernels and assigns all retained fail-stop callsites.
This closes completion package 5's conditional private author review; it does
not qualify the whole image, OS stack window, arbitrary exceptions or an
independent retest. The earlier checkpoints below are historical, superseded by
the [private composition closure](windows-enclave-sha2-batch-chains.md#private-composition-closure-2026-10-07).

The narrow-output checkpoint assigns the last eighteen returning interfaces:
eight final copies, the eight-lane owner-transfer loop, two dynamic error clears,
two identity clears, two scratch clears, scalar/CPU cleanup and the output
destructor. All 62 narrow returning interfaces now have assignments, as do the
previously reviewed 36 wide-child returning calls and 27 wide-parent interfaces.
The final copies use the current source pointers and original bounded widths;
the owner loop advances its returned-descriptor cursor and destination in
lockstep. Descriptor validity is required at the final transfer reads, not just
at construction. Final private-frame/storage composition across all four routes
is still open. Shared SDK/probe implementations and platform/window guarantees
remain package 8; exhausting the interface list is not whole-image qualification.

The narrow-vector checkpoint joins all six vector-loop call interfaces: two
linked cancellation calls, state packing, input-block packing, compression and
state unpacking. It reuses the completed original input/authority, compact-index,
kernel and loop reviews, and checks actual argument slices over 384 bounded
public geometries. Normal helper writes and the twelve-body stack closure are
disjoint from live descriptors, pointer slots, control, typed inputs and compact
indices. That left eighteen narrow output/cleanup interfaces (44 of 62 then
assigned), followed by final private-frame/storage composition across all four
routes. SDK/probe, ABI and OS obligations remain separate; no individual spill
erasure, new native execution or whole-image qualification is inferred.

The narrow-admission/setup checkpoint joins fifteen more sites: operation
admission, three compiled callbacks, two authority checks, owner-output clearing,
the tail predicate, the stack-probe interface and six SDK initialization calls.
Original owner/authority pointers and per-lane input origins reuse the completed
lifetime reviews. Exact helper bodies retain the narrow layout and rejection
tags; setup cannot re-enter after output descriptor construction. That left
24 narrow calls: six vector-loop helpers and eighteen output/cleanup sites.
Final private-frame/storage composition remains open, as do the explicitly
separate SDK/probe, ABI and OS obligations. Production and gate policy remain
unchanged.

The parent-interface checkpoint assigns the last three wide-parent sites:
the bounded tail-byte predicate, all six original child-executor arguments,
and the stack-probe size/placement. All 27 parent call interfaces and all 36
returning child calls now have assignments. The child's helper effects are
joined to the parent's live input descriptors, original output descriptors and
owner slot; its returned-object lifetime still starts only after result admission.
This is not a complete memory/stack-effect qualification: seven SDK/probe calls
remain shared-runtime obligations, and private-frame assignment/erasure is still
open. That checkpoint left 39 narrow-route sites, followed by final private
frame/storage composition across the four routes. Production and gate policy
are unchanged.

The parent-admission checkpoint joins twelve more wide-parent calls: operation
admission, two compiled callbacks, two authority checks, owner-output clearing,
and six fixed SDK copy/fill calls. Complete operation/check bodies preserve the
phase, nonwrapping sequence, health and revalidation failures; successful admission
returns the original owner pointer. Actual caller roots, callback/backend fields,
bounded helper stacks and non-overlap are checked. Setup cannot re-enter after
output descriptor construction. That checkpoint left 39 narrow calls and three parent
sites (stack probing, the tail-mask predicate and child-executor composition).
The six SDK memory-call implementations/stacks remain explicitly in shared
runtime qualification; assigning their private arguments does not close that
work. Final private frame/storage assignments remain open in package 5.

The wide-parent output checkpoint joins ten additional callsites: four transfers
into the admitted protected owner, two output-scratch clears, scalar/CPU wipes
and two output destructors. Actual pointer definitions, same-lane lengths,
unsigned capacity guards and descriptor-drop lifetimes are checked; bounded
indexed initialization cannot silently overwrite the saved owner pointer. The
six-body normal helper-stack closure and mapped writes exclude live descriptors
and that pointer slot. That checkpoint left 39 narrow and 15 wide-parent callsite
joins; the parent-admission checkpoint above further reduces the latter.
Remaining child effects and the shared ABI remain explicit conditions.
No whole-frame erasure or new native execution is claimed.

The wide-output checkpoint completes the saved wide SHA-512 child's normal
call-effect assignments: all 36 returning calls are covered and its one terminal
overflow call remains separately bound to the admitted-input unreachability
proof. This joins all four final copies, dynamic output clearing, identity-only
clearing and the two initial callbacks. Original workspace sources, matching
descriptor capacities/lengths, checked width guards and future saved-slot
preservation are traced through the emitted CFG. This remains conditional on
the recorded parent allocation/descriptor contracts and shared runtime/ABI
guarantees; it does not close whole-frame erasure. That checkpoint left 39 narrow
and 25 wide-parent callsite joins; the later parent-output checkpoint above
reduces the latter. No new native execution or production/gate change is involved.

The normal-helper checkpoint joins 53 returning callsites to concrete descriptor
regions and normal callee-stack bounds: 23 narrow, 28 wide child and two wide
parent calls. This includes all twelve workspace wipe/drop calls with actual
original pointer arguments. Narrow control-counter reuse in the future returned
descriptor area is allowed only when no normal CFG path from descriptor
construction reaches the earlier helper. The report retains explicit unassigned
call inventories (39 narrow, nine wide child, 25 wide parent); these are remaining
composition work, not necessarily previously unreviewed primitive bodies.
Package 5 and whole-frame qualification remain open. Production code and
release-gate policy are unchanged.

The latest overflow/cleanup-order checkpoint also closes the saved wide `.B302`
admitted-input proof and joins preceding caller-side cleanup-handler effects at
all 21 descriptor-related protected calls. Four parent tail-byte publications,
the child scalar index save/restore and the original input pointer are checked
through their actual CFGs. Seven complete handler prefixes and their write
envelopes preserve the live descriptors; wide invoke-time pointer slots are
re-traced rather than assumed valid across phases. Normal indirect helper-effect
composition and the finite private frame/storage assignments still remain in
package 5. OS/ABI handler stacks and runtime guarantees remain package 8.
These are saved-artifact author checks, not new native execution or independent
retest; production source and release-gate policy are unchanged.

The overflow-path checkpoint closes both incoming guards of the saved narrow
SIMD resident's `.B190` panic block, conditional on the completed input/metadata/
allocation reviews and named shared-runtime prerequisites. The iterator remains
in zero through seven at its overflow comparison; the admitted final-byte value
remains in one through seven on the partial-byte path. Neither panic effects nor
arbitrary unwind cleanup are assumed harmless. This is a saved-image author
check, not a new native run or whole-frame qualification. Remaining package-5
work is the other caller prerequisites and enclosing private frame/storage
cleanup composition; release-gate policy is unchanged.

The concrete allocation checkpoint joins both saved SIMD routes' constructor
placement, five metadata writes, fifteen dominating admission edges, and all
fourteen header/payload copy destinations to their live page/worker/caller
storage. Both Win64 modulo-32 entry alignments are checked through normal CFGs;
the caller descriptors/results, resident subobjects and wide child allocations
are concretely disjoint. This closes the conditional private allocation/lifetime
join, not OS residency or whole-window erasure. Shared nonreentrancy, page/window
admission, Win64 ABI and runtime guarantees remain package 8. Next package-5
work, after the later overflow-path checkpoint above, is the other caller
prerequisites and complete private frame/storage cleanup composition. Production
code and release gates are unchanged.

The metadata checkpoint closes conditional input/authority-field preservation
and compact-cursor lifetimes in both saved SIMD routes. It inventories 288
aliases and 298 accesses, assigns 82 helper callsites, and checks all 90 input
reads and sixteen compact-index reads against initialization and invalidation
through normal/unwind control flow. The emitted cursor slots have separate
phase-specific reaching-definition checks, including their earlier/later reuse.
This composes the existing machine geometry and helper contracts, not a general
LLVM proof or, by itself, evidence that separate symbolic roots cannot alias.
The later concrete allocation checkpoint above supplies that conditional private
join. Remaining caller/fail-stop and private-frame cleanup obligations are still
open. Production code, native images and release gates are unchanged.

The narrow pointer-lifetime checkpoint closes the saved SHA-224/256 authority
and per-lane input pointer-definition tracing item. It covers six owner reloads,
eleven authority reloads, twenty authority uses, all eight typed input lanes,
the three distinct slot-112 lifetimes, vector/scalar copy arguments and eleven
potentially unwinding callsites. This is saved-artifact author review, not a new
native enclave run or independent retest. The subsequent metadata checkpoint
above adds conditional field preservation and compact-cursor lifetimes, and the
concrete allocation checkpoint joins private storage placement/lifetimes.
Remaining caller/frame cleanup and shared-runtime obligations stay open.
Release gates are unchanged.

The earlier-phase checkpoint assigns all 34 wide indirect stores and
all six calls, composing their conditional effects with the normal stack bounds.
The local scratch aliases, bounded state-initialization induction, vector-offset
guard, packed-state bases and session argument origins are checked. Three copy
sites have 96 independently replayed public geometry cases. Original input,
compact-index and authority-field lifetimes and physical allocation separation
remain required; package 5 is not closed by conditional footprints alone.

The vector-stack checkpoint adds the complete normal vector/copy/
cancellation callee closure: twelve bodies per SIMD route, including XMM/YMM
stack widths and nested/tail-call return slots. Those stack/home effects exclude
the selected saved slots. Both early wide callbacks retain their original
control-table/data capture under direct CFG definitions; all three earlier
state-pointer uses trace to workspace+512. Earlier indirect argument-write
preservation, physical allocation separation/lifetimes and individual stack
erasure are not inferred from these checks. Package 5 remains incomplete.

The [SHA-2 batch checkpoint](windows-enclave-sha2-batch-chains.md) binds all 178
emitted functions across the sequential scalar/SHA-NI and two AVX2 SIMD routes.
Fifty-two review tests pass on both hosts with matching reports; component, worker
and resident campaigns pass on native Linux. Selected admission, cleanup and
callback-target contracts are checked. Sequential sealing, cancellation,
checked export, operation-guard cleanup, buffer destruction and full-page
retirement are now composed. Fifteen scalar and fourteen SHA-NI helpers reuse
reproduced earlier reviews with exact body/reference/ABI contracts; the changed
SHA-NI finalizer and selected batch-caller preconditions are separately checked.
Slot selection, scalar finalizer input/width/transfer, both update routes, SHA-NI
constructor copies and its finish cleanup funclet are now checked, with fresh
passing scalar/SHA-NI component campaigns. Public IV construction, initial
placement, eight-slot plan admission and the public SHA-NI startup KAT now have
explicit checks, including replayed public-loop comparisons.
Both SIMD sessions, local authority checks, padding helper accounting/clearing
and all 32 invoked cleanup funclets now have semantic checks. All 29 indirect
callsites are inventoried; remaining digest sites now have concrete callback
source/transfer checks. Thirty compiler cleanup tables bind the recorded handler
order. Complete SIMD cleanup routines now cover all declared workspace fields,
including inactive lanes; trailing alignment padding is explicitly not individually
erased. Selected error returns, output/worker-buffer destruction, cancellation
and resident-page retirement are checked. Enclosing storage lifetimes, full
error-entry coverage and general alias composition remain pending.
Both complete AVX2 kernels and all six transpose routines now have semantic,
round-constant, lane-bound and erasure checks. Fresh native AVX2 component
campaigns pass 3,216 narrow and 2,408 wide lane comparisons plus compiled mutants.
Worker entry/buffer bounds, request decoding, private input handoff, exact export
plan matching and successful output clearing now have saved-path checks. Fresh
native worker-double campaigns pass 402/602 oracle cases and fourteen worker
mutants per family. They do not qualify OS-copy behavior or whole-frame erasure.
Both complete SIMD constructors now have checks for public KAT inputs/constants,
all-lane comparison, authority/owner placement and failure-page clearing.
Fresh native resident campaigns pass 402/602 oracle cases, four resident mutants
and eight ownership negatives per family. Startup data is public; incoming
register saves and enclosing-window reclamation remain separate obligations.
Both SIMD digest callers now check typed input admission, canonical tails,
saved guard state, private destination layout, plan/width preservation and
post-result cleanup through retained output publication. The inner lane engine's
preservation of returned destination pointers is not yet qualified.
The final output-commit region now checks all width preflights and copy arguments,
plus byte-exact returned descriptor moves. Exhaustive saved LLVM use checks now
establish descriptor initialization/immutability and original prepared-source
provenance; seventy-three tests pass on both hosts. Composition with emitted
stack-slot lifetimes and indirect memory effects remains pending.
Complete emitted vector-loop regions now bind lane packing, input block bounds,
checked session/report accounting and indexed write-back. Eighty-one tests pass
on Linux and Windows, including 1,548 new instruction/control mutations and
independent geometry/accounting boundary checks. Enclosing compaction, scalar
finalization and live-storage composition remain pending; this is not a new
native enclave run or a whole-frame claim.
Both scalar remainder/finalization regions now have complete emitted checks,
including padding, length encoding, wide variant tables, output masks and
successful per-lane wiping. Eighty-nine tests pass on both hosts; an independent
bit-string model matches all private input bit lengths. Primitive-helper reuse,
enclosing compaction/preconditions and live pointer/frame composition remain;
neither matching primitive bytes nor caller checks alone close those obligations.
Explicit primitive replay now binds four scalar helpers per SIMD route, including
round-table references and strictly named ABI differences. The changed zeroizer
is reviewed separately. Ninety-four tests pass on both hosts with matching
reports. Remaining work is caller/precondition and live-storage composition,
not re-reviewing these unchanged helper instructions.
Public compact-index construction now has bounded emitted-instruction replay
across all 6,561 narrow and 1,296 wide typed identity combinations, with exact
active counts, narrow public IV placement and declared workspace contents.
Ninety-nine tests pass on both hosts, including 32 new compaction mutations;
parsed reports match. Original input/frame preconditions and subsequent index
lifetimes still require composition; this is not a whole-frame qualification.
All 104 direct/tail SIMD zeroizer callers now establish positive lengths:
99 fixed literals and five full-width descriptor guards. One hundred and three
tests pass on Linux and Windows with matching parsed reports; 730 new caller
mutations reject. Dynamic descriptor upper bounds, live storage and pointer
validity remain separate obligations; the broader caller-completion flag stays
false. No production or release-gate change was made.
Descriptor construction now replays all 256 narrow identity combinations and
260 per-lane wide width assignments. Wide field independence is checked before
composing those cases. Exact lane pointers and widths fit disjoint slots inside
256-byte scratch, with other storage unchanged. Propagation through subsequent
machine lifetimes remains open; bounded origins alone do not close all consumers.
All 106 tests pass on Linux and Windows with matching reports, including 77 new
descriptor-origin mutations that bypass earlier literal staging checks.
Direct emitted-frame checks now preserve the first output-pointer cell against
overlapping stores, frame-base changes and direct address exposure, accounting
for alternate stack/frame bases and alignment. Seven indirect stores and 36
calls in those regions remain explicitly inventoried for effect composition;
the complete pointer lifetime is not yet qualified.
All 109 tests pass on Linux and Windows, with matching parsed reports and 41
new frame-cell mutations rejected independently of earlier shape checks.
The seven indirect stores now have conditional bounded write-footprint checks
from their emitted address calculations, with volatile copy-call clobbers and
nonwrapping arithmetic enforced. All 113 tests pass on Linux and Windows with
matching reports, including 22 new address/mask/width mutations. Original object
placement/non-aliasing, intervening call effects and full pointer lifetimes
remain open; these conditional footprints do not discharge those obligations.
Twelve of the 36 calls now compose actual argument registers with the reproduced
wipe/compression/clear contracts. State/block/scratch disjointness and full clear
extents are checked within the assigned objects; 24 other call effects remain.
The twelve conditional checks still require original live-slot/object placement
and callee stack/home-space composition. All 117 review tests pass on both hosts;
47 additional pointer/extent/call mutations reject and parsed reports match.
Ten copy calls and three mask calls now also have conditional argument-region
checks over 6,654 public-geometry cases. Empty copies have no byte accesses;
same-object nonempty copies must not overlap. All 121 tests pass on both hosts,
with matching reports, 79 transfer mutations and four call-population regressions
rejected. Eleven other call effects remain. Original live-object/slot placement,
physical aliasing and callee stack/home-space obligations are not discharged by
these bounded transfer cases.
The 2026-10-07 control/placement checkpoint assigns all 36 calls in those tracked
regions: 35 returning calls have conditional effects; the guarded fail-stop
retains explicit reachability preconditions. Four padding calls include all
workspace/control/report effects, and private callback targets bind to the
actual readonly table. All 35 returning calls and seven indirect stores now
have bounded caller/child-relative placements that exclude the saved pointer
cells. This does not prove original live slot values, external allocation
separation or complete private callee frames. All 130 tests pass on both hosts
with identical parsed reports; no production or release-gate change was made.
Whole-function normal-return ordering now covers both SIMD digests, all eleven
wide dispatch tables and all 40 sensitive-helper sites. Every returning path
after one of those helpers must pass a later full workspace wipe; an earlier
wipe does not suffice, and the two terminal paths are not cleanup successes.
All 134 tests pass on both hosts with matching reports, including 40 injected
post-helper returns, two complete-wipe removals and 22 dispatch mutations.
Original argument/storage validity and full private-frame composition remain
separate from this control-flow ordering check.
The tracked normal callee stacks are now bounded across ten narrow and eleven
wide transitive bodies: allocations, direct stack accesses, save/restore order,
calls, tail transfers and normal exits are checked. Their extents, including
return slots, exclude the tracked saved pointer cells. All 139 tests pass on
both hosts; 92 new saved-body mutations reject. This discharges the normal
private-stack component for those 35 calls, not the argument/slot provenance,
other private frames, arbitrary unwind or individual frame-erasure obligations.
The first prepared source now has a whole-function reaching-definition check:
both final reads require the actual address initializer or explicit absent
value on every path. Three wide reaching definitions all reload the original
workspace argument. All 144 tests pass on both hosts, including 21 new saved
origin/bypass/overwrite mutations. This is direct CFG provenance, still
conditional on indirect memory effects, original allocation lifetime and ABI
preservation; it is not a complete physical pointer-lifetime qualification.
Six further wide helper slots now have direct CFG origins through their last
ten helper reload sites, as do all 40 input-pointer and twelve executor-pointer
reloads. Two computed stack-store ranges and both scalar wipe arguments are
checked. The tracked call/store/private-stack effects exclude all eleven saved
argument/source slots. All 151 tests pass on both hosts with matching reports;
89 emitted mutations and fifteen effect mutations reject. Earlier vector-phase
effects on slot 984, external separation and original physical lifetimes still
need composition; the narrow per-lane origins remain separate work.
**Step 5 remains in progress**: remaining caller preconditions,
enclosing constructor cleanup, SIMD enclosing lane-engine and normal error-path composition,
and private frame/storage assignments remain explicit obligations.

The [TupleHash chain review](windows-enclave-tuple-chains.md) binds both complete
saved populations (52 scalar functions; 55 AVX2 main functions plus six cleanup
funclets), kernels, constants, helper ABI reuse and wrapper/transport targets.
Item framing, bit packing, phase/sequence admission, setup/rehash, finalization,
readers, export, error/funclet cleanup and full page retirement pass fourteen
review tests on both hosts with matching reports. Scalar/AVX2 component,
resident, worker, host-wire and focused Miri campaigns pass. **Step 4 is closed**
at private-family scope, with explicit function/frame assignments and scalar
fail-stop caller preconditions. Shared runtime/SDK and whole-window reclamation
remain in step 8; the review does not qualify the whole image. SHA-2 batch is
the current finite family package.

The [KMAC chain review](windows-enclave-kmac-chains.md) now binds both saved
workers (84 scalar functions; 64 AVX2 main functions and thirteen cleanup
funclets), complete kernels/constants, tag comparison, suffix/key completion,
worker-buffer cleanup and actual wrapper/transport destinations. Nineteen
review tests pass on both hosts with matching reports, alongside the existing
component, oracle, mutation and focused Miri campaigns. Helper ABI reuse and
explicit prefix specializations, widened bit-XOR ranges, retained-key ordering,
scalar constructor/reader transfers and all thirteen invoked cleanup funclets
are now checked. The final lifecycle composition adds phase/sequence admission,
setup/update/finalization error cleanup, terminal-reader wipes, full resident-page
retirement and explicit storage assignments for every private frame. KMAC's
**private package is closed**, with no unassigned family path. Shared runtime
depth, SDK boundaries and complete stack-window reclamation remain in final
reconciliation; this is not whole-image qualification.

The [AVX2 SHA-3 chain completion](windows-enclave-sha3-avx2-chain.md) binds all
emitted functions, three dispatch tables, authority/owner lifetimes and the
complete opaque kernel. Both hosts pass ten new review tests with matching
reports; all 254 saved build inputs match. Native Linux AVX2 component, resident,
worker and focused placement-only Miri campaigns pass. The local bound is
`H-12380`, excluding shared runtime frames. Incoming nonvolatile saves and
compiler-created aggregate copies still require whole-window reclamation in
final reconciliation. No private SHA-3 inner-path item remains unassigned.

The [scalar SHA-3 chain completion](windows-enclave-sha3-chain.md) composes the
prior reviews, adds the complete permutation and buffer destructor, and checks
every emitted function and actual inner reference. All 158 saved build inputs
match the checkout. Both hosts pass 88 focused review tests and produce matching
reports. The local frame contribution is conservatively bounded at `H-8568`,
excluding shared runtime frames; this is not maximum whole-image depth. The
eight remaining runtime/transport boundaries are explicitly assigned, not waived.
SHA-2 batch is the next family package. The entries below
retain their historical scope and are superseded by this composition where
they identify scalar inner functions as still pending.

The [streamed cSHAKE setup review](windows-enclave-sha3-setup.md) binds all six
rate-specific push/bit/advance bodies, failure cleanup and exact completion.
Eight tests and matching reports pass on both hosts, rejecting 2,537 body-byte
mutations each; four actual Rust setup tests pass. Scalar permutation internals,
the public remainder runtime helper and maximum whole-image depth remain open.

The [terminal cSHAKE output review](windows-enclave-sha3-terminal.md) binds both
scalar adapters, exact initialization, partial-byte masking and admitted-path
owner/output cleanup. Nine tests and matching reports pass on both hosts,
rejecting 1,452 body-byte mutations each; the Rust sponge and worker/oracle
campaigns also pass. Streamed setup helpers, scalar permutation internals and
maximum whole-image depth remain open. Earlier progress entries below retain
the scope of their own reviews, extended by subsequent entries.

The [scalar finalization/squeezing review](windows-enclave-sha3-finalize.md)
adds six rate-specific finalizer, typed-squeeze and cSHAKE transition bodies.
Nine review tests and matching reports pass on both hosts; each rejects 3,712
body-byte mutations. Nine actual sponge tests and the worker/oracle campaign
pass. Terminal output adapters, scalar permutation internals and maximum
whole-image depth remain open.

The [scalar sponge-update review](windows-enclave-sha3-update.md) covers all five
rates, counter admission, buffered/direct/tail partitioning and ten immediate
permutation-scratch erasure sites. Eight tests and matching reports pass on both
hosts; each rejects 3,801 body-byte mutations. Actual owner tests pass. Scalar
finalization/squeezing, permutation internals and maximum whole-image depth
remain open.

The [scalar cSHAKE prefix review](windows-enclave-sha3-prefix.md) adds both
rate-specific string/bit-packer chains, bulk versus partial-bit paths, checked
flush accounting and constructor-dependent error cleanup. Eight tests and
matching reports pass on both hosts, with 1,202 body-byte mutations rejected
each. Actual Rust prefix tests and the worker/oracle campaign pass. Sponge and
permutation internals and maximum whole-image depth remain open.

The [scalar SHA-3 transfer/output review](windows-enclave-sha3-transfers.md)
adds ten private helpers, exact initialization/publication, copy/bit/mask
contracts and public-length encoding. Nine tests and matching parsed reports
pass on both hosts; each rejects 756 body-byte mutations. Actual Rust helper
tests and the component/oracle campaign also pass. Prefix/sponge/permutation
internals and maximum whole-image depth remain open.

The [scalar SHA-3 state review](windows-enclave-sha3-state.md) adds construction,
fixed-output consumption and XOF dispatch, with both exact tables and all fifteen
inlined permutation-site scratch erasures checked. Eight tests and identical
parsed reports pass on Linux and Windows; 10,496 body-byte and 48 table-byte
mutants are rejected per host. The existing component/oracle campaign also
passes. The subsequent transfer/output review above extends its helper coverage;
transitive sponge/prefix/permutation helpers and maximum whole-image depth remain
open.

The [scalar SHA-3 owner operation review](windows-enclave-sha3-operations.md) now
binds nine owner operations and the actual receiver, including streamed setup,
finalization, retained rehash, squeeze and public export. Ten tests and identical
parsed reports pass on Linux and Windows; each host rejects 10,191 body-byte and
160 table-byte mutations. The component/oracle campaign also passes. Compiler-
created state copies still depend on full-window reclamation; transitive state/
sponge/prefix callees and maximum whole-image depth remain open.

The [scalar SHA-3 lifecycle review](windows-enclave-sha3-lifecycle.md) now binds
cancellation, quarantine, active-state destruction, all thirteen sponge erasure
regions and enclosing page teardown. Ten tests and identical reports pass on
Linux and Windows, rejecting 774 body-byte and 32 dispatch-table byte mutations
per host. The existing component campaign also passes seven component tests,
one placement test and ten compiled mutants. The subsequent owner review above
extends these paths; deeper callees remain open, not whole-image qualified.

The [SHA-NI owner/decoder review](windows-enclave-sha-ni-owner.md) completes this
selected route's normal-return owner paths, including all four width tables,
partial-bit validation and the actual request decoder. Eight review tests pass
on both hosts with identical reports; 3,083 body-byte and 112 table-byte mutants
are rejected per host. The existing Linux component/placement campaign also
passes thirteen tests, rejects eighteen compiled mutants and thirteen ownership
negatives. Bound cleanup funclets do not establish arbitrary OS-unwind behavior;
remaining whole-image/runtime and other-family obligations are unchanged.

The [SHA-NI engine/session review](windows-enclave-sha-ni-engine.md) now covers
the selected normal update/finalize/padding paths, startup self-test, session
dispatch and opaque kernel cleanup. Ten tests pass on each host, with identical
reports and 2,903 body-byte plus 20 dispatch-byte mutations rejected per host.
Five existing Rust engine tests also pass on Linux. Selected startup depth
reaches `H-13928`; length spills and saved caller registers remain dependent on
window clearing. Complete owner/decoder semantics, other families and maximum
whole-image depth are still open.

The [SHA-NI state review](windows-enclave-sha-ni-state.md) now binds the saved
constructor/finalizer, their owner call edges, two IV constants and private copy
helpers. Eight tests pass on Linux and Windows with identical parsed reports;
2,286 actual body-byte mutants are rejected per host. Selected constructor depth
reaches `H-13504`; saved XMM6 and moved copies still require enclosing-window
clearing. Engine/KAT internals, complete owner-operation semantics and maximum
transitive depth remain open; this is not whole-image qualification.

The [SHA-NI lifecycle/receiver review](windows-enclave-sha-ni-lifecycle.md) now
binds admission, cancellation, quarantine, resident construction/destruction and
scratch clearing, plus receiver bounds, dispatch tables and explicit public
export. Eleven tests and identical parsed reports pass on Linux and Windows;
1,976 body-byte and 52 table-byte mutants are rejected per host. Review records
the moved enum's dependence on outer-window/page clearing and the compiler's
private bounded-input precondition. Inner state/engine callees and maximum
transitive depth remain open; this is not whole-image qualification.

The extended [worker reconciliation](windows-enclave-worker-reconciliation.md)
closes forty scalar SHA-2 memory calls and its five transport connections,
rebinds memory runtimes in all eighteen sequential images, and covers 102 C
adapters, 36 Rust boundary bodies, 97 direct transport calls and 590 memory calls
in 175 caller bindings across the seventeen family workers. Twenty-three new
focused tests pass on both hosts with identical parsed reports. All ten existing
accelerated/SIMD worker campaigns passed again, rejecting 233 compiled mutants;
the SIMD campaigns passed 1,524 oracle cases. Whole-image qualification remains
open: source lifecycle review and exact call binding do not substitute for the
remaining transitive machine-code/stack/indirect-dispatch obligations.

Current implementation status: the bounded SHA-256, scalar SHA-2/SHA-3/KMAC/TupleHash
streaming, SHA-2/SHA-3 batches and sequential scalar ParallelHash Windows enclave
APIs are integrated and development-tested. Explicit opt-in SHA-NI SHA-224/256
sessions now have native debug/release host coverage. The explicit AVX2 routes
and bounded concurrent ParallelHash API have subsequent development coverage;
see the [current acceleration status](windows-enclave-acceleration.md) and
[crate-integrated concurrent API](windows-enclave-parallel-concurrent.md).
Existing Linux-style host-slice
sessions still reject Unsupported on Windows. Broader algorithms and production
qualification remain incomplete. The release scope
remains the [Windows strict protected profile](windows-strict-profile.md), with
explicit acceleration and unchanged release-gate policy.

Latest cross-image step: the [shared sequential C review](windows-enclave-sequential-c-review.md)
binds four complete common functions across all eighteen sequential images,
including chained runtime fragments, wrapper callees and named SDK imports.
Six focused tests and identical saved-artifact reports pass on Linux and Windows.
The subsequent [helper review](windows-enclave-sequential-helpers.md) binds eight
shared called C bodies across those images; six focused tests and matching
reports pass on both hosts, including 1,028 actual-template byte mutations.
Distinct retained Rust workers still need reconciliation; this does not transfer
worker semantics or claim whole-image qualification.
The next [bounded SHA-256 dispatcher review](windows-enclave-bounded-dispatch.md)
now binds its retained lifecycle, exact jump-table destinations and clearing
helper to the saved bounded image. Six tests and matching reports pass on both
hosts. The subsequent [borrowed-input caller review](windows-enclave-bounded-input.md)
binds the bounded `hash`/`receive` bodies, admission/cleanup return paths and known
frames; six tests and identical reports pass on both hosts, rejecting 3,366 actual
body-byte mutations. The [rehash caller review](windows-enclave-bounded-rehash.md)
now adds the emitted token, generation, commit and cleanup paths; six focused
tests and matching reports pass on both hosts, with 2,284 actual-body mutations
rejected per host. The [owner-clearing review](windows-enclave-bounded-owner.md)
now binds placement hashing and all eight workspace-clearing regions; seven
focused tests and matching reports pass on both hosts, with 587 actual-body
mutations rejected per host. The [SHA-256 operation review](windows-enclave-bounded-sha256.md)
now binds update/finalize, scalar compression and both copy helpers, including
their linked constants and local call depth. Eight focused tests and matching
reports pass on both hosts; 1,798 actual body-byte mutations are rejected per
host. The [bounded callback review](windows-enclave-bounded-callbacks.md) adds
seven input-copy, observer and reset/readout bodies, exact metadata placement,
Rust call edges and the named SDK inbound-copy connection. Nine focused tests
and matching reports pass on both hosts, rejecting 798 actual-body mutations.
The [cross-copy/export review](windows-enclave-bounded-export.md) adds six linked
C/Rust bodies, public-token/report bounds, exact SDK copy directions and the
existing Rust failure cleanup. Seven focused tests and matching reports pass
on both hosts, rejecting 420 actual body-byte mutations. The
[bounded memory-runtime reconciliation](windows-enclave-bounded-memory.md) now
binds four runtime bodies, twenty relocation operands, eight dispatch tables
and five actual Rust calls. Nine tests and matching reports pass on both hosts,
rejecting 2,617 actual body-byte and 512 table-byte mutations per host. Live
runtime-selector initialization and the other Rust workers remain open; this
is not whole-image qualification.
The [scalar SHA-2 streaming entry review](windows-enclave-sha2-stream-entry.md)
now binds its distinct worker, receiver and buffer destructor, six-operation
table and complete header/payload readback. Eight tests and matching reports
pass on both hosts, rejecting 1,217 actual body-byte and 24 table-byte mutations.
Its transitive owners/copy adapters and the separate accelerated worker remain
explicitly unqualified by this entry review.
The subsequent [scalar owner lifecycle review](windows-enclave-sha2-stream-lifecycle.md)
binds admission, quarantine, cancellation and destruction to the reviewed
workspace wipe. Seven tests and matching reports pass on both hosts, rejecting
714 actual body-byte mutations. It records the nonzero-sequence compiler
precondition and the original inactive owner bytes' dependence on full-page
teardown. The subsequent [scalar operation caller review](windows-enclave-sha2-stream-operations.md)
binds begin/update/finish/rehash/export, their six algorithm tables and explicit
quarantine/staging/export cleanup paths. Eight tests and identical reports pass
on both hosts, rejecting 2,573 body-byte and 168 table-byte mutations per host.
The [state construction/consumption review](windows-enclave-sha2-state-review.md)
now adds the constructor and state finalizer, nine dispatch tables, five constant
regions and explicit compiler preconditions. Nine tests and matching reports
pass on both hosts, rejecting 5,838 body-byte and 252 table-byte mutations per
host. The subsequent [primitive review](windows-enclave-sha2-primitives.md) now
binds twelve update/finalize/compression/output/copy/mask bodies and both round
tables to this image. Nine tests and identical reports pass on both hosts,
rejecting 3,731 actual body-byte mutations. Scalar runtime/export connections
and other workers remain; selected helper review is not whole-image qualification.

The next qualification item is [final-image ABI/register/spill and dump
cleanup](windows-enclave-whole-image-cleanup.md), followed by independent retest.
The latest [loaded SDK observation](windows-enclave-loaded-sdk.md) matches all
121,931 saved `.text` bytes inside a separate native diagnostic enclave, with
three rejection controls and eight regressions per host. It does not qualify
other SDK sections or retrospectively bind the nineteen application images.
The subsequent [current-image dump campaign](windows-enclave-current-image-dumps.md)
adds 72 observations across the eighteen unchanged sequential images, with real
ordinary-memory controls and confirmed cleanup. Together with the six existing
concurrent-image observations, all nineteen current images now have scoped dump
evidence at their explicitly different checkpoints. All eighteen sequential
images also bind to the tested clearing wrapper's exact bytes. Whole-image
caller/runtime qualification remains separate; these results do not add
arbitrary-exception, fatal-path, mid-compression or production-signing guarantees.
The 2026-10-05 [slot lifecycle review](windows-enclave-slot-cleanup.md) adds four
linked ParallelHash bodies: worker result/error cleanup, its retained funclet,
root consumption and four-slot destruction. Seven focused regressions and the
exact-image review pass on Linux and Windows. Two separate compiler-generated
state copies are mapped into the worker's cleared window; they are not claimed
individually erased by the active-owner destructor. Remaining caller/state/runtime
semantic review and independent retest are the next tasks, not another rerun of
the completed image-refresh/dump campaigns.
The subsequent [direct state-destruction review](windows-enclave-slot-cleanup.md#direct-state-destruction-chain)
now closes that normal cleanup call chain in the saved scheduler image. State
drop, memory wipe, scratch wipe and the volatile byte clearer are bound together;
eight focused tests and 495 actual-body byte mutations pass on Linux and Windows.
The modeled owned writes distinguish volatile secret erasure from public metadata
stores and padding. Construction/update/finalization, root/wave/publication paths
and cross-image/runtime reconciliation remain; no whole-image claim is added.
The following [publication join/drop review](windows-enclave-slot-cleanup.md#publication-join-and-destruction)
now accounts for its three emitted bodies and eleven pointer/length clearing
stores. Seven review regressions, 919 real-body byte mutations and ten existing
Rust gate tests pass on Linux and Windows. The subsequent
[reduction/retirement review](windows-enclave-slot-cleanup.md#ordered-reduction-and-generation-retirement)
now accounts for the copied-input root's normal reduction/reuse ordering and
both Rust/native generation retirements. Seven review tests pass on both hosts;
the real C gate baseline and fourteen compiled mutants pass on Linux. State
construction/update/finalization, full root terminal cleanup and cross-image/runtime
reconciliation remain outstanding. These reviews do not claim payload erasure
from metadata stores or fatal-exit cleanup.
The subsequent [root owner terminal review](windows-enclave-slot-cleanup.md#root-owner-finalization-export-and-destruction)
now accounts for owner-level finish/export/destruction and suffix-scratch clearing.
It binds six saved bodies and their cleanup calls, while keeping the state
update/finish/squeeze callees explicitly unresolved by this review. Component
oracle, cleanup mutations and ownership tests supplement the machine-code
inspection; no new enclave image campaign is claimed. Next are state construction
and operation internals, outer-root/SDK terminal reconciliation and other images.
The subsequent [state-operation adapter review](windows-enclave-slot-cleanup.md#state-operation-adapters-and-staged-output)
now covers update, XOF finalization, terminal squeeze and Core clearing/destruction
in five saved bodies. Four review tests and 1,452 body-pin mutations pass on both
hosts; separate native AVX2 component tests pass eleven tests, twenty-one compiled
mutants and six ownership negatives per host with identical source hashes.
The distinction between memory cancellation and scratch destruction is explicit.
Next are construction and deeper engine/helper internals, then outer-root/SDK
return handling and cross-image reconciliation; completed enclave campaigns remain
valid for their recorded scope and were not repeated.
The following [engine and transfer-helper review](windows-enclave-slot-cleanup.md#engine-operations-and-transfer-helpers)
now accounts for absorb/finish/read loops and their byte-transfer adapters in
the same saved scheduler image. Six inspector tests and the seven existing
native AVX2 engine tests pass on both hosts. The review explicitly preserves
caller cancellation for private absorb and staged-output cleanup for a late
read error; relative frames do not establish transitive stack bounds. Construction
and prefix setup, permutation-session reconciliation and root/SDK return handling
are the next boundaries before cross-image reconciliation and independent retest.
The subsequent [constructor/prefix review](windows-enclave-construction-cleanup.md)
binds seven more saved bodies, the complete startup KAT constants, specialized
rate table and padding buffer. Five inspector tests and identical records pass
on both hosts; 3,226 body-pin mutations are rejected. The unchanged native
component campaign is reused after checking all 240 source hashes. Inline root
prefix initialization, remaining session/runtime callees and outer-root/SDK return
handling remain open; this does not qualify every constructor or image family.
The following [root initialization review](windows-enclave-root-setup.md) closes
that selected inline-prefix step: bounded root inputs, exact domain name/rates,
encoding, returned-error destruction and compiler-moved regions are now traced
in the original image. Seven inspector/model tests and identical saved-image
records pass on both hosts. Runtime callees, remaining permutation-session work,
outer-root/SDK returns and cross-image reconciliation remain; whole-image cleanup
is not yet qualified and the completed native campaigns were not repeated.
The following [session/runtime review](windows-enclave-session-runtime.md) now
accounts for the static permutation session, its linked kernel, public remainder
and stack-probe frames. Ten inspector/model tests and four native Keccak tests
pass on both hosts, with identical saved-image reports. The kernel's ABI saves
are restored, not individually erased; the enclosing normal-return window remains
necessary. Memory-runtime dispatch, outer-root/SDK return handling and cross-image
reconciliation are next, without repeating completed enclave/dump campaigns.
The subsequent [memory-runtime review](windows-enclave-memory-runtime.md) binds
the copy/fill bodies, REP tails and eight dispatch tables, with eight focused
tests passing on both hosts. Exact saved-image reports match; modeled forward
spans stay in range for the tested bounded lengths and alignments. These helpers
do not erase volatile payload registers or their restored save slots. Outer
return/SDK reconciliation and other image families remain; completed native
campaigns and the release-gate policy are unchanged.
The following [outer-root return review](windows-enclave-root-return.md) binds
input completion, native completion/output admission, staging cleanup and normal
success/error return paths in five saved bodies. Seven focused tests and 4,131
actual-body byte mutations pass on both hosts, with identical parsed records.
Host copying is explicitly nontransactional, and failed export stays reserved.
The root's normal-return cleanup is now traced; SDK/output-return reconciliation
and other image families remain before independent retest. No native campaign,
production code or release-gate change was needed for this offline review.
The subsequent [SDK output-return reconciliation](windows-enclave-sdk-return.md)
binds the saved root's import thunk and named IAT entry to the saved SDK's actual
export, syscall and status-tail paths. Six new regressions pass on both hosts,
with matching reports; the existing SDK review suites pass on Linux. This closes
that selected saved-file linkage, not runtime IAT attestation, kernel storage or
exception cleanup. Final C-body/wrapper handoff and other image families remain.
The following [clearing-wrapper handoff review](windows-enclave-wrapper-return.md)
now closes that selected normal-return step. Five tests pass on both hosts with
identical reports; the original wrapper probe's source/artifact hashes and its
32 baseline/208 rejected/80 control cases revalidate separately from an older
host-test record whose source changed. All eighteen sequential wrapper bindings
still match. Their distinct caller/storage paths and final scope reconciliation
remain before independent retest; no completed native campaign was rerun.
A native public-sentinel probe identified missing wrapper register clearing;
both wrappers now clear the volatile return boundary, with ABI-preservation and
compiled omission tests plus two rebuilt native VBS routes. A separate instrumented
VBS campaign now verifies frame/reply/shadow placement for 270 active callbacks
across 31 scheduler cases, with compiled measurement controls. A further
instrumented register campaign covers 552 active VBS callbacks, all sixteen
XMM/YMM registers and eleven non-argument GPRs, with direct positive and compiled
omission controls. No four-byte test pattern was observed at host callback entry on the tested
Windows build; this is not a universal register-erasure guarantee. Six scoped
full-WER-dump observations now cover the unchanged concurrent scheduler image:
root admission, a five-window worker barrier and completed public output, with
ordinary-memory positive controls. No enclave-reservation bytes were included in
those dumps; raw dumps were deleted in the guest. This does not qualify SDK/caller
spills or other images. All 66 selected caller identities in the saved
uninstrumented image are now accounted for, including interior destructor
funclets and reference-disambiguated panic helpers. Handler metadata is bound
to the objects, not qualified for safe unwinding or erasure. A selected seven-body
caller review now maps fifteen saved-register/reply spans into the cleared window,
with six geometry regressions passing on Linux and Windows. A subsequent
[saved SDK-file review](windows-enclave-sdk-frames.md) maps the transition's
nonvolatile register saves and copy-entry frames into that window; six additional
tests pass on Linux and Windows. The subsequent SDK status-helper review binds
six more bodies and maps fifteen selected spills/home slots; eight regressions
pass on Linux and Windows. It explicitly identifies thread-relative status
writes and stops at the deeper diagnostic callee. A further saved-file extension
now binds eight diagnostic/formatter-adapter bodies and models all four bounded
retry capacities; eight more regressions pass on Linux and Windows. Deeper
formatting, exception/fatal helpers and stack-probe page addresses remain
unqualified; these are not a transitive stack-depth or unwind proof. A formatter
extension now binds ten further ranges and maps its scratch/output-helper frames;
seven regressions and 3,030 real-body byte mutations pass on Linux and Windows.
The conversion/context extension binds five further bodies and the observed
invalid-argument context destination; eight regressions and 641 real-body
mutations pass on Linux and Windows. The saved SDK's conversion leaf rejects;
thread-relative error writes and guarded diagnostic re-entry are documented.
The runtime-adapter extension adds nine ranges, including lookup/unwind entry
frames and the context-flag helper chain; eight regressions and 1,718 actual-body
mutations pass on Linux and Windows. Deeper cache locking, directory parsing,
the unwind engine and exceptional/fatal callees still have no transitive bound.
A subsequent directory extension accounts for five fixed-frame bodies and
eleven selected spans per origin; seven regressions and 668 real-body byte
mutations pass on both hosts. The header call disables optional size checks,
so this is deliberately not a malformed-image safety or exception-path proof.
The ordinary directory frames are accounted for; cache slow paths and the
unwind/exception/fatal boundaries remain unfinished.
A subsequent locking extension binds nine ranges and thirteen selected spans;
eight regressions and 1,216 real-body mutations pass on Linux and Windows.
It accounts for ordinary cache-lock frames, including queue tail-call reuse,
and records publication of the stack wait node through shared lock state.
Node reclamation and concurrency are not thereby qualified. The invalid-unlock
status raiser is recursive: only its first frame is mapped, with no finite
transitive bound. Unwind/exception/fatal cleanup remains unfinished.
The subsequent [unwind-engine review](windows-enclave-sdk-unwind.md) binds
three ranges and a read-only slot table, including the caller-owned flag slot.
Eight regressions pass on both hosts; 2,417 body-byte and eleven table-byte
mutations are rejected. Its fixed frames are accounted for, not its complete
decoder or exception behavior. The epilogue interpreter and opcode decoder
remain the next normal-path boundaries.
The subsequent decoder review now accounts for both fixed frames, their reused
home slots and selected scalar/vector writes into the known captured context.
Nine regressions and 2,534 actual-body byte mutations pass on Linux and Windows.
No additional ordinary callees were introduced by those two decoders. Generic
unwind correctness, arbitrary context/metadata bounds and exception cleanup
remain unqualified; the next work is the exception/fatal boundary and broader
whole-image qualification.
The subsequent [exception/fatal storage review](windows-enclave-sdk-unwind.md#exception-and-fatal-storage-boundary)
now binds those two bodies and their syscall stubs: ten regressions and 929
actual-body byte mutations pass on Linux and Windows. It accounts for selected
fixed frames while leaving runtime-sized context writes unknown, and explicitly
places fatal register capture in SDK globals outside the clearing stack window.
Extended-context helpers, exception dispatch/restore and fatal diagnostic
callees remain unqualified. This does not add arbitrary exception or fatal-path
cleanup guarantees; no production code or release-gate policy changed.
The subsequent [context-helper review](windows-enclave-sdk-unwind.md#context-sizing-initialization-and-selected-capture)
accounts for size/initialization frames and the selected capture entry. Ten
regressions and 1,280 byte mutations pass on Linux and Windows. Conditional
layout models retain DWORD wrap and reject malformed-table write-fit claims;
they do not establish live OS feature-table values. The capture entry saves
nonvolatile registers, not full extended state. Exception dispatch/restore,
fatal-path disposition and whole-image qualification remain open.
The subsequent [dispatch/restore review](windows-enclave-sdk-unwind.md#dispatch-restore-and-external-continuations)
binds seven additional ranges; eight regressions and 2,469 byte mutations pass
on Linux and Windows. It accounts for selected fixed/context-copy spans and
tail-call reuse, while retaining unknown handler/callback targets and IRET
continuations. Stack-bound/progression, context-copy and alternate-unwind
helpers remain direct review boundaries; no general exception-cleanup or
finite recursive-depth claim has been added.
The subsequent [direct helper review](windows-enclave-sdk-unwind.md#direct-dispatch-helpers)
now accounts for those four bodies, with eight Linux/Windows regressions and
724 actual-byte mutations rejected per host. The point-versus-range distinction,
selected context writes and adapter/engine flag alias are regression-tested.
No further unreviewed direct callees arise from these helpers. Fatal diagnostic
behavior, external handlers and arbitrary exceptions remain outside a cleanup
guarantee; loaded-module and broader whole-image qualification remain open.
Loaded-module identity,
kernel storage and remaining SDK paths remain unqualified. This is not whole-image stack-depth or cleanup
proof. Seven additional no-unwind helpers are now byte-bound and reviewed,
completing the primary Rust object's 64-function identity inventory (73 entries
with the selected C functions). This is not all linked runtime/library code.
The old SHA-256 and SHA-512 SIMD images have now been rebuilt with the clearing
wrapper and passed fresh component/worker mutations plus native campaigns
(302 and 318 calls). Their signed bytes bind the reviewed wrapper. Fresh
[public-host campaigns](../assurance/windows-protection-observations/simd-host-refresh-20261004.json)
now pass debug/release against those SHA-2 images and the refreshed Keccak image:
403 eight-lane SHA-224/256, 559 four-lane SHA-512-family and 521 four-lane Keccak
batches per profile, plus lifecycle tests and scoped Clippy. Positive execution
uses internal development transport; production constructors still reject the
development signatures. This does not replace remaining-image dump qualification.
A [four-stream manifest review](../assurance/windows-protection-observations/stream-refresh-inventory-20261004.json)
identified older wrappers in the saved SHA-NI SHA-2, AVX2 SHA-3, KMAC and TupleHash
streaming images. The subsequent [streaming refresh](windows-enclave-stream-refresh.md)
now covers SHA-2 and SHA-3: rebuilt images, native VBS campaigns and debug/release
host tests pass with the reviewed wrapper. The subsequent KMAC/TupleHash refresh
also passes native execution and debug/release host tests (546/230 cases per
profile), with exact wrapper binding. All four accelerated streams are refreshed;
other affected images still need reconciliation. Three incomplete TupleHash
attempts are excluded; its corrected test harness passes on Linux and Windows
without changing production code, the timeout or release-gate policy.
These are distinct from the three multibuffer images. The subsequent scalar
streaming refresh also passes debug/release native host campaigns for SHA-2,
SHA-3, KMAC and TupleHash (631/1,028/546/230 cases per profile), with exact wrapper
binding. The subsequent sequential batch and ParallelHash refresh adds six
images with debug/release native host campaigns and scoped Clippy passing.
The final bounded SHA-256 refresh also passes debug/release native host tests,
including rejection of a mismatched hash before signature verification.
The [completed public-opening-route snapshot](../assurance/windows-protection-observations/current-image-routes-complete-20261004.json)
counts all 19 current module-root `Session::open*` routes with recorded
development refresh coverage. Only the bounded native test's image pin and
negative assertion changed; earlier observations retain their historical source
snapshots, not a claim of a new whole-candidate rerun.
This is a source-bound checklist, not a new gate or whole-image qualification.
Whole-image caller/spill and runtime review and independent retest are
unfinished. Current public-route image refresh and scoped dump coverage are
complete, as recorded at the top of this page. The
chronological development entries below retain their original scope and should
not be read as a current claim that the concurrent crate API is still absent.

Distribution follows the [consumer-managed deployment model](windows-enclave-deployment.md):
Brynja supplies source/APIs/build and verification tooling; the application
publisher supplies production signing and deployment. Development can proceed
without a Brynja-owned signing subscription. This does not qualify production
execution or waive implementation, runtime checks, pentest or existing gates.

## Next implementation boundary

The image-admission and bounded SHA-256 owner/session integration items are now
implemented. `brynja_strict::enclave` supplies public production-policy
construction, lifetime-bound retained results, rehashing, cancellation,
transactional public output and fail-closed cleanup. The shipping host adapter
is Rust; no consumer-supplied driver or development bypass is exported. See the
[API and limitations](windows-enclave-owner.md). The historical steps below
describe how the worker was developed, not outstanding constructor work.

- Build on the completed fixed-public-vector native retained-owner experiment;
  it now covers placement, cross-return digest retention and destruction before
  unlock/free, but is not a production API or general residency qualification.
- Build on the connected native affine borrowed-input host and retained worker.
  They now cover actual input copying, private epochs, retained digest ownership,
  cleanup before public output, abandoned/forgotten handles, startup failures,
  copy rejection, simulated lost completion and deletion failure. A fixed
  secret-to-secret SHA-256 rehash operation now also passes two native worker/host
  campaigns, including chaining, generation/replay rejection and seven compiled
  mutant controls. It exposes no enclave-private memory as host slices. These
  campaigns still use bounded public test data, not a production confidential API.
- Native injected prefix-copy cleanup now covers all 33 header and 1,025 payload
  boundaries, followed by quarantine rejection and confirmed destruction. This
  uses a controlled failure after successful OS copying, not an observed OS
  partial-copy failure. Two-live-enclave routing now also passes native foreign
  token tests in both directions, unchanged-origin oracle checks, stale owner
  epochs and all four token-field mutations.
- The affine host now uses checked, nonrecycled process-local receipt IDs rather
  than allocation addresses. Forced address reuse, stale receipts, terminal
  close, exhaustion and concurrency have focused tests; two native campaigns
  pass against the unchanged image. This does not make the enclave's separate
  mapping-address token identity persistent or authenticated.
- These boundaries now have a crate-integrated lifetime-bound enclave owner and
  facade. Enclave mapping addresses can still repeat across destruction/recreation
  or processes; stale handles must never cross those lifetime boundaries.
  Diagnostic metadata exports are not shipping APIs.
  The current experiments are not a production operation protocol or general
  residency qualification.
- A concrete retained-output facade candidate now passes local ownership/surface
  checks and two native campaigns. It supports bounded SHA-256, retained rehash,
  explicit public declassification and cancellation without generic drivers or
  host secret slices. Its constructor stays private to the fixture: production
  integration of admission and public construction is now implemented separately
  in the crate API; independent review remains required.
- The bounded x86-64 image-admission component and consumer workflow are now
  implemented and development-tested: compiled trusted identity/hash policy,
  bounded PE/import parsing, held file handles, separate development/production
  profiles and Windows trust/load/initialization checks. Native tests prove
  development success, production rejection of the untrusted test certificate,
  and OS rejection of wrong import identities/versions at initialization.
  This is not remote attestation or successful production deployment. Public
  construction is now integrated without a development fallback. See the
  [completed development pass](windows-enclave-image-admission-results.md).

## Broader implementation and qualification

- The separate public-data concurrency probe now observes four overlapping
  worker calls plus a controller in one five-thread development VBS enclave.
  Duplicate/replayed lanes reject and workers join before deletion. This does
  not yet implement protected multicore ParallelHash: per-worker protected
  stacks/owners, enclave-local leaf storage and ordered root reduction remain.
  See the [concurrency boundary and next design](windows-enclave-concurrent-design.md).
  A separate per-slot guarded-stack image now also passes four-worker overlap,
  denial and after-lock failure cleanup, and a native missing-clear negative
  control. Live host reads reject at three sampled addresses per admitted
  window. Explicit child-process working-set budgeting is recorded after the
  default lock allowance rejected extra workers. This is public-marker stack
  isolation, not yet protected Rust owners or ParallelHash leaf processing.
  The private safe-Rust concurrent leaf/root component now passes Linux and
  Windows process tests: four bounded leaf slots, one-use plan identity, ordered
  reduction, cancellation and cleanup; 380 oracle cases in two orders, fifteen
  compiled mutations and thirteen ownership/API negatives. This logic is not
  connected to the protected stack/storage adapter yet. See the
  [component scope and remaining integration](windows-enclave-parallel-concurrent.md).

- The private four-message Keccak AVX2 component and fixed-page resident now
  pass native Linux and Windows process campaigns: each stage covers 520
  independent cases/2080 lane comparisons across SHA-3/SHAKE/cSHAKE, mixed rates,
  bit tails, arbitrary-bit N/S, empty messages/outputs and bounded lengths.
  Fourteen component and four placement mutants are rejected, alongside six
  component and eight resident ownership negatives. Strict-provenance Miri
  rejects six allocation/lifetime/rollback mutants in a placement-only model.
  This reuses the existing hardened independent-message engine, not the
  sequential single-state route. Process execution and model checks do not
  establish OS protection or whole-image cleanup. See the
  [component and resident observations](../assurance/windows-protection-observations/keccak-simd-component-20261002.json).
  The version-22 worker and baseline C adapter now also pass native Linux/Windows
  tests: 520 oracle cases, 3954 injected partial-copy prefixes, fourteen Rust
  worker mutations and twenty-one C admission/entry/copy mutations. The real
  development-signed VBS worker passes 53 batches/212 lane digests across 318
  calls, including twelve actual OS payload-copy failures and retained reuse.
  Windows rejects the unsigned image; the temporary signing key was removed.
  The supported `keccak_simd::Session::open_avx2` host API is now connected:
  native debug/release campaigns each pass 521 batches/2084 lane comparisons.
  Twenty-one host mutations, ten ownership negatives, five host-only Miri tests
  and the packaged facade's 487 export/ownership checks pass. Production opening
  rejects the development signature. Shared admission was split without changing
  its trust rules; native SHA-256 SIMD regression passes in both profiles.
  See the [host observations](../assurance/windows-protection-observations/keccak-simd-host-20261003.json)
  and [API example](windows-enclave-keccak-simd.md). Whole-image cleanup,
  multicore ParallelHash and production qualification remain separate. See the
  [worker and native observations](../assurance/windows-protection-observations/keccak-simd-worker-20261002.json).

- The private eight-message SHA-224/256 AVX2 component, resident and version-21
  worker now pass native Linux/Windows process campaigns: 402 independent cases
  and 3216 lane comparisons per stage, including every mixed SHA-224/256 lane
  plan. Component/resident/worker tests reject 12/4/14 compiled mutations;
  baseline C admission/entry/copy tests reject nineteen more. All 3032 injected
  copy-failure prefixes fail closed. A placement-only Miri model rejects six
  provenance/destruction/rollback mutations; this model does not execute SIMD.
  Development-signed execution inside the local Windows VBS enclave now passes
  53 batches/424 lane comparisons across 302 calls, including all eight actual
  OS lane-copy failures, retained reuse and quarantine. Windows rejects the
  unsigned image; the temporary signing key was removed. Sources and preserved
  artifacts match their recorded hashes. The supported version-21
  `sha256_simd::Session::open_avx2` host API is now integrated: development-signed
  native debug/release campaigns each pass 403 batches/3224 digest comparisons.
  Eighteen compiled host mutations, ten ownership negatives and five host-only
  Miri tests pass; the packaged facade rejects 472 export/ownership cases.
  Production construction still rejects the development signature. The existing
  SHA-512 SIMD host regression also passes against the updated shared owner.
  Whole-image cleanup and production qualification remain separate. See the
  [host observations](../assurance/windows-protection-observations/sha256-simd-host-20261002.json)
  and the
  [component, worker and native observations](../assurance/windows-protection-observations/sha256-simd-worker-20261002.json).

- The private four-message SHA-512-family AVX2 component now passes Linux and
  local Windows native-process campaigns: 602 independent cases/2408 lane
  comparisons, twelve compiled runtime mutations and six ownership/lifetime
  negatives. Mixed identities, unequal lengths and every general-t parameter
  are covered. It is bounded to 1024 bytes per lane and requires a common full
  block; no portable fallback or arbitrary-length streaming is claimed. The
  explicit host route is now connected and development-tested. Current-image
  cleanup qualification remains outstanding. The public
  VBS kernel diagnostic does not substitute for that integration. See the
  [component observations](../assurance/windows-protection-observations/sha512-simd-component-20261002.json).
  Private resident placement now passes native Linux/Windows tests with the same
  602 cases, four additional compiled mutations and eight ownership negatives.
  A placement-only Miri model rejects six provenance, destruction-order and
  constructor-rollback mutations. Full-page clearing is tested; OS protection,
  VBS execution and protected worker frames are not established by those tests.
  See the [resident observations](../assurance/windows-protection-observations/sha512-simd-resident-20261002.json).
  The version-20 worker and baseline C adapter are now implemented privately.
  Linux and Windows OS-copy-double tests each pass 602 oracle cases, 1813
  copy-failure prefixes, fourteen Rust mutations and nineteen C mutations.
  The unsigned Windows enclave image builds and links. Current-image qualification
  remains outstanding;
  an image build is not proof of runtime protection. See the
  [worker/build observations](../assurance/windows-protection-observations/sha512-simd-worker-20261002.json).
  Subsequent development-signed VBS execution now passes 61 four-message
  comparisons/244 lane digests across 318 calls, including seventeen rejection
  campaigns and cancellation/reuse. The unsigned image rejects with error 577;
  the temporary signing key was removed. This is native private-worker evidence,
  not a supported host API or whole-image qualification. See the
  [native observations](../assurance/windows-protection-observations/sha512-simd-native-20261002.json).
  The subsequent explicit `sha512_simd::Session::open_avx2` host API now passes
  559 batches/2236 digests in each native debug/release profile, plus sixteen
  compiled host mutations and ten ownership negatives. Prepared import identities
  are required; the original private image correctly rejected. Development
  signatures still fail production trust. See the
  [host observations](../assurance/windows-protection-observations/sha512-simd-host-20261002.json).

- The private sequential AVX2 ParallelHash resident/worker now passes native
  Windows development execution (50 comparisons, 650 VBS calls), full-page
  placement/destruction tests, copy/quarantine mutations and baseline CPU/OS
  admission tests. Its placement-only Miri model is not kernel qualification.
  The version-eighteen worker is now connected to explicit opt-in `open_avx2`
  host selection and mandatory production trusted-image admission. Native
  debug/release campaigns each pass 332 direct and 256 retained cases on both
  scalar and AVX2 routes, with wrong-image/identity and transactional rejection
  tests. See the [host observations](../assurance/windows-protection-observations/parallel-accelerated-host-20261001.json).
  Multicore scheduling and current-
  image ABI/register/spill/dump qualification remain separate outstanding work.
  See the [worker observations](../assurance/windows-protection-observations/parallel-accelerated-worker-20261001.json).

- The private sequential AVX2 SHA-3 batch resident/worker now passes native
  Windows development execution (50 comparisons, 614 VBS calls), full-page
  placement/destruction checks, copy/quarantine mutations and baseline CPU/OS
  admission tests. Its placement-only Miri model is not kernel qualification.
  The version-seventeen route is now connected to the supported affine batch
  host through opt-in `open_avx2`, mandatory production trust and a distinct
  image identity. Native debug/release tests each pass 323 batches/1344 digests
  per scalar/AVX2 route; encoder parity, ten compiled mutations, focused host
  Miri and packaged feature/ownership tests pass. Independent-message SIMD,
  multicore batching and current-image cleanup qualification remain separate
  work. See the [host observations](../assurance/windows-protection-observations/sha3-batch-accelerated-host-20261001.json)
  and the
  [batch worker observations](../assurance/windows-protection-observations/sha3-batch-accelerated-worker-20261001.json).

- Scalar SHA-2 streaming, bit tails, all named identities and general SHA-512/t
  are implemented in the [separate version-six worker/API](windows-enclave-sha2.md).
  Scalar ParallelHash host integration is also implemented; complete wider qualification.
  Extend the integrated enclave-compatible strict facade.
  Keep unsupported routes fail-closed and ordinary APIs unchanged. Do not claim
  the existing host-slice/closure APIs are transparently enclave-compatible.
  Scalar SHA-3/SHAKE/cSHAKE is now integrated in the
  [version-seven worker/API](windows-enclave-sha3.md), including streamed N/S
  setup, incremental XOF fragments and exact-bit retained rehashing. Native
  development enclave campaigns pass 1028 cases in each debug/release build.
  Worker vectors, compiled mutants, placement/lifecycle Miri and packaged
  ownership tests pass. This completes the scalar algorithm implementation
  pass, not acceleration, independent review or production qualification.
  The next private KMAC worker component implements all four identities using
  existing strength-enforcing KMAC states, retained fixed/XOF output,
  full-width tag verification and exact-bit retained-output rekeying. Its local
  author tests cover 256 independent oracle cases, 128 rekey combinations,
  cancellation/copy/unwind cleanup and eleven compiled mutations, with focused
  Miri. The library now supplies exact-length streamed key/customization setup
  for all four identities, including bit-fragmented inputs larger than 1024 bytes.
  The private worker now streams key/S setup across sequenced requests and
  supports retained-output rekeying with streamed customization. Per-request
  fragments remain bounded to 1024 bytes, not total key/S length. Ten local and
  Windows component tests cover 256 independent fragmented bit-oracle cases
  (including larger-than-1024-byte inputs) and 256 retained rekey combinations;
  eighteen compiled mutations and focused lifecycle Miri pass locally. See
  [cross-call component observations](../assurance/windows-protection-observations/kmac-crosscall-component-20260930.json).
  Version-eight worker transport now validates canonical public headers before
  payload copying, supports exact-bit fixed tags, and separates explicit tag
  export from the one-byte public verification decision. Thirteen component
  tests pass on Linux and Windows, including the same 256 oracle cases through
  direct and decoded-wire paths; twenty-six compiled mutants and two focused
  Miri checks pass. The Rust entry/C OS-copy adapter also builds and links as a
  Windows enclave image. Its initial build-only observations are retained in
  [wire/image build observations](../assurance/windows-protection-observations/kmac-wire-build-20260930.json).
  The subsequent version-eight host API now supplies affine Session/Stream/
  Reader/Retained types, bounded setup snapshots, receipt validation, retained
  rekeying, explicit public export and full-width verification. Native VBS
  development execution passes 546 cases in each debug/release build. These
  include all four identities, partial bits, setup larger than one request,
  incremental XOF output, cancellation and abandoned-handle quarantine. See
  [host observations](../assurance/windows-protection-observations/kmac-owner-20260930.json).
  Production trust is still mandatory at the public constructor; development
  signing is available only to the private test harness. Independent review,
  compiler/register qualification and production deployment remain pending.
  The previous bounded component's seven tests passed in an ordinary Windows process; this is
  [source-bound component evidence](../assurance/windows-protection-observations/kmac-component-20260930.json),
  not a VBS enclave execution claim.
  The private TupleHash component now covers all four identities using hardened
  cSHAKE, exact-length streamed customization/items, arbitrary-bit packing,
  retained fixed/XOF output and exact-bit retained-output rehashing as one tuple
  member. An unfinished item blocks finalization; empty members remain distinct
  from absent members. Its version-nine metadata decoder bounds snapshots and
  rejects noncanonical fields before payload copying. Seven component tests pass
  locally and in an ordinary Windows process: 272 independent bit-oracle cases
  run through both direct and decoded-wire paths, including larger-than-request
  setup/items; 128 retained rehash combinations pass. Nineteen compiled mutations
  reject protocol, framing, bounds and cleanup regressions; two focused Miri
  cleanup/quarantine tests pass. This is not native
  enclave qualification. The OS-copy entry now builds and links as a Windows
  enclave image, with bounded snapshots and public cleanup receipts. Placement
  tests cover destruction of an active partial item, wrong-page rejection,
  full-page clearing and recreation; Miri and two compiled placement mutants
  pass. The version-nine image now executes inside VBS using development signing.
  The affine host interface now includes item writers, fixed/XOF results,
  retained-output rehashing and transactional public export. Its bounded
  transport passes 230 native differential cases in each debug/release profile,
  including retained rehashing, incremental XOF and empty output. Empty
  customization no longer reenters completed setup, and a host open-item latch
  rejects forgotten-item finalization before backend entry, preserving clean
  destruction. The worker retains its independent rejection. See the
  [native development observations](../assurance/windows-protection-observations/tuple-owner-20260930.json).
  See the
  [component observations](../assurance/windows-protection-observations/tuple-component-20260930.json).
  The subsequent [entry/image observations](../assurance/windows-protection-observations/tuple-entry-build-20260930.json)
  preserve the separate source-bound build and placement checks.
  A candidate host metadata encoder is now tested against the actual enclave
  decoder across valid and rejected request shapes, including 128-bit item and
  customization lengths. Four encoder mutations are rejected. This is
  shared source used by the host API and the isolated parity fixture. Host-only
  mock tests cover abandonment, forgotten parent loans, output-copy failures,
  chunking and reuse; these are not native OS-copy evidence.
- The first private scalar batch component covers eight ordered SHA-2 slots,
  all named/general identities, streamed bounded input and arbitrary-bit final
  tails. A public byte budget bounds input, inactive slots remain zero and
  export requires completion of the entire declared plan plus an explicit seal.
  Failed operations clear all retained results and quarantine. Six tests cover
  72 independent hashlib cases, 255 activity masks and 4080 general-t bit cases;
  eleven compiled mutants and a focused Miri cleanup/unwind test pass. This is
  also tested in an ordinary Windows process; see the
  [component observations](../assurance/windows-protection-observations/sha2-batch-component-20260930.json). It is
  not a host batch API or native enclave evidence. The subsequent version-ten
  protocol now validates its 128-byte header before bounded payload copying;
  only explicit export authorizes copying the fixed 512-byte result block.
  Nine component/wire tests and 22 compiled mutants pass locally and on Windows.
  Placement tests cover retained output plus a live stream, wrong-page rejection,
  full-page erasure after destruction and recreation. Two placement mutants and
  three focused Miri checks pass. The Rust worker/C OS-copy adapter compiles and
  links as an unsigned enclave image, but has not executed inside VBS; see the
  [wire/build observations](../assurance/windows-protection-observations/sha2-batch-wire-build-20260930.json).
  The subsequent [batch host API](windows-enclave-sha2-batch.md) now supplies
  affine Session/Batch/Item/Retained owners, a typed public plan, an open-item
  latch, transactional declassification and reuse after confirmed cancellation.
  Its actual encoder is checked against the worker decoder. Six host tests pass
  normally and under Miri; twenty negative ownership doctests pass. Ten component
  tests reject 26 compiled mutants, plus two placement mutants. Native VBS
  development debug/release campaigns each pass 355 batches/1822 digests, including
  all activity masks, mixed identities and every valid general SHA-512/t parameter.
  This finishes scalar SHA-2 batch host integration, not qualification or the
  remaining ParallelHash pass. No SIMD or
  throughput gain is implied by sequential batching.
- The private scalar SHA-3/SHAKE/cSHAKE batch component and version-eleven
  transport now implement eight ordered slots sharing 1024 retained output bytes.
  Fixed digests require their exact width; XOF shapes declare their final-bit
  width up front. cSHAKE name/customization and message input stream through
  bounded snapshots. Independent oracle cases cover fractional setup/message/
  output bits, rate boundaries and setup larger than one snapshot. All 255
  active-slot masks cover mixed algorithms and packed output offsets, including
  active empty-output slots. Export requires every declared slot and an explicit
  seal; copy errors and recoverable unwind clear results and quarantine.
  This is a bounded scalar building block, not incremental batch XOF readers,
  a shipping batch host API or a SIMD/parallel throughput claim. The remaining
  work is host ownership/receipt integration, native enclave execution and
  qualification; existing single-stream XOF APIs retain their separate bounds.
  Nine component/wire tests pass locally and in an ordinary Windows process:
  604 independent oracle cases, 255 mixed-slot masks, 30 compiled component/
  protocol mutants and two placement mutants. Three focused Miri checks pass.
  The worker links as an unsigned Windows enclave image. Source-bound
  [component/build observations](../assurance/windows-protection-observations/sha3-batch-wire-build-20260930.json)
  distinguish this from native enclave execution and production qualification.
  The subsequent `enclave::sha3_batch` host API is now integrated: eight host
  tests pass normally and under Miri, twenty negative doctests enforce ownership,
  and native development tests pass 323 batches/1344 digests per debug/release
  profile. All 255 activity masks, long setup, exact-bit output, cancellation
  and forgotten-item rejection are exercised. The shared stream/batch campaigns
  also pass. See [host observations](../assurance/windows-protection-observations/sha3-batch-owner-20260930.json).
- The [private ParallelHash component](windows-enclave-parallelhash.md) now
  implements four scalar identities with streamed leaves/customization, exact
  leaf-count completion, clearing private counters, fixed retained output and
  incremental XOF fragments. Its version-twelve metadata and placement entry
  retain bounded snapshots and full-page destruction. The initial component-only
  step did not establish host integration, retained composition or native enclave
  execution; subsequent results are recorded below. Parallel workers and
  acceleration remain pending.
  Thirteen component tests, 332 independent cases, 24 compiled component/wire
  mutants and two placement mutants pass on Linux/Windows. Seven focused Miri
  checks pass locally; the unsigned Windows worker links. All 171 captured source
  hashes match. See [component observations](../assurance/windows-protection-observations/parallel-component-20260930.json).
  The subsequent `enclave::parallelhash` Session/Stream/Reader/Retained API now
  integrates that worker, including exact-bit secret-to-secret rehashing and
  production-signature-only construction. Native development debug/release
  campaigns each pass 332 direct oracle cases and 256 retained-composition cases.
  Seven host tests pass normally and under Miri; 25 negative ownership doctests,
  the packaged API example, 435 packaged forbidden-export/ownership probes,
  31 component/encoder mutants and two placement mutants pass. Eight focused
  component Miri checks pass. Shared native stream/batch regressions are green.
  All 535 native source/manifest hashes match; artifacts are saved outside target/.
  See [host observations](../assurance/windows-protection-observations/parallel-owner-20260930.json).
  This finishes the sequential scalar algorithm/API pass, not multicore,
  hardware/SIMD or production qualification.
- Add and qualify the supported opt-in hardware/SIMD paths, including Windows
  ABI/register cleanup and bounded ParallelHash worker ownership/concurrency.
  The [public-vector acceleration diagnostic](windows-enclave-acceleration.md)
  now confirms SHA-NI and AVX2 execution inside the development VBS guest:
  496 comparisons pass across five existing hardened kernels, with startup KATs
  and post-quarantine rejection. Dedicated x86 SHA-512 is absent. This is not
  session integration or secret-placement/cleanup qualification; both remain.
  The private retained SHA-NI SHA-224/256 component and version-13 decoder now
  pass real-kernel Linux/Windows component tests. Its authority/stream placement
  has native lifecycle tests and a separately labeled Miri lifetime model. The
  feature-checked enclave entry now has a separate private worker image: 21
  native public-vector comparisons across 151 calls pass, including copy faults,
  terminal rejection, cancellation and retained rehash. Nine Rust and fifteen C
  entry/gate mutations are rejected on Linux and Windows. Generated artifact
  bytes are checked after mutation restoration. The supported SHA-NI host route
  is now integrated behind explicit acceleration: 46 accelerated and 631 scalar
  cases pass in each native debug/release campaign, including trust, image,
  identity and lifecycle rejection. Four additional actual-C protocol mutants
  are rejected. Wider routes and current-image ABI/register/dump review remain. See
  [host observations](../assurance/windows-protection-observations/sha2-accelerated-host-20261001.json),
  [worker observations](../assurance/windows-protection-observations/sha2-accelerated-worker-20261001.json);
  the [component evidence](../assurance/windows-protection-observations/sha2-accelerated-component-20260930.json)
  must not be read as enclave or production qualification.
  The private AVX2 SHA-3/SHAKE/cSHAKE component now covers all eight identities,
  streamed exact-bit N/S, retained output/rehash and terminal authority failure.
  It reuses the existing hardened engine source unchanged. Its differential,
  lifecycle, compiled-mutation and prefix-only Miri checks are recorded in
  [SHA-3 component observations](../assurance/windows-protection-observations/sha3-accelerated-component-20261001.json).
  The subsequent private version-14 resident and feature-checked worker now
  execute inside development VBS: 57 independent comparisons across 419 calls
  pass, including exact-bit cSHAKE setup, retained rehash and copy-failure
  quarantine. Native placement/wire tests, 25 compiled regressions, seven
  ownership negatives, nine worker and eighteen baseline C mutants pass on
  Linux/Windows. A placement-only Miri model rejects three memory regressions.
  See [worker observations](../assurance/windows-protection-observations/sha3-accelerated-worker-20261001.json).
  The supported opt-in `sha3::Session::open_avx2` constructor now preserves
  production image/trust admission and scalar defaults. Native debug/release
  campaigns pass 1028 cases per route on AVX2 and the freshly rebuilt scalar
  image; nine compiled encoder mutations, focused host Miri and packaged
  feature/ownership negatives pass. See
  [host observations](../assurance/windows-protection-observations/sha3-accelerated-host-20261001.json).
  Current-image secret-storage/ABI qualification is still
  separate; the development image does not close that work.
  The next private KMAC AVX2 component now passes native Linux/Windows tests:
  256 independent bit cases, 128 retained rekeys, 22 compiled mutants and six
  ownership/lifetime negatives. Streamed key/customization completion, full-strength
  tags, XOF suffixes, verification and terminal authority failures are covered;
  a focused actual-key-prefix Miri model passes with a noncryptographic sink.
  See [KMAC component observations](../assurance/windows-protection-observations/kmac-accelerated-component-20261001.json).
  The subsequent private version-fifteen KMAC resident and feature-checked worker
  now pass Linux/Windows mutation tests and a focused Miri placement model.
  Development VBS execution passes 50 public-vector comparisons across 672 calls,
  including all sixteen retained rekey pairs. See
  [KMAC worker observations](../assurance/windows-protection-observations/kmac-accelerated-worker-20261001.json).
  The supported opt-in `kmac::Session::open_avx2` constructor now preserves
  production trust and the separate version-fifteen protocol with no fallback.
  Native debug/release campaigns pass 546 cases per route against AVX2 and a
  freshly rebuilt scalar image; encoder mutations and feature-gated packaged
  consumer checks pass. See
  [KMAC host observations](../assurance/windows-protection-observations/kmac-accelerated-host-20261001.json).
  Current-image qualification remains unfinished;
  development execution is not a production signing or independent pass.
  The private TupleHash AVX2 component now passes Linux/Windows tests: 272
  independent bit cases, 128 retained compositions, 22 compiled mutants and six
  ownership/lifetime negatives. A focused Miri model of the actual bit packer
  passes and rejects three mutants; it does not run AVX2 or VBS. See
  [TupleHash component observations](../assurance/windows-protection-observations/tuple-accelerated-component-20261001.json).
  Its subsequent version-sixteen resident/worker now passes Linux/Windows
  mutations and a focused Miri placement model. Development VBS execution passes
  50 public-vector comparisons across 853 calls, including retained composition
  and incremental XOF output. See
  [TupleHash worker observations](../assurance/windows-protection-observations/tuple-accelerated-worker-20261001.json).
  The supported accelerated host constructor is now development-tested:
  feature-gated `open_avx2` retains mandatory image trust and rejects scalar
  images. Native debug/release tests pass 230 cases per scalar/AVX2 route,
  alongside encoder mutations, host Miri and packaged feature-on/off checks.
  See [TupleHash host observations](../assurance/windows-protection-observations/tuple-accelerated-host-20261001.json).
  Current-image qualification remains open.
  The private sequential SHA-3 batch component now preserves eight-slot streaming
  semantics over the existing AVX2 engine, with a separate version-seventeen
  decoder. Its component/oracle, authority, mutation and ownership checks are
  recorded in [batch observations](../assurance/windows-protection-observations/sha3-batch-accelerated-component-20261001.json).
  This is single-state acceleration per item, not independent-message SIMD or
  multicore batching. The subsequent batch resident/worker and opt-in host are
  now development-tested; current-image cleanup and wider batch routes remain.
- Sequential AVX2 ParallelHash component, resident/worker and opt-in host
  integration are development-tested as recorded above. Multicore scheduling
  and current-image qualification remain open, not host integration.
- The private sequential SHA-NI SHA-224/256 batch component now passes native
  Linux and ordinary Windows-process tests: 244 independent cases in all eight
  slots, 255 mixed activity masks, 29 compiled mutations and six ownership
  negatives. Its separate version-nineteen decoder binds the narrow route;
  wide identities reject without fallback. The subsequent full-page resident
  and feature-checked VBS worker now pass native development tests: 40 independent
  comparisons across 466 VBS calls, three resident and nine worker mutations,
  nineteen baseline-C mutations and seven resident ownership negatives. A focused
  Miri placement/rollback model rejects six mutations; it is not kernel evidence.
  Explicit `sha2_batch::Session::open_sha_ni` host selection now enforces distinct
  image identity and production trust. Native debug/release host campaigns pass
  291 batches/1312 digests for SHA-NI and 355 batches/1822 digests for scalar per
  profile; wide plans reject without fallback. Encoder mutation, Miri and
  packaged feature/ownership tests pass. See the
  [host observations](../assurance/windows-protection-observations/sha2-batch-accelerated-host-20261001.json).
  Current-image qualification remains separate from the
  [worker observations](../assurance/windows-protection-observations/sha2-batch-accelerated-worker-20261001.json).
  Independent-message SIMD and wider SHA-2 acceleration remain separate work.
  Earlier [component observations](../assurance/windows-protection-observations/sha2-batch-accelerated-component-20261001.json)
  retain the distinct ordinary-process campaign.
- Finish compiler/runtime and protected worker/storage review. Test the new
  retained allocation in controlled dump experiments; cover supported error and
  unwind paths without extending claims to fatal abort, caller copies or
  privileged snapshots. Existing dump observations bind older images only.
- Qualify the integrated identity/import admission and consumer build/sign/load
  workflow in a production deployment. Production signing
  credentials and costs belong to the application publisher, not necessarily
  Brynja. Production success remains untested until actually exercised;
  production-profile rejection tests and test-signed execution on a
  Secure-Boot-disabled host are not production qualification.
- Obtain native evidence for each claimed Windows architecture/configuration.
  Only x86-64 enclave experiments have run here; Windows AArch64 is not qualified.
  If the stated architecture scope cannot be delivered, obtain an explicit scope
  decision instead of silently describing cross-compilation as native support.

## Release work after implementation

- Reconcile crate documentation, examples, support tables, release notes and
  assurance records with what is actually implemented and qualified.
- Obtain the independent pentest/retest for this candidate, resolve findings and
  collect final source-bound native evidence. The current pentest ledger remains
  pending; v0.24.49 reviews do not qualify these changes.
- Run final verification under the existing planner and evidence-reuse rules,
  then wait for green GitHub checks and explicit tagging authorization. No extra
  release-gate policy or crates.io publication is introduced by this work.

Latest focused component: [retained secret-to-secret composition](windows-enclave-retained-rehash-design.md).
Latest native platform step: [trusted image-admission development results](windows-enclave-image-admission-results.md).
Completed bounded API step: [Windows enclave owner integration results](windows-enclave-owner-results.md).
