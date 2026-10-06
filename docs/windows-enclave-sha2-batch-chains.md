# Windows SHA-2 batch chain review

Status: **partial author review**, completion package 5. The four existing
images are bound, but their complete private lifecycle composition is not yet
closed. This is neither independent retest nor whole-image qualification.
No production code, release gate or native enclave image changed in this pass.

## Bound populations and selected contracts

The frozen inventory covers every emitted Rust body, including cleanup funclets,
and binds the original build inputs, archive members, LLVM IR, assembly and signed
images. SIMD image manifests also bind their underlying worker source manifests.

| Route | Functions (including funclets) | Funclets | Source inputs | Body-byte mutants | Table-byte mutants |
| --- | ---: | ---: | ---: | ---: | ---: |
| Sequential scalar SHA-2 | 32 | 0 | 176 | 16,688 | 336 |
| Sequential SHA-NI | 42 | 1 | 272 | 14,878 | 48 |
| Eight-lane SHA-224/256 AVX2 | 52 | 16 | 258 | 16,562 | 0 |
| Four-lane SHA-512-family AVX2 | 52 | 16 | 260 | 18,757 | 296 |

Actual incoming references, cleanup metadata, constant tables and SDK transport
targets are checked in the linked images. The SIMD cancellation vtables have
exact read-only layouts and absolute pointers to the actual local callback
bodies. Both the closure and its thunk return false without reading input.
The resident constructors install the compiled-target capability function into
the authority; its one-bit private ABI and complete body are checked. This
function is a build-wide capability predicate, not runtime CPU detection or a
migration monitor. Neither callback-target binding nor constructor checking
establishes provenance at every later indirect callsite.

Selected semantic checks cover exact nonwrapping sequence/phase admission,
output clearing on enumerated rejection paths, authority health and revocation,
scalar active-slot and checked budget accounting, and scalar completion
publication only after successful finalization. Private ABI checks retain the
compiler's 1,024-byte sequential input bound and fixed SIMD lane-array sizes.
Constructor failure loops clear all 4,096 backing-page bytes. This does not
claim erasure of constructor stack copies. SIMD retirement is checked separately below.

The sequential scalar and SHA-NI terminal/retirement composition additionally
checks all eight plan entries against their completion bits before sealing.
Export requires the Sealed phase and compares all 64 plan bytes before the
fixed 512-byte copy-out. Copy failure reaches the operation guard; successful
copy-out clears retained output and returns to Empty. SHA-NI rechecks authority
after the copy. Cancellation is admitted only in Collecting, Streaming or
Sealed; selected rejection and success return paths require output erasure.
Incomplete operation guards quarantine the owner (and SHA-NI authority).

Sequential state clearing invalidates the placed enum before destroying the
taken state, including live SHA-NI scratch. All normal worker returns after
buffer construction pass buffer destruction: 128/144 header bytes and 1,024
payload bytes are cleared. Scalar retirement destroys the owner, clears LIVE
and erases the full page; SHA-NI takes the resident out of LIVE, invokes its
destructor and clears the separate page identity. Its destructor destroys the
state and erases all 4,096 backing bytes. These are bounded normal-path checks,
not guarantees for arbitrary OS unwinding, aborts or constructor-stack copies.

The SHA-NI image's two panic-location descriptors bind the actual immutable
filename, length, line and column. This records reachable diagnostic data; it
does not resolve the fail-stop caller preconditions or promise abort cleanup.
Frame sizes, saved vectors and direct reference graphs are recorded, but no
transitive depth bound is qualified while indirect-call composition is pending.

## SIMD authority, session and padding contracts

The complete ordered indirect-call populations contain thirteen SHA-224/256
sites and sixteen SHA-512-family sites. Six and seven authority sites,
respectively, now have local checks for health, kernel identity, revalidation
and rejection. This inventories all sites but does not establish their complete
caller-supplied pointer provenance. The wide private executor permits absent
authority; the resident caller's required authority remains a separate obligation.

Both compression sessions wipe scratch before transpose, select the x86 kernel
only for tag zero, revalidate before publication and reject counter overflow
before committing caller output. Success wipes scratch; selected failure paths
wipe scratch and revoke authority. Complete local transpose and kernel checks
are described below; enclosing digest-engine composition remains open.
Private ABI checks bind state/block extents and the aligned scratch workspaces.

All thirty-two invoked cleanup funclets are checked against their exact parent-frame
slots. Session handlers revoke authority, with the active scratch handler also
wiping scratch; owner-operation cleanup clears retained output and quarantines
the owner and authority. Digest handlers cover workspace, output and scratch
destruction. Four conditional handlers permit an unarmed return: their exact flag
test is checked, and cleanup must dominate normal returns along the armed path.
Unconditional handlers require their cleanup on all normal returns.

The remaining digest-engine indirect sites now have concrete source checks:
authority pointers come from the admitted owner; cancellation objects and their
bound vtables are constructed inside the resident. Narrow execution uses the
local control at frame offset 240. Wide execution passes its offset-144 control
through the sixth executor argument, then preserves the data/function pair for
loop polls. Session and padding calls retain the corresponding authority/control.
The separately emitted wide executor also has explicit private ABI checks.
These are saved-program source/transfer checks, not a general alias proof or
closure of the surrounding storage lifetimes.

All thirty compiler cleanup tables for ten parent functions are checked in full:
headers, predecessor states, funclet identities and IP-to-state transitions.
They specify which handlers run and in what order for the recorded call regions,
including session scratch clearing after revalidator failure and outer owner
quarantine after digest cleanup. Existing binding checks connect complete associated
object metadata and actual funclet destinations to the image. OS dispatcher
semantics, enclosing storage-lifetime composition and arbitrary OS unwinding
are not qualified by these checks.

Both padding helpers check copying and cancellation before charging their budget,
reject exhausted budgets and counter overflow, and clear 640 scratch bytes and
128 block bytes after scalar compression. Report accounting also rejects overflow.
Early helper failures still depend on caller-owned workspace cleanup; callback
object provenance and scalar-kernel composition remain pending.

## SIMD owned storage and selected normal cleanup

Complete emitted instruction sequences now cover seven cleanup routines per SIMD
route: CPU scratch, scalar owner, hash workspace, workspace drop glue, secret
output drop, worker buffer clear and buffer drop glue. Workspace field coverage
is checked byte-for-byte without overlap, including inactive lanes. The narrow
workspace clears 5,275 declared-field bytes out of its 5,280-byte allocation;
the wide workspace clears 5,751 out of 5,760. The trailing alignment padding is
not individually wiped. Neither this field check nor drop glue qualifies
compiler-created copies, register saves or the enclosing frame.

Secret output destruction visits all eight narrow or four wide pointer/length
slots and clears the identity field. Null/empty slots are not dereferenced;
validity and lifetime of caller-supplied destinations remain caller obligations.
Selected resident and wide-executor error paths require workspace and staging
erasure before normal return. The private engine's saved error-discriminant
arithmetic distinguishes ordinary request rejection from integrity failures;
this does not assert that every outer owner remains reusable after rejection.
Complete error-entry and success-transfer composition remain pending.

Every normal worker return after buffer construction reaches destruction of
the complete 8,192-byte narrow or 4,096-byte wide payload and its 288/160-byte
header. Admitted cancellation clears retained output and resets the plan/phase.
Retirement checks the supplied page identity, removes the resident from LIVE,
destroys its output/authority state, and uses an explicit volatile loop to clear
all 4,096 backing-page bytes before clearing the page identity. The old-page
replacement loop is also checked. Complete worker admission/lifetime composition
and shared-window reclamation are still separate obligations.

## Complete SIMD transpose and kernel contracts

All six emitted transpose routines are checked in full, including their
pointer-only prologues/epilogues. Their two counters produce the exact lane/word
address mapping, public byte reversal and register erasure. Models exercise
every public width (including zero), both word sizes and 8/16-word layouts:
source/destination accesses are bounded, no two active words alias, inactive
lanes remain untouched and packing/unpacking preserves each active byte.
The session still supplies the actual disjoint arrays and admitted width;
complete enclosing lifetime composition is not inferred from this model.

Both complete AVX2 kernels now have instruction-by-instruction semantic checks:
64/80-round schedule expansion, the SHA-2 small/big sigma rotations, Ch/Maj,
round additions and feedforward. The linked read-only round constants match
exact integer cube-root derivation for the first 64/80 primes. All vector
operations are lane-local; there are no cross-lane permutations. The eight-lane
32-bit and four-lane 64-bit states each occupy 256 bytes. Schedule/temporary
bounds agree with the reviewed workspace layouts.

Each kernel clears its initial state, expanded schedule and temporary regions,
leaving only its 256-byte result for the session to commit and wipe. Working
YMM0–3, RAX/RCX/RDX, flags and upper vector halves are cleared. The opaque blocks
contain no stack access or calls. Windows ABI prologues save ten incoming XMM
registers, and epilogues restore only those incoming values; those save slots
remain an enclosing-window cleanup obligation, not individually erased data.
Exact tail wrappers connect the session calls to the checked kernels.

This is a scoped author review of these saved routines, not a formal proof or
whole-program timing/cleanup qualification. Fresh native Linux AVX2 campaigns
also pass 402 narrow/602 wide oracle cases (3,216/2,408 lane comparisons), twelve
compiled cleanup/control mutants and six ownership negatives per family.
Windows replay checks the saved signed-image bindings, not a new enclave run.

## SIMD worker request and export composition

Both saved worker entries check non-null page identity, 4,096-byte alignment,
nonwrapping page bounds, a 65,536-byte worker window and page/window separation.
They initialize their buffer before use and check both header and payload ranges
inside that window before receiving input. Page allocation lifetime, serialized
entry and synchronous OS-copy behavior remain linked C/runtime obligations;
numeric range checks alone do not establish those properties.

The fixed 288/160-byte request copy precedes decoding. Checks retain the exact
version, nonzero sequence, mode, command and budget rules; every lane has its
identity, bounded message length, last-bit width and nonwrapping opaque host
address validated. Digest requires at least one complete common block. Export
requires zero length/tail/source fields, and cancellation requires zero lane
records. Arithmetic models cover the full low 16-bit identity domain and u64
edges, including general SHA-512/t exclusions and pointer overflow.

Every subsequent input-copy site is bounded to a separate 1,024-byte lane slot;
only the copy adapter consumes opaque host addresses. The digest receives
pointers into these private slots, with their validated lengths and metadata.
The narrow emitted array-builder's slice-failure branches cannot be reached
with the unchanged lengths validated at these callsites. These are specific
saved-path preconditions, not permission to call private helpers with arbitrary
values or to bypass the serialized transport.

Export requires the Retained phase and exact identities for all lanes, including
the general-t parameters where present. It copies exactly 256 bytes, revalidates
the authority after copying, then clears retained output before successful return
and resets the plan/phase. Armed failure cleanup clears and quarantines. The
surrounding worker clears buffers, checks every header/payload byte and requires
the cleanup observer's success before reporting success. The narrow three-byte
payload-check loop's final two-byte group is included in coverage. These checks
do not make the public copy transactional by themselves; that remains an
explicit transport obligation.

Fresh native Linux worker-double campaigns pass all 402/602 oracle cases and
fourteen compiled worker mutants per family. Their component campaigns also
pass, including twelve mutants and six ownership negatives each. These tests
exercise real AVX2 with OS-copy doubles, not native Windows VBS behavior.

## Reproduced primitives and changed finalizer

The review replays the earlier streaming scalar and SHA-NI semantic checks
against their saved objects and images before permitting reuse. It explicitly
selects fifteen scalar and fourteen SHA-NI helpers and requires complete body,
reference, extent-kind and resolved LLVM ABI equality. Renaming is allowed only
for the scalar `State::finish` definition; its complete local dispatch-table
bytes and relocation offsets must also match. All actual destinations and
constants are rebound in the current images. Other equal bodies are not
implicitly qualified. Batch-specific caller preconditions remain open.

The changed SHA-NI `State::finish` is reviewed separately, not accepted through
body equality. Checks retain its 2,000-byte state and 28-through-32-byte private
output ABI, exact SHA-224/SHA-256 width selection, engine success before output
publication, owner/scratch destruction and 32-byte staging erasure on every
normal return. The batch caller checks active-slot identity, budget, canonical
partial-bit input, eight-slot bounds, 64-byte output stride and success before
completion publication. The additional state-transition review below covers its
cleanup funclet and constructor copies. These checks do not claim individual erasure of
moved-from compiler copies or arbitrary OS-exception cleanup.

## Sequential slot/state composition

Both start-slot operations require the first active, unfinished slot. Their
unrolled eight-slot selections are checked against every pair of activity and
completion masks. Equality to that selected slot bounds the subsequent plan
load, including when all planned slots are already complete. Scalar identity
decoding and rounded output width are cross-checked over 65,539 wire identities,
including u64 boundaries; every admitted output fits its fixed 64-byte slot.
These arithmetic models supplement emitted-instruction checks, not native
execution. Twenty-one scalar constructor/update/finalizer dispatch destinations
are checked in semantic variant order as well as bound to actual image bytes.

The scalar caller verifies canonical tail bits, consumes the placed state before
finalization, passes the exact slot destination and publishes completion only
after success. Updates dispatch to the appropriate reproduced 32/64-bit helper
(with the distinct general-t owner offset). SHA-NI update checks the active slot,
budget and present state before entering the reproduced engine. Selected failure
returns require full 512-byte output clearing.

Both constructors wipe an old live state before replacement and publish Streaming
only after installing the new state and active slot. The SHA-NI constructor also
checks health/kernel identity, startup KAT failure destruction, both IV selections,
all intermediate session/owner copies, and the copied authority pointer/epoch
check before publication. Initialization `memset` is not credited as volatile
erasure; compiler-created copies still require enclosing-window reclamation.
The additional constructor/admission checks below cover scalar IV calculation,
initial owner placement and begin-plan validation. Enclosing frame/storage
reclamation is still required; these checks do not close the whole constructor
cleanup composition.

The SHA-NI finish funclet reads the owner and completion flag from the actual
parent-frame slots and invokes its bound operation destructor on every return.
That destructor destroys taken state and scratch, clears output and quarantines
authority when incomplete. This covers the invoked compiler cleanup path, not
arbitrary OS exceptions, aborts or a guarantee that all such failures invoke it.

## Initial placement and public IV construction

Both sequential begin operations require Empty-phase admission, a nonempty plan
and validation of every one of its eight identities before copying the complete
64-byte plan and publishing Collecting. Scalar accepts the six named identities
and general-t values 1..511 except 384; SHA-NI accepts only SHA-224/256. Zero means
an inactive slot. Tests cover each slot with 65,539 wire values, both alone and
alongside a separate valid entry, so a valid neighbor cannot hide an invalid
identity. Selected rejection paths destroy taken state and clear all output;
SHA-NI also revokes authority on guard failure.

Initial placement checks cover page alignment, nonwrapping window bounds,
duplicate-live rejection, empty state/plan/output initialization and publication
only after success. The SHA-NI worker also checks page/window disjointness;
the scalar worker relies on its enclosing C admission for that property. No
claim is made that inactive enum payload or all padding is initialized. SHA-NI
startup failure erases the backing page. Its public `abc` KAT checks the complete
SHA-256 schedule, SHA-NI rounds, feedforward and full-width result comparison,
with linked IV, round table and expected digest bindings. This is not CPU
feature detection or independent review, and its stack still requires the
enclosing window cleanup.

The scalar constructor checks all six named IVs, zero initialization and final
placement. For general SHA-512/t it checks decimal-label generation across all
510 admitted parameters, one-block padding, XOR-adjusted IV, feedforward,
big-endian serialization and the three-byte layout displacement. The 23-line
schedule loop and 46-line round loop must match the earlier replayed streaming
review under an explicit stack displacement and register substitution. The old
assembly is separately pinned; this is scoped comparison of two public loops,
not a general machine-code interpreter. Mutating each instruction in either
version rejects all 138 changes.

## Tests and retained evidence

Thirty-nine review tests pass on Linux and Windows with matching parsed reports.
They reject 542 semantic-landmark removals, 48 private ABI changes, 105
required-return-event bypasses (104 cleanup and one KAT comparison), twelve
lifecycle, eleven finalizer, seven state/funclet and three admission/KAT premature returns,
116 per-helper body/reference/extent/ABI mutations, altered callback layouts/pointers, diagnostic-data drift,
incomplete inventories and inconsistent source closures. The byte-mutation
counts above establish binding durability, not algorithm correctness alone.
Separate regressions reject missing prior semantic reviews, changed dispatch
tables and changed resolved target attributes; an equal unlisted function is
not added to the reused set. All 21 scalar dispatch-order mutations are rejected.
Twelve linked constructor-constant mutations and 138 explicit-loop mutations
are also rejected. The plan arithmetic checks are models, not native execution.

Scoped native Linux component campaigns also pass:

- Scalar: ten component tests, 72 hashlib cases, 255 active-slot masks, 4,080
  general-SHA-512/t bit cases and 26 compiled mutants; one placement test and
  two allocation/lifetime mutants.
- SHA-NI: twelve component tests, 244 independent cases, 255 mixed masks,
  29 compiled mutants and six ownership negatives. Worker tests reject nine
  Rust mutants and nineteen baseline C-gate mutants. Resident tests cover
  242 independent bit cases, 255 masks, three placement mutants and seven
  ownership negatives.
- SHA-224/256 AVX2: 402 independent cases and 3,216 lane comparisons, twelve
  component mutants and six ownership negatives; fourteen worker mutants;
  four resident mutants and eight ownership negatives.
- SHA-512-family AVX2: 602 independent cases and 2,408 lane comparisons with
  the same component/worker/resident mutation and ownership counts as above.

These component runs exercise native SHA-NI/AVX2 on Linux, not Windows enclave
execution or dedicated x86 SHA-512 instructions. Windows replay inspects the
previously saved native images. Inputs remain under
`release-reports/windows-local-20261004/`; reports and component artifacts are
under `release-reports/windows-worker-review-20261006/`, outside `target/`.
The [checkpoint observation](../assurance/windows-protection-observations/sha2-batch-chain-progress-20261006.json)
retains its earlier scope and report hashes. The
[sequential lifecycle observation](../assurance/windows-protection-observations/sha2-batch-lifecycle-progress-20261006.json)
records the extended checks and fresh scalar component, SHA-NI worker and
resident campaigns. The earlier unchanged SIMD campaigns remain applicable;
no product source changed.
The [primitive/finalizer observation](../assurance/windows-protection-observations/sha2-batch-reuse-progress-20261006.json)
records the latest replay and regression scope; it retains those unchanged
component results rather than claiming another native enclave execution.
The [state-transition observation](../assurance/windows-protection-observations/sha2-batch-state-progress-20261006.json)
supersedes that partial checkpoint for the caller/funclet checks above. It also
records fresh passing scalar and SHA-NI component/oracle/mutation runs on native
Linux; Windows replay still inspects the saved enclave images.
The [constructor/admission observation](../assurance/windows-protection-observations/sha2-batch-constructor-progress-20261006.json)
records the additional scope above, retaining the unchanged component results.
The [SIMD authority observation](../assurance/windows-protection-observations/sha2-batch-authority-progress-20261006.json)
records the session, authority, padding and invoked-funclet contracts. It also
records 87 indirect-call changes plus two added-function callsites rejected,
and nineteen premature returns rejected across session failures and funclets.
The [digest callback/cleanup observation](../assurance/windows-protection-observations/sha2-batch-digest-progress-20261006.json)
extends that checkpoint to all 32 SIMD funclets, forty session/funclet premature
return mutations, 258 cleanup-table field mutations and sixty table deletion or
duplication mutations. Earlier observations retain their historical scope.
The [owned-storage observation](../assurance/windows-protection-observations/sha2-batch-storage-progress-20261006.json)
adds the field coverage, complete cleanup routines, selected normal error paths
and worker retirement checks. All 284 individual destructor instruction/control
label replacements are rejected. It retains the unchanged native component runs;
the Windows replay is not a new native enclave execution.
The [kernel/transpose observation](../assurance/windows-protection-observations/sha2-batch-kernel-progress-20261006.json)
adds the complete SIMD routine checks, 1,072 rejected instruction/early-return
mutations, twelve marker removals and 896 changed constant bytes. Its fresh
native component reports supplement the saved-image replay; previous component
and review observations remain historical evidence.
The [worker request/export observation](../assurance/windows-protection-observations/sha2-batch-worker-progress-20261006.json)
records entry/buffer bounds, decoding, private input handoff and export cleanup,
with fresh native worker-double campaigns. It keeps the full enclosing
digest-engine and frame/lifetime review explicitly pending.
The [SIMD constructor observation](../assurance/windows-protection-observations/sha2-batch-simd-constructor-progress-20261006.json)
adds complete emitted constructor-body checks, not just selected landmarks.
All eight narrow and four wide startup lanes contain the padded public `abc`
message. Integer-derived SHA-2 initial values and independently computed expected
digests are bound to the actual linked constant bytes. The full comparison,
four compiled-route checks, authority/owner placement, zero output and initial
phase/sequence, and both full-page failure-clearing paths are checked.
The constructor's input, state, schedule and CPU-workspace stack ranges are
disjoint and initialized; startup locals contain public test data, not caller
messages. This does not qualify incoming register saves or enclosing-window
reclamation. These routines invoke the previously reviewed transpose, compression
and wipe bodies. Shared `memcpy` and stack probing still belong to package 8.
The new tests reject 1,002 instruction/control/early-return mutations, 192
constant-byte changes, twelve constant-removal/extent changes, and every one of
4,096 single-bit output mismatches across all startup lanes. Fresh Linux AVX2
resident campaigns pass 402/602 oracle cases, four compiled resident mutants and
eight ownership negatives per family, plus the component campaigns. Windows
replays the saved images; this checkpoint is not a new native enclave run.
The [digest caller observation](../assurance/windows-protection-observations/sha2-batch-digest-caller-progress-20261006.json)
adds input admission, private descriptor construction and retained-output
lifetime checks for both SIMD routes. Every typed lane is bounded to 1024 bytes;
empty inputs require zero tail width, and fractional tails must have canonical
unused bits. Early failures with an armed operation clear the retained owner
and quarantine its authority. The saved guard cannot be disarmed in those paths.
Plans are preserved from the typed inputs. Scratch is zeroed before digest output
and split into eight 32-byte or four 64-byte destinations. All four SHA-512
output-width dispatch tables are checked against the linked, byte-bound tables.
Returned slots must be present and bounded before copying into the retained
owner. The output owner is destroyed before final revalidation; only then may
the plan and retained phase be published. Every checked post-result normal
return clears output ownership, scratch and workspace, including copy failures.
The inner engine's preservation of destination provenance is **still pending**;
these caller checks do not make an arbitrary returned pointer trustworthy.
Fifty-two review tests pass on both hosts, rejecting fifteen added premature
returns, twenty-eight dispatch mutations and two saved-guard disarming changes,
alongside the existing semantic-sequence and cleanup-event mutations. Fresh
Linux AVX2 worker-double campaigns pass for both families. Shared OS-copy and
window cleanup are not qualified by those tests.
The [output commit observation](../assurance/windows-protection-observations/sha2-batch-output-commit-progress-20261006.json)
adds every destination-width preflight before the first write, all eight/four
copy call arguments and failures, and workspace destruction after successful
commit. Narrow widths must be 28 or 32 bytes; wide widths must be 1 through 64.
Selected contiguous move-only regions now have symbolic byte-provenance checks:
136 narrow descriptor/identity bytes and two 72-byte wide transfers are preserved
exactly. The checker handles overlapping copies, GPR subregister writes and
VEX upper-lane clearing; unseeded origins are distinct, not assumed zero.
It rejects address-base rewrites and unsupported operations. Its fixed frame/ABI
assignments are not a general alias analysis or a proof of pointer integrity
through the preceding engine. In particular, the first prepared source pointer's
lifetime across finalization and the destination table's lifetime across inner
computation remain pending.
Sixty-three review tests pass on Linux and Windows with matching parsed reports.
They reject 280 returned-byte corruptions and thirteen shifted source loads,
alongside 630 semantic-sequence mutations and the earlier regression campaigns.
Production sources are unchanged; the preceding native worker reports are reused,
not represented as fresh runs. This checkpoint does not close package 5.
The [descriptor provenance observation](../assurance/windows-protection-observations/sha2-batch-descriptor-provenance-progress-20261006.json)
adds an exhaustive use check for the saved LLVM descriptor allocations, including
all 100 derived/root addresses. The narrow constructor supplies eight distinct
slots of its original private scratch; the wide routine initializes descriptors
with one exact 64-byte incoming copy. Pointer and length fields have no later
IR writes. Later identity writes and clearing are confined to the separate
eight-byte identity tail. Unknown address operations or consumers reject;
the bounded cleanup loop and reviewed unwind destructor are explicit exceptions.
All twelve prepared copy sources select only null or their original workspace
slot, and each feeds its matching original destination pointer and length.
This complements the byte-exact returned aggregate checks; it does not prove
the compiler's hoisted spill slots or every emitted indirect write safe.
Seventy-three tests pass on both hosts with matching parsed reports. New IR
regressions reject 300 allocation-alias writes/escapes, eight cleanup/copy-bound
changes, eight original-scratch-pointer replacements, and sixty prepared-source
origin/escape/copy changes. Native worker results remain reused, not rerun.

The [vector-loop observation](../assurance/windows-protection-observations/sha2-batch-vector-loop-progress-20261006.json)
adds complete emitted width/setup and inner vector-loop regions for both SIMD
routes. Index and input-presence checks precede packing, each complete block's
extent is checked before input copying, and state write-back uses the original
compact index. Every compression charges the selected width, checks the actual
session completion count and checks report counters for overflow. External
branches into the loop's interior are rejected. The reviewed snapshots are
machine-code contracts, not an independent compiler or general alias proof.
Independent geometry tests cover every active-lane mask, reordered indices,
partial groups, block boundaries and the maximum bit count. Accounting tests
cover exact-maximum success, exhaustion, overflow and mismatched completion.
They do not assert control rollback on rejection: charging and computation may
already have occurred before an error.
Eighty-one tests pass on both hosts, with matching parsed reports. New tests
reject 1,548 instruction/control mutations across the two vector loops, as well
as ambiguous labels and external side entries. Three additional setup sequences
bring the existing semantic-sequence mutations to 633. Production sources and
release gates are unchanged, and native worker results are reused. Compaction's
uniqueness, original slice/storage aliasing, scalar finalization and emitted
frame lifetimes still require enclosing composition; package 5 is not closed.

The [scalar finish observation](../assurance/windows-protection-observations/sha2-batch-scalar-finish-progress-20261006.json)
adds both complete emitted scalar-finalization regions within the SIMD engines:
remaining-block traversal, checked work accounting, compression scratch clearing,
remainder/partial-byte placement, one- or two-block padding, big-endian length
encoding, output truncation, and owner wiping around each successful lane.
Both wide identity jump tables now have explicit variant-order checks tied into
the saved-image replay. The narrow byte-mask helper has a specialized argument
ABI; both helper forms, their wrappers, opaque boundaries and working-register
erase are checked independently instead of assuming identical signatures.
These are caller-region checks. Their primitive compression contracts and
enclosing live-memory relationships still need composition.
An independent bit-string padding construction matches the byte-level model for
all 8,193 private message lengths in each family. Consumed-block geometry,
canonical partial bytes, maximum length encoding and every supported wide
output width/mask have boundary tests. Eighty-nine tests pass on both hosts with
matching parsed reports, rejecting 1,350 new finalization instruction/control
mutations, twenty-one mask/helper mutations, six misplaced opaque markers and
forty wrong variant-table targets. Production and release-gate code are unchanged;
native worker results remain reused, not presented as fresh enclave execution.

```sh
python3 scripts/cryptography/test-windows-enclave-sha2-batch-chains.py \
  --saved-directory release-reports/windows-local-20261004
python3 scripts/cryptography/windows_enclave_sha2_batch_chains.py \
  release-reports/windows-local-20261004 --mutate \
  --output release-reports/windows-worker-review-20261006/sha2-batch-scalar-finish-linux.json
```

Without the saved directory the test command runs forty-five self-contained tests
and explicitly skips the forty-four saved-artifact tests.

## Remaining package-5 work

- Finish batch-specific caller preconditions for the reproduced primitive contracts.
- Complete enclosing constructor frame/storage cleanup composition. Public IV
  calculation, initial placement, plan admission, selected state transfers,
  finalizer callers and the SHA-NI finish funclet are now checked. Both complete
  SIMD constructor bodies, public startup KATs and failure-page cleanup now have
  checks; enclosing-window cleanup is not inferred from their public local data.
- Complete SIMD surrounding pointer/storage lifetimes, enclosing lane-engine
  composition and normal error paths. Local callback sources, invoked funclet
  actions and compiler cleanup-state order are now checked; these need composition
  with each caller's live storage. Declared-field erasure, output/worker buffer
  destruction, page retirement and selected error-return cleanup now have checks;
  complete transposes and AVX2 compression kernels are now checked. These do
  not close complete alias or lifetime composition across the digest engine.
  The enclosing digest caller now has typed input admission, scratch/output
  layout, plan/width and post-result lifetime checks; the inner lane engine and
  preservation of destination pointers across computation remain to be composed.
  The final width preflight, copies and returned descriptor moves now have checks;
  descriptor initialization, immutability and prepared-source provenance now
  have whole-function LLVM use checks. Compose those with emitted stack-slot
  lifetimes and indirect memory effects; do not promote IR checks alone to a
  complete machine-code lifetime proof.
  Complete vector-loop regions now bind lane packing, complete-block input
  bounds, session accounting and indexed state write-back. Finish the enclosing
  compaction/preconditions and live-storage composition. The scalar remainder,
  padding and output-mask caller regions now have complete checks, including
  both variant dispatch tables and the specialized mask helpers. Compose the
  remaining scalar compression/transfer contracts with these caller regions;
  do not infer primitive reuse merely from matching names or instruction bytes.
- Assign every reachable private frame and storage region, and resolve the
  remaining fail-stop caller preconditions.

Shared runtime, SDK, final platform/depth reconciliation and enclosing-window
reclamation remain package 8 obligations. Nothing here promotes moved-from
copies, compiler spills or incoming register saves to individually erased data.
