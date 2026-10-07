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

The [primitive reuse observation](../assurance/windows-protection-observations/sha2-batch-primitive-reuse-progress-20261006.json)
replays the earlier scalar review before reusing four selected helpers per SIMD
route: scalar compression, owner wiping, checked region copying and byte copying.
Complete instruction bytes and extent kinds must match. Compression permits
only the single known round-table relocation rename, with matching offset,
addend and trailing bytes; the current linked table also matches independently
derived SHA-2 round constants. Other helper references must match exactly.
Resolved ABI comparison permits only the precise saved target-feature string
change and the two named copy-length range widenings. It does not remove
attributes generally or qualify other helpers merely because their bytes match.
The changed zeroizer is separately reviewed in full, including its stricter
positive-length ABI. Copy and clear interval tests cover lengths through 4,096
bytes and the largest permitted integer boundaries. Callers must still establish
valid nonoverlapping copy regions, live storage and positive clearing lengths.
Ninety-four tests pass on Linux and Windows with matching parsed reports. New
regressions reject seventy primitive body/reference/ABI/constant changes and
112 zeroizer instruction/store changes. Production and release-gate code are
unchanged, and no new native enclave execution is claimed.

The [compaction observation](../assurance/windows-protection-observations/sha2-batch-compaction-progress-20261006.json)
executes the saved public lane-compaction instructions in a bounded integer and
byte-memory model. All 6,561 narrow identity combinations and 1,296 wide
combinations reproduce strictly ordered, unique, bounded indices and the exact
active count. Narrow lanes also reproduce SHA-224/SHA-256 IV placement. Every
other declared workspace byte remains zero after the separately reviewed wipe;
alignment padding is not included in that clearing claim.
Unknown instructions, calls, uninitialized reads, writes outside assigned storage
and exhausted instruction budgets reject. The sole abstract call is the reviewed
workspace wipe, which clears its assigned fields and invalidates volatile
registers and flags. This is not a general x86 emulator or whole-frame proof:
original typed inputs, frame setup and subsequent lifetimes remain caller
obligations. Ninety-nine tests pass on Linux and Windows with matching parsed
reports, including 32 wrong-index/count/address/IV mutations. No new native
enclave execution or production change is claimed.

The [clearing-caller review](../assurance/windows-protection-observations/sha2-batch-clear-callers-progress-20261006.json)
now checks all 104 direct and tail transfers into
the stricter SIMD-image zeroizer. Ninety-nine calls have a locally established,
positive 32-bit literal length; five load descriptor lengths and test all 64
bits before the call. Only explicitly reviewed intervening instructions that
preserve the length register are accepted. Labels, unexpected calls, register
clobbers, missing guards and changed call populations reject. This check composes
with the parent control-flow and jump-table bindings; it does not replace them.
Positive length is now checked, but dynamic descriptor upper bounds, valid
pointers and live storage still need composition. The broader
`all_callers_checked` field therefore remains false rather than implying those
remaining obligations are closed.
All 103 tests pass on Linux and Windows with identical parsed reports. The new
tests reject 730 length, guard, clobber, alternate-entry and population mutations
without relying on the enclosing whole-body hash to reject them. Production
code and release gates remain unchanged; this is saved-image review, not new
native enclave execution.

The [destination-construction observation](../assurance/windows-protection-observations/sha2-batch-descriptor-bounds-progress-20261006.json)
records a bounded emitted-instruction replay. All 256
typed narrow identity combinations produce the exact original lane pointer and
28/32-byte width. For the wide route, the emitted region must consist of eight
independent register-to-descriptor stores: each width is then checked across
0 through 64 in each slot (260 assignments, not a claimed 65-to-the-fourth
runtime campaign). Zero is included as a conservative superset; the existing
clearing guard skips it. Each descriptor fits its own 32/64-byte slot inside the
256-byte scratch region; no source or scratch bytes may be changed by descriptor
construction. The original typed inputs, live frame and wide dispatch-table
bindings remain required. These origin bounds must still be composed with
subsequent machine-code storage lifetimes before qualifying every consumer.
All 106 tests pass on Linux and Windows with matching parsed reports. The 77 new
origin mutations exercise this checker with the earlier literal staging checks
disabled, so their rejection is not attributed to those earlier checks. Separate
regressions require staging, width admission and parent integration. No production
code, release-gate policy or native enclave execution changed in this checkpoint.

The [first-output frame-cell observation](../assurance/windows-protection-observations/sha2-batch-frame-cell-progress-20261006.json)
records direct emitted-frame checks from the prepared pointer's
hoisted initialization through preflight: bytes 184–191 relative to the narrow
aligned frame and bytes 976–983 relative to the wide frame pointer. The checker
accounts for RSP aliases and all 32 possible narrow alignment deltas, rejects
frame-base register changes (including partial-register writes), and checks the
full byte range of scalar and vector stores. Only initial assignment and the
named absent-output zeroing may directly overlap the saved pointer; its address
may not be directly exposed. The record inventories calls and indirect stores
instead of treating them as harmless. Seven indirect stores and 36 calls remain
to be composed with these cell lifetimes; this does not close the complete
first-pointer lifetime or whole-frame claim.
All 109 tests pass on Linux and Windows with matching parsed reports. Forty-one
new overlap/base/exposure mutations reject with the earlier finish/commit shape
checks disabled, so those existing literal checks do not mask the new check's
behavior. Production sources and release-gate policy are unchanged; no new
native enclave execution is claimed.

The seven indirect stores now also have bounded write-footprint checks using
the emitted address-producing instructions. The two separator stores use the
masked 0–63 and 0–127 remainder ranges. The other stores are the authority health
byte, two control counters and the wide length words. The small interpreter
forgets volatile registers across the reproduced copy ABI, rejects unknown
store addresses and wrapping arithmetic, and checks the complete store inventory.
These footprints are conditional on named live frame/workspace/control/authority
objects: their original placement, non-aliasing and preservation across the 36
calls are **not** proved by the footprint check. Step 5 remains incomplete.
The follow-up runs 113 tests on Linux and Windows with matching parsed reports;
22 new address/mask/width mutations reject through the effect checker itself.
The existing 41 direct-cell mutations continue to reject. No production changes,
release-gate changes or new native enclave execution are included.

Twelve scalar helper calls now have conditional caller/callee region composition:
four owner wipes, two scalar compressions and six explicit clears. The checker
replays the emitted argument slices, preserves only ABI-nonvolatile registers
between calls, and composes their arguments with the reproduced primitive
contracts. State, block and schedule/work storage must be relatively disjoint;
both scalar kernels' full 640-byte scratch clears are included. The original
live-object and saved-slot preconditions, callee stack/home-space placement and
full physical alias proof remain separate obligations. The other 24 calls still
need effect composition. Nothing promotes the complete pointer lifetime to
qualified on the strength of these conditional regions.
All 117 review tests pass on both hosts with matching parsed reports. Forty-seven
new pointer/extent/call mutations reject directly through this checker, without
relying on the earlier literal scalar-finish checks. Production and release-gate
policy remain unchanged; saved images are replayed, not newly executed.

The ten copy calls and three byte-mask calls now have conditional argument-region
checks as well. A 6,654-case public-geometry replay covers lane offsets, all
0–1024 complete-byte lengths for remainder copies, nonempty partial-byte inputs,
complete-block positions and every supported output identity/width. Zero-length
copies record no byte reads or writes; nonempty same-object copies must not
overlap. Mask footprints cover each possible padding-byte and final-output-byte
position. Complete finish/variant-table and primitive checks remain required;
seeded input extent, live slot values and physical object placement are still
caller obligations, not established by selecting symbolic object names.
All 121 tests pass on both hosts with matching parsed reports. Seventy-nine new
pointer/capacity/call mutations and four missing/duplicate-call cases reject.
There are eleven other call effects left to compose; all enclosing lifetime,
alias and callee stack/home-space obligations remain explicit. Step 5 is still
in progress, with no production changes or new native enclave execution.

## Control calls and conditional frame placement (2026-10-07)

The [control/placement checkpoint](../assurance/windows-protection-observations/sha2-batch-control-placement-progress-20261007.json)
assigns the eleven remaining calls in the two tracked first-output-pointer
regions. Four padding calls, four cancellation calls and two authority checks
have conditional argument/effect contracts. The linked readonly callback slot
and complete memory-free cancellation/detector leaves are checked. Padding
effects include control/report accounting and all scratch/block clearing, not
only compression writes.

The remaining narrow call is a guarded fail-stop. Its two incoming guards are
checked; it is **not** modeled as a returning call with no effects. Establishing
the original admitted fields and their preserved lifetimes is still required
to discharge its reachability preconditions.

The composition now accounts for all 35 returning calls and seven indirect
stores in these regions. Child-frame placement is derived from the actual
return slot, eight saved registers, 1,192-byte allocation and frame adjustment;
incoming arguments match caller slots 32/40. Bounded named-object effects do not
overlap the saved pointer cells or escape their assigned objects. The outgoing
home areas also exclude those cells. This does not prove the original seeded
pointer values, external allocation separation, complete private callee frames
or whole-window erasure.

All 130 tests pass on Linux and Windows with identical parsed reports. Eighty
control argument/target/population mutants, 22 effect-assignment/overlap/extent
mutants, seven frame/callsite mutations and five fail-stop guard mutations reject.
These are saved-artifact replays, not new native enclave execution. Step 5
remains open for original pointer/storage lifetimes, private frame composition
and the remaining caller/fail-stop preconditions.

## Whole-function normal-return ordering (2026-10-07)

The [cleanup-order checkpoint](../assurance/windows-protection-observations/sha2-batch-cleanup-paths-progress-20261007.json)
traverses both complete SIMD digest control-flow graphs with a live/cleared
state. Copies, masks, scalar compression, vector sessions and padding helpers
conservatively mark workspace data live; only the reviewed full workspace wipe
or destructor clears that state. A wipe before a later sensitive helper is not
sufficient. Loops are explored to a finite fixed point, and every destination
of the eleven wide dispatch tables is included. Earlier image/table binding and
complete wipe-contract checks remain required.

Both functions have one reachable normal-return site. Every normal path after
one of the 22 narrow or 18 wide sensitive-helper sites passes a later complete
wipe. Two terminal paths are recorded separately, not accepted as cleanup
success. Forty injected post-helper returns and removal of every complete wipe
from each caller are rejected, alongside 22 dispatch-target/edge mutations.

All 134 tests pass on both hosts with matching parsed reports. This closes the
normal-return **ordering check**, not original pointer/argument validity, alias
freedom, arbitrary exception cleanup or whole-frame erasure. Those remaining
composition obligations still prevent step 5 from being declared complete.

## Tracked normal callee stack bounds (2026-10-07)

The [callee-stack checkpoint](../assurance/windows-protection-observations/sha2-batch-callee-stack-progress-20261007.json)
follows the actual transitive returning-call population in the two tracked
first-output-pointer regions: ten narrow and eleven wide bodies, reached from
17/18 callsites. It checks stack allocations, matched register saves/restores,
frame-base setup, direct stack accesses, outgoing home space, nested calls and
tail transfers on every normal CFG path. Stack aliases cannot escape, explicit
accesses cannot reach saved registers, incoming home space or return addresses,
and every normal exit restores the entry stack. Unknown call targets, inconsistent
join states and recursive call graphs reject.

Including each nested return slot, those private stack effects occupy
`[-136, 0)` relative to the narrow caller's aligned frame and `[-264, -128)`
relative to the wide executor's frame base. Both exclude the tracked saved
pointer cell. Indirect targets and argument-reachable memory still require the
separate target/effect contracts; the stack check does not establish those by
itself. It also does not claim individual erasure of stack contents, arbitrary
unwind safety or coverage of every other private frame in the four images.

All 139 tests pass on Linux and Windows with matching parsed reports. The new
saved-body campaign rejects 92 stack overwrite, escaping-alias, unbalanced
return and unassigned/missing-callee mutations. Original pointer/slot lifetimes
and external allocation separation remain required before the conditional
effects can become a complete lifetime argument. Step 5 is not closed.

## First prepared-source CFG origins (2026-10-07)

The [source-origin checkpoint](../assurance/windows-protection-observations/sha2-batch-source-lifetime-progress-20261007.json)
adds whole-function reaching-definition checks for the first prepared source
pointer, whose saved slot spans the finalization loop. Every path to its null
check and copy read must reach either the actual workspace-address initializer
or the explicit absent-output initializer. Unknown values from a bypass,
partial overwrite or indexed frame store reject. A correct path cannot hide an
incorrect incoming branch; loop backedges and all wide dispatch destinations
participate in the fixed point. Earlier counter uses of the same stack slots
are not mistaken for initialized pointers.

For the wide caller, all three definitions reaching the address calculation
reload the original fifth argument at frame offset 1,168. Fixed-offset writes
to that incoming slot are rejected. The parent/child layout check binds this
argument to the resident's workspace. RAX must reach the initializer directly
from the exact address calculation; calls and partial/conditional register
writes are accounted for rather than ignored.

This establishes the **direct control-flow origin/preservation** component,
conditional on the separately required indirect-memory, fixed-frame,
nonvolatile ABI and original allocation-lifetime contracts. It does not assert
that an incoming pointer stays physically valid merely because it was reloaded,
nor that arbitrary indirect writes preserve it. Those are still composition
obligations, not waived checks.

All 144 tests pass on Linux and Windows with matching parsed reports. The new
saved-body campaign rejects 21 source-origin, bypass, overwrite and wrong-argument
mutations; synthetic regressions also cover loop backedges, conditional-register
definitions, ABI clobbers and all indirect branch targets. No production source,
native image or release-gate policy changed.

## Wide helper-slot and ABI origins (2026-10-07)

The [slot-origin checkpoint](../assurance/windows-protection-observations/sha2-batch-slot-origins-progress-20261007.json)
checks the remaining six saved scalar-helper pointers against actual emitted
definitions, without seeding those slots with their expected values. Every
normal predecessor and loop backedge is included; partial stores, overlapping
stores, volatile register clobbers and conditional definitions are retained.

| Saved frame slot | Workspace offset | Helper reload sites |
| ---: | ---: | ---: |
| 760 | 4580 | 1 |
| 1016 | 5604 | 3 |
| 1024 | 5348 | 2 |
| 968 | 4708 | 1 |
| 928 | 5476 | 2 |
| 984 | 512 | 1 |

Both scalar-owner wipe arguments are traced through their register transfers
and loop reloads. The input pointer at slot 1040 has 40 normal reload sites;
all originate in incoming R8. The executor pointer at slot 1048 has twelve;
all originate in incoming RDX. Reload cycles require a real entry argument and
reject unknown incoming definitions. A cycle alone does not establish origin.

Two earlier computed frame writes are bounded explicitly: public label padding
touches `[553, 556)`, and the 64-iteration schedule loop touches `[32, 544)`.
Their definitions, loop entry/backedge and complete computed-store population
are checked. Incoming workspace/control slots receive no direct writes.

The existing tracked call/store effects, outgoing home space and transitive
normal callee stacks are also composed against all eleven saved slots: the six
helper pointers, first prepared source, input/executor and incoming workspace/
control arguments. These conditional effects do not overlap the slots. The
earlier vector-phase indirect effects on slot 984, external allocation
separation, original physical lifetimes and the fixed-frame/nonvolatile ABI
remain separate requirements. Later legitimate reuse of a helper slot for
output preflight is outside its last helper consumption, not misclassified as
a pointer corruption. This still does not close the entire private chain.

All 151 tests pass on Linux and Windows with matching parsed reports. The new
campaign rejects 89 emitted origin/overwrite/index mutations and fifteen
effect-overlap, stack, population and direction mutations. No production or
release-gate changes, image rebuild or fresh native enclave execution occurred.

```sh
python3 scripts/cryptography/test-windows-enclave-sha2-batch-chains.py \
  --saved-directory release-reports/windows-local-20261004
python3 scripts/cryptography/windows_enclave_sha2_batch_chains.py \
  release-reports/windows-local-20261004 --mutate \
  --output release-reports/windows-worker-review-20261006/sha2-batch-slot-origins-linux.json
```

Without the saved directory the test command runs seventy-seven self-contained
tests and explicitly skips the seventy-four saved-artifact tests.

## Vector-callee stacks and early saved pointers (2026-10-07)

All 157 tests pass on Linux and Windows with matching parsed reports: eighty
self-contained and seventy-seven saved-artifact tests. The new campaign rejects
108 callee stack/alias/call/spill mutations and twenty early callback/state-slot/
call-population mutations. The retained observation is
[`sha2-batch-vector-stack-progress-20261007.json`](../assurance/windows-protection-observations/sha2-batch-vector-stack-progress-20261007.json).

The normal vector/copy/cancellation closure now checks twelve actual callee
bodies per SIMD route, including the nine-body vector-session closure and its
kernel wrapper. XMM/YMM stack transfers use their real 16/32-byte widths and
must stay within live local allocations; computed/escaping stack aliases and
unassigned callees reject. Nested and tail transfers contribute to the bound,
including every call's return-address store. The resulting spans are
`[-288,0)` relative to the narrow aligned frame and `[-416,-128)` relative to
the wide inner RBP. These and the outgoing home areas exclude the selected
saved authority/input/source and callback/ABI slots. Bounds do not establish
individual erasure of the saved SIMD registers or private stack bytes.

The earlier wide region has exactly six calls: two cancellation polls, three
copies and one vector session. Whole-function reaching definitions now bind
both polls to the original control object's saved callback and data slots,
including partial-overwrite rejection. All three earlier uses of saved slot984
(state initialization, packing and write-back) trace to workspace+512. Later
legitimate reuse of those slots is outside the reviewed consumption interval.
The readonly callback and compiled-target bodies remain explicitly checked.

This is conditional normal-stack and direct-definition composition, not a
claim that earlier indirect argument writes preserve every slot. Those effects,
original physical separation/lifetimes, revalidator-field preservation and
arbitrary unwind remain separate obligations. No production or release-gate
change or new native enclave execution is involved.

```sh
python3 scripts/cryptography/windows_enclave_sha2_batch_chains.py \
  release-reports/windows-local-20261004 --mutate \
  --output release-reports/windows-worker-review-20261006/sha2-batch-vector-stack-linux.json
```

## Earlier wide stores and call effects (2026-10-07)

All 169 tests pass on Linux and Windows, with matching parsed reports:
86 self-contained and 83 saved-artifact tests. The new checks reject 83
store/origin/index/guard mutations, four hidden-write/partial-index/guard-bypass
mutations, twenty independent copy-argument mutations and eleven call-base/
effect/stack mutations. The retained observation is
[`sha2-batch-early-effects-progress-20261007.json`](../assurance/windows-protection-observations/sha2-batch-early-effects-progress-20261007.json).

The earlier wide region now has a complete 34-store indirect-write inventory:
eight state-initialization words, four control-counter writes, 21 local IV
scratch stores and one vector-offset store. Both scratch aliases trace to
`RBP-88` through all reaching definitions. State initialization uses an anchored
zero-origin four-lane induction, including its saved-index restore; public IV
arithmetic in the same register is not treated as a valid index. The vector
offset store requires the successful `index <= 3` edge on every normal path.
Unexpected stores, partial pointer overwrites, unguarded loop entries and
wrong address/width calculations reject.
The induction additionally checks every increment-to-save path crosses the
non-exhausted loop edge: a check that dominated the first iteration cannot
justify re-entry after exhaustion. Likewise, vector-offset guard coverage
starts from the defining index load, not an earlier iteration's successful
check.

All six earlier calls now have conditional effects: the two image-bound
cancellation callbacks are memory-free, three copies have independently replayed
argument geometry (96 public cases), and the vector session's original
authority/state/block/scratch argument origins are checked. Both packed-state
reloads and the saved CPU scratch base trace to their original workspace fields.
The reviewed session/kernel/transpose contracts bound the packed-state, CPU
scratch and authority writes. These effects and the normal callee stacks are
composed with the caller/child placement, excluding the live callback and
argument slots. The report no longer lists earlier-phase effect assignment as
pending, but explicitly retains its conditional nature.

Original input/compact-index and authority-field lifetimes, actual allocation
separation and nonvolatile ABI assumptions are still required. In particular,
the finite public replay does not prove provenance for arbitrary external input
pointers. Neither individual stack erasure nor arbitrary unwind is qualified.
No production code, release-gate policy or saved native image changed.

```sh
python3 scripts/cryptography/windows_enclave_sha2_batch_chains.py \
  release-reports/windows-local-20261004 --mutate \
  --output release-reports/windows-worker-review-20261006/sha2-batch-early-effects-linux.json
```

## Narrow authority and input-pointer lifetime checkpoint (2026-10-07)

All 180 review tests pass on Linux and Windows (91 self-contained and 89
saved-artifact tests), with matching parsed reports. The new checks reject
140 mutations: 71 pointer overwrites, 25 loop/index/reuse changes, five operation
result substitutions, sixteen transfer-argument changes and 23 unwind-pointer
or invoke-population changes. The retained observation is
[`sha2-batch-narrow-lifetimes-progress-20261007.json`](../assurance/windows-protection-observations/sha2-batch-narrow-lifetimes-progress-20261007.json).

The SHA-224/256 pointer-definition lifetime item is now checked across the
complete saved normal control-flow graph, including loop backedges and error
branches. The original owner returned by `Owner::operation` is traced through
all six saved-owner reloads. Its authority field supplies all eleven saved
authority reloads, twenty field/callback uses and the vector session argument.
Partial writes, overlapping RSP/RBP aliases, conditional substitutions and
uninitialized paths reject. The stack-probe argument-preservation and Win64
nonvolatile-register contracts remain explicit shared-runtime prerequisites.

All eight typed input pointers retain their lane pairing through the paired
24-byte source / 40-byte internal-descriptor induction. The scalar lane loop
traces every pointer initializer and all three input reads. Stack slot 112's
counter, input and output lifetimes are checked independently: neither a previous
lane's pointer nor the earlier counter may satisfy the current lane's load.
The block-copy start/end registers retain input provenance across calls and
loop increments. Vector gathers check a fresh bounded lane index and the actual
descriptor-to-copy argument chain; tail and last-byte copies retain their
original scalar input pointer. All ten indexed frame stores have bounded spans
and cannot silently invalidate the direct saved-slot analysis.

The saved LLVM invoke population is also reconciled with all eleven emitted
protected-call regions and the bound FH3 cleanup chains. At each potentially
unwinding call, every handler consuming slot 88 or 152 has the original saved
pointer available. No handler reads the reused input slot 112. Nounwind cleanup
calls are not incorrectly classified as potentially unwinding calls merely
because they lie textually after a cleanup-state marker. OS dispatch behavior,
indirect alias preservation and complete handler-frame cleanup are not inferred
from this caller-side availability check.

The reproducible checker is `windows_enclave_sha2_narrow_lifetimes.py`, integrated
into the existing batch report and regression suite. This closes the narrow
pointer-origin/definition-lifetime subtask, not package 5: input/authority field
integrity against indirect writes, compact-index preservation, physical
allocation validity/separation and complete cleanup composition remain separate.
No production code, saved native image or release-gate policy changed.

```sh
python3 scripts/cryptography/windows_enclave_sha2_batch_chains.py \
  release-reports/windows-local-20261004 --mutate \
  --output release-reports/windows-worker-review-20261006/sha2-batch-narrow-lifetimes-linux.json
```

## Metadata preservation checkpoint (2026-10-07)

The next saved-image review joins the existing compaction, pointer-origin,
vector geometry and helper-effect contracts with an exhaustive LLVM address-use
inventory. It covers 143 aliases / 159 accesses in the narrow digest and
145 aliases / 139 accesses in the wide digest. All 82 tracked helper callsites
receive explicit effects; LLVM `readonly` annotations alone are not used to
declare a callee harmless. Unknown address operations and escapes reject.

Input descriptor fields have only their assigned initialization writes; the
wide input descriptors are read-only throughout. The authority callback,
backend identity and owner-to-authority pointer fields remain immutable, while
the separately reviewed counter and quarantine writes remain allowed. The
narrow iterator's pointer/integer roundtrip includes its complete temporary-slot
use population, not just its two casts. The input and compact-array validity
analysis follows branches, loops, invokes and cleanup transfers. All 90 input
reads and sixteen compact-index reads require their current initialization;
terminal workspace wipes and lifetime ends cannot establish a reusable fact.

The emitted compact cursors have separate phase-specific definition checks.
Narrow slot 104 has four reloads and one width increment rooted at workspace
offset 4096. Wide slot 944 has three original-base reloads; slot 1024 has three
cursor reloads and one increment rooted at workspace offset 4576. Earlier
status/index uses and later scalar/output uses cannot satisfy the vector-phase
proof. Complete vector-region checks supply the bounded cursor arithmetic;
partial slot overwrites, missing initializers and altered increments reject.

This closes the **conditional metadata-preservation and compact-cursor subtask**,
not the physical allocation/separation or whole-frame review. The analysis uses
the already reviewed machine geometry and helper contracts of these exact bound
images. It is not a general LLVM range prover, a proof that distinct symbolic
roots cannot alias, an independent retest or a fresh native enclave execution.
Package 5 remains open. Production code and release-gate policy are unchanged.

All 194 tests pass on both Linux and Windows (98 self-contained and 96
saved-artifact tests), including 164 new saved-artifact rejection mutants. The
parsed integrated reports match. The source/report bindings and explicit scope
are recorded in
`assurance/windows-protection-observations/sha2-batch-metadata-progress-20261007.json`.

Reproduce the integrated report and its regressions with:

```sh
python3 scripts/cryptography/windows_enclave_sha2_batch_chains.py \
  release-reports/windows-local-20261004 --mutate \
  --output release-reports/windows-worker-review-20261006/sha2-batch-metadata-linux.json
python3 scripts/cryptography/test-windows-enclave-sha2-batch-chains.py \
  --saved-directory release-reports/windows-local-20261004
```

## Concrete allocation and lifetime checkpoint (2026-10-07)

The saved SIMD review now connects the actual constructor/page placement,
worker publication, input-copy destinations and nested caller frames. It no
longer relies on naming `resident-page`, `worker-input` and `resident-frame`
as different symbolic roots to establish their conditional separation.

Both constructors place authority at page offset 0 and owner at offset 24.
The allocated authority region is `[0,24)`; the narrow owner occupies
`[24,312)`, and the wide owner `[24,320)`, within the same 4,096-byte page.
The complete constructor contracts and the three-pointer publication bridge
are checked together. Each image has nineteen direct resident/page metadata
references and exactly five publication/take/retirement writes. Nested workers
cannot take the metadata address or add another global mutation.

Fifteen normal-CFG admission edges per route must dominate the worker's receive
call: page/window checks, live identity, non-retirement operation and buffer
bounds. Construction/publication and retirement cannot reach that call in the
same invocation. This is conditional on the linked transport's serialized,
nonreentrant lifetime contract; arbitrary callbacks are not assumed safe.

All nine narrow and five wide host-copy destinations trace through every
reachable register definition to the original worker payload argument plus
the assigned slice/header offset. Partial writes, volatile-call clobbers,
unknown pointer arithmetic, implicit/multiple-destination instructions and
unanchored cycles reject. The existing typed descriptor construction checks
are joined to the actual owner/result/input ABI handoff.

The stack checker follows all normal branches and jump tables, verifies live
frame anchors, home areas and matched returns, and calculates both Win64 entry
alignments modulo 32. In coordinates relative to the worker RSP at `receive`:

| Allocation | SHA-224/256 | SHA-512 family |
| --- | --- | --- |
| Input slices (each 1,024 bytes) | `[64,8256)`; eight disjoint slices | `[64,4160)`; four disjoint slices |
| Header | `[8256,8544)` | `[4160,4320)` |
| Receive RSP | `-704` | `-464` |
| Typed input descriptors | `[-336,-144)` | `[-240,-144)` |
| Result | `[-496,-464)` | `[-384,-352)` |
| Aligned resident RBX | `-12784` or `-12768` | `-13520` or `-13536` |

Resident inputs, output descriptors/scratch and workspaces are bounded and
disjoint in these concrete coordinates. The wide child frame, control and
executor placements are also joined to this parent allocation. The existing
field-preservation, pointer-lifetime and helper-effect contracts remain required.

This closes the **conditional private allocation/lifetime join**, not the OS
residency or erasure guarantee. In particular, the admitted worker window must
contain the nested frames and their callees; payload bounds alone do not prove
that. Win64 nonvolatile/call behavior, `__chkstk`, serialized page retention,
SDK/runtime behavior and final window reclamation remain package-8 obligations.
Package 5 still needs its remaining caller/fail-stop and complete private
frame/storage cleanup composition. No production code, native image or release
gate changed; these are author checks of the already-bound saved images.

All 206 tests pass on both Linux and Windows (105 self-contained and 101
saved-artifact tests), including 74 new saved-code rejection mutants. The
integrated parsed reports match. Source/report bindings and explicit prerequisites
are recorded in
`assurance/windows-protection-observations/sha2-batch-allocation-progress-20261007.json`.
The new report uses output filename `sha2-batch-allocation-linux.json` with the
same reproduction commands above.

## Admitted narrow overflow-path composition (2026-10-07)

`windows_enclave_sha2_failstop.py` joins the two incoming edges of the saved
SHA-224/256 resident's `.B190` overflow-panic block to its admitted, preserved
inputs. The panic is still a nonreturning fail-stop: it is **not** assigned empty
returning effects or treated as successful cleanup.

The first comparison checks the iterator in RAX, not the active compact count.
RAX and the lane counter in RDX start at zero. Full-CFG reaching definitions,
single-entry checks and paired-update checks establish that both counters retain
the same value. Updates occur once per iteration and require the unsigned lane
bound of seven. Headers can therefore contain zero through eight, while the
overflow comparison sees only zero through seven, never `u64::MAX`. The proof
conservatively follows both sides of the exhausted iterator's pointer test; it
does not assume that a pointer-null predicate prunes a path.

The second comparison reads the final-byte count from the current scalar input
descriptor. Each field publication originates either in a zero definition or
in this lane's byte load through the actual unsigned admission check. Exhausting
all 256 byte values gives admitted counts zero through eight. The emitted
`testb $-9` excludes the aligned zero/eight cases from the partial-byte path,
leaving one through seven. Reaching definitions establish that this same byte
survives to the overflow comparison, including the intervening copy call under
the separately stated Win64 nonvolatile-register contract.

The parent joins these checks to the already-reviewed eight-lane input
construction and scalar selection, metadata preservation, physical allocation
lifetimes and exhaustive compaction replay. Added incoming panic edges, missing
guards, stale definitions, partial register clobbers and mismatched prerequisite
results reject. The guard proof deliberately does not replace the independent
compaction geometry/termination or complete-image checks.

This closes **these two selected overflow-path prerequisites** under the named
shared-runtime assumptions. It does not qualify arbitrary panic/unwind behavior,
individual caller-frame erasure, OS residency or the complete worker window.
Correction from the subsequent whole-function inventory: the wide selected
slice contains no direct panic call, but does branch to `.B302` outside that
slice. The earlier absence wording was too broad; see the checkpoint below.
Package 5 remains open for the remaining caller and private cleanup composition;
package 8 retains shared ABI, SDK, transport and enclosing-window obligations.
Production code, images and release-gate policy are unchanged.

Reproduce using the commands above with output name
`sha2-batch-failstop-linux.json`. The checkpoint's source/report bindings and
completed Linux/Windows regression results are recorded in
`assurance/windows-protection-observations/sha2-batch-failstop-progress-20261007.json`.
All 217 tests pass on each host (110 self-contained and 107 saved-artifact),
including 49 new saved-code mutants and eight prerequisite-result mutations.
The integrated parsed reports match, with all 140 review-module bindings current.

## Dynamic clearing descriptor checkpoint (2026-10-07)

The saved-image checker now assigns all five dynamic zeroizer call sites:
three in the SHA-224/256 route and two in the SHA-512 route. Each complete loop
checks both advances, the four/eight-lane termination bound, the matching
pointer/length loads and the null/empty skips. Alternate entries into the
iteration region reject. The complete generic output destructor, including its
separate eight-byte identity tail clear, remains independently checked.

For the narrow resident, a normal-CFG analysis tracks the initialized descriptor
regions at offsets 864 and 2912. Partial, overlapping and computed direct writes
invalidate their provenance. Reads before construction or after an unassigned
overwrite reject. Both aggregate transfers are checked byte for byte, including
the reverse transfer used by the final destructor. The constructor's existing
exhaustive identity replay supplies exact scratch destinations and widths.

For the wide child, the same analysis checks the copied descriptor region at
offset 816 through its inline cleanup and result transfer. The initial copy must
read the original R9 argument. The child's return transfer and both parent
aggregate moves preserve every byte. This does **not** yet join the caller's
original descriptor lifetime and returned-result discriminant across the call;
the report leaves that requirement open rather than inferring it from move
correctness alone.

The analysis also checks descriptor availability at nine narrow and ten wide
child protected-call boundaries against the saved FH3 cleanup-state chains.
Narrow returned-output cleanup uses a per-path availability flag; it is not
treated as unconditionally initialized. The handlers' actual descriptor arguments
are checked. This establishes caller-side availability, conditional on the
previously named ABI/helper assumptions. It does not prove OS exception dispatch,
noninterference of every earlier handler or complete cleanup coverage when a
flag is false. The wide parent's returned-output destructor still needs its join.

The wide overflow inventory now explicitly records the comparison/branch to
`.B302`, its shift-overflow panic call and `ud2`. Its admitted-input
unreachability join remains pending. This corrects the previous report's
selected-slice scope; no production behavior or existing panic guard changed.

Reproduce with the commands above and output name
`sha2-batch-dynamic-cleanup-linux.json`. The checkpoint's results and source/report
bindings are in
`assurance/windows-protection-observations/sha2-batch-dynamic-cleanup-progress-20261007.json`.
All 226 tests pass on each host (114 self-contained and 112 saved-artifact),
including 66 new saved-code mutations. The integrated reports match with 143
checker-source bindings; Linux took 363.760 seconds and Windows 383.261 seconds.
Package 5 remains open. These are saved-artifact author checks, not a new native
enclave execution or independent retest. No production source, image or release
gate changed. Direct-write preservation alone is not a whole-machine alias proof;
the remaining indirect helper effects, actual cleanup order and enclosing-frame
assignments must still be composed. Shared window/OS/SDK work remains package 8.

## Wide descriptor/result handoff (2026-10-07)

The subsequent `windows_enclave_sha2_wide_result.py` check closes the direct
wide caller/result obligation left open above. It composes the fresh descriptor
geometry, aggregate-move and direct-write lifetime checks; it does not replace
their helper, physical-separation or ABI prerequisites.

The child's hidden result pointer must originate in entry RCX and remain the
same pointer for all eleven result-object stores. The original R9 descriptor
argument may be consumed only by its two vector loads. Additional pointer aliases,
escapes, partial substitutions or result stores reject. The 72-byte descriptor
transfer and subsequent metadata writes have separate checked extents in the
104-byte return object. Metadata cannot overwrite the returned descriptors.

Every normal return must follow either the error tag at result offset 96 or the
complete preserved-descriptor copy followed by its result tag. The finite CFG
check includes branches and backedges; an early return, skipped copy, missing tag
or vacuous success form rejects. This is a one-way guarantee: a non-error result
has copied descriptors. It is not a claim that every successful computation uses
one particular public error/status value.

The parent passes its initialized descriptors at offset 352 and the result area
at offset 4640. Only the non-error edge of the offset-4736 tag comparison creates
the returned-descriptor fact. The error edge never initializes that fact. The
parent's full direct-write CFG then checks the forward and reverse descriptor
copies, both normal output destructors and its guarded unwind destructor at the
two protected-call sites. The original descriptor fact is invalidated by partial,
overlapping or unbounded computed writes; the result branch cannot restore a
corrupted original source. The actual aligned parent frame bases remain fixed.

The integrated report clears the previous
`original_R9_caller_bounds_and_wide_return_discriminant_join_pending` flag only
after this check passes. The standalone descriptor checker still correctly
reports that it cannot establish that join by itself. Complete indirect helper
effects, earlier cleanup-handler effects, the wide `.B302` admission proof and
the final private frame/storage assignments remained open at that checkpoint.
The following checkpoint closes the named overflow and handler-prefix joins.
No claim of whole-frame
erasure, arbitrary exception cleanup, OS residency or independent review follows.

Reproduce with the commands above and output name `sha2-batch-wide-result-linux.json`.
Results and source/report bindings are recorded in
`assurance/windows-protection-observations/sha2-batch-wide-result-progress-20261007.json`.
All 235 tests pass on each host (118 self-contained and 117 saved-artifact),
including 47 new saved-code mutations and three prerequisite mutations. Parsed
reports match with 144 checker-source bindings. Linux took 363.782 seconds;
Windows took 363.408 seconds.
Production source, images and release-gate policy are unchanged; the saved native
artifacts are reused, not presented as a new native enclave execution.

## Wide overflow and descriptor cleanup-order composition (2026-10-07)

`windows_enclave_sha2_wide_failstop.py` joins the saved wide `.B302` shift-panic
guard to the parent admission and child scalar-lane lifetimes. The whole-function
inventory still includes the panic call and `ud2`; an empty list of panic calls
inside the smaller finish slice is not an absence claim.

The parent publishes all four tail-byte fields with index 34, 74, 114 and 154,
corresponding to offset 24 in the descriptors at 192, 232, 272 and 312. Every
publication is zero or passes the unsigned one-through-eight admission guard.
Single-entry and backedge checks establish the complete publication induction;
the child call is reachable only through its exhausted-loop edge.

The child uses original input argument R8, saved at frame offset 1040. Its scalar
byte-offset starts at zero, advances by 40, and stops at 160. The nonempty-lane
path saves the current index at offset 1000 and restores that exact value before
the next increment. The absent-lane path preserves the same index. Both paths,
all reaching definitions, computed stack-store extents and bypass/replay edges
are checked. The field load at descriptor offset 24 therefore selects one of
the four admitted original fields. `testb $-9, %bl` selects only values 1–7;
the same BL survives to `cmpb $7, %bl` under the reviewed nonvolatile ABI. The
overflow branch is unreachable for these admitted, preserved inputs. Current
field-preservation and physical-allocation reviews remain explicit prerequisites.

`windows_enclave_sha2_cleanup_order.py` joins the caller-side cleanup order to
the previously checked dynamic descriptor lifetimes. It covers all 21 related
protected-call boundaries: nine narrow, ten wide child and two wide parent.
Complete prefixes of seven distinct handlers are checked, including their frame
reconstruction, guard, pointer reloads, preceding workspace wipe and quarantine
stores. The actual FH3 chain may not contain an unassigned earlier handler.

Narrow earlier handlers use the already traced authority slot. The wide check
re-traces the original incoming workspace, executor and the first-invoke
authority save at each applicable call; it does not assume that repurposed
offset 1024 always contains an authority. Handler write envelopes exclude the
live descriptor regions and guard flag. The returned narrow and wide parent
destructors have no earlier handler effects. Existing exact workspace-wipe
contracts are reproduced, not inferred from a function name alone.

These are conditional **caller-side** joins. Unwinding callees, normal helper
effects, private frame assignments, OS dispatcher/handler stacks and the shared
runtime contract are not thereby qualified. They do not establish individual
spill erasure, arbitrary exception cleanup or whole-frame erasure. Production
code, native images and release gates are unchanged.

Reproduce with the earlier commands and output name
`sha2-batch-overflow-cleanup-linux.json`. The new focused regressions reject 51
saved-code overflow mutations and five weakened overflow prerequisites, plus
37 cleanup-prefix/pointer mutations and twelve weakened cleanup prerequisites.
The complete two-host results are recorded in
`assurance/windows-protection-observations/sha2-batch-overflow-cleanup-progress-20261007.json`.
All 246 tests pass on each host (119 self-contained and 127 saved-artifact).
Parsed reports match with 146 current checker-source bindings. Linux took
375.776 seconds; Windows took 412.420 seconds.

## Normal helper effects and descriptor lifetimes (2026-10-07)

`windows_enclave_sha2_normal_effects.py` connects the existing finish and early
vector helper contracts to the concrete descriptor regions. Slice-relative
finish call offsets are translated to whole-function offsets and checked against
the actual call instruction and target. Earlier wide vector offsets are already
whole-function coordinates. Duplicate, stale and invented assignments fail.

This joins 53 returning callsites: 23 narrow, 28 wide child and two wide parent.
The selected scalar/transfer/control calls and six early wide calls retain their
checked argument-effect contracts. All twelve workspace wipe/drop calls also
receive explicit assignments. Each wipe uses the actual original workspace:
an uninterrupted resident-frame address calculation, or a full normal-CFG trace
from the child's original incoming workspace pointer. Complete wipe/drop bodies
are rechecked, including scalar/CPU field clearing; the symbol name is not the
proof. Their five-body normal stack closure is traversed and bounded.

Mapped writes, callee stacks and outgoing ABI home areas exclude live original,
child and returned descriptors, including the wide parent's two regions.
Narrow padding uses bytes 2928–2936 as control counters before the returned
descriptor is constructed there. This is valid temporal reuse, not simultaneous
nonoverlap: a CFG reachability check requires that no path from the completed
descriptor copy reaches those earlier helpers. Instruction ordering alone is
insufficient. An injected post-copy backedge is rejected.

Current original-pointer, descriptor, field-preservation and physical-allocation
reviews are required inputs. Their named Win64/runtime and external-allocation
conditions remain explicit. Normal stack bounds do not establish erasure of
each compiler spill, arbitrary unwind cleanup or whole-window qualification.

The exhaustive call inventory preserves the remaining composition work: 39
narrow calls, nine wide child calls and 25 wide parent calls. The narrow terminal
overflow call is listed separately, not assigned returning effects. The wide
whole-function terminal remains in its outstanding inventory; its admitted-input
unreachability proof is already recorded in the preceding checkpoint. Several
remaining calls have existing primitive/geometry reviews; this list requires
joining those reviews to the caller, not rebuilding the implementations.

Reproduce using the earlier commands with output name
`sha2-batch-normal-effects-linux.json`. The focused regressions exercise call
offsets, duplicate/missing contracts, descriptor-overlapping effects, nested
stack extents, pointer substitutions, bypasses, temporal-reuse backedges and
weakened lifetime prerequisites. This is saved-artifact author review, not a new
native enclave run. Production sources, images and release gates are unchanged.

Both hosts passed all 254 tests (121 self-contained and 133 saved-artifact).
Linux took 407.777 seconds and Windows 447.142 seconds. Parsed reports match,
including 147 current checker-source bindings. The new saved regressions reject
82 contract, pointer, control-flow, stack and prerequisite mutations. Hashes and
the exact partial scope are recorded in
`assurance/windows-protection-observations/sha2-batch-normal-effects-progress-20261007.json`.

## Wide child final outputs, clearing and callbacks (2026-10-07)

`windows_enclave_sha2_wide_outputs.py` assigns the remaining eight returning
calls in the saved wide SHA-512 child. Combined with the preceding normal-helper
checkpoint, all 36 returning calls are assigned exactly once. The remaining
shift-overflow panic call is listed separately, followed by `ud2`, and requires
the existing admitted-input unreachability proof. It is not given harmless
returning effects.

For each of the four final copies, the actual RCX destination and RDX capacity
come from that lane's preserved original descriptor. R8 traces to the original
workspace at offsets 1024, 1088, 1152 and 1216. R9 traces through the real
register/save/reload chain to the same descriptor length as the capacity. The
successful unsigned decremented-width check dominates each copy: a reached
copy has length 1–64. CFG checks reject entries that bypass argument setup or
width admission, partial pointer/length overwrites and stale phase-specific
slot contents.

This is a **conditional private-caller proof**. The already checked parent
constructs all four destination pointers inside its live output allocation at
offsets 1376, 1440, 1504 and 1568. They are nonnull. The analysis therefore
excludes exactly four corresponding preflight null edges, after checking their
actual predicates. It retains all other branches, including width rejection,
copy failures and later source-null checks. No arbitrary external descriptor
array is admitted by this reasoning; the original construction, preservation,
physical allocation and handoff contracts are mandatory prerequisites.

The error-clearing loop reuses the complete paired pointer/length induction
proof at indices 0, 16, 32 and 48. Nonempty clearing is bounded by each original
64-byte destination slot. The separate eight-byte identity clear traces its
pointer to frame offset 880 rather than assuming that RDI still means workspace.
All clear effects, final-copy destinations and normal callee stacks exclude the
live descriptors and subsequent copies' saved source/length slots. Copy sources
and destinations are disjoint owned allocations.

The first revalidator now traces to the original executor's authority field and
backend byte. The first cancellation call traces the original control pointer,
readonly vtable slot and callback data. Both targets are the existing bound
private leaves; their entire bodies are checked to be memory-free. The five-body
normal stack closure covers these two callbacks, the copy wrapper, byte-copy
helper and zeroizer. Shared nonvolatile ABI, live parent objects and remaining
parent-helper noninterference stay explicit conditions.

The focused regressions mutate source/length lifetimes, preflight bypasses,
capacity and lane substitutions, zeroizer pointer/count/loop behavior, callback
roots and bodies, and every new prerequisite. Reproduce using the earlier
commands with output name `sha2-batch-wide-outputs-linux.json`. Production
sources, native images and release-gate policy are unchanged. Whole-frame,
arbitrary-exception and independent qualification are not claimed.

Both hosts passed all 262 tests (123 self-contained and 139 saved-artifact).
Linux took 424.148 seconds; Windows took 456.418 seconds. Parsed reports match
with 148 current checker-source bindings. The new saved regressions reject 60
mutations. Exact scope and hashes are recorded in
`assurance/windows-protection-observations/sha2-batch-wide-outputs-progress-20261007.json`.

## Wide parent output transfers and cleanup (2026-10-07)

`windows_enclave_sha2_parent_outputs.py` joins ten previously unassigned normal
parent callsites to their original live allocations. All four copies read the
preserved lane pointer and length, use that same length for source count and
destination capacity, and reach the call only through the unsigned at-most-64
admission and nonnull source checks. Their destinations trace through slot 64
to the admitted operation result, then to owner offsets 24, 88, 152 and 216.
Correctness of the operation result remains an explicit caller prerequisite;
this check does not substitute a symbol name for that remaining contract.

All sixteen computed parent stores are bounded: eight input-descriptor stores
use the already-checked four-iteration publication index, and eight scratch
stores use a checked ten-iteration initialization loop. Full-width reaching
definitions include partial writes, overlaps and all normal CFG edges. Mutated
owner-slot bytes, loop seeds/strides/limits, and bypass entries are rejected.

The two scratch-clear calls write exactly frame bytes 1376 through 1631.
Scalar and CPU wipes trace their actual saved-register arguments back to the
original subobjects; their complete existing wipe contracts are replayed.
Both output destructors receive the previously proved live descriptor objects
at offsets 4640 and 352. They read the four preserved pairs, clear the parent
output allocation and erase the eight-byte identity tail. They do not erase
the descriptor pointer/length bytes themselves. The separate final frame
assignment must account for any such residuals.

Writes and the complete six-body normal helper-stack closure are disjoint from
all live descriptor regions and the saved owner-pointer slot. This adds ten
call assignments to the previous two parent workspace wipe/drop assignments,
leaving fifteen parent calls and thirty-nine narrow calls to compose. Remaining
operation/setup/check/child effects, nonvolatile ABI behavior and shared runtime
guarantees remain conditions; no whole-frame/image claim is made.

Five added saved-artifact tests reject 69 mutations: 28 lane/width/owner/call
bypasses, twelve owner-admission/pointer-slot or indexed-initialization corruptions, seventeen
cleanup argument/body changes, and twelve prerequisite/inventory/overlap cases.
The existing Linux/Windows suite also checks integration through the real parent
checker. This pass changes no production source, image or release-gate policy.

Final Linux validation passed all 267 tests in 443.613 seconds. Windows passed
all 267 tests in 459.215 seconds before the last admission-edge strengthening,
then all five affected tests on the final revision in 13.114 seconds. The final
integrated mutation reports match on both hosts with 149 current checker-source
bindings. These scopes are recorded separately, not reported as a final full
Windows rerun. Exact hashes and conditions are in
`assurance/windows-protection-observations/sha2-batch-parent-outputs-progress-20261007.json`.

## Wide parent admission and setup composition (2026-10-07)

`windows_enclave_sha2_parent_authority.py` checks the complete emitted operation
and authority-check bodies, then joins six actual parent callsites. The operation
compares the requested phase, rejects sequence wrap/mismatch, checks authority
health and the compiled kernel identity, and requires both callbacks to succeed
before publishing the original owner pointer with its non-error tag. Rejection
paths retain output clearing and quarantine. The check helper retains both
revalidations and its health-byte write on failure. The compiled callback's
complete body is memory-free; its source remains the image-bound constructor.

The parent passes the original owner/sequence arguments, phase zero and its
private result object. Result capture is reachable only through the non-error
admission edge. Both direct callbacks trace the authority and backend byte back
to that admitted owner, including the saved pointer's full-width reload. Both
later checks and the remaining output clear likewise use original owner roots.
The complete four-body normal closure (operation, check, compiled callback and
zeroizer) lies in parent-relative stack bytes -104 through -1. Its writes and
home area exclude live descriptors and the saved owner-pointer slot. Individual
compiler spill erasure and OS unwind behavior are not inferred from this bound.

`windows_enclave_sha2_parent_setup.py` additionally assigns all six parent
`memcpy`/`memset` calls: exact destination/source roots and byte counts, zero fill
values, allocation bounds and disjoint copy regions. Input descriptors, the
executor object, authority slot and owner slot remain untouched. The frame areas
later used for output descriptors may be initialization storage only because
the emitted CFG has no path from descriptor construction back to these calls.
Injected late re-entry edges are rejected, rather than treating instruction
order alone as a lifetime proof.

These six calls still depend on their bound SDK runtime memory semantics and
stack/ABI contracts, explicitly retained for shared completion package 8.
`memset` is not counted as volatile secret erasure. The private parent now has
24 assigned sites and three remaining sites: stack probe, input-tail mask and
child executor. Narrow caller composition and final private frame/storage
assignments remain open. No production image or release-gate policy changed.

Nine new saved-artifact tests cover this checkpoint. They reject 118 individual
helper-instruction deletions, eleven operation argument/result changes, fifteen
callback/check/clear corruptions, twelve authority prerequisite/effect changes,
24 SDK pointer/count/bypass changes, six late setup re-entries and six setup
prerequisite/inventory changes. These are author checks on saved artifacts, not
a new native enclave run or independent retest.

Both hosts passed the final 276-test suite (123 self-contained and 153 saved
artifact tests): Linux in 447.043 seconds and Windows in 461.136 seconds. The
31-test parent-focused run also passed. Integrated reports match with 151
current checker-source bindings. Exact source/report hashes, the 192 new
mutation cases and remaining conditions are recorded in
`assurance/windows-protection-observations/sha2-batch-parent-admission-progress-20261007.json`.

## Wide parent final call interfaces (2026-10-07)

`windows_enclave_sha2_parent_remaining.py` assigns the last three parent sites
without treating their distinct obligations as interchangeable. The stack probe
has the exact 12,984-byte allocation argument and occurs before private-frame
alignment; its register preservation and stack-touch implementation remain in
shared package 8. It is not assigned an empty memory-effect contract.

The tail predicate reads exactly one byte from the original current input's
`pointer + length - 1`. Its full emitted body, cleared temporary and leaf stack
are checked. The header cursor starts at the incoming argument plus twenty,
advances by twenty-four exactly once per published input, and selects four
headers. Only lengths one through 1,024 and terminal bit counts one through
seven can enter this predicate. Empty and byte-aligned inputs take separate
paths; they are not newly rejected by the public API.
CFG checks reject bypasses and repeated cursor advances. The broad input read
envelope is not an assertion that the predicate reads every byte.

The child call checks all six actual ABI arguments, including the two outgoing
stack slots and the workspace pointer's reaching definition. The existing
104-byte hidden-result contract and non-error descriptor handoff are required.
All 36 returning child helpers and the separately unreachable overflow terminal
are assigned exactly once. Their mapped effects exclude the parent's live input
headers, original output descriptors and admitted-owner pointer. Child result
stores construct a new returned object; they are not misclassified as preserving
an already-live returned object.

All 27 parent call **interfaces** are now assigned. This does not close private
frame erasure, every direct compiler spill, or shared-runtime qualification.
The report explicitly retains seven shared calls (the probe plus six SDK memory
calls), final child private-frame assignment, and the existing OS/window/ABI
conditions. The 39 narrow-route caller sites remain next. Six focused tests
reject 76 new mutations of predicate bodies, cursor/length/mask guards, argument
slots, inventories, effects and prerequisites. No production source, native
image or release-gate policy changed.

Both hosts passed all 282 tests (123 self-contained and 159 saved-artifact
tests): Linux in 455.123 seconds and Windows in 475.557 seconds. The integrated
mutation reports are identical after parsing and bind 152 current checker
sources. Hashes, scopes and remaining conditions are recorded in
`assurance/windows-protection-observations/sha2-batch-parent-remaining-progress-20261007.json`.

## Narrow admission and setup joins (2026-10-07)

`windows_enclave_sha2_narrow_admission.py` joins nine previously unassigned
sites to the existing original-owner, authority and input-lifetime reviews.
The shared complete-body checker now selects an explicit narrow or wide layout:
narrow output starts at owner byte 16, sequence at 272, phase at 280 and the
authority pointer at 8. Narrow rejection writes its one-byte enum tag, not the
wide two-byte tag. Both complete operation/check bodies retain phase, sequence
wrap/mismatch, health, kernel and callback failures; the success result must
still contain the original owner pointer.

All three direct callbacks receive the backend byte from the original authority.
Both output-boundary checks and the 256-byte owner-output clear retain original
owner roots through their actual reaching definitions. The tail predicate reads
one byte only on the admitted nonempty, partial-bit path; length is one through
1,024 and the terminal bit count one through seven. Its address is formed from
the same original input header and bounded eight-lane cursor. Empty and
byte-aligned inputs follow their existing separate paths.

The five-body normal closure (operation, check, compiled callback, zeroizer and
predicate) is bounded to parent-relative stack bytes -104 through -1. Mapped
effects exclude live original/returned descriptors, input headers and saved
owner/authority pointer slots. The separate 11,992-byte stack-probe interface
does not acquire an empty effect contract or runtime qualification.

`windows_enclave_sha2_narrow_setup.py` binds all six SDK initialization calls to
their exact original pointers, byte counts, zero-fill values and disjoint copy
ranges. The frame regions later used for output descriptors are reusable here
only because no normal CFG path from their construction can re-enter setup.
Regression probes add actual late backedges while keeping staging sequences
intact, so rejection depends on the lifetime check rather than stale offsets.
SDK memory and stack semantics remain shared package-8 obligations; ordinary
`memset` is not volatile secret erasure.

This leaves 24 narrow interfaces, not an unbounded new review population:
six vector-loop helpers and eighteen output/cleanup sites. Final private-frame
assignment and erasure remain open. Nine new saved-artifact tests cover 229
mutations: 132 helper instruction/label deletions, three wrong-layout selections,
21 authority argument/bypass changes, 24 predicate/cursor changes, eleven
admission prerequisite/inventory/probe changes, 24 SDK argument/bypass changes,
six late setup re-entries and eight setup prerequisite/inventory changes.
Production Rust, native images and release-gate policy are unchanged.

Both final full suites passed all 291 tests (123 self-contained and 168 saved
artifact tests): Linux in 510.820 seconds and Windows in 540.799 seconds. Parsed
reports match with 154 current checker-source bindings. The observation
`assurance/windows-protection-observations/sha2-batch-narrow-admission-progress-20261007.json`
records the source/report hashes, focused runs and remaining conditions.

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
  bounds, session accounting and indexed state write-back. Public lane compaction
  now has exhaustive typed-identity replay; finish its original caller
  preconditions and subsequent live-storage composition. The scalar remainder,
  padding and output-mask caller regions now have complete checks, including
  both variant dispatch tables and the specialized mask helpers. Compose the
  reproduced scalar compression/transfer contracts with these caller regions.
  Their complete bytes, references, round tables and exact ABI differences now
  have explicit checks; the changed zeroizer has a separate complete review.
  Positive clearing lengths now have exhaustive direct/tail call-site checks.
  Descriptor construction now establishes exact slot pointers and bounded,
  disjoint destination regions under the typed/live-frame preconditions.
  Propagate those origins through subsequent machine lifetimes and establish
  every remaining caller's valid/disjoint regions, rather than inferring caller
  safety from callee identity or bounded construction alone.
  Narrow authority and per-lane pointer definitions now have whole-CFG and
  invoke/cleanup-callsite checks; do not repeat that completed analysis. Next
  metadata/cursor and concrete allocation reviews above now join those private
  lifetime/separation contracts, subject to their named shared-runtime
  prerequisites. Do not repeat those completed conditional checks or promote
  them to whole-window residency or erasure. The later admitted overflow-path
  composition above closes the narrow `.B190` prerequisites; do not repeat that
  step. The dynamic descriptor checkpoint now covers all five clearing loops,
  narrow normal descriptor copies/direct-write lifetimes and nineteen protected
  call boundaries. The wide descriptor/result checkpoint now also joins the
  original R9 argument, both normal parent destructors and the two protected
  parent call boundaries. The latest checkpoint also closes the wide `.B302`
  admission proof and preceding caller-side cleanup-handler effects at all 21
  descriptor boundaries. Finish normal indirect helper-effect composition and
  close the finite private frame/storage assignments. Do not repeat completed
  loop, direct-write, result-admission, overflow or handler-prefix
  checks as a substitute for those remaining joins.
- Assign every reachable private frame and storage region, and resolve the
  remaining fail-stop caller preconditions.

Shared runtime, SDK, final platform/depth reconciliation and enclosing-window
reclamation remain package 8 obligations. Nothing here promotes moved-from
copies, compiler spills or incoming register saves to individually erased data.
