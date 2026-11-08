# AArch64 AES bounded emitted-code review

This is a **compile-only, partial review**, not AArch64 native timing acceptance
or final-linked application qualification. It does not add a hardware AES
backend or change the portable implementation.

## Reproducible scope

`brynja-verify run aes aarch64-dataflow-review` builds the checkout's
`brynja-crypto` library with default features disabled and `hazmat-aes-block`
enabled, for `aarch64-unknown-linux-gnu`. Both Rust 1.90.0 and 1.99.1 are checked
with panic abort and unwind: release optimization level 3, fat LTO setting,
one codegen unit, and overflow checks enabled. Library LLVM/assembly emission
under that setting is **not** evidence of a final application's LTO output.
Each configuration uses a fresh private Cargo environment, offline locked
dependencies, and explicit target selection. Logs include compiler identity
and hashes of the emitted LLVM and assembly artifacts.

The shared conservative LLVM model covers eleven helpers: byte substitution,
column mixing, scalar field inversion, AES-128/192/256 expansion and transform,
and both round-key additions. Loads and the inverse's byte argument are secret;
addresses, control conditions, variable shift counts, public helper arguments
and status returns must not depend on them. Unknown forms fail closed.

The only new intrinsic rule is `llvm.usub.sat.i64` in the wide round-key helper,
with two public scalar operands. This computes the remaining public slice
length, saturating at zero. It does not admit secret-dependent subtraction
operands, other widths, or other helper roles. See the
[LLVM intrinsic definition](https://llvm.org/docs/LangRef.html#llvm-usub-sat-intrinsics).

## Inverse assembly review

The scalar field inverse has its own AArch64 machine-instruction policy in
this check. Both compiler endpoints were inspected. Their instruction streams
use register Boolean arithmetic, immediate shifts/bit-field extraction,
sign extension, and register conditional selection. The only memory accesses
are an exact set of callee-save/restore operations at fixed offsets in an
80-byte stack frame. No calls, conditional branches, data-indexed accesses,
division, or variable shifts are admitted. The checker preserves `#` immediate
values, ignores comments/CFI metadata, and rejects unknown instructions and
operands. This is not a mathematical equivalence proof of the machine code.

| Compiler | Panic | Instructions | Review distinction |
| --- | --- | ---: | --- |
| 1.90.0 | abort | 596 | Some callee saves interleaved with register arithmetic |
| 1.90.0 | unwind | 596 | Same operations, callee saves grouped at entry |
| 1.99.1 | abort | 599 | Updated register arithmetic scheduling |
| 1.99.1 | unwind | 599 | Same normalized stream as abort |

`scripts/aes/aarch64-inverse-review.json` pins each compiler/panic stream
separately. Changes require inspection and an explicit policy update, never an
automatic fingerprint refresh. The grammar alone is not sufficient for a pass.
Register conditional selection is admitted as dataflow, **not** as a claim of
data-independent instruction latency or an assumption that a deployment has
enabled any architectural timing control.

The inverse and LLVM checks in each real configuration reject 23 mutations: a secret-dependent branch
in every LLVM helper, eleven unreviewed assembly operations, and one otherwise
allowed arithmetic insertion that must fail the exact fingerprint. Mutation
tests check the rejection reason so a broken fixture cannot masquerade as
successful coverage. Separate synthetic tests cover target selection, the
intrinsic's taint rule, instruction operands, frame/return population, policy
scope, missing/ambiguous artifacts, environment overrides and registry signals.

## Round-key addition, substitution and mixing assembly

Four additional emitted assembly bodies are reviewed in
`scripts/aes/aes_aarch64_helpers.py`. Their complete streams are pinned for each
compiler/panic pair; the instruction grammar alone cannot establish a pass.
Local branch labels are resolved to instruction indices before hashing, so
compiler label renumbering is harmless but branch retargeting is not. The only
admitted call is to the exact field-inverse symbol selected from this same
compilation and checked above. There is no automatic policy refresh.

| Helper | 1.90.0 instructions | 1.99.1 instructions | Branches / static calls |
| --- | ---: | ---: | --- |
| AES-128 round-key addition | 73 | 73 | 1 / 0 |
| Wide round-key addition | 164 | 164 | 16 / 0 |
| Byte substitution | 474 | 474 | 1 / 32 |
| Column mixing | 219 | 228 | 2 / 0 |

Counts exclude labels and CFI metadata. Abort/unwind streams are identical
after local-label normalization except Rust 1.90.0 substitution, which places
the frame-pointer setup two instructions later in abort builds. Both schedules
are separately pinned. Rust 1.99.1 substitution matches the 1.90.0 unwind
schedule. These are emitted assembly observations, not decoded final executable
bytes, a mathematical equivalence proof or a native instruction-latency result.

The reviewed data and control flows are:

- **AES-128 addition:** the round argument is shifted by four to form a public
  schedule offset. The bound check precedes loads; on the admitted path the
  state and round-key bytes are XORed at fixed offsets 0 through 15. The status
  return derives from the public bound, not the key/state. This helper is called
  by the separately constrained transform; this review does not widen its
  internal round-argument contract to arbitrary integers.
- **Wide addition:** the shifted public round and schedule length produce a
  saturated remaining length. The unrolled bounds exits and status returns
  depend on that length and public offsets. Each key address is the schedule
  base plus a public offset; loaded bytes are XORed into corresponding fixed
  state positions. Temporary registers reused for offsets are overwritten with
  public values before address use. Short internal slices can partially update
  state before returning failure, as the source specifies; this is not a new
  whole-operation failure-atomicity claim.
- **Substitution:** the sole conditional branch tests the public inverse flag.
  Both paths process 16 bytes at fixed offsets with affine Boolean operations
  and one field-inverse call per byte. There are 32 static call sites, not 32
  calls per execution. The state pointer is retained in a callee-saved register;
  the 32-byte frame saves/restores registers. No lookup table is used.
- **Mixing:** the first branch tests the public direction. The inverse path
  processes four columns using a public counter initialized to 16 and reduced
  by four, with fixed byte displacements and a four-byte pointer increment.
  The forward path is unrolled. Secret bytes feed scalar Boolean arithmetic,
  immediate shifts and sign extensions, not branch flags or addresses. The
  inverse path saves/restores a 16-byte frame on Rust 1.90.0 and a 32-byte frame
  on Rust 1.99.1. These frame restorations are not secret erasure guarantees.

Every real build rejects twelve additional mutations per helper, covering
unreviewed branches/calls/division/indexed loads/variable shifts/directives and
stack-pointer writes, plus otherwise admitted arithmetic insertion, changed
load base, deleted store and missing branch target. Together with the inverse
and LLVM controls, these contribute 71 mutations per configuration. Synthetic unit
fixtures exercise the checker but cannot pass a real policy. Unit tests also
bind immediate values, branch destinations, call identities and exact policy
population, including rejection of duplicate or dangling labels.

## Expansion and transform assembly

The six remaining portable helper bodies are reviewed in
`scripts/aes/aes_aarch64_rounds.py`, with explicit policies in
`scripts/aes/aarch64-rounds-review.json`. The four compiler/panic profiles are
pinned separately. Abort/unwind streams within each compiler are identical
after local-label and selected-callee normalization. Every instruction operand,
including frame offsets, byte permutations, round limits and clear-call
arguments, remains in the fingerprint. These are **library assembly** policies,
not final-linked machine-code qualification or equivalence proofs.

| Helper | 1.90.0 instructions / branches | 1.99.1 instructions / branches | Static calls / clear calls |
| --- | ---: | ---: | ---: |
| AES-128 expansion | 136 / 6 | 134 / 5 | 5 / 1 |
| AES-192 expansion | 149 / 6 | 148 / 5 | 5 / 1 |
| AES-256 expansion | 205 / 9 | 199 / 6 | 9 / 1 |
| AES-128 transform | 457 / 6 | 455 / 6 | 12 / 4 |
| AES-192 transform | 459 / 6 | 457 / 6 | 12 / 4 |
| AES-256 transform | 459 / 6 | 457 / 6 | 12 / 4 |

Counts exclude labels/CFI. Clear calls are included in static call counts;
dynamic counts depend on the public round loops. Expansion may only call the
selected inverse and the unique external core clearing declaration. Transform
may only call the selected substitution, mixing, appropriate round-key addition
and that clearing declaration. Normalization never admits an arbitrary symbol
merely because its name resembles a helper.

### Expansion bounds and dataflow

Each entry checks the public key slice length against 16, 24 or 32 before
reading key material. The initial key is copied to the schedule using fixed
vector/scalar loads and stores. The schedule cursor advances four bytes per
word; each generated word combines the previous word with the word one key
length earlier. Four byte inversions plus affine Boolean operations implement
SubWord. AES-256 has a second static SubWord path halfway through each 32-byte
key cycle. Rcon arithmetic is branchless and independent of key data.

Rust 1.90.0 uses cursor counters starting at 19, 27 and 35, terminating at 179,
211 and 243. The checked word-start limits are 175, 207 and 239. AES-128 uses
the public counter's low bits for its 16-byte cycle, AES-256 for its 32-byte
cycle. AES-192 computes a public modulo-24 selection with reciprocal multiply
(`umulh`, shift and `msub`), using the public counter and constant reciprocal;
no secret byte is a multiply operand or branch condition.

Rust 1.99.1 moves length rejection ahead of frame allocation and proves away
the internal impossible bounds exits. AES-128/256 retain fixed four-byte cursor
increments and public terminal comparisons. AES-192 uses `umulh`/`madd` with
public counters for the cycle selection and an `adds` carry exit after 46
generated words. The arithmetic between that counter update and its conditional
branch does not replace the flags with secret-derived flags. Short-key status
and successful completion status remain functions of public length/control.

All admitted expansion paths initialize a four-byte temporary word at
`x29 - 4` (stack offsets 12–15 in a 112-byte frame) and reach a common call with
that pointer and length four before return. Rust 1.90.0's internal bounds-error
paths also use that call. Rejected key lengths do not initialize this temporary.
The expanded schedule remains live intentionally; these calls do not destroy
the returned schedule.

**Observed spill limitation:** Rust 1.99.1 AES-192 expansion additionally stores
a key-derived intermediate at `[sp, #8]` and reloads it later. The explicit
four-byte clear at `[sp + 12, sp + 16)` does **not** clear that spill. Frame
deallocation and restoring registers are not erasure. This concrete observation
reinforces the documented compiler-spill/register limitation; this policy must
not be presented as whole-frame zeroization or deployment qualification for
residual-secret threats.

### Transform control and scratch lifetime

The public direction flag selects encryption or decryption. Each uses 10, 12
or 14 rounds according to the helper's fixed width. Initial/final round-key
XORs use unrolled fixed byte offsets; middle rounds call the already reviewed
round-key helper. Wide calls supply schedule lengths 208 or 240. Error branches
test its public bounds status, not a state byte.

Each ShiftRows copies the 16-byte state to the frame's fixed scratch area and
reads fixed permutations. Forward source indices are
`0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11`; inverse indices are
`0,13,10,7,4,1,14,11,8,5,2,15,12,9,6,3`. Each such copy is followed by a clear
call with `sp` and length 16, before the next helper call or possible bounds
error return. There are four static sites: middle/final rounds in each
direction. The 64-byte frame also contains saved registers, which this scratch
clear does not cover.

Rust 1.90.0 decrypts middle rounds with a counter initialized to the round
count and decremented before use; encryption starts at one. Rust 1.99.1 uses
round-count-plus-one with a minus-two call argument for decryption and a
zero-based counter incremented before the encryption round-key call. The
resulting schedule rounds are unchanged. Secret state bytes only enter
fixed-offset state writes and the selected arithmetic helpers.

The expansion/transform policies bind the external clearing routine's **call
identity and arguments**; its matching implementation is reviewed in the core
dependency section below. The six bodies contain no
local unwind landing pads; panic-mode coverage here does not establish caller
unwind cleanup or exception-table correctness.

Sixteen mutations per new helper exercise unknown operations/calls, changed
load bases and stores, immediate round bounds, branch retargeting/missing
targets, removed clearing calls and wrong clear pointer/extent. The combined
helper checks reject 167 mutations per configuration, 668 across four builds.
Synthetic regression tests separately exercise symbol admission, role-specific
callees, policy population, operand preservation and ambiguous/dangling labels.

## Surviving secret-output wrapper assembly

`scripts/aes/aes_aarch64_wrappers.py` and
`scripts/aes/aarch64-wrappers-review.json` add six emitted bodies to the same
compile-only registration. These are the ephemeral AES-128/192/256 owner
transforms, cached AES-128 transform and two width-specific wide secret-output
helpers. **They are not every public caller.** Cached AES-192/256 callers are
inlined around the wide secret helpers; those callers have the separate
entry-point review below. Public-ciphertext paths also have a separate review.

| Wrapper | Rust 1.90.0 instructions, abort / unwind | Rust 1.99.1 instructions, abort / unwind |
| --- | ---: | ---: |
| Ephemeral AES-128 | 104 / 128 | 102 / 127 |
| Cached AES-128 | 88 / 104 | 86 / 100 |
| Ephemeral AES-192 | 76 / 90 | 68 / 82 |
| Ephemeral AES-256 | 77 / 91 | 69 / 83 |
| Wide secret AES-192 | 53 / 70 | 52 / 69 |
| Wide secret AES-256 | 53 / 70 | 52 / 69 |

The selector requires the exact six-body population and rejects wrapper aliases
or unfamiliar owner namespaces. Each generic wide secret helper is identified
by its call to the already selected width-specific portable transform; current
compiler generic-name parameters must agree with that width. Ephemeral wide
owners can only call their matching expansion and secret-output helper.

External core calls are bound to unique LLVM declarations for
`SecretRegionInitialization::{begin,write,finish}`, its Drop implementation and
`clear_owned_region`. The parser handles the quoted legacy Drop symbol without
loosening its identity pattern. Unwind profiles additionally bind the declared
`panic_in_cleanup` and the emitted `_Unwind_Resume` ABI call. This verifies
**which routine is called**. The matching core bodies are reviewed separately
below; runtime unwind trustworthiness remains outside this registration.

### Reviewed normal and error paths

- Owner wrappers first request initialization of exactly 16 output bytes. An
  initialization error returns without reading input or expanding a schedule.
  Key admission uses public pointer/length metadata. Ephemeral owners zero a
  176-, 208- or 240-byte local schedule before calling the matching expansion.
  An expansion failure clears that schedule and drops the output guard.
- The AES-128 paths and wide secret helpers copy exactly 16 input bytes to
  fixed stack scratch and invoke the selected transform with the public
  direction flag. Transform failure clears the scratch and drops the guard;
  ephemeral callers additionally clear their schedule. Cached AES-128 rejects
  absent or incorrectly sized schedule storage, then uses the borrowed schedule
  directly; it does not clear the live cached key after every block.
- Output is passed through the core initialization guard's 16-byte `write` and
  consuming `finish`. Only successful finish constructs the returned secret
  owner metadata. Error paths set the error discriminant, retain no successful
  owner, and clear temporary state. These are secret-output owners, not public
  plaintext release paths. Guard copies in frames are pointer/length/lifecycle
  metadata, not copies of the guarded output bytes.
- Rust 1.90.0 checks the write result's low byte against its compiled success
  encoding, four. Rust 1.99.1 uses `mov w8, #255; bics wzr, w8, w0` to check
  the changed encoding. Begin/finish result checks similarly change from a
  comparison against one to zero tests. Those are public result tags, not
  comparisons of cryptographic output. The compiler-specific streams are
  pinned separately rather than assuming a stable Rust enum ABI.
- Scratch and schedule clear pointers/extents are preserved verbatim in the
  policies. Rust 1.90.0 ephemeral schedules begin at `sp + 64`; Rust 1.99.1
  places them at `sp + 32`. The wide secret helpers use a 16-byte state at `sp`.
  Ephemeral AES-128 uses `x29 - 48` on 1.90.0 and `x29 - 112` on 1.99.1;
  cached AES-128 uses `x29 - 16` and `sp + 32`, respectively. Full frame sizes
  and register-save areas are also pinned, but are **not** asserted to be erased.

### Emitted unwind cleanup, not unwind dispatch qualification

Unwind builds contain additional cleanup bodies. The emitted paths clear an
initialized state/schedule, conditionally drop the still-owned output guard,
and resume unwinding. Ownership flags are reset before transferring the guard
to `finish` or the wide secret helper so its caller does not drop it twice.
Cleanup failure routes end in `panic_in_cleanup`. Normal-return bodies use
the same lifetime distinctions even when the compiler merges error exits or
removes redundant branches.

The normalized fingerprint retains branch destinations and the instruction
positions of `.Ltmp` exception-range and function-begin labels. Numbering may
change, but labels cannot silently move, duplicate names or dangle. Different
metadata and branch labels may legitimately refer to the same instruction.
**CFI, LSDA exception-table contents, personality selection and runtime unwind
dispatch are not qualified by this policy.** No native ARM unwind execution was
performed, and panic-abort builds cannot establish cleanup on abort.

Every real build rejects sixteen additional mutations per wrapper: unknown
operations and callees, permitted instruction insertion, removed clearing or
guard-drop calls, zero clear length, redirected clear pointer, wrong success
discriminant, deleted first call, retargeted branches and unknown branch
destinations. Helpers and wrappers together reject 263 mutations per
configuration, 1,052 across four builds. Synthetic regressions also cover
exact policy population, alias/namespace/generic-width confusion, ambiguous or
missing external declarations, role-specific calls and exception-label positions.

## Matched core output initialization, transfer and clearing

The registration additionally emits `brynja-core` LLVM and assembly using the
same compiler, target, release profile, panic setting and private Cargo
environment. It requires exactly one artifact of each kind and logs their
hashes. The five imported core symbols selected from the crypto library must
exist as **definitions with exactly matching names** in the core artifact;
missing definitions, alias substitutions and ambiguous helpers fail. The
private copy and volatile zeroizer are selected by exact module/function
patterns. Core source, manifest/dependency/build-script inputs are tracked
(the reused `asan-source-core` input group does not imply an ASan execution).
This matching is library-level, not a claim about a downstream final linker.

`scripts/aes/aes_aarch64_core.py` and
`scripts/aes/aarch64-core-review.json` pin all seven instruction streams and
their direct/tail call destinations. Tail branching to the zeroizer is distinct
from calling it and returning; neither can silently replace the other. The
zeroizer's complete normalized LLVM body is separately pinned, including its
volatile byte store and single-thread compiler fence.

| Core body | Rust 1.90.0 instructions | Rust 1.99.1 instructions | Reviewed behavior |
| --- | ---: | ---: | --- |
| Initialization begin | 23 | 23 | Reject empty region; clear before creating guard |
| Initialization write | 28 | 29 | Check ownership, length overflow and capacity before copy |
| Initialization finish | 16 | 15 | Exact completion; clear incomplete owned region |
| Clear owned region | 9 | 9 | Reject empty region; call volatile zeroizer |
| Initialization Drop | 6 | 6 | Clear complete owned region if present |
| Private byte copy | 21 | 21 | Public-count word/tail copy; erase working registers |
| Volatile zeroizer | 5 | 6 | Public-count zero-byte loop |

Rust 1.90.0 abort/unwind differ only in the placement of register saves/frame
setup in begin/write; both are pinned separately. Rust 1.99.1's seven streams
match across panic modes after symbol and local-label normalization. These
bodies contain no local unwind landing pads or unreviewed calls.

### State and bounds observations

`begin` checks the public region length, invokes the zeroizer before returning
pointer/length ownership, and initializes the written-byte count to zero. Empty
regions take the error path without memory clearing or secret-byte reads.
`write` checks that the guard still owns a region, then checks unsigned overflow
of initialized length plus input length and compares the end against capacity.
Rust 1.90.0 uses `cmn` for the carry check; Rust 1.99.1 uses `adds`. Every failure
returns before the copy or initialized-count update. The admitted destination
address is base plus the public initialized offset; input bytes do not control
the checks. Only successful copying advances the initialized count.

`finish` requires an owned region and exact initialized length. A complete
region becomes the returned owner without clearing its secret. An absent region
returns an error; an incomplete owned region returns the error encoding and
tail-calls the zeroizer for the entire region. Rust 1.90.0 explicitly nulls the
consumed guard pointer on success; Rust 1.99.1 removes that dead store in this
consuming boundary. Neither emitted success path calls guard Drop. Standalone
guard Drop checks presence, loads the full region length, then tail-calls the
same zeroizer. Result-tag encodings agree with each compiler's wrapper checks.

### Clearing and copy observations

The zeroizer tests the public byte count, then writes zero once per byte while
decrementing the count. Rust 1.90.0 increments the pointer with a post-indexed
store; Rust 1.99.1 uses a separate increment. There are no secret loads, calls,
stack accesses, tables or data-dependent branches. Empty slices return without
a store. The LLVM fence is a **compiler barrier**, not a CPU/device fence,
cache flush or DMA synchronization operation.

The private copy uses public source/destination pointers and length. Eight-byte
loads/stores consume full chunks, followed by byte loads/stores for the tail.
Only the remaining length controls branches and only the offset controls
addresses. Before normal return it sets `x4` (the loaded secret), `x5` (offset)
and `x6` (remaining count) to zero and sets flags with `cmp xzr, xzr`. It makes
no calls and uses no stack. This is a narrow observation of this routine's
working-register cleanup, **not** caller-register, spill, interrupted-state or
whole-process erasure. Valid disjoint live slices remain a caller precondition.

Each configuration rejects 105 assembly mutations across the seven bodies and
two zeroizer LLVM mutations removing volatility or the compiler fence. The
helper/secret-wrapper/core slices therefore reject 370 mutations per
configuration. Additional regressions cover exact dependency
identity, wrong targets, missing/duplicate core artifacts, build failures,
alias substitution, tail calls, unsigned bounds, zero-store values and all
three copy working-register clear operations.

## Public ciphertext boundaries

`aes_aarch64_public.py` and `aarch64-public-review.json` add the six emitted
`encrypt_block_public` methods: ordinary and expanded owners at each key width.
Selection admits exact legacy/v0 names and namespaces, rejects aliases,
missing/duplicate owners and unexpected widths, and binds each width to its
already-reviewed transform (and, for ordinary owners, expansion). Calls to
other widths, indirect calls, unknown instructions and addressing forms fail.
All operands, local branch destinations and emitted EH-label positions remain
in the pinned fingerprint. These are library artifacts, not final-linked code.

| Owner | Abort instructions, both compilers | Unwind instructions, both compilers | Abort/unwind clear calls |
|---|---:|---:|---:|
| AES-128 key | 43 | 55 | 2 / 4 |
| AES-192 key | 44 | 57 | 2 / 4 |
| AES-256 key | 47 | 60 | 2 / 4 |
| Expanded key, each width | 30 | 37 | 1 / 2 |

Ordinary owners zero their operation-local 176/208/240-byte schedules and pass
public key pointer/length metadata to expansion. Expansion failure skips input
loading and destination writing, then clears the schedule. On success the input
block is copied into 16-byte stack scratch and transformed with inverse=false.
The transform's result bit controls whether a single 16-byte load/store copies
that scratch to the caller's output. On failure that copy is skipped. Scratch
is cleared on either normal transform result, then the schedule is cleared;
the original result is preserved across clear calls and returned.

Expanded owners first check schedule presence and exact 176/208/240-byte length.
Rejection returns before input loading, transformation or destination mutation.
Admitted owners use the same private-scratch, success-before-copy and scratch
clearing pattern. They do not expand or clear the caller's retained schedule.
The 48-byte stack frame is allocated after admission in abort builds and before
admission in unwind builds. Rust 1.90.0 abort orders several frame saves/input
loads differently; those streams have separately reviewed fingerprints.

Unwind builds contain cleanup paths that clear initialized block scratch and,
for ordinary owners, the temporary schedule before `_Unwind_Resume`. Ordinary
AES-192/256 have an additional `panic_in_cleanup` call site compared with
AES-128. Expanded owners have one scratch cleanup path and a cleanup-panic
terminal. These bodies and EH-label positions are pinned; **the exception
tables and runtime dispatch to them remain unqualified**. A panic after the
public copy is not a promise to retract ciphertext. Abort cannot run unwinding
cleanup. SIMD register `q0`, caller registers, saved registers, unowned stack
slots and interrupted execution are not covered by an erasure claim.

Each public boundary rejects 18 deliberate mutations, including inverted success
branches, output stores moved before transformation, wrong destination pointers,
removed transforms/clears, zero clear lengths, wrong clear pointers, changed
return status and redirected branches/callees. Separate regressions preserve EH
positions, cleanup/resume calls and exact symbol populations. These add 108
mutations per configuration, bringing the helper/wrapper/core/public slices to
478 per configuration. No production AES code was changed by this review.

## Key and expanded-key constructors

`aes_aarch64_constructors.py` and `aarch64-constructors-review.json` cover the
six surviving `new` bodies: ordinary and expanded AES-128/192/256 owners.
Exact legacy/v0 symbols and namespaces must be present once, without aliases.
Each constructor can call only its selected guard operations and, for cached
owners, its width's expansion plus the selected clear routine. The core guard
bodies and expansion are reviewed above; no new unchecked dependency is
introduced by these call edges. As with the other boundary policies, every
operand, local branch destination and EH-label position is pinned, not only
the instruction/call counts.

| Constructor | 1.90.0 instructions, abort / unwind | 1.99.1 instructions, abort / unwind |
|---|---:|---:|
| Ordinary key, each width | 55 / 61 | 53 / 59 |
| Expanded AES-128 | 80 / 97 | 78 / 92 |
| Expanded AES-192 | 81 / 98 | 79 / 93 |
| Expanded AES-256 | 82 / 99 | 80 / 94 |

### Normal and error paths

Ordinary constructors pass the caller's storage pointer and exact 16/24/32-byte
extent to `begin`, which clears the destination before admitting the guard.
An error result exits without reading key bytes. On admission, the guard's
pointer/length/initialized-count metadata is moved into its local owner, and
`write` receives the original input pointer and the matching fixed key length.
Write failure stores an error tag and calls guard Drop. Write success moves
the guard into `finish`. Only a successful finish stores the returned region's
pointer/length and a success tag in the result. A failed finish returns an
error without dropping the already-consumed original guard; finish itself owns
incomplete-region cleanup. No ordinary constructor expands the key or directly
loads key bytes: the reviewed core copy handles their transfer.

Expanded constructors first admit the full 176/208/240-byte destination through
the same guard. Only then do they zero their operation-local schedule, call the
matching expansion with a 16/24/32-byte input, and test its result. Expansion
failure and guard-write failure clear the temporary schedule and drop the
still-owned guard. A complete write transfers the guard to `finish`. Both
finish-result paths clear the temporary schedule, but only success returns the
initialized caller-owned schedule. There is no clearing of that successfully
returned schedule in the constructor.

The compiler differences are material and reviewed separately: 1.90.0 uses
128-byte ordinary frames and 320/352/384-byte expanded frames, with expanded
schedule storage at `sp+64`; 1.99.1 uses 144-byte ordinary frames and
352/384/416-byte expanded frames, with schedule storage at `sp+32`. The result
tag checks agree with the corresponding core policies: 1.90.0 compares guard
errors to one and write success to four; 1.99.1 uses zero/nonzero guard tags and
the write success encoding 255. Error branches and multiple return paths are
retained in the complete-stream fingerprints.

### Emitted unwind cleanup

Ordinary constructors have a landing-pad body that drops the still-live guard
after a write unwind, then resumes; a cleanup panic has a terminal call. In
expanded constructors, `w21` starts at one while the original guard is live and
is zeroed immediately before consuming it in `finish`. Their emitted unwind
path clears the temporary schedule, then drops the original guard only when
that ownership flag remains set. Rust 1.90.0 additionally tracks a merged
normal-error cleanup path with `w20`, distinguishing errors before finish from
errors after guard consumption. These flags describe ownership/result state,
not key values. Both compilers preserve the resume and cleanup-panic edges.

This checks the **emitted cleanup instructions**, not LSDA/CFI tables, runtime
dispatch, or cleanup after abort. It also does not establish register, whole
frame, stale metadata, compiler-spill or physical erasure. The existing
key-derived spill caveat in AES-192 expansion remains unchanged.

Each constructor rejects 25 mutations: missing guard operations, zero admission
or write extents, incorrect input pointers, wrong result tags or ownership
metadata, premature ownership publication, redirected branches, and (for
expanded constructors) removed expansion/clearing or incorrect sizes/pointers.
Regressions also check unwind ownership flags, cleanup/resume removal, EH-label
positions, exact symbol populations and fail-closed grammar. These add 150
mutations per configuration, bringing the preceding slices to 628 per
configuration.

## Twelve secret-output API entry points

`aes_aarch64_callers.py` selects the exact twelve `encrypt_block` and
`decrypt_block` methods for the ordinary and expanded AES-128/192/256 owners.
Legacy/v0 symbol populations, owner namespaces and operation names must match;
missing/duplicate methods, aliases and unexpected widths fail closed. This
completes the entry-point paths to the six secret-output wrappers above for
these particular library artifacts, not arbitrary consumer inlining or every
AES lifecycle method.

Eight methods (all ordinary owners plus expanded AES-128) contain exactly six
instructions on both compilers and panic profiles. They forward destination
from `x2` to `x4`, input from `x1` to `x3`, set the inverse flag in `w5` to zero
for encrypt or one for decrypt, load the owner's pointer/length into `x1/x2`,
move the result pointer from `x8` to `x0`, and tail-branch to the selected
owner's transform. The validator requires that exact sequence and destination;
changing the tail branch to a call or changing even one argument is rejected.
These methods allocate no stack, load no key/block bytes themselves and have
no cleanup after the tail transfer.

The four expanded AES-192/256 methods have 53 instructions on Rust 1.90.0 and
57 on Rust 1.99.1, with three local branches and three return paths. They load
the retained schedule's public pointer/length metadata, then admit the 16-byte
caller output through `begin`. A failed admission returns an error. A missing
schedule or a length other than 208/240 returns an error and drops the admitted
output guard, clearing the destination. Input block bytes have not been read on
those rejection paths. On admission, the complete guard metadata is moved into
the argument for `secret192`/`secret256`; the call receives the selected schedule,
input, result pointer and explicit inverse flag in `w4` (zero/one). The callee
owns that transferred guard. The caller does not drop it after the call and
does not expand or clear the retained schedule.

Rust 1.90.0 uses a 144-byte frame, compares the begin error tag to one, and moves
the guard from `sp` to `x29-32` before passing it. Its abort/unwind profiles
differ only in frame-save ordering. Rust 1.99.1 uses a 160-byte frame, tests the
begin tag for zero, and retains `x23 = x29-32` to reload the admitted guard
metadata into the by-value argument at `sp+32`. Its abort/unwind streams match.
All of those offsets, metadata loads/stores and return paths are pinned in
`aarch64-callers-review.json`.

None of these twelve emitted entry points has a local unwind landing pad.
For cached-wide callers, the normal rejection path calls guard Drop; after
the successful transfer, cleanup belongs to the reviewed secret helper.
Absence of a caller landing pad is not evidence that the operation cannot
unwind. Exception tables/runtime dispatch and caller register/spill erasure
remain outside the claim.

Each short forwarding method rejects twelve mutations (six removed instructions
and six changed arguments/direction/callee). Each cached-wide method rejects
twenty mutations, including wrong direction, wrong input/output pointers,
zero admission length, incorrect schedule bounds, erased guard metadata,
changed error tags, omitted calls and redirected branches. These add 176 per
configuration. The full registration now rejects **804 mutations per
configuration, 3,216 across four configurations**.

## Explicitly unfinished

- Coverage beyond the explicitly listed library bodies, including arbitrary
  consumer inlining, other API/lifecycle methods and relevant dependencies.
- Packaged final-linked application builds and their post-LTO instruction,
  call/address, cleanup and spill review, including exception-table/runtime
  unwind dispatch beyond the emitted landing-pad instructions above.
- Native AArch64 correctness and the predefined fixed/random timing campaign,
  with CPU/compiler/profile identity and retained alarms. Cross compilation or
  emulation cannot substitute for native timing observations.
- Physical fault, power/EM resistance, universal constant-time behavior and
  compiler-spill/register erasure guarantees. This check establishes none of
  those properties.

The v0.27.2 milestone remains in progress; this registration is independent of
the publication gate and does not promote historical evidence to a current pass.
