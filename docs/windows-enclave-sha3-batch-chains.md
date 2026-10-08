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

## Remaining package-6 work

- Complete nested slot selection and subsequent state/copy-helper caller
  arguments, including owner and input/output lifetime preservation by callees.
  The sequential update caller checkpoint below covers absorption after admission;
  it does not establish the initial state invariant supplied by `start`.
- Complete scalar setup finalization, final-bit framing, squeeze and retained-output
  production paths for both sequential routes; receiver-side export is checked.
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
