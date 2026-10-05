# Saved Windows ParallelHash slot cleanup review

This is a **selected author review**, not whole-image qualification or a new
release gate. On 2026-10-05 the four emitted `Slot::run`, its destructor funclet,
`Slot::absorb`, and four-slot array-drop bodies were reviewed against the saved,
uninstrumented concurrent image. The linked bytes, relocations and associated
handler metadata are checked against the exact original COFF object. No worker,
cryptographic implementation, native image or release policy changed.

## What the emitted instructions establish

- `run`'s ordinary validation/revocation errors converge on a 64-byte volatile
  clear of the slot's CV followed by the `Dead` phase. The successful path sets
  `Complete` and bypasses this clear so the root can consume the CV. State
  finalization/squeeze error paths conditionally drop the initialized state
  before entering the same slot-clear path.
- `absorb` rejects a wrong phase, plan pointer or index **without consuming or
  clearing that slot**. Once admitted, the state-update result is saved, the
  complete 64-byte CV is cleared, and the slot becomes `Dead` before returning.
  A rejected identity must not be described as an unconditional erase operation.
- Four-slot destruction invokes the volatile-clear target four times, at CV
  offsets 16, 104, 192 and 280, each for 64 bytes. The corresponding phase bytes
  at 80, 168, 256 and 344 are then set to `Dead`.
- The retained destructor funclet conditionally calls the state destructor,
  then clears the slot and marks it `Dead`. Its exact parent metadata references
  this funclet. This does **not** establish that an OS exception invokes it.
  The previously reviewed Rust panic path still terminates through fast fail;
  it does not imply recoverable-panic cleanup.

The compiler materializes two separate 992-byte state regions in `run`, at
stack offsets 64 and 1056 after its aligned allocation. It copies between them
using `memcpy` and vector/scalar moves. Dropping the active state must not be
mistaken for erasing every prior compiler-created copy. Those stack copies
depend on the enclosing full-window reclamation on normal return. Saved
nonvolatile registers are restored, not claimed individually scrubbed here.

For the reviewed straight leaf chain, the aligned `run` stack pointer is 2,496
bytes below its own 64-KiB window's upper bound. Both state regions, its saved
slot pointer, parent-frame pointer and pushed registers fit in that window.
The CV slot itself belongs to the root's published storage, not this worker's
stack; this arithmetic does not invent a measurement of root-slot placement.
The parent root's calls to `absorb` and array-drop are modeled separately.
Called state/kernel/library bodies need their own review; this is not a maximum
transitive stack-depth calculation or a generic machine-code taint analysis.

## Reproduction and limits

`scripts/cryptography/windows_enclave_slot_review.py` accepts the original
object and signed image, checks their identities before parsing, verifies the
four linked bodies and handler records, and checks 17 instruction anchors,
19 selected branches and all 16 named call relocations. `--mutate` rejects
896 single-byte changes to the reviewed object bodies. These are review-binding
mutations, not 896 executions or proof of general algorithm correctness.
Seven focused tests cover calls, branches, population, geometry and claim limits;
all pass on Linux and Windows. The actual saved-object/image inspection also
passes on both hosts with identical parsed results, including all 896 mutations.

The [source-bound record](../assurance/windows-protection-observations/slot-cleanup-20261005.json)
records the saved-image review. Previous native functional, register, placement
and dump results remain separate. Nothing here expands the protection boundary
to caller-created copies, arbitrary exceptions, fatal termination, privileged
snapshots or production signing. Remaining whole-image caller/runtime review
and independent retest are still pending.

## Direct state-destruction chain

The subsequent 2026-10-05 review follows `State` destruction through
`Memory::wipe`, `KeccakScratch::wipe` and the emitted volatile byte clearer.
All four exact bodies are present in the same saved object and signed image;
all sixteen call/tail-call relocations resolve to these bound bodies. The slot
callers' destructor and clearer targets agree. This closes the **direct normal
state-destruction chain** for this image, not the other state operations or their
transitive callees. No SDK call, allocation or callback appears in this chain.

For an initialized live state, the emitted writes are:

| Storage | Relative offset in the 992-byte state | Clearing behavior |
| --- | --- | --- |
| Seven Keccak scratch regions | 0–575 | Seven volatile clears; 576 distinct bytes |
| Sponge lanes, message/output counters, suffix | 624–857 | Four volatile clears totaling 234 bytes; executed twice through cancel/drop |
| Pending prefix content, if present | 936 | One volatile byte clear |
| Position | 616–623 | Ordinary zero store |
| Public prefix counters and used-bit count, if present | 864–927 and 937 | Ordinary zero stores |
| Failed/phase/prefix-discriminant metadata | 859, 962 and 938 | Terminal marker stores, not zeroization |

The empty-state branch skips payload access. The prefix discriminant becomes
absent before the later cleanup, and the intervening memory/scratch wipes do not
overlap it; therefore the retained second prefix check skips on the valid normal
path. This is not a guarantee for fabricated enum values or concurrent corruption.
Padding, unused fields and the entire 992-byte object are **not** claimed
individually erased. Prior compiler-created copies still depend on the enclosing
window wipe described above.

The byte clearer first stores `length % 8` zero bytes, then performs eight byte
stores per iteration until the end pointer. It has no calls, payload loads or
stack stores. Its reviewed callers supply valid bounded regions; the helper
does not validate arbitrary pointers itself. Exhaustive model checks for lengths
0–4096, 65535 and 65536 cover each requested byte exactly once. These are model
checks tied to reviewed instructions, not new native executions of those lengths.

On the previously mapped leaf chain, the destructor and helper stack pointers
are respectively 2560 and 2608 bytes below the worker window's upper bound.
A direct clearer call reaches 2616 bytes; the final tail clear reuses the helper
entry at 2568 bytes after frame restoration. Nonvolatile saves remain inside the
window and are restored, not individually erased. This finite chain bound does
not bound the complete worker, fault handlers or other algorithms.

Eight focused tests and the real saved-image inspection pass on both Linux and
Windows, with identical parsed records. All 495 single-byte changes to these
four object bodies are rejected by the review pins. The
[state-cleanup record](../assurance/windows-protection-observations/state-cleanup-20261005.json)
binds this review and its Python source closure. The command is
`python3 scripts/cryptography/windows_enclave_state_cleanup.py OBJECT IMAGE --mutate`.
It is an offline author tool, not a release gate or independent qualification.

## Publication join and destruction

The next saved-image review covers `Publication::join`, publication destruction
and `Option<Publication>` destruction. These are three distinct emitted bodies,
including the option's absent-value branch, not three names assumed to share
one implementation. Their only call is the reviewed `PrivateWaveAbort` fast-fail
target; the admission and polling operations are inlined.

The emitted locked compare/exchange loop closes admission while preserving the
generation, claimed/success bits and live-ticket bits. The polling predicate
requires CLOSED, not OPEN, and zero live tickets. It deliberately does **not**
require successful worker results: a failed operation must still finish joining
before its storage can be reclaimed. Join does not retire the generation or
authorize another wave. A previously retired publication bypasses its old
pointer cleanup; this prevents a late destructor from clearing a new wave's
publication. Empty options skip the publication entirely.

After observing quiescence the code writes eleven zero qwords: four slot
pointers, four bit lengths, and the input pointer, width and block metadata.
The inspector resolves each instruction's actual RIP-relative write address,
including the four-byte immediate following its displacement. All 88 bytes fit
in five disjoint writable, non-executable image globals, and the three bodies
agree on those targets. These are pointer/shape cleanup writes, **not payload
zeroization**. Slot CVs, input buffers and root/worker state retain their separate
clearing obligations. The emitted copied-input variant has no live `OFFSET`
global store in this cleanup sequence.

The polling loop has a `2^32` iteration budget and ends in fast fail if exhausted;
there is no timeout return that frees a root still borrowed by workers. This is
not a wall-clock bound, and it does not bound compare/exchange retries under
arbitrary contention. No fatal-exit cleanup or scheduler-fairness guarantee is
added. The selected direct call from the root uses a 40-byte stack allocation;
it does not load payload bytes or create a new payload spill.

Seven focused review tests and exact saved-image inspection pass on Linux and
Windows with identical parsed results. All 919 single-byte body mutations are
rejected by the review pins. A model exhausts all 19 relevant low gate bits,
checking that close preserves live tickets and that quiescence is distinct from
success and retirement; this is not a universal concurrent execution proof.
The existing ten real Rust gate tests also pass on both hosts under Rust 1.98.1,
including close/claim races, delayed generations and competing root reservations.
The tested gate source matches the gate source saved with the original image.
These fresh process tests do not rebuild or re-execute an enclave image.

The [publication record](../assurance/windows-protection-observations/publication-cleanup-20261005.json)
binds the offline review and its Python source closure. Process-test logs are
preserved under `release-reports/windows-local-20261005-publication/`. Reproduce
the review with `python3 scripts/cryptography/windows_enclave_publication_review.py OBJECT IMAGE --mutate`.
Root reduction, explicit retirement and the remaining state-operation/cross-image
review are still separate work; publication joining alone does not qualify them.

## Ordered reduction and generation retirement

The subsequent saved-image review follows the actual **copied-input** root and
its emitted dispatch closure, not the earlier fixed-public-input bridge. Both
Rust bodies and the native `PrivateSchedulerRetire` body are bound to their
original objects and the same signed image. This accounts for normal returned
success/error ordering; it is not a general concurrency or arbitrary-exception
proof, and does not change a release gate.

The dispatch closure calls native dispatch, then `Publication::join`, **before**
checking the dispatch result. Successful return additionally requires matching
claimed/success masks and a closed, quiescent Rust gate. Its ordinary failure
cleanup also joins before returning and clears publication metadata. The root
therefore does not reduce or destroy slots still borrowed by those workers.
Pre-publication failures have no dispatched workers to join. Fatal poll exhaustion
does not return into slot reclamation.

The root consumes up to four slots in index order, with the same plan and root
state passed to the previously reviewed `Slot::absorb`. Slots are at root RSP
offsets 448, 536, 624 and 712 (88-byte stride). Unused slots must have their empty
phase and zero CV; they are not silently accepted as completed leaves. Checked
additions and expected-count bounds precede committing merged-leaf/input-bit
accounting. Any returned reduction failure reaches four-slot destruction and
the root operation's cancellation path, not the next wave.

On success, four-slot destruction precedes reuse of that stack area for the
publication record. Rust retirement then requires quiescence, rejects an already
retired handle, and atomically replaces the gate with its generation and zero
low bits. Only after that succeeds does the root call native retirement with
the same generation. A native return other than one leads to publication/root
cleanup, never the loop back-edge. The next input copy is reachable only after
both retirements succeed. These distinct retirements are not interchangeable.

The emitted native retirement rechecks the generation, nonempty expected mask,
all claimed/success bits, CLOSED with neither OPEN nor RESERVED, zero live
workers, and **zero diagnostic readers** before its compare/exchange clears the
low gate word. A reader entering between the load and compare/exchange changes
that word and prevents retirement on that attempt. Its `2^32` retry budget ends
in fast fail rather than authorizing reuse. This is not a wall-clock or fairness
guarantee. Three inlined metadata-cleanup sequences resolve to the same eleven
zero-qword targets already reviewed; none is represented as a payload wipe.

Seven focused Python regressions and exact-image inspection pass on both hosts
with identical parsed results. The review pins reject 5,490 actual-body byte
mutations; that number measures identity protection, not executed schedules.
Separate predicate tests cover all claimed/success/expected masks and every
nonzero 12-bit reader count. The existing real C gate test was rerun on Linux:
baseline plus fourteen compiled mutation rejections pass, including removal of
the reader exclusion. Its tested header exactly matches the saved build's header
(`8d4cc0e083bb19fbaf1aa60f104ad26ddf547326bef2156e02947cf1c7a6b602`).
These are ordinary-process tests, not a new enclave campaign.

The [retirement record](../assurance/windows-protection-observations/retirement-cleanup-20261005.json)
binds the exact bodies, call edges and inspector sources. Reproduce using
`python3 scripts/cryptography/windows_enclave_retirement_review.py OBJECT NATIVE_OBJECT IMAGE --mutate`.
The C test logs are in `release-reports/windows-local-20261005-native-retirement/`.
State construction/update/finalization, full root terminal cleanup and cross-image
runtime reconciliation remain separate; this review does not close whole-image
qualification or add production-signing, fatal-exit or privileged-snapshot claims.
