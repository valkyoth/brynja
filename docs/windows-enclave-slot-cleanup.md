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
