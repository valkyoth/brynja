# Saved bounded SHA-256 worker dispatch

The [observation](../assurance/windows-protection-observations/bounded-dispatch-20261005.json)
binds the 1,603-byte `RetainedWork` dispatcher and its 105-byte volatile-clearing
helper to the saved bounded SHA-256 image. The incoming address agrees with the
previously bound C dispatcher. This starts the image-specific Rust review after
the [shared C helper review](windows-enclave-sequential-helpers.md); it does not
qualify hashing/rehashing callees or the other seventeen sequential images.

## Artifact and dispatch identity

The original Rust archive and extracted member are separately SHA-256 pinned.
The member is `retained_rehash_worker.retained_rehash_worker.5ba691928e62cbf8-cgu.0.rcgu.o`
from the saved `bounded-cleanup-image/normal_rust.lib`; it was extracted with
`ar x`, not rebuilt. The inspector binds complete instructions, relocation
identities and the dispatcher runtime extent to the saved signed image.
The clearing helper has no runtime-function entry; the existing leaf binder
checks its exact bytes at the caller's resolved address. Absence of unwind
metadata alone is not treated as evidence of clearing behavior.

The indirect dispatch table is checked separately: all forty object bytes,
all ten REL32 relocations and their dispatcher-section targets, the linked
read-only table mapping, and every resolved operation destination. The table
cannot be replaced with arbitrary in-function offsets while retaining a pass.

| Operation | Selected path |
| --- | --- |
| 0 | Construct in the supplied retained page |
| 1 | Borrowed-input hash callee |
| 2, 5, 6 | Export; diagnostic wrong-token/null-destination variants |
| 3 | Dispose, handled before the jump table |
| 4 | Cancel retained result |
| 7 | Quarantine owner |
| 8, 9 | Rehash current/previous token through the rehash callee |
| 10 | Cross-token copy followed by rehash |

The spare table slot for operation three points to the common epilogue because
the earlier branch already handles disposal. The native private dispatcher is
not itself the supported application API; diagnostic operations do not imply
equivalent public facade exports.

## Inspected lifecycle and output paths

Construction rejects an already live owner, epoch overflow, a null page or
misalignment. It clears the entire 4-KiB page using an eight-byte-unrolled byte
store loop, initializes the retained result/owner metadata and only then
publishes the new epoch and live owner. The page is supplied under the C caller's
exclusive allocation/lifetime contract; the Rust entry is not a general safe
validator of arbitrary pointers.

Disposal removes the live owner, rejects absent ownership, clears the retained
32-byte result and writes the terminal state. It then clears all 4,096 page bytes,
including the owner's placement, and resets current/previous public token
metadata before returning four. This matches the C caller's subsequent full-page
readback and release path. The stale second word of an absent `Option` is pointer
metadata, not a second live page borrow; it is not claimed as secret erasure.

Export checks state and the complete supplied token before invoking the fixed
copy adapter. Token mismatch clears the result and returns the mismatch status.
After a returning copy call, both success and failure clear the retained result;
success empties it, while copy failure quarantines it. No transactional behavior
inside the SDK copy is inferred. Cancellation similarly clears the retained
result and selects its result according to the token comparison. Explicit
quarantine clears the result and preserves an already terminal state.

The hash/rehash paths publish returned token metadata only when the callee's
returned option indicates success. Their internal framing, hashing, workspace
cleanup and error handling remain separate review obligations. The cross-token
path clears its first 32-byte staging slot after the copy call; a compiler-created
copy used for rehash remains in the enclosing stack window. A copy failure also
clears the retained result and quarantines a nonterminal owner.

The clearing leaf uses byte stores for the length remainder and eight-byte groups
for the rest, with no stack frame or calls. Its whole emitted body is pinned and
all dispatcher references resolve to that exact helper. Its pointer/length
preconditions still come from the caller; this inspection does not turn it into
a safe arbitrary-memory operation.

## Stack and normal-return scope

The dispatcher saves five nonvolatile GPRs and allocates 320 bytes; its fixed
frame is 360 bytes excluding the call return address. In the reviewed C call
chain, its RSP is `H-464`, where `H` is the work-window upper boundary. The model
places result staging, token/candidate copies, saved registers and the opaque
output argument inside the existing 64-KiB wrapper-cleared window.

Those stack copies are **not** all individually erased at the dispatcher return.
Normal returns converge on the ABI epilogue, then return to the C caller and
clearing wrapper. The model stops at hash/rehash and copy-callee entry/home space;
it is not a maximum transitive stack-depth proof. No guarantee is added for
arbitrary unwind, fatal abort, SDK internals or caller-created copies.

## Validation and next step

Six focused tests pass on Linux and Windows, and the saved-image reports match.
The actual dispatcher/clearer reject 1,708 single-byte mutations per host.
Tests also reject altered dispatch destinations, incomplete tables, wrong
relocation targets/types, writable table mappings, branch changes and incomplete
body/reference inventories. The frame model is checked at three window bases.
These are offline inspection regressions, not fresh native crypto tests.

The subsequent [borrowed-input caller review](windows-enclave-bounded-input.md)
now binds `hash`/`receive`, their returning cleanup branches and known frames.
Next: rehash, deeper placement/wipe callees and copy adapters; then the other
distinct worker families. Whole-image
qualification and independent retest remain outstanding. Existing native/dump
campaigns were not rerun, and no production code, image or release gate changed.

```sh
python3 scripts/cryptography/test-windows-enclave-bounded-dispatch.py
python3 scripts/cryptography/windows_enclave_bounded_dispatch.py SAVED_DIRECTORY EXTRACTED_OBJECT --mutate
```
