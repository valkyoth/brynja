# Saved bounded SHA-256 operation chain

The [saved observation](../assurance/windows-protection-observations/bounded-sha256-20261005.json)
continues the [owner-clearing review](windows-enclave-bounded-owner.md). It binds
five complete function bodies to the original signed bounded image, without
rebuilding the archive or repeating the native/dump campaign:

| Function | RVA | Bytes | Fixed stack use, excluding return address |
| --- | ---: | ---: | ---: |
| `update32` | 11,824 | 525 | 120 |
| `finalize_secret` | 12,848 | 691 | 104 |
| Scalar compression | 12,352 | 482 | 16 |
| Equal-length copy adapter | 11,632 | 32 | 40 |
| Opaque copy leaf | 11,440 | 68 | 0 |

Complete object bodies, relocations, linked bytes and runtime extents are checked.
The no-unwind copy leaf is separately bound through its incoming references.
Placement hash and rehash compute both resolve update, finalization, workspace
wipe and volatile clearing to the same reviewed bodies. The operation bodies'
exact reference inventory contains only these helpers and the scalar constant
table; the table's complete 256 bytes match in the object and readonly linked
image at RVA 33,028. No external runtime call is hidden in this operation chain.

## Update and finalization

Update reads the big-endian accumulated byte count, rejects addition wrap and
counts above `u64::MAX / 8` before mutation. A pending partial block receives at
most the remaining space and input length. The emitted destination bound is
checked against the 128-byte owned array. Full blocks are copied 64 bytes at a
time into block-copy storage; each compression is followed by clearing the
640-byte schedule and 128-byte block-copy region. A completed partial block is
also cleared. The remaining 0–63 bytes go to the partial buffer, and the new
big-endian count is committed only on the successful path.

Copy rejection returns an error. Update itself does **not** promise rollback or
a complete workspace wipe after partial progress: its previously reviewed
placement/rehash callers perform terminal cleanup. The review assumes a valid,
initialized owner and live, disjoint Rust slices. It does not reinterpret the
private buffer-length checks as a general detector for corrupted owner metadata.

Finalization clears its 32-byte destination before testing the active flag and
byte-count-to-bit-count bound. For a valid buffered length below 64, it copies
the tail into padding, writes `0x80`, emits an extra block when the tail length
is at least 56, and stores the big-endian bit length at padding offset 56. Each
compression is followed by schedule/block-copy clearing. The eight four-byte
state-to-output copies are checked at their exact source/destination offsets;
the unused output-staging suffix and partial-input region are cleared.

On success the 32-byte output is copied to the live destination and its pointer,
length and success discriminant are written. Errors write the error variant and
clear the destination again. Both paths restore the local ABI frame and tail-jump
to the already reviewed full 1,170-byte workspace wipe before returning to the
caller. This establishes the output shape relied upon by the callers' normal
success paths. It does not extend their cleanup guarantee to fatal shape-mismatch
aborts, arbitrary exceptions or invalid pointers.

## Copy and scalar helpers

The 32-byte copy adapter rejects unequal lengths without invoking the leaf.
Equal lengths are forwarded to the opaque transfer, then return the success
representation expected by update. Fixed equal-length finalization copies cannot
take that length-rejection branch under their valid-slice preconditions.

The copy leaf checks the public remaining count before each eight-byte access,
then handles the final 0–7 bytes individually. Empty input performs no access.
It makes no calls or stack accesses and clears EAX/ECX/EDX before returning.
Pointer registers are not claimed erased by that leaf; enclosing wrapper cleanup
remains required.

The scalar body reads 64 block bytes and 32 chaining-state bytes. Its schedule
and eight working words occupy offsets 0–287 of the 640-byte scratch region;
the constant-table index stays within 64 four-byte words. Its fixed-count loops
perform the scalar round work and state accumulation. Before return, it writes
zero across all 640 scratch bytes and clears the working EAX/ECX/EDX/R8D/R10D
registers. The opaque region contains no calls or stack accesses. The surrounding
prologue/epilogue saves/restores RSI/RDI; this is not a claim that every caller
register or compiler-created copy is individually erased.

This is a bounds, call-chain and cleanup inspection of the saved implementation,
not a new independent cryptographic-correctness proof or differential campaign.

## Stack scope and validation

Under the previously modeled placement chain, update reaches `H-3616` and
finalization `H-3600`. The nested copy adapter reaches `H-3664`; its call-free
leaf's return address reaches `H-3672`, the deepest point in this operation
chain. Scalar's two pointer pushes reach `H-3640` when called by update. No
alignment allocation is invented for either leaf. Finalization's wipe tail
reuses the original entry rather than retaining the finalization frame.

The saved-GPR, pointer/count and return/home spans fit the existing 64-KiB
wrapper-cleared window at three tested base addresses. This closes the local
operation-depth uncertainty, not the maximum depth of the entire image. The
enclosing C copy/observer/runtime paths and other distinct image families still
need reconciliation.

Eight focused tests pass on Linux and Windows; parsed saved-image reports are
identical. All 1,798 actual body-byte mutations are rejected per host. Focused
tests also reject changed admission/commit/error branches, rendering offsets,
copy-loop and erasure instructions, all 256 single-byte constant-table mutations,
missing/wrong call targets, wrong-image bindings and changed fixed-frame extents.
These are offline review regressions, not fresh native execution evidence or an
independent retest. Production code, signed images and release gates are unchanged;
whole-image qualification remains incomplete.

```sh
python3 scripts/cryptography/test-windows-enclave-bounded-sha256.py
python3 scripts/cryptography/windows_enclave_bounded_sha256.py SAVED_DIRECTORY EXTRACTED_OBJECT --mutate
```
