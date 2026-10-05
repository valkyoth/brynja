# Saved scalar SHA-2 streaming entry

Follow-up: [owner lifecycle review](windows-enclave-sha2-stream-lifecycle.md)
binds admission, quarantine, cancellation and destruction, including the moved
state-copy and deferred full-page clearing limits described below.

The [saved report](../assurance/windows-protection-observations/sha2-stream-entry-20261005.json)
reviews the scalar `sha2/mod.rs::open` image's entry, request receiver and buffer
destructor. It follows the bounded-image review but does not assume that the
two workers have interchangeable layouts or lifecycle rules. The SHA-NI image
has a distinct resident owner and protocol and is not qualified by this step.

| Selected body | RVA | Bytes | Fixed frame, including pushes |
| --- | ---: | ---: | ---: |
| `RetainedWork` | 4,096 | 760 | 1,160 |
| `receive` | 5,504 | 414 | 104 |
| `Buffers` drop glue | 5,440 | 43 | 40 |

Complete object bytes and relocation lists are pinned and bound to the exact
saved image, with complete runtime extents and frame records. The previously
reviewed shared C entry resolves `RetainedWork` to this body. Its receive/drop
references agree with those bodies' linked addresses. Both the worker and
destructor call the same 105-byte volatile clearer reviewed in the bounded
image; its full bytes are identical and its incoming references and no-unwind
extent are rebound here. The live-owner pointer occupies a completely mapped,
writable, nonexecutable eight-byte region.

## Entry and normal cleanup

The entry checks a non-null, page-aligned pointer and a non-underflowing 64-KiB
window length. Creation requires no existing owner and writes initial public
metadata before publishing the live pointer. Other operations require a live
pointer equal to the supplied page. These early admission failures return their
existing status; this review does not invent quarantine behavior for them.
Page ownership, residency, serialization and window separation continue to rely
on the enclosing C admission contract, not merely these Rust checks.

Teardown calls the owner's destructor and, where the remaining enum tag
requires it, its state wipe. It then clears the live pointer and writes all
4,096 page bytes in an eight-byte-unrolled byte-store loop before returning
status four. This binds the normal caller ordering and final page overwrite;
the transitive owner destructor/wipe semantics remain a separate obligation.

Ordinary work initializes a contiguous 1,072-byte stack buffer. Compiler field
layout places the 1,024-byte payload first, at worker RSP+32, followed by the
48-byte header at RSP+1,056. Both spans are checked against the supplied window
before receiving a request. A window failure calls quarantine and buffer drop;
a failed receive calls quarantine before explicit clearing.

After receive, the worker clears the complete header and payload using the
volatile helper. Two emitted, short-circuit readback loops together inspect
exactly those 1,072 bytes. Any nonzero byte routes to quarantine/drop with error
205. Only successful readback calls `PublicSha2Observe` with public buffer
addresses and the cleanup flag. An observer result other than one takes the
same failure path. The destructor clears both regions again on normal exits,
including successful observer return. Successful receive returns the operation
with bit 32 set; failed receive returns 206 after cleanup. Observer success is
not itself cryptographic success.

The destructor makes one 48-byte clear call for the header, then restores its
frame and tail-jumps to clear the 1,024-byte payload. No additional call frame
is invented for that tail transfer. Compiler-held metadata/register copies are
not claimed individually erased by these buffer operations.

## Header validation and operation dispatch

The receiver requests exactly 48 header bytes through `PublicSha2Input`, then
checks protocol version six, a nonzero sequence, payload length at most 1,024,
and a last-bit field fitting in one byte. It checks null-source/zero-length
agreement and rejects source-address addition overflow before any payload copy.

Only update/finalize may carry payload or last-bit metadata. Update, finalize
and cancel require a zero algorithm field. Update requires a last-bit value of
eight for nonempty input and zero for empty input. Finalization's finer bit
rules and algorithm/sequence semantics remain downstream owner responsibilities.
An empty payload skips the second copy. A failed header or payload copy returns
false to the worker's quarantine-and-cleanup path.

The emitted operation index subtracts eleven and bounds it to five. Its exact
six-entry read-only table is reconciled from object relocations through the
linked image, selecting begin, update, finish, rehash, public export and cancel
for operations 11–16. Every destination remains inside the reviewed receiver.
The receiver forwards bounded slices and metadata and recognizes the owner's
existing success discriminant. This reviews dispatch, not the owner operations'
cryptographic semantics or the C/SDK copy adapters.

## Stack and evidence scope

The shared C body reaches `H-96`; the selected worker reaches `H-1,264`, receive
`H-1,376`, and buffer drop `H-1,312`. Payload, header and the final-bit stack
argument lie inside the previously admitted clearing window. Owner operations,
runtime fill, C input/observer adapters and their callees are explicitly listed
as unreviewed transitive edges. Their entry/home slots are modeled, not their
complete depth. No whole-image maximum-depth or arbitrary-exception claim is
made.

Eight focused tests pass on Linux and Windows with identical parsed reports.
Each host rejects mutations of all 1,217 actual selected-body bytes and all
24 actual operation-table bytes. Regressions also cover reference identity,
cleanup/validation landmarks, branches, frame/callee mismatches, table mapping
and translated window geometry. Related shared-C, dispatcher, leaf-binding,
frame and construction-review tests pass locally. This is offline author review,
not a fresh native enclave campaign or independent retest. Production code,
signed images and release gates are unchanged.
