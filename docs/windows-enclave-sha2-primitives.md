# Saved scalar SHA-2 primitive cleanup review

Follow-up: the [runtime/export reconciliation](windows-enclave-worker-reconciliation.md)
now closes the direct memory/transport connections left open in this report.
Live-runtime and whole-image scope limitations remain explicit.

The [saved report](../assurance/windows-protection-observations/sha2-primitives-20261005.json)
continues the [state construction/consumption review](windows-enclave-sha2-state-review.md)
in the same scalar streaming image. It binds twelve complete helper bodies,
their relocations, actual caller/callee addresses, fixed frames and both round
tables. This is offline implementation-author review, not independent retest,
fresh native execution or whole-image qualification.

| Helper | RVA | Bytes | Fixed frame, including pushes |
| --- | ---: | ---: | ---: |
| `update32` | 7,056 | 525 | 120 |
| `update64` | 8,288 | 549 | 120 |
| `finalize32` | 6,368 | 674 | 104 |
| `finalize64` | 7,584 | 698 | 104 |
| narrow scalar compression | 9,536 | 482 | 16 |
| wide scalar compression | 8,848 | 545 | 32 |
| `write_secret` | 9,408 | 120 | 72 |
| `copy_secret_region` | 6,112 | 32 | 40 |
| `copy_bytes` | 6,032 | 68 | leaf |
| mask tail thunk | 6,144 | 5 | leaf |
| byte mask | 6,160 | 13 | leaf |
| mask predicate | 6,176 | 20 | leaf |

The update32 and two copy helpers exactly reuse the previously reviewed
[bounded SHA-256 bodies and references](windows-enclave-bounded-sha256.md).
They are still rebound to this image. Narrow scalar compression has the same
body but a different round-table symbol; its relocation identity is separately
pinned. Both tables are checked in the object and linked read-only image:
256 bytes at RVA 37,840 and 640 bytes at RVA 37,200. Leaf bodies are anchored
through actual incoming references, not selected by an unqualified byte match.

## Update and finalization

The wide update adds the input length to the big-endian 128-bit byte count,
checks carry/overflow and the bit-length ceiling before committing that count.
It fills the partial buffer, processes 128-byte blocks and retains the remainder.
Both update variants use bounded equal-size copies before compression, then
clear the 640-byte scratch and 128-byte compression block. Completing a buffered
block also clears the input region. Internal rejection relies on the reviewed
owner's failure/quarantine cleanup; it is not a standalone transactional API.

Both finalizers mark the state closed, copy the buffered bytes into padding,
append the partial byte and padding bit, and select one or two blocks. The
one-block thresholds are 55 and 111 buffered bytes. Narrow finalization writes
the 64-bit length at owner+952; wide writes the 128-bit length at +1008/+1016.
Each compression is followed by scratch/block clearing. Rendering performs
eight equal-width state-to-output copies (four or eight bytes each), followed
by a zero-filled output tail and a tail-call clearing the 128-byte input region.

These private functions depend on the already-reviewed caller: used bytes are
below the block size; a non-null fractional-byte pointer has a bit count 1–7;
narrow output width is 28/32; wide output width is at most 64. The retained
shift-overflow panic branch is unreachable under that admitted contract, not
proof of cleanup after arbitrary corrupted internal calls. The focused model
checks every valid buffer/partial-bit boundary and output width; it does not
execute the machine code or replace the existing vector/oracle tests.

Output-tail `memset` is ordinary zero filling, **not** a volatile-erasure claim.
The state, padding and rendered output remain until the enclosing finalizer
wipes the active 1,170-byte workspace. Old by-value copies and caller spills
still depend on the full outer stack-window clear.

## Compression, transfer and masking

The wide scalar body uses a fixed circular schedule and eighty rounds. Its
opaque block has no stack accesses; it clears all 640 scratch bytes and EAX,
ECX, EDX, R8D, R9D, R10D and R11D before return. Its four saved nonvolatile GPRs
are used as pointers within the function, but their incoming saved values may
contain caller data. Their stack slots therefore remain inside the outer-window
obligation. The narrow scalar body reuses the prior fixed-work review.

`write_secret` rejects an empty destination. For nonempty destinations it clears
the complete destination before comparing lengths. Equal lengths permit the
copy; mismatch returns an error and tail-clears the destination again. Checked
copy rejects unequal lengths without writing; the byte-copy leaf clears its
payload temporary after the word/byte loops. The byte mask performs AND/OR,
stores the masked byte and clears EAX. The predicate intentionally returns its
boolean result in EAX and clears its R10D payload temporary. This mask body is
not conflated with the scheduler's differently specialized helper.

## Scope, stack and validation

The deepest selected caller is state finish at H-5,232. Its update frame reaches
H-5,360, copy frame H-5,408 and copy leaf H-5,416. Fixed-frame and caller argument
spans remain within the 64-KiB window at three tested address bases. Call-free
scalar leaf saves are modeled without inventing stack alignment allocations.
Final clear and output-error clear tail calls reuse their caller's entry frame.
This is selected-chain arithmetic, not the maximum transitive image depth:
`memset` implementation/dispatch and the remaining runtime/export/SDK boundary
still need image-specific reconciliation. No arbitrary-exception claim is added.

Nine focused tests pass on Linux and Windows with identical parsed saved-image
reports. All 3,731 actual helper-body byte mutations are rejected on each host.
Separate regressions cover references, semantic landmarks and rendering without
hash checks, both round-table byte sequences, exact inventories/call edges,
frame/image substitutions and admitted padding arithmetic. No production code,
signed image, native campaign or release-gate policy changed.
