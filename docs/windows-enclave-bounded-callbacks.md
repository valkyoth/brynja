# Saved bounded input and observation callbacks

The [saved observation](../assurance/windows-protection-observations/bounded-callbacks-20261005.json)
extends the [bounded SHA-256 operation review](windows-enclave-bounded-sha256.md)
to seven C adapters in the same signed image. The C object, Rust archive and
signed image remain unchanged. This is offline inspection, not a new enclave run.

| Function | RVA | Complete body bytes |
| --- | ---: | ---: |
| `PublicInputCopy` | 14,752 | 182 |
| `PublicInputObserve` | 14,944 | 134 |
| `PublicInputSource` | 15,088 | 30 |
| `PublicRehashObserve` | 16,240 | 149 |
| `PublicRetainedInput` | 16,656 | 201 |
| `PublicInputControl` | 14,704 | 44 |
| `PublicRehashControl` | 16,176 | 58 |

The complete bodies and relocations are pinned and matched to the linked image.
Copy has three contiguous runtime-function fragments that share one 40-byte
fixed frame. The other six bodies are individually reviewed call-free,
stack-free leaves with RIP-relative data references. Their specialized binder
accepts only this pinned population, rejects runtime-function overlap and
requires a unique complete nonwritable code match. Absence of unwind metadata
alone is not used as proof of leaf behavior.

The existing Rust receive, hash and rehash bodies resolve their calls to these
exact entries. The three host controls also match their named PE exports, not
just a similar instruction sequence. Shared globals agree with the prior
wrapper/C review. Nine metadata regions are mapped to complete, writable,
nonexecutable, mutually nonoverlapping spans.

## Admission and SDK copy

`PublicInputCopy` requires both active flags, a kind of zero or one, and a
destination span within the locked window. It checks the destination against
the upper bound before subtraction, then compares length against the remaining
space. Length is at most 1,024 bytes. Kind zero requires exactly 32 bytes; kind
one requires a nonempty payload and exactly one recorded successful header copy.
Rejections return `E_FAIL` without calling the SDK or incrementing counters.

The admitted path increments the appropriate attempt counter, forwards the
destination/source/length to the SDK, increments success only for `S_OK`, and
returns the actual SDK status. These counters rely on the previously reviewed
fixed header/payload call population and per-request reset, not arbitrary-loop
overflow handling. This adapter itself does not erase a failed copy destination;
the reviewed Rust error/cancellation path owns that cleanup. The host source is
not dereferenced directly here: its accessibility is delegated to the SDK copy.

The linked call reaches the exact import thunk at RVA 23,922 and named
`vertdll.dll!EnclaveCopyIntoEnclave` IAT slot at RVA 28,824. The separately saved,
hash-pinned SDK file exports that function at RVA 16,528. Its complete body sets
the inbound flag to one, calls the reviewed syscall stub, hands status to the
existing conversion path and tail-transfers after restoring its frame.

The [saved SDK status review](windows-enclave-sdk-frames.md) is reused, not
replaced by an assumption that an imported function is harmless. Matching an
on-disk SDK export does not retrospectively prove which module bytes were loaded
in the original application run. Kernel copy storage, interruption behavior and
SDK self-erasure remain outside this observation's claim.

## Metadata publication and reset

The source accessor returns the configured host address only during an active
retained call. The input observer requires a complete 56-byte report within the
locked window; rehash requires 64 bytes. Both reject before reading a report
outside that span. Each load/store pair is checked at its exact word offset.

Input observation publishes four storage addresses, input length, the caller's
cleanup-readback flag and expected sequence. Rehash publishes three storage
addresses, its cleanup result, old/new generation, epoch and operation status.
These schemas come from the already bound Rust callers. They are declared
metadata, not digest/payload bytes; this review does not promise that addresses,
message lengths or generations are confidential. Observer success means the
metadata was accepted, not that the underlying cryptographic operation succeeded.

`PublicRetainedInput` rejects during an active/retained call. Otherwise it stores
the host source pointer and resets all eight rehash words, eleven input words
and six cross-report words before returning success. Input readout accepts only
operations 16–26 while idle. Rehash readout accepts 16–24 while idle, with 24
returning the existing public-copy counter. Its other eight operations read the
rehash report. These checks retain the serialized fixture's existing contract;
they are not newly claimed atomic synchronization for arbitrary concurrent use.
Cross-report reset is covered, but the distinct cross-copy operation is not
qualified by inspecting its reset alone.

## Frame scope and validation

The copy adapter's three unwind fragments account for its RBX push, 32-byte
allocation and conditional RDI save in caller home space at RSP+48. In the
reviewed receive chain it reaches `H-3408`; the SDK copy's 40-byte frame reaches
`H-3456`, with the syscall return at `H-3464`. The observer/accessor leaves add
only their return address. Exported host-control frames are not included in
the worker's cleared-window model. All modeled spans fit at three tested window
bases; the model stops short of a kernel-storage or whole-image depth claim.

Nine focused tests pass on Linux and Windows, with identical parsed reports.
All 798 actual body-byte mutations are rejected per host. Additional regressions
cover copy bounds/status branches, report word offsets and relocations, pinned
data-leaf matching, unwind overlap, named exports/forwarders/ordinals, incoming
Rust edges, global identity/placement, chained frame geometry and every byte of
the SDK inbound-copy body. These are inspection-tool regressions, not an
independent retest or a new native cryptographic campaign.

The subsequent [cross-copy/export review](windows-enclave-bounded-export.md)
adds those distinct paths. Next are memory-runtime reconciliation and other
image families. Whole-image qualification remains open. Production
code, signed images and release gates are unchanged.

```sh
python3 scripts/cryptography/test-windows-enclave-bounded-callbacks.py
python3 scripts/cryptography/windows_enclave_bounded_callbacks.py SAVED_DIRECTORY EXTRACTED_OBJECT --mutate
```
