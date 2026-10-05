# Saved bounded cross-copy and output export

Follow-up: [bounded memory-runtime reconciliation](windows-enclave-bounded-memory.md)
binds the saved image's compiler-emitted copy/fill routines and their Rust callers.

The [saved observation](../assurance/windows-protection-observations/bounded-export-20261005.json)
continues the [input/observer review](windows-enclave-bounded-callbacks.md) in the
same signed bounded image. It binds six additional complete C/Rust bodies:

| Function | RVA | Body bytes |
| --- | ---: | ---: |
| `PublicCrossCopy` | 14,176 | 194 |
| `PublicCrossControl` | 14,096 | 75 |
| `PublicRetainedCopy` | 16,592 | 52 |
| `PublicRetainedOutput` | 16,864 | 34 |
| `PublicRetainedControl` | 16,544 | 44 |
| `RetainedTokenWord` | 4,096 | 21 |

This inspector is deliberately specific to the saved image, not a generic
linker-layout detector. It pins full object bytes and relocations, reconstructs
every REL32 displacement including its addend/trailing immediate, and compares
the complete linked body at its reviewed RVA. Code must be mapped and
nonwritable. The call-free/tail-transfer bodies must not overlap unwind entries;
the cross-copy routine has one complete 40-byte fixed frame. Named controls
also match the PE export directory. The Rust dispatcher resolves cross-copy,
output-copy and token storage to those same entries/addresses, and shared C
globals agree with the preceding review. Twelve writable, nonexecutable metadata
spans are checked for complete mapping and separation.

## Cross-copy and public token reports

Cross-copy requires active/retained entry, operation exactly ten, a destination
with at least 32 remaining bytes inside the locked window, and no previous
cross-copy attempt since the input-preparation reset. The upper-address check
precedes subtraction. It marks the attempt before calling the SDK, so an SDK
failure cannot reopen another attempt in that prepared request. Admission
failure returns `E_FAIL` without reading the source or copying payload.

On SDK success, it records success and copies exactly four eight-byte words
from the 32-byte destination into the cross report. These are **public protocol
token words**, not a confidential-input channel. The report is intentionally
readable through the idle host control; arbitrary confidential data must not be
submitted as a token. This is not provenance enforcement or a guarantee that
token/report copies are individually erased.

The already reviewed Rust dispatcher copies the staged token into its comparison
slot, clears the 32-byte input staging on both success and failure, and checks
the SDK result. Failure clears the retained digest and quarantines a nonclosed
owner. Success continues into the previously reviewed rehash token checks. The
token comparison-slot copy remains inside the enclosing wrapper-cleared stack
window rather than receiving a separate local erase claim.

`PublicCrossControl` rejects while active or retained. Operations 16–19 require
the retained-live flag and tail-transfer to `RetainedTokenWord` with index 0–3.
That Rust leaf independently rejects indexes above three before reading the
four-word token array. Operations 32–37 read only the six cross-report words;
all other operations return zero. The scalar/token returns add no local stack
frame. They intentionally expose routing/token metadata, not retained digest
storage.

## Explicit digest export

`PublicRetainedOutput` stores the host output pointer only while idle. It does
not dereference or validate that host pointer itself. `PublicRetainedCopy`
requires active entry, retained-call and retained-live flags, plus exactly
32 output bytes. It increments the fixed-call counter and tail-jumps to the
SDK outbound copy without adding a frame. The Rust caller supplies the source
only after its existing ready-state and exact-token checks.

After the SDK returns, that caller clears the retained digest regardless of
status. Success returns the owner to idle; failure quarantines it. The adapter
does not claim transactional rollback or erasure of a host destination that the
SDK may have partially written. This is an explicit output-export path; its
host-memory and declassification obligations are not replaced by enclave
workspace cleanup.

`PublicRetainedControl` accepts only idle operations 16–25 and reads the ten-word
retained report. These idle/active checks preserve the serialized fixture's
contract; they are not an added concurrency guarantee.

## SDK and stack scope

Both copy directions are bound through their exact import thunks and named
`vertdll.dll` import slots to the previously pinned SDK file's exports. The
outbound direction/syscall/status-tail inspection is reused alongside the
preceding inbound inspection. This is saved-file linkage, not proof of the
original process's loaded SDK identity, kernel-storage erasure or exceptional
termination behavior.

From the dispatcher at `H-464`, cross-copy reaches `H-512` and its nested SDK
copy reaches `H-560`. The outbound C adapter tail-transfers, so its SDK copy
reaches `H-512`, not an invented additional C frame. Cross-copy staging at
dispatcher RSP+128 and token comparison storage at +96 are each 32 bytes;
their spans, saved RBX and syscall return addresses fit the existing cleared
window at three tested bases. Exported host-control frames are not claimed part
of that worker window. Maximum transitive runtime depth remains a separate task.

Seven focused tests pass on Linux and Windows with identical parsed reports.
All 420 actual body-byte mutations are rejected per host. Regressions also
cover admission/failure paths, token/report ranges, REL32 addends and trailing
immediates, full linked-byte matching, writable/unmapped/overlapping code,
unwind overlap, Rust/C identity agreement, metadata placement and tail-frame
geometry. These are offline inspection tests, not a fresh native campaign or
independent pentest.

Production code, signed images and release gates are unchanged. Next are
memory-runtime reconciliation and the remaining distinct worker/image families;
whole-image qualification remains open.

```sh
python3 scripts/cryptography/test-windows-enclave-bounded-export.py
python3 scripts/cryptography/windows_enclave_bounded_export.py SAVED_DIRECTORY EXTRACTED_OBJECT --mutate
```
