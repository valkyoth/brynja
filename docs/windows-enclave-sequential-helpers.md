# Saved sequential helper normal paths

This extends the [shared C scaffolding review](windows-enclave-sequential-c-review.md)
to its selected called helpers and the public-marker routine invoked before
retained Rust dispatch. The [observation](../assurance/windows-protection-observations/sequential-helpers-20261005.json)
records 144 complete helper bindings across the same eighteen saved signed
images: eight shared templates totaling 1,028 bytes. Both hosts reproduce the
same parsed report. This is offline author inspection, not native execution,
independent qualification or a new release gate.

## Bound population

| Helper | Bytes | Scope inspected |
| --- | ---: | --- |
| `BaseLockedBody` | 80 | Admission check, public-marker call and normal return |
| `locked_work` | 337 | Fixed public sentinel, normal clearing/readback and cookie-call boundary |
| `page_info` | 137 | Stack-guard page metadata validation |
| `notify_host` | 78 | Public window address/event acknowledgement |
| `retained_guards` | 98 | Three-page protection sequence |
| `retained_page` | 122 | Retained-page metadata validation |
| `retained_notify` | 93 | Retained middle-page address/event acknowledgement |
| `retained_free` | 83 | Allocation release and success/failure bookkeeping |

Each complete body and relocation inventory matches across the eighteen original
C objects. Each is separately linked to its own signed image and reconciled with
the previously bound callers. Shared globals, helper-to-helper calls and named
SDK imports must agree; identical function names alone are insufficient.

`BaseLockedBody` and `locked_work` have exception-handler metadata. For these two,
the inspector checks that the selected runtime range covers the **entire** COFF
function section before using the handler-aware binder. It binds their associated
metadata and expected `__C_specific_handler` / `__GSHandlerCheck_SEH` identities.
This does not qualify handler behavior, the cleanup funclet on arbitrary unwind,
or fatal cookie-check paths. The other six helpers use the existing complete
function/unwind-chain binder. No parser acceptance rules were relaxed.

## Normal-path observations

Both page helpers request exactly 48 bytes of `VirtualQuery` metadata. They reject
short/failed results before inspecting the returned structure, require committed
memory with the exact requested protection, and check complete 4-KiB coverage.
Base-address ordering is checked before subtraction; region size is checked
against 4 KiB before subtracting the page size. Thus their coverage comparison
does not rely on a wrapping subtraction. `page_info` additionally records the
query error in public status storage. Neither helper dereferences payload bytes
or proves the OS implementation of the query.

`retained_guards` requires, in order, no access for the first page, read/write for
the middle page and no access for the last page. It stops on any failed check.
The region comes from the previously reviewed allocation/guard setup; these
private helpers are not general validators for arbitrary wrapping addresses.

The notification helpers initialize the reply to null, require the callback
(and retained allocation where applicable), and combine a page address with the
public event code. They return success only when `CallEnclave` succeeds **and**
the reply is exactly one. This acknowledges host orchestration, not independent
attestation of residency. Page addresses/events are metadata; they are not
copies of retained payloads.

`retained_free` calls `VirtualFree` with zero size and `MEM_RELEASE`. Failure
records the error and preserves the retained pointer. Only successful release
nulls the pointer and records the success flag. This helper is not an eraser:
the caller's prior Rust disposal and full-page zero readback remain necessary.
Construction-error uses occur before a successful live-owner construction and
must not be mistaken for a secret-owner destructor.

`BaseLockedBody` returns zero without admission. Otherwise it calls `locked_work`
and normally skips the exception-handler body to return public step metadata.
`locked_work` fills and checks a fixed 256-byte public sentinel, then clears and
checks it on normal return. Its final cookie check is a separate runtime boundary.
The optional synthetic exception path and associated funclet are not evidence
of arbitrary secret-bearing exception cleanup. This routine runs before the
subsequent retained Rust work, not as a digest implementation.

## Local storage and limits

The frame model is tied to the inspected prologues, saved-register locations and
call sites. With `H` denoting the upper work-window boundary, the shared C body
uses RSP `H-96`; the selected nested public-marker frame uses `H-480`; the nested
retained-page query frame uses `H-240`. Its public query structure, acknowledgement
slot, sentinel, cookie and reviewed saved-register slots all lie inside the
existing 64-KiB clear/readback window. Register restores are not independently
called erasure; the surrounding clearing wrapper remains part of the contract.

The model stops at SDK and `RetainedWork` entry/home space. It does not calculate
their full transitive stack use. Admission/finish/restoration callback frames
below the work window are explicitly excluded; their public-only arguments and
the wrapper's register clearing remain necessary. No claim is added for loaded
SDK identity, fatal exits, caller copies, privileged snapshots or arbitrary
exceptions.

## Checks and next work

Six focused tests pass on Linux and Windows. They reject wrong parent/child
addresses, image/extent drift, changed globals/imports/handler identities,
instruction and branch changes, and incomplete body/relocation inventories.
The actual saved templates reject 1,028 single-byte mutations on each host.
The translated frame model has the same offsets at three aligned window bases.
These are inspection regressions, not fresh cryptographic or enclave tests.

The selected shared C helper normal paths are now reconciled. The subsequent
[bounded dispatcher review](windows-enclave-bounded-dispatch.md) starts the
distinct retained Rust worker/storage review without qualifying its callees.
Remaining storage/copy/return paths are followed by
the remaining compiler/SDK scope reconciliation and independent retest. Shared
C helpers do not transfer a Rust-worker review across algorithms. The completed
nineteen-image and scoped dump campaigns are unchanged and were not rerun.

```sh
python3 scripts/cryptography/test-windows-enclave-sequential-helpers.py
python3 scripts/cryptography/windows_enclave_sequential_helpers.py SAVED_DIRECTORY --mutate
```
