# Borrowed caller-input boundary

Status: isolated v0.24.50 Rust model and direct-copy worker experiment. **Not
secret-input qualification or a shipping Windows API.** Production implementations,
platform availability and release gates are unchanged.

## Preserve the existing contract

The existing strict SHA-2 worker already borrows caller buffers. Original input,
caller-created copies and public lengths remain caller-owned; implementation-owned
workspaces and output use protected storage. An enclave adapter need not add an
authenticated network protocol merely to preserve that existing local-input
contract. An attested confidential channel would be a **separate** capability and
threat model, not a prerequisite silently added to ordinary borrowed-input support.

The earlier public-only host fixture copies its input into a 1072-byte ordinary
request array. That is acceptable for its public vectors, but cannot be reused
for secrets while claiming that all new implementation-owned plaintext copies
are protected. This model instead serializes a fixed 64-byte descriptor containing
only public addresses, length and operation metadata. The original input remains
borrowed until the native adapter completes; no payload is copied on the host.

This does **not** conceal the caller's original input from its own process or
from a malicious containing process. Nor does a public address or token authenticate
the source. Rust borrows constrain safe callers; they cannot prevent an unsafe or
external actor from changing memory during the OS copy.

## Exact metadata and bounded snapshot

The eight little-endian u64 fields are version 3, reserved zero, length 0..1024,
input address, command address, command width 64, flags zero and trailing zero.
Empty input requires address zero and causes no input read. Nonempty input requires
a nonzero address and a checked end. The command range must be nonzero, bounded
and representable on the target. Malformed versions, widths, flags, overflow or
noncanonical empty input reject before the input reader or operation runs.

The host `Request` consists of exactly those 64 metadata bytes and zero-sized
borrow/thread markers. Its constructor only uses the borrowed slice's pointer and
length. It has no owned payload, secret byte view, Clone, Copy, Debug, Send or Sync
implementation. Metadata is intentionally copyable **public data**, not a
dereference capability: a real native adapter must retain the original request
borrow and must not accept arbitrary saved descriptors as safe pointer authority.

Inside the eventual protected worker, `Snapshot` owns a fixed 1024-byte region.
It clears the full capacity before admission, validates one private metadata
snapshot, requests at most one exact-length platform copy, then lends the admitted
bytes to the trusted operation. There is no second source read. A guard clears
the full capacity on success, rejection, partial copy failure and recoverable
unwind; the owner's Drop also clears it. Empty input does not pass a null pointer
to a platform copy API. No cleanup is promised for `panic=abort`.

The copy result means only that the selected reader reported success. It is not
authentication, a guarantee of an atomic snapshot under hostile mutation, or
proof the storage was locked. The higher-ranked operation borrow cannot escape
as a returned slice, but a trusted operation could still deliberately copy bytes.
These generic closures are research/test seams, **not a proposed user callback
API**. The native adapter must bind them to fixed platform-copy and in-enclave
operations and must keep raw metadata entry inaccessible through a safe facade.

## Tests and cross-build

```text
python3 scripts/cryptography/test-windows-enclave-borrowed-input.py
python3 scripts/cryptography/windows_enclave_borrowed_build.py <persistent-directory>
```

Four Rust tests run at O0 and O2. They exercise every length 0..1024, exact read
counts, changed source on a hypothetical second read, malformed metadata, partial
copy failures and both copy/operation unwind paths. Twenty independent Python
`hashlib` vectors pass through the snapshot and the existing first-party hardened
SHA-256 workspace with irregular updates; snapshot and secret output clearing are
checked separately. No production crypto code or dependency is changed.

Four compiled mutants skip clearing, ignore copy failure, reread the input or hash
unused capacity; each must fail its targeted test at both optimization levels.
A positive consumer compiles and 16 negative consumers reject source mutation,
escaped source lifetime, private storage access, returned snapshot borrows and
escaped copy-reader borrows and Send/Sync/Copy/Clone/Debug on either owner. Windows cross-compilation alone is not
native execution or a protected-memory test.

## Separate native worker experiment

`window_borrowed.rs` combines the model with the existing first-party SHA-256
workspace and one-use result protocol. Its separately built image reuses the
guarded, locked worker scaffold, without replacing the earlier signed image.
The worker copies only the 64-byte header first, then copies the admitted payload
directly from the original host address into its 1024-byte snapshot using
`EnclaveCopyIntoEnclave`. A private fixed copy adapter replaces the model callback.
The header, payload, command, workspace and output must all fit in the admitted
64 KiB window; report validation checks bounds and disjointness.

The snapshot has an explicit byte-array layout. The worker checks its full
capacity is zero after the scope returns, before its Drop and before the outer
assembly window wipe. Workspace and output clearing are checked independently.
Input-copy failures cannot issue a result. Successful results retain the existing
explicit public-export/cancel decision and terminal replay rejection.

Seven compiled worker tests run at O0/O2, including all 1025 lengths, 20 independent
digests, post-copy source mutation, partial input-copy failures, malformed
metadata, transport failures and terminal result handling. Four broken model
variants are linked into the actual worker and must fail. The native campaign
also includes an input straddling a committed page and an inaccessible page.
Mock capture tests are not evidence that this OS copy actually failed safely;
that requires running the separate signed image on the development host.

```text
python3 scripts/cryptography/test-windows-enclave-borrowed-worker.py
python3 scripts/cryptography/test-windows-enclave-borrowed-native.py
python3 scripts/cryptography/windows_enclave_borrowed_worker_build.py <persistent-directory>
```

The Python native driver holds only public test data and deliberately permits
mutation for fault testing. It is not the Rust borrowing host adapter and does
not establish a secret-input product contract. The subsequent
[Rust-owned host experiment](windows-enclave-borrowed-host-results.md) binds the
descriptor lifetime to the original input across the native call without payload
serialization. That adapter is still isolated research, not a shipping API.

## Host integration and persistent results still required

The [separate native experiment](windows-enclave-borrowed-input-results.md) now
instantiates the snapshot inside the preacquired, guarded and locked enclave
window, copies metadata once through the OS boundary, and binds the input reader
directly to the platform copy-in function. Its capture independently checks
full-capacity clearing before outer-window clearing. The subsequent Rust-owned
host experiment retains the original input borrow and removes the ordinary host
payload serializer; its remaining full-runtime and production boundaries are
recorded separately.
Microsoft defines the copy source as outside the enclave; the native adapter must
retain this boundary, not replace it with a raw pointer dereference. Invalid and
page-boundary source failures and enclave-internal source rejection have now
been exercised in the [native observations](windows-enclave-borrowed-input-results.md).
[EnclaveCopyIntoEnclave](https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclavecopyintoenclave).
Only public diagnostic vectors may be used until these platform obligations and
the complete worker/runtime coverage have been reviewed.

Persistent results are a distinct allocation/lifetime boundary. The current
assembly clears the worker window on return, so a result cannot be "retained" by
keeping a pointer into that window. It needs separately owned protected storage,
locked before use and cleared while still locked before slot reuse or release.
Instance/generation-bound handles must prevent stale, cross-instance and repeated
use; cancellation, abandoned handles, failed copies and uncertain transport need
explicit cleanup/quarantine behavior. Host handles must retain the actual instance,
not just a token whose owner may have been deleted.
The [retained-result lifecycle model](windows-enclave-persistent-result-design.md)
now exercises these state transitions independently; native persistent allocation
and host-handle integration remain unimplemented.

The current Linux `Digest::expose` returns a borrowed protected slice. Returning
enclave-private memory as a host slice is not a compatible implementation. A
production enclave result API therefore needs explicitly reviewed opaque-result,
in-enclave composition and public-declassification operations; it must not silently
export secret bytes to emulate that existing method. This document does not add
that API or change the existing strict facade.
