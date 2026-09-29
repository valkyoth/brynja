# Scoped enclave result-lifetime experiment

Status: v0.24.50 research, **not a shipping enclave API or Windows strict support**.
Production cryptography and release gates are unchanged. This extends the
[scoped-owner experiment](windows-enclave-hardened-owner-design.md), alongside
the separate [public request-copy experiment](windows-enclave-request-design.md).
It does not yet connect result handles to the host wire protocol.
The [native lifecycle observations](windows-enclave-result-results.md) record
this deliberately narrower scope and its rejected controls.

## Ownership and terminal outcomes

An isolated, safe Rust fixture owns one existing `OwnedSecretRegion` containing
a hardened SHA-256 result. A higher-ranked operation borrow exposes a private-
field handle, not the storage or a host pointer. The handle cannot be returned
from that scope or implement Send, Sync, Clone, Copy or Debug. Issuer fields are
private too; the sequence advances with checked addition and permanently rejects
exhaustion without wrapping. Failed admission clears the supplied destination.

Export takes the output owner out of an Option **before** checking request
metadata or invoking the copy operation. Thus every export attempt is terminal:
successful export, wrong identity/sequence, absent public-output flag and failed
copy all leave a spent handle. Cancellation is also terminal, including a wrong
token. Every replay rejects without invoking the copy operation. Abandonment and
recoverable unwind release the owner at scope exit. `panic=abort` has no such
guarantee. The internal copy operation may partially write before returning false;
only owned-memory cleanup is promised, not host-output rollback.

This is a source-isolated research library with an internal generic test callback,
not a new generic callback entry point on the strict facade. It exports no
production crate surface. The callback's byte borrow is valid only during explicit
public export; compile-negative tests prevent that borrow escaping. Public test
digests alone are compared in the native worker, not returned through host callbacks.

## Identity is not authentication

The two public token words are an experiment instance identifier and sequence.
The identifier is supplied by the test; it is **not** unpredictable authority,
an attested enclave identity or authentication. Tests reject a different identifier
and prior/future sequences within an issuer, but constructing a new issuer with
the same identifier resets its sequence. Do not reuse this model constructor as a
production identity source or claim cross-instance/restart replay protection.

The native campaign creates a fresh issuer inside each worker call, with a fixed
public diagnostic identity. Handles do not cross that call; native tests establish
only the scoped Rust lifecycle, not host-token routing. Enclave-origin instance
identity, wire admission and instance-borrowed host handles remain required before
external handle use. A public-output marker remains a caller assertion, not proof
of provenance or permission to declassify secret material.

## Verification scope

Six local Rust tests cover success/replay, stale/future/wrong identity, missing
public flags, cancellation, abandonment, partial copy failure, callback/copy
unwind, sequence exhaustion, and every length 0..1024. Seventeen downstream
compile-negative probes enforce ownership, field privacy, non-reentrancy and
non-escaping handle/output borrows, after a positive consumer compiles.

Four compiled model mutations retain a consumed output, forget the output owner,
ignore the token, or ignore the public-output flag. Each must fail both the local
model campaign and the exact worker campaign. The native worker uses the existing
twenty independent public vectors in four modes: successful comparisons plus
replay rejection, cancel/abandon, stale-token/missing-flag rejection, and internal
copy-failure simulation followed by replay rejection. The last mode does not
exercise a Windows copy API. The prior separate request experiment covers that API.

Input, output and exact-layout workspace checks run before outer clearing, in the
same 64 KiB guarded/locked window. Native execution must separately establish
actual layout, callback/guard ordering, cleanup and image/compiler identity.
Cross-builds and mocks alone are not native observations. No register, runtime,
TLS, concurrency, persistent storage, confidential-channel, dump or production-
signing qualification is inferred from this scoped model.
