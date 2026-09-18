# Scoped hardened storage

Status: fixed-output SHA-3 API development checkpoint; wider rollout and complete
register/spill qualification pending. No independent verification or FIPS claim.

The first additive API is `brynja_hash_sha3::hardened_in_place`, with
`Sha3_224Workspace`, `Sha3_256Workspace`, `Sha3_384Workspace` and
`Sha3_512Workspace`. Each provides `new`, `Default` and `with`. Its borrowed
state provides `update`, byte/bit `finalize_secret`, byte/bit `finalize_public`,
and `cancel`. Public finalization requires `Sha3PublicDeclassification`;
secret finalization returns the existing `HardenedSha3SecretOutput`.

The module's compiled example demonstrates returning a secret output from a
scope. The state cannot escape. Its lifetime is independent of the separately
borrowed destination, so callers can use a returned output after the workspace
has been cleared. Neither storage nor state implements Copy/Clone/Debug/Send/Sync.

## Ownership and failure behavior

Storage is secret-free at construction and after every scope. During `with`, an
exclusive borrow prevents its semantic move or overlapping use. Finalization
moves only the reference-bearing handle. No new unsafe code, allocation, heap
pinning, thread support, feature default or dependency is required.

Handle finalization/cancellation/Drop clears every region of the existing
`HardenedFips202Owner` in place. An outer cleanup guard independently clears
the owner on callback return or recoverable unwind, including `mem::forget` of
the handle. An update error clears and terminally disables the handle. Failed
secret finalization clears the entire destination; failed public finalization
leaves its destination unchanged. The workspace can be used for a new computation
only after the prior scope has ended and its guard has cleared storage.

The final output owner still requires normal destruction; deliberately forgetting
that separate output owner defeats its Drop-based destination clearing. Abort,
process termination and interruption snapshots are outside the guarantee.

## What this does not establish

The existing movable hardened APIs retain their existing owned-memory guarantee.
They have not been silently upgraded. Scoped storage removes semantic moves of
the active owner but does not prohibit compiler-created copies or spills inside
an operation. Absorb/padding/squeeze paths still need separate qualification.
The private opaque permutation and secret-copy boundaries cover only their own
normal-return work. Callers' inputs, register state, caches, dumps and platform
storage are not erased by an ownership API.

This initial module uses the portable hardened implementation, including its
already implemented baseline scalar permutation ports. It does not enable an
optional hardware/SIMD route. SHAKE/cSHAKE readers, accelerated sessions, other
hash families and higher constructions remain rollout work before the broader
F1 remediation can be declared complete. Release gates and publishing are unchanged.

## Development checks

All four identities are compared against existing byte/bit APIs over chunk sizes,
rate/padding boundaries and tail widths. Tests cover exact storage identity,
all-region clearing, bad output sizes, counter failure, cancellation, forgotten
handles, recoverable unwind and reuse. Forty-eight compile-fail examples reject
handle escape, overlapping workspace use and forbidden traits. A separate
downstream fixture checks the public API and a known-answer digest.

`python3 assurance/register-cleanup/check_in_place_sha3.py` executes positive
controls and six compiled lifecycle/output mutants in debug and release. It is
a development driver, not a new release-gate mechanism. The existing workspace
test/doctest path exercises the in-crate tests without changing gate commands.
