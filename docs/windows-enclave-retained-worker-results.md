# Native retained Rust-owner observations

Status: **research observations only**, not a production Windows backend, strict
qualification or independent cryptographic review. All messages and digests are
fixed public test vectors. Windows strict constructors remain unsupported.

Source: `e1190ac8a690f61475f4b353ffb5652e16f9f300`.
The [reviewed record](../assurance/windows-protection-observations/retained-worker-e1190ac8.json)
binds source hashes, compiler identity, Rust archives, native images, command
outcomes and complete raw-artifact hashes. The local archive is retained outside
Cargo's `target/` tree:

```text
release-reports/windows-azure-replacement-2026-09-29/retained-worker-e1190ac8.tar
SHA256 357afef022b85047d7b9d33ad40aa015bb4f6c86e8dab3fe136d14b683c2850f
```

## What ran

The separate `window_retained.c` / `window_retained.rs` image connects the
[tested Rust placement](windows-enclave-retained-placement-design.md) to the
independently allocated, guarded and host-locked middle page. Result bytes and
the owner live there across calls; hashing workspace, input and staging are
range-checked inside the guarded 64-KiB worker window. The handle and token globals
contain routing metadata, not digest bytes. One configured enclave thread and
nonreentrant C entry serialize access. This is a private fixture ABI, not a
general raw-pointer constructor or application callback interface.

Twenty messages, including SHA-256 padding boundaries and a 1,024-byte message,
are hashed with the unchanged first-party in-place hardened implementation.
Each digest survives worker return and its complete window wipe, then is exported
on a later call through the fixed OS copy-out function with public-output
acknowledgment. Python `hashlib` independently checks every exported digest.

Each of two runs passed 82 native calls covering:

- Twenty hash/export/replay sequences.
- Busy rejection without losing the already retained result; cancellation.
- Wrong-token rejection that consumes the result without writing output.
- Failed copy-out to a null destination, followed by terminal quarantine.
- Explicit quarantine; close/recreate; close with an unconsumed ready result.
- Owner destruction and full-page zero readback while still locked, before
  unlock/free; worker-window and guard checks around every call.

Each run also passed a separate one-call denied-admission control. Three separately
built and signed broken images were rejected twice: forgetting the placed owner
failed full-page cleanup before unlock; falsely reporting export success failed
the replay outcome; discarding a digest immediately after hashing failed later
export. Exact subprocess exits were `0, 0, 1, 1, 1` in both campaigns.

## Failure found and corrected

The first image at `e954078c` reached the Busy control and failed with status 191.
The fixture incorrectly expected a newly constructed workspace to be all-zero;
its documented initial state contains the public SHA-256 IV. Busy/Quarantined
rejections never entered its computation scope, so they left that public IV intact.

The corrected fixture runs an empty cancel scope **before** the attempted operation.
It does not wipe the workspace after the operation before checking it, which would
hide a real cleanup regression. An O0/O2 test covers success, Busy and Quarantined
with fresh workspaces; removing that setup makes the test fail. The original image,
build and failing diagnostic remain in the archive, not relabeled as passes.

## Build and platform limits

Native MSVC `/O2 /W4 /WX /MT /guard:cf` builds succeeded; Rust 1.98.1 was
cross-compiled for x86-64 Windows MSVC with O2, LTO and panic=abort. Pre-sign PE
inspection showed non-debuggable enclave policy, one thread, a 256-MiB reservation
and image-ID-bound enclave runtime imports. SignTool returned 2 for every image
with the VBS compatibility warning; the signing wrapper returned 1. Those warnings
are preserved, not converted into a clean signing PASS. Ephemeral signing keys
were removed and cleanup found no remaining probe processes or test certificates.
All three older signed evidence images retained their previous hashes.

This ran on the existing VBS/HVCI-enabled Azure x86-64 development host with test
signing and Secure Boot disabled. It does not qualify production signing, Windows
AArch64, arbitrary call depth, Rust unwind/abort cleanup, runtime/TLS copies,
malicious-host residency attestation or the new allocation's dump exclusion.
The old dump observations cover older images only.

Next: an affine host handle owning the actual enclave instance, arbitrary borrowed
input and result-composition protocol, integrated failure/teardown tests, then
production API/algorithm coverage and qualification. See the
[remaining release work](windows-v02450-remaining.md).
