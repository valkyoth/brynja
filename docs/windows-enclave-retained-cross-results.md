# Native two-live-enclave routing observations

Status: **research observations only**, not production Windows strict support.
This separate image tests retained-token routing between two simultaneously live
enclaves. It builds on the [retained composition work](windows-enclave-retained-rehash-results.md).
Production crates, earlier signed images and release-gate policy are unchanged.

Source: `bce5cd2a9a76fb3908e421b0c8ed06d7b22de18e`.
The [observation record](../assurance/windows-protection-observations/retained-cross-bce5cd2a.json)
binds source hashes, generated build inputs, libraries, executable and signed
images, both campaigns and exact outcomes. Native builds used transferred
source-bound archives rather than the remote machine's older Git checkout.
Complete artifacts, including the initially rejected build, are saved outside
Cargo's target directory:

```text
release-reports/windows-azure-replacement-2026-09-29/retained-cross-complete.tar
SHA256 571a74fb0b76080f8a4a930db4cd21b59dc4fb81080cb2937d5a576ca309ed2c
```

## Identity scope

Earlier single-instance fixtures used a constant first identity word and a
per-image owner epoch. That was not a cross-instance uniqueness guarantee. In
this image, the first word is the address of a private static anchor inside the
enclave mapping. The other token fields retain the checked owner epoch, result
generation and format marker. The native host checks that the anchor falls within
the corresponding live mapping and that the two instances' anchors differ.

This identifies **simultaneously live mappings in one process**, not a persistent
identity. Recreating a retained owner inside the same live enclave advances its
epoch, so stale owner tokens are rejected. Destroying and recreating an enclave
can reuse an address and reset its epoch; that case is explicitly outside these
observations. Production ownership must prevent old handles from crossing an
enclave lifetime boundary. Cross-process routing, restart persistence and
authenticated capabilities are not established here.

Tokens remain public routing metadata, not secrets or authentication. A private
diagnostic export reads only the four token words. A separate diagnostic operation
copies a supplied 32-byte token with the actual OS copy primitive into an admitted
worker buffer, decodes it and invokes the fixed retained SHA-256 rehash operation.
No retained digest or enclave-private slice is exported by this operation. These
diagnostic exports are not a proposed production API.

The host validates the exact copied token, one attempted/successful OS copy,
status, workspace/scratch bounds and disjointness, clearing, epoch and generation
transition, with no public result copy during rehash. A foreign or modified token
quarantines and clears the receiving owner; its destruction must still be verified
before releasing residency. These are source-bound observations, not hostile-host
attestation.

## Native verification

Two campaigns passed on the Azure x86-64 Windows development host. Each normal
campaign completed **45 calls**, created/deleted two enclave instances, and
reported zero retained resources and cleanup errors:

- Both instances remain live while holding different public-vector digests.
  Their epochs and generations match, but their mapping identities differ.
- An origin token is routed to the other instance in both directions. Each
  receiver rejects it and subsequently rejects public export as quarantined,
  leaving the sentinel destination unchanged. Cleanup is confirmed.
- The original owner's token remains unchanged and usable. Rehashing and final
  export match independently generated hashlib digests for `abc` and `xyz`.
- Recreating an owner in the same still-live enclave rejects the saved old epoch.
- Altering each of the four token words is rejected with quarantine, unchanged
  public output and confirmed destruction.

Two deliberately broken images fail with the expected diagnostics and counters.
The constant-identity image fails the mapping/identity check after four calls.
The ignored-token image accepts a foreign token internally, which the host rejects
as an unexpected success after five calls. Both exit 97 and deliberately retain
two uncertain resources until their child exits. They are not cleanup successes.

## Focused checks and preserved artifacts

Local C report tests at O0/O2 reject changed copy observations, every report field,
overlap, wrong status and five compiled policy mutants. Native result tests reject
counter, type and exit-code tampering. Generated worker tests cover all token-word
byte ordering and the existing real-owner hashing/cleanup tests. Earlier rehash
worker and partial-copy regression suites and script inventory checks pass.

The initial MSVC build correctly rejected a shadowed oracle-table name with C4459
under warnings-as-errors. The name and regression check were corrected, and a new
directory was built without warnings or errors. The original attempt remains in
the archive. Rust uses the pinned 1.98.1 worker build and panic=abort; MSVC uses
O2, warnings-as-errors and control-flow protection.

All three images signed with the known VBS compatibility warning: each SignTool
exit was 2 and the wrapper exit was 1. This is development-only signing, not a
clean production-signing result. The ephemeral certificate/key was removed; no
probe children remain active. Earlier retained, input and partial-copy images
are unchanged, and no host configuration changed.

Artifact review verified committed/current source hashes, generated files,
libraries, DLL/EXE hashes, raw repeated captures, exact outcomes, build/signing
logs and cleanup. No production, dump, arbitrary-depth/TLS or Windows AArch64
qualification is claimed. Remaining work is [listed here](windows-v02450-remaining.md).
