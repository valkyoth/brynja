# Retained enclave allocation observations

Status: **public-marker platform experiment only**. No production cryptography,
Windows strict availability, dependencies or release gates changed. The retained
Rust result model is not linked into this image yet.

Source commit: `2cf29e7784b3e6e5c7db3a77b81d0d4d0c1c8364`.
Host: existing disposable Azure x86-64 Windows Server 2025 development machine,
build 26100, on 2026-09-29. VBS is enabled; Secure Boot remains disabled and
test-signing enabled. This does not qualify a production signed deployment.

## Observed behavior

`window_persistent.c` uses the existing guarded/cleared 64 KiB worker scaffold,
but allocates a separate three-page region from inside the enclave. The middle
4096-byte page holds only an `0xa5` public marker. Both adjacent pages are
inaccessible. Each recorded address was inside the enclave reservation and
disjoint from the entire guarded worker window.

The ten-call normal sequence passed, then passed again in a fresh child:

- Allocate, establish guards and acquire the middle page's host-managed lock.
- Fill and read back all 4096 bytes.
- Return through complete worker-window clearing, then inspect the retained
  marker from later calls. Residency observations remained locked between calls.
- Attempt two reads of each retained allocation guard: four exact-address read
  access violations were caught; neither access completed. Guards remained set.
- Reinspect the retained marker, then clear/read back all 4096 bytes while still
  locked, acknowledge cleanup, unlock and successfully free the allocation.
- Reject an inspection with no live allocation, then allocate/fill/clear/free a
  second slot. Reuse does not depend on whether the OS chooses the same address.

A separate denied-admission run also passed twice: no marker was written, no
result became ready and the unused allocation was freed. These are controlled
denials before acquiring the slot lock, not a complete callback-failure campaign.

Two separately compiled/signed negative images were rejected in both runs:

| Deliberate regression | Observed result |
| --- | --- |
| Erase the marker immediately after filling | Later retained-data check fails; state becomes failed |
| Skip slot clearing | Full-page zero check fails before unlock/free acknowledgment |

Negative runs are failures, not successful cleanup claims. Their bounded children
reported exit 1. Normal and denied-admission children reported exit 0. The harness
tears down the enclave in `finally`; no capture process remained afterward.

## Verification and artifact binding

Four orchestration regression tests passed locally and on Windows. They cover
the complete normal/denial sequence, every report field, omitted fields/events,
cross-call address drift, false residency/qualification claims and unlock failure.
Mocks do not substitute for the native observations above. The native MSVC build
completed with `/O2 /W4 /WX /MT /guard:cf`.

The initial PowerShell wrapper lost its exit codes and recorded `null`. Its raw
transcripts remain preserved, but those wrapper fields are not treated as passes.
The short campaign was repeated using Python's subprocess exit codes. Both sets
of successful capture bodies passed canonical validation; only the repeat's
exact exit codes are used in the reviewed outcome table.

SignTool returned 2 for each image with its VBS compatibility warning, and the
wrapper returned 1. These remain warnings, not a clean signing PASS. Native load
and execution are separate development-host observations. The temporary signing
certificate/key was removed; older signed worker images retain their prior hashes.

The [reviewed record](../assurance/windows-protection-observations/persistent-slot-2cf29e77.json)
binds all source hashes, signed images, exact repeat exits, capture records,
compiler/disassembly transcripts and cleanup. Source hashes were checked against
both the capture commit and local bytes. The complete public archive is stored
outside Cargo's cleanable `target/` directory:

`release-reports/windows-azure-replacement-2026-09-29/persistent-slot-2cf29e77.tar`

SHA-256: `821c9152c34659147c5f96404b1c8acbb71b4e09408727e808bacc00a096502d`.
It contains neither crash dumps nor a private signing key.

## Remaining work

This supplies native allocation/retention/clear-before-release observations for
one fixed public-marker slot. It does not establish a persistent cryptographic
result API, protected Rust placement, affine host ownership, arbitrary concurrent
workers, Rust unwinding, complete runtime cleanup or dump exclusion for the new
allocation. Host page-lock observations are not attestation against a malicious
containing process. Cancellation, abandoned host handles, failed result copies,
lost completion and OS teardown failure need integrated coverage.

Next is connecting the [retained-result lifecycle model](windows-enclave-persistent-result-design.md)
to independently resident storage and a host owner that retains the actual
enclave. No enclave-private slice may be exposed as ordinary host memory.
