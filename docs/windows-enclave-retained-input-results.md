# Native borrowed-input retained-worker observations

Status: **research observations only**, not production Windows strict support.
The [borrowed-input component](windows-enclave-retained-borrowed-design.md) now
runs inside a separate native enclave image, driven by a bounded Python host.
The separate [affine Rust host adapter](windows-enclave-retained-native-host-results.md)
still uses fixed public vectors; connecting its lifetime-bound request API to this
worker remains pending. No production crate or release-gate policy changed.

Source: `e88a7f6be397d69c350101bd6969721cfd8bc0b3`.
The [observation record](../assurance/windows-protection-observations/retained-input-worker-e88a7f6b.json)
binds source hashes, signed images, captures and cleanup. The complete local
archive is outside Cargo's `target/` tree:

```text
release-reports/windows-azure-replacement-2026-09-29/retained-input-worker-complete.tar
SHA256 367f218cf4c8606424e89e4d430b9ff388d20be43e0687c52139c7fd0a755b6a
```

## Native boundary

The worker copies the 32-byte metadata header once with
`EnclaveCopyIntoEnclave`. It compares the supplied sequence with its own checked
retained-owner epoch, not a value reread from the header. Invalid version,
sequence, length or source metadata rejects before payload copying. Nonempty
payloads are copied once through the same fixed OS adapter; empty input causes no
payload copy. The Rust worker never dereferences the caller's payload pointer.

Header, 1,024-byte input snapshot, SHA-256 workspace and staging addresses must be
disjoint and inside the admitted guarded/locked worker window. Before returning,
the worker checks complete clearing, with component cleanup checked before the
wrapper's defensive wipe so that the wrapper cannot hide a missing component
wipe. Copy or metadata errors quarantine the retained owner. Recoverable unwind
is exercised only by component tests; the native image uses panic=abort.

The digest remains in the separate retained owner across worker returns. The
Python driver zeros original caller payload and metadata after the synchronous
hash call and before the subsequent export. Exported public digests must still
match independently generated hashlib values. Destruction observes full-page
clearing before unlock/free. Sequence matching is not authentication, and does
not establish a cross-instance application protocol or hostile-host attestation.

## Results

Two normal campaigns passed, each with 138 enclave calls:

- Twenty independent SHA-256 vector comparisons, including empty input, padding
  boundaries and the full 1,024-byte fixture capacity, followed by replay rejection.
- Stale/future sequence, wrong version, oversized length and invalid source
  rejection, followed by quarantined export and destruction.
- Actual invalid-address header and payload copy failures through the OS API.
- Cancellation and Busy/quarantine lifecycle controls.

Four compiled broken image variants were rejected in both campaigns: omitted
snapshot clearing, ignored copy failure, repeated payload copying, and trusting
the header's sequence instead of the enclave epoch. Expected process exits were
`0, 1, 1, 1, 1`. The sequence mutant was rejected at copy-count validation because
it improperly reached payload copying for a stale request; the initial runner
expected a later diagnostic. Its assertion failure was not a product failure,
and the complete repeat used the actual required rejection diagnostic.

Local O0/O2 worker tests and four compiled mutants pass. Three capture-checker
tests pass locally and on Windows, rejecting changed copy counters, storage
bounds, sequence, clearing, output, claims and event records. These mocked tests
do not replace the native campaigns. Partial-copy writes and recoverable unwind
remain component-test observations, not claims about native OS partial writes.

## Build, signing and preserved failures

Rust 1.98.1 O2/fat-LTO archives were linked with native MSVC
`/O2 /W4 /WX /MT /guard:cf`. The archive review checks source bytes against the
commit and current checkout, generated root, Rust archives, image hashes,
canonical capture records, exact mutant diagnostics and native build logs.

All five signing commands returned exit 2 with the known VBS compatibility
warning; the signing wrapper returned 1. This is explicitly **not a clean
production signing pass**. The development-only images ran on the existing
test-signing, Secure-Boot-disabled Azure x86-64 host. The first warning-interrupted
signing attempt and its partially signed image are preserved. A first capture
failed before native entry because Git was absent from PATH; it is also retained,
not relabeled as a native failure or success.

Cleanup found no probe children or ephemeral signing certificates. The signing
helper removed its temporary nonexportable private key, and all four previous
signed image hashes are unchanged. No private key or raw dump is archived.

These observations do not qualify confidential application inputs, production
signing, Windows AArch64, arbitrary worker depth/TLS/runtime copies, new dump
protection or retained-result composition. Production strict constructors still
reject Unsupported. See [remaining work](windows-v02450-remaining.md).
