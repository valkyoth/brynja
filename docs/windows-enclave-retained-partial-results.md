# Native injected partial-copy cleanup observations

Status: **research observations only**, not production Windows strict support.
This separately built image extends the
[retained composition experiment](windows-enclave-retained-rehash-results.md)
with controlled copy failures. It does not modify the previous signed images,
production crates or release-gate policy.

Source: `53e6c421655f9a2506a3789d52f0277b84ee7de6`.
The [observation record](../assurance/windows-protection-observations/retained-partial-53e6c421.json)
binds committed source, generated inputs, libraries, executable and signed-image
hashes, exact results and both campaigns. The remote build used transferred
source-bound archives, not its older Git checkout. Complete artifacts are saved
outside Cargo's target directory:

```text
release-reports/windows-azure-replacement-2026-09-29/retained-partial-complete.tar
SHA256 b4f1c2b68fe7f1d7170e036d98cfc724fbde74bd6913044423eb2d0a45602547
```

## What the failure means

The private diagnostic control selects either the 32-byte request header or the
1,024-byte public test payload, plus a prefix length. A nonempty prefix is copied
with the actual `EnclaveCopyIntoEnclave` OS primitive. Only after that call succeeds
does the injected path report failure to the Rust worker. A zero-length prefix
performs no OS copy. This deliberately exercises partially written destinations;
it is **not evidence that the Windows copy primitive itself partially wrote and
then failed**. That distinction is recorded as `os_partial_failure_claim: false`.

The control is one-shot and private to this research image. It is not a proposed
production API. It rejects malformed kind/length commands and cannot be changed
during an active worker call. Reports bind the command, matched invocation, copied
byte count, successful OS-copy count and injected failure. The host independently
checks the exact expected command and all observations before accepting cleanup.
These are observations from a source-bound test image, not hostile-host attestation.

The existing worker still verifies its workspace/snapshot/staging cleanup before
any extra defensive wipe and reports complete header/buffer clearing. The existing
native host verifies guarded-worker bounds, disjointness, page residency, callback
phases and destruction/zero readback before unlocking or freeing the retained page.
No enclave-private slice is exposed to the host.

## Native campaign

Both native campaigns passed on the Azure x86-64 Windows development host. Each
normal campaign completed **4,236 calls**, with one enclave created/deleted, zero
retained resources and zero cleanup errors:

- All 33 header-prefix boundaries, including zero and the complete header.
- All 1,025 payload-prefix boundaries, including zero and the complete payload.
- Each copy error rejects the operation, clears its storage and quarantines the
  retained owner. An export retry must report Quarantined without changing the
  sentinel public destination. Owner destruction then clears/unlocks/frees storage.
- A fresh owner in the same enclave succeeds after the campaign and produces the
  independent SHA-256 `abc` known answer. Fault injection does not leak into it.

Two deliberately broken images are rejected with exact diagnostics and counters:
one omits the prefix copy, the other returns success instead of the injected
failure. The first fails at the first nonempty prefix; the second at the first
header case. Both return exit 97 and retain one uncertain resource until the child
exits. Those negative controls are not counted as successful clearing or deletion.

These runs use a direct C diagnostic driver over the previously tested native
transport and real Rust retained worker. They do not extend the affine public host
API or qualify a shipping confidential-input interface.

## Local verification and preservation

At O0/O2, local C checks cover every prefix boundary, malformed selections, all five
tampered report fields and five compiled policy mutants. Native-result checker
tests reject changed counters, booleans substituted for integers and wrong exits.
The generation checks ensure the experiment remains separate. Existing retained
rehash host/worker regressions and script inventory checks also pass.

Native MSVC builds used O2, warnings-as-errors and control-flow protection, with
no build warnings or errors. Rust worker libraries use the existing pinned 1.98.1
build, checked arithmetic and panic=abort. Archive review verified committed and
current source hashes, generated files, library/image/executable hashes, raw
captures, exact repeated outcomes and cleanup records.

All three development images signed with the known VBS compatibility warning:
SignTool exited 2 for each, and the wrapper exited 1. Logs are preserved; this is
not a clean production-signing result. The ephemeral certificate/key was removed,
no probe child remains active, earlier retained image hashes are unchanged, and
no host configuration changed.

Actual native cross-instance identity and rejection remain pending. So do
production facade integration, other algorithms, acceleration, deployment signing
and the broader platform/worker/storage qualification listed in the
[remaining work](windows-v02450-remaining.md). No new dump or Windows AArch64 claim
is established here. Recoverable unwind remains component-test coverage, not a
native panic=abort result.
