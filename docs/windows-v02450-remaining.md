# v0.24.50 remaining work

Current implementation status: Windows strict sessions still reject Unsupported.
The work so far consists of isolated platform experiments and Rust ownership
components; it is not a completed production Windows backend. The release scope
remains the [Windows strict protected profile](windows-strict-profile.md), with
explicit acceleration and unchanged release-gate policy.

## Next implementation boundary

- Build on the completed fixed-public-vector native retained-owner experiment;
  it now covers placement, cross-return digest retention and destruction before
  unlock/free, but is not a production API or general residency qualification.
- Connect the tested affine host result/session model to a private adapter that
  retains the actual enclave instance. The safe component now covers exclusive
  ownership, abandonment, receipt validation and transactional public output;
  its synthetic transport does not qualify Windows cleanup. Finish the operation protocol, borrowed inputs, explicit public
  export and in-enclave result composition without exposing enclave-private
  memory as host slices.
- Extend the fixed-vector coverage to the host-owned protocol: abandoned or
  forgotten handles, replay, stale/cross-instance identities, startup failures,
  partial copies, lost completion, quarantine and teardown failure. Component
  tests and fixed-vector native operations do not replace integrated host-handle
  lifecycle tests.

## Broader implementation and qualification

- Integrate the enclave-compatible API into the intended strict facade and cover
  the remaining SHA-2/SHA-3, KMAC, TupleHash, batch and ParallelHash operations.
  Keep unsupported routes fail-closed and ordinary APIs unchanged. Do not claim
  the existing host-slice/closure APIs are transparently enclave-compatible.
- Add and qualify the supported opt-in hardware/SIMD paths, including Windows
  ABI/register cleanup and bounded ParallelHash worker ownership/concurrency.
- Finish compiler/runtime and protected worker/storage review. Test the new
  retained allocation in controlled dump experiments; cover supported error and
  unwind paths without extending claims to fatal abort, caller copies or
  privileged snapshots. Existing dump observations bind older images only.
- Resolve production image signing, identity/import binding and reproducible
  deployment. Current test-signed images on a Secure-Boot-disabled development
  host are not production qualification.
- Obtain native evidence for each claimed Windows architecture/configuration.
  Only x86-64 enclave experiments have run here; Windows AArch64 is not qualified.
  If the stated architecture scope cannot be delivered, obtain an explicit scope
  decision instead of silently describing cross-compilation as native support.

## Release work after implementation

- Reconcile crate documentation, examples, support tables, release notes and
  assurance records with what is actually implemented and qualified.
- Obtain the independent pentest/retest for this candidate, resolve findings and
  collect final source-bound native evidence. The current pentest ledger remains
  pending; v0.24.49 reviews do not qualify these changes.
- Run final verification under the existing planner and evidence-reuse rules,
  then wait for green GitHub checks and explicit tagging authorization. No extra
  release-gate policy or crates.io publication is introduced by this work.

Latest focused component: [affine retained-result host model](windows-enclave-retained-host-design.md).
Latest native platform step: [retained Rust-owner campaign](windows-enclave-retained-worker-results.md).
