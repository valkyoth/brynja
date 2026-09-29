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
- Build on the connected native affine borrowed-input host and retained worker.
  They now cover actual input copying, private epochs, retained digest ownership,
  cleanup before public output, abandoned/forgotten handles, startup failures,
  copy rejection, simulated lost completion and deletion failure. A fixed
  secret-to-secret SHA-256 rehash component now passes oracle, cleanup, ownership
  and Miri checks. Connect it to the native worker and affine host without
  exposing enclave-private memory as host slices. The existing native campaigns
  still use bounded public test data and do not include composition.
- Complete integrated partial-copy and stale/cross-instance protocol controls
  for those general operations. The current private token model and bounded
  borrowed-input host campaign are not a production operation protocol or general residency
  qualification.

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

Latest focused component: [retained secret-to-secret composition](windows-enclave-retained-rehash-design.md).
Latest native platform step: [affine borrowed-input host](windows-enclave-retained-borrowed-host-results.md).
