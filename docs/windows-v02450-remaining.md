# v0.24.50 remaining work

Current implementation status: the bounded SHA-256 Windows enclave owner/session
API is integrated and development-tested. Existing Linux-style host-slice
sessions still reject Unsupported on Windows. Broader algorithms and production
qualification remain incomplete. The release scope
remains the [Windows strict protected profile](windows-strict-profile.md), with
explicit acceleration and unchanged release-gate policy.

Distribution follows the [consumer-managed deployment model](windows-enclave-deployment.md):
Brynja supplies source/APIs/build and verification tooling; the application
publisher supplies production signing and deployment. Development can proceed
without a Brynja-owned signing subscription. This does not qualify production
execution or waive implementation, runtime checks, pentest or existing gates.

## Next implementation boundary

The image-admission and bounded SHA-256 owner/session integration items are now
implemented. `brynja_strict::enclave` supplies public production-policy
construction, lifetime-bound retained results, rehashing, cancellation,
transactional public output and fail-closed cleanup. The shipping host adapter
is Rust; no consumer-supplied driver or development bypass is exported. See the
[API and limitations](windows-enclave-owner.md). The historical steps below
describe how the worker was developed, not outstanding constructor work.

- Build on the completed fixed-public-vector native retained-owner experiment;
  it now covers placement, cross-return digest retention and destruction before
  unlock/free, but is not a production API or general residency qualification.
- Build on the connected native affine borrowed-input host and retained worker.
  They now cover actual input copying, private epochs, retained digest ownership,
  cleanup before public output, abandoned/forgotten handles, startup failures,
  copy rejection, simulated lost completion and deletion failure. A fixed
  secret-to-secret SHA-256 rehash operation now also passes two native worker/host
  campaigns, including chaining, generation/replay rejection and seven compiled
  mutant controls. It exposes no enclave-private memory as host slices. These
  campaigns still use bounded public test data, not a production confidential API.
- Native injected prefix-copy cleanup now covers all 33 header and 1,025 payload
  boundaries, followed by quarantine rejection and confirmed destruction. This
  uses a controlled failure after successful OS copying, not an observed OS
  partial-copy failure. Two-live-enclave routing now also passes native foreign
  token tests in both directions, unchanged-origin oracle checks, stale owner
  epochs and all four token-field mutations.
- The affine host now uses checked, nonrecycled process-local receipt IDs rather
  than allocation addresses. Forced address reuse, stale receipts, terminal
  close, exhaustion and concurrency have focused tests; two native campaigns
  pass against the unchanged image. This does not make the enclave's separate
  mapping-address token identity persistent or authenticated.
- These boundaries now have a crate-integrated lifetime-bound enclave owner and
  facade. Enclave mapping addresses can still repeat across destruction/recreation
  or processes; stale handles must never cross those lifetime boundaries.
  Diagnostic metadata exports are not shipping APIs.
  The current experiments are not a production operation protocol or general
  residency qualification.
- A concrete retained-output facade candidate now passes local ownership/surface
  checks and two native campaigns. It supports bounded SHA-256, retained rehash,
  explicit public declassification and cancellation without generic drivers or
  host secret slices. Its constructor stays private to the fixture: production
  integration of admission and public construction is now implemented separately
  in the crate API; independent review remains required.
- The bounded x86-64 image-admission component and consumer workflow are now
  implemented and development-tested: compiled trusted identity/hash policy,
  bounded PE/import parsing, held file handles, separate development/production
  profiles and Windows trust/load/initialization checks. Native tests prove
  development success, production rejection of the untrusted test certificate,
  and OS rejection of wrong import identities/versions at initialization.
  This is not remote attestation or successful production deployment. Public
  construction is now integrated without a development fallback. See the
  [completed development pass](windows-enclave-image-admission-results.md).

## Broader implementation and qualification

- Extend the integrated enclave-compatible strict facade to cover
  the remaining SHA-2/SHA-3, KMAC, TupleHash, batch and ParallelHash operations.
  Keep unsupported routes fail-closed and ordinary APIs unchanged. Do not claim
  the existing host-slice/closure APIs are transparently enclave-compatible.
- Add and qualify the supported opt-in hardware/SIMD paths, including Windows
  ABI/register cleanup and bounded ParallelHash worker ownership/concurrency.
- Finish compiler/runtime and protected worker/storage review. Test the new
  retained allocation in controlled dump experiments; cover supported error and
  unwind paths without extending claims to fatal abort, caller copies or
  privileged snapshots. Existing dump observations bind older images only.
- Qualify the integrated identity/import admission and consumer build/sign/load
  workflow in a production deployment. Production signing
  credentials and costs belong to the application publisher, not necessarily
  Brynja. Production success remains untested until actually exercised;
  production-profile rejection tests and test-signed execution on a
  Secure-Boot-disabled host are not production qualification.
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
Latest native platform step: [trusted image-admission development results](windows-enclave-image-admission-results.md).
Completed bounded API step: [Windows enclave owner integration results](windows-enclave-owner-results.md).
