# v0.24.50 remaining work

Current implementation status: the bounded SHA-256, scalar SHA-2/SHA-3/KMAC/TupleHash
streaming, SHA-2/SHA-3 batches and sequential scalar ParallelHash Windows enclave
APIs are integrated and development-tested. Explicit opt-in SHA-NI SHA-224/256
sessions now have native debug/release host coverage; wider acceleration remains.
Existing Linux-style host-slice
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

- Scalar SHA-2 streaming, bit tails, all named identities and general SHA-512/t
  are implemented in the [separate version-six worker/API](windows-enclave-sha2.md).
  Scalar ParallelHash host integration is also implemented; complete wider qualification.
  Extend the integrated enclave-compatible strict facade.
  Keep unsupported routes fail-closed and ordinary APIs unchanged. Do not claim
  the existing host-slice/closure APIs are transparently enclave-compatible.
  Scalar SHA-3/SHAKE/cSHAKE is now integrated in the
  [version-seven worker/API](windows-enclave-sha3.md), including streamed N/S
  setup, incremental XOF fragments and exact-bit retained rehashing. Native
  development enclave campaigns pass 1028 cases in each debug/release build.
  Worker vectors, compiled mutants, placement/lifecycle Miri and packaged
  ownership tests pass. This completes the scalar algorithm implementation
  pass, not acceleration, independent review or production qualification.
  The next private KMAC worker component implements all four identities using
  existing strength-enforcing KMAC states, retained fixed/XOF output,
  full-width tag verification and exact-bit retained-output rekeying. Its local
  author tests cover 256 independent oracle cases, 128 rekey combinations,
  cancellation/copy/unwind cleanup and eleven compiled mutations, with focused
  Miri. The library now supplies exact-length streamed key/customization setup
  for all four identities, including bit-fragmented inputs larger than 1024 bytes.
  The private worker now streams key/S setup across sequenced requests and
  supports retained-output rekeying with streamed customization. Per-request
  fragments remain bounded to 1024 bytes, not total key/S length. Ten local and
  Windows component tests cover 256 independent fragmented bit-oracle cases
  (including larger-than-1024-byte inputs) and 256 retained rekey combinations;
  eighteen compiled mutations and focused lifecycle Miri pass locally. See
  [cross-call component observations](../assurance/windows-protection-observations/kmac-crosscall-component-20260930.json).
  Version-eight worker transport now validates canonical public headers before
  payload copying, supports exact-bit fixed tags, and separates explicit tag
  export from the one-byte public verification decision. Thirteen component
  tests pass on Linux and Windows, including the same 256 oracle cases through
  direct and decoded-wire paths; twenty-six compiled mutants and two focused
  Miri checks pass. The Rust entry/C OS-copy adapter also builds and links as a
  Windows enclave image. Its initial build-only observations are retained in
  [wire/image build observations](../assurance/windows-protection-observations/kmac-wire-build-20260930.json).
  The subsequent version-eight host API now supplies affine Session/Stream/
  Reader/Retained types, bounded setup snapshots, receipt validation, retained
  rekeying, explicit public export and full-width verification. Native VBS
  development execution passes 546 cases in each debug/release build. These
  include all four identities, partial bits, setup larger than one request,
  incremental XOF output, cancellation and abandoned-handle quarantine. See
  [host observations](../assurance/windows-protection-observations/kmac-owner-20260930.json).
  Production trust is still mandatory at the public constructor; development
  signing is available only to the private test harness. Independent review,
  compiler/register qualification and production deployment remain pending.
  The previous bounded component's seven tests passed in an ordinary Windows process; this is
  [source-bound component evidence](../assurance/windows-protection-observations/kmac-component-20260930.json),
  not a VBS enclave execution claim.
  The private TupleHash component now covers all four identities using hardened
  cSHAKE, exact-length streamed customization/items, arbitrary-bit packing,
  retained fixed/XOF output and exact-bit retained-output rehashing as one tuple
  member. An unfinished item blocks finalization; empty members remain distinct
  from absent members. Its version-nine metadata decoder bounds snapshots and
  rejects noncanonical fields before payload copying. Seven component tests pass
  locally and in an ordinary Windows process: 272 independent bit-oracle cases
  run through both direct and decoded-wire paths, including larger-than-request
  setup/items; 128 retained rehash combinations pass. Nineteen compiled mutations
  reject protocol, framing, bounds and cleanup regressions; two focused Miri
  cleanup/quarantine tests pass. This is not native
  enclave qualification. The OS-copy entry now builds and links as a Windows
  enclave image, with bounded snapshots and public cleanup receipts. Placement
  tests cover destruction of an active partial item, wrong-page rejection,
  full-page clearing and recreation; Miri and two compiled placement mutants
  pass. The version-nine image now executes inside VBS using development signing.
  The affine host interface now includes item writers, fixed/XOF results,
  retained-output rehashing and transactional public export. Its bounded
  transport passes 230 native differential cases in each debug/release profile,
  including retained rehashing, incremental XOF and empty output. Empty
  customization no longer reenters completed setup, and a host open-item latch
  rejects forgotten-item finalization before backend entry, preserving clean
  destruction. The worker retains its independent rejection. See the
  [native development observations](../assurance/windows-protection-observations/tuple-owner-20260930.json).
  See the
  [component observations](../assurance/windows-protection-observations/tuple-component-20260930.json).
  The subsequent [entry/image observations](../assurance/windows-protection-observations/tuple-entry-build-20260930.json)
  preserve the separate source-bound build and placement checks.
  A candidate host metadata encoder is now tested against the actual enclave
  decoder across valid and rejected request shapes, including 128-bit item and
  customization lengths. Four encoder mutations are rejected. This is
  shared source used by the host API and the isolated parity fixture. Host-only
  mock tests cover abandonment, forgotten parent loans, output-copy failures,
  chunking and reuse; these are not native OS-copy evidence.
- The first private scalar batch component covers eight ordered SHA-2 slots,
  all named/general identities, streamed bounded input and arbitrary-bit final
  tails. A public byte budget bounds input, inactive slots remain zero and
  export requires completion of the entire declared plan plus an explicit seal.
  Failed operations clear all retained results and quarantine. Six tests cover
  72 independent hashlib cases, 255 activity masks and 4080 general-t bit cases;
  eleven compiled mutants and a focused Miri cleanup/unwind test pass. This is
  also tested in an ordinary Windows process; see the
  [component observations](../assurance/windows-protection-observations/sha2-batch-component-20260930.json). It is
  not a host batch API or native enclave evidence. The subsequent version-ten
  protocol now validates its 128-byte header before bounded payload copying;
  only explicit export authorizes copying the fixed 512-byte result block.
  Nine component/wire tests and 22 compiled mutants pass locally and on Windows.
  Placement tests cover retained output plus a live stream, wrong-page rejection,
  full-page erasure after destruction and recreation. Two placement mutants and
  three focused Miri checks pass. The Rust worker/C OS-copy adapter compiles and
  links as an unsigned enclave image, but has not executed inside VBS; see the
  [wire/build observations](../assurance/windows-protection-observations/sha2-batch-wire-build-20260930.json).
  The subsequent [batch host API](windows-enclave-sha2-batch.md) now supplies
  affine Session/Batch/Item/Retained owners, a typed public plan, an open-item
  latch, transactional declassification and reuse after confirmed cancellation.
  Its actual encoder is checked against the worker decoder. Six host tests pass
  normally and under Miri; twenty negative ownership doctests pass. Ten component
  tests reject 26 compiled mutants, plus two placement mutants. Native VBS
  development debug/release campaigns each pass 355 batches/1822 digests, including
  all activity masks, mixed identities and every valid general SHA-512/t parameter.
  This finishes scalar SHA-2 batch host integration, not qualification or the
  remaining ParallelHash pass. No SIMD or
  throughput gain is implied by sequential batching.
- The private scalar SHA-3/SHAKE/cSHAKE batch component and version-eleven
  transport now implement eight ordered slots sharing 1024 retained output bytes.
  Fixed digests require their exact width; XOF shapes declare their final-bit
  width up front. cSHAKE name/customization and message input stream through
  bounded snapshots. Independent oracle cases cover fractional setup/message/
  output bits, rate boundaries and setup larger than one snapshot. All 255
  active-slot masks cover mixed algorithms and packed output offsets, including
  active empty-output slots. Export requires every declared slot and an explicit
  seal; copy errors and recoverable unwind clear results and quarantine.
  This is a bounded scalar building block, not incremental batch XOF readers,
  a shipping batch host API or a SIMD/parallel throughput claim. The remaining
  work is host ownership/receipt integration, native enclave execution and
  qualification; existing single-stream XOF APIs retain their separate bounds.
  Nine component/wire tests pass locally and in an ordinary Windows process:
  604 independent oracle cases, 255 mixed-slot masks, 30 compiled component/
  protocol mutants and two placement mutants. Three focused Miri checks pass.
  The worker links as an unsigned Windows enclave image. Source-bound
  [component/build observations](../assurance/windows-protection-observations/sha3-batch-wire-build-20260930.json)
  distinguish this from native enclave execution and production qualification.
  The subsequent `enclave::sha3_batch` host API is now integrated: eight host
  tests pass normally and under Miri, twenty negative doctests enforce ownership,
  and native development tests pass 323 batches/1344 digests per debug/release
  profile. All 255 activity masks, long setup, exact-bit output, cancellation
  and forgotten-item rejection are exercised. The shared stream/batch campaigns
  also pass. See [host observations](../assurance/windows-protection-observations/sha3-batch-owner-20260930.json).
- The [private ParallelHash component](windows-enclave-parallelhash.md) now
  implements four scalar identities with streamed leaves/customization, exact
  leaf-count completion, clearing private counters, fixed retained output and
  incremental XOF fragments. Its version-twelve metadata and placement entry
  retain bounded snapshots and full-page destruction. The initial component-only
  step did not establish host integration, retained composition or native enclave
  execution; subsequent results are recorded below. Parallel workers and
  acceleration remain pending.
  Thirteen component tests, 332 independent cases, 24 compiled component/wire
  mutants and two placement mutants pass on Linux/Windows. Seven focused Miri
  checks pass locally; the unsigned Windows worker links. All 171 captured source
  hashes match. See [component observations](../assurance/windows-protection-observations/parallel-component-20260930.json).
  The subsequent `enclave::parallelhash` Session/Stream/Reader/Retained API now
  integrates that worker, including exact-bit secret-to-secret rehashing and
  production-signature-only construction. Native development debug/release
  campaigns each pass 332 direct oracle cases and 256 retained-composition cases.
  Seven host tests pass normally and under Miri; 25 negative ownership doctests,
  the packaged API example, 435 packaged forbidden-export/ownership probes,
  31 component/encoder mutants and two placement mutants pass. Eight focused
  component Miri checks pass. Shared native stream/batch regressions are green.
  All 535 native source/manifest hashes match; artifacts are saved outside target/.
  See [host observations](../assurance/windows-protection-observations/parallel-owner-20260930.json).
  This finishes the sequential scalar algorithm/API pass, not multicore,
  hardware/SIMD or production qualification.
- Add and qualify the supported opt-in hardware/SIMD paths, including Windows
  ABI/register cleanup and bounded ParallelHash worker ownership/concurrency.
  The [public-vector acceleration diagnostic](windows-enclave-acceleration.md)
  now confirms SHA-NI and AVX2 execution inside the development VBS guest:
  496 comparisons pass across five existing hardened kernels, with startup KATs
  and post-quarantine rejection. Dedicated x86 SHA-512 is absent. This is not
  session integration or secret-placement/cleanup qualification; both remain.
  The private retained SHA-NI SHA-224/256 component and version-13 decoder now
  pass real-kernel Linux/Windows component tests. Its authority/stream placement
  has native lifecycle tests and a separately labeled Miri lifetime model. The
  feature-checked enclave entry now has a separate private worker image: 21
  native public-vector comparisons across 151 calls pass, including copy faults,
  terminal rejection, cancellation and retained rehash. Nine Rust and fifteen C
  entry/gate mutations are rejected on Linux and Windows. Generated artifact
  bytes are checked after mutation restoration. The supported SHA-NI host route
  is now integrated behind explicit acceleration: 46 accelerated and 631 scalar
  cases pass in each native debug/release campaign, including trust, image,
  identity and lifecycle rejection. Four additional actual-C protocol mutants
  are rejected. Wider routes and current-image ABI/register/dump review remain. See
  [host observations](../assurance/windows-protection-observations/sha2-accelerated-host-20261001.json),
  [worker observations](../assurance/windows-protection-observations/sha2-accelerated-worker-20261001.json);
  the [component evidence](../assurance/windows-protection-observations/sha2-accelerated-component-20260930.json)
  must not be read as enclave or production qualification.
  The private AVX2 SHA-3/SHAKE/cSHAKE component now covers all eight identities,
  streamed exact-bit N/S, retained output/rehash and terminal authority failure.
  It reuses the existing hardened engine source unchanged. Its differential,
  lifecycle, compiled-mutation and prefix-only Miri checks are recorded in
  [SHA-3 component observations](../assurance/windows-protection-observations/sha3-accelerated-component-20261001.json).
  The subsequent private version-14 resident and feature-checked worker now
  execute inside development VBS: 57 independent comparisons across 419 calls
  pass, including exact-bit cSHAKE setup, retained rehash and copy-failure
  quarantine. Native placement/wire tests, 25 compiled regressions, seven
  ownership negatives, nine worker and eighteen baseline C mutants pass on
  Linux/Windows. A placement-only Miri model rejects three memory regressions.
  See [worker observations](../assurance/windows-protection-observations/sha3-accelerated-worker-20261001.json).
  The supported opt-in `sha3::Session::open_avx2` constructor now preserves
  production image/trust admission and scalar defaults. Native debug/release
  campaigns pass 1028 cases per route on AVX2 and the freshly rebuilt scalar
  image; nine compiled encoder mutations, focused host Miri and packaged
  feature/ownership negatives pass. See
  [host observations](../assurance/windows-protection-observations/sha3-accelerated-host-20261001.json).
  Current-image secret-storage/ABI qualification is still
  separate; the development image does not close that work.
  The next private KMAC AVX2 component now passes native Linux/Windows tests:
  256 independent bit cases, 128 retained rekeys, 22 compiled mutants and six
  ownership/lifetime negatives. Streamed key/customization completion, full-strength
  tags, XOF suffixes, verification and terminal authority failures are covered;
  a focused actual-key-prefix Miri model passes with a noncryptographic sink.
  See [KMAC component observations](../assurance/windows-protection-observations/kmac-accelerated-component-20261001.json).
  The subsequent private version-fifteen KMAC resident and feature-checked worker
  now pass Linux/Windows mutation tests and a focused Miri placement model.
  Development VBS execution passes 50 public-vector comparisons across 672 calls,
  including all sixteen retained rekey pairs. See
  [KMAC worker observations](../assurance/windows-protection-observations/kmac-accelerated-worker-20261001.json).
  The supported opt-in `kmac::Session::open_avx2` constructor now preserves
  production trust and the separate version-fifteen protocol with no fallback.
  Native debug/release campaigns pass 546 cases per route against AVX2 and a
  freshly rebuilt scalar image; encoder mutations and feature-gated packaged
  consumer checks pass. See
  [KMAC host observations](../assurance/windows-protection-observations/kmac-accelerated-host-20261001.json).
  Current-image qualification remains unfinished;
  development execution is not a production signing or independent pass.
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
