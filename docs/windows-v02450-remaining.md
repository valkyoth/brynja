# v0.24.50 remaining work

Current implementation status: the bounded SHA-256, scalar SHA-2/SHA-3/KMAC/TupleHash
streaming, SHA-2/SHA-3 batches and sequential scalar ParallelHash Windows enclave
APIs are integrated and development-tested. Explicit opt-in SHA-NI SHA-224/256
sessions now have native debug/release host coverage. The explicit AVX2 routes
and bounded concurrent ParallelHash API have subsequent development coverage;
see the [current acceleration status](windows-enclave-acceleration.md) and
[crate-integrated concurrent API](windows-enclave-parallel-concurrent.md).
Existing Linux-style host-slice
sessions still reject Unsupported on Windows. Broader algorithms and production
qualification remain incomplete. The release scope
remains the [Windows strict protected profile](windows-strict-profile.md), with
explicit acceleration and unchanged release-gate policy.

The next qualification item is [final-image ABI/register/spill and dump
cleanup](windows-enclave-whole-image-cleanup.md), followed by independent retest.
A native public-sentinel probe identified missing wrapper register clearing;
both wrappers now clear the volatile return boundary, with ABI-preservation and
compiled omission tests plus two rebuilt native VBS routes. A separate instrumented
VBS campaign now verifies frame/reply/shadow placement for 270 active callbacks
across 31 scheduler cases, with compiled measurement controls. A further
instrumented register campaign covers 552 active VBS callbacks, all sixteen
XMM/YMM registers and eleven non-argument GPRs, with direct positive and compiled
omission controls. No four-byte test pattern was observed at host callback entry on the tested
Windows build; this is not a universal register-erasure guarantee. Six scoped
full-WER-dump observations now cover the unchanged concurrent scheduler image:
root admission, a five-window worker barrier and completed public output, with
ordinary-memory positive controls. No enclave-reservation bytes were included in
those dumps; raw dumps were deleted in the guest. This does not qualify SDK/caller
spills or other images. All 66 selected caller identities in the saved
uninstrumented image are now accounted for, including interior destructor
funclets and reference-disambiguated panic helpers. Handler metadata is bound
to the objects, not qualified for safe unwinding or erasure. A selected seven-body
caller review now maps fifteen saved-register/reply spans into the cleared window,
with six geometry regressions passing on Linux and Windows. A subsequent
[saved SDK-file review](windows-enclave-sdk-frames.md) maps the transition's
nonvolatile register saves and copy-entry frames into that window; six additional
tests pass on Linux and Windows. Loaded-module identity, kernel storage and
remaining SDK paths remain unqualified. This is not whole-image stack-depth or cleanup
proof. Seven additional no-unwind helpers are now byte-bound and reviewed,
completing the primary Rust object's 64-function identity inventory (73 entries
with the selected C functions). This is not all linked runtime/library code.
The old SHA-256 and SHA-512 SIMD images have now been rebuilt with the clearing
wrapper and passed fresh component/worker mutations plus native campaigns
(302 and 318 calls). Their signed bytes bind the reviewed wrapper. Fresh
[public-host campaigns](../assurance/windows-protection-observations/simd-host-refresh-20261004.json)
now pass debug/release against those SHA-2 images and the refreshed Keccak image:
403 eight-lane SHA-224/256, 559 four-lane SHA-512-family and 521 four-lane Keccak
batches per profile, plus lifecycle tests and scoped Clippy. Positive execution
uses internal development transport; production constructors still reject the
development signatures. This does not replace remaining-image dump qualification.
A [four-stream manifest review](../assurance/windows-protection-observations/stream-refresh-inventory-20261004.json)
identified older wrappers in the saved SHA-NI SHA-2, AVX2 SHA-3, KMAC and TupleHash
streaming images. The subsequent [streaming refresh](windows-enclave-stream-refresh.md)
now covers SHA-2 and SHA-3: rebuilt images, native VBS campaigns and debug/release
host tests pass with the reviewed wrapper. KMAC and TupleHash remain to refresh.
These are distinct from the three multibuffer images; the inventory is not exhaustive.
Whole-image caller/spill review,
remaining-image dump coverage and image refresh are unfinished. The
chronological development entries below retain their original scope and should
not be read as a current claim that the concurrent crate API is still absent.

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

- The separate public-data concurrency probe now observes four overlapping
  worker calls plus a controller in one five-thread development VBS enclave.
  Duplicate/replayed lanes reject and workers join before deletion. This does
  not yet implement protected multicore ParallelHash: per-worker protected
  stacks/owners, enclave-local leaf storage and ordered root reduction remain.
  See the [concurrency boundary and next design](windows-enclave-concurrent-design.md).
  A separate per-slot guarded-stack image now also passes four-worker overlap,
  denial and after-lock failure cleanup, and a native missing-clear negative
  control. Live host reads reject at three sampled addresses per admitted
  window. Explicit child-process working-set budgeting is recorded after the
  default lock allowance rejected extra workers. This is public-marker stack
  isolation, not yet protected Rust owners or ParallelHash leaf processing.
  The private safe-Rust concurrent leaf/root component now passes Linux and
  Windows process tests: four bounded leaf slots, one-use plan identity, ordered
  reduction, cancellation and cleanup; 380 oracle cases in two orders, fifteen
  compiled mutations and thirteen ownership/API negatives. This logic is not
  connected to the protected stack/storage adapter yet. See the
  [component scope and remaining integration](windows-enclave-parallel-concurrent.md).

- The private four-message Keccak AVX2 component and fixed-page resident now
  pass native Linux and Windows process campaigns: each stage covers 520
  independent cases/2080 lane comparisons across SHA-3/SHAKE/cSHAKE, mixed rates,
  bit tails, arbitrary-bit N/S, empty messages/outputs and bounded lengths.
  Fourteen component and four placement mutants are rejected, alongside six
  component and eight resident ownership negatives. Strict-provenance Miri
  rejects six allocation/lifetime/rollback mutants in a placement-only model.
  This reuses the existing hardened independent-message engine, not the
  sequential single-state route. Process execution and model checks do not
  establish OS protection or whole-image cleanup. See the
  [component and resident observations](../assurance/windows-protection-observations/keccak-simd-component-20261002.json).
  The version-22 worker and baseline C adapter now also pass native Linux/Windows
  tests: 520 oracle cases, 3954 injected partial-copy prefixes, fourteen Rust
  worker mutations and twenty-one C admission/entry/copy mutations. The real
  development-signed VBS worker passes 53 batches/212 lane digests across 318
  calls, including twelve actual OS payload-copy failures and retained reuse.
  Windows rejects the unsigned image; the temporary signing key was removed.
  The supported `keccak_simd::Session::open_avx2` host API is now connected:
  native debug/release campaigns each pass 521 batches/2084 lane comparisons.
  Twenty-one host mutations, ten ownership negatives, five host-only Miri tests
  and the packaged facade's 487 export/ownership checks pass. Production opening
  rejects the development signature. Shared admission was split without changing
  its trust rules; native SHA-256 SIMD regression passes in both profiles.
  See the [host observations](../assurance/windows-protection-observations/keccak-simd-host-20261003.json)
  and [API example](windows-enclave-keccak-simd.md). Whole-image cleanup,
  multicore ParallelHash and production qualification remain separate. See the
  [worker and native observations](../assurance/windows-protection-observations/keccak-simd-worker-20261002.json).

- The private eight-message SHA-224/256 AVX2 component, resident and version-21
  worker now pass native Linux/Windows process campaigns: 402 independent cases
  and 3216 lane comparisons per stage, including every mixed SHA-224/256 lane
  plan. Component/resident/worker tests reject 12/4/14 compiled mutations;
  baseline C admission/entry/copy tests reject nineteen more. All 3032 injected
  copy-failure prefixes fail closed. A placement-only Miri model rejects six
  provenance/destruction/rollback mutations; this model does not execute SIMD.
  Development-signed execution inside the local Windows VBS enclave now passes
  53 batches/424 lane comparisons across 302 calls, including all eight actual
  OS lane-copy failures, retained reuse and quarantine. Windows rejects the
  unsigned image; the temporary signing key was removed. Sources and preserved
  artifacts match their recorded hashes. The supported version-21
  `sha256_simd::Session::open_avx2` host API is now integrated: development-signed
  native debug/release campaigns each pass 403 batches/3224 digest comparisons.
  Eighteen compiled host mutations, ten ownership negatives and five host-only
  Miri tests pass; the packaged facade rejects 472 export/ownership cases.
  Production construction still rejects the development signature. The existing
  SHA-512 SIMD host regression also passes against the updated shared owner.
  Whole-image cleanup and production qualification remain separate. See the
  [host observations](../assurance/windows-protection-observations/sha256-simd-host-20261002.json)
  and the
  [component, worker and native observations](../assurance/windows-protection-observations/sha256-simd-worker-20261002.json).

- The private four-message SHA-512-family AVX2 component now passes Linux and
  local Windows native-process campaigns: 602 independent cases/2408 lane
  comparisons, twelve compiled runtime mutations and six ownership/lifetime
  negatives. Mixed identities, unequal lengths and every general-t parameter
  are covered. It is bounded to 1024 bytes per lane and requires a common full
  block; no portable fallback or arbitrary-length streaming is claimed. The
  explicit host route is now connected and development-tested. Current-image
  cleanup qualification remains outstanding. The public
  VBS kernel diagnostic does not substitute for that integration. See the
  [component observations](../assurance/windows-protection-observations/sha512-simd-component-20261002.json).
  Private resident placement now passes native Linux/Windows tests with the same
  602 cases, four additional compiled mutations and eight ownership negatives.
  A placement-only Miri model rejects six provenance, destruction-order and
  constructor-rollback mutations. Full-page clearing is tested; OS protection,
  VBS execution and protected worker frames are not established by those tests.
  See the [resident observations](../assurance/windows-protection-observations/sha512-simd-resident-20261002.json).
  The version-20 worker and baseline C adapter are now implemented privately.
  Linux and Windows OS-copy-double tests each pass 602 oracle cases, 1813
  copy-failure prefixes, fourteen Rust mutations and nineteen C mutations.
  The unsigned Windows enclave image builds and links. Current-image qualification
  remains outstanding;
  an image build is not proof of runtime protection. See the
  [worker/build observations](../assurance/windows-protection-observations/sha512-simd-worker-20261002.json).
  Subsequent development-signed VBS execution now passes 61 four-message
  comparisons/244 lane digests across 318 calls, including seventeen rejection
  campaigns and cancellation/reuse. The unsigned image rejects with error 577;
  the temporary signing key was removed. This is native private-worker evidence,
  not a supported host API or whole-image qualification. See the
  [native observations](../assurance/windows-protection-observations/sha512-simd-native-20261002.json).
  The subsequent explicit `sha512_simd::Session::open_avx2` host API now passes
  559 batches/2236 digests in each native debug/release profile, plus sixteen
  compiled host mutations and ten ownership negatives. Prepared import identities
  are required; the original private image correctly rejected. Development
  signatures still fail production trust. See the
  [host observations](../assurance/windows-protection-observations/sha512-simd-host-20261002.json).

- The private sequential AVX2 ParallelHash resident/worker now passes native
  Windows development execution (50 comparisons, 650 VBS calls), full-page
  placement/destruction tests, copy/quarantine mutations and baseline CPU/OS
  admission tests. Its placement-only Miri model is not kernel qualification.
  The version-eighteen worker is now connected to explicit opt-in `open_avx2`
  host selection and mandatory production trusted-image admission. Native
  debug/release campaigns each pass 332 direct and 256 retained cases on both
  scalar and AVX2 routes, with wrong-image/identity and transactional rejection
  tests. See the [host observations](../assurance/windows-protection-observations/parallel-accelerated-host-20261001.json).
  Multicore scheduling and current-
  image ABI/register/spill/dump qualification remain separate outstanding work.
  See the [worker observations](../assurance/windows-protection-observations/parallel-accelerated-worker-20261001.json).

- The private sequential AVX2 SHA-3 batch resident/worker now passes native
  Windows development execution (50 comparisons, 614 VBS calls), full-page
  placement/destruction checks, copy/quarantine mutations and baseline CPU/OS
  admission tests. Its placement-only Miri model is not kernel qualification.
  The version-seventeen route is now connected to the supported affine batch
  host through opt-in `open_avx2`, mandatory production trust and a distinct
  image identity. Native debug/release tests each pass 323 batches/1344 digests
  per scalar/AVX2 route; encoder parity, ten compiled mutations, focused host
  Miri and packaged feature/ownership tests pass. Independent-message SIMD,
  multicore batching and current-image cleanup qualification remain separate
  work. See the [host observations](../assurance/windows-protection-observations/sha3-batch-accelerated-host-20261001.json)
  and the
  [batch worker observations](../assurance/windows-protection-observations/sha3-batch-accelerated-worker-20261001.json).

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
  The private TupleHash AVX2 component now passes Linux/Windows tests: 272
  independent bit cases, 128 retained compositions, 22 compiled mutants and six
  ownership/lifetime negatives. A focused Miri model of the actual bit packer
  passes and rejects three mutants; it does not run AVX2 or VBS. See
  [TupleHash component observations](../assurance/windows-protection-observations/tuple-accelerated-component-20261001.json).
  Its subsequent version-sixteen resident/worker now passes Linux/Windows
  mutations and a focused Miri placement model. Development VBS execution passes
  50 public-vector comparisons across 853 calls, including retained composition
  and incremental XOF output. See
  [TupleHash worker observations](../assurance/windows-protection-observations/tuple-accelerated-worker-20261001.json).
  The supported accelerated host constructor is now development-tested:
  feature-gated `open_avx2` retains mandatory image trust and rejects scalar
  images. Native debug/release tests pass 230 cases per scalar/AVX2 route,
  alongside encoder mutations, host Miri and packaged feature-on/off checks.
  See [TupleHash host observations](../assurance/windows-protection-observations/tuple-accelerated-host-20261001.json).
  Current-image qualification remains open.
  The private sequential SHA-3 batch component now preserves eight-slot streaming
  semantics over the existing AVX2 engine, with a separate version-seventeen
  decoder. Its component/oracle, authority, mutation and ownership checks are
  recorded in [batch observations](../assurance/windows-protection-observations/sha3-batch-accelerated-component-20261001.json).
  This is single-state acceleration per item, not independent-message SIMD or
  multicore batching. The subsequent batch resident/worker and opt-in host are
  now development-tested; current-image cleanup and wider batch routes remain.
- Sequential AVX2 ParallelHash component, resident/worker and opt-in host
  integration are development-tested as recorded above. Multicore scheduling
  and current-image qualification remain open, not host integration.
- The private sequential SHA-NI SHA-224/256 batch component now passes native
  Linux and ordinary Windows-process tests: 244 independent cases in all eight
  slots, 255 mixed activity masks, 29 compiled mutations and six ownership
  negatives. Its separate version-nineteen decoder binds the narrow route;
  wide identities reject without fallback. The subsequent full-page resident
  and feature-checked VBS worker now pass native development tests: 40 independent
  comparisons across 466 VBS calls, three resident and nine worker mutations,
  nineteen baseline-C mutations and seven resident ownership negatives. A focused
  Miri placement/rollback model rejects six mutations; it is not kernel evidence.
  Explicit `sha2_batch::Session::open_sha_ni` host selection now enforces distinct
  image identity and production trust. Native debug/release host campaigns pass
  291 batches/1312 digests for SHA-NI and 355 batches/1822 digests for scalar per
  profile; wide plans reject without fallback. Encoder mutation, Miri and
  packaged feature/ownership tests pass. See the
  [host observations](../assurance/windows-protection-observations/sha2-batch-accelerated-host-20261001.json).
  Current-image qualification remains separate from the
  [worker observations](../assurance/windows-protection-observations/sha2-batch-accelerated-worker-20261001.json).
  Independent-message SIMD and wider SHA-2 acceleration remain separate work.
  Earlier [component observations](../assurance/windows-protection-observations/sha2-batch-accelerated-component-20261001.json)
  retain the distinct ordinary-process campaign.
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
