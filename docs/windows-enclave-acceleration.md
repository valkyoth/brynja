# Windows enclave acceleration development

Scalar constructors remain scalar. Explicit SHA-NI SHA-224/256 and AVX2
SHA-3/SHAKE/cSHAKE, KMAC, TupleHash, sequential SHA-3 batch and ParallelHash host
routes are development-tested; wider accelerated
session routes are still pending.
The historical public-vector diagnostics below are not, by themselves, secret
input qualification. Release-gate policy and dependencies are unchanged.

## Sequential SHA-NI batch component

The private version-19 component processes up to eight ordered SHA-224/256
slots over the existing hardened SHA-NI streams. This is sequential hardware
acceleration, not independent-message SIMD. Its 144-byte header binds the route,
plan, sequence, public byte budget and canonical fields; wide/general SHA-512
identities reject rather than falling back. Authority is checked even at
non-compressing boundaries and after output copying. Failures and owner drop
clear retained state and revoke authority; successful export/cancellation permits
reuse while healthy.

Native Linux and ordinary Windows-process tests each pass 12 tests, covering
244 independent byte/bit oracle cases in every slot, all 255 nonempty mixed
SHA-224/256 activity masks, output tails and lifecycle failures. Each campaign
rejects 29 compiled runtime mutations and six ownership/lifetime negatives.
See the [source-bound component observations](../assurance/windows-protection-observations/sha2-batch-accelerated-component-20261001.json).
That component result does not itself establish resident placement, VBS execution
or host integration. The subsequent private resident and worker are now tested
separately, as described below; a supported host constructor remains next.

## Sequential SHA-NI batch resident and worker

The private version-19 resident places the authority and borrowing batch owner in
aligned, disjoint regions of one exclusively borrowed page. It destroys the owner
first, then authority, and volatile-clears all 4096 bytes, including padding and
inactive storage. Linux and ordinary Windows tests pass 242 independent bit cases
in each of eight slots, 255 mixed activity masks, cancellation/reuse, retained plus
active-state destruction and three cleanup/quarantine mutations. Seven compiled
ownership/lifetime negatives reject. A separate strict-provenance Miri model runs
the actual placement/destruction code with noncryptographic lifetime doubles and
rejects six provenance, ordering, overlap and constructor-rollback mutations. It
does not execute the real assembly kernels or qualify OS residency.

The worker now connects that resident to the guarded page and 64-KiB worker
window in a development image. Baseline C requires the whole compiled
SHA/SSE2/AVX/AVX2 bundle and OS XMM/YMM state before every specialized Rust entry,
including destruction. Feature rejection is terminal, not permission to run an
unsupported cleanup routine. Rust validates metadata before bounded payload
copying; copy errors, wrong-page/repeated initialization and cleanup-receipt
failures quarantine. Nine worker and nineteen baseline-C compiled mutations are
rejected on Linux and Windows.

The development-signed image passes 40 independent comparisons across 466 VBS
calls, including partial bits, mixed/sparse plans, cancellation/reuse and seven
metadata/OS-copy failure campaigns. The temporary signing certificate/key was
removed. The SDK older-OS compatibility warning remains recorded, not a clean
production signing pass. The [source-bound observations](../assurance/windows-protection-observations/sha2-batch-accelerated-worker-20261001.json)
bind the retained artifacts. Supported host selection, current-image ABI/register/
spill/dump qualification, wider SHA-2 routes and independent review remain open.

## Platform observations

Microsoft lists `IsProcessorFeaturePresent` among the
[Vertdll APIs available inside VBS enclaves](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/enclaves-available-in-vertdll).
Its [feature definitions](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent)
include SSE2, XSAVE, AVX and AVX2. The diagnostic queries that API inside the
enclave, along with bounded CPUID leaves and guarded XGETBV. It does not copy a
host feature mask into an authority. Faults, malformed queries, missing
prerequisites and changing observations reject the experiment.

The Azure Windows Server 2025 x64 development guest reports AMD EPYC 9V45,
SHA-NI, AVX2 and enabled XMM/YMM state inside VBS. Dedicated x86 SHA-512 is absent;
no dedicated SHA-512 execution is claimed. SHA-512 **batch** compression below
uses AVX2 integer instructions, not the dedicated SHA-512 instruction extension.
Feature discovery and KATs do not prove that arbitrary scheduling, hotplug or VM
migration preserves these features, nor confer production trust or cleanup proof.

## Native public-vector experiment

C performs only OS/CPU queries and bounded routing. Cryptography uses existing
first-party Rust hardened kernels unchanged. The whole Rust image is compiled
with `+sha,+sse2,+avx,+avx2`, so the baseline C entry requires the **complete**
bundle before entering any Rust routine, even the SHA-NI experiment. There is
no fallback or dedicated-SHA512 route. Each campaign revokes its authority and
requires subsequent work to fail.

| Existing hardened kernel | Independent comparisons |
| --- | ---: |
| SHA-256 SHA-NI | 32 |
| Single-state Keccak AVX2 | 16 |
| Eight-lane SHA-256 AVX2 | 256 |
| Four-lane SHA-512 AVX2 | 128 |
| Four-lane Keccak AVX2 | 64 |

All 496 comparisons passed inside the development VBS enclave. SHA-2 expectations
come from Python hashlib; Keccak uses the existing independent Python oracle.
Lane inputs differ; successful batch call counts are checked. Startup KATs run
in addition to these comparisons.

Local and ordinary Windows-process tests pass. Three corrupted oracle tables
cause exactly the five relevant campaigns to fail. Seven Python tests cover
malformed inventory, missing prerequisites, result tampering, timeouts, cleanup
and rejection without execution. A separate test compiles the **actual C entry**
against mock public feature queries and rejects eleven compiled guard mutations.
The mock test is not enclave execution evidence.

The [source-bound observations](../assurance/windows-protection-observations/cpu-kernels-20260930.json)
reference the saved image, emitted assembly, commands and native results. All
166 build/capture source hashes match. Temporary signing certificates/private
keys were removed; enclave deletion succeeded. SignTool reported success with
its SDK compatibility warning; the wrapper returned nonzero. No clean production
signing result is claimed.

## Retained SHA-NI component

A separate **private component**, not a shipping host route, now implements
retained SHA-224/256 using the existing hardened SHA-NI streams. It borrows an
exact `X86Sha256` authority, rejects wide/unknown identities, and never selects
portable hashing. Its version-13, 64-byte request header requires an explicit
route identity, zero reserved fields and bounded copied payloads. Decode failure
revokes retained state in the placement adapter; empty updates, cancellation and
export also check authority health. The copy callback is a private OS-adapter
seam, not a new application callback API.

The placement layer keeps the authority and borrowing owner in nonoverlapping,
aligned slots in one borrowed page. It exposes neither object, destroys the
owner before its authority, then volatile-clears the entire page, including
padding and inactive enum storage. Backing bytes use `MaybeUninit` because typed
object placement may introduce uninitialized padding. These are placement rules,
**not residency guarantees**: the future enclave entry must admit the actual
page and worker stack and must perform deterministic destruction. Forgetting a
Rust owner is not equivalent to running its clearing destructor.

The focused tests cover 242 fragmented arbitrary-bit comparisons, 32 independent
hashlib byte-message cases (including million-byte inputs), all four retained
SHA-224/256 compositions, revocation, copied-header validation, output failures,
recoverable unwind, cancellation and reuse. Nine component and four real-owner
placement tests reject fifteen component and three placement mutations, plus
thirteen compiled ownership/lifetime violations.
These pass locally and in an ordinary Windows process, not inside the enclave.
All 251 Windows build-source hashes match; the
[component observations](../assurance/windows-protection-observations/sha2-accelerated-component-20260930.json)
bind the saved build, binaries and test diagnostics outside `target/`.

A separate Miri **placement model** uses explicit non-cryptographic lifetime
doubles because the real kernels contain inline assembly. It executes the same
placement/destruction implementation without runtime source changes, exercises
alignment and full-page provenance, and rejects narrowed pointer provenance,
overlapping slots and reversed destruction order. This is not Miri coverage of
SHA-NI, the real owner internals, Windows OS admission or enclave execution.

## Retained SHA-NI enclave worker

The private version-13 component is now connected to the existing admitted
64-KiB worker window and guarded retained page in a development image. The
baseline C entry validates the complete SHA/SSE2/AVX/AVX2 bundle before **any**
specialized Rust entry, including destruction. A rejected feature query latches
failure; restoring advertised features does not reopen it. If features disappear,
the adapter must not call an unsupported Rust destructor and pretend cleanup
completed. Arbitrary CPU migration is not qualified by this check.

Only allocation/lifetime metadata lives in the worker's static slot. The page
keeps the borrowing owner and authority alive across returns. The worker copies
and validates the 64-byte header before copying its bounded payload, revokes the
owner after copy/decoding/receipt failures, and clears both snapshot buffers before
reporting completion. Destruction drops the stream before its authority; C then
checks all 4096 backing bytes are zero before unlock/free.

One sequential real-owner worker test passes on Linux and ordinary Windows,
rejecting nine compiled Rust mutations. Eleven compiled feature-gate mutations
and four mutations of the actual generated C entry are rejected as well. These
include entry without feature validation and entry after restriction failure.
The mutation runner restores original **bytes**, including line endings, and
checks every generated build artifact against its recorded digest. An initial
Windows run exposed CRLF restoration drift; the corrected run is recorded
separately rather than treating its first artifact manifest as current.

The final development VBS image passes 21 independent hashlib comparisons in
151 calls, covering SHA-224/256 boundaries, fragmented input, retained rehash,
cancellation/reuse, seven malformed/copy-failure cases and terminal rejection.
There are 207 page-residency/lifecycle events. The native adapter checks worker
and allocation geometry, copy/clear receipts, locked-page observations and
zero-before-release outcomes. It also verifies that the internal Rust and copy
entry points are not exported, preventing direct bypass of the baseline gate.
These are public-vector author experiments, **not**
current-image dump/register qualification or approval for real secret inputs.
All 344 capture-source hashes and 24 generated artifact hashes match the
[saved worker observations](../assurance/windows-protection-observations/sha2-accelerated-worker-20261001.json).
SignTool's compatibility warning/nonzero exit is preserved; temporary signing
certificates and keys were removed, and native enclave deletion succeeded.

## Explicit host session route

The existing `sha2::Session` now has a separate `open_sha_ni` constructor behind
`strict-sha2-acceleration` (facade feature `acceleration`). Mandatory production
signature, image identity and imports remain enforced. An additional baseline
enclave export identifies the version-13 route and checks its full feature bundle;
missing or wrong protocol rejects construction. This identity check supplements,
and never replaces, the trusted signed-image policy.

Only SHA-224/256 may start or receive a retained rehash. Wide/general identities
reject and quarantine before transport, and failures never select scalar hashing.
The existing `open` constructor and 48-byte scalar protocol remain unchanged;
the new route checks the entire 64-byte accelerated header and receipt.

Native development debug/release tests each pass 46 accelerated cases and 631
scalar cases. They also reject development signatures through both public
constructors, mismatched scalar images, incorrect image policies, unsupported
identities and invalid output sizes, and cover cancellation/reuse and abandonment.
Windows scoped Clippy passes. Linux packaged consumers check that the new method
is absent without acceleration and available when explicitly enabled. The actual
C protocol export adds four compiled mutants to the worker checks (nine Rust and
nineteen C mutants rejected on Linux and Windows).

These are source-bound author tests, not production signing or independent
qualification. Current-image ABI/register/stack/dump review remains open, as do
wider algorithm acceleration and Windows ARM64. See the
[host observations](../assurance/windows-protection-observations/sha2-accelerated-host-20261001.json)
and [API guide](windows-enclave-sha2.md).

## Private AVX2 SHA-3/SHAKE/cSHAKE component

A separate private component now implements all eight SHA-3/SHAKE/cSHAKE
identities with an exact borrowed `X86Keccak` authority. It compiles the existing
hardened Keccak engine source unchanged, rather than introducing another
permutation implementation or using an ordinary non-erasing state. Production
crate sources and the existing scalar enclave API are unchanged by this step.

The new prefix adapter supports exact public N/S bit lengths streamed across
calls. Fractional fragments concatenate without intermediate padding; setup
cannot transition into message absorption until the phase, remaining length,
pending bits and exact padded byte count all agree. Empty N/S retains SHAKE
semantics. State, the pending byte and staging are owned and cleared; the eventual
placement adapter must also destroy live objects and clear their entire backing
allocation, including padding and inactive variants. This private component does
not establish residency or erase arbitrary caller frames.

Retained fixed/XOF output, partial final bits, incremental squeeze, retained
rehash and streamed rehash customization retain the scalar protocol's ownership
rules. Every operation checks authority health, even empty updates, cancellation
and output export. Errors and recoverable unwind clear the owner and quarantine
its authority. There is no portable fallback.

The component tests reuse the scalar oracle/lifecycle tests with only explicit
authority construction and lifetime annotations adapted. Additional tests cover
578 one-bit-fragmented setup combinations, revocation at non-permuting operations,
revocation during copy, overflow and incomplete setup. The native campaign also
covers 628 cSHAKE vectors, 76 NIST bit vectors, 96 hashlib cases (including
million-byte messages) and 512 retained-rehash cases. Compiled mutants must fail
at runtime, not merely fail compilation; generated source bytes are restored and
checked against the build manifest before a successful result is written.

A separately labeled Miri prefix model uses the **actual prefix source** and a
synthetic byte sink. It checks independent bit concatenation and each completion
proof field, but does not execute AVX2 or qualify the real engine, owner placement,
Windows APIs or enclave memory. See the
[component observations](../assurance/windows-protection-observations/sha3-accelerated-component-20261001.json)
for results and saved artifacts. The subsequent private version-fourteen worker
now places the authority and borrowing owner together in a retained page, drops
them in order and clears the entire page. Its bounded decoder is distinct from
the scalar protocol. Baseline C checks AVX/AVX2 and OS vector-state support before
every specialized Rust entry, including destruction; rejection is terminal.
It does not unnecessarily require SHA-NI.

Resident/wire and worker mutation campaigns pass on Linux and ordinary Windows;
a separately labeled Miri model checks actual placement/destruction with
noncryptographic lifetime doubles. Native VBS development execution passes 57
independent comparisons across 419 calls, including fractional cSHAKE prefixes,
retained rehash, copy faults and quarantine. All captured source and generated
artifact hashes reconcile locally; artifacts are saved outside `target/`.
See [worker observations](../assurance/windows-protection-observations/sha3-accelerated-worker-20261001.json).
The supported accelerated SHA-3 host constructor is now available through
`sha3::Session::open_avx2` under explicit acceleration. Native debug/release tests
pass 1028 cases per route for both AVX2 and a freshly rebuilt scalar image;
production signature, image, identity and transactional-output rejections pass.
The shipping encoder agrees with the actual worker decoder, with nine compiled
regressions rejected. See [host observations](../assurance/windows-protection-observations/sha3-accelerated-host-20261001.json).
Current-image qualification remains unfinished. The SDK signing warning is retained; development execution
does not qualify production signing, secret placement or register/spill cleanup.

## Private AVX2 KMAC component

The private KMAC128/256 and KMACXOF128/256 component now reuses the existing
accelerated cSHAKE state and the unchanged first-party KMAC suffix packer. It
streams exact-length customization and keys through bounded snapshots, including
fractional-bit fragments. Key bytepad completion checks both consumed input and
the exact padded length. Key/tag strength checks remain mandatory. Fixed KMAC
binds `right_encode(L)` while KMACXOF binds `right_encode(0)`.

The affine owner retains the exact AVX2 authority. Every operation, including
non-permuting export, cancel and verification, checks authority; copy failure,
unwind, stale sequence and backend failure clear active/retained state and latch
quarantine. Retained outputs can become the next key without host export.
Verification releases only its explicit comparison result; mismatch clears the
tag but permits reuse. The cSHAKE engine and permutation sources are unchanged.

Linux and Windows native **component** tests pass 256 independent arbitrary-bit
oracle cases, 128 cross-identity retained rekeys, lifecycle/strength tests and the
suffix packer's own framing tests. Twenty-two compiled mutants and six
ownership/lifetime negatives are rejected on both targets. A focused Miri model
executes the actual incremental key packer against a noncryptographic byte sink;
it does not execute AVX2 or prove enclave placement. See
[component observations](../assurance/windows-protection-observations/kmac-accelerated-component-20261001.json).

That component evidence alone does not qualify an enclave image. The subsequent
private version-fifteen worker now places the authority and borrowing KMAC owner
separately in one retained page, destroys the owner before its authority and
clears the complete page, including inactive variants and padding. A distinct
112-byte protocol rejects scalar headers and noncanonical route/reserved fields
before payload copying. Baseline C checks the complete AVX2/OS state bundle before
specialized Rust entry, including destruction; rejected authority stays latched.

Native Linux and Windows resident tests pass 256 independent bit cases, all 16
wire-level retained rekey pairs and incremental XOF output across rate boundaries.
They reject 29 compiled wire/placement mutants and seven ownership/lifetime
probes. Worker tests reject nine transport/cleanup mutants and 18 baseline C
admission mutants. A focused Miri placement model rejects narrowed provenance,
overlapping objects and reversed destruction order using noncryptographic
lifetime doubles, not the AVX2 kernel.

The development-signed worker executes inside VBS: 50 public-vector comparisons
across 672 calls cover all four identities, fractional setup, retained rekeying,
verification, cancellation and rejected metadata/copy paths. Source and artifact
hashes reconcile with the local checkout; evidence is saved outside `target/`.
The SDK signing warning (exit 2, older-OS compatibility) remains recorded, and the
temporary signing certificate/key were removed. See
[worker observations](../assurance/windows-protection-observations/kmac-accelerated-worker-20261001.json).

The subsequent host integration now exposes feature-gated
`kmac::Session::open_avx2` with mandatory production image/signature/import
admission and the distinct version-fifteen protocol query. Enable
`strict-sha2,strict-kmac-acceleration` on the hosted crate, or `acceleration` on
`brynja-strict`. The host needs no build-wide AVX2 flags. Scalar `open` remains
version eight; unsupported platforms, images or instruction bundles reject
without scalar fallback. Losing CPU support cannot promise specialized cleanup;
deployment must preserve features across scheduling and migration.

Native debug/release host campaigns pass 546 cases per route for AVX2 and a
freshly rebuilt scalar image, including retained composition and exact-bit
verification. Public constructors reject development signatures; the private
test-only route also rejects wrong image hashes/identities and a scalar image
requested as AVX2. Actual host/worker encoder parity rejects ten compiled
mutations. Packaged consumers verify feature-on availability and feature-off
absence. Focused host Miri checks use mock transport, not VBS or AVX2.

Current-image ABI/register/spill/dump review and independent retest remain
unfinished. This is development evidence, not production qualification. The
SDK signing warning remains recorded. No release-gate policy changed.

```rust,no_run
# #[cfg(feature = "acceleration")]
fn accelerated_kmac(image: &std::path::Path,
    policy: &'static brynja_strict::enclave::ImagePolicy)
    -> Result<brynja_strict::enclave::kmac::Session, brynja_strict::enclave::Error>
{
    brynja_strict::enclave::kmac::Session::open_avx2(image, policy)
}
```

Author commands (native AVX2 host required):

```sh
python3 scripts/cryptography/test-windows-enclave-kmac-accelerated.py component-results
python3 scripts/cryptography/test-windows-enclave-kmac-key-model.py key-model-results --miri-toolchain nightly-2026-09-11
python3 scripts/cryptography/test-windows-enclave-kmac-resident.py resident-results --attest-native-bundle
python3 scripts/cryptography/test-windows-enclave-kmac-resident-model.py placement-model-results
python3 scripts/cryptography/test-windows-enclave-kmac-worker.py worker-results --attest-native-bundle
```

## Retained AVX2 TupleHash component

A separate private TupleHash/TupleHashXOF component now reuses the existing
accelerated cSHAKE engine. The scalar item framing is preserved, and the builder
requires the clearing bit packer to match its scalar counterpart apart from
borrowed-state lifetime annotations. Streamed customization and items bind exact
declared lengths; fixed output encodes its bit length and XOF encodes zero.
Retained output can become exactly one item of the next tuple without host export.

The owner borrows an explicit AVX2 authority and checks it on every operation,
including empty/non-permuting calls and after its private trusted-copy seam.
Errors and recoverable unwind clear active state, pending bits and retained
output, and latch quarantine. Cancellation permits reuse; owner destruction
revokes its authority. Whole-allocation erasure, including inactive variants and
padding, still requires the future enclave placement adapter.

Native Linux and Windows component tests pass 272 independent bit cases,
128 retained compositions and lifecycle/authority tests. Twenty-two compiled
mutations and six ownership/lifetime negatives are rejected on both targets.
A focused Miri model executes the actual bit packer with a noncryptographic sink
and rejects three compiled mutations; it does not execute AVX2 or VBS.
All Windows source and generated artifact hashes reconcile locally. See
[TupleHash component observations](../assurance/windows-protection-observations/tuple-accelerated-component-20261001.json).

The subsequent private version-sixteen worker now places the authority and owner
in separate aligned slots in one retained page. It destroys the borrowing owner
first, then clears the complete page including inactive variants/padding.
Its distinct 112-byte header rejects scalar versions and noncanonical route or
reserved fields before payload copying. Baseline C admits the complete AVX2/OS
state bundle before every specialized Rust entry and latches feature rejection.

Linux and Windows resident tests cover 272 independent bit cases and all sixteen
wire-level retained compositions, rejecting 29 wire/placement mutants and seven
ownership/lifetime probes. Worker tests reject nine transport/cleanup mutations
and eighteen baseline-C admission mutations. A focused Miri placement model
rejects narrowed provenance, overlapping objects and reversed destruction order.

The development-signed image passes 50 independent public-vector comparisons
across 853 VBS calls: all four identities, fractional customization/items,
retained composition, incremental XOF output and seven metadata/OS-copy rejection
campaigns. Source, generated artifacts and executed binaries reconcile locally.
The SDK compatibility warning is retained, not called clean production signing;
the temporary development certificate and private key were removed. See
[TupleHash worker observations](../assurance/windows-protection-observations/tuple-accelerated-worker-20261001.json).

The supported accelerated host route now exposes feature-gated
`enclave::tuplehash::Session::open_avx2`. It requires a separately reviewed
version-sixteen image, mandatory production signature/import admission and the
distinct `PublicTupleAvx2Protocol` identity. Scalar `open` remains version nine;
an unavailable accelerated route never falls back. Enable facade `acceleration`
or hosted `strict-sha2,strict-tuplehash-acceleration`. Host builds require no
build-wide AVX2 flags; the baseline enclave entry checks the complete CPU/OS
bundle. Deployment must preserve that bundle across scheduling and migration.

Native debug/release host campaigns pass 230 cases per route against AVX2 and
a freshly built scalar image. Tests reject development signatures through public
constructors, scalar images on the AVX2 route, wrong image hashes/identities and
invalid public output without mutation. Ten compiled shipping-encoder mutants,
host Miri and packaged feature-on/off constructor checks accompany the native
tests. See [host observations](../assurance/windows-protection-observations/tuple-accelerated-host-20261001.json).
Current-image ABI/register/spill/dump qualification remains unfinished. These
are author development results, not production signing or independent review.
Dependencies, scalar defaults and release-gate policy are unchanged.

Author commands (the component run requires a native AVX2 host):

```sh
python3 scripts/cryptography/test-windows-enclave-tuple-accelerated.py tuple-component-results
python3 scripts/cryptography/test-windows-enclave-tuple-packer.py tuple-packer-results --miri-toolchain nightly-2026-09-11
python3 scripts/cryptography/test-windows-enclave-tuple-resident.py tuple-resident-results --attest-native-bundle
python3 scripts/cryptography/test-windows-enclave-tuple-resident-model.py tuple-placement-results
python3 scripts/cryptography/test-windows-enclave-tuple-worker.py tuple-worker-results --attest-native-bundle
python3 scripts/cryptography/test-windows-enclave-tuple-host-wire.py tuple-host-wire-results
```

## Sequential accelerated SHA-3 batches: private component

The private `sha3_batch_accelerated` component preserves the existing eight-slot
streaming batch model while using the unchanged single-state AVX2 Keccak engine
for each active item. All eight SHA-3/SHAKE/cSHAKE identities, arbitrary-bit N/S
setup and final tails, exact output shapes, sparse slot order and finite input
budgets retain their scalar semantics. This is sequential accelerated execution,
not multi-message SIMD or multicore throughput. Those integrations remain open.

An explicitly borrowed authority is checked at every operation, including
zero-work cancellation and sealing, and again after the fixed copy seam. Failures
and recoverable unwind clear owned state and quarantine the authority; successful
cancellation/export permit reuse. Drop revokes the authority. The resident
adapter below also erases the entire allocation, including padding and inactive
enum storage; field cleanup alone is not claimed as that guarantee.

A separate version-seventeen, 304-byte metadata decoder binds the acceleration
route and reserved word in addition to the full eight-slot output plan. It
validates metadata before a future OS payload copy, and copied-length mismatch
quarantines retained results. The component tests preserve the existing scalar
oracle rather than comparing AVX2 with itself. Native Linux/Windows component
results are recorded in
[batch component observations](../assurance/windows-protection-observations/sha3-batch-accelerated-component-20261001.json).

The subsequent private resident/worker image and baseline CPU/OS admission now
pass development testing. The supported host constructor and whole-image cleanup
qualification remain pending. No shipping API or release gate changes in these
private integration steps.

```sh
python3 scripts/cryptography/test-windows-enclave-sha3-batch-accelerated.py batch-component-results
```

This standalone test binary requires a native AVX2-compatible host. It is not a
portable feature detector, VBS capture or production-signing result.

### Batch resident and native development worker

The version-seventeen worker places its authority and borrowing batch owner in
one exclusive aligned page, destroys the owner before its authority, and erases
the full allocation before release. Only pointer metadata remains in the worker
static. Copied request and payload buffers stay within the admitted worker
window and are cleared before the public completion receipt. Rejected copies,
wrong page/window identity, repeated initialization and malformed requests
quarantine retained state. Baseline C checks the complete AVX2/OS-managed vector
state bundle before any specialized Rust entry, including destruction; rejected
authority is terminal. No fallback route is provided.

Linux and Windows tests each pass 604 independent cases through resident wire
placement, three resident mutations, seven lifetime/ownership rejection probes,
nine worker mutations and eighteen baseline C admission/protocol mutations.
Placement-only Miri runs the actual placement/destruction source against explicit
noncryptographic lifetime doubles and rejects three unsafe memory regressions.
It does not interpret the hardware kernels or qualify the enclave image.

The development-signed image passes 50 independent public-vector comparisons
across 614 native VBS calls, covering all eight identities, fractional setup and
message/output bits, large setup/input, mixed and sparse slot plans, cancellation
and reuse, and seven malformed-metadata/OS-copy rejection campaigns. See
[batch worker observations](../assurance/windows-protection-observations/sha3-batch-accelerated-worker-20261001.json).
The temporary signing certificate and private key were removed. The SDK
compatibility warning is retained; this is not successful production signing.
This remains sequential per-item AVX2, not independent-message SIMD or multicore.
Public host selection is now integrated as described below. Current-image
ABI/register/spill/dump qualification, independent review and production
deployment remain outstanding.

```sh
python3 scripts/cryptography/test-windows-enclave-sha3-batch-resident.py batch-resident-results
python3 scripts/cryptography/test-windows-enclave-sha3-batch-resident-model.py batch-placement-results
python3 scripts/cryptography/test-windows-enclave-sha3-batch-worker.py batch-worker-results --attest-native-bundle
```

### Supported sequential AVX2 batch host selection

`brynja_strict::enclave::sha3_batch::Session::open_avx2` is available with the
facade's `acceleration` feature. It requires mandatory production image trust
and the distinct version-seventeen `PublicSha3BatchAvx2Protocol` identity.
Scalar `open` remains version eleven; an accelerated request never falls back.
The existing affine Session/Batch/Item/Retained owners and exact public plan
remain unchanged. The host validates the entire 304-byte header region in
completion receipts, rather than the scalar protocol's 288-byte region.

Native Windows development debug/release campaigns each pass 323 batches and
1344 digests for both scalar and AVX2 routes, including every nonempty activity
mask, mixed identities, arbitrary-bit output, large setup and cancellation.
Public constructors reject the development signatures; wrong images/identities
and scalar images on the accelerated route are rejected. Test-only retained-plan
corruption preserves the destination and quarantines the session. Uncertain
backend completion deliberately makes explicit close fail with `Release` and
retains resources until process exit; the test does not call that clean release.

The actual shipping encoder matches the worker decoder and rejects ten compiled
mutants. Ten focused host tests pass under Miri (mock transport, not VBS/kernel
execution); packaged debug/release tests reject 440 feature/surface/ownership
violations, including feature-off constructor use. See
[host observations](../assurance/windows-protection-observations/sha3-batch-accelerated-host-20261001.json).
This completes sequential per-slot host integration, not independent-message
SIMD, multicore batching, production signing or whole-image qualification.

```sh
python3 scripts/cryptography/test-windows-enclave-sha3-batch-host-wire.py batch-host-wire-results
```

## Sequential AVX2 ParallelHash component

The private `parallel_accelerated` component covers ParallelHash128/256 and both
XOF identities, using the unchanged hardened AVX2 Keccak engine for root and
leaves. One borrowed authority outlives both states; every operation, including
zero-work requests, checks its health. Copy failure, recoverable unwind and
revocation clear owned results/counters and quarantine; successful cancellation
allows reuse. Drop revokes authority. Placement must still erase the complete
allocation, including inactive enum storage and padding, before release.

The scalar framing is preserved: streamed exact-bit customization, positive B,
bounded fragments without a B-sized allocation, exact leaf-count completion,
right-encoded leaf count/output length, incremental XOF output and exact-bit
retained-output rehashing. Version eighteen has a separate 128-byte header with
an explicit accelerated route and zero reserved words. Invalid metadata is
rejected before payload access; copied-length failure quarantines active state.

The ordinary-process component campaign covers 332 independent bit cases,
including 12 NIST samples, and 256 retained compositions. It rejects 32 compiled
framing, authority, cleanup and protocol mutations plus six ownership/lifetime
violations. The source-bound records distinguish this from native enclave
execution: [component observations](../assurance/windows-protection-observations/parallel-accelerated-component-20261001.json).
Compilation failure is not counted as runtime mutant rejection. Clean source is
restored, recompiled and rerun at the end of each campaign.

```sh
python3 scripts/cryptography/test-windows-enclave-parallel-accelerated.py parallel-component-results
```

This fixture requires a compatible native AVX2 host. It is single-state AVX2
with sequential leaves, not independent-message SIMD or multicore scheduling.
The subsequent resident/worker pass below adds placement and development VBS
coverage. Public accelerated host selection and current-image ABI/register/
spill/dump qualification remain pending. The component campaign itself claims
no Miri, production signing or independent qualification.

### ParallelHash resident and native development worker

The private version-eighteen worker places its authority and borrowing root/leaf
owner in one exclusive aligned page. Destruction drops the borrowing owner
before the authority and volatile-clears the complete page, including padding
and inactive storage. Fixed header/payload snapshots occupy the admitted worker
stack and are cleared before the public completion receipt. OS copy failures,
noncanonical metadata and lost observations quarantine the retained owner.

Baseline C validates the complete AVX2/OSXSAVE/XCR0 bundle before any specialized
Rust entry, including destruction. Feature loss latches rejection; it must not
attempt accelerated cleanup after instruction authority has been lost. The
separate protocol query identifies this image without entering specialized Rust.

Linux and Windows tests each pass 332 independent cases through resident wire
placement, three resident mutations, seven lifetime/ownership negatives, nine
compiled worker mutations and eighteen baseline-C admission mutations. A focused
Miri model tests the actual placement/destruction source with explicitly
noncryptographic lifetime doubles and rejects three provenance/order/overlap
mutations. That model does not qualify cryptographic execution or the full image.

Native development VBS execution passes 50 independent comparisons across 650
calls: all four identities, bit-fragmented customization/input/output, sixteen
retained cross-identity rehashes, two incremental XOF comparisons, cancellation
and seven metadata/copy rejection campaigns. Source, generated artifacts,
binaries and image hashes were reconciled with locally preserved records.
The temporary development signing certificate/key were removed. SignTool's
older-OS compatibility warning is retained, not counted as production signing.
See the [worker observations](../assurance/windows-protection-observations/parallel-accelerated-worker-20261001.json).

```sh
python3 scripts/cryptography/test-windows-enclave-parallel-resident.py parallel-resident-results
python3 scripts/cryptography/test-windows-enclave-parallel-resident-model.py parallel-placement-results
python3 scripts/cryptography/test-windows-enclave-parallel-worker.py parallel-worker-results --attest-native-bundle
```

The worker campaign itself is private development evidence, not multicore or
production qualification. The subsequent host integration is described below.

### Explicit ParallelHash host selection

`windows_enclave::parallelhash::Session::open_avx2` now binds the version-eighteen
image to the existing production signature/identity policy. Enable
`strict-sha2,strict-sha3-acceleration`, or use the strict facade's `acceleration`
feature. Scalar `open` remains scalar; failed accelerated construction never
retries another route. The baseline enclave query validates the complete
CPU/OS bundle before any specialized Rust entry. Host builds need no AVX2 flags.

All four identities retain the existing affine stream/reader/result API,
streamed customization and input, exact-bit output, retained-output rehashing,
transactional public export and quarantine behavior. Receipt validation accounts
for the full 128-byte header; even an overlap confined to its new tail rejects.

Native debug/release development campaigns each pass 332 direct and 256 retained
oracle cases on each scalar/AVX2 route. Wrong image/hash/identity and production
signature rejection pass; corrupting a retained identity rejects without changing
the public destination and leaves release uncertain, as required by the existing
resource-retention contract. Ten compiled encoder mutations, focused host Miri,
ownership doctests and packaged feature-on/off tests also pass. See the
[host observations](../assurance/windows-protection-observations/parallel-accelerated-host-20261001.json).

This completes sequential AVX2 host integration, not multicore scheduling,
current-image register/spill/dump qualification or independent review.

## Next integration boundary

- Extend explicit opt-in selection beyond SHA-224/256, SHA-3/SHAKE/cSHAKE,
  KMAC, TupleHash, sequential SHA-3 batches and sequential ParallelHash, binding each route to its
  trusted image policy. Scalar constructors remain scalar; failed acceleration
  must not silently choose scalar execution.
- Keep backend owners and scratch in enclave storage. Preserve streamed
  framing, retained composition, output transactionality and quarantine.
- Inspect Windows ABI/register behavior for the actual integrated image. This
  public diagnostic does not qualify caller frames, stacks, secret placement,
  spills or erasure merely because it invokes hardened kernels.
- Complete differential, negative-selection, cleanup and independent review;
  qualify bounded multicore ParallelHash separately.

These observations concern one development x64 guest. Windows ARM64, production
signing, arbitrary migration and privileged snapshots are not qualified.
