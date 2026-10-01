# Brynja v0.24.50

Status: in progress; Windows strict protected-profile design and qualification.
The previous v0.24.49 signed tag is the implementation baseline. This release
selects no crates.io publication and changes no supporting crate versions.

The scope is operational Windows x86-64 and AArch64 protected storage and
worker stacks for the existing strict cryptographic APIs, preserving explicit
opt-in SIMD/hardware acceleration and fail-closed resource acquisition.
See the [platform design and open proof obligations](../docs/windows-strict-profile.md).

Existing Linux-style host-slice sessions remain unsupported on Windows. The new
`brynja_strict::enclave` owner integrates bounded scalar SHA-256 construction and
retained results with mandatory image/signature/import admission. This candidate does not
claim implementation completion, native qualification or a passed pentest.
The milestone requires failure/rollback and cleanup tests, packaged consumers,
Windows ABI/register inspection and native evidence for each claimed platform,
followed by the existing exceptional pentest/retest and release checks.
No release-gate policy is being changed.

The private sequential accelerated SHA-3 batch component preserves eight-slot
streaming, exact-bit cSHAKE setup, retained outputs, work budgets and sparse
ordering over the unchanged single-state AVX2 engine. Its separate version-17
decoder binds the route and complete plan. The subsequent private resident/worker
places authority and state together, erases the full allocation and admits the
complete CPU/OS bundle in baseline C before specialized entry. Linux/Windows
placement, mutation and ownership tests plus placement-only Miri pass; the
development-signed image passes 50 public-vector comparisons across 614 VBS
calls. The supported host constructor now exposes explicit opt-in `open_avx2`
with mandatory production image trust and no fallback. Native debug/release
host campaigns pass 323 batches/1344 digests per scalar/AVX2 route; ten compiled
encoder mutations, focused host Miri and packaged feature/ownership tests pass.
Scalar defaults are unchanged. Whole-image cleanup qualification, multi-message
SIMD and multicore batching remain outstanding. The SDK signing compatibility
warning remains recorded; production signing is not qualified.

The private accelerated TupleHash component now covers all four fixed/XOF
identities over the existing AVX2 cSHAKE engine, with exact streamed item framing
and retained composition. Linux/Windows component tests pass 272 independent bit
cases and 128 retained compositions, reject 22 compiled mutants and six ownership
violations; a focused bit-packer Miri model rejects three mutants. These are
ordinary native-process tests, not enclave execution. The subsequent private
version-sixteen resident/worker now passes Linux/Windows wire, placement and
transport mutations plus a focused Miri placement model. Its development-signed
image passes 50 independent public-vector comparisons across 853 VBS calls,
including retained compositions and incremental XOF output. The accelerated
host API now exposes opt-in `open_avx2` with mandatory trust and a distinct image
identity. Native debug/release host tests pass 230 cases per scalar/AVX2 route;
encoder mutations, focused Miri and packaged feature gating also pass.
Current-image qualification remains pending; the SDK signing warning is retained
and production signing remains unqualified.

A separate [public-vector VBS acceleration diagnostic](../docs/windows-enclave-acceleration.md)
now executes five existing hardened SHA-NI/AVX2 kernels natively, with 496
independent comparisons, startup KATs and quarantine rejection. Dedicated x86
SHA-512 is absent on this guest. That diagnostic alone does not qualify protected
secret inputs. The SHA-NI host integration below is now development-tested;
wider integration and Windows ABI/register qualification remain pending.

The private accelerated SHA-3/SHAKE/cSHAKE component adds exact-length streamed
N/S prefix handling and retained output/rehash on the unchanged hardened AVX2
engine. It rejects incomplete setup, stale authority and noncanonical operations
without fallback. Component oracle, lifecycle, ownership-negative and compiled
mutation checks are separate from native enclave execution. The subsequent
private version-fourteen resident/entry now has development VBS coverage: 57
independent comparisons across 419 calls pass, alongside Linux/Windows mutation
tests and a focused Miri placement model. Authority/owner placement and full-page
destruction are explicit; baseline AVX2 admission precedes every specialized
entry. The supported SHA-3 host route now exposes feature-gated `open_avx2`,
retaining production image/trust checks with no fallback. Native debug/release
campaigns pass 1028 cases per route for AVX2 and a freshly rebuilt scalar image;
nine compiled host-encoder mutations and packaged feature negatives pass.
Current-image qualification remains unfinished. Scalar defaults and release gates are
unchanged by these component/worker steps. The SDK signing warning and
development-only scope remain recorded.

The separate [SHA-2 streaming enclave API](../docs/windows-enclave-sha2.md) now
implements all six named identities and general SHA-512/t, bounded input
snapshots for large streams, arbitrary-bit final tails and exact-bit retained
rehashing. Native Windows development tests pass in debug/release. The worker
is scalar by default. A separate feature-gated `Session::open_sha_ni` constructor
now requires the reviewed version-thirteen SHA-224/256 image, with mandatory
production trust and explicit protocol/complete-feature admission. Wide identities
reject before transport and never fall back. Development debug/release host tests
pass 46 accelerated and 631 scalar cases each, plus trust/image/lifecycle rejection
checks. This is not production or independent qualification. Wider hardware work
remains; the completed scalar batching and ParallelHash passes are described below.

The separate [SHA-3 enclave API](../docs/windows-enclave-sha3.md) implements all
eight SHA-3/SHAKE/cSHAKE identities, incremental exact-bit output, streamed
cSHAKE N/S setup and retained rehashing. Native development debug/release
campaigns pass 1028 cases each. The version-seven worker uses scalar first-party
Rust and requires the existing signed-image admission. The explicit
version-fourteen AVX2 route is described above; neither route claims production
signing success or independent qualification.

The version-eight `enclave::kmac` API implements KMAC128/256 and KMACXOF128/256,
streamed exact-length key/customization setup, retained-output rekeying,
incremental XOF fragments and full-width verification. Native development
campaigns pass 546 cases in each debug/release profile. Tags/readers stay inside
the enclave until explicit public declassification; verification exports only
the decision. The public constructor still requires production image trust.
This completes scalar host integration, not independent or production
qualification, compiler/register qualification, or hardware/SIMD coverage.

The separate private AVX2 KMAC component now streams keys/customization over the
existing accelerated cSHAKE engine and unchanged KMAC suffix packer. Native
Linux/Windows component tests pass 256 independent bit cases, 128 retained rekeys,
22 compiled mutations and six ownership/lifetime negatives. A focused Miri
key-prefix model passes. The subsequent private version-fifteen resident/worker
passes 29 wire/placement, nine transport and 18 baseline C admission mutations,
seven ownership negatives and a focused Miri placement model. Its development
VBS image passes 50 comparisons across 672 calls, including all sixteen retained
rekey pairs. Evidence and the SDK signing warning are preserved locally. The
opt-in host route now exposes `kmac::Session::open_avx2`, feature-gated through
`strict-kmac-acceleration` or the strict facade's `acceleration`. It requires
production image trust and the distinct version-fifteen protocol, never scalar
fallback. Native debug/release campaigns pass 546 cases per route for AVX2 and
scalar, plus image/trust/output negatives. Encoder parity, focused host Miri and
packaged feature tests pass. Current-image qualification and independent review
remain pending; release-gate policy is unchanged.

The version-nine `enclave::tuplehash` host interface now provides all four
TupleHash/TupleHashXOF identities, exact-length item writers, retained-output
rehashing and transactional explicit public export. Its encoder shares source
with the worker parity tests. Local lifecycle/mock-transport tests, ownership
doctests, Miri and Windows cross-compilation pass. Native development campaigns
pass 230 cases in each debug/release profile, including retained rehashing,
empty output, incremental XOF and forgotten-item rejection. Host regressions
prevent reentering completed empty customization and dispatching finalization
with a forgotten item. Production, compiler/register and independent
qualification remain pending.

The private scalar SHA-2 batch component now supplies eight ordered slots,
bounded streamed input, canonical bit tails and all-or-nothing sealed export.
Its version-ten metadata, placement worker and OS-copy adapter pass focused
component/mutation/Miri tests and build as an unsigned Windows enclave image.
The subsequent `enclave::sha2_batch` host API now provides a typed plan, exclusive
item writers, sealed retained results, cancellation and transactional public
export. Native VBS development tests pass 355 batches/1822 digest comparisons in
each debug/release profile. Forgotten writers cannot finalize implicitly; twenty
negative doctests and packaged consumer checks enforce ownership. See the
[batch API example and limits](../docs/windows-enclave-sha2-batch.md).
ParallelHash, hardware/SIMD and qualification remain unfinished.

The private SHA-3/SHAKE/cSHAKE batch component now supports eight ordered slots
with a shared 1024-byte retained output bound, exact fixed/XOF bit shapes,
streamed cSHAKE setup and sealed explicit export. Version-eleven metadata is
validated before bounded payload copying; the worker destroys the typed owner
before clearing its whole page. Focused oracle, mutation and placement tests
cover these boundaries. The `enclave::sha3_batch` host API now supplies a typed
plan, exclusive item writers and sealed retained output with transactional public
export. Native development tests pass 323 batches/1344 digest comparisons in each
debug/release profile. Eight host tests pass under Miri; twenty negative doctests
and packaged checks enforce ownership. The guide includes a compiled downstream
example. This is bounded sequential scalar batching, not incremental multi-reader
XOF batching, SIMD, independent review or production qualification.

The next private ParallelHash component supports all four fixed/XOF identities,
streamed customization and leaves without a B-sized allocation, exact completion
proof, clearing counters and retained output. Its version-twelve decoder checks
metadata before copying bounded input, and its placement adapter destroys typed
state before clearing the whole allocation. This sequential scalar building
block is integrated into the host API described below. See the
[component contract and remaining work](../docs/windows-enclave-parallelhash.md).

The subsequent `enclave::parallelhash` host API now supports all four identities,
streamed customization/message input, bounded retained fixed/XOF output and
exact-bit retained-to-retained composition without a host secret slice. Native
development campaigns pass 332 direct and 256 composition cases per debug/release
profile. Ownership, metadata parity, cleanup and mutation tests cover the new
path. B never determines an allocation size. This is sequential scalar execution,
not a multicore or hardware/SIMD route, independent review or production signing.

The chosen enclave distribution model is source/API/tooling with consumer-managed
signing and deployment, not a Brynja-operated production-signing service. Native
observations so far use development-signed images on a specifically configured
Azure x86-64 host. Production signing/deployment has not been validated, and the
retained-output facade now has a public production-policy constructor backed by
first-party Rust OS/ownership code. Native debug/release tests use a private
test-only development constructor; the public constructor rejects that certificate.
See the [deployment responsibilities and evidence limits](../docs/windows-enclave-deployment.md).

The supported [owner/session API](../docs/windows-enclave-owner.md) covers bounded
input, retained rehashing, cancellation, transactional public declassification,
abandoned/forgotten results, caller unwinding and explicit closure. It exports no
raw driver or host secret slices and adds no foreign crypto dependency. Source
admission and ownership regression checks cover the packaged facade; unchanged
Linux strict APIs retain their previous behavior. This finishes the bounded
SHA-256 production API integration item, not the wider Windows algorithms,
hardware/SIMD work, independent retest or production qualification.

A development-only main-image pinning fixture now passes two native campaigns:
changed bytes and conflicting writer/rename access reject, the reviewed facade
completes while pinned, and weakened hash/sharing mutants are caught. This is not
signature-chain/import verification or production admission. See the
[source-bound results and limitations](../docs/windows-enclave-image-pin-results.md).

The next development pass implements trusted compiled image-policy admission,
bounded PE/import checks, Windows-author import constraints and separate
development/production loader profiles, with a documented consumer build/sign/load
workflow. Native repeats cover successful development execution, production
rejection of the test certificate, mutated artifacts and wrong import identities
or security versions. Windows rejects the latter at initialization, not loading
alone. This does not enable production strict Windows APIs or claim successful
production signing. See [admission results](../docs/windows-enclave-image-admission-results.md).

An isolated synthetic Windows mapping probe passed its first native Windows
Server 2025 x86-64 run, alongside all 15 portable regression tests. It
checks allocation/guard geometry, page locking, WER registration and cleanup,
with portable failure-injection regressions. Its output is explicitly not
strict qualification; crash-dump exclusion and worker-stack protection remain
unverified. No production Rust behavior or dependency is changed by this probe.

A separate, explicitly approved local-crash-dump experiment is prepared with
synthetic control mappings, bounded address-based dump parsing and cleanup of
its own application-specific configuration. Parser and orchestration regressions
pass locally and on Windows. Two native runs found that the full local crash
dump still includes all bytes of the WER-registered synthetic mapping. This
candidate protection mechanism is therefore insufficient for claiming local
dump exclusion; Windows strict constructors remain unsupported. Temporary test
configuration and raw dumps were removed, with cleanup independently checked.
Worker-stack review also tracks OS-owned fiber register state, which a stack-only
wipe would not cover. No weaker deployment contract has been substituted.

The follow-up AWE physical-memory experiment also found all 8 KiB of its
synthetic payload in full local dumps on two native runs. Allocation, normal
clearing/release and all 39 probe tests passed; dump exclusion did not. The
temporary Lock Pages account right was removed and exact prior rights restored;
a fresh-token negative test rejected the unprivileged AWE path. The observation
is recorded without claiming Windows strict qualification. Production behavior
and release gates remain unchanged.

A read-only enclave capability probe now records negative results without
confusing OS API availability with qualification. Its eight regression tests
pass on Windows, including parsing the real embedded PowerShell query. The
current EC2 host reports no VBS/SGX enclave support. The separate enclave design
review identifies required operation/secret-output API changes, residency and
worker cleanup questions, signing requirements and the host prerequisite.
No enclave runtime, dependency or weaker Windows profile has been introduced.

A subsequent Azure host reports VBS enclave support with VBS and HVCI running
after an authorized, non-UEFI-locked configuration and reboot. Secure Boot remains
enabled. All eight capability-probe tests passed natively and the source-bound
observation is recorded. This clears the initial host prerequisite only; enclave
loading/signing, residency, dump exclusion and complete worker cleanup remain
unqualified. The local test-signing route requires a separate development boot
configuration and is not production qualification.

On the disposable Azure host, a separate test-signing configuration restored
running VBS/HVCI with Secure Boot disabled. A temporary non-cryptographic smoke
image was rejected when unsigned and executed four public-value calls when
test-signed, with successful termination/deletion on repeat runs. The signing
wrapper's compatibility warning failure is retained in the research notes;
this is not a clean release-assurance lane. Residency, dump exclusion and full
cleanup remain unproved, and no Windows strict implementation is enabled.

The synthetic lifecycle source and bounded host driver are now preserved with
eight failure-injection tests passing on Linux and Windows. Clean-commit native
records cover unsigned rejection and repeated signed execution. Build/signing
transcripts retain the warning rather than presenting the setup as a clean
automation pass. This adds no production dependency and changes no release gate.

The controlled enclave full-local-dump experiment now has two native Azure runs:
each contains all 8 KiB of the ordinary positive control and none of the enclave
region. Internal marker/clear/refill checks passed. A parser correction handles
native zero-byte descriptors without counting them as coverage, with focused
non-vacuity regressions. Raw dumps and owned temporary configuration were removed
and cleanup independently checked. This establishes only the observed dump path;
residency, complete worker cleanup and production signing remain unresolved.
Windows strict constructors and release-gate policy are unchanged.

Follow-up native runs successfully locked every page touched by the synthetic
enclave buffer. Two combined locking/dump runs retained full positive-control
coverage and zero enclave-region coverage. Seven residency regressions and the
expanded fourteen-test dump harness pass locally and natively. This identifies
a candidate fixed-buffer mechanism, not complete worker protection: admission
before secret input, erase-before-unlock, stack/TLS ownership and production
signing remain unqualified. No shipped cryptographic behavior has changed.

A native worker-inventory experiment now checks local-array and static-TLS
clearing and rejects a compiled missing-clear mutant. Eight driver regressions
pass locally and on Windows. Host and enclave allocation views differ and are
recorded separately; neither a cleared array nor an idle worker's successful
termination is claimed as complete stack/TLS cleanup. Full worker ownership,
protection-before-input and clearing-before-release remain unresolved.

A separate owned-allocation probe now demonstrates the normal-return ordering
on the Azure development host: reserved guards, full payload locking before
public-marker writes, zero readback while still locked, then unlock and release.
Two cycles pass; a compiled missing-clear mutant refuses release and never
explicitly unlocks its dirty payload. Twelve focused regressions pass locally
and on Windows. This is not yet an execution-stack adapter or failure-path
erasure proof; strict Windows support and release policy remain unchanged.

The owned-allocation driver now also clears on recoverable host-side failures
without swallowing the original error. Four native one-shot fault-injection
cases pass, including lost replies after a real write/clear; a missing-clear
image fails recovery. Seventeen focused regressions pass on Linux and Windows.
This does not yet establish native exception/unwind or execution-stack cleanup.

Native paired stack tests now identify a concrete remaining blocker: the
synthetic separate-mapping stack returns normally but terminates its child with
an access violation during native unwinding. Direct OS-stack and matched
assembly-trampoline OS-stack exception controls pass. Emitted frame/unwind
metadata, failure records and nine focused regressions are retained; the failed
prototype is not admitted, and Windows strict support remains Unsupported.

A separate OS-managed-stack window prototype passes native normal return and
an exact synthetic exception caught inside the window. Full-region readback
rejects separately compiled missing-clear images, including after local-array
finally cleanup. Seven focused regressions pass on Linux and Windows. This
narrows the execution-stack design search; it does not yet prove residency,
guard bounds, Rust panic handling, full worker cleanup or production support.
