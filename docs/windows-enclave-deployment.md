# Windows enclave deployment and evidence scope

Status: the separate `brynja_strict::enclave` APIs are implemented and
development-tested for Windows x64 MSVC. They cover retained SHA-256, streaming
SHA-2/SHA-3, KMAC, TupleHash, sequential and SIMD batches, and sequential and
concurrent ParallelHash. Acceleration is explicitly opt-in. Existing host-slice
strict constructors still return `Unsupported` on Windows; these are distinct
enclave interfaces, not drop-in replacements. Windows ARM64 is unsupported by
these interfaces and unqualified by this evidence.

Independent review and final release verification remain pending. Development
signing is not production-signed deployment qualification. The accepted cleanup
scope is [conditional Brynja-owned cleanup](windows-enclave-whole-image-cleanup.md#bounded-cleanup-claim-and-evidence-map),
not complete SDK/OS or whole-process erasure.

## Source-library distribution model

The project owner selected consumer-managed enclave deployment on 2026-09-29.
Brynja's intended deliverables are the Rust APIs, first-party cryptographic
implementation, enclave source, build/verification tooling and documented
deployment requirements. The application publisher or deploying organization
builds and signs its enclave image and supplies its trusted deployment policy.
Individual users consuming that publisher's signed image need not rebuild it.

Brynja does not need to operate a paid signing account merely to distribute
source and APIs. We are not promising to distribute a Brynja-operated,
production-signed enclave DLL. No signing account has been provisioned and no
signing-service charge has been authorized for this work.

This allocation of responsibility does not make signing optional in production.
Microsoft documents local test signing and a separate production VBS-enclave
certificate profile through Trusted Signing (now Artifact Signing).
[Development/signing guide](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide),
[service terminology](https://azure.microsoft.com/en-us/products/artifact-signing/).
The publisher is responsible for applicable account eligibility, credentials,
certificate profile, service costs and signing each rebuilt image. Signing
establishes a deployment identity/integrity property, not cryptographic
certification or proof of Brynja's protection guarantees.

## Responsibility boundary

The containing application is trusted. Retained KMAC output and rekey chains
avoid host copies through the supported Rust API, but are not non-exportable
keys against injected or hostile in-process code. The public declassification
marker records caller intent; it is not authentication at the enclave boundary.
Protecting keys from that caller requires the separately deferred authenticated
provisioning and authorization design.

Default builds of `window_guard.c` reject deliberate boundary-fault modes 1–4
and exclude their faulting code. The historical synthetic guard campaign needs
the explicit `BRYNJA_DIAGNOSTIC_GUARD_FAULTS` compiler definition. Do not define
it for consumer images or treat the old diagnostic-image captures as evidence
for newly rebuilt images. Region-address queries remain necessary for host
residency validation; they do not promise secrecy of layout from the trusted host.

Sequential images and their loaders require exactly one enclave thread; their
plain reentrancy guards are not a general multithreaded synchronization primitive.
The five-thread concurrent protocol is separately admitted and must not be
substituted for a sequential image. Raising a sequential image's thread count
requires a new concurrency design and review, not a configuration-only change.

Image trust requires both the reviewed complete-file hash and Windows signature
verification. The latter accepts publishers trusted by the deployment; it is
not an application-specific publisher-certificate pin. Online revocation checks
can make construction depend on network availability. These APIs do not offer
sealing or persistent keys; the fixed enclave OwnerID must not be interpreted
as application-specific sealed-storage isolation.

The main image must be a local disk file with a bounded absolute
`GLOBALROOT\Device\HarddiskVolume...` name obtainable from its handle. The
loader pins that file and its ancestors without write/delete sharing and
compares the complete volume/file identity. Drive-letter and per-logon
volume-GUID aliases are not used for the final load. Neither is `GLOBALROOT`:
direct NT calls can shadow that name even when `DefineDosDeviceW` refuses it.
After acquiring and comparing the file guards, the loader exclusively creates
a temporary NT symbolic link to the admitted native device/file path. Its handle
stays owned by the image pin until retirement. An existing name rejects
construction; it is never opened or adopted. The final loader path uses this
held alias. The containing process and its device-map/impersonation context must
remain trusted and stable; this is not protection against hostile in-process
code or a privileged actor changing the OS namespace itself.
Filesystems that cannot
provide the required device path or full file identity fail closed; network,
redirected and arbitrary device namespaces are not supported deployment paths.

A failed operation remains quarantined even if its enclave is subsequently
destroyed. On Drop, destruction may release resources after synchronous calls
return and host pointer revocation is confirmed, without claiming a successful
cleanup receipt. If destruction cannot be confirmed, image guards remain held.
Confidentiality after `DeleteEnclave` without an enclave erase receipt assumes
the VBS secure kernel scrubs enclave pages before making them accessible to VTL0;
this platform assumption requires deployment qualification and is not proved by
Brynja's resource-release tests.
Fatal revocation failures still terminate the process under the accepted
fail-stop contract; this is not a high-availability isolation mechanism.

| Brynja implementation responsibility | Deployer responsibility |
| --- | --- |
| Document reproducible build inputs and the enclave/host protocol | Build the intended reviewed revision and retain its artifacts |
| Provide checked image/identity/import admission and reject mismatches before confidential input | Supply a trusted image policy through the supported deployment interface, not trust metadata read from an arbitrary DLL |
| Keep image/resource ownership and cleanup fail-closed; never fall back to ordinary storage | Provision compatible OS/hardware/protection settings and treat constructor failure as a failure |
| Keep SIMD/hardware selection explicit and qualify claimed routes | Select only qualified routes and uphold scheduling/platform requirements |
| Document tested configurations, failure cases and exclusions precisely | Sign and deploy the image, manage credentials and updates, and validate the actual production environment |

These responsibilities do not constitute a completed deployment qualification.
Delegating signing does not delegate away Brynja's runtime checks or permit a
caller to bypass protection with an unchecked boolean. Exact file hashing is
not signature-chain verification, import identity validation or attestation.
The bounded admission component now implements a compiled, separately reviewed
policy and Windows trust/import checks. The public enclave sessions use those
checks through their Rust OS adapters. Each requires a trusted static
policy, not an unchecked arbitrary-DLL constructor. Independent review remains
pending. See the [consumer workflow](windows-enclave-image-admission.md) and
[owner/session API](windows-enclave-owner.md).

## Current API and evidence coverage

The [nineteen-route evidence map](windows-enclave-whole-image-cleanup.md#route-coverage)
binds the saved development images and their family/worker reviews. Examples,
message limits and output semantics belong to each API, not to a universal
host-slice interface:

| API family | Implemented routes and consumer guide |
| --- | --- |
| Retained bounded SHA-256 | [Scalar owner/session](windows-enclave-owner.md) |
| Streaming SHA-2 | [Named identities and general SHA-512/t; scalar or SHA-NI for SHA-224/256](windows-enclave-sha2.md) |
| Streaming SHA-3/SHAKE/cSHAKE | [Scalar or AVX2](windows-enclave-sha3.md) |
| KMAC/KMACXOF | [Scalar or AVX2 API](../crates/brynja-crypto-cpu-std/src/windows_enclave/kmac/mod.rs) |
| TupleHash/TupleHashXOF | [Scalar or AVX2 API](../crates/brynja-crypto-cpu-std/src/windows_enclave/tuplehash/mod.rs) |
| SHA-2 batches | [Sequential scalar/SHA-NI, eight-message SHA-224/256 AVX2, four-message SHA-512-family AVX2](windows-enclave-sha2-batch.md) |
| SHA-3/SHAKE/cSHAKE batches | [Sequential scalar/AVX2](windows-enclave-sha3.md#batching) and [four-message AVX2 SIMD](windows-enclave-keccak-simd.md) |
| ParallelHash/ParallelHashXOF | [Sequential scalar/AVX2](windows-enclave-parallelhash.md) and [up to four AVX2 leaf workers](windows-enclave-parallel-concurrent.md#crate-api-integration) |

Concurrent ParallelHash requires public output; it does not retain secret
results. SIMD lanes have their own bounded input/output sizes. No route implies
AVX-512 or dedicated x86 SHA512 instruction support. Public constructors require
production trust; successful development tests use private test-only admission.

The author review covers named owners, working registers and returning paths
under explicit platform/ABI assumptions. Full returning-window clear/readback
does not prove that every secret copy stayed in that window. SDK diagnostics,
copy scratch, arbitrary interruptions and fatal termination remain outside the
claim. Production-signed success and independent review are still absent.

## Earlier development experiments

Evidence is source/image/configuration-bound. Earlier experiments are not
automatically qualifications of later images. The following table retains those
experiments' original limits; it is not the current algorithm inventory.

| Area | Current evidence and limit |
| --- | --- |
| Platform | Native Azure Windows x86-64 development host with VBS/HVCI running, Secure Boot disabled and test signing enabled; not a normal production configuration |
| Signing/loading | Local test-signed enclave images execute; early unsigned-image rejection was observed. Recorded compatibility warnings remain in signing transcripts; they are not clean production-signing results |
| Residency/dumps | Specific public-marker experiments observed page locking and exclusion from the selected full-local-dump path; not arbitrary snapshot protection or automatic coverage of every newer image |
| Retained ownership | Native copy, lifetime, cleanup, quarantine, rehash and cross-instance routing campaigns; bounded public vectors and explicit negative controls |
| Facade candidate | Two native 281-call campaigns and local ownership/surface tests; bounded scalar SHA-256, private fixture constructor, no production API activation |
| Integrated Rust owner | Public construction with mandatory trust verification; native debug/release author tests of hashing, retained rehash, cancellation and ownership cleanup through a private test-only development constructor; no production-signed success claimed |
| Main-file pinning candidate | Two native campaigns rejected altered bytes and conflicting write/delete/rename operations while the reviewed facade ran; hash and write-sharing mutants rejected. Not signature-chain, imported-image or attestation verification |
| Admission integration | Two native development successes and production-profile rejections of an untrusted test signature; separately signed wrong-import-author/version controls rejected at initialization. Compiled trusted policy and import checks implemented, not production-facade integration |
| Production deployment | Trust/identity/import checks are integrated, but no production-signed success or normal-production-configuration end-to-end qualification is claimed |
| Architecture | The evidence is Windows x64 only; Windows ARM64 remains unsupported/unqualified |

See [platform experiments](windows-strict-profile.md),
[retained facade results](windows-enclave-retained-facade-results.md) and
[remaining implementation work](windows-v02450-remaining.md) for exact scope.
The [development image-file pinning results](windows-enclave-image-pin-results.md)
record the earlier isolated experiment. The subsequent
[image-admission results](windows-enclave-image-admission-results.md) establish
the development-tested identity/import component. Wider API integration is
covered by the current map above, not inferred from those early experiments.
Successful production signing/deployment and final qualification remain pending.

## What this decision does not change

The decision permits continued development without a project-owned production
signing subscription. It does not finish v0.24.50, close its pending pentest,
qualify production Windows support, change the release gates or turn previous
research records into release evidence. Source/API readiness and a deployer's
production qualification must be described separately. Missing implementation
or failing checks remain missing or failing, even when signing is external.
