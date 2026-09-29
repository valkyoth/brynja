# Windows enclave deployment and evidence scope

Status: development-route implementation and observations only. Windows strict
constructors still return Unsupported. This is not a production deployment
guide or a claim that the existing strict facade is enclave-compatible today.

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

| Brynja implementation responsibility | Deployer responsibility |
| --- | --- |
| Document reproducible build inputs and the enclave/host protocol | Build the intended reviewed revision and retain its artifacts |
| Provide checked image/identity/import admission and reject mismatches before confidential input | Supply a trusted image policy through the supported deployment interface, not trust metadata read from an arbitrary DLL |
| Keep image/resource ownership and cleanup fail-closed; never fall back to ordinary storage | Provision compatible OS/hardware/protection settings and treat constructor failure as a failure |
| Keep SIMD/hardware selection explicit and qualify claimed routes | Select only qualified routes and uphold scheduling/platform requirements |
| Document tested configurations, failure cases and exclusions precisely | Sign and deploy the image, manage credentials and updates, and validate the actual production environment |

These are intended deliverables, not a checklist already marked complete.
Delegating signing does not delegate away Brynja's runtime checks or permit a
caller to bypass protection with an unchecked boolean. Exact file hashing is
not signature-chain verification, import identity validation or attestation.
The bounded admission component now implements a compiled, separately reviewed
policy and Windows trust/import checks. Production facade/constructor integration
still requires implementation and review; there is no public arbitrary-DLL
constructor today. See the [consumer workflow](windows-enclave-image-admission.md).

## What has actually been tested

Evidence is source/image/configuration-bound. Earlier experiments are not
automatically qualifications of later images.

| Area | Current evidence and limit |
| --- | --- |
| Platform | Native Azure Windows x86-64 development host with VBS/HVCI running, Secure Boot disabled and test signing enabled; not a normal production configuration |
| Signing/loading | Local test-signed enclave images execute; early unsigned-image rejection was observed. Recorded compatibility warnings remain in signing transcripts; they are not clean production-signing results |
| Residency/dumps | Specific public-marker experiments observed page locking and exclusion from the selected full-local-dump path; not arbitrary snapshot protection or automatic coverage of every newer image |
| Retained ownership | Native copy, lifetime, cleanup, quarantine, rehash and cross-instance routing campaigns; bounded public vectors and explicit negative controls |
| Facade candidate | Two native 281-call campaigns and local ownership/surface tests; bounded scalar SHA-256, private fixture constructor, no production API activation |
| Main-file pinning candidate | Two native campaigns rejected altered bytes and conflicting write/delete/rename operations while the reviewed facade ran; hash and write-sharing mutants rejected. Not signature-chain, imported-image or attestation verification |
| Admission integration | Two native development successes and production-profile rejections of an untrusted test signature; separately signed wrong-import-author/version controls rejected at initialization. Compiled trusted policy and import checks implemented, not production-facade integration |
| Production deployment | Not executed or qualified: no production-signed candidate, production signature/identity/import integration or normal-production-configuration end-to-end result |
| Architecture/algorithms | Windows AArch64, wider enclave algorithms and opt-in acceleration remain incomplete/unqualified |

See [platform experiments](windows-strict-profile.md),
[retained facade results](windows-enclave-retained-facade-results.md) and
[remaining implementation work](windows-v02450-remaining.md) for exact scope.
The [development image-file pinning results](windows-enclave-image-pin-results.md)
record the earlier isolated experiment. The subsequent
[image-admission results](windows-enclave-image-admission-results.md) establish
the development-tested identity/import component. Production API integration,
successful production signing/deployment and final qualification remain unfinished.

## What this decision does not change

The decision permits continued development without a project-owned production
signing subscription. It does not finish v0.24.50, close its pending pentest,
qualify production Windows support, change the release gates or turn previous
research records into release evidence. Source/API readiness and a deployer's
production qualification must be described separately. Missing implementation
or failing checks remain missing or failing, even when signing is external.
