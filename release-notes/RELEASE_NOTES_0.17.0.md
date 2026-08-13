# Brynja v0.17.0 Development Milestone

Status: implementation complete; awaiting green GitHub and CodeQL

Brynja v0.17.0 freezes an inert `no_std` FIPS-aware provider architecture in
`brynja-core`. It advances only the `brynja` facade version, selects no
crates.io publication, and remains inside the cumulative change range that the
scheduled v0.20.0 checkpoint will assess.

## Exact Service Separation

- `FipsServiceSet` classifies each exact installed-provider operation as
  intended approved or explicitly non-approved without implying an opposite
  direction. Either side may be intentionally empty.
- Transactional configuration rejects duplicate fields, overlap, an
  unclassified provider capability, or a classified operation absent from the
  exact provider contract.
- Approved is configuration intent only. No type, value, feature, build, or
  result represents FIPS validation.

## Module-Owned Environment And Build Expectations

- `FipsOperationalEnvironment` binds a nonzero environment identity to one
  exact scalar or accelerated backend, its complete required feature bundle,
  and module-owned symbol class.
- The ordinary `ValidatedModule` backend placeholder is explicitly excluded.
  `BackendPolicy`, opportunistic dispatch, runtime std detection, and the
  `brynja-crypto-cpu-std` adapter cannot enter this API.
- `FipsBuildExpectations` requires nonzero source, toolchain, flags, and
  dependency digests. They are deterministic-build expectations, not a frozen
  validated binary identity.

## Self-Tests And Permanent Failure

- An explicitly trusted `FipsSelfTestRunner` receives the exact mandatory
  integrity and algorithm-known-answer plan. Application code cannot directly
  obtain or complete the internal self-test guard.
- Service authorization remains unavailable before successful self-tests.
  Failure, reentry, interruption, panic, cancellation, impossible transition,
generation exhaustion, or a later catastrophic event permanently latches
the caller-owned session failed.
- Non-cloneable, non-formattable, thread-bound service indicators retain one
  exact operation, disposition, provider, and health generation. A later
  terminal failure immediately makes every outstanding indicator stale.

## SSP Boundary

- `FipsSspPolicy` freezes internal, import, export, or combined SSP movement
  intent together with a mandatory nonempty complete-copy destruction set.
- No memory pinning, OS service, provider effect, secret import/export,
  cryptographic operation, or erasure implementation is added by this policy
  type.

## Verification And Limits

Six behavior groups cover empty and duplicate service sets, environment and
feature mismatch, sealed-provider exclusion, empty build digests and
destruction duties, complete/disjoint provider classification, pre-test and
unsupported-service rejection, successful authorization, catastrophic token
invalidation, explicit test failure, interrupted test unwind, reentry, and
permanent failure. Four compile-fail examples reject raw service-set
fabrication, ordinary backend-policy injection, service-indicator cloning, and
cross-thread movement.
A SHA-256-bound four-file policy keeps every source below 500 lines, forbids
standard-library, allocation, unsafe, FFI, runtime detection, ordinary dispatch,
global/atomic state, and std-adapter access, and rejects twenty-three broken fixtures.

This milestone does not implement a FIPS cryptographic module, cryptographic
algorithm, provider effect, self-test algorithm, service execution, CPU kernel,
runtime detector, operating-environment measurement, deterministic binary
reproduction, SSP transport or destruction effect, independent verification,
CMVP submission, certificate, or FIPS 140-3 validation. Implementations of the
self-test runner remain security-critical trusted code.

## Release Process

v0.17.0 is an ordinary tagged development milestone. The complete local gate,
green GitHub and CodeQL, and explicit authorization are mandatory before its
signed tag. It has no scheduled standalone pentest and selects no crates.io
publication. Every change after v0.15.0 remains in the scheduled cumulative
v0.20.0 assessment; a material finding may still trigger an earlier exceptional
review under the release policy.
