# Brynja v0.17.0 Development Milestone

Status: pentest PASS; awaiting green GitHub and CodeQL

Brynja v0.17.0 freezes an inert `no_std` FIPS-aware provider architecture in
`brynja-core`. It advances only the `brynja` facade version, selects no
crates.io publication, and remains inside the cumulative change range that the
scheduled v0.20.0 checkpoint will assess.

## Exact Service Separation

- `FipsServiceSet` classifies broad installed-provider operation categories.
  Every current capability must be explicitly non-approved; configuration
  rejects every nonempty approved set until algorithm, parameter, backend, and
  usage identities exist across the provider request and result path.
- Transactional configuration rejects duplicate fields, overlap, an
  unclassified provider capability, or a classified operation absent from the
  exact provider contract.
- The reserved approved disposition is unreachable. No operation-only value
  authorizes provider execution or represents FIPS validation.

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
- Service indication remains unavailable before successful self-tests.
  Failure, reentry, interruption, panic, cancellation, impossible transition,
generation exhaustion, or a later catastrophic event permanently latches
the caller-owned session failed.
- Non-cloneable, non-formattable, thread-bound service indicators retain one
  exact operation, disposition, provider, and health generation. A later
  terminal failure immediately makes every outstanding indicator stale.

## SSP Boundary

- `FipsSspPolicy` freezes internal, import, export, or combined SSP movement
  intent. Its complete-copy destruction set is derived from the installed
  provider and cannot be independently weakened by a caller.
- No memory pinning, OS service, provider effect, secret import/export,
  cryptographic operation, or erasure implementation is added by this policy
  type.

## Verification And Limits

Six behavior groups cover empty and duplicate service sets, environment and
feature mismatch, sealed-provider exclusion, empty build digests,
complete/disjoint provider classification, nonempty-approved rejection,
provider-derived SSP duties, pre-test and unsupported-service rejection,
successful non-approved indication, catastrophic indicator
invalidation, explicit test failure, interrupted test unwind, reentry, and
permanent failure. Four compile-fail examples reject raw service-set
fabrication, ordinary backend-policy injection, service-indicator cloning, and
cross-thread movement.
A SHA-256-bound four-file policy keeps every source below 500 lines, forbids
standard-library, allocation, unsafe, FFI, runtime detection, ordinary dispatch,
global/atomic state, and std-adapter access, and rejects twenty-four broken fixtures.

## Security Assessment And Remediation

The exceptional repository-owner assessment of initial implementation commit
`d3b8a23d42dbeb80643b1c41ce626364cbca1d9a` found two High latent design
issues. Broad operation categories could be configured as approved before an
exact algorithm-and-parameter identity existed, and caller-supplied SSP
destruction duties could omit copies declared by the installed provider.

Configuration now rejects every nonempty approved set, and the operation-only
output has been renamed and constrained to an informational service indicator
that cannot authorize or execute provider work. SSP destruction duties now
come directly from the provider contract, removing the second source of truth.
The repository owner retested exact signed remediation candidate
`bc83f44a9c8fdb710d03429b1669ee6c4449b054` and reported a green result with
zero open findings. The permanent `PASS`/`PASS` report is
[`security/pentest/v0.17.0.md`](../security/pentest/v0.17.0.md).

The assessment also records a non-exploitable future constraint: permanent
failure is currently scoped to one caller-owned session. Before executable or
approved FIPS services exist, v0.127.1 must introduce one irreversible
module-wide latch shared by every current and future session, so a newly
constructed sibling session cannot bypass failure.

This milestone does not implement a FIPS cryptographic module, cryptographic
algorithm, provider effect, self-test algorithm, service execution, CPU kernel,
runtime detector, operating-environment measurement, deterministic binary
reproduction, SSP transport or destruction effect, independent verification,
CMVP submission, certificate, or FIPS 140-3 validation. Implementations of the
self-test runner remain security-critical trusted code.

## Release Process

v0.17.0 is an exceptionally assessed development milestone. Its green owner
retest and committed `PASS`/`PASS` report are complete. The complete local
gate, green GitHub and CodeQL, and explicit authorization remain mandatory
before its signed tag. It selects no crates.io publication. Every change after
v0.15.0 remains in the scheduled cumulative v0.20.0 assessment.
