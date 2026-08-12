# Brynja v0.14.0 Development Milestone

Status: remediation complete; awaiting repository-owner retest

Brynja v0.14.0 implements the entropy and initialized secure-random contract
needed by future first-party cryptographic mechanisms. It advances only the
`brynja` facade version to 0.14.0, selects no crate for crates.io publication,
and remains inside the cumulative v0.10.0-to-v0.15.0 pentest range.

## Entropy Boundary

- `RawEntropyRequest` binds exact instantiation or reseed purpose, security
  strength, and byte length before it can own caller-provided secret memory.
- Raw input is affine, non-cloneable, non-formattable, cleared on every exit,
  and explicitly does not represent an entropy estimate, DRBG, OS source, or
  validation claim.
- Requests are nonempty, bounded to 65,536 bytes, and require enough storage
  capacity for the declared 128-, 192-, or 256-bit strength.

## Initialized Secure Randomness

- `SecureRandomEngine` separates first-party or caller-provided mechanisms
  from the version-neutral upstream state machine.
- `SecureRandom` binds one configuration and runtime generation, forbids
  cloning and formatting, counts only successful requests, forces bounded
  reseed, and rejects inherited post-fork state until reseeded.
- Output begins as cleared write-only caller memory and becomes readable only
  after exact complete initialization. Length mismatch, partial output,
  retryable failure, permanent failure, underfill, and rollback expose no
  output and clear the complete region.
- Permanent faults destroy and quarantine engine state. Explicit and `Drop`
  teardown preserve the mandatory terminal handler when complete destruction
  cannot be established.

## Test-Only Provider And Enforcement

- Permanently unpublished `brynja-test-support` adds a deterministic engine
  with retryable, permanent, partial-write, underfill, reseed, and destruction
  fault injection. It is intentionally non-cryptographic and production-
  unreachable.
- Eleven core state-machine tests, two deterministic-provider tests, and affine
  compile-fail examples cover bounds, exact binding, no mutation, clearing,
  request intervals, fork/reseed, rollback, retry, quarantine, teardown, and
  all declared output purposes.
- A SHA-256-bound source policy rejects cloning or formatting secret state,
  OS randomness, allocation, standard-library use, unsafe or foreign code,
  missing state transitions, test-provider publication, dependency-boundary
  drift, files over 500 lines, and unreviewed source changes. Nine broken
  fixtures exercise the policy.
- The normative surface and requirement registers now bind
  `BRY-REQ-ENTROPY-0014` to the implementation and its exact tests.

## Security And Scope

This milestone implements no random algorithm, DRBG, entropy source, source
health test, OS integration, FFI, cryptographic primitive, protocol engine,
performance claim, independent cryptographic verification, or FIPS validation.
Caller-provided bytes do not inherit a FIPS or entropy-quality claim merely by
passing through these types. Later roadmap milestones retain ownership of
source health, DRBGs, platform providers, and validated-module boundaries.

The voluntary assessment of exact signed implementation candidate
`c7d34806a6170857d2152dc6a9a359b37cd9aaa3` found one Medium destruction-
failure handling gap: failed explicit teardown returned an error without
invoking the mandatory terminal handler. All four failed-destruction paths now
invoke the renamed `handle_destruction_failure` hook, and regression tests
cover explicit and `Drop` failure exactly once. Local remediation passes; the
repository-owner retest remains pending.

## Release Process

v0.14.0 is an internal development milestone. The complete local gate, green
GitHub and CodeQL, and explicit repository-owner authorization are mandatory
before its signed tag. It has no scheduled standalone pentest or crates.io
publication unless an exceptional trigger is activated; its entire change
delta remains in the scheduled cumulative v0.15.0 assessment.
