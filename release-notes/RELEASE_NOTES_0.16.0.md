# Brynja v0.16.0 Development Milestone

Status: implementation complete; awaiting green GitHub and CodeQL

Brynja v0.16.0 implements an upstream `no_std` lifecycle for pending
certificate, external-signature, and accelerator operations. It advances only
the `brynja` facade version, selects no crates.io publication, and begins the
cumulative change range that the scheduled v0.20.0 checkpoint will assess.

## Exact Pending Requests

- `PendingRequest` consumes one previously authorized provider request and
  admits only certificate-path, signature, or accelerator-eligible operations.
- Admission requires the same installed provider to declare exact poll and
  cancellation capabilities. External signatures additionally require the
  external-store destruction duty; accelerator requests require its
  accelerator destruction duty.
- Immutable nonzero effect-attempt and backpressure-response limits follow the
  affine request through every no-state retry and active transition.

## Resumption And Cancellation

- `PendingProvider` separates downstream effects from the upstream lifecycle.
  Begin either creates no provider state or exactly one opaque state.
- Every active, retry, backpressure, completion, cancellation, and provider-
  failure response returns state ownership to the lifecycle. No result can
  silently lose, duplicate, or substitute continuation state.
- Effect calls and cumulative backpressure responses use checked counters.
  Exhaustion is terminal and triggers mandatory cleanup.

## Authoritative Destruction

- Completion and cancellation become authoritative only after provider state
  is consumed with a non-cloneable `PendingDestructionToken`.
- The token exposes the exact resource, terminal cause, and frozen local,
  external-store, accelerator, cache, and DMA duties. Only consuming it can
  produce a completion or closed failure.
- Provider failure, exhaustion, explicit completion/cancellation, and `Drop`
  all use the same single-consumption cleanup path. A failed `Drop` cleanup is
  routed to the provider's mandatory durable or fail-stop handler.

## Verification And Limits

Seven deterministic state-machine tests cover exact admission, no-state begin,
retry, backpressure, completion, cancellation, provider failure, exhaustion,
destruction failure, `Drop`, and unchanged input. Compile-fail tests reject
request, operation, and destruction-token duplication. A SHA-256-bound policy
keeps each source below 500 lines, requires the security transitions, forbids
standard-library, allocation, unsafe, FFI, platform, and architecture access,
and rejects eleven broken fixtures.

This milestone implements no downstream provider, certificate validator,
signature mechanism, key store, accelerator driver, CPU kernel, OS integration,
protocol engine, cryptographic algorithm, independent verification, or FIPS
validation. Trait implementations remain trusted to honor their documented
state and destruction assertions; process abort, leaked values, external
device failure, dumps, caches, DMA copies, and physical remanence remain within
the existing operating-boundary limitations.

## Release Process

v0.16.0 is a tagged development milestone. The complete local gate, green
GitHub and CodeQL, and explicit repository-owner authorization are mandatory
before its signed tag. It has no scheduled standalone pentest or crates.io
publication unless an exceptional trigger is activated. Every change after
v0.15.0 remains in the scheduled cumulative v0.20.0 assessment.
