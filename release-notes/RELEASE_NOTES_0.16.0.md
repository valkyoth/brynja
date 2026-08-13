# Brynja v0.16.0 Development Milestone

Status: remediation complete; awaiting repository-owner retest

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
- Every effect exposes the exact opaque installed-provider handle it
  implements. A request authorized by another provider fails before effectful
  work, and identity is rechecked before later transitions.
- Resume, cancellation, and destruction borrow state owned by the lifecycle.
  Recoverable provider unwinding therefore leaves state available to the
  mandatory `Drop` cleanup path.
- Effect calls and cumulative backpressure responses use checked counters.
  Exhaustion is terminal and triggers mandatory cleanup.

## Authoritative Work

- Bounded, effect-free provider cost methods derive the exact charge for begin,
  resume, and cancellation.
- The lifecycle rejects zero charges, debits the monotonic request meter, and
  only then creates a private, non-forgeable work permit consumed by the effect.
- Application code can neither debit pending work directly nor construct a
  permit that authorizes uncharged work.

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

Eleven deterministic and adversarial state-machine tests cover exact admission,
provider substitution, provider-derived and zero work charges, resume/cancel
unwinding, no-state begin, retry, backpressure, completion, cancellation,
provider failure, exhaustion, destruction failure, `Drop`, and unchanged input.
Compile-fail tests reject request, operation, and destruction-token duplication
plus work-permit forgery. A SHA-256-bound policy
keeps each source below 500 lines, requires the security transitions, forbids
standard-library, allocation, unsafe, FFI, platform, and architecture access,
and rejects sixteen broken fixtures.

## Security Assessment And Remediation

The exceptional repository-owner assessment found two High issues and one
Medium issue in the initial implementation commit
`cb45db56db65a658b73f3cb5273ca36648514b91`. An authorized request could be
executed by a substituted provider effect; resume or cancellation unwinding
could move state beyond `Drop`; and pending effects could not debit the
authoritative work meter. Exact identity binding, borrowed callback state, and
provider-derived precharged work permits close those paths. The remediation is
locally green and awaits repository-owner retest; the permanent report is
[`security/pentest/v0.16.0.md`](../security/pentest/v0.16.0.md).

This milestone implements no downstream provider, certificate validator,
signature mechanism, key store, accelerator driver, CPU kernel, OS integration,
protocol engine, cryptographic algorithm, independent verification, or FIPS
validation. Trait implementations remain trusted to honor their documented
state and destruction assertions; process abort, leaked values, external
device failure, dumps, caches, DMA copies, and physical remanence remain within
the existing operating-boundary limitations.

## Release Process

v0.16.0 is a tagged development milestone. The complete local gate, green
GitHub and CodeQL, a green repository-owner retest, and explicit authorization
are mandatory before its signed tag. This exceptional assessment does not
select a crates.io publication. Every change after
v0.15.0 remains in the scheduled cumulative v0.20.0 assessment.
