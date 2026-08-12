# Brynja v0.15.0 Public Checkpoint

Status: awaiting pentest

Brynja v0.15.0 adds typed wall and monotonic clock contracts and prepares the
cumulative public checkpoint covering every change after v0.10.0 through this
candidate. Nothing may be tagged or published until the repository owner
records the cumulative PASS pentest report and GitHub and CodeQL are green.

## Typed Clock Boundary

- `ClockDuration` is canonical, nonnegative, and checked for carry, borrow,
  overflow, underflow, and monotonic-tick representability.
- `WallTime` represents signed Unix time independently of monotonic time;
  inclusive `WallTimeRange` evaluation provides explicit before, valid, and
  after outcomes for later PKI policy.
- `MonotonicInstant` is opaque, redacts its raw tick value, and is bound to one
  explicit nonzero runtime or boot generation.
- `MonotonicClock` admits equal ticks, reports temporary source unavailability
  without losing prior state, and permanently fails after any rollback.
- `MonotonicDeadline` binds checked duration to one generation and one exact
  timer, freshness, ticket, or replay purpose.

## Test And Policy Evidence

- Eight core behavior tests and two deterministic-source tests cover canonical
  arithmetic, signed epoch edges, inclusive ranges, unavailable reads,
  generation exhaustion, equal ticks, rollback, elapsed direction, deadline
  purpose/generation binding, and overflow.
- Compile-fail examples reject wall/monotonic interchange and direct instant
  construction.
- A SHA-256-bound policy enforces five reviewed files, private monotonic state,
  redacted formatting, permanent rollback latching, four exact purposes, the
  500-line ceiling, no `std`, allocation, unsafe, FFI, or OS clock access, and
  permanent non-publication of deterministic fixtures. Nine broken fixtures
  prove the checks fail closed.

## Cumulative Publication Candidate

The guarded publication plan selects fourteen crates in dependency order:
`brynja-core 0.8.0`, `brynja-crypto 0.1.1`, initial
`brynja-crypto-cpu 0.1.0` and `brynja-crypto-cpu-std 0.1.0`, eight modern
dependency-only packages at `0.1.7`, initial `brynja-sanitization 0.1.0`, and
`brynja 0.15.0` last. Repository-only and unimplemented legacy packages remain
unpublished. Selection is not publication: the script cannot upload before the
committed PASS report, signed matching tag, clean tree, and explicit version
confirmation.

## Security And Scope

This checkpoint provides no OS clock, PKI validator, protocol timer engine,
ticket service, replay database, cryptographic algorithm, accelerated kernel,
TLS implementation, independent cryptographic verification, or FIPS
validation. Wall time can be adjusted externally; monotonic time is only as
trustworthy as the downstream source and explicit generation supplied by its
integrator. The cumulative pentest covers changes after signed public tag
v0.10.0 through the exact v0.15.0 candidate.
