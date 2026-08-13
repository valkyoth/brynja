# Brynja v0.18.1 Development Milestone

Status: implementation complete; awaiting repository-owner review, the final
committed candidate, and green GitHub and CodeQL

Brynja v0.18.1 adds a bounded observational security-event schema to
`brynja-core`. It advances the `brynja` facade to `0.18.1`, retains every
supporting crate's published version, and selects no crate for crates.io.

## Bounded Observational Events

- `SecurityEvent` is opaque and can only be derived from an exact v0.18
  pending/outcome value or a non-ready authoritative snapshot.
- Closed event classes cover pending, accepted, approved, non-approved,
  rejected, canceled, failed, and terminal observations.
- Outcome events preserve the exact authority-retained decision and
  disposition. Terminal observations preserve the exact terminal reason and
  deliberately carry no invented decision identity.
- Events contain no authority generation, secret, key/provider handle, peer
  identity, plaintext, transcript, PSK identity, ticket, ECH inner name,
  arbitrary string, byte payload, or stable cross-connection identifier.
- Event formatting can expose only closed secret-free fields. Events remain
  independent of peer-visible alerts.

## Timestamp And Queue Contract

- `SecurityEventRecord` begins explicitly untimestamped and can receive one
  caller-provided `WallTime` or generation-bound `MonotonicInstant` later.
- Enrichment reads no clock, rejects an untimestamped input, and cannot replace
  an existing timestamp.
- `SecurityEventQueue<N>` embeds a fixed `[Option<SecurityEventRecord>; N]`
  caller-owned FIFO and allocates nothing.
- Enqueue and drain perform no callback, I/O, retry, wait, provider operation,
  peer alert, or protocol transition. Exclusive mutable access prevents safe
  reentrant queue mutation.
- Full and zero-capacity queues drop the incoming observational record
  immediately. The exact drop count saturates at `u64::MAX`, and a separate
  visible flag records that the true count no longer fits.

## Security Boundary

Event construction, copying, formatting, timestamping, queuing, dropping, and
draining cannot authorize, commit, complete, latch, or alter the v0.18
authority. Missing, ignored, delayed, duplicated, or dropped events cannot make
rejected, non-approved, failed, incomplete, or terminal work appear accepted,
approved, complete, or successful. The schema implements no audit sink,
delivery guarantee, persistence, serialization format, policy engine, provider
effect, protocol state machine, cryptographic operation, independent review,
or FIPS validation.

Caller timestamp privacy, audit transport, persistence, access control,
serialization, retention, and response policy remain application-owned.

## Verification

- Ten integration tests cover all seventeen security-decision domains, exact
  negative outcomes, token-bound verified acceptance, non-ready snapshots,
  terminal state, wall and monotonic timestamp enrichment, deterministic FIFO
  ordering, wraparound, zero/full capacity, absent drains, loss visibility,
  and equality across different authority generations.
- Two internal tests construct and format every closed event disposition and
  exercise counter saturation without requiring `u64::MAX` enqueue attempts.
- Three compile-fail examples reject raw event forging, event authorization,
  and simultaneous mutable queue access.
- Four source files are SHA-256 locked and remain below 500 lines.
- Twenty-two broken fixtures reject dynamic or secret payloads, identifiers,
  authority/provider/alert crossing, callbacks, public internal state,
  wrapping counters, lost saturation, oversized sources, and reviewed-source
  drift.
- The complete workspace gate covers Rust 1.90.0 through 1.97.1, all promised
  targets, `no_std`, dependency/advisory policy, SBOM, package contents,
  documentation, and modern/legacy isolation.

## Release Process

v0.18.1 is a signed development milestone after the exact candidate passes the
complete local gate and GitHub and CodeQL are green. It has no scheduled
pentest or crates.io publication unless an exceptional trigger is recorded.
All changes after v0.15.0, including v0.18.1, remain in the backwards-looking
cumulative v0.20.0 assessment range.

