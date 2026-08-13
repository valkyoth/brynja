# Brynja v0.18.0 Development Milestone

Status: implementation complete; awaiting pentest

Brynja v0.18.0 adds the mandatory security-outcome authority contract to
`brynja-core`. It advances only the `brynja` facade version, selects no
crates.io publication, and remains inside the cumulative range that the
scheduled v0.20.0 checkpoint will assess.

## Exact Decision Domains

- Sealed type-level domains distinguish self-tests, service approval, protocol
  and profile selection, authentication, tickets, resumption, PSKs, early
  data, anti-replay, amplification, exhaustion, provider results, key
  lifecycle, ECH, policy, and terminal transitions.
- One allocation-free caller-owned authority permits only one incomplete
  decision at a time and binds it to a checked monotonic generation.
- The contract is protocol-neutral and contains no decision policy or provider
  effect.

## Mandatory Authoritative Outcomes

- Exhaustive typed results distinguish accepted, approved, non-approved,
  rejected, pending, canceled, failed, and terminal work.
- Approved and non-approved results are confined to service approval; ordinary
  domains cannot claim them, and service approval cannot collapse into an
  ordinary accepted result.
- Explicit terminal transitions can remain pending or enter terminal state but
  cannot claim non-terminal success.
- Closed rejections and failures carry no arbitrary text, secret, provider-native
  code, peer bytes, length, or offset.
- Terminal integrity, provider, external-key destruction, generation,
  invariant, and policy reasons permanently latch the authority.

## External-Key Destruction

- External-key destruction begins as an exact key-lifecycle decision.
- The flow issues one non-cloneable, thread-bound token naming the
  external-store destruction target.
- Only consuming the exact authority- and generation-bound token can produce a
  successful result.
- Duplicate token requests, cross-authority or cross-generation substitution,
  provider failure, explicit abandonment, and `Drop` before completion fail
  terminally.

## Verification

- Ten deterministic behavior groups exercise all decision classes and every
  accepted, approved, non-approved, rejected, pending, canceled, failed, and
  terminal outcome class.
- Rejection matrices cover unsupported, policy, authentication, replay,
  amplification, ticket, PSK, early-data, and ECH decisions; failure matrices
  cover self-test, provider, exhaustion, authentication, key lifecycle, and
  policy failures. Cross-domain reasons fail terminally.
- Three compile-fail examples reject pending-decision cloning and thread
  movement plus external-key token cloning.
- A SHA-256-bound four-file policy enforces private authority state,
  single-consumption destruction, exact approval and terminal separation, the
  500-line source ceiling, and no `std`, allocation, unsafe, FFI, provider
  effect, or audit-event coupling. Eighteen broken fixtures test the gate.

## Limits

This milestone implements no self-test, service-approval policy, protocol or
profile selector, authentication, ticket, resumption, PSK, early-data,
anti-replay, amplification, ECH, provider effect, external key store,
destruction effect, event schema, cryptographic algorithm, protocol engine,
independent verification, or FIPS validation. A token completion is a trusted
provider assertion, not proof that an external key was erased.

## Release Process

v0.18.0 is a tagged development milestone with no scheduled cumulative
pentest or crates.io publication unless its implementation triggers an
exceptional assessment. Its implementation candidate must receive the requested
pentest, then the complete local gate, green GitHub and CodeQL, and explicit
authorization before its signed tag. Every change after v0.15.0 remains in the
scheduled cumulative v0.20.0 assessment.
