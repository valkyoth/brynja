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

## Planning Update

The roadmap now adds RFC 9580 OpenPGP as a separately bounded final pre-1.0
protocol phase. Thirty-six OpenPGP implementation and assurance stops run from
v0.163.0 through v0.180.0, followed by integrated TLS/OpenPGP rehearsal, final
audit, remediation, cumulative pentest, and production-candidate gates through
v0.185.0. OpenPGP shares reviewed primitive crates but never TLS state, PKIX
trust, deprecated algorithm fallback, implicit platform effects, or a FIPS
approved-service claim.

Version v0.47.1 now owns a future admission review for exact-pinned first-party
`base64-ng` reuse. Brynja will not duplicate Base64, but the reachable PEM and
OpenPGP armor path must remain allocation-free, `no_std`, feature-minimal,
native-code-free, non-cryptographic, and outside `brynja-fips-module`.
`base64-ng-openpgp` is not pre-admitted; it must first expose the required
caller-buffer profile or Brynja will reuse only the core Base64 transforms.
This planning change adds no v0.18.0 production dependency or runtime code.
Complete streaming and fixed-message SHA-1 is separately planned once in
`brynja-legacy-sha1` with explicit collision-resistance warnings and no modern
graph edge. A following milestone admits `brynja-openpgp-legacy` as its first
consumer solely for v4 fingerprints. Future legacy protocol or post-1.0 legacy
hash-facade consumers require their own numbered integration review and reuse
the same implementation rather than building SHA-1 again.

## Release Process

v0.18.0 is a tagged development milestone with no scheduled cumulative
pentest or crates.io publication unless its implementation triggers an
exceptional assessment. Its implementation candidate must receive the requested
pentest, then the complete local gate, green GitHub and CodeQL, and explicit
authorization before its signed tag. Every change after v0.15.0 remains in the
scheduled cumulative v0.20.0 assessment.
