# Brynja 0.24.5 Release Notes

Status: implementation, live authority observation, and complete local
verification passed; candidate commit, hosted GitHub and CodeQL, and signed
tag pending; no scheduled pentest or crates.io publication is selected

Brynja 0.24.5 implements the cross-authority standards lifecycle monitor. It
extends the existing immutable standards ledger with explicit official
publication identity and mutable upstream state while preventing network
observations from changing requirements, code, Brynja classification,
publication selection, or security claims.

## Added

- A generated machine-readable register for all 130 locked authorities: 104
  RFCs, 14 NIST publications, two ITU-T documents, two admitted RISC-V
  cryptography specifications, and eight IANA registries.
- Separate upstream `draft`, `final`, `update-planned`, `superseded`, and
  `withdrawn` states and Brynja `current`, `compatibility`, `legacy-only`,
  `disabled`, and `rejected` dispositions.
- Canonical landing and content URLs, exact content hashes, stable landing-page
  projections, edition, publisher, planning notice, replacement relation,
  last observation, reviewed impact, and affected requirement, symbol,
  evidence, and milestone fields.
- A dependency-free exact-URL observer with response, time, and parser bounds;
  strict redirect rejection; official RFC-index and errata projections; and
  non-authorizing review artifacts for drift, rollback, malformed data,
  oversized responses, timeout, or outage.
- A weekly and manual read-only GitHub workflow using immutable latest action
  pins, plus offline repository validation, release-age validation, live
  pre-tag observation, and a committed PASS freshness receipt.
- Broken fixtures for byte, status, draft/final, planning, supersession,
  withdrawal, replacement, metadata, rollback, replay, redirect, malformed,
  oversized, timeout, outage, state-forgery, review, and workflow regressions.

## Verification

- The deterministic register reproduces byte-for-byte and contains exactly 130
  unique sorted authority rows with complete official and ownership fields.
- Two consecutive captures of all 17 distinct local-authority landing pages
  produced identical stable-field projections. NIST projections exclude shared
  navigation and active content while retaining publication-specific status,
  planning, documentation, related-publication, and history fields.
- The first strict 2026-08-31 live observation detected newly reported RFC
  9846 editorial erratum 9157. Human review classified its capitalization of
  two `Main Secret` references as unverified and `track-not-applied`, with no
  TLS behavior or requirement change; the exact errata evidence and all 31
  affected requirement revisions were refreshed explicitly.
- The final complete observation fetched every locked document and registry,
  all local publication pages, the RFC index, and every locked RFC's errata
  feed. It returned `PASS` with zero new or unresolved observations.
- A later clean observation cannot erase an older unresolved observation.
  Behavior-changing dispositions require an exact corrective milestone and
  `exceptional-required` pentest state.
- Ordinary builds and the complete repository gate perform only deterministic
  offline reproduction; scheduled and pre-tag network observations cannot
  write repository policy or pins.

## Security Boundaries

The monitor treats every upstream response as untrusted evidence. An official
status label is not an instruction: it cannot keep a withdrawn capability
modern, move code into a legacy facade, disable code, accept a draft, update a
requirement, or authorize publication. Only a committed human disposition may
decide no effect, implementation update, compatibility, legacy-only, disabled,
or rejected handling. Any decision that can change security behavior requires
a corrective milestone, repeated affected evidence, and an exceptional
pentest.

This milestone changes no production Rust, hash result, protocol parser,
public cryptographic API, dependency graph, unsafe boundary, CPU-backend
admission, independent-review state, secret-erasure state, or FIPS 140-3 claim.

## Release Process

Version 0.24.5 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range. It advances only the facade version and selects zero
crates.io packages. No scheduled or exceptional pentest is required because
the change is repository-only assurance tooling and adds no production or
cryptographic behavior. The verified candidate must still pass the complete
local gate plus hosted GitHub and CodeQL before its signed tag is authorized.
