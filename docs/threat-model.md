# Brynja Threat Model

Status: initial; expands with every milestone

## Assets

Traffic keys, private keys, PSKs, tickets, exporter secrets, transcript state,
trust anchors, peer identity decisions, plaintext, configuration intent, and
availability are protected assets. FIPS assets additionally include exact
module identity, certificate and caveat truth, approved-service results,
self-test and permanent-error state, entropy and operational-environment
identity, security-policy integrity, and the boundary between validated and
ordinary Brynja packages.
Standards assets include exact current and compatibility source identity,
normative requirement strength, registry values, errata decisions, explicit
surface disposition, and source-to-code-and-test traceability.

## Adversaries

Assume an active network attacker controls bytes, segmentation, ordering,
duplication, loss, timing, downgrade signals, certificates, names, extensions,
alerts, retry behavior, and connection volume. Also consider malicious peers,
compromised roots, local unprivileged observers, dependency/supply-chain
attackers, CI compromise, operator mistakes, weak platform entropy/time, and
cross-protocol confusion. Also assume attempts to select the wrong FIPS module
or operational environment, inject a generic provider, suppress service
indicators, reuse a certificate claim for a changed artifact, operate after
sunset or revocation, and confuse a patched unvalidated line with the validated
line. Also assume stale or obsolete RFC text presented as current, silently
weakened SHOULD requirements, unsigned or contradictory-revocation
certificates, suppressed Must-Staple failures, DTLS path hijacking during CID
migration, forged OCSP cache metadata, external-PSK role or peer misbinding,
production secret logging, and HPKE replay, loss, role confusion, or
use-after-failure.

## Required Controls

- strict canonical parsing with exact consumption and bounded work;
- fallible untrusted-input paths return typed errors and must not rely on
  unwinding, panic recovery, unchecked arithmetic, or indexing; release builds
  deliberately abort if an otherwise unreachable panic violates this boundary,
  accepting availability loss as the final fail-closed response;
- typed states that cannot emit application data before authentication;
- transcript and negotiation binding with downgrade and cross-protocol checks;
- constant-time secret operations and explicit secret lifetime/erasure;
- nonce uniqueness, sequence exhaustion, replay, key-update, and ticket limits;
- fail-closed entropy, time, identity, revocation, and algorithm policy;
- no secret-bearing logs, panics, debug formatting, or error strings;
- modern/legacy package and runtime isolation;
- deterministic builds, pinned CI actions, zero dependencies, SBOMs, and
  a current committed pentest report that must change with every later release
  candidate fix;
- explicit package classes and exact no-default and all-feature graph policy so
  optional features cannot smuggle legacy, research, tooling, or platform code
  across a product boundary;
- protected signed linear history, accountable bypass identities, clean
  CodeQL, exact signed release tags, and regular committed report files;
- exact-pinned, default-features-disabled admission of any optional
  `brynja-sanitization` adapter, with no `zeroize` or third-party crate in its
  activated graph and no path into facades, engines, or the FIPS module;
- machine-readable protocol-surface classification so new or changed standards
  and IANA entries cannot remain silently unowned;
- current RFC update closure and complete normative-requirement traceability,
  with obsolete-authority, orphan, drift, and weakened-language failures;
- current PKIX revocation and policy semantics, authoritative Must-Staple
  failure, signed OCSP authority over caller-owned cache metadata, pairwise and
  domain-bound external PSKs, production key-log isolation, path-bound DTLS
  return-routability, and terminal HPKE context invalidation and destruction;
- certificate-bound FIPS module selection, mandatory service indicators,
  approved-only typestates, exact operational-environment matching, immutable
  validated artifacts, and fail-closed claim withdrawal or revalidation after
  guidance, algorithm, vulnerability, patch, certificate, or environment drift.

## Non-Goals At 0.3.3

No transport security or interoperability guarantee exists. The current Rust
code is still package scaffolding. v0.3.0 inventories and locks source
authority, lifecycle, errata, registry, and roadmap ownership. v0.3.1
classifies every pinned registry entry and explicit semantic surface. v0.3.2
proves stable requirement identity, lifecycle, mapping, and drift enforcement
with a 12-requirement authority pilot. v0.3.3 adds 34 cryptography, encoding,
PKIX, OCSP, and CT requirements, but does not implement protocol or
cryptographic behavior. TLS, DTLS, QUIC, optional, legacy, residual, and hybrid
domain population remains owned by v0.3.4 and v0.3.5. Planned, future-work, and
governance-tool implementation states are not protocol implementation claims.
