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

## Non-Goals At 0.1.0

No security or interoperability guarantee exists. The current code is package
scaffolding only.
