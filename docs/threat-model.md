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
use-after-failure. Assurance infrastructure additionally assumes hostile
corpora and adapters that hang, crash, flood output, emit malformed or
noncanonical results, disagree silently, attempt shell or capability escape,
or exploit a verifier/toolchain mismatch to create a false proof claim.
Foundation-domain attackers additionally try to overflow or underflow numeric
state, force platform-width truncation, confuse item counts with byte lengths,
wrap sequence numbers or epochs, select accidental unlimited defaults, mutate
limit policy during an operation, or extract configured limits through errors.
Cursor attackers additionally supply every possible truncation boundary,
oversized lengths that overflow end offsets, valid prefixes with trailing
bytes, and read sequences intended to advance state after failure, fork parser
state, escape caller lifetimes, or disclose input through diagnostics. Output
attackers additionally force capacity and aggregate-length failures after
valid prefixes, split data across empty and non-empty parts, and attempt to
observe partial mutation, outside-buffer writes, stale cursor advancement,
mutable aliasing, or output-derived diagnostics.
Workspace attackers additionally attempt to confuse named arena domains,
reuse caller storage containing prior connection material, read a retained-byte
allocation before complete initialization, treat `SecretDomain` as a secret
owner or erasure guarantee, store private keys in the certificate arena, or
infer destruction from an ordinary safe fill, debug canary, or drop.
Secret-lifecycle attackers additionally attempt partial-initialization escape,
duplicate completion, missed destruction on error or replacement, early
termination after one failed destruction target, value-bearing diagnostics,
false local-memory erasure assertions, or production reachability of the RFC
9850 traffic-secret key logger.
Owned-memory attackers additionally try to elide clearing stores through
optimization, escape the one approved unsafe block, read partial initialization,
retain prior caller bytes, overrun a region, create mutable aliases, confuse a
returned local-memory completion with cache or DMA completion, or extend the
claim to registers, copies, dumps, suspend images, physical memory, forgotten
owners, concurrency, and termination.

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
- private-field bounded numeric values, checked arithmetic in every profile,
  semantically separate quantities, non-wrapping monotonic values, explicit
  immutable single-assignment budgets with typed duplicate and incomplete
  construction failures, and limit-value-free exhaustion errors;
- private-field borrowed cursors with checked end offsets, bounds-checked slice
  access, exact success-only advancement, unchanged state on every failure,
  explicit trailing-data rejection, caller-bound input lifetimes, no cursor
  cloning or formatting, and value-free read errors;
- private-field caller-buffer write cursors with exclusive output lifetimes,
  checked complete-range and aggregate-part preflight, exact success-only
  mutation and advancement, byte-for-byte failure preservation, consuming
  exact-capacity completion, no cursor cloning or formatting, and value-free
  write errors;
- exact caller-workspace partitioning with compile-time domain separation,
  complete-range allocation, retained-byte initialization duties, and an
  explicit prohibition on secret-bearing consumption until typed complete
  initialization and proven complete-region destruction are implemented;
- affine secret initialization with exact complete-write transition,
  single-consumption destruction completion, all-target cleanup attempts,
  returned terminal failure on explicit transitions, mandatory durable or
  fail-stop notification for a failure reached through `Drop`; the abstract
  state remains byte-free while only the v0.11 owned-region state may back it;
- exclusive borrowed secret-region ownership that clears prior bytes before
  write-only sequential initialization, exposes read access only after exact
  completion, clears the complete region on explicit and Drop exits, confines
  one volatile store to one private unsafe module, verifies emitted code at MIR,
  LLVM IR, and assembly levels, and keeps cache, DMA, copy, dump, physical, and
  termination duties outside the local-allocation completion claim;
- RFC 9850 traffic-secret logging only in a separately compiled, unpublished
  test-support package that production packages and features cannot reach;
- fail-closed entropy, time, identity, revocation, and algorithm policy;
- no secret-bearing logs, panics, debug formatting, or error strings;
- modern/legacy package and runtime isolation;
- deterministic builds, pinned CI actions, zero third-party dependencies, SBOMs, and
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
- current RFC update closure, globally reconciled normative-section decisions,
  verified cross-bundle delegation, and complete requirement traceability,
  with cross-policy conflicts, RFC 6066 semantic misbinding,
  obsolete-authority, orphan, drift, and weakened-language failures;
- current PKIX revocation and policy semantics, authoritative Must-Staple
  failure, signed OCSP authority over caller-owned cache metadata, pairwise and
  domain-bound external PSKs, production key-log isolation, DTLS-owned
  path-bound return-routability state, extension, ContentType 27 and message
  registries, bounded RFC 6066 peer ClientHello ignore with separate
  configuration rejection and TLS 1.2 ownership,
  source-blocked legacy lifecycles, and terminal HPKE context invalidation and
  destruction;
- deterministic bounded mutation and external-process differential execution
  with no shell, descriptor-bound limit-plus-one input reads, one-case corpus
  streaming, Windows kill-on-close Job Objects, cooperative POSIX
  process-group cleanup, fail-closed hostile-POSIX external-containment
  preconditions, simultaneous output caps, canonical result parsing, explicit
  replay identity, at least two distinct adapters, exact external tool pins,
  separate release/Kani compiler pairings, and caller-enforced OS sandboxing;
- certificate-bound FIPS module selection, mandatory service indicators,
  approved-only typestates, exact operational-environment matching, immutable
  validated artifacts, and fail-closed claim withdrawal or revalidation after
  guidance, algorithm, vulnerability, patch, certificate, or environment drift.

## Non-Goals At 0.11.0

No transport security or interoperability guarantee exists. The only protocol
code consists of allocation-free shared alert/failure, bounded
numeric/resource value domains, and protocol-neutral borrowed read and
transactional caller-buffer write cursors, an exact caller-owned workspace
partition with monotonic arena accounting, an abstract secret-lifetime
contract, and exclusive caller-owned secret-region clearing. There is no cache,
DMA, register, copy, dump, suspend-image, physical-memory, forgotten-owner, or
termination erasure guarantee, integer encoder or decoder, framing layer,
protocol parser, record layer, arena release or reuse, handshake, provider
implementation, PKI, or
cryptography.
v0.3.0 inventories and locks source
authority, lifecycle, errata, registry, and roadmap ownership. v0.3.1
classifies every pinned registry entry and explicit semantic surface. v0.3.2
proves stable requirement identity, lifecycle, mapping, and drift enforcement
with a 12-requirement authority pilot. v0.3.3 adds 34 cryptography, encoding,
PKIX, OCSP, and CT requirements. v0.3.4 adds 70 TLS, DTLS, and QUIC-TLS
requirements with exact version, state, rejection, and caller-owned
boundaries. v0.3.5 adds 50 optional, HPKE, ECH, ML-KEM, entropy, operational,
legacy, and residual requirements and closes every locked source, roadmap row,
and protocol surface. v0.4.0 adds assurance policy, runners, and OS-less compile
evidence but no protocol corpus, differential backend, Kani proof harness, or
assurance campaign result. v0.5.0 classifies the alert registry, admits
assigned alerts by protocol version, and separates close, cancellation,
local, provider, and resource-exhaustion outcomes without wire or state-machine
behavior. v0.6.0 adds checked bounded arithmetic, distinct counts and lengths,
non-wrapping protocol-neutral sequence/epoch values, and immutable explicit
resource/work limits without claiming direction-specific state or wire
semantics. v0.7.0 adds exact transactional borrowed input consumption without
claiming framing, parsing, secret ownership, or protocol behavior. v0.8.0 adds
complete-operation-preflight caller-buffer writes without claiming integer
encoding, compound rollback across separate successful calls, arenas, overlap
policy, secret destruction, framing, or protocol behavior. v0.9.0 safely
partitions one exact caller buffer into five named disjoint domains and adds
monotonic allocation telemetry without claiming release, reuse, zeroization,
secret ownership, framing, or protocol behavior. v0.10.0 adds only abstract
complete-initialization and destruction-duty states plus repository-only RFC
9850 test support. v0.11.0 adds only the complete exclusively borrowed Rust
allocation clearing primitive and affine byte-backed region states; it makes no
platform-wide erasure, protocol, interoperability, independent-review, FIPS, or
production claim. Planned,
future-work, blocked, legacy,
governance-tool, and policy-only assurance states are not protocol
implementation, formal verification, bare-metal runtime support, or FIPS
validation claims.
