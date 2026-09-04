# Modularity Policy

Status: enforced policy

Rust source files must remain at or below 500 lines, including tests and module
documentation. New code should split around 450 lines. Splits follow security
and ownership boundaries, not arbitrary line counts.

The modern facade may depend only on modern production crates. Every legacy
engine is named `brynja-legacy-<protocol>` so risk is visible in package
metadata without inspecting source or features. Legacy packages may reuse
reviewed primitive crates but may not be dependencies, features, modules, or
fallback paths of `brynja`. Repository-only packages must remain unpublished.
Scripts check the dependency graph, manifest policy, README synchronization,
and source-file lengths.

`package-policy.toml` is the executable inventory for these boundaries. It
classifies every workspace package and freezes its exact direct dependencies,
optional feature edges, publication class, and resolved no-default and
all-feature graph expectations. Adding, renaming, publishing, or connecting a
package therefore requires an explicit reviewed policy change.

The first-party Rust cryptography golden rule applies across every package and
companion adapter. No Brynja cryptographic or FIPS service may be implemented
by a foreign source file, native object or library, build script, foreign ABI,
or external software cryptographic provider. First-party intrinsics and inline
assembly remain separately reviewed Rust-owned CPU symbols; they do not admit
external assembly or vendor modules. The machine policy in
`first-party-rust-cryptography.md` rejects native implementation edges before
ordinary build and graph checks run.

The `brynja-sanitization` package is a downstream integration
boundary, never a feature or dependency of `brynja`, `brynja-core`,
`brynja-crypto`, `brynja-pki`, a modern or legacy engine, or
`brynja-fips-module`. v0.11.1 admits exact first-party
`sanitization 2.0.4` only for this boundary; v0.11.2 introduced the adapter and
v0.24.14 refreshes its exact pin
with default features disabled and no activated `zeroize` or other third-party
crate. Adapter-owned wrappers bridge the contracts without violating Rust's
orphan rules. The same protocol-neutral package serves modern and legacy
callers with identical destruction guarantees; legacy code does not receive a
separate weaker sanitizer. Any future need for `brynja-legacy-sanitization`
requires its own numbered admission review.

Base64 is an encoding boundary, not cryptography. v0.47.1 reviews the latest
stable first-party `base64-ng` family and may admit only an exact-pinned,
default-feature-disabled, allocation-free `no_std` edge with no unsafe, native
code, build script, or transitive package. `base64-ng-openpgp` is admitted only
if it offers that same caller-buffer profile; otherwise Brynja uses
`base64-ng` transforms behind its own bounded PEM and OpenPGP armor framing.
No admitted Base64 edge may enter primitive implementations,
`brynja-fips-module`, or an unrelated protocol package.

RFC 9850 key logging belongs only to a separately compiled, unpublished
test-support artifact. No production crate, facade feature, default build,
release archive, FIPS module, or downstream dependency path may contain its
labels, formatting code, callbacks, environment lookup, or secret-export hook.

Protocol-facing capability and effect contracts belong in upstream `no_std`
interfaces such as `brynja-core`. `brynja-platform` is downstream and may
implement them, but TLS, QUIC TLS, and DTLS must not depend on it. The
`brynja-tls` package is the evergreen facade and one-pass router; it does not
own version-specific protocol state machines. `brynja-tls12` owns the hardened
TLS 1.2 engine. `brynja-tls13` owns TLS 1.3 stream records and adapts the
`brynja-tls13-handshake` record-independent state machine that is also consumed
by QUIC TLS. A future TLS generation receives its own version-named package and
cannot alter an older engine in place. DTLS may reuse reviewed codecs,
transcript, certificate, and key-schedule components but retains a distinct
state machine, path identity, epochs, fragmentation, and retransmission.

OpenPGP is a separate modern protocol family. `brynja-openpgp-core` owns RFC
9580 packet, registry, resource, certificate and key models without platform
effects. `brynja-openpgp-armor` owns only armor framing over the admitted
Base64 boundary. `brynja-openpgp` owns modern Sans-I/O message and key-lifecycle
engines and depends on exact reusable primitive packages; it never depends on
TLS, PKI path validation, platform implementations, or a global trust store.
Deprecated algorithms, when independently justified for read, decrypt, or
verify interoperability, live in optional `brynja-openpgp-legacy`; it cannot
enter the modern facade, defaults, FIPS artifacts, or generate weak material.
`brynja-legacy-sha1` owns one complete streaming and fixed-message SHA-1
implementation with conspicuous collision-resistance warnings. It is not a
modern hash family and never enters `brynja`, defaults, TLS, PKIX, general hash
or FIPS graphs. Before 1.0, only `brynja-openpgp-legacy` may depend on it and
only for exact v4 fingerprint/key-ID derivation. A later legacy protocol or
post-1.0 legacy hash facade may reuse that exact implementation only after its
own numbered consumer-specific admission, graph review, cryptographic audit
and pentest; no consumer may create a second SHA-1 implementation.
OpenPGP structural and cryptographic validity never implies Web-of-Trust or
application identity trust, and no package performs an implicit keyserver,
WKD, DNS, filesystem, TOFU, or network operation.

CPU acceleration follows an equally strict downstream boundary.
Portable scalar references belong to the smallest semantic family. Before the
first hash implementation, `brynja-hash-core` owns only fixed-output and XOF
interfaces, `brynja-hash-sha2` owns SHA-2, `brynja-hash-sha3` owns SHA-3 and
SHAKE, and `brynja-mac-hmac` owns HMAC. `brynja-crypto` consumes those exact
symbols and owns provider contracts, compositions, and scalar primitives not
yet split into a narrower reviewed family. This prepares the versionless
[post-1.0 hashing plan](POST_1_0_HASH_PLAN.md) without adding the future facade
or catalogue to the v1 graph.

`brynja-crypto-cpu` is an optional zero-dependency `no_std` package for
separately reviewed, hashed ISA kernels, compile-time selection, capability
tokens, KAT health, quarantine and reporting. Its x86 SHA, AArch64 SHA2, and
RV64 Zknh SHA-256 candidates are implemented but unadmitted. The opt-in
`brynja-crypto-cpu-std` boundary uses `std` only for x86/AArch64 CPU feature detection and
dispatch initialization. It cannot provide entropy or other OS services and
cannot enter a default, protocol-engine, bare-metal or validated-module graph.
No CPU package or feature may alter scalar public type layout or protocol
semantics. Candidate detection is not activation; required acceleration fails
closed, opportunistic fallback is explicit, and every FIPS artifact owns its
exact implementation symbols, dispatch table and operational-environment
evidence without inheriting the ordinary std adapter.

Future `brynja-rustls` and `brynja-tokio` are explicit downstream companion
packages in separately locked integration workspaces. They are never
dependencies, features, or re-exports of `brynja`, its engines, crypto
packages, legacy packages, defaults, bare-metal graph, or validated module.
Their narrowly admitted pure-Rust rustls or Tokio dependencies are integration
API exceptions only: each adapter owns an exact feature allowlist, dependency
closure, freshness review, advisory policy, SBOM, and native-code rejection.
`brynja-rustls` disables built-in rustls providers and fills every advertised
operation with Brynja cryptography; `brynja-tokio` wraps Brynja TLS rather than
rustls or a raw AEAD stream. Neither exception permits an external
cryptographic implementation anywhere in the project.

Supersession alone never makes a TLS version legacy. Reclassification needs
a dedicated numbered security-boundary release, standards and cryptographic
evidence, removal from every modern dependency and negotiation path, and a
clean graph audit. Any justified controlled-interoperability continuation moves
to a newly named `brynja-legacy-tls1N` package with independent types,
configuration, state, credentials, caches, tickets, audit, pentest, and SemVer.
The formerly modern package receives an explicit deprecation release and may
never become a hidden forwarding dependency to the legacy package.

The bounded SecurityEvent schema is an upstream `no_std` interface owned with
the other Sans-I/O effects. Engines and providers emit caller-drained actions;
they never depend on a logger, allocator, callback, or platform integration.
Event capacity, ordering, caller-supplied timestamps, redaction, and dropped
counts are explicit. Boot and self-test events may be untimestamped for later
caller enrichment; dropped counts saturate and report saturation; identifiers
cannot contain handles, private identities, or stable cross-connection values.
Observation cannot block or alter cryptographic state. SecurityEvent is only an
audit duplicate: service approval, external-key destruction, authentication,
ECH, early-data, anti-replay, and policy decisions remain authoritative through
mandatory typed results, single-consumption completion tokens, and engine state.
Ignoring or dropping every event cannot turn a rejected or non-approved outcome
into an apparently accepted or approved one.

The stable effect surface is explicitly versioned as EngineV1, EventV1, and
ActionV1. Mandatory effects are exhaustive and cannot be ignored through a
wildcard arm or generic success path. Adding a mandatory effect creates V2
interfaces and requires a major SemVer release; V1 does not change underneath
applications. Only bounded, secret-free, observational SecurityEvent values may
be non-exhaustive, and unknown informational values cannot affect engine state.

Standards traceability is also a boundary. One machine-readable source ledger
owns current, obsolete-compatibility, legacy, and caller-owned authorities;
one protocol-surface register owns every identifier and disposition; and one
normative-requirement matrix owns exact source-to-decision, milestone, code or
documented boundary, test, and evidence links. Generated projections may not
become competing authorities. Repository checks reject stale source closure,
orphan requirements, unclassified surfaces, and obsolete text presented as
current.

Every arithmetic and cryptographic implementation milestone owns its applicable
proof harness beside the small production module. Harness and documentation
claims explicitly distinguish symbolic full-width proofs, sound proofs
parameterized over limb count, reduced-width exhaustive models that validate
algorithm and harness structure, and production-width vector or differential
evidence. Reduced-width evidence never proves production-width equivalence;
residual width, path, abstraction, and tool gaps remain explicit through the
v0.155.0 final coverage gate. That gate owns a deterministic machine-readable
claim register mapping each primitive and exact implementation symbol to its
property, supported widths or parameters, verification method, evidence,
assumptions, and residual gaps; repository checks reject stale or incomplete
entries.

FIPS is a package and type boundary, never an additive boolean Cargo feature.
The separately publishable `brynja-fips-module` is the exact artifact inside the
validation boundary. The downstream `brynja-fips` facade provides easy client
and server construction but requires a matching certificate-bound manifest and
validated-module handle; ordinary `brynja` configuration and generic providers
cannot acquire or imply a FIPS claim.

The FIPS sequence first freezes a current overall Security Level 1 requirement
baseline, then its boundary, dependency allowlist, services, ports, SSP design,
and operational-environment model; it does not claim an exact artifact identity
at either point. Only after SP 800-90B entropy, the SP 800-90A DRBG, SP 800-90C
construction, provider, indicators, SSP services, algorithms, pre-operational
and conditional self-tests, permanent error state, and module audit events are
final does the artifact freeze its source, symbols, exact dependency closure,
features, dispatch tables, build inputs, tool configuration, and binary hashes.
HPKE, ECH, certificate compression, and every later optional module remain
downstream of provider ports and cannot alter that artifact. Any such change
starts a new validation and artifact line.

`brynja-sanitization` is outside the validated module closure. It may protect
application-owned storage around a FIPS deployment, but it cannot implement,
replace, or imply the validated module's SSP destruction service or inherit
the module certificate.

Certificate identity, caveats, status, sunset, operational environments,
approved services, security-policy hash, and artifact hashes live in an
immutable generated manifest. Patched unvalidated artifacts use a separate
release identity and cannot reuse the validated claim. Guidance changes,
algorithm transitions, vulnerabilities, patches, certificate changes, and
environment additions require recorded impact, regression scope, and the
applicable CMVP revalidation path.
