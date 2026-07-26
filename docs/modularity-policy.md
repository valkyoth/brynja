# Modularity Policy

Status: enforced policy

Rust source files must remain at or below 500 lines, including tests and module
documentation. New code should split around 450 lines. Splits follow security
and ownership boundaries, not arbitrary line counts.

The modern facade may depend only on modern production crates. Historical
packages may reuse reviewed primitive crates but may not be dependencies,
features, modules, or fallback paths of `brynja`. Repository-only packages
must remain unpublished. Scripts check the dependency graph, manifest policy,
README synchronization, and source-file lengths.

RFC 9850 key logging belongs only to a separately compiled, unpublished
test-support artifact. No production crate, facade feature, default build,
release archive, FIPS module, or downstream dependency path may contain its
labels, formatting code, callbacks, environment lookup, or secret-export hook.

Protocol-facing capability and effect contracts belong in upstream `no_std`
interfaces such as `brynja-core`. `brynja-platform` is downstream and may
implement them, but TLS, QUIC TLS, and DTLS must not depend on it. A planned
`brynja-tls-handshake` crate owns the single record-independent TLS 1.3
handshake used by stream TLS and QUIC TLS. DTLS may reuse reviewed codecs,
transcript, certificate, and key-schedule components but retains a distinct
state machine, path identity, epochs, fragmentation, and retransmission.

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
owns current, obsolete-compatibility, historical, and caller-owned authorities;
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

Certificate identity, caveats, status, sunset, operational environments,
approved services, security-policy hash, and artifact hashes live in an
immutable generated manifest. Patched unvalidated artifacts use a separate
release identity and cannot reuse the validated claim. Guidance changes,
algorithm transitions, vulnerabilities, patches, certificate changes, and
environment additions require recorded impact, regression scope, and the
applicable CMVP revalidation path.
