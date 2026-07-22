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
Observation cannot block or alter cryptographic state.

The stable effect surface is explicitly versioned as EngineV1, EventV1, and
ActionV1. Mandatory effects are exhaustive and cannot be ignored through a
wildcard arm or generic success path. Adding a mandatory effect creates V2
interfaces and requires a major SemVer release; V1 does not change underneath
applications. Only bounded, secret-free, observational SecurityEvent values may
be non-exhaustive, and unknown informational values cannot affect engine state.

The FIPS architecture freezes its boundary, dependency allowlist, services,
ports, SSP design, and operational-environment model before implementation; it
does not claim an exact artifact identity at that point. Only after the DRBG,
provider, indicators, SSP services, algorithms, and linked self-tests are final
and module-specific security events are integrated does the artifact freeze its
source, symbols, exact dependency closure, features, dispatch tables, build
inputs, tool configuration, and binary hashes.
HPKE, ECH, certificate compression, and every later optional module remain
downstream of provider ports and cannot alter that artifact. Any such change
starts a new validation and artifact line.
