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
