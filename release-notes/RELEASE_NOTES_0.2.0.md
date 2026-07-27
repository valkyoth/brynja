# Brynja 0.2.0 Release Notes

Status: pentest complete; awaiting green GitHub CI

Brynja 0.2.0 is a release-integrity and package-isolation milestone. It does
not implement TLS, cryptography, PKI, QUIC, DTLS, platform services, or legacy
protocols and must not be used to secure network traffic.

The release classifies all 24 workspace packages and freezes their exact
direct dependencies, optional features, publication classes, target kinds,
edition, MSRV, license, and source boundaries. Repository checks independently
validate no-default and all-feature resolved graphs. Negative fixtures reject
modern/legacy crossover, optional feature smuggling, repository and research
leaks, QUIC-to-stream-TLS coupling, incomplete version routing, publication
drift, external sources, non-exact pins, and package metadata drift.

Release readiness now accepts only a regular committed pentest report that is
updated with every later candidate change. Publication requires an annotated
signed tag pointing directly to the exact candidate commit with the canonical
`brynja vX.Y.Z` subject. Lightweight, unsigned, stale, indirectly targeted, or
misnamed tags fail closed.

GitHub `main` is protected by an active machine-checked ruleset matching the
`eth` model: signed linear history, review and CODEOWNER requirements, stale
review dismissal, last-push approval separation, CodeQL at all severities, and
deletion and non-fast-forward protection. Explicit owner and organization
administrator bypass identities preserve the accountable direct release
workflow.

The v0.2.0 pentest identified a no-default-feature Clippy coverage gap. The
repository gate now applies the same forbid-level lint enforcement to both
all-feature and no-default-feature configurations. The review also confirmed
the intentional panic policy: fallible untrusted-input paths must return typed
errors, while an otherwise unreachable release panic aborts as the final
fail-closed response. The repository owner explicitly accepted the current
solo-maintainer CODEOWNER and accountable direct-release bypass model.

Only `brynja 0.2.0` is selected for crates.io publication. All unchanged
modern support crates remain exact-pinned at their published `0.1.0` versions.
