# Brynja 0.1.0 Release Notes

Status: corrected crates.io publication candidate; not production ready

This foundation milestone establishes the dependency-free `no_std` workspace,
documentation, security policy, standards corpus workflow, platform matrix,
explicit `brynja-legacy-*` package naming, and separation between modern
and legacy protocol crates. It also establishes `brynja-tls` as an
evergreen router facade over the version-specific `brynja-tls12`,
`brynja-tls13`, and `brynja-tls13-handshake` boundaries. It does not implement
TLS and must not be used for network security.

The initial crates.io release publishes the eleven modern packages required by
the `brynja` facade, including its optional normal dependencies. The guarded
independent-crate release policy used by `eth` publishes dependencies in order
and `brynja` last. Every later official tag publishes a matching `brynja`
version while unchanged supporting crates are not republished. Legacy and
repository-only packages remain excluded.

The foundation pentest reported two low-severity hardening opportunities and
one medium release-integrity finding. Truncating-cast and sign-loss lints are
now non-overridable, CI verifies independently pinned SHA-256 hashes for its
security and SBOM tool archives, and the release policy no longer permits an
official tag that publishes no `brynja` facade. Retesting found no open
findings.

The release script validates policy with `--check`; `--package-check` validates
every selected package file set and creates every dependency-root archive
available before registry indexing. The interactive tag-bound crates.io
publisher creates and publishes downstream archives in dependency order only
after the complete release gate passes.
