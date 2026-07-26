# Brynja 0.1.0 Release Notes

Status: pentest passed; awaiting green GitHub CI; not released

This foundation milestone establishes the dependency-free `no_std` workspace,
documentation, security policy, standards corpus workflow, platform matrix,
explicit `brynja-legacy-*` package naming, and separation between modern
and legacy protocol crates. It also establishes `brynja-tls` as an
evergreen router facade over the version-specific `brynja-tls12`,
`brynja-tls13`, and `brynja-tls13-handshake` boundaries. It does not implement
TLS and must not be used for network security.

The foundation also installs the guarded independent-crate release policy used
by `eth`: every admitted modern release publishes `brynja` at the tag version,
changed supporting crates publish first on their own SemVer lines, and
unchanged supporting crates are not republished. Repository-only packages are
mechanically excluded, and actual publication requires the matching tag at
`HEAD` plus the complete release gate.

The foundation pentest reported two low-severity hardening opportunities.
Truncating-cast and sign-loss lints are now non-overridable, and CI downloads
each exact security and SBOM tool archive, verifies its independently pinned
SHA-256 hash, and installs from the verified source archive and packaged
lockfile. Retesting found no open findings.

Release remains blocked on green GitHub checks and explicit tag authorization
described in `docs/RELEASE_PLAN.md`.
