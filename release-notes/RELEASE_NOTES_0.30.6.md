# v0.30.6 — standalone cipher package publication acceptance (in preparation)

This checkpoint prepares the cumulative package split since the public v0.25.3
baseline. It adds no cipher or hardware backend. The root and facade READMEs
now list the owning crate, available import routes, and independent-review
status separately. Start with the [capability tables](../README.md#cryptography-verification-status)
when choosing between a raw primitive and authenticated encryption.

## Packaging progress

An offline Cargo packaging preview on Rust 1.100.0 assembled the 29 local
packages in the normal/build dependency closure (including optional edges) of
`brynja`, `brynja-crypto-cpu-std`, and `brynja-legacy-hkdf`. The five new
archives (ChaCha20, AES, GHASH, AES-GCM/GMAC and legacy HKDF) each contained
the README and both licenses, byte-identical to their source files. This used
the current development versions and Cargo's package staging area, not the
live registry. The staging closure is **not** the list of packages to upload.

Before publication:

- Freeze fresh versions for changed published packages and resolve the exact
  dependency pins in dependency-first order. The current development versions
  of `brynja-crypto` and the CPU crates must not be republished unchanged.
- Run clean registry-style consumer acceptance against the frozen archives
  without workspace path overrides: direct leaf and supported facade imports,
  type identity, feature isolation, exact resolved versions and `no_std` on
  Rust 1.90.0 and 1.100.0.
- Confirm the new package names and owners on crates.io, and the exact indexed
  versions before uploading dependents. Use the existing pentest, final gate,
  and green GitHub/CodeQL handoff. No upload or tag is authorized by this preview.
