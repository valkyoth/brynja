# Supply-Chain Security

Status: policy

Brynja's core workspace and every facade, engine, cryptographic package,
legacy package, default feature, bare-metal graph, and FIPS module reject every
unreviewed external Cargo crate. `Cargo.lock`, Cargo metadata, `cargo deny`,
`cargo audit`, and the SBOM still run so a dependency cannot enter unnoticed.
Git and unknown registry sources are denied. GitHub Actions are pinned to full
commit SHAs and checked online before release.

Every Brynja cryptographic implementation is first-party Rust. Native source,
objects, archives, shared libraries, package build scripts, build dependencies,
Cargo native-link metadata, foreign ABIs, external assembly files, and foreign
software cryptographic providers are forbidden. The exact policy and machine
checks live in `first-party-rust-cryptography.md`.

The only admitted external production dependency is first-party: the separate
downstream `brynja-sanitization` adapter exact-pins reviewed
`sanitization 2.0.4` with default features disabled. Its
activated graph must contain no `zeroize`, derive, serde, subtle, or other
third-party crate, and no
Brynja facade, engine, default feature, or FIPS module may depend on it. Version,
source hash, feature, unsafe, advisory, license, MSRV, target, or guarantee drift
forces a new admission decision. Release-gate online checks also reject a newer
crates.io release or package-checksum drift. Failure removes or withholds the
adapter without changing Brynja's mandatory internal destruction path.

Version 0.47.1 may admit the latest stable first-party `base64-ng` family only
as an encoding dependency for bounded Base64, PEM, and OpenPGP armor. Admission
requires an exact pin, default features disabled, `no_std`, no allocator in the
reachable protocol path, no unsafe or native code, no build script, no
transitive package, and complete MSRV, target, advisory, license, source-hash,
streaming and canonical-decoding evidence. `base64-ng-openpgp` is rejected if
it cannot provide that allocation-free caller-buffer profile; Brynja then owns
the protocol framing and reuses only `base64-ng` transforms. This exception
never implements cryptography or enters `brynja-fips-module`.

Future separately locked `brynja-rustls` and `brynja-tokio` companion adapter
workspaces may depend only on the exact pure-Rust ecosystem API they implement.
They are not members or dependencies of the core workspace. Each owns a
minimal feature allowlist, lockfile, package policy, SBOM, advisory and
freshness checks, and native-code closure gate. `brynja-rustls` must disable
rustls default providers and reject AWS-LC, ring, rustls's `fips` feature, and
every fallback provider. `brynja-tokio` may use Tokio I/O interfaces but not a
second TLS or cryptographic implementation. These narrow integration
exceptions never weaken the first-party Rust cryptography golden rule.

Official standards and vectors have reviewed source URLs and integrity hashes.
Local-only licensed documents are listed by provenance but ignored. Release
artifacts will be reproducibly packaged from a clean tree with checksums,
provenance, and exact commit identity.
