# Supply-Chain Security

Status: policy

Brynja admits no third-party Cargo crates. `Cargo.lock`, Cargo metadata,
`cargo deny`, `cargo audit`, and the SBOM still run so a dependency cannot
enter unnoticed. Git and unknown registry sources are denied. GitHub Actions
are pinned to full commit SHAs and checked online before release.

The only planned external production dependency is conditional and first-party:
after the v0.11.1 admission review, the separate downstream
`brynja-sanitization` adapter may exact-pin the approved stable
`sanitization` release with default features disabled. Its activated graph must
contain no `zeroize`, derive, serde, subtle, or other third-party crate, and no
Brynja facade, engine, default feature, or FIPS module may depend on it. Version,
source hash, feature, unsafe, advisory, license, MSRV, target, or guarantee drift
forces a new admission decision; failure removes or withholds the adapter
without changing Brynja's mandatory internal destruction path.

Official standards and vectors have reviewed source URLs and integrity hashes.
Local-only licensed documents are listed by provenance but ignored. Release
artifacts will be reproducibly packaged from a clean tree with checksums,
provenance, and exact commit identity.
