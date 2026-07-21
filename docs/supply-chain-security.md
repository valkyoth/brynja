# Supply-Chain Security

Status: policy

Brynja admits no third-party Cargo crates. `Cargo.lock`, Cargo metadata,
`cargo deny`, `cargo audit`, and the SBOM still run so a dependency cannot
enter unnoticed. Git and unknown registry sources are denied. GitHub Actions
are pinned to full commit SHAs and checked online before release.

Official standards and vectors have reviewed source URLs and integrity hashes.
Local-only licensed documents are listed by provenance but ignored. Release
artifacts will be reproducibly packaged from a clean tree with checksums,
provenance, and exact commit identity.

