# Supply-Chain Security

Status: policy

Brynja admits no third-party Cargo crates. `Cargo.lock`, Cargo metadata,
`cargo deny`, `cargo audit`, and the SBOM still run so a dependency cannot
enter unnoticed. Git and unknown registry sources are denied. GitHub Actions
are pinned to full commit SHAs and checked online before release.

The only admitted future external production dependency is conditional and
first-party: the separate downstream `brynja-sanitization` adapter may
exact-pin reviewed `sanitization 2.0.3` with default features disabled. Its
activated graph must contain no `zeroize`, derive, serde, subtle, or other
third-party crate, and no
Brynja facade, engine, default feature, or FIPS module may depend on it. Version,
source hash, feature, unsafe, advisory, license, MSRV, target, or guarantee drift
forces a new admission decision. Release-gate online checks also reject a newer
crates.io release or package-checksum drift. Failure removes or withholds the
adapter without changing Brynja's mandatory internal destruction path.

Official standards and vectors have reviewed source URLs and integrity hashes.
Local-only licensed documents are listed by provenance but ignored. Release
artifacts will be reproducibly packaged from a clean tree with checksums,
provenance, and exact commit identity.
