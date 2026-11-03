# v0.26.1 — HKDF public API usability acceptance

Internal development milestone; no crates.io publication is selected.

## Changes

- Modern and isolated legacy HKDF support allocation-free multipart info with
  `expand_parts`. Parts are concatenated without implicit framing; existing
  `expand` remains compatible.
- Separate no_std public consumers exercise RFC vectors, TLS/QUIC label
  vectors, bounds, multipart behavior and ownership contracts against packaged
  crates. Compiler-negative probes check the intended diagnostic.
- Packaging isolates Cargo configuration, compares archived inputs with their
  sources and requires both license texts and a README. The legacy HKDF crate
  now includes those documents.
- TLS-label Debug output exposes lengths rather than label/context contents.

See [public API assurance](../docs/assurance/hkdf-public-api.md) for the detailed
remediation and test history, and the [owner-supplied retest](../security/pentest/v0.26.1.md)
for the reviewed scope and exclusions. Historical/local observations are not
independent certification. Compiler/side-channel qualification remains separate.

## Release workflow

The finite candidate gate covers targeted HKDF tests, lint/format, integration,
registry and release regressions, package consumers at the MSRV/current
endpoints, SBOM and dependency checks. It does not implicitly repeat the full
compiler, Miri, ASan, proof or timing campaigns.

The committed candidate must pass the finite gate and exact-commit GitHub/CodeQL
checks before separately authorized tagging. No tag or publication is implied
by these notes. Full TLS key-schedule work remains at its planned milestone.
