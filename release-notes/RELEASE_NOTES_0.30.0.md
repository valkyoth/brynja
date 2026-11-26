# v0.30.0 — Portable ChaCha20 (internal candidate)

The direct `brynja-crypto` crate now offers the RFC 8439 stream behind
`hazmat-chacha20`. It supports disjoint and in-place buffers, partial blocks
and checked exhaustion without allocation. It does not implement authenticated
encryption. No new runtime dependency, CPU feature or crates.io publication
is selected. See the [verification scope](../docs/assurance/chacha20-development.md).
