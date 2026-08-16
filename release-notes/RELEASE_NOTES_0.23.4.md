# Brynja 0.23.4 Release Notes

Status: final candidate; voluntary pentest PASS and local verification green;
hosted verification and internal tag pending; no crates.io publication

Brynja 0.23.4 closes the complete SHA-2 implementation chain with a
separately packaged downstream consumer that uses only documented public APIs.

## Added

- One standalone allocation-free `no_std` consumer covering SHA-224,
  SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256 through both the
  `brynja-hash-sha2` leaf and `brynja::crypto` facade.
- Independent expected digests for empty, text, binary, multi-block,
  million-byte, and file-like inputs, exercised through one-shot and irregular
  streaming use.
- Exact checks for each algorithm identity, digest width, deterministic
  message-length exhaustion, implementation status, and all five optional CPU
  candidate dispositions.
- Isolated offline assembly and execution of the complete 15-package archive
  closure with an empty Cargo home and version-only downstream dependencies.
- Adversarial fixtures that reject each corrupted expected digest, missing
  family APIs or documentation, wrong output widths, incomplete backend
  accounting, forbidden evidence features, and incomplete package contents.

## Verification

- The downstream fixture runs against repository sources and safely extracted
  `cargo package` archives.
- Rust 1.90.0 through 1.97.1 run the same public consumer.
- Every promised OS-less target checks the fixture's `no_std` library.
- Documentation examples and package contents are included in the ordinary
  repository gate.

## Security Boundaries

This milestone changes acceptance tooling, documentation, and the facade
version; it does not change SHA-2 compression, state, CPU kernels, backend
admission, or dependencies. All five accelerated candidates remain
unadmitted. Ordinary SHA-2 state is for unkeyed hashing and makes no secret
remanence, independent-review, or FIPS 140-3 validation claim.

## Release Process

Version 0.23.4 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates.io packages. It had no
scheduled pentest because it introduces no exceptional trigger, but the
repository owner voluntarily assessed exact signed implementation candidate
`7864a8f3a8766d16fc9bb2ea89893351f29aa842` and reported `PASS`/`PASS` with
zero open findings. The complete delta remains subject to the scheduled
backwards-looking v0.25.0 assessment. The full local gate is green; hosted
GitHub and CodeQL must be green before explicit tag authorization.
