# Brynja 0.23.0 Release Notes

Status: implementation candidate; exceptional pentest required; internal development tag; no crates.io publication

Brynja 0.23.0 adds a complete portable SHA-224 implementation beside the
accepted SHA-256 implementation. It is directly usable through
`brynja-hash-sha2`, `brynja-crypto`, and the modern `brynja` facade.

## Added

- A distinct allocation-free `no_std` `Sha224` streaming state with the exact
  FIPS 180-4 initial value, checked byte-length domain, transactional updates,
  consuming finalization, and 28-byte digest.
- The public `sha224` one-shot function, `Sha224Digest`, `Sha224Error`, and the
  existing algorithm-independent `Update` and `FixedOutput` trait surface.
- Exact SHA-224 reexports and authoritative real-use tests through the leaf,
  cryptographic-composition, and main facade packages.
- NIST CAVP short-message and Monte Carlo evidence, FIPS long and million-byte
  examples, critical padding-boundary vectors, every two-part split, every
  fixed chunk width for representative input, and a failure-atomic exhaustion
  regression.
- Four local Kani harnesses covering the complete SHA-224 and SHA-256 checked
  byte domains and exact one-block/two-block padding decisions.
- SHA-224 execution under the pinned Miri and AddressSanitizer gates, the full
  Rust 1.90.0-through-1.97.1 matrix, and promised hosted and bare-metal builds.
- Adversarial source policy that rejects IV, output-width, length, padding,
  identity, implementation-claim, evidence, dependency, allocation, unsafe,
  native-code, and reviewed-source regressions.

## Security Boundaries

SHA-224 is not truncated SHA-256: it uses its own normative initial value and
algorithm identity. The implementation contains no new unsafe block, foreign
ABI, C code, assembly, dependency, allocation, I/O, mutable global, runtime
detector, or provider effect.

SHA-224 is an unkeyed digest, not authentication, a MAC, a password hash, or a
signature check. Ordinary `Sha224` does not guarantee erasure of buffered
secret input, chaining state, message schedules, CPU registers, caches, or
compiler-created copies. A caller cannot erase private internal state. HMAC or
another secret-bearing construction must own and verify hardened cleanup before
it may consume this implementation.

No cryptographic code in this repository has been independently reviewed.
Brynja has no FIPS 140-3 validation, certificate, approved security policy, or
certificate-bound operational-environment claim.

## Roadmap Adjustment

The former oversized v0.23.0 complete-family stop is now five reviewable tags:

- v0.23.0 completes portable SHA-224;
- v0.23.1 completes portable SHA-384 and SHA-512;
- v0.23.2 completes SHA-512/224 and SHA-512/256, including SHA-512/t IV
  derivation;
- v0.23.3 covers complete-family CPU acceleration; and
- v0.23.4 closes package-external public usability acceptance.

Each implementation stop must finish directly usable named algorithms; no
partial algorithm is presented as implemented.

## Release Process

Version 0.23.0 is an internal milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates.io packages. Adding a new
first-party cryptographic algorithm triggers an exceptional pentest before the
tag. After the committed report and remediation retest pass, the exact report
commit must pass the complete local gate plus hosted GitHub and CodeQL checks
before explicit tag authorization.
