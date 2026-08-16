# Brynja 0.23.2 Release Notes

Status: implementation complete; exceptional pentest required; internal development tag; no crates.io publication

Brynja 0.23.2 completes the portable FIPS 180-4 SHA-2 family with distinct
SHA-512/224 and SHA-512/256 implementations. Both are directly usable through
`brynja-hash-sha2`, `brynja-crypto`, and the modern `brynja` facade.

## Added

- Distinct public `Sha512_224` and `Sha512_256` streaming states, one-shot
  functions, closed errors, exact 28-byte and 32-byte digest types, and common
  `Update` and `FixedOutput` trait implementations.
- The exact FIPS 180-4 SHA-512/t IV-generation procedure for the approved ASCII
  identities `SHA-512/224` and `SHA-512/256`.
- Normative initial-state constants bound to the public constructors and an
  executable check proving that the derivation procedure produces both exact
  constant sets.
- Exact reexports through the protocol-facing cryptographic composition crate
  and the main Brynja facade.

## Verification

- NIST CAVP empty, one-byte, 1,816-bit long-message, and Monte Carlo COUNT 0
  vectors for both named algorithms.
- The million-`a` results plus independently generated exact digests across
  111, 112, 127, 128, 129, 255, 256, and 257-byte boundaries.
- Every two-part split and every fixed chunk width for representative input,
  public trait use, exact maximum-length preflight, failure-atomic shared-state
  exhaustion, and consuming finalization.
- Negative identity tests proving that neither named algorithm equals the
  leftmost bytes of ordinary SHA-512.
- Reviewed-source hashes and adversarial fixtures covering normative IVs,
  derivation mask and labels, widths, claims, length domains, identity,
  evidence, dependency isolation, allocation, unsafe/native code, and file
  size.
- The complete promised Rust, target, dependency, package, documentation,
  dynamic-analysis, proof, and workspace gates.

## Security Boundaries

No unsafe Rust, foreign ABI, C or C++ code, assembly, external cryptographic
dependency, allocation, I/O, runtime detector, mutable global, provider effect,
or new accelerated backend is introduced.

SHA-512/224 and SHA-512/256 are unkeyed digests. They are not authentication,
MACs, password hashing, or signature checks. Their ordinary states do not
guarantee erasure of buffered input, chaining state, message schedules,
registers, caches, crash snapshots, or compiler-created copies. Future HMAC
and every other secret-bearing owner must add and verify hardened cleanup
internally; callers cannot erase private hash state.

No cryptographic code in this repository has been independently reviewed.
Brynja has no FIPS 140-3 validation, certificate, approved security policy, or
certificate-bound operational-environment claim. Implementing algorithms
specified by FIPS 180-4 is not FIPS 140-3 module validation.

## Release Process

Version 0.23.2 is an internal milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates.io packages. Adding two named
first-party cryptographic algorithms and their IV-derivation boundary triggers
an exceptional pentest before the tag. After the committed report and any
required remediation retest pass, the exact report commit must pass the full
local gate plus hosted GitHub and CodeQL checks before explicit tag
authorization.
