# Brynja 0.23.1 Release Notes

Status: exceptional pentest PASS; awaiting hosted GitHub and CodeQL; internal development tag; no crates.io publication

Brynja 0.23.1 adds complete portable SHA-384 and SHA-512 implementations beside
SHA-224 and SHA-256. Both are directly usable through `brynja-hash-sha2`,
`brynja-crypto`, and the modern `brynja` facade.

## Added

- One private, allocation-free, `no_std`, 80-round `u64` SHA-512-family
  compression owner with exact FIPS 180-4 round constants and wrapping
  arithmetic.
- One private shared 128-byte buffered state with transactional checked `u128`
  byte accounting, a 128-bit big-endian bit-length field, and exact
  111/112-byte final-padding behavior.
- Distinct public `Sha384` and `Sha512` streaming states, one-shot functions,
  closed errors, exact 48-byte and 64-byte digest types, and the common
  `Update` and `FixedOutput` traits.
- Exact reexports through the protocol-facing cryptographic composition crate
  and the main Brynja facade.
- Six cumulative Kani harnesses for SHA-224/SHA-256 and the shared
  SHA-384/SHA-512 checked message and padding domains.

## Verification

- NIST CAVP one-byte and Monte Carlo COUNT 0 vectors for SHA-384 and SHA-512.
- FIPS 180-4 empty, `abc`, long-message, and million-`a` examples.
- Independently generated exact digests across 111, 112, 127, 128, 129, 255,
  256, and 257-byte boundaries.
- Every two-part split and every fixed chunk width for representative input,
  public trait use, exact maximum-length preflight, failure-atomic overflow,
  and an explicit test proving SHA-384 is not truncated SHA-512.
- Reviewed-source hashes and adversarial fixtures covering constants, IVs,
  widths, length domains, padding, identity, evidence, dependency isolation,
  allocation, unsafe/native code, and file-size regressions.
- Hosted Miri and AddressSanitizer execution plus the complete promised Rust,
  target, dependency, package, documentation, and workspace gates.

## Security Boundaries

No unsafe Rust, foreign ABI, C or C++ code, assembly, external cryptographic
dependency, allocation, I/O, runtime detector, mutable global, provider effect,
or accelerated SHA-384/SHA-512 backend is introduced.

SHA-384 and SHA-512 are unkeyed digests. They are not authentication, MACs,
password hashing, or signature checks. Their ordinary states do not guarantee
erasure of buffered input, chaining state, message schedules, registers,
caches, crash snapshots, or compiler-created copies. Future HMAC and every
other secret-bearing owner must add and verify hardened cleanup internally;
callers cannot erase private hash state.

No cryptographic code in this repository has been independently reviewed.
Brynja has no FIPS 140-3 validation, certificate, approved security policy, or
certificate-bound operational-environment claim.

## Release Process

Version 0.23.1 is an internal milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates.io packages. Adding two new
first-party cryptographic algorithms and their compression foundation triggers
an exceptional pentest before the tag. After the committed report and any
required remediation retest pass, the exact report commit must pass the full
local gate plus hosted GitHub and CodeQL checks before explicit tag
authorization.

The repository-owner assessment of exact implementation candidate
`22c1dcdc7594a34bc14b53b42d1d56f7aa66047b` reported no finding and required
no remediation. The permanent report records `PASS`/`PASS` with zero open
findings. v0.23.1 now awaits green hosted GitHub and CodeQL before explicit tag
authorization.
