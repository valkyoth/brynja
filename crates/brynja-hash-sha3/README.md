<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja">Crates.io</a>
  |
  <a href="https://docs.rs/brynja">Docs.rs</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md">Release Plan</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md">Threat Model</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/brynja">
    <img src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja security-first Rust cryptography and secure protocols overview">
  </a>
</p>

# brynja-hash-sha3

First-party, allocation-free `no_std` SHA-3 and SHAKE family ownership for
Brynja. Version 0.1.0 now provides all six complete portable FIPS 202 functions
through distinct fixed-output SHA-3 and extendable-output SHAKE APIs over one
private Keccak-f[1600] permutation. The complete leaf and facade API now pass
frozen package-external portable acceptance. Hardware acceleration, final
cross-backend acceptance, independent review, and FIPS 140-3 validation remain
later work.

```rust
use brynja_hash_sha3::{Sha3_256, sha3_256};

let one_shot = sha3_256(b"abc").unwrap();
let mut streaming = Sha3_256::new();
streaming.update(b"a").unwrap();
streaming.update(b"bc").unwrap();
assert_eq!(streaming.finalize(), one_shot);

let mut xof = [0_u8; 64];
brynja_hash_sha3::shake256(b"abc", &mut xof).unwrap();
assert_eq!(xof.len(), 64);
```

These APIs are unkeyed hashes, not authentication, MACs, password hashing, or
raw Keccak. Ordinary states do not promise erasure of input remnants or
private working state; later keyed constructions require hardened ownership.

The exceptional v0.24.0 assessment found one High tracked-build-artifact issue
in the repository differential harness, not an algorithm error. All generated
artifacts were removed, the harness now builds in a fresh isolated target, and
independent remediation retest passed with zero open findings. This remains
pentest evidence rather than independent cryptographic verification.

## Cryptography Verification Status

| Hash | Implemented | Independently verified |
| --- | --- | --- |
| SHA3-224 | ✅ Implemented | ❌ Not independently verified |
| SHA3-256 | ✅ Implemented | ❌ Not independently verified |
| SHA3-384 | ✅ Implemented | ❌ Not independently verified |
| SHA3-512 | ✅ Implemented | ❌ Not independently verified |
| SHAKE128 | ✅ Implemented | ❌ Not independently verified |
| SHAKE256 | ✅ Implemented | ❌ Not independently verified |
| Complete SHA-3/SHAKE family | 🚧 In progress | ❌ Not independently verified |

Only a named independent reviewer and linked review evidence can change the
independent status. Project tests, CI, Kani, Miri, fuzzing, and pentests do not
by themselves constitute independent cryptographic verification.

The project-wide first-party-Rust, no-third-party-crates, `no_std`, 500-line
source-file, portability, and modern/legacy isolation policies apply here.
