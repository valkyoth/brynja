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
Brynja. Version 0.1.0 provides correct portable byte-oriented and canonical
arbitrary-bit implementations of all six FIPS 202 functions through distinct
fixed-output SHA-3 and extendable-output SHAKE APIs over one private
Keccak-f[1600] permutation. SHAKE also supports standards-valid output lengths
that do not end on a byte boundary. Version 0.24.10 of the repository also
adds distinct hardened states for secret-derived inputs and outputs with
compiler-resistant cleanup of all source-declared owned regions. Final combined
package-external acceptance, independent review, and FIPS 140-3 validation
are closed by the combined v0.24.11 acceptance. Repository milestone v0.24.12
adds the complete SP 800-185 encoding foundation plus cSHAKE128 and cSHAKE256
with byte and arbitrary-bit function names, customization, messages and output;
repository milestone v0.24.13 builds all four KMAC/KMACXOF constructions over
the hardened cSHAKE owner in the separate `brynja-mac-kmac` leaf. The wider
SP 800-185 family remains in progress through v0.24.17.

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

// FIPS 202 bit strings store valid tail bits at the low end of the byte.
let bits = brynja_hash_sha3::Fips202BitString::new(&[0b0001_0011], 5).unwrap();
let bit_digest = brynja_hash_sha3::sha3_256_bits(bits).unwrap();
assert_eq!(bit_digest.as_bytes().len(), 32);

// Request exactly 100 bits of SHAKE output: 12 bytes plus 4 low bits.
let mut output = [0xff_u8; 13];
let destination = brynja_hash_sha3::Fips202Output::new(&mut output, 4).unwrap();
brynja_hash_sha3::shake128_bits(bits, destination).unwrap();
assert_eq!(output[12] & 0xf0, 0);

let mut customized = [0_u8; 32];
brynja_hash_sha3::cshake128(
    &[0, 1, 2, 3],
    b"",
    b"Email Signature",
    &mut customized,
).unwrap();
assert_eq!(&customized[..4], &[0xc1, 0xc3, 0x69, 0x25]);
```

These APIs are unkeyed hashes, not authentication, MACs, password hashing, or
raw Keccak. Ordinary states do not promise erasure of input remnants or
private working state. This also applies to ordinary cSHAKE. Secret-derived
uses must select the distinct `HardenedSha3_*`, `HardenedShake*`, or
`HardenedCshake*` states, explicitly declassify public
output or retain typed secret output, and let the owner clear Brynja-owned
lanes, buffers, counters, suffix/padding/squeeze staging, and permutation
scratch on every terminal path. Scalar fixed-count lane/counter conversion and
registered partial-output staging avoid source-created secret byte arrays
outside that owner. Callers remain responsible for buffers and copies they
own.

```rust
use brynja_hash_sha3::{HardenedSha3_256, Sha3PublicDeclassification};

let mut state = HardenedSha3_256::new();
state.update(b"secret-derived input").unwrap();
let mut digest = [0_u8; 32];
state
    .finalize_public(&mut digest, Sha3PublicDeclassification::acknowledge())
    .unwrap();
```

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
| Arbitrary-bit FIPS 202 messages and SHAKE output | ✅ Implemented | ❌ Not independently verified |
| Hardened SHA-3/SHAKE secret-bearing states | ✅ Implemented | ❌ Not independently verified |
| Complete SHA-3/SHAKE family, including final combined acceptance | ✅ Fully implemented | ❌ Not independently verified |
| SP 800-185 encodings (`left_encode`, `right_encode`, `encode_string`, `bytepad`) | ✅ Implemented | ❌ Not independently verified |
| cSHAKE128 and cSHAKE256 | ✅ Implemented | ❌ Not independently verified |
| Complete SP 800-185 family | 🚧 In progress — cSHAKE and KMAC complete; TupleHash and ParallelHash pending | ❌ Not independently verified |

Only a named independent reviewer and linked review evidence can change the
independent status. Project tests, CI, Kani, Miri, fuzzing, and pentests do not
by themselves constitute independent cryptographic verification.

The project-wide first-party-Rust, no-third-party-crates, `no_std`, 500-line
source-file, portability, and modern/legacy isolation policies apply here.
