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

# brynja-hash-sha2

The separate general SHA-512/t extension is **In progress**: v0.24.27 adds
expanded [lifecycle evidence](https://github.com/valkyoth/brynja/blob/main/docs/sha512-t-lifecycle.md)
over the unchanged v0.24.26 implementation of
ordinary/hardened incremental and one-shot byte/bit hashing for all 510 valid t,
behind the default-off `general-sha512-t` leaf feature. It follows
its [authority and public API contract](https://github.com/valkyoth/brynja/blob/main/docs/sha512-t-contract.md).
Typed secret output clears on Drop or explicit consuming declassification;
every secret-output error clears the entire destination. Expanded lifecycle
evidence is in v0.24.27; package and family closure remain v0.24.28–v0.24.29. The six named SHA-2
identities below remain unchanged.

```rust
use brynja_hash_sha2::{Sha512TBits, Sha512TDigest};
let parameter = Sha512TBits::new(9)?;
let mut label = [0; 11];
let length = parameter.write_iv_label(&mut label)?;
assert_eq!(&label[..length], b"SHA-512/9");
// Import an already PUBLIC digest from another implementation, not a message.
let digest = Sha512TDigest::from_bytes(parameter, &[0xab, 0x80])?;
assert_eq!(digest.parameter().bits(), 9);
# Ok::<(), brynja_hash_sha2::Sha512TError>(())
```

Enable `features = ["general-sha512-t"]` for this example. Value import and IV
diagnostics are not authentication, message hashing, FIPS approval or secret
ownership. Public values are copyable and are not zeroized. Equality includes t
but is not constant-time verification. General and named digest types remain
distinct; short t values have weak collision/preimage security bounds.

```rust
use brynja_hash_sha2::{Sha512TBits, sha512_t, hardened_sha512_t_secret,
    PublicDeclassification};
let parameter = Sha512TBits::new(9)?;
let ordinary = sha512_t(parameter, b"abc")?; // Public input only.
let mut destination = [0; 2]; // Exactly ceil(t / 8) bytes.
let secret = hardened_sha512_t_secret(parameter, b"abc", &mut destination)?;
let public = secret.declassify(PublicDeclassification::acknowledge())?;
assert_eq!(public, ordinary);
assert_eq!(destination, [0; 2]);
# Ok::<(), brynja_hash_sha2::Sha512TError>(())
```

For confidential input use `HardenedSha512T` or the hardened one-shot APIs,
never ordinary `Sha512T` or `Sha512TDigest::from_bytes`. Secret processing does
not stage through a public digest; only explicit declassification creates one.
Borrowing secret bytes does not make copies public or erase caller-owned inputs.
Mandatory clearing covers the existing eight SHA-2 owner regions, including
schedule, buffered input and staging; it does not promise erasure of registers,
compiler copies/spills, caches, dumps, swap, aborts or caller-created copies.

`PublicDeclassification::acknowledge()` is available to any caller: it records
intent in code, not runtime authorization or access control. Applications own
disclosure policy, auditing and the handling of explicitly borrowed secret bytes.
For untrusted streams, also enforce total input limits, time budgets and rate
limits at ingestion; the hash's mathematical length limit is not a DoS budget.

First-party, allocation-free `no_std` SHA-2 implementations for Brynja. The
crate provides correct portable byte-oriented one-shot and streaming APIs for
all six FIPS 180-4 SHA-2 algorithms. The optional `cpu` feature added at v0.22.1 and extended
with the unadmitted RV64 Zknh candidate at v0.22.2 accepts an
already tested `brynja-crypto-cpu` session without changing scalar ownership.
Its x86_64, AArch64, and RISC-V candidates remain unadmitted pending native
evidence. The v0.22.3 packaged downstream acceptance closes the complete
public SHA-256 chain. v0.23.0 adds complete portable SHA-224, v0.23.1 adds
complete portable SHA-384 and SHA-512, and v0.23.2 completes SHA-512/224 and
SHA-512/256 with exact FIPS SHA-512/t IV derivation.
v0.23.3 extends the forced backend API to SHA-224 and all four SHA-512-family
identities. AArch64 SHA-512 and RV64 Zknh SHA-512 candidates remain
unadmitted; x86_64 SHA-512 remains an explicit scalar-only decision. v0.23.4
closes byte-oriented family usability with source and separately packaged
downstream acceptance through only documented public APIs. v0.24.7 adds the
complete FIPS 180-4 arbitrary-bit input domain to all six identities through
canonical one-shot and consuming incremental final-tail APIs. The wider family
is **Fully implemented** after the combined downstream acceptance at v0.24.11.
v0.24.8 adds distinct hardened states for all six identities, complete
source-declared internal sanitization, explicit public declassification, and
typed secret output.

## Example

```rust
use brynja_hash_sha2::{
    BitString, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
    sha224, sha256, sha256_bits, sha384, sha512, sha512_224, sha512_256,
};

let sha224_one_shot = sha224(b"abc").unwrap();
let one_shot = sha256(b"abc").unwrap();
let sha384_one_shot = sha384(b"abc").unwrap();
let sha512_one_shot = sha512(b"abc").unwrap();
let sha512_224_one_shot = sha512_224(b"abc").unwrap();
let sha512_256_one_shot = sha512_256(b"abc").unwrap();

let mut sha224_streaming = Sha224::new();
sha224_streaming.update(b"a").unwrap();
sha224_streaming.update(b"bc").unwrap();
assert_eq!(sha224_streaming.finalize(), sha224_one_shot);

let mut streaming = Sha256::new();
streaming.update(b"a").unwrap();
streaming.update(b"bc").unwrap();
assert_eq!(streaming.finalize(), one_shot);

let mut sha384_streaming = Sha384::new();
sha384_streaming.update(b"abc").unwrap();
assert_eq!(sha384_streaming.finalize(), sha384_one_shot);

let mut sha512_streaming = Sha512::new();
sha512_streaming.update(b"abc").unwrap();
assert_eq!(sha512_streaming.finalize(), sha512_one_shot);

let mut sha512_224_streaming = Sha512_224::new();
sha512_224_streaming.update(b"abc").unwrap();
assert_eq!(sha512_224_streaming.finalize(), sha512_224_one_shot);

let mut sha512_256_streaming = Sha512_256::new();
sha512_256_streaming.update(b"abc").unwrap();
assert_eq!(sha512_256_streaming.finalize(), sha512_256_one_shot);

// Canonical arbitrary-bit inputs use the high bits of their final byte.
let three_bits = BitString::new(&[0b0110_0000], 3).unwrap();
let bit_digest = sha256_bits(three_bits).unwrap();
assert_eq!(&bit_digest.as_bytes()[..4], &[0x1f, 0x77, 0x94, 0xd4]);
```

Incremental callers absorb any complete-byte prefix with `update`, then pass
one canonical final byte or byte-aligned suffix to the consuming
`finalize_bits` method. Consuming the state makes repeated tails and absorption
after a partial tail unrepresentable in safe Rust.

Secret-bearing callers use a distinct hardened state rather than an ordinary
state:

```rust
use brynja_hash_sha2::{HardenedSha256, PublicDeclassification};

let mut state = HardenedSha256::new();
state.update(b"secret-derived input").unwrap();
let mut digest = [0_u8; 32];
state
    .finalize_public(&mut digest, PublicDeclassification::acknowledge())
    .unwrap();
```

`finalize_secret` instead returns a typed `OwnedSecretRegion` over the caller's
destination, which is cleared when dropped. Hardened states are sealed,
non-cloneable, non-formattable, non-resettable, and portable-only. They clear
every Brynja-owned source-declared state and scratch region on normal exits,
errors, `Drop`, and recoverable unwinding. The exact claim excludes registers,
caches, compiler-created copies, dumps, `mem::forget`, abort, forced
termination, suspend images, power loss, and physical-memory attacks.

Callers with external file or stream metadata can preflight the checked FIPS
message-length domain without allocating or mutating the state:

```rust
use brynja_hash_sha2::Sha256;

let state = Sha256::new();
state.check_additional_bytes(4_294_967_296).unwrap();
```

Static `no_std` callers may explicitly request a compile-time-proven backend:

```rust
# #[cfg(feature = "cpu")]
# {
use brynja_hash_sha2::{Sha256BackendSession, sha256_with_backend};

if let Some(backend) = Sha256BackendSession::for_compiled_target() {
    let digest = sha256_with_backend(b"abc", &backend)?;
    assert_eq!(digest.as_bytes().len(), 32);
}
# }
# Ok::<(), brynja_hash_sha2::Sha256AcceleratedError>(())
```

Until native admission evidence is accepted, the constructor returns `None`.
The default feature set always remains portable scalar SHA-2. The same static
session model is available as `Sha512BackendSession` for SHA-384, SHA-512,
SHA-512/224, and SHA-512/256 on exact qualifying targets.

Run the repository-owned downstream acceptance from a clean checkout with:

```bash
python3 scripts/sha2/check-sha2-public-api.py
```

It uses only ordinary public package APIs and repeats the run from assembled
Cargo package contents. It needs no network or private test hook.

## Cryptography Verification Status

All six portable FIPS 180-4 SHA-2 algorithms are implemented through v0.23.2,
and v0.23.3 adds complete forced candidate APIs while keeping every backend
unadmitted pending native evidence. v0.23.4 completes packaged downstream
byte-oriented family acceptance. v0.24.7 completes the canonical arbitrary-bit
input APIs, and v0.24.8 completes all six hardened secret-bearing state APIs.
Final combined acceptance passes at v0.24.11, so the expanded family is fully
implemented. Independent cryptographic review and FIPS validation remain absent.
No code in this crate has been independently reviewed. A component only moves
from ❌ to ✅ when a named independent reviewer signs off and linked evidence
identifies the reviewed implementation. Project tests, CI, Kani, Miri,
fuzzing, and pentesting do not by themselves constitute independent
verification.

| Algorithm | Implementation chain | Independently verified |
| --- | --- | --- |
| SHA-2 (all six identities, ordinary and hardened byte and arbitrary-bit APIs) | ✅ Fully implemented | ❌ Not independently verified |

These are unkeyed hashes. Digest equality is not MAC verification,
authentication, password hashing, or a signature check. Brynja makes no FIPS
140-3 validation claim. Ordinary SHA-2 states are intended for unkeyed hashing
and do not guarantee erasure of remnants when their input contains secrets. A
caller cannot erase private working state, schedules, or buffered input. The
distinct hardened profiles use Brynja's admitted sanitization mechanism for
every owned chaining state, partial buffer, schedule, block copy, temporary,
and terminal path; HMAC and every future secret-derived consumer must use
those owners.

See the [full project documentation](https://github.com/valkyoth/brynja),
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md),
and [verification inventory](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md).

Licensed under either Apache-2.0 or MIT, at your option.
