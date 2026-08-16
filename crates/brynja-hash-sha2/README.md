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

First-party, allocation-free `no_std` SHA-2 implementations for Brynja. The
crate provides all six complete portable FIPS 180-4 SHA-2 algorithms through
one-shot and streaming APIs. The optional `cpu` feature added at v0.22.1 and extended
with the unadmitted RV64 Zknh candidate at v0.22.2 accepts an
already tested `brynja-crypto-cpu` session without changing scalar ownership.
Its x86_64, AArch64, and RISC-V candidates remain unadmitted pending native
evidence. The v0.22.3 packaged downstream acceptance closes the complete
public SHA-256 chain. v0.23.0 adds complete portable SHA-224, v0.23.1 adds
complete portable SHA-384 and SHA-512, and v0.23.2 completes SHA-512/224 and
SHA-512/256 with exact FIPS SHA-512/t IV derivation.
v0.23.3 extends the forced backend API to SHA-224 and all four SHA-512-family
identities. AArch64 SHA-512 and RV64 Zknh SHA-512 candidates remain
unadmitted; x86_64 SHA-512 remains an explicit scalar-only decision.

## Example

```rust
use brynja_hash_sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
    sha224, sha256, sha384, sha512, sha512_224, sha512_256,
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
```

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
python3 scripts/check-sha256-public-api.py
```

It uses only ordinary public package APIs and repeats the run from assembled
Cargo package contents. It needs no network or private test hook.

## Cryptography Verification Status

The complete portable FIPS 180-4 SHA-2 family is implemented through v0.23.2,
and v0.23.3 adds complete forced candidate APIs while keeping every backend
unadmitted pending native evidence. Packaged downstream family acceptance
remains v0.23.4. No code in this crate has been independently reviewed. A component only moves
from ❌ to ✅ when a named independent reviewer signs off and linked evidence
identifies the reviewed implementation. Project tests, CI, Kani, Miri,
fuzzing, and pentesting do not by themselves constitute independent
verification.

| Algorithm | Implementation chain | Independently verified |
| --- | --- | --- |
| SHA-2 (FIPS 180-4: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256) | ✅ Fully implemented | ❌ Not verified |

These are unkeyed hashes. Digest equality is not MAC verification,
authentication, password hashing, or a signature check. Brynja makes no FIPS
140-3 validation claim. Ordinary SHA-2 states are intended for
unkeyed hashing and do not guarantee erasure of remnants when their input
contains secrets. A
caller cannot erase the private working state, message schedule, or buffered
input itself. HMAC and every future secret-derived consumer must add hardened
secret ownership and emitted-code-verified cleanup before admission.

See the [full project documentation](https://github.com/valkyoth/brynja),
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md),
and [verification inventory](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md).

Licensed under either Apache-2.0 or MIT, at your option.
