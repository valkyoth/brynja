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
v0.22.0 implementation candidate provides complete portable SHA-256 one-shot
and streaming APIs. The optional `cpu` feature added at v0.22.1 and extended
with the unadmitted RV64 Zknh candidate at v0.22.2 accepts an
already tested `brynja-crypto-cpu` session without changing scalar ownership.
Its x86_64, AArch64, and RISC-V candidates remain unadmitted pending native
evidence. The v0.22.3 packaged downstream acceptance closes the complete
public SHA-256 chain. SHA-224, SHA-384, and SHA-512 are absent.

## Example

```rust
use brynja_hash_sha2::{Sha256, sha256};

let one_shot = sha256(b"abc")?;

let mut streaming = Sha256::new();
streaming.update(b"a")?;
streaming.update(b"bc")?;
assert_eq!(streaming.finalize(), one_shot);
# Ok::<(), brynja_hash_sha2::Sha256Error>(())
```

Callers with external file or stream metadata can preflight the checked FIPS
message-length domain without allocating or mutating the state:

```rust
use brynja_hash_sha2::Sha256;

let state = Sha256::new();
state.check_additional_bytes(4_294_967_296)?;
# Ok::<(), brynja_hash_sha2::Sha256Error>(())
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
The default feature set always remains portable scalar SHA-256.

Run the repository-owned downstream acceptance from a clean checkout with:

```bash
python3 scripts/check-sha256-public-api.py
```

It uses only ordinary public package APIs and repeats the run from assembled
Cargo package contents. It needs no network or private test hook.

## Cryptography Verification Status

The portable SHA-256 implementation and its public usability acceptance are
complete through v0.22.3. No code in this crate has been independently
reviewed. A component only moves
from ❌ to ✅ when a named independent reviewer signs off and linked evidence
identifies the reviewed implementation. Project tests, CI, Kani, Miri,
fuzzing, and pentesting do not by themselves constitute independent
verification.

| Algorithm | Implementation chain | Independently verified |
| --- | --- | --- |
| SHA-256 | ✅ Implemented | ❌ Not verified |

This is an unkeyed hash. Digest equality is not MAC verification,
authentication, password hashing, or a signature check. Brynja makes no FIPS
140-3 validation claim. Ordinary `Sha256` is intended for unkeyed hashing and
does not guarantee erasure of remnants when its input contains secrets. A
caller cannot erase the private working state, message schedule, or buffered
input itself. HMAC and every future secret-derived consumer must add hardened
secret ownership and emitted-code-verified cleanup before admission.

See the [full project documentation](https://github.com/valkyoth/brynja),
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md),
and [verification inventory](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md).

Licensed under either Apache-2.0 or MIT, at your option.
