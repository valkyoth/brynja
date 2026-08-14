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
and streaming APIs. Accelerated backends and final chain usability acceptance
remain assigned to v0.22.1-v0.22.3. SHA-224, SHA-384, and SHA-512 are absent.

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

## Cryptography Verification Status

The portable SHA-256 implementation is complete at v0.22.0, but the public
project capability table remains pending until the v0.22.3 chain acceptance.
No code in this crate has been independently reviewed. A component only moves
from ❌ to ✅ when a named independent reviewer signs off and linked evidence
identifies the reviewed implementation. Project tests, CI, Kani, Miri,
fuzzing, and pentesting do not by themselves constitute independent
verification.

| Algorithm | Implementation chain | Independently verified |
| --- | --- | --- |
| SHA-256 | 🟡 Portable implementation complete; acceptance pending v0.22.3 | ❌ Not verified |

This is an unkeyed hash. Digest equality is not MAC verification,
authentication, password hashing, or a signature check. Brynja makes no FIPS
140-3 validation claim.

See the [full project documentation](https://github.com/valkyoth/brynja),
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md),
and [verification inventory](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md).

Licensed under either Apache-2.0 or MIT, at your option.
