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


Optional hosted CPU detection for the isolated, collision-broken SHA-1 leaf.
# brynja-legacy-md5-std

Optional host observation for collision-broken legacy MD5. The leaf remains
allocation-free `no_std`; this adapter is never a modern-facade dependency.

No MD5 SIMD candidate is admitted. `opportunistic()` selects the portable leaf;
`required()` fails closed. CPU detection cannot establish migration-safe
execution authority, including in evidence builds. No global installation,
affinity changes or third-party dependency is introduced.

```rust
use brynja_legacy_md5::{BitString, Md5BatchControl};
use brynja_legacy_md5_std::RuntimeMd5Backend;
let selected = RuntimeMd5Backend::opportunistic();
let input = BitString::new(b"public legacy bytes", 8).map_err(|_| "bit input")?;
let mut output = [[0; 16]; 8];
let mut slots = [None; 8];
slots[0] = Some(input);
let report = selected.batch(&slots, &mut output, &mut Md5BatchControl::new(1))?;
assert_eq!(report.active_lanes, 1);
assert_eq!(report.vector_blocks, 0);
assert!(RuntimeMd5Backend::required().is_err());
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Cryptography Verification Status

No named independent reviewer has verified this component. Passing tests, CI,
Kani, Miri, fuzzing or a pentest is not independent cryptographic verification.

| Algorithm | Implementation | Independent verification |
| --- | --- | --- |
| MD5 | ✅ Fully implemented | ❌ Not independently verified |

MD5 is collision-broken. Do not use it for new authentication, signatures or
password hashing. Public data only; use the leaf's portable hardened batch
owner for confidential legacy compatibility. No FIPS validation or SIMD cleanup
claim. Rust 1.90.0–1.98.1; MIT OR Apache-2.0.

See [MD5 acceleration](https://github.com/valkyoth/brynja/blob/main/docs/legacy-md5-acceleration.md)
for the ownership contract and non-production evidence procedure.
