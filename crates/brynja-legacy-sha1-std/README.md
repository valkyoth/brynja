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

# brynja-legacy-sha1-std

Optional hosted CPU detection for the isolated, collision-broken SHA-1 leaf.
This crate is not a default or modern-facade dependency. The leaf stays `no_std`.

No SHA-1 backend is admitted. Detection only reports possible hardware:
opportunistic calls use portable SHA-1; `required()` fails closed. A thread-local
feature check does not establish migration safety. This adapter deliberately
cannot turn a feature report into an instruction-execution capability, even in
evidence builds. Safe runtime acceleration awaits reviewed execution authority.

```rust
use brynja_legacy_sha1_std::RuntimeSha1Backend;
let selected = RuntimeSha1Backend::opportunistic();
let mut state = selected.start();
state.update(b"public legacy file bytes")?;
assert_eq!(selected.hash(b"public legacy file bytes")?, state.finalize());
assert!(RuntimeSha1Backend::required().is_err());
# Ok::<(), brynja_legacy_sha1::Sha1Error>(())
```

## Cryptography Verification Status

No named independent reviewer has verified this component. Passing tests, CI,
Kani, Miri, fuzzing or a pentest is not independent cryptographic verification.

| Algorithm | Implementation | Independent verification |
| --- | --- | --- |
| SHA-1 | In progress through v0.24.23 | ❌ Not independently verified |

SHA-1 is unsuitable for new signatures, authentication or password hashing.
This adapter handles public data only; confidential legacy data requires the
leaf's portable hardened owner. No FIPS validation or accelerated cleanup claim.
Rust 1.90.0–1.98.1; MIT OR Apache-2.0; zero third-party dependencies.

See [SHA-1 acceleration](https://github.com/valkyoth/brynja/blob/main/docs/legacy-sha1-acceleration.md)
for evidence restrictions and the native capture procedure.
