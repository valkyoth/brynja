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

## Cryptography Verification Status

No named independent reviewer has verified this component. Passing tests, CI,
Kani, Miri, fuzzing or a pentest is not independent cryptographic verification.

| Algorithm | Implemented | Independently verified |
| --- | --- | --- |
| SHA-1 | ✅ Fully implemented | ❌ Not independently verified |
| Opt-in hosted ordinary acceleration | 🚧 In progress; native observations passed, final release checks pending | ❌ Not independently verified |

## Hardware and SIMD

The default `RuntimeSha1Backend` remains observational: opportunistic calls use
portable SHA-1 and `required()` fails closed. The separate default-off
`runtime-execution` feature exposes `execution::select(Mode)` for ordinary
public data. Supported AArch64 system feature APIs can authorize the SHA1/NEON
route; generic x86 required mode fails, since current-core CPUID alone cannot
establish migration safety. Specialized x86 binaries use the leaf's explicit
static route. No feature report can be converted into an execution authority.
Operational native observations passed on Linux and macOS; other supported OS
lanes and final release checks are not qualified by those observations. See the
[operational API](https://github.com/valkyoth/brynja/blob/main/docs/legacy-sha1-execution.md)
for selection, streaming, byte/bit hashing and ownership examples.

## Use

This adapter is unpublished. For a local checkout:

```sh
cargo add brynja-legacy-sha1-std --path /path/to/brynja/crates/brynja-legacy-sha1-std
cargo add brynja-legacy-sha1 --path /path/to/brynja/crates/brynja-legacy-sha1
```

```rust
use brynja_legacy_sha1_std::RuntimeSha1Backend;
let selected = RuntimeSha1Backend::opportunistic();
let mut state = selected.start();
state.update(b"public legacy file bytes")?;
assert_eq!(selected.hash(b"public legacy file bytes")?, state.finalize());
assert!(RuntimeSha1Backend::required().is_err());
# Ok::<(), brynja_legacy_sha1::Sha1Error>(())
```

SHA-1 is unsuitable for new signatures, authentication or password hashing.
This adapter handles public data only; confidential legacy data requires the
leaf's portable hardened owner. No FIPS validation or accelerated cleanup claim.
MIT OR Apache-2.0; zero third-party dependencies.

See [SHA-1 acceleration](https://github.com/valkyoth/brynja/blob/main/docs/legacy-sha1-acceleration.md)
for evidence restrictions and the native capture procedure.
