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

# brynja-crypto-cpu-std

Optional hosted feature observation and CPU authority for Brynja.
This adapter uses `std`; portable algorithm leaves remain `no_std`.
It is not automatically installed or added to facade/default graphs.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Historical SHA-2 host observation and portable fallback | ✅ Implemented; candidate routes unadmitted | ❌ No |
| Explicit hosted raw execution | ✅ Opt-in, qualifying AArch64 only | ❌ No |
| Ordinary SHA-3/SHAKE/cSHAKE sponge adapters | ✅ Opt-in, public data only | ❌ No |

No named independent cryptographic review or FIPS 140-3 validation is claimed.

## Use

The explicit execution APIs require the unpublished checkout:

```sh
cargo add brynja-crypto-cpu-std --path /path/to/brynja/crates/brynja-crypto-cpu-std --no-default-features --features runtime-execution
```

```rust
use brynja_crypto_cpu_std::execution::{Authority, Kernel, Mode, Route};
let owner = Authority::new(Kernel::ArmSha256, Mode::Portable).unwrap();
assert_eq!(owner.report().route, Route::PortableRequested);
assert!(owner.session().unwrap().is_none());
```

`Portable` never probes; the caller performs portable work. `Prefer`
reports pre-execution fallback reasons. `Require` rejects unavailable
acceleration. Failed KATs and quarantined sessions never authorize fallback.

Enable `sponge-execution` for borrowing `sponge::Sponge` constructors for
all four SHA-3 hashes, both SHAKE strengths and cSHAKE128/256. They accept
explicitly public byte/bit inputs and preserve transactional output. They are
not secret-erasing owners.

## Hardware and SIMD

Hosted execution uses qualifying AArch64 system-wide feature APIs for
SHA2/SHA-512/SHA3 kernels. Generic x86 and unreviewed platforms cannot derive
migration authority from current-core CPUID; required hosted execution fails
closed. Target-specialized x86-64 SHA/AVX2 binaries can instead use the
separate static API under its deployment contract.

The historical `RuntimeSha256Backend` and `RuntimeSha512Backend` adapters
remain distinct: observation does not admit their candidates, opportunistic
use stays portable, and required acceleration errors. They must not be
confused with the explicit `execution` authority. No automatic RISC-V
activation or global affinity/process-policy change occurs.

## Security boundaries

Raw state and blocks require `PublicData`; ordinary sponge input requires
`Public`/`PublicBits`. These markers record intent, not data-provenance
proof or clearing. Secret-bearing algorithms use separate hardened owners
from their leaf crates. Borrowed authority remains thread-bound and revocable;
copied health reports cannot create sessions.

[Hosted contract](https://github.com/valkyoth/brynja/blob/main/docs/hosted-cpu-execution.md)
· [Sponge examples](https://github.com/valkyoth/brynja/blob/main/docs/cshake-ordinary-execution.md).
MIT OR Apache-2.0.
