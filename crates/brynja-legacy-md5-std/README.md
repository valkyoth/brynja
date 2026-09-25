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

# brynja-legacy-md5-std

Optional host observation for collision-broken legacy MD5. The leaf remains
allocation-free `no_std`; this adapter is never a modern-facade dependency.

## Cryptography Verification Status

Default-off `strict-acceleration` adds `strict_execution::batch::Session`.
Supply protected stack/output mapping budgets and an aggregate input-bit limit.
`digest` accepts eight `Option<Input>` slots, a finite compression budget and
a cancellation token. The affine output exposes eight ordered 16-byte slots
and public work metadata; inactive slots are zero. Build-wide AVX2 or NEON is
required on GNU/Linux x86-64 or little-endian AArch64 respectively. Deployment
must preserve support throughout execution. Ineligible workloads reject;
scalar tails and padding use clearing owners on protected stacks. Budget and
cancellation failures preserve reuse; backend failure or panic quarantines.
Compiler/platform qualification and independent retest remain pending.

No named independent reviewer has verified this component. Passing tests, CI,
Kani, Miri, fuzzing or a pentest is not independent cryptographic verification.

| Algorithm | Implemented | Independently verified |
| --- | --- | --- |
| Protected compiled MD5 SIMD batches | 🚧 Implemented; qualification pending | ❌ No |
| MD5 | ✅ Fully implemented | ❌ Not independently verified |
| Ordinary hosted batch SIMD | 🚧 In progress; native qualification pending | ❌ No |
| Hardened hosted batch SIMD | 🚧 In progress; retest and native evidence pending | ❌ No |
| Opt-in protected scalar MD5 session | 🚧 Implemented; qualification pending | ❌ No |

## Protected scalar compatibility profile

Default-off `strict-execution` exposes `strict_execution::Session` with bounded
byte/bit requests and an affine protected output loan. GNU/Linux native x86-64
and little-endian AArch64 acquire locked, guarded, dump/fork-excluded stack and
output mappings before input; unsupported targets and model builds reject.
The library-controlled scalar worker creates the scoped state on its protected
stack, joins and clears before returning. Errors, cancellation and recoverable
unwind clear output; explicit public release consumes the loan. This feature
does not select SIMD and does not repair MD5's collision weakness.

See the [compiled Session example](https://github.com/valkyoth/brynja/blob/main/crates/brynja-legacy-md5-std/src/strict_execution/mod.rs)
and [strict-profile limitations](https://github.com/valkyoth/brynja/blob/main/docs/strict-hardening-profile.md).
Native/platform qualification and independent retest remain pending. Inputs,
caller copies, abort and whole-process/register/interruption erasure are not
covered by this resource profile.

## Hardware and SIMD

The distinct default-off `runtime-hardened-execution` feature exposes
`hardened_execution::select(Mode::{Portable,Prefer,Require})`. It returns a
clearing executor with affine per-batch owners and typed secret output. Generic
x86 remains portable unless compiled with AVX2; allowlisted little-endian Arm
platforms can select NEON. Cached detection is not proof of arbitrary hotplug or
VM-migration safety. Batch dimensions and work reports are public.

```rust
# #[cfg(feature = "runtime-hardened-execution")] {
use brynja_legacy_md5_std::hardened_execution::{select, Mode};
use brynja_legacy_md5::{BitString, Md5BatchControl};
let executor = select(Mode::Prefer).map_err(|_| "selection")?;
let data = [0x41; 128];
let inputs = [Some(BitString::new(&data, 8).map_err(|_| "bits")?); 8];
let mut output = [[0; 16]; 8];
let (secret, _) = executor.batch().digest_secret(
    &inputs, &mut output, &mut Md5BatchControl::new(24),
).map_err(|_| "batch")?;
assert_eq!(secret.expose().len(), 128);
drop(secret);
assert_eq!(output, [[0; 16]; 8]);
# }
# Ok::<(), &'static str>(())
```

See [hardened storage and deployment limits](https://github.com/valkyoth/brynja/blob/main/docs/legacy-md5-hardened-execution.md).

No MD5 SIMD candidate is admitted. `opportunistic()` selects the portable leaf;
`required()` fails closed. CPU detection cannot establish migration-safe
execution authority, including in evidence builds. No global installation,
affinity changes or third-party dependency is introduced.

The separate default-off `runtime-execution` feature adds `execution::select`.
Hosted little-endian AArch64 can use NEON under its supported OS feature contract.
Generic x86-64 stays portable; explicit AVX2-specialized binaries can use static
authority. Cached detection does not prove arbitrary hotplug or VM migration
safety. Ordinary public-data SIMD does not authorize secret processing. Require
rejects batches without a complete active vector group before work/output mutation.

## Use

This adapter is unpublished. For a local checkout:

```sh
cargo add brynja-legacy-md5-std --path /path/to/brynja/crates/brynja-legacy-md5-std
cargo add brynja-legacy-md5 --path /path/to/brynja/crates/brynja-legacy-md5
```

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

With `runtime-execution` explicitly enabled:

```rust
# #[cfg(feature = "runtime-execution")] {
use brynja_legacy_md5::{BitString, Md5BatchControl};
use brynja_legacy_md5_std::execution::{select, Mode, PublicData};
let executor = select(Mode::Prefer).map_err(|_| "authority")?;
let message = [0x41; 128];
let inputs = [Some(BitString::new(&message, 8).map_err(|_| "bits")?); 8];
let mut output = [[0; 16]; 8];
let report = executor.digest(&inputs, &mut output, &mut Md5BatchControl::new(24),
    PublicData::acknowledge()).map_err(|_| "batch")?;
assert_eq!(report.work.active_lanes, 8);
assert_eq!(report.work.scalar_blocks + report.work.vector_blocks, 24);
# }
# Ok::<(), &'static str>(())
```

See the [ordinary execution contract](https://github.com/valkyoth/brynja/blob/main/docs/legacy-md5-execution.md)
for authority, ordered batch semantics and pending native evidence.

MD5 is collision-broken. Do not use it for new authentication, signatures or
password hashing. Public data only; use the leaf's portable hardened batch
owner for confidential legacy compatibility. No FIPS validation or SIMD cleanup
claim. MIT OR Apache-2.0.

See [MD5 acceleration](https://github.com/valkyoth/brynja/blob/main/docs/legacy-md5-acceleration.md)
for the ownership contract and non-production evidence procedure.
