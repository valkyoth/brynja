# Complete ordinary SHA-2 execution

Status: v0.24.33 implementation candidate; exceptional owner pentest and fresh
native family-level observations required before tagging. No publication.

All six named SHA-2 identities and all 510 valid general SHA-512/t parameters
have byte/bit one-shot and streaming APIs in `brynja_hash_sha2::execution`.
Existing portable APIs, digest identities and default graphs are unchanged.

## Opt-in selection

`static-execution` exposes the optional dependency-free CPU leaf through SHA-2.
`runtime-execution` additionally accepts a borrowed platform session. Neither
feature adds std or a third-party crate to SHA-2. The separate
`brynja-crypto-cpu-std` adapter supplies hosted Portable/Prefer/Require policy.
All features are default-off; these new APIs are repository-only until the
next public checkpoint, not part of the older published support artifacts.

For a target-specialized no_std executable:

```rust
use brynja_hash_sha2::execution::{Kernel, Mode, Sha256, StaticSelection};
let selected = StaticSelection::new(Kernel::X86Sha256, Mode::Prefer)?;
let result = Sha256::hash(selected.execution()?, b"public file contents")?;
let digest = result.digest;
let report = result.report;
```

For hosted applications, enable `runtime-execution` in both the SHA-2 leaf and
the separate CPU std adapter. The application supplies error conversion:

```rust
use brynja_crypto_cpu_std::execution::{Authority, Kernel, Mode};
use brynja_hash_sha2::execution::{Execution, Sha512};
let owner = Authority::new(Kernel::ArmSha512, Mode::Prefer)?;
let selection_report = owner.report();
let execution = match owner.session()? {
    Some(session) => Execution::from_runtime(session),
    None => Execution::portable(),
};
let mut hash = Sha512::new(execution)?;
hash.update(b"public stream part one")?;
hash.update(b"public stream part two")?;
let result = hash.finalize()?;
```

Never turn a session error into portable fallback. Retain the hosted owner's
report for its fallback reason; the leaf's `Route::Portable` does not infer it.
Static deployment must satisfy the compiler feature and OS-state requirements
on all schedulable CPUs. Hosted execution retains the platform ABI assumptions
of [the underlying authority](hosted-cpu-execution.md). Generic x86 hosted
selection still reports unavailable: use portable or a correctly deployed static
binary. Arm SHA-512 needs the complete SHA3/SHA512 bundle. RISC-V remains on its
separate unadmitted candidate path; it has no operational authority here.

## APIs, work and failure semantics

Each named stream has `new`, `update`, `finalize`, `finalize_bits`, `hash`,
`hash_bits`, byte/bit length preflight, accepted-byte count and `report`.
General `execution::Sha512T` also takes validated `Sha512TBits` and returns the
same parameter-aware public digest as portable general-t. Partial-byte input
enters only through consuming finalization. No clone, reset or route switch.

`Output<D>` carries the digest and successful work counts. `message_blocks`
and `padding_blocks` use the selected route. Padding construction, copying and
serialization remain scalar Rust. Even an empty message performs one padding
compression on the selected kernel; a short update can buffer without one.
General-t IV derivation is always one separately reported portable block.
Named variants use fixed IV constants and report zero IV-derivation blocks.
Reports are observations, not permits or timing proofs.

Constructor and empty-update health checks fail closed. Every kernel operation
repeats raw-session checks. Length admission precedes live mutation. A fixed
ordinary staging copy makes update failure atomic for chaining state, buffer,
length and counts. Kernel failure never switches route or returns a digest;
finalization consumes the stream on errors too. Reentrant entry is unsupported.

These APIs do not erase private state or staging and are public-data-only.
Raw calls explicitly classify borrowed state and blocks with `PublicData`;
classification is caller intent, not proof of non-secret provenance. Hardened,
HMAC, KDF, password and confidential inputs must not enter these routes.
Hardened acceleration is separate v0.24.34 work. No named independent review,
FIPS validation, register/spill erasure or native side-channel approval exists.

## Reproduce acceptance

Run `python3 scripts/sha2/check-sha2-execution.py` for extracted-package tests,
240 official NIST cases, all 4,590 general-t oracle cases, ownership negatives
and compiled mutants. `--qemu` adds Arm hosted/static execution;
`--native-x86` requires a deployment supporting SHA/SSE2 and tests native static
SHA-224/256. Do not use that flag on incompatible hardware.

On native Arm/Apple, after fetching the locked dependencies, run:

```sh
cargo run --locked --offline --release --manifest-path assurance/sha2-execution/Cargo.toml -- hosted
```

QEMU does not replace native migration, performance or side-channel evidence.
