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

# brynja-crypto-cpu

Optional, allocation-free `no_std` first-party CPU kernels and execution
authority. Complete hash framing, padding and streaming belong to algorithm
leaves; raw compression or permutation is not a complete hash API.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Hardened SHA-224/256 batch compression with clearing packed storage | 🚧 CPU foundation; qualification pending | ❌ No |
| SHA-512-family four-lane AVX2 / two-lane NEON compression | 🚧 Implemented; qualification pending | ❌ No |
| Keccak four-state AVX2 / two-state NEON permutation | 🚧 Implemented; qualification pending | ❌ No |
| Independent-message SHA-224/256 AVX2 / NEON kernels | ✅ Opt-in, platform-limited | ❌ No |
| Static x86-64 SHA-256 and AVX2 Keccak execution | ✅ Opt-in | ❌ No |
| Static AArch64 SHA-256, SHA-512 and SHA3 Keccak execution | ✅ Opt-in | ❌ No |
| Low-level hosted-authority boundary | ✅ Platform proof required | ❌ No |
| Hardened SHA-2 and Keccak sessions with clearing scratch | ✅ Opt-in | ❌ No |
| RISC-V Zknh SHA-256/SHA-512 candidates | 🚧 QEMU/codegen only; unadmitted | ❌ No |

No independent cryptographic review, side-channel certification or FIPS
140-3 validation is claimed.

## Use

The separate default-off `sha256-hardened-batch` feature exposes the
`sha256_hardened_batch::{Authority, Session, Workspace}` compression foundation.
AVX2 handles eight independent states; little-endian AArch64 NEON handles four.
The packed workspace clears on every operation exit and Drop. Caller-provided
raw states and blocks remain caller-owned and must be cleared by their owner.
This is not yet a complete hardened batch hashing API: framing, typed leaf
outputs and hosted adapters are still under development. It does not enable or
reuse the ordinary batch feature. See the
[implementation design](https://github.com/valkyoth/brynja/blob/main/docs/hardened-multibuffer-owners.md).

The separate default-off `sha256-batch` feature exposes independent-message
AVX2 (eight lanes) and AArch64 NEON (four lanes) compression. Both raw states and
blocks require explicit `PublicData` classification; no zeroization is provided.
Use `brynja-hash-sha2::batch` for complete hashing, padding and transactional output.

```rust
use brynja_crypto_cpu::sha256_batch::Kernel;
assert_eq!(Kernel::Avx2.width(), 8);
assert_eq!(Kernel::Neon.width(), 4);
// Authority::for_compiled_target requires the complete compiled target bundle.
// Reports/feature booleans cannot mint a session or platform authority.
```

See the [batch API and deployment contract](https://github.com/valkyoth/brynja/blob/main/docs/sha256-batch-execution.md).

Current execution APIs are unpublished workspace functionality:

```sh
cargo add brynja-crypto-cpu --path /path/to/brynja/crates/brynja-crypto-cpu --no-default-features --features static-execution
```

Inspect a target-specialized authority, handling unsupported targets explicitly:

```rust
use brynja_crypto_cpu::static_execution::{Authority, Kernel};
if let Ok(owner) = Authority::new(Kernel::X86Sha256) {
    let _session = owner.session().unwrap();
    assert_eq!(owner.report().kernel, Kernel::X86Sha256);
}
```

This does not itself hash a message. Prefer an algorithm leaf for complete
operations. The example executes a startup KAT only when the complete target
bundle is compiled; the deployment must uphold that bundle on every CPU
the process can run on.

## Hardware and SIMD selection

- `static-execution`: explicit ordinary raw sessions for x86-64 SHA and
  AVX2 Keccak, or AArch64 SHA2/SHA-512/SHA3 with required NEON support.
- `runtime-execution`: low-level platform-proof boundary. Hosted applications
  normally use `brynja-crypto-cpu-std::execution`, not their own assertions.
- `hardened-execution`: separate secret-bearing sessions whose private
  source-declared permutation/compression scratch is cleared.
- Historical candidate sessions remain unadmitted; feature unification does
  not activate them. Repository evidence flags are not application APIs.

x86-64 SHA-512 and RISC-V Keccak have no operational instruction backend here.
RISC-V SHA candidates require exact Zknh instructions; generic RV64, RVV or
bit manipulation cannot substitute for them. No AVX-512 backend is provided.

## Safety and ownership

Static compilation is not runtime detection. Compatible CPUs, OS register
state, scheduling and VM migration are deployment preconditions. `!Send`/
`!Sync` does not prevent OS migration. No CPU probing, I/O, global registry,
foreign implementation or external assembly module is used here.

Authorities own health and generation; sessions borrow them. Startup tests
exercise actual kernels. Quarantine revokes sibling sessions; reports cannot
mint authority. Failure is owner-local, not a process-wide FIPS error latch.

Raw operations require `PublicData` markers. They record caller intent, not
proof of secrecy, and do not erase secret schedules or state. Do not use raw
ordinary kernels for keys, passwords, HMAC or KDF intermediates. Hardened
sessions are distinct and do not guarantee register, compiler-spill, cache,
dump, swap or abort-time erasure.

[Static execution](https://github.com/valkyoth/brynja/blob/main/docs/static-cpu-execution.md)
· [Hosted execution](https://github.com/valkyoth/brynja/blob/main/docs/hosted-cpu-execution.md)
· [Hardened Keccak](https://github.com/valkyoth/brynja/blob/main/docs/hardened-keccak-execution.md).
MIT OR Apache-2.0.

## Ordinary Keccak batching

Independent-state Keccak uses the separate default-off `keccak-batch` feature
and `keccak_batch::{Authority, Session, Kernel}` API. It processes four public
states on AVX2 or two on NEON, with no erasure or hash framing. Complete
SHA-3/SHAKE/cSHAKE batches live in `brynja-hash-sha3::batch`.
See the [Keccak batch contract](../../docs/keccak-batch-execution.md).

## Ordinary SHA-512-family batching

Enable `sha512-batch` for `sha512_batch::{Authority, Session, Kernel}`.
Raw compression uses four fixed state/block slots (NEON uses the first two).
Use the SHA-2 leaf's `batch512` API for hashing, IVs, bit padding and digests.

This API is caller-classified public-data-only, not a declassification boundary,
and does not zeroize. Do not pass keys, passwords or secret-derived material.
Portable defaults are unchanged. A Cargo feature alone does not enable AVX2;
generic x86 builds remain portable/Unavailable. Static AVX2 requires
`-C target-feature=+avx,+avx2` on a supporting deployment. Hosted Arm NEON
relies on the documented OS ABI, not independent migration proof. No universal
speedup is promised. See the [batch contract](../../docs/sha512-batch-execution.md).
