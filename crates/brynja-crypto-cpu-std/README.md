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
| Protected byte storage (Linux GNU x86-64/little-endian AArch64) | 🚧 Implemented; qualification pending; not strict execution | ❌ No |
| Synchronous protected execution stacks (same Linux GNU targets) | 🚧 Implemented; qualification pending; not strict hashing | ❌ No |
| Protected scalar SHA-2 sessions (same Linux GNU targets) | 🚧 Six named identities and general SHA-512/t; qualification pending | ❌ No |
| Protected scalar SHA-3/SHAKE/cSHAKE sessions (same Linux GNU targets) | 🚧 Eight identities with exact-bit output; qualification pending | ❌ No |
| Protected scalar KMAC/KMACXOF sessions (same Linux GNU targets) | 🚧 Four identities, protected verification; qualification pending | ❌ No |
| Protected scalar TupleHash/TupleHashXOF sessions (same Linux GNU targets) | 🚧 Four identities, exact item completion; qualification pending | ❌ No |
| Hosted independent-message SHA-512-family batching | 🚧 Implemented; qualification pending | ❌ No |
| Distinct hardened SHA-2 and Keccak hosted batch owners | 🚧 Implemented; qualification pending | ❌ No |
| Hosted independent-message SHA-3/SHAKE/cSHAKE batching | 🚧 Implemented; qualification pending | ❌ No |
| Hosted independent-message SHA-224/256 batching | ✅ Opt-in, platform-limited | ❌ No |
| Historical SHA-2 host observation and portable fallback | ✅ Implemented; candidate routes unadmitted | ❌ No |
| Explicit hosted raw execution | ✅ Opt-in, qualifying AArch64 only | ❌ No |
| Ordinary SHA-3/SHAKE/cSHAKE sponge adapters | ✅ Opt-in, public data only | ❌ No |

No named independent cryptographic review or FIPS 140-3 validation is claimed.

## Use

`protected-memory` provides bounded `protected_memory::ProtectedBytes` with
resident pages, per-mapping core-dump exclusion and guard pages. Allocation is
fallible and fails closed on unsupported systems or OS protection failure.
`new(bytes, max_mapping_bytes)` returns initially zeroed storage; use explicit
`as_bytes`/`as_bytes_mut` loans and `clear`/`close`. Drop clears the full payload
before release. It is not a strict hashing authority;
ordinary caller copies, stack and registers remain outside its guarantee.
No hardware/SIMD instruction feature is required for this storage adapter.
See the [implementation contract](../../docs/strict-hardening-profile.md).

The same feature provides `protected_memory::ProtectedStack`. Acquire it with
`new(stack_bytes, max_mapping_bytes)`, then call `run` with a borrowed
`FnOnce() + Send` callback returning `()`. It joins before returning and clears
the entire stack from the caller's stack, including after recoverable panic.
The minimum reservation is 64 KiB; callers must budget enough for their work.
No ordinary-stack fallback is allowed. This is not a secure closure sandbox:
captures, arbitrary heap/TLS allocations, panic hooks and registers are outside
its storage guarantee. Concurrent protected hashing is not implemented yet.

`strict-sha2` adds a library-controlled protected hash session. It preacquires
stack/output resources and rejects unsupported targets instead of silently using
ordinary storage. This initial path uses the hardened scalar implementation,
not SIMD/hardware acceleration. It is not independently qualified or a
whole-process/register-erasure guarantee. Inputs and caller-created copies remain
caller responsibilities. Construct `Session::new(Algorithm::Sha256, limits)`
with explicit stack/mapping, message-bit and chunk bounds, then use
`session.hash(input)`. Drop the digest loan to clear output and reuse the session.
See the [compiled API example and complete limits](src/strict_sha2/mod.rs).

`hash_chunks` also accepts a raw MSB-first final bit tail and a cooperative
`Cancellation`. The returned digest loan has no implicit public conversion;
`expose` is a deliberate borrow and `declassify` requires explicit authority.

`strict-sha3` separately enables `strict_sha3::Session`. Select a fixed identity
such as `Algorithm::Sha3_256` or an exact XOF width such as
`Algorithm::Shake256(257)`, then supply explicit mapping, message, customization,
output-bit and chunk limits. `hash` uses byte input; `hash_chunks` accepts raw
LSB-first `Bits`, and `hash_customized_chunks` additionally accepts cSHAKE N/S.
Empty N/S preserves SHAKE equivalence. Canonical validation runs on the protected
worker; output loans clear on Drop. Empty and partial-bit XOF output are supported.
Prefix setup is bounded but not internally cancellable. This is scalar-only and
qualification-pending, with the same target and caller-storage limits as above.
See the [compiled SHA-3 session example](src/strict_sha3/mod.rs).

`strict-kmac` enables `strict_kmac::Session` with four scalar KMAC/KMACXOF
identities. `Session::new(Algorithm::Kmac256(256), limits)` preacquires protected
stack, staging and output. `authenticate(key, message, customization)` returns a
secret output loan; `compute(request, cancellation)` also supports bit keys,
customization and message tails. `verify(request, candidate, cancellation)`
compares on the protected worker and returns only the public Boolean decision.
Keys must be full-strength; fixed tags and verification also require full-strength
output even if conformance-testing is enabled elsewhere. Use `declassify` for
explicit public tags. Setup and fixed finalization are bounded, not internally
cancellable. SIMD/hardware, native Arm and independent qualification remain pending.
See the [compiled KMAC session example](src/strict_kmac/mod.rs) and the
[resource/limit contract](../../docs/strict-hardening-profile.md).

`strict-tuplehash` enables `strict_tuplehash::Session`. Construct it with
`Algorithm::TupleHash256(256)` and explicit mapping, input/customization/output,
item-count and chunk-count limits. `hash(&[Item::bytes(first), Item::bytes(second)],
customization)` preserves tuple-element boundaries. `compute` accepts chunked
items, raw LSB-first final bits and cooperative cancellation. Splitting an item
into chunks does not create more tuple elements; an empty tuple differs from
one empty element. Item lengths are derived and completed on the protected
worker. Fixed/XOF output, including empty and partial-bit output, stays in an
affine protected loan until exposure or explicit declassification. Setup and
fixed finalization are bounded but not internally cancellable. This path is
scalar-only, qualification-pending and has the target/caller-storage limits above.
See the [compiled TupleHash session example](src/strict_tuplehash/mod.rs).

Enable `sha256-batch` for the separate ordinary/public SHA-224/256 multibuffer
adapter. Portable selection never probes; Require fails on unqualified platforms
and Prefer only falls back before execution, never after a backend failure.

```rust
use brynja_crypto_cpu_std::sha256_batch::{Authority, Mode};
let owner = Authority::new(Mode::Portable).map_err(|e| format!("{e:?}"))?;
assert_eq!(owner.kernel().map_err(|e| format!("{e:?}"))?, None);
let executor = owner.executor(1).map_err(|e| format!("{e:?}"))?;
// Use executor.digest with public, mixed-identity eight-slot batches.
drop(executor);
# Ok::<(), String>(())
```

AVX2 uses eight lanes in a target-specialized executable; allowlisted AArch64
NEON uses four. Generic x86 current-core detection does not authorize migration.
On x86-64, the Cargo feature alone does not activate AVX2: a generic build's
`Mode::Prefer` selects portable and `Mode::Require` returns `Error::Unavailable`,
even on an AVX2-capable machine. Use `RUSTFLAGS="-C target-feature=+avx,+avx2"`
only for deployments guaranteeing the full CPU/OS bundle throughout execution,
scheduling and migration. This is not an automatic runtime CPUID selector.
Neither the state nor vector scratch is zeroized. See the
[batch contract](https://github.com/valkyoth/brynja/blob/main/docs/sha256-batch-execution.md).

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

Hardened batching has three separate default-off features. None enables ordinary
batching or relabels an ordinary authority/workspace:

| Feature | Hosted module | Leaf executor |
| --- | --- | --- |
| `sha256-hardened-batch` | `sha256_hardened_batch` | `brynja_hash_sha2::hardened_batch` |
| `sha512-hardened-batch` | `sha512_hardened_batch` | `brynja_hash_sha2::hardened_batch512` |
| `keccak-hardened-batch` | `keccak_hardened_batch` | `brynja_hash_sha3::hardened_batch` |

For each module, call `Authority::new(Mode::Portable/Prefer/Require)` and then
`authority.executor(nonzero_threshold)`. The borrowed executor accepts its
distinct clearing `Workspace`, canonical `Input` slots and secret destinations
through `digest_secret`; `digest_public` requires explicit declassification.
The leaf module rustdocs contain runnable complete hashing examples. SHA-2
thresholds count common complete input blocks; Keccak thresholds count per-lane
prefix/padding/squeezing permutations. Reports count actual vector work.

Portable does not probe. Prefer falls back only on initial unavailability, never
after startup KAT, health or execution failure. Generic x86 stays portable or
Unavailable; AVX2 requires a matching build-wide bundle and compatible deployment.
Little-endian AArch64 NEON uses allowlisted OS feature contracts. Cached detection
does not prove arbitrary VM migration/hotplug safety. CPU quarantine revokes all
borrowed accelerated executors; portable selection has no CPU authority, so use
the portable executor's own `quarantine` when local revocation is wanted.
Full qualification remains pending; see the
[hardened multibuffer contract](../../docs/hardened-multibuffer-owners.md).

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

## Ordinary Keccak batching

Default-off `keccak-batch` similarly exposes `keccak_batch::Authority` for
independent SHA-3/SHAKE/cSHAKE messages, with borrowed batch executors and
caller-owned output staging. This is public-only, not a secret-erasing API.
Generic x86 builds remain portable/unavailable; an AVX2-specialized deployment
or an allowlisted AArch64 NEON platform is required for hosted SIMD.
See the [Keccak batch contract](../../docs/keccak-batch-execution.md).

## Ordinary SHA-512-family batching

Enable `sha512-batch` and select `sha512_batch::Authority::new(Mode)`.
Portable never probes; Prefer reports initial unavailability as portable;
Require rejects it. Backend health failure never permits silent fallback.

```rust
use brynja_crypto_cpu_std::sha512_batch::{Authority, Mode};
let owner = Authority::new(Mode::Portable);
assert!(owner.is_ok());
# Ok::<(), String>(())
```

This API is caller-classified public-data-only, not a declassification boundary,
and does not zeroize. Do not pass keys, passwords or secret-derived material.
Portable defaults are unchanged. A Cargo feature alone does not enable AVX2;
generic x86 builds remain portable/Unavailable. Static AVX2 requires
`-C target-feature=+avx,+avx2` on a supporting deployment. Hosted Arm NEON
relies on the documented OS ABI, not independent migration proof. No universal
speedup is promised. See the [batch contract](../../docs/sha512-batch-execution.md).
