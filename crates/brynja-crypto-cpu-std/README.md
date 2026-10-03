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

Default-off `strict-tuplehash-acceleration` exposes `strict_tuplehash::CompiledSession`.
Select build-wide AVX2 or Arm NEON/SHA3 on supported GNU/Linux strict targets,
and preserve CPU/OS support throughout execution. Authority, exact-item writers,
framing and XOF state stay on protected worker stacks; staging/output use
protected mappings. Cancellation permits reuse; backend failure or worker panic
quarantines permanently without fallback. Scalar `Session` remains unchanged.
Compiler/platform qualification and independent retest remain pending.
See the [compiled TupleHash API example](src/strict_tuplehash/compiled.rs).

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Windows x64 VBS retained SHA-256 owner/session | 🚧 Bounded scalar API; development-tested; production qualification pending | ❌ No |
| Windows x64 VBS streaming SHA-2 and general SHA-512/t | 🚧 Scalar version-six worker; development-tested; qualification pending | ❌ No |
| Windows x64 VBS SHA-224/256 SHA-NI sessions | 🚧 Explicit opt-in; development-tested; qualification pending | ❌ No |
| Windows x64 VBS streaming SHA-3/SHAKE/cSHAKE | 🚧 Scalar version-seven worker; development-tested; qualification pending | ❌ No |
| Windows x64 VBS SHA-3/SHAKE/cSHAKE AVX2 sessions | 🚧 Explicit opt-in; development-tested; qualification pending | ❌ No |
| Windows x64 VBS streaming KMAC/KMACXOF | 🚧 Scalar version-eight worker; development-tested; qualification pending | ❌ No |
| Windows x64 VBS KMAC/KMACXOF AVX2 sessions | 🚧 Explicit opt-in; development-tested; qualification pending | ❌ No |
| Windows x64 VBS streaming TupleHash/TupleHashXOF | 🚧 Scalar version-nine worker; development-tested; qualification pending | ❌ No |
| Windows x64 VBS TupleHash/TupleHashXOF AVX2 sessions | 🚧 Explicit opt-in; development-tested; qualification pending | ❌ No |
| Windows x64 VBS SHA-2 batches | 🚧 Scalar and opt-in sequential SHA-NI SHA-224/256; development-tested; qualification pending | ❌ No |
| Windows x64 VBS SHA-3/SHAKE/cSHAKE batches | 🚧 Scalar and opt-in sequential AVX2; development-tested; qualification pending | ❌ No |
| Windows x64 VBS ParallelHash/ParallelHashXOF | 🚧 Scalar and opt-in sequential AVX2; development-tested; qualification pending | ❌ No |
| Protected compiled TupleHash/TupleHashXOF sessions | 🚧 Implemented; qualification pending | ❌ No |
| Protected SHA-2/SHA-3/SHAKE/cSHAKE SIMD batch sessions | 🚧 Implemented; qualification pending | ❌ No |
| Protected byte storage (Linux GNU x86-64/little-endian AArch64) | 🚧 Implemented; qualification pending; not strict execution | ❌ No |
| Joined single/group protected execution stacks (same Linux GNU targets) | 🚧 Implemented; qualification pending; not strict hashing | ❌ No |
| Protected scalar SHA-2 sessions (same Linux GNU targets) | 🚧 Six named identities and general SHA-512/t; qualification pending | ❌ No |
| Protected compiled SHA-2 hardware sessions (same Linux GNU targets) | 🚧 Explicit static kernels; qualification pending | ❌ No |
| Protected scalar SHA-3/SHAKE/cSHAKE sessions (same Linux GNU targets) | 🚧 Eight identities with exact-bit output; qualification pending | ❌ No |
| Protected compiled SHA-3/SHAKE/cSHAKE sessions (same Linux GNU targets) | 🚧 Explicit static AVX2/Arm kernels; qualification pending | ❌ No |
| Protected scalar KMAC/KMACXOF sessions (same Linux GNU targets) | 🚧 Four identities, protected verification; qualification pending | ❌ No |
| Protected compiled KMAC/KMACXOF sessions (same Linux GNU targets) | 🚧 Explicit static AVX2/Arm kernels and protected verification; qualification pending | ❌ No |
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

`strict-sha2` also exposes `windows_enclave`, the separate retained-result Windows
x64 VBS interface re-exported as `brynja_strict::enclave`. It uses a trusted static
image policy and Windows signature/load/initialization checks, not a runtime
development switch. It currently supports scalar SHA-256 up to 1024 bytes,
retained rehashing, cancellation and explicit public output. It does not expose
enclave-private memory as host slices or make the Linux host-slice APIs work on
Windows. Production-signed qualification remains pending.
See the [API guide](../../docs/windows-enclave-owner.md).
The distinct `windows_enclave::sha2` module covers streaming, all named SHA-2
identities, general SHA-512/t and bit tails with retained cross-algorithm rehashing.
Its version-six image is not interchangeable with the bounded worker. See the
[streaming API guide](../../docs/windows-enclave-sha2.md).
With `strict-sha2-acceleration`, explicitly use `sha2::Session::open_sha_ni`
and a reviewed version-thirteen image for SHA-224/256. The enclave requires its
complete SHA/SSE2/AVX/AVX2 bundle; other identities and mismatched images reject
without scalar fallback. Default constructors stay scalar. This development-tested
route still needs production, register/dump and independent qualification.
`windows_enclave::sha2_batch` adds eight declared SHA-2 slots, streamed item
writers and sealed retained results. Its separate version-ten worker is scalar,
not SIMD or parallel. With `strict-sha2-acceleration`, explicit
`sha2_batch::Session::open_sha_ni` uses the distinct version-nineteen image and
complete SHA/SSE2/AVX/AVX2/OS bundle for ordered SHA-224/256 items. Wide plans reject;
scalar `open` stays scalar. This is not independent-message SIMD.
See the [batch API and example](../../docs/windows-enclave-sha2-batch.md).
The separate `windows_enclave::sha512_simd` interface requires
`strict-sha2-acceleration` and explicit `Session::open_avx2` with a reviewed
version-twenty image. It computes four independent wide SHA-2 messages in AVX2
lanes, bounded to 128..=1024 bytes per lane; no scalar fallback or unbounded
streaming is promised. Production signature/import admission remains mandatory.
Development host tests pass; current-image and independent qualification remain pending.
The distinct `windows_enclave::sha256_simd::Session::open_avx2` interface uses
the same opt-in feature and a reviewed version-twenty-one image for eight
independent SHA-224/256 lanes. Each lane contains 64..=1024 bytes with a common
complete block; results remain retained until explicit public declassification.
No fallback, unbounded streaming or multicore behavior is implied. The same
production trust and qualification limits apply.
With `strict-sha2` and `strict-sha3-acceleration`,
`windows_enclave::keccak_simd::Session::open_avx2` selects the version-twenty-two
four-message SHA-3/SHAKE/cSHAKE image. Each message/N/S field is bounded to 1024
bytes and output to 2048 bits per lane. Explicit declassification, mandatory
image trust and no-fallback behavior remain unchanged. See the
[Keccak SIMD API and example](../../docs/windows-enclave-keccak-simd.md).
With both `strict-sha2` and `strict-sha3`, `windows_enclave::sha3` adds the eight
SHA-3/SHAKE/cSHAKE identities, streamed N/S and retained incremental output.
Use the separate version-seven image and [SHA-3 guide](../../docs/windows-enclave-sha3.md).
For explicit AVX2, enable `strict-sha2` and `strict-sha3-acceleration`, then use
`windows_enclave::sha3::Session::open_avx2` with the version-fourteen image.
The baseline enclave entry validates AVX/AVX2 and OS vector state; the host needs
no build-wide AVX2 flags. Trust checks remain mandatory, scalar `open` stays
scalar, and failed acceleration never selects a fallback. Development tests
pass; production and independent qualification remain pending.
With `strict-sha2` and `strict-kmac`, `windows_enclave::kmac` supports all four
KMAC identities, streamed key/customization setup, retained-output rekeying and
full-width tag verification. Its separate version-eight image keeps tags and
readers private until explicit public declassification; verification exports
only a decision. Caller-owned input buffers remain outside enclave storage.
This is scalar development-tested functionality, not production qualification.
For explicit AVX2, enable `strict-sha2` and `strict-kmac-acceleration`, then use
`windows_enclave::kmac::Session::open_avx2` with the separate version-fifteen
image. Complete AVX/AVX2 and OS vector-state checks happen inside the enclave;
host builds need no AVX2 flags. Image trust remains mandatory and failed
acceleration never falls back to scalar. Caller inputs remain caller-owned;
production, independent and current-image cleanup qualification remain pending.

With `strict-sha2,strict-tuplehash`, `windows_enclave::tuplehash` supports all four
TupleHash identities, streamed item framing, retained composition and incremental
XOF output. `Session::open` uses the scalar version-nine image. Explicit
`Session::open_avx2` additionally requires `strict-tuplehash-acceleration` and the
version-sixteen image, with complete AVX/AVX2 and OS vector-state checks inside
the enclave. It retains mandatory image trust and never falls back to scalar.
Caller buffers remain outside enclave protection; development execution does
not establish production or current-image cleanup qualification.

With `strict-sha2,strict-sha3-acceleration`,
`windows_enclave::sha3_batch::Session::open_avx2` explicitly selects the
version-seventeen batch image. It retains mandatory production trust and checks
the full AVX/AVX2/OS bundle inside the enclave. Slots execute sequentially using
single-state AVX2, not independent-message SIMD or multicore batching. Scalar
`open` remains unchanged; wrong images and unsupported routes never fall back.
See the [batch API and qualification limits](../../docs/windows-enclave-sha3.md#batching).

With `strict-sha2,strict-sha3`, `windows_enclave::parallelhash` provides all four
ParallelHash identities, streamed leaves/customization, exact-bit retained
results and incremental XOF fragments. Retained rehashing stays inside the
enclave; explicit declassification is the only output export. B never sizes an
allocation. `Session::open` selects the sequential scalar version-twelve worker. For AVX2,
enable `strict-sha2,strict-sha3-acceleration` and use
`windows_enclave::parallelhash::Session::open_avx2` with the reviewed
version-eighteen image. Complete AVX/AVX2/OS checks run inside the enclave; the
host needs no build-wide AVX2 flags. Production image trust stays mandatory;
failed selection never retries scalar. Root and leaves remain sequential, not
multicore or SIMD. See the [API example and limits](../../docs/windows-enclave-parallelhash.md).

Default-off `strict-kmac-acceleration` adds `strict_kmac::CompiledSession` with
explicit AVX2 or Arm NEON/SHA3 selection. Enable the complete build-wide features
and establish compatible CPU/OS support throughout execution. Keyed state,
authority, startup tests and full-width tag comparison remain on protected
worker stacks; output and staging use resident protected mappings. A tag mismatch
or cancellation permits reuse; backend failure or worker panic permanently
quarantines the session. Full-strength key/tag rules and scalar `Session` are
unchanged. The [compiled KMAC API example](https://github.com/valkyoth/brynja/blob/main/crates/brynja-crypto-cpu-std/src/strict_kmac/compiled.rs)
shows explicit setup and secret output ownership. Compiler/platform qualification
and independent retest remain pending.

Default-off `strict-sha3-acceleration` adds `strict_sha3::CompiledSession` for
SHA-3, SHAKE and cSHAKE with exact-bit outputs and optional bit-oriented N/S.
Select `X86Keccak` (AVX2) or `ArmKeccak` (NEON/SHA3), enable the complete build-wide
features, and establish compatible CPU/OS deployment throughout execution.
Authority, scoped sponge and XOF staging stay on protected worker stacks; failed
backends cannot silently fall back or regain health. Cancellation allows reuse.
Scalar `Session` is unchanged. The [compiled SHA-3 API example](https://github.com/valkyoth/brynja/blob/main/crates/brynja-crypto-cpu-std/src/strict_sha3/compiled.rs)
shows construction and protected output ownership. Wider compiler/platform
qualification and independent retest remain pending.

Default-off `strict-sha2-acceleration` adds `strict_sha2::CompiledSession`.
It requires an exact compatible SHA-2 kernel and its complete build-wide target
features. Authority, startup tests, hash state and staging are created on the
protected stack; backend failure or worker panic permanently quarantines the
session without scalar fallback. Ordinary cancellation permits reuse. This is
not runtime CPU detection: deployment must preserve CPU/OS support across
scheduling and migration. The scalar `strict_sha2::Session` remains unchanged.
See the [compiled hardware-session example](https://github.com/valkyoth/brynja/blob/main/crates/brynja-crypto-cpu-std/src/strict_sha2/compiled.rs).
Native Arm/dedicated x86 SHA-512 and emitted-code qualification remain pending.

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
its storage guarantee. `ProtectedStack::run_group` runs 1..=64 borrowed callbacks
on distinct preacquired stacks, joins every started worker on errors/unwind and
clears stacks after termination. It never exposes a join handle or retries on an
ordinary stack. Callbacks must finish without relying on unstarted peers; output
transactions are the integrator's responsibility. The separate strict
ParallelHash adapter uses these resources for protected root/leaf execution;
the general callback resource itself is not hashing admission.

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

`strict-batch` enables `strict_batch::Session` for protected independent-message
SHA-2/SHA-3/SHAKE/cSHAKE batches. `Route::Sha256(None)`, `Sha512(None)` and
`Keccak(None)` explicitly select portable execution. `Some(kernel)` requires
matching compiled AVX2/NEON and eligible actual SIMD work; it never silently
falls back. SHA-256 has eight slots; wide/Keccak batches have four. Exact identity,
bit width and inactive slots remain distinct, and outputs borrow protected
storage. All public destinations are checked before declassification writes.
See the [compiled batch example](src/strict_batch/mod.rs). Qualification is
pending; caller inputs/copies and public lengths retain the limits above.

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
