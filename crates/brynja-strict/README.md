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

# brynja-strict

Strict-only entry point for modern protected cryptography. Existing `brynja`
remains portable and unchanged; importing this crate is an explicit application
choice, not certification or proof that all application code uses this profile.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Strict-only modern protected sessions | 🚧 Implemented; qualification pending | ❌ No |
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
| Windows x64 VBS concurrent ParallelHash/ParallelHashXOF | 🚧 Opt-in four-worker AVX2; public output only; qualification pending | ❌ No |
| Explicit compiled hardware/SIMD selection | 🚧 Implemented; qualification pending | ❌ No |

Exports: `sha2`, `sha3` (SHAKE/cSHAKE), `kmac`, `tuplehash`, `parallelhash`
and independent-message `batch`, plus the separate Windows `enclave` interface.
Windows `enclave::sha2_batch` supports eight declared SHA-2 slots with retained
all-plan output; see the [batch API example](../../docs/windows-enclave-sha2-batch.md).
`enclave::parallelhash` supports all four fixed/XOF identities and retained exact-bit
composition; see the [ParallelHash example](../../docs/windows-enclave-parallelhash.md).
This Windows path is sequential scalar or explicitly selected AVX2, not the Linux
protected multicore API. With `acceleration`, use
`enclave::parallelhash::Session::open_avx2` and the reviewed version-eighteen
image. CPU/OS admission runs inside the enclave; failed selection never falls
back. Production trust and current-image qualification remain required.
The separate `enclave::parallel_concurrent` API, also under `acceleration`, uses
an exact five-thread image with up to four scoped AVX2 leaf workers. It borrows
caller inputs and requires explicit public declassification; it does not retain
secret results. All joins and destruction precede borrow release. Production
qualification remains pending. See the [concurrent example and limits](../../docs/windows-enclave-parallel-concurrent.md#crate-api-integration).
No legacy hashes, ordinary digests, raw CPU
execution authorities, generic protected callbacks or protocol APIs are exported.
Even with default features disabled, dependencies enable the protected sessions.

## Hardware and SIMD

Scalar `Session` constructors stay scalar. Enable `acceleration` to expose
separate `CompiledSession` constructors; batches always require an explicit
portable or compiled kernel route. Full build-wide CPU feature bundles and
compatible deployment are required for compiled kernels. No CPU detection,
affinity or live-migration guarantee is implied. Missing required features reject.
There is no automatic switch to a weaker memory profile.
On Windows, `acceleration` exposes the distinct `enclave::sha2::Session::open_sha_ni`
constructor for SHA-224/256 only. It requires a reviewed version-thirteen image
and the full SHA/SSE2/AVX/AVX2 bundle inside the enclave, not build-wide host flags.
Scalar `open` stays scalar; unsupported identities, platforms and images reject
without fallback. `enclave::sha3::Session::open_avx2` separately requires the
version-fourteen image and AVX/AVX2 plus enabled OS vector state. It covers all
eight SHA-3/SHAKE/cSHAKE identities with the same retained-output interface;
see the [SHA-3 guide](../../docs/windows-enclave-sha3.md).
`enclave::kmac::Session::open_avx2` requires the distinct version-fifteen image
and the same AVX/AVX2 plus OS vector-state bundle. All four identities preserve
streamed key/customization setup, retained rekeying and verification without
host secret-output slices. Scalar `open` is unchanged; no fallback is allowed.
`enclave::tuplehash::Session::open_avx2` requires the distinct version-sixteen
image and the same complete AVX/AVX2/OS bundle. It preserves streamed tuple items,
retained composition and incremental XOF output; default `open` remains scalar.
`enclave::sha3_batch::Session::open_avx2` requires the distinct version-seventeen
image and the same AVX/AVX2/OS bundle. Slots execute sequentially; this is not
independent-message SIMD or multicore batching. Scalar `open` stays scalar.
`enclave::sha2_batch::Session::open_sha_ni` requires `acceleration` and the distinct
version-nineteen image with the full SHA/SSE2/AVX/AVX2/OS bundle. It supports only
ordered SHA-224/256 items; wide plans reject without scalar fallback. This is
sequential hardware acceleration, not independent-message SIMD.
`enclave::sha512_simd::Session::open_avx2` selects the separate version-twenty
four-message SHA-512-family AVX2 image. Each lane is bounded to 128..=1024 bytes
with a common complete block; retained results require explicit declassification.
It never falls back. See the [bounded SIMD example](../../docs/windows-enclave-sha2-batch.md#four-message-wide-simd).
With `acceleration`, `enclave::sha256_simd::Session::open_avx2` selects the
distinct version-twenty-one image for eight independent SHA-224/256 AVX2 lanes.
Each lane is bounded to 64..=1024 bytes with a complete block; wide identities
reject. Retained results require explicit declassification into eight 32-byte
slots. Production signature and import admission remain mandatory; there is no
fallback. See the [narrow SIMD example](../../docs/windows-enclave-sha2-batch.md#eight-message-narrow-simd).
With `acceleration`, `enclave::keccak_simd::Session::open_avx2` selects the
version-twenty-two image for four independent SHA-3/SHAKE/cSHAKE messages.
Message/N/S fields are bounded to 1024 bytes each, output to 2048 bits per lane;
mixed identities are supported. Trust checks and explicit declassification
remain mandatory. See the [Keccak SIMD example](../../docs/windows-enclave-keccak-simd.md).
Production and
independent qualification are pending; see the [SHA-2 guide](../../docs/windows-enclave-sha2.md).

## Usage

The development facade requires the checkout until its scheduled publication:

```sh
cargo add brynja-strict --path /path/to/brynja/crates/brynja-strict --no-default-features
```

This example deliberately requests invalid resources and safely rejects on every
platform; it never silently creates an ordinary-memory session:

```rust
use brynja_strict::sha2::{Algorithm, Limits, Session};
let result = Session::new(Algorithm::Sha256, Limits {
    stack_bytes: 0, max_stack_mapping_bytes: 0,
    max_output_mapping_bytes: 0, max_message_bits: 8192, max_chunks: 16,
});
assert!(result.is_err());
```

See the [compiled session-pool example](src/lib.rs) for successful hashing on a
supported deployment. Construct a bounded pool at startup, use exclusive session
loans, drop each output before reuse and retire quarantined compiled sessions.
Do not allocate an unbounded new session per incoming request.

## Platform and memory limits

This is a hosted crate requiring `std` through its dependencies. Its local
`#![no_std]` attribute avoids an implicit standard-library prelude; it is not a
bare-metal portability claim.

Host-slice constructors require native GNU/Linux x86-64 or little-endian AArch64, Linux 4.4
and glibc 2.27 or newer, plus successful eager page locking and dump/fork exclusion.
Other supported hosted targets and verification models can compile for portability
tests but constructors return errors. They never return a weaker implementation.

The distinct `enclave::Session::open` targets native Windows x64 MSVC with VBS.
It admits an application-reviewed signed image using a static `ImagePolicy` and
Windows trust/load/initialization checks. It retains SHA-256 results privately,
supports retained rehashing and cancellation, and only releases bytes after
explicit public declassification. Input is limited to 1024 bytes per request;
caller-owned input storage remains outside protection. See the
[owner/session example and deployment requirements](../../docs/windows-enclave-owner.md).
The separate `enclave::sha2::Session` supports all named SHA-2 identities,
general SHA-512/t, streaming, final bit tails and retained cross-algorithm rehashing.
It requires the matching version-six image. See the
[streaming example and protection limits](../../docs/windows-enclave-sha2.md).
`enclave::sha3::Session` adds all eight SHA-3/SHAKE/cSHAKE identities, streamed
N/S, incremental XOF output and exact-bit retained rehashing using a separate
version-seven image. See the [SHA-3 guide](../../docs/windows-enclave-sha3.md).
No production signing service is bundled; deployment credentials belong to the
application publisher. Development-signing success is not production qualification.

On 4 KiB pages, a SHA-256 session with a 262144-byte stack locks 266240 bytes:
64 stack pages plus one digest page. Guard pages add virtual address space,
not locked payload. Other families have additional mappings and ParallelHash
has one stack per worker plus its root and CV/staging/output mappings. Budget
all live sessions together against RLIMIT_MEMLOCK; bounds are per resource,
not a process-wide quota. Lock exhaustion rejects construction before input.

Inputs and copies made by the application remain its responsibility. Lengths,
scheduling, privileged snapshots, hibernation, arbitrary register interruption,
external protection revocation, panic hooks and fatal abort remain outside the
bounded protection. Sanitizer builds are diagnostics only, not qualified
secret-processing deployments. Native Arm qualification and independent review
remain pending. See the [complete contract](../../docs/strict-hardening-profile.md).
