<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja-strict">Crates.io</a>
  |
  <a href="https://docs.rs/brynja-strict">Docs.rs</a>
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
    <img width="840" src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja security-first Rust cryptography and secure protocols overview">
  </a>
</p>

# brynja-strict

Strict-only entry point for modern protected cryptography. Existing `brynja`
remains portable and unchanged; importing this crate is an explicit application
choice, not certification or proof that all application code uses this profile.

## Cryptography Verification Status

✅ marks an implemented API within the stated feature/platform scope, not
independent review, certification or unrestricted deployment approval.
Qualification limits remain separate from implementation completion.

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Strict-only modern protected sessions | ✅ Implemented; qualification pending | ❌ No |
| Protected HMAC SHA-2/general SHA-512/t/SHA-3 sessions | ✅ Implemented; Scalar and explicit compiled routes; qualification pending | ❌ No |
| Windows x64 VBS retained SHA-256 owner/session | ✅ Implemented; Bounded scalar API; development-tested; production qualification pending | ❌ No |
| Windows x64 VBS streaming SHA-2 and general SHA-512/t | ✅ Implemented; Scalar version-six worker; development-tested; qualification pending | ❌ No |
| Windows x64 VBS SHA-224/256 SHA-NI sessions | ✅ Implemented; Explicit opt-in; development-tested; qualification pending | ❌ No |
| Windows x64 VBS streaming SHA-3/SHAKE/cSHAKE | ✅ Implemented; Scalar version-seven worker; development-tested; qualification pending | ❌ No |
| Windows x64 VBS SHA-3/SHAKE/cSHAKE AVX2 sessions | ✅ Implemented; Explicit opt-in; development-tested; qualification pending | ❌ No |
| Windows x64 VBS streaming KMAC/KMACXOF | ✅ Implemented; Scalar version-eight worker; development-tested; qualification pending | ❌ No |
| Windows x64 VBS KMAC/KMACXOF AVX2 sessions | ✅ Implemented; Explicit opt-in; development-tested; qualification pending | ❌ No |
| Windows x64 VBS streaming TupleHash/TupleHashXOF | ✅ Implemented; Scalar version-nine worker; development-tested; qualification pending | ❌ No |
| Windows x64 VBS TupleHash/TupleHashXOF AVX2 sessions | ✅ Implemented; Explicit opt-in; development-tested; qualification pending | ❌ No |
| Windows x64 VBS SHA-2 batches | ✅ Implemented; Scalar and opt-in sequential SHA-NI SHA-224/256; development-tested; qualification pending | ❌ No |
| Windows x64 VBS SHA-3/SHAKE/cSHAKE batches | ✅ Implemented; Scalar and opt-in sequential AVX2; development-tested; qualification pending | ❌ No |
| Windows x64 VBS eight-message SHA-224/256 SIMD | ✅ Implemented; Opt-in AVX2; development-tested; qualification pending | ❌ No |
| Windows x64 VBS four-message SHA-512-family SIMD | ✅ Implemented; Opt-in AVX2; development-tested; qualification pending | ❌ No |
| Windows x64 VBS four-message SHA-3/SHAKE/cSHAKE SIMD | ✅ Implemented; Opt-in AVX2; development-tested; qualification pending | ❌ No |
| Windows x64 VBS ParallelHash/ParallelHashXOF | ✅ Implemented; Scalar and opt-in sequential AVX2; development-tested; qualification pending | ❌ No |
| Windows x64 VBS concurrent ParallelHash/ParallelHashXOF | ✅ Implemented; Opt-in four-worker AVX2; public output only; qualification pending | ❌ No |
| Explicit compiled hardware/SIMD selection | ✅ Implemented; qualification pending | ❌ No |

Exports: `sha2`, `sha3` (SHAKE/cSHAKE), `hmac`, `kmac`, `tuplehash`, `parallelhash`
and independent-message `batch`, plus the separate Windows `enclave` interface.
Windows `enclave::sha2_batch` supports eight declared SHA-2 slots with retained
all-plan output; see the [batch API example](https://github.com/valkyoth/brynja/blob/main/docs/windows-enclave-sha2-batch.md).
`enclave::parallelhash` supports all four fixed/XOF identities and retained exact-bit
composition; see the [ParallelHash example](https://github.com/valkyoth/brynja/blob/main/docs/windows-enclave-parallelhash.md).
This Windows path is sequential scalar or explicitly selected AVX2, not the Linux
protected multicore API. With `acceleration`, use
`enclave::parallelhash::Session::open_avx2` and the reviewed version-eighteen
image. CPU/OS admission runs inside the enclave; failed selection never falls
back. Production trust and current-image qualification remain required.
The separate `enclave::parallel_concurrent` API, also under `acceleration`, uses
an exact five-thread image with up to four scoped AVX2 leaf workers. It borrows
caller inputs and requires explicit public declassification; it does not retain
secret results. All joins and destruction precede borrow release. Production
qualification remains pending. See the [concurrent example and limits](https://github.com/valkyoth/brynja/blob/main/docs/windows-enclave-parallel-concurrent.md#crate-api-integration).
No legacy hashes, ordinary digests, raw CPU
execution authorities, generic protected callbacks or protocol APIs are exported.
Even with default features disabled, dependencies enable the protected sessions.

## Hardware and SIMD

Windows enclave evidence covers [conditional Brynja-owned cleanup](https://github.com/valkyoth/brynja/blob/main/docs/windows-enclave-whole-image-cleanup.md#bounded-cleanup-claim-and-evidence-map),
not complete SDK/OS or whole-process erasure. Development signing does not
establish production deployment qualification. Windows ARM64 is unsupported by
these enclave interfaces; Linux host-slice sessions are separate APIs.

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
see the [SHA-3 guide](https://github.com/valkyoth/brynja/blob/main/docs/windows-enclave-sha3.md).
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
It never falls back. See the [bounded SIMD example](https://github.com/valkyoth/brynja/blob/main/docs/windows-enclave-sha2-batch.md#four-message-wide-simd).
With `acceleration`, `enclave::sha256_simd::Session::open_avx2` selects the
distinct version-twenty-one image for eight independent SHA-224/256 AVX2 lanes.
Each lane is bounded to 64..=1024 bytes with a complete block; wide identities
reject. Retained results require explicit declassification into eight 32-byte
slots. Production signature and import admission remain mandatory; there is no
fallback. See the [narrow SIMD example](https://github.com/valkyoth/brynja/blob/main/docs/windows-enclave-sha2-batch.md#eight-message-narrow-simd).
With `acceleration`, `enclave::keccak_simd::Session::open_avx2` selects the
version-twenty-two image for four independent SHA-3/SHAKE/cSHAKE messages.
Message/N/S fields are bounded to 1024 bytes each, output to 2048 bits per lane;
mixed identities are supported. Trust checks and explicit declassification
remain mandatory. See the [Keccak SIMD example](https://github.com/valkyoth/brynja/blob/main/docs/windows-enclave-keccak-simd.md).
Production and
independent qualification are pending; see the [SHA-2 guide](https://github.com/valkyoth/brynja/blob/main/docs/windows-enclave-sha2.md).

## Usage

Select this protected-only facade explicitly; it does not replace the portable facade.

After this source version is published, install from the registry:

```sh
cargo add brynja-strict --no-default-features
```

For an unpublished candidate or matching local checkout instead:

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

See the [compiled session-pool example](https://github.com/valkyoth/brynja/blob/main/crates/brynja-strict/src/lib.rs) for successful hashing on a
supported deployment. Construct a bounded pool at startup, use exclusive session
loans, drop each output before reuse and retire quarantined compiled sessions.
Do not allocate an unbounded new session per incoming request.

### HMAC

`hmac::Session<A>` accepts a complete bounded request and retains its tag in
protected storage. It supports the ten named SHA-2/SHA-3 identities and general
`Sha512T<T>` for 128..=511 except 384. Select the full or truncated tag policy
before accepting a candidate; truncation is whole-byte and at least 128 bits.
Empty or predictable keys are insecure even though the mathematical operation
accepts them. Callers remain responsible for key entropy and input storage.

This cross-platform example deliberately gives an invalid stack budget and
checks fail-closed construction. The [module example](https://github.com/valkyoth/brynja/blob/main/crates/brynja-strict/src/hmac.rs) shows a
successful complete request on a supported deployment.

```rust
use brynja_strict::hmac::{Error, Limits, Session, Sha256, TagPolicy};
let session = Session::<Sha256>::new(TagPolicy::Full, Limits {
    stack_bytes: 0, max_stack_mapping_bytes: 1048576,
    max_buffer_mapping_bytes: 65536, max_key_bytes: 4096,
    max_message_bits: 65536, max_chunks: 16,
});
assert!(session.is_err()); // no weaker memory fallback
# Ok::<(), Error>(())
```

Use `compute(Request { key, chunks, tail }, &cancellation)` for chunks/final bits,
or `verify` to authenticate with `Result<(), Error>` (mismatch is an error). `Output::declassify` requires an
explicit `PublicDeclassification` acknowledgement. Original inputs and copies
made through `Output::expose` are not protected by the session.

The scalar HMAC session stays scalar. With this facade's `acceleration` feature,
`hmac::CompiledSession<A>` additionally requires an explicit `Kernel` and its
complete build-wide features: x86 SHA/SSE2 for SHA-224/256, dedicated
SHA512/AVX/AVX2 for the wide family, or AVX/AVX2 for Keccak; Arm requires
NEON/SHA2 for SHA-224/256 or NEON/SHA3 for the wide/Keccak families. Deployment
support must be established before construction. Missing features reject;
backend failure latches quarantine. There is no independent-message HMAC SIMD
batch API. This namespace does not export the low-level hash trait or portable
HMAC owner; enabling lower-level acceleration elsewhere cannot publish its
`CompiledSession` or `Kernel` without the facade's own feature.

Strict HMAC constructors reject on macOS and Windows. The separately named
lower-level Mac resident HMAC API is not dump-excluded and is not re-exported
here. Windows enclave HMAC is not implemented. The bounded compiler/native
development checks are not independent review or release qualification; see the
[HMAC composition inventory](https://github.com/valkyoth/brynja/blob/main/docs/hmac-development-inventory.md).

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
[owner/session example and deployment requirements](https://github.com/valkyoth/brynja/blob/main/docs/windows-enclave-owner.md).
The separate `enclave::sha2::Session` supports all named SHA-2 identities,
general SHA-512/t, streaming, final bit tails and retained cross-algorithm rehashing.
It requires the matching version-six image. See the
[streaming example and protection limits](https://github.com/valkyoth/brynja/blob/main/docs/windows-enclave-sha2.md).
`enclave::sha3::Session` adds all eight SHA-3/SHAKE/cSHAKE identities, streamed
N/S, incremental XOF output and exact-bit retained rehashing using a separate
version-seven image. See the [SHA-3 guide](https://github.com/valkyoth/brynja/blob/main/docs/windows-enclave-sha3.md).
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
remain pending. See the [complete contract](https://github.com/valkyoth/brynja/blob/main/docs/strict-hardening-profile.md).
