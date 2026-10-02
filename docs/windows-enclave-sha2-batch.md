# Windows enclave SHA-2 batches

`brynja_strict::enclave::sha2_batch` provides sequential scalar batches through a
separate version-ten enclave worker. The lower-level interface is also available
from `brynja_crypto_cpu_std::windows_enclave::sha2_batch` with `strict-sha2`.
An explicit `Session::open_sha_ni` constructor adds sequential SHA-NI SHA-224/256
through a distinct version-nineteen image. Neither route is independent-message
SIMD or multithreaded execution; neither replaces the existing Linux protected
batching APIs. Production deployment and independent qualification remain pending.

The application supplies a reviewed image and a trusted compiled `ImagePolicy`.
`Session::open` requires production signature verification and successful Windows
VBS initialization; it never retries with an ordinary-memory implementation.
Unsupported hosts reject. Development signing is confined to private tests.
See [deployment responsibilities](windows-enclave-deployment.md).

## Plan and ownership

A `Plan` contains eight public `Option<Algorithm>` slots. At least one is active.
The scalar route supports all six named SHA-2 identities and every valid general
SHA-512/t parameter. The SHA-NI route accepts only SHA-224/256; a wide/general plan
rejects and quarantines the session without scalar fallback.
`None` is an inactive slot, distinct from an active empty message.
Items are submitted in increasing active-slot order. One exclusive writer exists
at a time; finishing an item retains its digest inside the enclave.

The public input-byte budget counts the total supplied bytes, including any byte
containing a partial final tail. It is not a compression-work budget or a query
into secret accumulated length. Each copied input snapshot is at most 1024 bytes;
larger updates/final fragments are split by the host. Final bits use SHA-2's
MSB-first convention with unused low bits zero.

`Batch::seal` requires every declared item to finish before returning `Retained`.
The worker independently enforces order, completion, sequencing and plan identity.
The host's open-item latch rejects forgotten-writer finalization before dispatch.
Cancellation clears all batch progress, including a forgotten writer, and permits
session reuse after confirmed completion. Abandonment, invalid final bits,
transport failures and recoverable unwinding quarantine the session. Explicit
`close` reports uncertain cleanup; it does not free unconfirmed resources.
Fatal abort/process termination is outside the Drop cleanup guarantee.

## Explicit public output

No host secret-output slice is exposed. Declassification exports one fixed
512-byte block: eight 64-byte slots, each populated only up to its algorithm's
public digest width. Inactive slots and unused suffixes are zero; partial general
SHA-512/t output has canonical unused bits. The destination is committed only
after transport and cleanup receipts succeed. Caller-owned inputs and explicitly
declassified outputs are ordinary host memory, outside enclave protection.

The following mixed-width example requires a scalar session:

```rust,no_run
use brynja_strict::enclave::{sha2_batch::{Algorithm, Plan, Session}, Error, PublicDeclassification};

pub fn public_example(session: &mut Session) -> Result<[u8; 512], Error> {
    let plan = Plan::new([
        Some(Algorithm::SHA256), None, Some(Algorithm::SHA512),
        None, None, None, None, None,
    ])?;
    let mut batch = session.batch(plan, 6)?;
    let mut first = batch.item()?;
    first.update(b"abc")?;
    first.finish()?;
    batch.item()?.finish_bits(b"def", 8)?;
    let mut public = [0; 512];
    batch.seal()?.declassify(&mut public, PublicDeclassification::acknowledge())?;
    Ok(public)
}
```

Session, Batch, Item and Retained are lifetime-bound and do not implement
Send/Sync/Copy/Clone/Debug. Public plans and algorithm identities are copyable;
they do not contain secret state. An application must not treat a constructor
failure as permission to fall back to ordinary processing.

## Explicit SHA-NI selection

Enable `brynja-strict`'s `acceleration` feature, or the lower-level
`strict-sha2-acceleration` feature, and call `Session::open_sha_ni` with a reviewed
version-nineteen image and trusted static `ImagePolicy`. This retains mandatory
production signature/import/identity checks; enabling a feature does not select
acceleration automatically. Default `open` remains scalar. A scalar image cannot
stand in for the accelerated protocol.

The baseline enclave entry requires the full SHA/SSE2/AVX/AVX2 bundle and enabled
OS XMM/YMM state before specialized entry. Host compilation needs no build-wide
SHA/AVX flags. This is hardware acceleration of each ordered item, not concurrent
SIMD lanes. Feature detection does not prove arbitrary migration safety; deployment
must preserve the advertised instruction set throughout the enclave's lifetime.

## Four-message wide SIMD

With `acceleration`, `enclave::sha512_simd::Session::open_avx2` selects the
separate version-twenty image. This is four independent AVX2 lanes, not SHA-NI,
AVX-512, dedicated SHA512 instructions or multicore scheduling. It accepts
SHA-384, SHA-512, named /224 and /256 and every valid general SHA-512/t parameter.
Each lane must contain 128..=1024 bytes and at least one complete 128-byte block.
Partial final bytes use high-order bits with zero unused bits; validation happens
inside the enclave after copying. Unsupported shapes reject without fallback.

Caller input storage remains outside the enclave. Plans, lengths and budgets
are public metadata. The affine retained handle borrows its session and cannot
be copied, cloned, shared or moved between threads. Explicit declassification
returns four 64-byte slots in plan order, with unused output bytes zeroed.
Cancellation permits reuse; abandonment, work failure or backend failure
quarantines. Forgetting a handle leaves the session busy until closed.

```rust,no_run
use brynja_strict::enclave::{sha512_simd::{Algorithm, Input, Plan, Session}, Error, PublicDeclassification};

pub fn public_wide_batch(session: &mut Session) -> Result<[u8; 256], Error> {
    let message = [0x80; 128]; // Public example, not caller-storage protection.
    let plan = Plan::new([Algorithm::SHA512; 4])?;
    let input = core::array::from_fn(|_| Input::bytes(&message));
    let retained = session.digest(plan, input, 100)?;
    let mut public = [0; 256];
    retained.declassify(&mut public, PublicDeclassification::acknowledge())?;
    Ok(public)
}
```

Production opening still requires a reviewed static policy, prepared system-import
identities and successful Windows signature verification. The existing image
preparation/signing workflow applies; merely signing the earlier private diagnostic
image does not satisfy host import admission. There is no public development bypass.
Native development-image host tests pass 559 batches/2236 digests per debug/release
profile; all general-t parameters, mixed plans, cancellation, forgetting, quarantine
and transactional rejection are exercised. Production trust rejects that test
signature. See the [host observations](../assurance/windows-protection-observations/sha512-simd-host-20261002.json).
Whole-image cleanup, production signing and independent qualification remain pending.

## Eight-message narrow SIMD

With `acceleration`, `enclave::sha256_simd::Session::open_avx2` selects the
distinct version-twenty-one image. It executes eight independent SHA-224/256
AVX2 lanes, not sequential SHA-NI or multicore work. All eight slots must be
present, each containing 64..=1024 bytes with at least one complete 64-byte block.
Both identities may be mixed; wide SHA-2 identities and incompatible shapes
reject without fallback. Partial bytes use high-order bits with unused bits zero,
validated only after enclave copying. Scalar tails and padding are explicit.

```rust,no_run
use brynja_strict::enclave::{sha256_simd::{Algorithm, Input, Plan, Session}, Error, PublicDeclassification};

pub fn public_narrow_batch(session: &mut Session) -> Result<[u8; 256], Error> {
    let message = [0x80; 64]; // Public example, not caller-storage protection.
    let plan = Plan::new([Algorithm::SHA256; 8])?;
    let input = core::array::from_fn(|_| Input::bytes(&message));
    let retained = session.digest(plan, input, 100)?;
    let mut public = [0; 256];
    retained.declassify(&mut public, PublicDeclassification::acknowledge())?;
    Ok(public)
}
```

Results stay enclave-resident until explicit declassification into eight 32-byte
slots in plan order; SHA-224 uses 28 bytes followed by four zeros. Public output
is transactional. Caller input storage is not protected by borrowing it. Lengths,
identities and compression-work budgets are public metadata. Session and retained
handles are thread-bound, non-copyable and non-cloneable. Cancellation permits
reuse; abandonment or failure quarantines, and forgetting a handle leaves the
session busy until closed. `panic=abort` cannot run Drop cleanup.

The constructor requires production signature verification, reviewed image/import
identity and successful VBS initialization. Merely enabling a Cargo feature does
not select SIMD. The host requires no build-wide AVX flags; the enclave admission
boundary checks its full AVX2/OS bundle. Deployment must preserve that bundle:
revalidation is not a scheduling lock or live-migration guarantee. Unsupported
platforms, capabilities and wrong images reject, never retry with scalar code.
Development-image tests are not production trust or whole-image qualification.

Native development debug/release host campaigns each pass 403 batches and 3224
lane digests, including mixed identities and failure/lifecycle checks. Host-only
Miri and compiled mutation/ownership checks provide additional author evidence.
See the [host observations](../assurance/windows-protection-observations/sha256-simd-host-20261002.json).

## Qualification boundary

Component tests, host/worker wire parity, mutation tests, Miri placement/lifecycle
checks and packaged ownership checks are author evidence, not certification.
The worker and the fixed OS-copy adapter build separately from the host API.
The earlier [unsigned build record](../assurance/windows-protection-observations/sha2-batch-wire-build-20260930.json)
does not establish native execution. Production signing, compiler/register and
platform qualification remain pending even after development execution succeeds.
No Windows ARM64 support is implied. The streaming `sha2_batch` interface is
sequential; only the separately bounded `sha256_simd` and `sha512_simd` interfaces claim
independent-message SIMD.

The subsequent native development campaign passes in debug and release with
355 batches and 1822 individual digest comparisons per profile. It covers all
255 nonempty activity masks, mixed named/general identities, every valid general
SHA-512/t parameter, padding boundaries, partial-bit tails, larger-than-request
inputs, cancellation and forgotten-item rejection. Source-bound
[native observations](../assurance/windows-protection-observations/sha2-batch-owner-20260930.json)
record the specific development image; they are not production trust evidence.

The explicit SHA-NI host campaign passes in debug and release with 291 batches
and 1312 digest comparisons per profile, including all 255 nonempty mixed
SHA-224/256 masks, partial bits and fragmented input. The scalar campaign also
passes again. Wrong images, production trust of development signatures, wide
plans and corrupted retained plans reject; failed export preserves the destination.
Ten compiled encoder mutations, focused host Miri and packaged feature/ownership
checks pass. The [accelerated host observations](../assurance/windows-protection-observations/sha2-batch-accelerated-host-20261001.json)
bind the tested source and artifacts. These remain author development tests,
not whole-image ABI/register/spill/dump or production qualification.
