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

## Qualification boundary

Component tests, host/worker wire parity, mutation tests, Miri placement/lifecycle
checks and packaged ownership checks are author evidence, not certification.
The worker and the fixed OS-copy adapter build separately from the host API.
The earlier [unsigned build record](../assurance/windows-protection-observations/sha2-batch-wire-build-20260930.json)
does not establish native execution. Production signing, compiler/register and
platform qualification remain pending even after development execution succeeds.
No Windows ARM64 or independent-message SIMD support is implied.

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
