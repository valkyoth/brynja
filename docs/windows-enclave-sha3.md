# Windows enclave SHA-3 streaming

`brynja_strict::enclave::sha3` implements scalar SHA3-224/256/384/512,
SHAKE128/256 and cSHAKE128/256 with retained enclave output. The version-seven
worker and host API pass development tests on Windows x64 VBS. Production
signing, independent review and final compiler/platform qualification remain
pending. This is not a hardware/SIMD implementation or Windows ARM64 evidence.

Use a reviewed version-seven worker image with the existing
[consumer-managed image admission](windows-enclave-image-admission.md) workflow.
The public constructor requires production signature, identity, import and VBS
checks. It exposes no development bypass or consumer-supplied transport. A
version-four SHA-256 or version-six SHA-2 image is not interchangeable with it.
Low-level `brynja-crypto-cpu-std` consumers need both `strict-sha2` and
`strict-sha3`; `brynja-strict` already enables both.

## Stream and retain output

```rust,no_run
use brynja_strict::enclave::{Error, ImagePolicy, PublicDeclassification};
use brynja_strict::enclave::sha3::{Algorithm, Finalized, Session};
use std::path::Path;

fn public_example(image: &Path, policy: &'static ImagePolicy) -> Result<[u8; 32], Error> {
    let mut session = Session::open(image, policy)?;
    let mut stream = session.stream(Algorithm::Sha3_256)?;
    stream.update(b"public example")?;
    let Finalized::Digest(digest) = stream.finalize()? else {
        return Err(Error::Protocol);
    };
    let mut output = [0; 32];
    digest.declassify(&mut output, PublicDeclassification::acknowledge())?;
    session.close()?;
    Ok(output)
}
```

Fixed hashes return `Finalized::Digest`; SHAKE and cSHAKE return
`Finalized::Reader`. `Reader::retain(width, last, terminal)` creates a retained
fragment of at most 1024 bytes. Nonterminal fragments contain complete bytes;
terminal fragments may end in a partial byte. Empty output requires `last=0`.
Declassifying a nonterminal fragment returns its reader for the next fragment.
Total XOF output is not limited to one fragment.

`Session::customized` accepts cSHAKE N/S bit strings and copies bounded snapshots
into an incremental hardened setup owner. Neither N nor S must fit in one
snapshot; exact declared bit lengths and bytepad completion are checked before
message absorption. Empty N/S gives SHAKE equivalence. `Bits` and
`Stream::finalize_bits` use FIPS 202 **low-bit-first** canonical packing, unlike
the SHA-2 API. Unused high bits must be zero.

`Retained::rehash` and `rehash_customized` consume the exact retained bit string
inside the enclave, without exporting it to the host. Rehashing a fragment
discards its previous XOF reader. No host secret slice or preflight length oracle
is exposed. Declassification is an explicit public-data decision, not a way to
obtain a convenient confidential buffer; destination width must match exactly
and failure leaves it unchanged.

## Ownership and limits

Session, Stream, Reader, Retained and Finalized are neither Send, Sync, Copy,
Clone nor Debug. Cancellation permits reuse; dropping an active loan quarantines
the owner. Forgetting it leaves the owner Busy. `close` retains responsibility
for destruction, even after abandonment. Unconfirmed transport, copying,
residency or cleanup never permits fallback.

The worker places typed state in a guarded resident enclave page. Input headers
and payloads are bounded and copied once per operation. Sequence numbers reject
replay, gaps and exhaustion. Active state, pending setup bits and retained output
clear on completion, cancellation or failure. Destruction ends the typed lifetime
before clearing the complete page and releasing it; the resident worker stack
window clears before returning. Inactive enum storage and padding stay protected
until whole-page destruction, rather than being claimed zero between calls.

Caller-owned inputs and application copies are outside this boundary. Fatal
aborts, privileged snapshots and arbitrary caller frames remain documented
limits. Prior dump experiments qualify only their original images, not this
worker. Confirmed resource cleanup is mandatory; a failure may retain mappings
and file guards, so applications must bound creation and retire failed owners.

## Build and author checks

```sh
python3 scripts/cryptography/windows_enclave_sha3_stream_build.py worker-build --image
python3 scripts/cryptography/test-windows-enclave-sha3-stream.py
```

Link with the generated MSVC/SDK `link.cmd`, run VEIID, transform system imports,
then sign and inspect the final image as described in the admission guide.
Compile the independently reviewed final-image policy into the application.
File hashing alone is not approval.

Author checks cover 628 cSHAKE vectors, 76 NIST bit vectors, 96 hashlib cases,
512 retained rehash cases, lifecycle/cleanup mutants, focused Miri and packaged
ownership negatives. Native enclave tests passed 1028 cases in both debug and
release, including streamed N/S larger than one snapshot. These checks use
public synthetic data and the private test-only development constructor.
The signing attempt emitted Microsoft's VBS compatibility warning; no clean
production signing result is claimed. See the
[source-bound development record](../assurance/windows-protection-observations/sha3-streaming-20260930.json).

## Batching

`brynja_strict::enclave::sha3_batch` is a separate version-eleven protocol,
not a reinterpretation of the streaming image. Direct users of
`brynja-crypto-cpu-std` enable both `strict-sha2` (the shared enclave owner)
and `strict-sha3`. No new default feature or hardware selection is introduced.

The public plan declares up to eight active slots. Results are packed in slot
order into a fixed 1024-byte export block; inactive slots occupy no bytes and
the suffix beyond `Plan::output_bytes()` is zero. SHA-3 requires its fixed width;
SHAKE/cSHAKE accept declared final-bit shapes, including empty output. Active
empty-output slots must still be completed. This API does not provide independent
incremental batch XOF readers or SIMD/parallel throughput.

```rust,no_run
use brynja_strict::enclave::{sha3_batch::{Algorithm, Bits, Output, Plan, Session},
    Error, PublicDeclassification};

pub fn public_batch(session: &mut Session) -> Result<[u8; 1024], Error> {
    let plan = Plan::new([
        Some(Output::new(Algorithm::Sha3_256, 32, 8)?),
        Some(Output::new(Algorithm::Cshake128, 33, 1)?),
        None, None, None, None, None, None,
    ])?;
    // Public budget counts supplied setup and message bytes, not permutations.
    let mut batch = session.batch(plan, 64)?;
    let mut first = batch.item()?;
    first.update(b"abc")?;
    first.finish()?;
    let empty = Bits::new(&[], 0).map_err(|_| Error::Bounds)?;
    let custom = Bits::new(b"example", 8).map_err(|_| Error::Bounds)?;
    let mut second = batch.item_custom(empty, custom)?;
    second.update(b"abc")?;
    second.finish_bits(&[1], 1)?;
    let mut public = [0; 1024];
    batch.seal()?.declassify(&mut public, PublicDeclassification::acknowledge())?;
    Ok(public)
}
```

`item_custom` streams exact low-bit-first cSHAKE name/customization data through
bounded snapshots; nonempty N/S is rejected for other identities. `Item` cannot
be cloned or shared. Dropping an unfinished item or result quarantines; forgetting
an item keeps the batch busy and cannot implicitly finalize it. Cancellation
clears the entire batch without export and permits reuse on confirmed success.
Failed output copying or validation leaves the caller's destination unchanged.
All declared slots must finish and seal before explicit public declassification.

Constructors require the same production signature and image policy as the
streaming owner. Enclave results never become host secret slices; caller-owned
input remains outside protection. Unsupported platforms fail closed. Scalar
host integration is not production, compiler/register, SIMD or independent
qualification. Build the matching image with
`python3 scripts/cryptography/windows_enclave_sha3_batch_build.py worker-build --image`
and run component/parity tests with
`python3 scripts/cryptography/test-windows-enclave-sha3-batch.py`.

Native development tests pass 323 batches and 1344 digest comparisons in each
debug/release profile, covering all 255 nonempty activity masks, mixed identities,
zero/partial/full output shapes, streamed cSHAKE setup, cancellation and forgotten
item rejection. Eight portable host checks also pass under Miri. These are author
checks using synthetic public data and the private development constructor, not
independent review or production signing. See the
[source-bound batch record](../assurance/windows-protection-observations/sha3-batch-owner-20260930.json).
