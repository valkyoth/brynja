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
