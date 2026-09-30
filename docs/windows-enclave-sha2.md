# Windows enclave SHA-2 streaming

`brynja_strict::enclave::sha2` provides scalar enclave streaming for SHA-224,
SHA-256, SHA-384, SHA-512, named SHA-512/224 and SHA-512/256, and all 510 valid
general SHA-512/t parameters. The host API and version-six worker are implemented;
development execution is tested. Production signing, independent review and
full compiler/platform qualification remain pending. No SIMD or hardware route
is implied by this implementation.

This is a separate protocol from the bounded version-four SHA-256 API at
`brynja_strict::enclave::Session`. Use the matching reviewed worker and image
policy; the old worker cannot satisfy the new constructor's export requirements.
The same production-only signature, file-identity, import and VBS admission
rules apply. There is no public development bypass or generic transport driver.

## Use the retained result API

```rust,no_run
use brynja_strict::enclave::{Error, ImagePolicy, PublicDeclassification};
use brynja_strict::enclave::sha2::{Algorithm, Session};
use std::path::Path;

fn public_example(image: &Path, policy: &'static ImagePolicy) -> Result<[u8; 64], Error> {
    let mut session = Session::open(image, policy)?;
    let mut stream = session.stream(Algorithm::SHA256)?;
    stream.update(b"public ")?;
    stream.update(b"example")?;
    let digest = stream.finalize()?.rehash(Algorithm::SHA512)?;
    let mut output = [0; 64];
    digest.declassify(&mut output, PublicDeclassification::acknowledge())?;
    session.close()?;
    Ok(output)
}
```

`Algorithm::sha512_t(t)` validates the exact public parameter, rather than just
its rounded output width. `finalize_bits(input, last_bits)` supports a canonical
MSB-first final bit string: empty input requires zero; otherwise the final byte
has 1 through 8 valid bits and unused low bits must be zero. `rehash` consumes the
exact retained bit string, including non-byte-aligned SHA-512/t results.

Each transport snapshot is at most 1024 bytes, but `update` splits larger slices
without copying them into another host buffer. Total input is bounded by the
algorithm's checked length domain, not the snapshot size. Caller-owned inputs,
their lifetime and application copies remain the application's responsibility.
Neither stream state nor digest bytes are returned as host secret slices.

Session, Stream and Digest are neither Send, Sync, Copy, Clone nor Debug. Loans
exclude concurrent reuse. Cancellation and successful declassification permit
reuse; abandonment, protocol failure or unwind quarantines the owner. Forgotten
handles leave it Busy. Explicit `close` still owns resource destruction. Public
declassification requires exact output width and leaves the caller's destination
unchanged on failure. Do not declassify merely to obtain a convenient secret slice.

## Worker ownership

The worker places its typed owner in a guarded, resident enclave page. All
cryptography uses existing first-party hardened SHA-2 implementations; the C
adapter only performs Windows enclave transport and memory orchestration.
Input headers and payloads are independently bounded and copied once per call.
Nonrecycled per-owner sequence numbers reject replay, gaps and exhaustion.
Every operation runs within the admitted resident stack window.

Active algorithm state and result bytes clear on cancellation, completion or
failure. Compiler-created inactive enum storage and padding remain inside the
protected owner page until close: destruction first ends the typed lifetime,
then volatile-clears the complete page before unlock/free. The complete worker
stack window is cleared before return. This is not a claim that every inactive
page byte is zero between calls, or that arbitrary caller frames, fatal aborts,
privileged snapshots or instrumented builds are qualified.

An unconfirmed OS copy, residency receipt, clearing or destruction never permits
fallback or unsafe release. Some such failures retain the mapping and file
guards; applications must bound session creation and retire failed owners.

## Build and development checks

Build a separate worker directory, without replacing older evidence:

```sh
python3 scripts/cryptography/windows_enclave_sha2_stream_build.py worker-build --image
python3 scripts/cryptography/test-windows-enclave-sha2-stream.py
python3 scripts/cryptography/test-windows-enclave-owner.py
```

The generated `link.cmd` requires an initialized MSVC x64 developer environment
with the enclave CRT/SDK. Link, run VEIID, apply the reviewed system-import
transform, then sign and inspect the final image using the
[consumer-managed signing workflow](windows-enclave-image-admission.md).
Compile an independently reviewed final-image policy into the application; file
hashing alone is not approval. Production opening requires successful trust
verification. Development tests use a private test-only constructor and public
synthetic inputs, not an application-facing weak mode.

Native developer campaigns cover all named identities, all general parameters,
bit tails, a million-byte input, retained cross-algorithm rehashing, cancellation
and abandonment in debug and release. Portable worker tests add 54,180 bit/stream
comparisons and compiled negative controls. These are author checks, not a
replacement for the candidate's pentest or final source-bound native collection.
The current development-signing attempt emitted Microsoft's VBS compatibility
warning; it is not recorded as a clean production signing result.

The [source-bound development record](../assurance/windows-protection-observations/sha2-streaming-20260930.json)
records the tested image, source hashes, test counts and qualification limits.
