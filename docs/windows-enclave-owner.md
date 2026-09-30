# Windows enclave owner and session API

`brynja_strict::enclave` is the supported construction and ownership interface for
the bounded Windows x64 VBS SHA-256 worker. Its implementation is integrated into
the crate, not a consumer-supplied driver. Development execution is tested;
production-signed deployment and independent qualification remain pending.
This completes the bounded SHA-256 facade integration, not all Windows work.
For full scalar SHA-2 streaming and general SHA-512/t, use the separate
[version-six SHA-2 API](windows-enclave-sha2.md) and matching worker image.
The [source-bound author results](windows-enclave-owner-results.md) describe
the tests and their limits.

## Supported operations

`Session::open` acquires one enclave using an application-reviewed, signed image
and a static `ImagePolicy` embedded in the trusted application build. `hash`
accepts at most 1024 bytes and returns an exclusive `Digest` loan. The result
stays in enclave storage. `rehash` replaces it with SHA-256 of those 32 bytes
without exporting them. `cancel` clears it; `declassify` explicitly authorizes
public output and commits the destination only after validated cleanup.

There is no generic callback, raw handle, digest token, host secret slice or
portable fallback. Sessions and digests are neither Send, Sync, Copy, Clone nor
Debug. A live digest prevents another request or closing its owner. Abandoning a
digest quarantines the owner; forgetting one leaves it Busy. `close` still owns
cleanup in either case. Successful cancellation/declassification permits reuse.

```rust,no_run
use brynja_strict::enclave::{Error, ImagePolicy, PublicDeclassification, Session};
use std::path::Path;

fn public_example(image: &Path, policy: &'static ImagePolicy) -> Result<[u8; 32], Error> {
    let mut owner = Session::open(image, policy)?;
    let result = owner.hash(b"public example")?.rehash()?;
    let mut output = [0; 32];
    result.declassify(&mut output, PublicDeclassification::acknowledge())?;
    owner.close()?;
    Ok(output)
}
```

Never acknowledge declassification merely to obtain convenient host access to a
secret result. Protect original input buffers yourself; their synchronous borrow
ends when `hash` returns. The crate does not erase application copies.

## Image deployment

Use the existing [build and signing workflow](windows-enclave-image-admission.md)
for the reviewed retained-input/rehash worker. Review its source and final signed
artifact independently of metadata emitted by inspection. After supplying an
owner-reviewed **production** policy, generate the application's Rust constant:

```sh
python3 scripts/cryptography/windows_enclave_admission.py owner-policy signed.dll reviewed-policy.json enclave_policy.rs
```

Move that generated module into the application's trusted source/build inputs;
pass `&enclave_policy::ENCLAVE_POLICY` to `Session::open`. The generator refuses
development policies, mismatched artifacts, duplicate fields and overwrites.
Generation is not signature approval. The public runtime always verifies trust.
There is no development Cargo feature or runtime bypass. Unit tests alone can
exercise the private constructor with the known development signature rejected.

The supported image has policy flags zero, one enclave thread, a 256 MiB virtual
enclave reservation and exactly the reviewed `ucrtbase_enclave.dll`/`vertdll.dll`
import identities and version floors. Paths must be bounded absolute drive paths
without reparse points. File and ancestor handles remain held until destruction;
the complete signed artifact hash, PE identity and imports are checked before
loading. Windows signature/revocation failure, including missing trust data,
rejects. Successful loading is insufficient: initialization must also succeed.
The implementation links only Windows OS libraries, not a native crypto library.

The current worker retains its versioned experimental metadata exports internally.
They are not Rust application APIs: the private adapter validates every receipt,
range and operation before changing the public lifecycle state. Publishers must
review this exact worker/protocol; an unrelated DLL is not compatible merely
because it exports similarly named functions. The trusted complete-file policy
is essential. This interface is not remote attestation against a hostile host.

## Failure and protection limits

Ordinary oversized requests reject without damaging a ready owner. Protocol,
residency or backend failures quarantine it. Public output is transactional.
Host input/output registrations are revoked before borrowed buffers expire,
including recoverable unwinding. Failure to confirm revocation aborts the
process rather than returning with dangling host addresses. Uncertain clearing
or enclave destruction retains the mapping and file guards; it never substitutes
unlocking/freeing for clearing. Use explicit `close` to observe release errors.
Forgetting the owner leaks resources; applications must bound their session pool.

Only native Windows x64 MSVC is implemented here. Other targets and verification
models return Unsupported. The existing Linux protected host-slice APIs remain
separate. Windows Arm, other algorithms, streaming/large inputs, batching,
hardware/SIMD routes and general worker concurrency are not supplied by this API.
No acceleration is selected by adding the facade's acceleration feature.

The native author tests use public synthetic inputs on a development-signing
Azure VM. They do not establish production signing, arbitrary dump/snapshot or
hibernation protection, fatal-abort erasure, caller-register clearing, or any
certification. Earlier dump observations do not automatically qualify this newer
host integration. Full platform/compiler review, native qualification and the
candidate's pentest remain required under the unchanged release process.
