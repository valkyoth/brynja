# Windows enclave four-message Keccak SIMD

With the strict facade's `acceleration` feature, `enclave::keccak_simd` exposes
the distinct version-22 four-state AVX2 worker. It supports SHA3-224/256/384/512,
SHAKE128/256 and cSHAKE128/256, including mixed identities and output sizes.
This does not change scalar defaults or provide Windows ARM64 support.

Each lane accepts a message and, for cSHAKE only, a function name and
customization. Each field is at most 1024 bytes. Partial final bytes use
low-order valid bits with zero unused high bits; empty fields require zero
valid bits. Fixed SHA-3 output sizes must match the identity. XOF output can be
0..=2048 bits per lane. This bounded batch API is not an unbounded stream.

Inputs remain borrowed caller-owned host buffers. The host validates metadata;
the enclave copies and validates the payload, including canonical bits. Results
remain in enclave storage until explicitly declassified into four 256-byte
slots in plan order, with zero padding and canonical final-bit masking.
Lengths, identities and budgets are public metadata. There is no secret host
output slice, generic callback, raw authority or silent scalar fallback.

## Example

The application supplies a reviewed image policy embedded in its trusted build
and a production-signed matching image, not a policy read from an untrusted
sidecar. The constructor cannot turn off Windows signature verification.

```rust,no_run
use brynja_strict::enclave::{Error, ImagePolicy, PublicDeclassification};
use brynja_strict::enclave::keccak_simd::{Algorithm, Input, Plan, Session, Slot};

pub fn public_batch(
    image: &std::path::Path,
    policy: &'static ImagePolicy,
    messages: [&[u8]; 4],
) -> Result<[u8; 1024], Error> {
    let mut session = Session::open_avx2(image, policy)?;
    let plan = Plan::new([Slot {
        algorithm: Algorithm::Sha3_256,
        output_bits: 256,
    }; 4])?;
    let retained = session.digest(plan, messages.map(Input::bytes), 1000)?;
    let mut output = [0; 1024];
    retained.declassify(&mut output, PublicDeclassification::acknowledge())?;
    session.close()?;
    Ok(output)
}
```

`Input::new` accepts three `Part` values for message/name/customization.
`Part::bits` records bit metadata without examining bytes on the host.
`Retained::cancel` discards results without export. Abandonment quarantines;
forgetting a handle keeps the session busy until close. Output remains unchanged
on reported export errors. Operation failures quarantine; cleanup uncertainty is
reported, not treated as successful release. With `panic = "abort"`, Drop does
not run. Feature revalidation is not a live migration guarantee.

Development-signed execution, production trust rejection and host model tests
are separate from whole-image cleanup, production deployment and independent
qualification. None constitutes certification. See the
[remaining work](windows-v02450-remaining.md) and
[deployment responsibilities](windows-enclave-deployment.md).
