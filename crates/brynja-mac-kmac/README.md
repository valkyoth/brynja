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

# brynja-mac-kmac

First-party, allocation-free `no_std` implementations of KMAC128, KMAC256,
KMACXOF128, and KMACXOF256 from NIST SP 800-185. All keyed state is owned by
Brynja's hardened cSHAKE implementation and compiler-resistantly clears every
source-declared key-derived region on success, error, cancellation, recoverable
unwind, and `Drop`.

Production constructors require keys and fixed tags at least as long as the
selected 128- or 256-bit security strength. Explicit `*_conformance` APIs retain
the complete standards-valid key and output domains while reporting weak or
short parameters as non-approved policy outcomes. All services report
`NonApproved`: Brynja has no FIPS 140-3 validation.

```rust
use brynja_mac_kmac::{Kmac128, KmacPublicDeclassification, KmacXof256};

let key = [0x42_u8; 32];
let mut state = Kmac128::new(&key, b"example protocol")?;
state.update(b"authenticated message")?;
let mut tag_bytes = [0_u8; 32];
let tag = state.finalize_tag(&mut tag_bytes)?;
assert!(tag.verify_candidate(tag.as_bytes()).expose_public());

let mut reader = KmacXof256::new(&key, b"example PRF")?.finalize_xof()?;
let mut public_output = [0_u8; 64];
reader.squeeze_public(
    &mut public_output,
    KmacPublicDeclassification::acknowledge(),
)?;
# Ok::<(), brynja_mac_kmac::KmacError>(())
```

KMAC fixed tags are opaque values without ordinary equality or formatting.
Verification uses content-independent work for the public candidate length.
KMACXOF output is secret by default: retain `KmacSecretOutput`, or provide an
explicit public-declassification authority. Callers remain responsible for
clearing key/message buffers and copies they own.

The crate does not guarantee erasure of compiler-created copies, registers,
caches, crash dumps, DMA-visible memory, swap, `mem::forget`, process aborts,
forced termination, or caller-owned copies. Platform-wide protections belong
to the separate high-assurance deployment layer planned by the repository.

## Cryptography Verification Status

| Construction | Implemented | Independently verified |
| --- | --- | --- |
| KMAC128 | ✅ Implemented | ❌ Not independently verified |
| KMAC256 | ✅ Implemented | ❌ Not independently verified |
| KMACXOF128 | ✅ Implemented | ❌ Not independently verified |
| KMACXOF256 | ✅ Implemented | ❌ Not independently verified |

Only a named independent reviewer and linked review evidence can change the
independent status. Project tests, CI, Kani, Miri, fuzzing, and pentests do not
by themselves constitute independent cryptographic verification.

The project-wide first-party-Rust, no-third-party-crates, `no_std`, 500-line
source-file, portability, and modern/legacy isolation policies apply here.
