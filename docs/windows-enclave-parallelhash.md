# Windows enclave ParallelHash sessions

The sequential scalar `brynja_strict::enclave::parallelhash` API binds a
version-twelve worker to the existing production image/signature policy. The
lower-level hosted crate requires `strict-sha2,strict-sha3`. Unsupported platforms
reject construction; no ordinary-memory fallback or development-signature switch
is exposed. Production qualification, acceleration and multicore scheduling
remain separate. The worker uses existing first-party hardened cSHAKE states,
not another permutation implementation.

## API example

Create a Session using the reviewed consumer image policy and the
[build/sign/load workflow](windows-enclave-image-admission.md). Then:

```rust,no_run
use brynja_strict::enclave::{parallelhash::{Algorithm, Bits, Session},
    Error, PublicDeclassification};

pub fn parallel_example(session: &mut Session) -> Result<[u8; 32], Error> {
    let empty = Bits::new(&[], 0).map_err(|_| Error::Bounds)?;
    let mut stream = session.stream(Algorithm::ParallelHash128, 8, empty, 3)?;
    stream.update(b"abc")?;
    let retained = stream.finalize(empty, 32, 8)?;
    let mut output = [0; 32];
    let _ = retained.declassify(&mut output, PublicDeclassification::acknowledge())?;
    Ok(output)
}
```

`Session`, `Stream`, `Reader`, `Retained` and `Finalized` are neither Send, Sync,
Copy, Clone nor Debug. Dropping an unfinished loan quarantines its session;
forgetting one leaves the session busy. Explicit cancellation permits reuse only
after the worker confirms cleanup. Closing destroys even forgotten worker state.
The public lifecycle does not expose private accumulated lengths or XOF positions.

## Algorithm and storage contract

The four identities are ParallelHash128/256 and ParallelHashXOF128/256. Framing
follows [NIST SP 800-185, section 6](https://doi.org/10.6028/NIST.SP.800-185):
`left_encode(B)`, ordered 256/512-bit leaf chaining values, `right_encode(n)` and
`right_encode(L)` (zero for XOF), with the root function name `ParallelHash`.

`B` is a positive `u64` byte count. The component streams one leaf at a time,
without allocating a B-byte buffer. A leaf crossing a request boundary remains
inside the owner. Customization is exact-length and bit-streamed; message updates
are bytes with one canonical low-bit-first final tail. Every request carries at
most 1024 payload bytes. A public budget counts supplied customization/message
bytes, including partial bytes. Internal checked `u128` input/leaf counters are
private and clearing; no public accumulated-length preflight API is exposed.

Before finalizing the root, a separate completion check recomputes the expected
leaf count from total input bits and B. All partial input must be consumed and
the completed count must match exactly. An empty input has zero leaves, not an
extra empty leaf. Final partial leaves preserve their exact bit width.

Fixed output is retained up to 1024 bytes with an exact final-bit shape. XOF
output can span multiple retained fragments; nonterminal fragments are byte
aligned and a terminal fragment may end in a partial byte. Even empty output
requires the appropriate state transition. Export consumes one exact declared
fragment through a private trusted OS-copy seam, not an application callback.

`Retained::rehash` consumes the exact retained bits as a complete new message,
with a new identity, positive B, streamed customization and byte budget. It
discards any prior XOF reader without exporting its output. Fixed destinations
declare their output shape; XOF destinations use `(0, 0)` and return a Reader.
No additional message bytes can be appended to that already-complete message.
The budget includes the retained message bytes as well as customization bytes.

## Request and lifetime boundary

| Operation | Meaning |
| --- | --- |
| 100 | Begin identity, B, declared customization bits and input budget |
| 101–102 | Supply customization fragments and require exact completion |
| 103–104 | Update message and finalize its exact tail/output domain |
| 105 | Retain one XOF fragment |
| 106 | Explicitly export the exact retained fragment |
| 107 | Cancel and clear, permitting reuse only after success |
| 108 | Rehash retained exact bits under a new identity/B/customization domain |

The 112-byte header binds version, sequence, identity, B, budget, customization
length, payload and output shapes, terminal flag and source address. Reserved or
irrelevant fields must be zero. The worker validates it before bounded payload
copying. Sequences cannot wrap or replay. Copy/protocol/algorithm errors and
recoverable unwinding clear owned state and quarantine the component. Fatal
abort does not imply destructor cleanup.

The one-thread placement entry requires one aligned, resident 4096-byte owner
page and the existing protected stack window. Destruction ends the typed
lifetime before clearing the complete page, including inactive enum storage and
padding. Root, leaf, chaining-value scratch, encodings and counters are retained
or cleared within that boundary. This does not establish arbitrary register,
caller-frame, signal, snapshot or fatal-abort erasure. Caller buffers remain
outside enclave protection.

## Build and author checks

```sh
python3 scripts/cryptography/test-windows-enclave-parallel-stream.py
python3 scripts/cryptography/test-windows-enclave-parallel-stream.py --miri-toolchain nightly-2026-09-11
python3 scripts/cryptography/windows_enclave_parallel_stream_build.py worker-build --image
```

The generated `link.cmd` requires the existing MSVC enclave/SDK environment and
runs VEIID. Build success alone is not image admission; future consumers must use
the [existing reviewed image/signing workflow](windows-enclave-image-admission.md).

Author tests include 332 independent bit cases, with the oracle cross-checked
against all 12 retained NIST samples; B/input boundaries, fragmented long
customization, zero and partial output, incremental XOF, budgets, exact leaf
completion, cleanup, cancellation, replay and wire validation. Mutation tests
exercise framing and lifetime checks. Placement tests include active state,
wrong-page rejection, whole-page clearing and recreation.

The earlier [source-bound component observation](../assurance/windows-protection-observations/parallel-component-20260930.json)
records thirteen tests passing locally and in an ordinary Windows process,
24 compiled component/wire mutants and two placement mutants rejected. Seven
focused Miri checks cover placement, each identity's copy-failure/unwind/cancel
lifecycle, exact completion/overflow and malformed copied payloads. The combined
lifecycle test exceeded the existing runner timeout, so those same assertions
are split into four identity-specific tests; none were removed. Scoped Clippy,
formatting, metadata and repository policy checks pass.

The Windows unsigned worker build links and passes VEIID. All 171 captured source
hashes match the local tree, and final clean executables are verified after the
mutation campaign. Sources, images, passing logs and superseded failed logs are
saved locally outside `target/`. The Windows machine uses source overlays rather
than an exact Git checkout. No ParallelHash image was signed or executed inside
the enclave during this component pass.

The subsequent [host integration observation](../assurance/windows-protection-observations/parallel-owner-20260930.json)
records successful native development VBS debug/release runs: 332 direct oracle
cases and 256 retained-to-retained cases in each profile. All four source and
destination identities and every valid partial-byte output shape participate in
the composition campaign. Seven host tests pass normally and under Miri; 25
negative ownership doctests and the packaged example pass. The packaged strict
facade rejects 435 ownership/export probes. Sixteen component tests pass with
31 compiled component/encoder mutants, two placement mutants and eight focused
Miri checks. The shared native stream and batch campaigns also pass.

All 535 captured native source/manifest hashes match. Sources, host binaries,
worker images and logs are preserved outside `target/`. The developer signer
reported successful signing with an SDK compatibility warning and a nonzero
wrapper result; the resulting image ran successfully in the explicitly private
test constructor, which requires rejection by production signature verification.
Temporary signing certificates/private keys were removed. Secure Boot was
disabled on this development server; no production-signing qualification follows.

## Still to implement or qualify

Host ownership/receipt integration and retained secret-to-secret composition are
implemented. Their current-image native observations and qualification must not
be inferred from the earlier component-only record. The component is sequential
scalar execution: it does not deliver multicore
scheduling, concurrent leaf ownership or hardware/SIMD acceleration. Those paths,
compiler/register cleanup, current-image dump experiments, independent review
and production deployment remain separately pending. Existing historical VBS
results do not automatically qualify this new image. Release gates are unchanged.
