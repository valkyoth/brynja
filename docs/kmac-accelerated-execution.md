# KMAC accelerated operations

v0.24.38 implements all four KMAC/KMACXOF execution APIs; exceptional pentest
and retest passed. Fresh three-platform native collection passed at `3578aeac`;
final scoped local release qualification passed. GitHub/CodeQL on the final
release-check commit remains required before tagging. Existing
portable family completion is unchanged. No independent cryptographic review,
FIPS validation, performance improvement or deployment approval is claimed.

Enable `hardened-execution` on `brynja-mac-kmac` for its `execution` module.
`runtime-execution` additionally accepts hosted authority sessions. Both are
default-off, first-party Rust; static execution retains `no_std`.

## Explicit selection

- `Mode::Portable` uses the erasing portable cSHAKE implementation.
- `Mode::Prefer(None)` chooses portable before key absorption.
- `Mode::Prefer(Some(session))` uses that authorized hardened Keccak session.
- `Mode::Require(None)` fails with `AccelerationUnavailable`.
- `Mode::Require(Some(session))` requires that exact session.

Acquire `KeccakSession::from_static(&authority)` from the default-off static
CPU authority, or `KeccakSession::from_runtime(session)` from the optional hosted
adapter. The authority enforces feature admission, startup KAT and quarantine.
A supplied unhealthy session always errors, including preferred mode. There
is no silent fallback after selection. `report()` reveals public route/health
only. x86 uses AVX2; Arm uses the complete admitted feature bundle. RISC-V is
not added here. CPU/VM migration stability remains a platform obligation.

## Example and API forms

```rust
use brynja_mac_kmac::execution::{Kmac128, Mode};

fn main() -> Result<(), brynja_mac_kmac::KmacError> {
    // Demonstration input only. Applications own and clear their real keys.
    let key = [0x42; 32];
    let mut mac = Kmac128::new(Mode::Portable, &key, b"application-v1")?;
    mac.update(b"message")?;
    let mut bytes = [0; 32];
    let tag = mac.finalize_tag(&mut bytes)?;
    assert_eq!(tag.as_bytes().len(), 32);
    Ok(())
}
```

`Kmac128/256` provide byte/bit constructors, streaming updates, consuming public
tags and typed-secret finalizers, cancellation and constant-work verification.
`verify_exact` rejects a protocol tag-width mismatch before output generation.
Callers must bound candidate lengths; `verify` uses the candidate length as the
SP 800-185 output domain, not as truncation of a longer tag.

`KmacXof128/256` finalize into an exclusively borrowed `Reader` for incremental
public/secret output, mixed reads and consuming final-bit output. Reader Drop
clears the original inline source; forgetting a reader cannot reopen absorption.
Partial message bits are accepted only at finalization. Bit strings use FIPS 202
LSB-first packing and output unused high bits are cleared.

Final message chunks need not be small: each complete-byte prefix is absorbed
in bulk, even when the final byte is partial. Only the following `right_encode`
trailer (at most 17 bytes) takes the misaligned byte-by-byte path. Large keys
likewise retain bulk absorption. Instrumented tests bound absorption calls;
adding alignment padding before the trailer would change the defined message.

All five owner/reader types have individual compile-fail rustdoc checks for
Send, Sync, Copy, Clone and Debug. The packaged-consumer gate independently
checks those traits plus authority, sealing and consuming/borrowed transitions.

Defaults require full-strength keys (128/256 bits) and fixed tags. Explicit
`conformance-testing` permits exact standard domains, including empty keys and
short/empty output, without an approval claim.

Public convenience output uses 168 bytes of erasing staging. Larger outputs use
`_with_scratch`; bit public forms take scratch explicitly. Scratch must cover
the complete destination and is entirely cleared, including its unused suffix,
on success, error and recoverable unwind. Public destinations are unchanged on
error. XOF public output needs `KmacPublicDeclassification`; tags are deliberately
public authenticators. Secret failures clear the entire destination. Successful
secret output remains non-Copy/non-Clone/non-formattable `KmacSecretOutput`.

## Clearing and evidence boundaries

Only hardened cSHAKE variants exist in the backend. Inline sponge, key/trailer
encoding, permutation scratch, message/output counts, phase/key classification,
comparison accumulator and output staging have clearing owners. Failure/unwind
guards cancel the source. Capabilities are sealed and owners/readers retain
authority lifetimes; none are Send, Sync, Copy, Clone or Debug.

Source-owned clearing does not guarantee erasure of registers, compiler-created
moves/copies/spills, caches, swap, dumps, DMA or hibernation. Abort, `mem::forget`,
forced termination and power loss can suppress Drop. Callers own original inputs
and exposed copies. Native tests do not prove machine-level side-channel safety.

Run `python3 scripts/kmac/check-kmac-execution.py` for independent bit-level,
streaming and output lifecycle comparisons. `--native-x86` validates AVX2 before
static execution; `--native-arm` runs hosted required mode before specializing.
The package checker rejects ownership and cleanup mutants. The codegen checker
covers MIR/LLVM/assembly on Rust 1.90.0 and 1.98.1. Miri and native ASan are
separate evidence. The [native index](../security/kmac-execution-native.json)
records fresh three-platform KMAC collection after the clean retest; older
Keccak-only artifacts were not substituted for these new keyed high-level paths.
All three platforms passed 268 cases per selected route and the actual-kernel
and clearing/quarantine tests. These are project-owned functional observations,
not independent verification or a platform-wide erasure/side-channel guarantee.
