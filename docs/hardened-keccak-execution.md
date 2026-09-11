# Hardened Keccak execution

Status: v0.24.37 implementation, focused assurance, exceptional retest and
three-platform native collection complete; final release verification is pending.

The default-off `hardened-execution` feature in `brynja-hash-sha3` exposes
`hardened_execution::{Sha3_224, Sha3_256, Sha3_384, Sha3_512, Shake128,
Shake256, Cshake128, Cshake256}`. Constructors take a
`brynja_crypto_cpu::hardened_execution::KeccakSession`, never ordinary execution
authority or a public-data marker. Existing portable hardened types remain
unchanged. Static sessions require the complete compiler target-feature bundle;
runtime sessions require the existing explicit platform authority. Neither
Cargo feature selection nor a thread-bound type alone establishes CPU support
across scheduling or VM migration.

## Ownership and failure

The CPU session owns seven erasing aggregate scratch regions: lanes, columns,
theta, rearranged lanes, current vector, next vector and following vector.
Hardened entry executes its own zero-state KAT. Caller state is committed only
after successful permutation; scratch clears on success, error, recoverable
unwind and Drop. An interrupted kernel operation quarantines its authority.
Private scratch reads, writes and chi coordinates return a typed error on an
invalid index. Such an invariant failure clears scratch, quarantines authority
and preserves caller state; it cannot silently substitute zero or skip a write.
The new kernels use AVX2 or AArch64 SHA3 instructions for chi, with scalar
theta/rho/pi over owned scratch. A speedup is not claimed before measurement.

High-level owners additionally clear sponge lanes, input/output counters,
suffix staging and output staging. No ordinary sponge or ordinary permutation
handles their secrets. Fixed finalization consumes the owner. XOF finalization
offers a consuming reader or an in-place absorbing-to-squeezing transition;
in-place owners reject further absorption and become terminal after final-bit
output or cancellation. Operational errors clear the owner and do not silently
fall back to portable hashing.

Public output requires `Sha3PublicDeclassification`. The convenience reader
stages at most 168 bytes; larger transactional public reads require caller-owned
scratch, which is itself treated as secret and completely cleared on every exit.
Secret output uses the existing non-cloneable `HardenedSha3SecretOutput` owner:
the entire destination clears on error or when the returned owner is dropped.
Original caller inputs and copies made by callers remain caller responsibilities.

These movable owners do not promise erasure of compiler-created copies, spills,
registers, caches, crash dumps, swap, DMA-visible storage, or physical remnants.
Drop cannot cover `mem::forget`, abort, forced termination or power loss.
This work is not independent cryptographic review or FIPS validation.

Control flow and memory access depend on public message/output lengths and
algorithm identity. These APIs do not conceal lengths. Counter bytes are still
cleared; rate, position and phase metadata do not receive a secrecy guarantee.
The supplemental exact owner register is
[`security/keccak-hardened-reviewed.json`](../security/keccak-hardened-reviewed.json),
enforced separately from the existing portable FIPS 202 owner register.

## Selecting and using the API

Enable `hardened-execution` on the SHA-3 leaf and CPU crate. For a deliberately
target-specialized x86 build, compile for `+avx2`; for Arm, use the complete
`+neon,+sha2,+sha3` bundle. Never deploy a specialized binary onto unsupported
CPUs. Creating a static authority fails when the required features were not
compiled. Cargo features alone do not authorize CPU instructions.

```rust
use brynja_crypto_cpu::static_execution::{Authority, Kernel};
use brynja_hash_sha3::hardened_execution::{Error, KeccakSession, Sha3_256};

fn main() -> Result<(), Error> {
// Select ArmKeccak instead on a qualified target-specialized Arm deployment.
let authority = Authority::new(Kernel::X86Keccak).map_err(Error::Backend)?;
let session = KeccakSession::from_static(&authority).map_err(Error::Backend)?;
let mut hash = Sha3_256::new(session)?;
hash.update(b"caller-owned input")?;
let mut destination = [0_u8; 32];
let digest = hash.finalize_secret(&mut destination)?;
let digest_bytes = digest.expose(); // borrowed secret, not a public declassification
assert_eq!(digest_bytes.len(), 32);
drop(digest); // clears the complete destination
Ok(())
}
```

For hosted Arm, enable `runtime-execution` as well and obtain an existing
`brynja_crypto_cpu_std::execution::Authority` with `Mode::Require`. Pass its
checked session to `KeccakSession::from_runtime`; never construct feature
attestations from guessed flags. Hosted x86 still requires a deployment-specific
migration authority and is not silently enabled by this work.

SHAKE/cSHAKE support streaming `update`, consuming `finalize_bits_xof`, and
incremental reader output. cSHAKE `new_bits` accepts canonical arbitrary-bit
function names and customization. `enter_squeezing_in_place` and the
`squeeze_*_in_place` methods retain the original erasing source for future keyed
composition. Final-bit reads terminate the source. An invalid phase, backend
failure or failed output operation permanently terminates that owner.

## Current verification and remaining work

Development checks have passed native AMD AVX2 and emulated AArch64 kernel
comparisons, high-level portable equivalence at byte/bit and rate boundaries,
output ownership, cancellation, late-error cleanup, unwind guards, targeted
AddressSanitizer, initial Miri memory-region checks, Rust 1.90 compilation and
bare-metal no_std compilation. QEMU is not native platform evidence.

Packaged debug/release tests reject 54 ownership/classification bypasses.
Eleven source-owned regions have live destructor probes and 22 compiled
region-removal mutants. MIR/LLVM/assembly checks cover compiler endpoints
1.90.0 and 1.98.1; explicit native AVX2 ASan executes the real kernels.
Miri checks owned-memory clearing, not architecture intrinsics. Cross-crate
unwind edges remain in emitted code; no compiler-proven `nounwind` claim is made.
Affected repository checks supplement these focused campaigns; final release
verification is separate and follows the exceptional retest and native collection.
Fresh hardened Keccak and refreshed hardened SHA-2 captures passed on Intel Xeon
Platinum 8488C, AWS Arm Neoverse-V1 and Apple M2 Pro at commit
`463ebf9a37ac61f7be89f1efa5fd4bd71f6e0696`. Reviewed records are indexed in
[`security/keccak-hardened-native.json`](../security/keccak-hardened-native.json)
and [`security/sha2-hardened-native.json`](../security/sha2-hardened-native.json).
These are project-owned functional/lifecycle observations, not independent review,
side-channel approval or proof of safety across every CPU/VM migration. Previous
ordinary Keccak captures are not reused as hardened evidence.

The packaged native campaign also executes a bounded operation-sequence property
test for SHAKE128/256 and cSHAKE128/256. It varies input data, one-byte and irregular
updates, empty operations, partial message/customization/output bits, repeated
phase transitions, cancellation, and mixed public/secret reads across rates.
Successful output is compared with the separate portable implementation; errors
must clear secret destinations, preserve public destinations and remain terminal.
The normal campaign uses seed 17037 and 64 scenarios per identity in debug/release;
the native artifact validator requires its execution marker, not only a compiled test.
This is reproducible randomized property testing, not coverage-guided fuzzing or
proof of all possible sequences. For a longer local run on an AVX2-capable host:

```sh
BRYNJA_KECCAK_PROPERTY_SEED=17037 BRYNJA_KECCAK_PROPERTY_CASES=4096 RUSTFLAGS="-C target-feature=+avx2" cargo +1.98.1 test --locked --offline --release -p brynja-hash-sha3 --features hardened-execution --test hardened_execution replayable_operation_sequences -- --nocapture
```

Use `-C target-feature=+neon,+sha2,+sha3` only on a qualified Arm host. Seeds are
nonzero u64 values; case counts are bounded to 1..=65536. Failures print seed/case
for replay. Longer campaigns stay local/native rather than extending ordinary CI.
The existing all-feature workspace CI test executes CPU doctests, including the
Keccak non-Send/non-Clone checks. Separately, the repository gate compiles the
54 packaged ownership negatives, covering Send, Sync, Copy, Clone and Debug.

Capture with `python3 scripts/sha3/capture-keccak-hardened-native.py LANE OUTPUT --attest-native`
from a clean committed checkout, using `linux-x86_64`, `linux-aarch64` or
`apple-aarch64`. Fetch the locked dependencies first. The JSON records exclude
hostnames and need separate owner review. The tag gate requires all three
committed records and rejects changed tested sources or missing execution.
