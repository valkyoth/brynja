# Ordinary SHA-3/SHAKE CPU execution

v0.24.35 adds default-off `brynja-hash-sha3::execution` APIs for SHA3-224,
SHA3-256, SHA3-384, SHA3-512, SHAKE128 and SHAKE256. These are **public-data-only,
non-erasing** states. Do not use them for passwords, keys, MACs, KDFs or other
secret-derived material. Existing portable and hardened constructors are unchanged.
cSHAKE integration is v0.24.36; hardened Keccak execution is v0.24.37.

## Selecting a route

Enable the leaf's `static-execution` feature for `execution::{StaticSelection,
Mode, Kernel}`. Select `Kernel::X86Keccak` (AVX/AVX2 plus OS register state) or
`Kernel::ArmKeccak` (NEON plus Rust's full SHA3/SHA512 feature bundle).
`Portable` never probes; `Prefer` falls back only when target features are
unavailable before entry, recording `Route::StaticFallback(reason)`; `Require`
fails closed. A wrong algorithm, failed startup KAT or quarantine never falls back.
Target-specialized binaries require compatible CPUs throughout their deployment.

For hosted discovery, enable `runtime-execution` on the leaf and separately on
`brynja-crypto-cpu-std`. Create its `execution::Authority`, inspect its selection
report, and pass `Some(session)` through `Execution::from_runtime(session)`.
`None` is an explicitly reported portable selection; never map `Err` to portable.
Only documented platform-wide feature authority permits hosted execution.
Generic x86 hosted detection remains unavailable where migration safety is not
established; use a target-specialized binary when its deployment permits it.

```rust
use brynja_hash_sha3::execution::{Execution, Public, Sha3_256, Shake128};

let result = Sha3_256::hash(Execution::portable(), Public::new(b"public file contents"))?;
let mut state = Shake128::new(Execution::portable())?;
state.update(Public::new(b"public input"))?;
let mut reader = state.finalize_xof()?;
let mut output = [0_u8; 512];
let mut scratch = [0_u8; 512];
reader.squeeze_with_scratch(&mut output, &mut scratch)?;
# Ok::<(), brynja_hash_sha3::execution::Error>(())
```

Replace `Execution::portable()` with a borrowed selection's `execution()?`
or a hosted session to execute kernels. Reports preserve exact route identity
and count absorbing, padding and squeezing permutations separately. This is a
single-state vectorized Keccak permutation, **not** multi-message SIMD.

## Complete byte/bit lifecycle

All fixed identities expose `new`, `update`, `finalize`, `finalize_bits`, `hash`
and `hash_bits`, preserving their distinct digest types and FIPS 202 domains.
SHAKE exposes consuming byte/bit finalization into its corresponding reader,
one-shot caller-scratch APIs and incremental byte output. Canonical inputs use
`PublicBits::new(Fips202BitString)`, with valid bits in the low end of the final byte.
Byte inputs require `Public::new(bytes)`. Neither accepts implicit conversion:
callers must explicitly classify each input as public. These markers cannot
prove data is non-secret and do not authorize wrapping confidential inputs.
Consuming
final-bit output uses `Fips202Output` and clears unused high bits. Empty messages
and empty outputs are valid. No state reset, cloning or post-finalization reuse.

Readers' `squeeze` and `squeeze_final_bits` use 168 bytes of stack scratch.
For larger requests, use repeated byte reads or the corresponding
`*_with_scratch` method. Caller scratch must cover the destination's byte length;
safe Rust prevents overlap with that destination. Scratch may change on failure
and is not secret storage. There is no heap allocation or algorithmic limit of
168 bytes: caller-scratch operations support any representable slice size.

Every update stages public state; every read stages output and state. Checked
length/work admission, wrong operations and late backend failures leave the
public destination and retained state/report unchanged. No kernel replay or
fallible operation follows the final output commit. Even empty requests check
health. Owners/readers are thread-bound, borrowed and non-cloneable. This does
not stop OS migration; the platform/compiler deployment contract still applies.
Dropping an ordinary state cancels it but does not erase its memory.

Bit-length preflights round up to include a partial backing byte. Input and output
execution enforce the same admission bound; reported byte counts retain their
documented meaning of complete bytes, excluding the final partial byte.

## Evidence and limitations

`python3 scripts/sha3/check-sha3-execution.py` builds a downstream consumer of
Cargo package archives, runs 76 pinned NIST bit vectors and 1,008 additional
rate/bit/streaming cases, and rejects compiled output/padding/work mutations and
ownership/classification violations. Scratch exhaustion and late permutation
faults exercise failure atomicity. The native fixture is reproducible with:

`cargo run --locked --offline --release --manifest-path assurance/sha3-execution/Cargo.toml -- portable`

Modes are `portable`, `prefer`, `static` and `hosted`. Static mode requires the
matching compiler flags and actual CPU support; hosted required mode can reject
unsupported deployments. Supplemental QEMU is not native platform evidence.
The owner-supplied retest of `010fb9ba` passed at its stated Critical/High threshold.
Fresh native AArch64 static/hosted observations remain required before the final
release gate; the retest's AVX2 results do not establish native Arm correctness.
New native Mac/Arm/Intel observations follow that retest; no old
kernel-only observation is presented as a fresh run of these high-level APIs.
No named independent cryptographic verification, side-channel certification,
FIPS validation, CPU-register erasure or military suitability is claimed.
