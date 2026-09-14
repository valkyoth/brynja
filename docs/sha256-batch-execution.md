# Independent-message SHA-224/256 SIMD

Status: implementation candidate; exceptional owner pentest and fresh native
AMD, Intel, AWS Arm and Apple M2 qualification pending. Not independently
verified, FIPS validated, or suitable for a secret-bearing deployment profile.

## Scope and public API

The `brynja-hash-sha2` default-off `batch-execution` feature exposes `batch`.
The CPU leaf's `sha256-batch` feature owns the isolated AVX2/NEON implementations;
the hosted adapter's same-named feature provides platform selection. No external
dependency was added. Defaults and the modern facade remain portable. Legacy
SHA-1/MD5 and hardened SHA-2 never route through this ordinary batch profile.

| Surface | Contract |
| --- | --- |
| `Input::new(Algorithm, BitString)` | Per-slot SHA-224 or SHA-256, canonical MSB-first bit input |
| `[Option<Input>; 8]` | Caller-owned bounded slots; inactive holes allowed; input order retained |
| `Digest::{Sha224,Sha256}` | Distinct typed public outputs; SHA-224 uses its own IV |
| `Executor::portable()` | No probing, KAT, hardware requirement or allocation |
| `Executor::with_session(session, mode, minimum_common_blocks)` | Borrowed, non-cloneable authority; positive explicit workload threshold |
| `Executor::digest(PublicData, destination, Control)` | Whole-destination transactional output; inactive slots become `None` on success |
| `Control::new(maximum_blocks, callback)` | Cumulative finite work and cancellation; no refund after charged work |
| `Report` | Exact kernel, vector calls/useful blocks and scalar/padding blocks |
| CPU `Authority::for_compiled_target` | Safe only under the executable's complete target/deployment contract |
| CPU `Authority::from_platform` | Explicit unsafe all-schedulable-CPU lifetime contract, plus revocation callback |
| Hosted `Authority::new(Portable/Prefer/Require)` | No implicit global dispatch; only pre-execution unavailability permits prefer fallback |

PublicData is **caller-asserted classification**, not a runtime check, secret
declassification operation or promise of erasure. Do not supply keys, passwords,
HMAC/KDF intermediates or confidential messages. Ordinary arrays, schedules,
round words and staging copies are not zeroized. Existing hardened single-stream
SHA-2 APIs remain the appropriate secret-bearing API; hardened multibuffer SIMD
is outside this ordinary milestone. Lengths, activity masks and batch shape are
public. Constant-work rounds do not hide these dimensions.

## Scheduling, bounds and errors

Active slots are packed in original order into full-width groups: eight for
AVX2, four for NEON. Each eligible group must share at least the caller's positive
minimum number of complete 64-byte blocks. Common prefixes run SIMD; incomplete
groups, unequal suffixes and every padding block run portable compression.
Mixed SHA-224/SHA-256 lanes remain distinct; packed state is transposed back to
the original slot, not exposed to callers. Partial final bytes never enter a
complete-block kernel. FIPS 180-4 padding appends the separator directly after
the last valid high bit and writes the original bit length big-endian.

Require rejects before work if no group is eligible. Prefer may select scalar
for an ineligible workload, but a revoked or failed supplied authority is always
an error, even for empty/short batches. Ordinary request rejection, work exhaustion
and cancellation retain owner reuse. Backend errors, internal invariant failure,
failed startup/revalidation and recoverable unwind revoke the affected owner.
No global quarantine, reset, silent post-error fallback or partial output commit.

One scalar compression costs one budget unit; one vector call costs its number
of useful lanes. Padding is included, KAT is not. Charge/poll occurs before each
dispatch, with a final cancellation/health check before output commit. Work
already charged is not refunded, including a subsequently rejected dispatch.
Authority-local successful dispatch counters bind each reported vector call to
actual kernel dispatch and fail closed on overflow. Callbacks must not be used
to assert CPU safety; cached detection is not a live revocation mechanism.

## Hardware and performance

AVX2 needs AVX/AVX2 plus OS-enabled XMM/YMM state; NEON needs the AArch64 NEON
bundle. The compiler's baseline target remains an additional deployment
obligation. Neither uses dedicated single-stream SHA-256 instructions.
Target-specialized executables must run only on compatible CPUs. Hosted generic
x86 CPUID does not establish the migration contract and remains unavailable;
an AVX2-specialized executable can use the hosted wrapper's static route.
Allowlisted Linux/Android/Darwin/Windows AArch64 system feature APIs authorize
NEON under a conforming process-wide OS/hypervisor ABI. Hotplug or VM migration
must preserve that ABI; cached `std_detect` does not prove arbitrary migration
safety. No process affinity, memory policy or OS settings are changed.

`assurance/sha256-batch` benchmarks SHA-224 and SHA-256 at 64, 128, 1024 and
16384 bytes per lane. Seven samples compare portable batches, selected SIMD,
and dedicated-instruction sequential batches when that compiled bundle exists.
Results include actual work and no-benefit dispositions; do not generalize a
machine's speedup. The caller chooses its threshold from its workload evidence;
no heuristic based solely on vector width is installed globally. Initial local
AMD measurements show a benefit for the tested full eight-lane shapes; fresh
committed native measurements and other platforms remain pending.

## Development evidence and remaining work

- 4,096 mask/tail/length batches compared with portable SHA-2, with distinct
  messages, mixed IVs, poisoned outputs and actual AVX2/NEON execution counters.
- Independent Python SHA-2 bit oracle: 384 batches, including 128 full-width
  SIMD batches; bounded malformed input rejection in the assurance adapter.
- Packaged consumer, negative ownership/classification/unsafe-authority tests,
  compiled padding/IV/output mutants and native route-substitution tests.
- Exact kernel-body assembly checks distinguish independent SIMD from scalar
  or dedicated-instruction replacements on Linux and Apple targets.
- Budget, cancellation, revocation and unwind tests; scoped Miri/ASan, supported
  toolchains and no_std compilation belong to development verification.

Native captures are self-attested project correctness/performance evidence,
not independent cryptographic review or a physical side-channel certificate.
Registers, compiler spills, caches, crash dumps, DMA, forced termination and
caller copies are outside any complete-erasure claim. This API provides no
source-owned erasure either. Release verification uses the existing workflow;
this milestone does not change approval, detached-runner or publication policy.

Normative algorithm: [FIPS 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf),
especially sections 5.1.1, 5.3.2, 5.3.3, 6.2 and 6.3. Instruction semantics follow
Rust's [AVX2](https://doc.rust-lang.org/core/arch/x86_64/index.html) and
[AArch64](https://doc.rust-lang.org/core/arch/aarch64/index.html) intrinsic contracts.
