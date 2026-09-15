# Ordinary SHA-512-family multibuffer execution

Status: development implementation; exceptional retest and fresh native
qualification are pending. Not independently cryptographically reviewed or
FIPS validated. This profile is ordinary/public-data-only and does not zeroize.
Hardened independent-message batching remains planned for v0.24.48.

## APIs and selection

Enable `batch512-execution` in `brynja-hash-sha2` for `batch512`, or
`sha512-batch` in `brynja-crypto-cpu-std` for hosted selection. Both are
default-off. The low-level `brynja-crypto-cpu/sha512-batch` feature exposes
fixed-size compression authority, not a standalone hash API.

Four caller-owned optional input slots may independently select SHA-384,
SHA-512, named SHA-512/224, named SHA-512/256, or validated general SHA-512/t.
Each slot has its own IV. General t is never implemented by truncating an
ordinary SHA-512 digest. General and named identities remain distinct even
when their output bytes agree. `Digest::algorithm()` retains identity and
`Digest::as_bytes()` exposes exactly the output width. Partial output bytes
are canonical MSB-first, with unused low bits zero.

`Input::new` accepts the existing checked canonical `BitString`. This bounded
one-shot API admits borrowed messages representable by its checked `usize`
bit count; it does not promise streaming a 2^128-bit message. Padding encodes
the exact length as a 128-bit big-endian field. Empty inputs, inactive slots,
unequal lengths and partial final bytes are supported. Inactive output slots
become `None` on success. No allocation or global dispatch is introduced.

`Executor::portable` needs no authority. `Executor::with_session` selects
`Prefer` or `Require` with a nonzero minimum common-block threshold.
The hosted `Authority::new(Mode)` makes unavailability explicit. Prefer may
select portable only for initial unavailability or ineligible groups; a KAT,
health, counter, dispatch or revalidation failure never authorizes fallback.

AVX2 compresses four independent 64-bit lanes. NEON compresses two, leaving
the other two low-level storage slots untouched. The high-level executor
groups active slots in stable input order; complete groups meeting the
threshold execute their common full 128-byte blocks together. It does not
sort or optimize arbitrary message lengths. Leftover slots, unequal suffixes
and padding are scalar. Require rejects if no vector group executes. A single
message is not advertised as independent-message SIMD.

## Public classification and lifecycle

`PublicData::new` is a caller assertion, not runtime provenance enforcement or
declassification. Every call site must be reviewed for public provenance.
Never pass keys, passwords, confidential messages, HMAC/KDF intermediates or
secret-derived state through this profile. No hardened owner routes here.
States, schedules, staging, register and compiler copies are not erased.

This remains an open design limitation of the ordinary API. Renaming a freely
constructible marker cannot prove provenance. Partial scratch wiping or
`black_box` alone would not establish compiler-resistant, complete cleanup.
The separate hardened batching milestone must cover owned state, schedules,
staging and all supported lifecycle exits; it does not turn this ordinary API
into a secret-bearing API. Review each new `PublicData::new` call site, including
the caller-asserted packed state and blocks at vector dispatch.

All caller outputs are staged and committed together after final health and
cancellation checks. Every error and recoverable unwind preserves the entire
destination, including inactive slots. A finite `Control` charges one per
scalar compression or per useful SIMD lane-block; general-t IV derivation is
also one charged scalar compression per applicable input. Startup KAT work is
excluded. Reports distinguish vector calls, useful vector blocks and scalar
blocks. Prior charges are not refunded on failure. Cancellation may occur
between blocks and before commit; finite work limits bound computation.

Routine ineligibility, work-limit and cancellation errors permit executor
reuse. Backend/invariant failures and callback unwinding permanently quarantine
the supplied authority. Authorities, sessions and borrowed executors are not
Send, Sync, Copy, Clone or Debug. Their borrowing prevents lifetime escape.

Quarantine on panic requires stack unwinding. With `panic = "abort"`, Drop does
not run: no explicit quarantine or cleanup is promised before termination.
The library does not select the application's panic profile. Process exit on
hosted targets is not memory erasure; embedded panic handlers and reset behavior
are deployment responsibilities. Never rely on an abort to clear ordinary data.

## Platform and performance boundaries

A Cargo feature does not enable AVX2 machine instructions by itself. Generic
x86 builds remain portable/Unavailable; static AVX2 requires build-wide
`-C target-feature=+avx,+avx2` and an executable deployed only on supporting
CPUs with OS-enabled XMM/YMM state. A cached current-core CPUID result alone
does not establish a lifetime migration guarantee.

Hosted NEON imports the same allowlisted AArch64 OS feature contract as the
existing SHA-224/256 batch adapter: Linux, Android, macOS, iOS and Windows,
under a conforming OS/hypervisor preserving the advertised process ABI across
scheduling/hotplug/migration. Cached detection is not a live migration monitor.
Unknown hosts remain portable or return Unavailable. Explicit unsafe platform
authority has a documented whole-lifetime obligation, never a safe boolean
override. No independent migration or machine-level side-channel claim is made.

`Authority::from_platform` is intentionally public and unsafe for external
no_std platform providers. Its private implementation module does not hide the
inherent method, and the hosted adapter is not the only permitted importer.
Making it `pub(crate)` would also prevent the separate hosted crate from using
it. Prefer the safe compiled-target or hosted constructors where applicable.
An arbitrary always-true callback is not platform attestation: an unsafe caller
must independently uphold the complete lifetime/CPU contract. Violating that
contract can execute unsupported instructions and terminate the process.

The separate ordinary single-stream execution API can use dedicated Arm
SHA-512 instructions; x86 dedicated SHA-512 is a later milestone. Native
capture measures portable, SIMD and available dedicated execution separately,
with per-workload medians and actual route counts. No universal speedup is
claimed: a no-benefit result must be retained, not hidden. QEMU execution and
assembly inspection do not substitute for native throughput or qualification.

## Development evidence

The bounded independent oracle covers 4,846 batches, including all 510 valid
t values, named IVs, all activity masks, padding boundaries and canonical bit
tails. Rust tests add rotated lane identities, failure atomicity, executor
reuse, revocation, unwind and charged IV derivation. Package-external ownership
negatives and compiled mutations test wrong IVs, padding, output commit,
no-op/scalar-substituted vector execution and counter failures.

Capture each matching native host with
`scripts/sha2/capture-sha512-batch-native.py`; records bind source hashes,
commit, compiler, platform, tests and benchmarks. Development results and
operator self-attestation must not be described as independent verification.
