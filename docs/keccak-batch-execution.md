# Ordinary Keccak multibuffer execution

Status: v0.24.47 implementation in development; native qualification and
exceptional pentest pending. Not independently verified or FIPS validated.

## API and feature boundaries

| Crate / feature | API | Purpose |
| --- | --- | --- |
| `brynja-crypto-cpu` / `keccak-batch` | `keccak_batch::{Authority, Session, Kernel}` | Raw independent-state permutation |
| `brynja-hash-sha3` / `batch-execution` | `batch::{Input, Algorithm, Executor, Workspace, Control}` | Complete bounded hash/XOF batches |
| `brynja-crypto-cpu-std` / `keccak-batch` | `keccak_batch::Authority` | Optional hosted selection and borrowed executors |

All features are default-off. The leaf is allocation-free `no_std`; the hosted
adapter is optional. Existing ordinary and hardened constructors stay unchanged.
The eight batch identities are SHA3-224/256/384/512, SHAKE128/256 and cSHAKE128/256.
Fixed SHA-3 requests require exactly their digest width. XOF output is finite,
including zero bits. `Fips202BitString` rejects noncanonical input high bits;
batch output clears unused high bits. cSHAKE accepts bit-oriented N and S;
empty N/S is SHAKE-equivalent, and nonempty N/S is rejected for other identities.

AVX2 handles four **independent states**; NEON handles two. Unlike the existing
single-state Keccak acceleration, lanes here belong to different messages.
All eight identities use the same Keccak-f[1600] permutation, so ready states
with different rates, suffixes or lengths can share a vector call without
sharing framing. Each retains its own input cursor and squeeze position.
Incomplete groups and exhausted lanes use scalar tails; inactive raw NEON
slots remain untouched. Output order always matches the supplied input order.
This does not construct a ParallelHash tree or start threads.

## Calling and scratch ownership

Use `Input::new` for SHA-3/SHAKE and empty-domain cSHAKE, or
`Input::with_customization` for explicit cSHAKE N/S. A call accepts zero to four
inputs, one exact-sized destination for each, a caller-owned `Workspace`, and
staging of at least the sum of requested output byte lengths. Larger workloads
use repeated bounded calls. Workspace and staging are reusable scratch and
may change on failure; all destination slices remain unchanged on every returned
error. Rust exclusive borrowing prevents aliasing destinations with input or
scratch. Partial output is never exposed as a successful digest.

`Control` supplies a finite cumulative permutation budget and cancellation
callback. Each independent state permutation costs one, including cSHAKE
prefixes, padding and extra squeeze blocks. Vector calls cost their width;
failed/cancelled calls do not refund charges. Shape/length/destination checks
precede hashing. A final cancellation and health check precedes output commit.
Normal cancellation, exhausted budgets and invalid requests preserve executor
reusability. Backend/invariant failures, revalidation failure and unwinding
quarantine supplied authority permanently; they never authorize silent fallback.
With `panic = "abort"`, Drop does not run and quarantine is not promised.
The crate does not select a consuming application's panic strategy.

`Mode::Portable` never probes. `Prefer` uses eligible complete groups and scalar
tails. `Require` rejects a workload lacking a complete eligible group but still
allows scalar tails after real vector execution. `minimum_permutations` is an
explicit per-lane workload threshold selected from caller measurements, not an
automatically claimed universal performance crossover. Reports distinguish
actual vector calls, vector state permutations and scalar state permutations.

## Platform authority

Static AVX2 requires build-wide `+avx,+avx2` and OS-enabled XMM/YMM context;
NEON requires AArch64 `+neon`. The Cargo feature alone does not set compiler
features. Every CPU on which the specialized executable runs must support its
bundle for the owner's lifetime, including hotplug and migration.

The hosted adapter follows existing batch selection: generic x86 detection does
not establish a lifetime-wide migration proof, so it stays portable/unavailable;
specialized x86 builds can use their target contract. Allowlisted AArch64
Linux/Android/macOS/iOS/Windows feature APIs are trusted under their conforming
OS/hypervisor process ABI. Cached detection is not live revocation. External
`no_std` providers may use the intentionally public **unsafe** `from_platform`
constructor, accepting its complete feature/OS/lifetime safety obligation.

Each authority runs a direct real-vector startup KAT, checks health before and
after dispatch, stages state updates, and checks its diagnostic counter before
commit. Owners and sessions are non-Send/non-Sync/non-cloneable. These operational
capabilities do not change historical candidate-admission decisions or confer
independent cryptographic verification, FIPS validation, or migration evidence.

## Public-data limitation

`PublicData` is a caller assertion, not provenance enforcement or declassification.
Review every new `PublicData::new` call site for public provenance. No inputs,
states, vector temporaries, workspace, output staging, outputs or platform copies
are zeroized. Do not use these APIs for keys, passwords, KMAC/KDF intermediates,
or other confidential material. All lengths and batch shape are public.
Hardened batching belongs to v0.24.48, not a partial wipe in this ordinary API.

## Evidence status

Development checks include independent bit-level differential comparisons,
packaged downstream compilation, ownership negatives, output/algorithm mutants,
native local AVX2 and supplemental emulated NEON comparisons. Scalar-reference
checks alone cannot qualify hardware; QEMU is explicitly not native evidence.
The exact AVX2/NEON multibuffer symbols are inspected in x86-64 Linux,
AArch64 Linux and Apple AArch64 emitted assembly, with instruction-removal and
unrelated-symbol regression checks. These establish vector-code presence, not
machine-level constant-time or erasure guarantees. The batch budget proof is
wired into the existing SHA-3 Kani family; focused Miri ownership/error checks
and actual-kernel ASan with forced LeakSanitizer use that family's existing
verification workflow. Approval and publication policies are unchanged.

The standalone `assurance/keccak-batch` fixture accepts `prefer --benchmark`
after `cargo run --locked --offline --release --manifest-path
assurance/keccak-batch/Cargo.toml --`. The 128-case matrix covers all eight
identities, one to four active lanes, empty/rate-sized/4 KiB/16 KiB messages,
unequal lengths and finite multi-block partial-bit XOF output. Seven paired
samples alternate portable/selected ordering; medians exclude allocation and
output comparison. Destinations start guaranteed incorrect on each sample and
all measured outputs must match the portable reference. Reports expose actual
vector calls. No speedup or automatic threshold is inferred from a single run;
collect on an otherwise idle target before choosing a workload threshold.

Use `scripts/sha3/capture-keccak-batch-native.py` with an explicit native lane,
new output JSON path and `--attest-native`. Capture requires a clean committed
checkout, exact source review, matching compiler/CPU/OS, packaged independent
oracles, actual-kernel markers, codegen and the complete benchmark matrix.
Artifacts are operator-self-attested, not authenticated platform certification.
Fresh Linux x86-64, Linux AArch64 and Apple AArch64 correctness/performance
collection and exceptional review remain required before
this milestone may be described as qualified. Existing single-state native
evidence does not qualify these new multibuffer kernels.
