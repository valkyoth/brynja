# Hardened MD5 batch SIMD

Status: implemented development candidate; exceptional pentest, reviewed native
correctness evidence and final release verification pending. Not independently
cryptographically verified, FIPS validated or approved for military deployment.
MD5 is collision- and chosen-prefix-broken; use only for required legacy compatibility.

## API and selection

The default-off leaf `hardened-execution` feature exposes a distinct
`hardened_execution::{Authority, Executor, Batch, Mode, Report, Error}` API.
The optional `brynja-legacy-md5-std` feature `runtime-hardened-execution` adds
`hardened_execution::select`. No ordinary authority/session can convert into a
hardened authority, and no raw packed state/session is exported. Portable defaults
and the historical unadmitted candidate APIs are unchanged.

`Executor::portable()` never constructs an instruction authority.
`Executor::for_compiled_target(Mode::{Prefer,Require})` requires the complete
binary target bundle and an actual lane-distinct KAT through the hardened kernel.
Prefer permits missing-feature and ineligible-workload fallback only before work.
Require needs at least one full-width vector invocation. Backend failure never
silently falls back. Failed batches are consumed and quarantine their executor;
create a fresh executor for a deliberate retry after a work/cancellation error.

Each `executor.batch()` creates eight non-cloneable clearing lane owners.
`digest_public` consumes the batch and requires `PublicDeclassification`;
`digest_secret` consumes it and returns an affine `OwnedSecretRegion` spanning
the eight ordered 16-byte slots. The caller's original inputs and any copies
the caller creates remain the caller's responsibility.

## Workload and confidentiality

All eight slots keep their order. `None` is inactive; `Some(empty)` hashes an
active empty message. AVX2 executes eight independent messages and little-endian
NEON executes four. Only full-width active contiguous groups sharing complete
64-byte message blocks are vectorized. Unequal suffixes and every padding block
use the existing clearing scalar MD5 owners. Reports count actual independent
message blocks, including scalar padding. Inactive outputs are zero on success.

Lengths, slot activity, budgets, cancellation and route/work reports are public.
This API does not hide traffic length. Pad externally when dimensions are secret.
There is no secret-derived digest formatting, implicit declassification or
ordinary equality on the secret output owner. Its explicit `expose()` borrow
retains ownership; dropping that owner clears the entire output destination.

Public outputs commit only after all lanes and the final authority check succeed.
Every secret-output error, cancellation or recoverable unwind clears the whole
destination, including inactive/not-yet-written slots. Batch ownership is consumed
on every outcome; callbacks cannot reopen a finalized batch.

## Owned-region register

| Owner | Source-owned regions | Lifecycle |
| --- | --- | --- |
| Eight `Md5Owner` instances | chaining state, block/partial tail, message length, buffered count, output staging per lane | Existing non-panicking wipe from Drop |
| Private `cpu::scratch::Scratch` | initial packed states (128 bytes), schedule/message words (512), working states (128), round temporaries (96) | Whole-region wipe from Drop; failed dispatch also wipes immediately |
| Output initialization/owner | All 128 caller destination bytes | Clear on failed initialization, error, unwind and owner Drop |

Packed word storage is transposed directly from caller input and clearing lane
owners. No ordinary vector scratch or ordinary compression kernel is called.
Inactive NEON upper half-lanes remain owned and are cleared too. Generated-code
checks bind the exact field receiver, full flattening, clearing call, Drop path
and emitted SIMD instructions for compiler endpoints and abort/unwind profiles.
The abort setting is an evidence variant only; Brynja does not force it on a
consumer. Cleanup executes during recoverable unwinding, not process abort.

Registers, compiler-created copies/spills, caches, crash dumps, DMA, swap,
hibernation, caller copies, `mem::forget`, abort, power loss and forced termination
remain residual risks. Intrinsic register values are not proof of complete
physical register erasure. These guarantees do not replace platform hardening.

## Platform authority

Static AVX2 is a full binary deployment contract including OS YMM context support,
not current-core CPUID detection. Static NEON similarly requires support on every
schedulable CPU throughout the owner lifetime. Generic hosted x86 stays portable;
Require rejects it unless the complete target bundle was compiled in.

Hosted little-endian AArch64 allowlists Linux, Android, macOS, iOS and Windows
system feature ABIs, using Rust's NEON detector. Linux/Android use the platform
HWCAP contract; Apple and Windows use their platform feature-query APIs. Cached
detection is not live revocation, hotplug validation or arbitrary VM migration
proof. The deployment must preserve its advertised process-wide feature bundle.
Other platforms fail closed. Non-Send/Sync markers do not prevent OS migration.

## Acceptance and remaining release work

Development tests cover all activity masks and bit tails, exact vector/scalar
accounting, poisoned output, every work/callback failure boundary, independent
bit-level oracle batches, packaged ownership negatives and compiled mutations.
The dedicated Miri cases exercise portable owner/output lifecycle; native ASan
forces AVX2 execution and LeakSanitizer with fatal exits. QEMU is supplemental
Arm correctness, never native platform qualification.

Before tagging, obtain the exceptional independent owner retest and fresh native
AMD/Intel/AWS Arm/Apple evidence of this exact source closure. Keep the v0.24.43
cleanup finding tracked until the hardened owner/evidence retest accepts closure;
do not rewrite its historical report or extend its internal-release exception.
