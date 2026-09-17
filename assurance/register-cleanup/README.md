# Register-cleanup development checks

Development assurance code, **not complete release evidence**.
The owner requested register-remanence remediation across the hardened backends
before another pentest. SHA-224/256 (single-state and batch), SHA-512 and
single-state Keccak use this boundary in production;
the fixture directly includes their actual private source files, rather than
testing duplicate implementations. Other ports and native qualification remain
pending. Release gates are unchanged. Finding F1 remains open.

## Intended boundary

On normal return from a qualified kernel, that kernel's temporary secret values
must not remain in its working registers or compiler-generated stack spills.
Caller-owned input, output, and pre-existing caller register contents are not
erased. This is a kernel-boundary guarantee, not an end-to-end promise covering
all callers, framing, output conversion, or the whole process.

Each kernel boundary keeps **all secret loads and computation inside one opaque,
side-effecting assembly block**. Only pointers enter; no secret Rust values
leave. The block uses fixed, reviewed memory bounds, no stack, no calls, and
only public loop counters. It clears non-output scratch and every working register
before leaving. Thus the compiler cannot spill an intermediate that it never
receives. This avoids adding a broad register clobber to the existing intrinsic
code, where live values could instead be moved to untracked spills.

The compiler still owns ABI preservation of pointer-bearing and pre-existing
caller registers. The emitted prologue/epilogue is checked separately. Windows
XMM6–15 must be preserved, not indiscriminately wiped. X86 SHA-512 uses volatile
YMM0–2; SHA-224/256 uses XMM0–3 and does not require AVX or SSE4. It clears the
128-bit working lanes, not pre-existing upper-vector caller contents. See the [Rust assembly contract](https://doc.rust-lang.org/reference/inline-assembly.html)
and [Windows x64 ABI](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention).

Asynchronous interruption can capture secrets **during** computation, before
cleanup. Signals, core dumps, abort, physical registers/caches, swap and OS
copies remain outside this normal-return contract. No FIPS, military suitability
or independent verification claim follows from these tests.

## Current implementation-author checks

| Candidate | Algorithm execution | Return-register observer | Production integration |
| --- | --- | --- | --- |
| x86 SHA-224/256 | Native Linux SHA-NI, 1,024 arbitrary state/block pairs per positive run | Seven integer registers plus four XMM registers; Win64 XMM6–15 canaries | Integrated; remaining native qualification pending |
| Arm SHA-224/256 | QEMU, 1,024 arbitrary state/block pairs per positive run | Five integer registers plus six vector registers; D8–15 caller canaries | Integrated; native qualification pending |
| Dedicated x86 SHA-512 | Intel SDE, 1,024 arbitrary state/block pairs per positive run | Seven integer registers plus three complete YMM registers | Integrated; native qualification pending |
| Arm SHA-512 | QEMU, 1,024 arbitrary state/block pairs per positive run | Five integer registers plus thirteen vector registers; D8–15 caller canaries | Integrated; native qualification pending |
| x86 single-state Keccak | Native Linux AVX2, 1,024 arbitrary states per positive run | Four integer registers plus four complete YMM registers; Win64 XMM6–15 canaries | Integrated; remaining native qualification pending |
| Arm single-state Keccak | QEMU, 1,024 arbitrary states per positive run | Five integer registers plus four vector registers; D8–15 caller canaries | Integrated; native qualification pending |
| x86 SHA-224/256 batch | Native Linux AVX2, 1,024 independent batches per positive run | Three integer registers plus four complete YMM registers; Win64 XMM6–15 canaries | Integrated; remaining native qualification pending |
| Arm SHA-224/256 batch | QEMU, 1,024 independent batches per positive run | Three integer registers plus four vector registers; D8–15 caller canaries | Integrated; native qualification pending |

The scalar schedule and feed-forward also live inside the block; this is not
merely a `vzeroupper`/`vzeroall` epilogue. The ordinary implementation is not
changed. No native dedicated-SHA512 machine has been used for this experiment.

`check.py` checks Rust 1.90.0 and 1.98.1, debug and release, for Linux, Apple x86,
and Windows x86 (GNU at the MSRV, MSVC at the current compiler). Cross-compiling
is not native platform execution. The Linux/SysV observer is an assembly call
site that snapshots registers immediately on return, before Rust can overwrite
them. Windows and Apple native observers remain pending. `check_arm.py` checks
Linux, Apple macOS/iOS and Android at both endpoints, plus Windows Arm at 1.98.1.
The Arm observer and guarded-page tests execute under QEMU, not native hardware.

The compiled mutation campaign poisons each working register before cleanup,
then independently removes its erasure. Separate mutations remove scratch
clearing or corrupt the final lane ordering. Positive poisoned controls must
still pass. Compiler-check mutations inject spills and loads before/after the
opaque boundary. These tests exercise the eight production kernels, not a complete
production qualification or a general assembly verifier.

The Linux bounds test also places each input, state, scratch and constants at
either edge of a writable page, with inaccessible neighboring pages (all sixteen
placement combinations). Input and constants pages become read-only before the
call. This supplements sanitizers, which cannot instrument loads and stores
inside opaque assembly.

SHA-224/256 also tests all fifteen nonzero byte offsets for input/state/scratch,
with u32 constants deliberately offset by four bytes from vector alignment.
Sentinels verify the inactive state half, caller input and surrounding storage
remain unchanged. The independent scalar reference uses only the first 64 input
bytes and 32 state bytes; sharing round constants does not share its recurrence.

Keccak uses an independent coordinate oracle generating rho offsets and round
constants, cross-checked against the zero-state known answer. Its Linux bounds
test covers four scratch/constants placements with read-only constants and
inaccessible neighbors, plus 31 unaligned scratch placements with sentinels.
Compiled mutations remove individual register wipes or scratch clearing and
corrupt theta, rho, chi or iota. These must fail in execution, not compilation.
The production layout assertions are also mutation-tested: no dynamic indexed
scratch helper remains, so the former silent-index tests are superseded by
exact-layout rejection, fixed-offset bounds and algorithm mutations.

SHA-224/256 batching tests eight AVX2 lanes or four NEON lanes against a
separate scalar compression oracle. The 2,752-byte scratch view retains only
packed output at 2304..2560; both other intervals are cleared. Inactive Arm
output halves are zero even when unused input capacity is poisoned. Four guarded
placements and 31 unaligned placements check bounds; constants need only u32
alignment. Thirteen x86 and fourteen Arm negative mutation classes remove wipes
or corrupt schedule/round/feed-forward/lane behavior. High-level packing and
output transfer are not part of this normal-return kernel contract.

Run with an already licensed, verified Intel SDE executable:

```sh
python3 assurance/register-cleanup/check.py --sde /absolute/path/to/sde64 --mutations
python3 assurance/register-cleanup/check_arm.py --qemu --mutations
python3 assurance/register-cleanup/check.py --sha256 --native --mutations
python3 assurance/register-cleanup/check_arm.py --sha256 --qemu --mutations
python3 assurance/register-cleanup/check_keccak.py x86 --execute --mutations
python3 assurance/register-cleanup/check_keccak.py arm --execute --mutations
python3 assurance/register-cleanup/check_keccak.py x86 --sha256-batch --execute --mutations
python3 assurance/register-cleanup/check_keccak.py arm --sha256-batch --execute --mutations
cargo clippy --locked --offline --manifest-path assurance/register-cleanup/Cargo.toml --all-targets -- -D warnings
cargo clippy --locked --offline --manifest-path assurance/register-cleanup/Cargo.toml --features batch256-probe --all-targets -- -D warnings -A clippy::chunks_exact_to_as_chunks
```

A generic `cargo test` explicitly ignores the instruction execution test. It
must not be cited as evidence that SHA instructions or erasure executed.
`--native` accepts only the SHA-224/256 lane and checks every reported Linux CPU
for SHA-NI/SSE2 before executing. It is development testing, not a migration proof.

The `win64-probe` fixture-only feature selects the Windows x64 observer. The
driver changes only the function ABI in a temporary copy of the production
source so the SDE/native campaign can execute that calling convention on Linux. A
function-pointer type check rejects enabling this observer against a SysV
function; use the driver, not a bare `cargo test --features win64-probe`.
Its observer
also seeds XMM6–15 and verifies their preserved lower halves on return. This is
not native Windows evidence and does not change any shipped Cargo feature.

## Native Windows collection

Windows evidence is useful and is **not interchangeable with Linux evidence**.
The existing Windows CI workspace tests are not native qualification of every
accelerated kernel. Once the ports are ready, collect a Windows x64 MSVC lane
covering actual selected instructions, immediate return-register observations,
callee-saved registers, recoverable unwinding/cleanup, quarantine, and packaged
consumer behavior. Record source revision, OS, compiler, CPU feature bundle and
actual route. Verify feature support before executing a specialized build.

Do not infer dedicated SHA512 support from SHA-NI, AVX2, AVX-512 or an AWS family
name. SDE remains emulation if the Windows host lacks the dedicated instruction.
A Windows x64 run does not qualify Windows Arm, and a single host does not prove
arbitrary VM migration safety. Existing platform-authority restrictions remain.
This planned collection does not add or alter a release-gate mechanism.

## All-backend implementation inventory

No row below is complete merely because the SHA-512 prototype passes.

| Hardened kernel family | x86 implementation to replace/review | Arm implementation to replace/review | Status |
| --- | --- | --- | --- |
| SHA-224/256 instructions | `x86_sha::secret::compress` | `aarch64_sha2::secret256::compress` | Integrated; native x86 and emulated Arm checks; full native qualification pending |
| SHA-384/512 and SHA-512/t instructions | `x86_sha512::secret::compress` | `aarch64_sha2::secret512::compress` | Integrated; source-bound emulated checks; native qualification pending |
| Keccak single state | `x86_avx2_keccak::secret::permute` | `aarch64_sha3_keccak::secret::permute` | Integrated; native x86 and emulated Arm checks; full native qualification pending |
| SHA-224/256 batch | `sha256_hardened_batch::x86` | `sha256_hardened_batch::arm` | Pending |
| SHA-512-family batch | `sha512_hardened_batch::x86` | `sha512_hardened_batch::arm` | Pending |
| Keccak batch | `keccak_hardened_batch::x86` | `keccak_hardened_batch::arm` | Pending |
| Legacy SHA-1 | `x86_sha1::compress_secret` | `aarch64_sha1::compress_secret` | Pending |
| Legacy MD5 batch | `cpu::x86_secret::compress_secret` | `cpu::arm_secret::compress_secret` | Pending |

This is sixteen existing hardware/SIMD entry points. Shared consumers include
SHAKE/cSHAKE, KMAC, TupleHash, ParallelHash and threaded batch execution; these
need integration/lifecycle regressions even where they share a qualified kernel.
RISC-V currently has no distinct hardened accelerated entry in this set; do not
silently activate its ordinary candidate kernels as a substitute.

The five portable hardened compression/permutation implementations (SHA-1,
MD5, SHA-256, SHA-512, Keccak), along with caller framing/output processing,
require a separate residue audit. Hardware-kernel success does not qualify
portable fallback or imply that all high-level API temporaries are erased.
Unsupported architecture/ABI coverage must remain explicit, without removing
existing portability or silently extending a cleanup claim.

## Remaining work before the requested retest

1. Complete the SHA-512 ports' native ABI coverage. SysV and Win64 observers
   under SDE, Arm observers under QEMU, Linux guard pages and endpoint compiler
   checks now bind the actual production sources. Native qualification remains.
2. Port the sixteen accelerated entry points without changing authority, KAT,
   quarantine, error atomicity, target features, public signatures or fallback
   policy. Prove all normal error exits and retain existing unwind guarantees.
3. Audit portable paths and shared high-level call boundaries; record precisely
   where a stronger return-boundary guarantee is implemented and tested.
4. Run independent differential vectors, ownership/error tests, cleanup
   mutations, sanitizers, and matching native/emulated ISA tests for each port.
   Recheck performance; do not silently replace acceleration with scalar work.
5. Refresh existing review bindings, obtain the new pentest and native evidence,
   then run the owner's approved full verification through the existing gates.
   No new release-gate mechanism is part of this work.

Keep the root `PENTEST.md` until its findings and this implementation are handled.
