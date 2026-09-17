# Register-cleanup prototype

Experimental assurance code, **not a production backend or release evidence**.
The owner requested register-remanence remediation across the hardened backends
before another pentest. Production code and release gates are unchanged while
the replacement boundary is being established here. Finding F1 remains open.

## Intended boundary

On normal return from a qualified kernel, that kernel's temporary secret values
must not remain in its working registers or compiler-generated stack spills.
Caller-owned input, output, and pre-existing caller register contents are not
erased. This is a kernel-boundary guarantee, not an end-to-end promise covering
all callers, framing, output conversion, or the whole process.

The prototype keeps **all secret loads and computation inside one opaque,
side-effecting assembly block**. Only pointers enter; no secret Rust values
leave. The block uses fixed, reviewed memory bounds, no stack, no calls, and
only public loop counters. It clears its scratch and every working register
before leaving. Thus the compiler cannot spill an intermediate that it never
receives. This avoids adding a broad register clobber to the existing intrinsic
code, where live values could instead be moved to untracked spills.

The compiler still owns ABI preservation of pointer-bearing and pre-existing
caller registers. The emitted prologue/epilogue is checked separately. Windows
XMM6–15 must be preserved, not indiscriminately wiped. The first prototype uses
only volatile vector registers 0–2. See the [Rust assembly contract](https://doc.rust-lang.org/reference/inline-assembly.html)
and [Windows x64 ABI](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention).

Asynchronous interruption can capture secrets **during** computation, before
cleanup. Signals, core dumps, abort, physical registers/caches, swap and OS
copies remain outside this normal-return contract. No FIPS, military suitability
or independent verification claim follows from these tests.

## Current experiment

| Candidate | Algorithm execution | Return-register observer | Production integration |
| --- | --- | --- | --- |
| Dedicated x86 SHA-512 | Intel SDE, 1,024 arbitrary state/block pairs per positive run | Seven integer registers plus three complete YMM registers | Pending |
| Arm SHA-512 | QEMU, 1,024 arbitrary state/block pairs per positive run | Five integer registers plus thirteen vector registers; D8–15 caller canaries | Pending |

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
opaque boundary. These tests establish a candidate technique, not a complete
production qualification or a general assembly verifier.

The Linux bounds test also places each input, state, scratch and constants at
either edge of a writable page, with inaccessible neighboring pages (all sixteen
placement combinations). Input and constants pages become read-only before the
call. This supplements sanitizers, which cannot instrument loads and stores
inside opaque assembly.

Run with an already licensed, verified Intel SDE executable:

```sh
python3 assurance/register-cleanup/check.py --sde /absolute/path/to/sde64 --mutations
python3 assurance/register-cleanup/check_arm.py --qemu --mutations
cargo clippy --locked --offline --manifest-path assurance/register-cleanup/Cargo.toml --all-targets -- -D warnings
```

A generic `cargo test` explicitly ignores the instruction execution test. It
must not be cited as evidence that SHA512 instructions or erasure executed.

The `win64-probe` fixture-only feature selects the Windows x64 function ABI so
the SDE campaign can execute that calling convention on Linux. Its observer
also seeds XMM6–15 and verifies their preserved lower halves on return. This is
not native Windows evidence and does not change any shipped Cargo feature.

## All-backend implementation inventory

No row below is complete merely because the SHA-512 prototype passes.

| Hardened kernel family | x86 implementation to replace/review | Arm implementation to replace/review | Status |
| --- | --- | --- | --- |
| SHA-224/256 instructions | `x86_sha::secret_sha` | `aarch64_sha2::secret_sha256` | Pending |
| SHA-384/512 and SHA-512/t instructions | `x86_sha512::secret_sha512` | `aarch64_sha2::secret_sha512` | x86/Arm isolated prototypes; production pending |
| Keccak single state | `x86_avx2_keccak::permute_secret_avx2` | `aarch64_sha3_keccak::permute_secret_sha3` | Pending |
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

1. Complete the pilot's native ABI coverage and production integration. SysV
   and Win64 ABI observers under SDE, Linux guard pages and endpoint compiler
   checks exist; these are not yet a source-bound production qualification.
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
