# RISC-V Native Host Inventory

Status: observed 2026-08-14; capability inventory only, not backend-admission
evidence

This document records the sanitized capabilities of Brynja's registered
`riscv64-cloud` lane. The SSH endpoint and account are intentionally absent.
The observation is useful for choosing future native tests, but it is not an
authenticated evidence bundle and cannot admit a cryptographic backend.

## Host And Toolchain

| Property | Observed value |
| --- | --- |
| Processor | SpacemiT X60, eight online RV64 harts |
| Frequency | 614.4 MHz minimum, 1.6 GHz maximum |
| Byte order and MMU | Little endian, Sv39 |
| Cache | 256 KiB L1 data, 256 KiB L1 instruction, 1 MiB L2 |
| Memory | 16,268,248 KiB total, no swap |
| Storage | 58 GiB root volume, approximately 11 GiB free at observation |
| Operating system | Bianbu 3.0.1, Linux 6.6.63, GNU userspace |
| Native C toolchain | GCC 14.2.0, binutils 2.44, glibc 2.41 |
| System Rust | Rust 1.84.1; outside Brynja's supported compiler line |
| User Rust | rustup 1.29.0 with Rust and Cargo 1.97.1 installed and default |

The non-interactive login path resolves `/usr/bin/rustc` first. The managed
evidence runner already prepends the user-local `.cargo/bin` directory and
therefore reuses Rust 1.97.1 without reinstalling it. Manual commands on this
lane must do the same or invoke the user-local binaries explicitly; output
from the system Rust must never be mistaken for supported-line evidence.

This is a comparatively slow host with limited free storage. Focused native
tests should use the detached runner and retain bounded logs. Full workspace,
Kani, large fuzzing, or broad benchmark campaigns belong on faster machines
unless a RISC-V-native result is specifically required.

## Observed ISA Intersection

All eight harts report this common instruction-set intersection:

```text
rv64imafdcv
zicbom zicboz zicntr zicond zicsr zifencei zihintpause zihpm
zfh zfhmin zca zcd zba zbb zbc zbs zkt
zve32f zve32x zve64d zve64f zve64x zvfh zvfhmin zvkt
sscofpmf sstc svinval svnapot svpbmt
```

Harts 0 through 3 append an additional observed `_ime` token that harts 4
through 7 do not report. Brynja assigns no capability meaning to that token.
Any migration-safe native work must use the intersection present on every
eligible hart and must not infer homogeneous execution from the model name.

Rust 1.97.1 recognizes the relevant RISC-V cryptographic target-feature names,
including `zknh`, `zkne`, `zknd`, `zkr`, `zvknha`, `zvknhb`, `zvkned`, and
`zvkg`. Compiler recognition is not hardware evidence: none of those
cryptographic extensions appears in any observed hart ISA string.

## Brynja Capability Classification

| Candidate use | Native status | Consequence |
| --- | --- | --- |
| Portable RV64 Rust and scalar cryptography | Hardware-capable | Suitable for focused portability and scalar-equivalence runs using Rust 1.97.1 |
| Generic vector and embedded-vector operations | `V`, `Zve*`, `Zvfh*` present | Potential future non-crypto/vectorized work requires its own stable-Rust, ABI, state, and side-channel review |
| Scalar bit manipulation | `Zba`, `Zbb`, `Zbc`, `Zbs` present | Potential focused arithmetic and carry-less-multiply experiments; not an algorithm admission |
| Data-independent execution-latency contracts | `Zkt` and `Zvkt` present | ISA declarations only; they do not implement a cipher or replace emitted-code and timing evidence |
| SHA-256/SHA-512 scalar acceleration | `Zknh` absent | The v0.22.2 RV64 SHA-256 candidate cannot execute natively on this lane |
| SHA-2 vector acceleration | `Zvknha` and `Zvknhb` absent | Vector SHA remains QEMU/codegen-only here |
| AES scalar/vector acceleration | `Zkne`, `Zknd`, and `Zvkned` absent | This lane cannot qualify future AES instruction backends |
| Vector GCM acceleration | `Zvkg` absent | Generic `Zbc` must not be represented as vector GCM support |
| SM3/SM4 acceleration | `Zksh`, `Zksed`, `Zvksh`, and `Zvksed` absent | This lane cannot qualify ShangMi instruction backends |
| Architectural entropy source | `Zkr` absent | This lane supplies no RISC-V architectural entropy-source evidence |
| Cache-block zero | `Zicboz` present | Useful capability metadata only; it provides no secret, register, spill, cache, or stack erasure guarantee |

## v0.22.2 Disposition

The v0.22.2 native preflight stopped before cloning, compilation, or candidate
execution because exact `Zknh` was absent. Installing another compiler cannot
create a missing CPU instruction. For this milestone, RV64 Zknh correctness is
therefore supported only by endpoint code generation and supplemental QEMU
differential execution. Those results do not establish native performance,
side-channel behavior, migration safety, authenticated provenance, independent
review, FIPS validation, or backend admission.

The unavailable native lane is a valid fail-closed outcome. The candidate
remains mechanically non-dispatchable in ordinary builds, while the portable
scalar implementation remains authoritative.

## Ongoing Evidence Policy

This host is not discarded merely because it lacks cryptographic SHA
extensions. Brynja may use it for focused native work whose exact required
features are present in the all-hart intersection above, including portable
scalar RV64 behavior and separately reviewed generic-vector or
bit-manipulation experiments. Each result must name the exact operation and
feature bundle it exercises and cannot be generalized to another backend.

For `Zknh`, `Zvknha`, `Zvknhb`, and every other absent cryptographic extension,
the project records the current route as **QEMU/codegen-only**. Emulation and
generated-instruction checks support implementation testing but never count as
native execution, performance, migration, side-channel, or admission evidence.

After v1.0.0, Brynja will seek additional real-hardware observations through
the reproducible community process in
[`POST_1_0_RISCV_QUALIFICATION_PLAN.md`](POST_1_0_RISCV_QUALIFICATION_PLAN.md).
The registered host remains useful in that campaign for supported common-hart
features and as a negative-feature, scalar-portability, and fail-closed lane.
