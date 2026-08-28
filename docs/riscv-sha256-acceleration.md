# RISC-V SHA-256 Acceleration Boundary

Status: v0.22.2 implements one RV64 Zknh candidate; automatic activation and
all admission claims remain disabled

## Normative ISA Choice

The ratified RISC-V scalar cryptography specification defines the `Zknh`
extension and its SHA-256 `sha256sig0`, `sha256sig1`, `sha256sum0`, and
`sha256sum1` instructions. Brynja's first RISC-V candidate targets exactly
RV64 plus `Zknh`; generic RV64, `Zkn`, the base vector extension, or a product
name is insufficient. The implementation uses the four scalar instructions
for the SHA-256 schedule and compression sums while retaining the same
first-party round logic and scalar-owned public hash state.

The ratified vector cryptography specification supplies SHA-256 through either
`Zvknha` or `Zvknhb`, using `vsha2ms.vv`, `vsha2ch.vv`, and `vsha2cl.vv` with
SHA-256's 32-bit element rules. Brynja's one reserved vector identity selects
exact `Zvknha`; `Zvknhb` would require its own later policy amendment rather
than acting as an undocumented alternative. That path remains reserved. Rust 1.90.0 through
1.98.0 exposes neither stable vector-crypto intrinsics nor stable vector-crypto
runtime detection, and this milestone does not add vector-state or ABI
authority merely because a compiler lists the target features.

Primary references:

- [RISC-V scalar cryptography, version 1.0.1](https://docs.riscv.org/reference/isa/unpriv/scalar-crypto.html)
- [RISC-V vector cryptography, version 1.0.0](https://docs.riscv.org/reference/isa/unpriv/vector-crypto.html)
- [Rust `core::arch::riscv64` source](https://doc.rust-lang.org/stable/src/core/stdarch/crates/core_arch/src/riscv64/zk.rs.html)
- [Rust RISC-V runtime feature-detection source](https://doc.rust-lang.org/stable/src/std_detect/detect/arch/riscv.rs.html)

## Stable Rust Strategy

Rust's RISC-V cryptography intrinsic functions are unstable across the
supported line. The candidate therefore uses four exact `core::arch::asm!`
statements in one hash-bound Rust module. This is inline assembly authored and
compiled as first-party Rust source; no external assembly file, foreign ABI,
native object, build script, C module, or delegated cryptographic provider is
present. The repository's unsafe policy separately pins the complete module,
the exact instruction inventory, target-feature annotation, local safety
arguments, and safe wrapper.

Both Rust 1.90.0 and 1.98.0 recognize `zknh`, compile the module, and emit all
four instructions. The module is RV64-only in this release. RV32 and every
other target retain portable scalar SHA-256 without compiling this source.

## Selection And Admission

Safe static selection exists only when the compiler proves both
`target_arch = "riscv64"` and `target_feature = "zknh"`. The separate `std`
detector intentionally does not select RISC-V in v0.22.2. The backend is marked
unadmitted, so ordinary construction rejects it even on a qualifying build.
Only the repository evidence configuration can force direct construction; it
runs the same startup `abc` KAT and permanent caller-owned quarantine used by
the other candidates.

The native capture route additionally requires an RV64 Linux host whose
observed ISA string names exact `zknh`. It rejects generic RV64 and unrelated
vector or scalar-crypto names. A native result is still non-authorizing until
the repository has authenticated provenance, CPU-migration controls,
correctness, performance, code-size, side-channel, and independent-review
evidence for the exact symbol and operating environment.

## Verification And Residual Gaps

The full accelerated SHA-256 differential corpus covers zero length, padding
boundaries, multiple blocks, irregular chunk widths, and scalar equality under
QEMU's explicit RISC-V model. Generated assembly from both supported endpoint
compilers contains all four required mnemonics. Builds without `+zknh` do not
select the backend.

QEMU and cross-compilation are supplemental only. A sanitized preflight of the
registered native lane found RV64 vector and bit-manipulation support but no
`Zknh`, `Zvknha`, or `Zvknhb`; see
[RISC-V Native Host Inventory](riscv-native-host-inventory.md). No qualifying
native RISC-V candidate execution, native performance result, side-channel
result, register or spill erasure claim, independent cryptographic review, or
FIPS validation exists.
Consequently the candidate is mechanically non-dispatchable in ordinary use,
portable scalar SHA-256 remains authoritative, and Brynja makes no RISC-V
acceleration support claim at v0.22.2.
