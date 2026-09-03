# Unsafe Rust Policy

Status: nine exact source-hash-bound modules approved; every other unsafe site forbidden

Workspace lints deny unsafe code by default. Repository policy permits unsafe
Rust in only nine exact modules: the private core volatile clearer; the
SHA-256 and Keccak session-attestation boundaries; the x86_64 SHA and AVX2
Keccak kernels; the AArch64 SHA2/SHA-512 and SHA3 Keccak kernels; the RISC-V
RV64 Zknh kernel; and the opt-in standard-library runtime detector. Each
complete source is pinned by SHA-256 with exact unsafe-block, unsafe-item,
local safety-proof, target-feature, intrinsic, assembly, and detector
invariants. Any byte change reopens review before semantic checks run. Every
other Rust source rejects unsafe, local unsafe allowances, assembly, FFI, and
code inclusion. Foreign source, native objects, build scripts, native links,
and external C cryptographic modules remain forbidden repository-wide. Rust
sources must be regular files beneath non-symlink package directories.

A future exception requires a versioned milestone, written necessity analysis,
safe alternative analysis, isolated module or crate, documented invariants,
Miri/sanitizer and adversarial tests, platform review, an external audit, and
explicit amendment of this policy. Assembly and FFI are treated as unsafe even
when hidden behind build tooling.

## v0.24.4 Keccak CPU-Intrinsic Exceptions

Version 0.24.4 adds exact first-party x86_64 AVX2 and AArch64 SHA3
Keccak-f[1600] candidates. The x86 module owns fixed-width AVX2 intrinsics; the
AArch64 module owns the architecture's `eor3`, `rax1`, and `bcax` intrinsic
path. `keccak.rs` owns the associated attestation constructor but no unsafe
block. Both kernels accept fixed arrays, execute fixed 24-round work, and are
reachable only through architecture-checked, thread-bound, direct-KAT-gated
evidence sessions. They contain no FFI, external assembly, native object,
build script, allocation, I/O, or pointer-length public API.

Both candidates remain unadmitted. Supplemental QEMU and emitted-instruction
evidence cannot establish native correctness, CPU-migration safety,
performance, side-channel behavior, secret-state erasure, independent
cryptographic verification, or FIPS validation. RISC-V remains scalar-only
for Keccak because the pinned ratified authorities contain no qualifying
route. Any admission is a separately reviewed architectural change, never a
source-hash-only edit.

## v0.22.2 RISC-V Zknh Inline-Assembly Exception

Rust 1.90.0 through 1.98.1 recognizes the ratified RISC-V `zknh` target
feature but does not expose stable SHA-2 intrinsic functions for it. Version
0.22.2 introduced four SHA-256 inline operations; v0.23.3 extended the same
module with the two qualifying SHA-512 sum operations. The current first-party
implementation therefore owns exactly six inline `asm!` statements in
`riscv64_zknh.rs`: `sha256sig0`, `sha256sig1`, `sha256sum0`, `sha256sum1`,
`sha512sum0`, and `sha512sum1`. The complete module is source-hash-bound with
eight unsafe blocks, two target-feature unsafe functions, and eight local
safety arguments. It has no memory operand, foreign ABI, external assembly,
native object, or build script.

The safe wrapper is reachable only on RV64 after compiler-proven `zknh` or an
explicit repository evidence attestation. It accepts one fixed block and one
exclusive state, runs the existing direct startup KAT, and keeps failed state
permanently quarantined. Ordinary activation remains forbidden because the
candidate has no qualifying native RISC-V correctness, migration, performance,
side-channel, or independent-review evidence. Generated code under Rust 1.90.0
and 1.98.1 must retain all four mnemonics; QEMU differential execution is
supplemental only.

The exception authorizes neither vector crypto nor generic RISC-V. `Zvknha`
and `Zvknhb` remain reserved because the supported Rust line lacks the stable
vector intrinsic, detection, and vector-state boundary required here. No
register/spill erasure, FIPS validation, or RISC-V acceleration support claim
is created. Because this is a new unsafe cryptographic assembly boundary,
v0.22.2 requires an exceptional pentest before tagging.

## v0.22.1 SHA-256 CPU-Intrinsic Exceptions

Versions 0.13.1 through 0.13.3 established the capability, package, unsafe
amendment, native-evidence, and performance-admission contracts without a
kernel. Version 0.22.1 uses that process for exactly two implemented SHA-256
candidates. `x86_sha.rs` is restricted to the x86 SHA-extension compression
entry; `aarch64_sha2.rs` is restricted to the AArch64 NEON/SHA2 compression
entry. `sha256.rs` owns the unsafe attestation constructors but no unsafe
block. `runtime_detection.rs` is the separate opt-in `std` adapter and uses
only standard-library feature detection before invoking that constructor.

The candidates accept one exact block behind a caller-owned, thread-bound
session that checks architecture, runs a direct KAT, records a health
generation, and permanently quarantines a bad answer. They use no external
assembly or ABI. Static selection requires complete compile-time features;
runtime selection requires the complete reviewed detector result. The
implementations make no register/spill erasure claim. Both remain unadmitted
and unreachable from ordinary execution until native evidence is complete;
cross-compilation or QEMU alone cannot authorize them. Approval never extends
to another primitive, architecture, symbol, feature bundle, or compiler path.

## v0.11.0 Volatile-Store Exception

Necessity: ordinary safe assignment or slice filling may be removed when the
compiler proves that the bytes are never read again. The exception calls
`core::ptr::write_volatile` once per byte so the stores are externally
observable compiler events. A final compiler fence is a compiler barrier only;
it is not presented as cache, DMA, atomic, or inter-thread synchronization.

Safe alternatives considered and rejected for the production claim are
ordinary assignment, `slice::fill`, `ptr::write_bytes`, and `black_box`; none
provides the admitted volatile-store guarantee. A third-party zeroization crate
is forbidden. The v0.11.1 review admits exact first-party
`sanitization 2.0.3` only for the separate v0.11.2 adapter; it does not become
Brynja's core guarantee.

The unsafe invariant is deliberately small: the raw pointer is derived from a
live exclusive `&mut u8`, is aligned, remains inside the same Rust allocation,
is written exactly once, and is never retained or offset. The safe API accepts
only an exclusive mutable slice. It clears the complete region before
initialization, exposes no read before exact completion, and clears the complete
region on every explicit and Drop exit that Rust executes.

MIR must retain the volatile call, LLVM IR must contain a volatile zero store,
and target assembly must contain a byte store. The matrix covers Rust 1.90.0
through 1.98.1 on x86_64 Linux and Rust 1.98.1 across Linux, Windows, FreeBSD,
macOS, Android, iOS, ARMv7E-M, RV32IMAC, and x86_64 bare metal. Pinned Miri and
AddressSanitizer execute every secret-memory integration test. Any compiler,
target, code, invariant, lint, or evidence change reopens this exception.

The claim covers only the bytes of the complete exclusively borrowed Rust
allocation when the clearing call returns. It excludes registers, caller- or
compiler-created copies, CPU and device caches, DMA-visible copies, crash dumps,
suspend images, physical-memory remanence, concurrent access, `mem::forget`,
abort, and process or power termination. External stores, accelerators, caches,
and DMA completion remain mandatory separate `SecretDestructor` duties. No
FIPS validation, independent verification, or whole-system erasure claim is
created.

Because this is the first unsafe secret-destruction boundary, v0.11.0 is an
exceptional development milestone: it requires a committed PASS pentest before
tagging but still publishes no crates. The v0.15.0 cumulative checkpoint must
review it again with every change after v0.10.0.

The initial v0.11.0 assessment found that the earlier semantic scanner could
accept extra operations inside the approved block and whitespace-varied FFI
combined with a lint expectation elsewhere. The production implementation did
not contain either bypass. Exact module-byte pinning, comprehensive token and
override rejection, code-inclusion rejection, and regression fixtures now
close the policy-control gap. Any future approved-module change must update the
pin as an explicit security review event rather than silently widening scope.
The first retest confirmed those submitted reproductions were closed but found
that comments between Rust tokens and `path` nested inside `cfg_attr` could
still evade syntax-shaped regular expressions. The scanner therefore no longer
models syntax or whitespace: broad identifier rejection closes the entire
reported class and fixtures retain all four comment/nested-attribute variants.
The repository-owner retest of signed follow-up remediation commit
`88a6c73d3b2ad055702aede3858b1e7ecc8d24aa` passed with zero open findings.

The v0.11.1 review records unsafe code inside exact `sanitization 2.0.3` as
part of the adapter's inherited trusted computing base. Its necessity,
invariants, Miri, emitted-code, target, and external-review evidence are
recorded in the admission artifact. Approval applies only to the separately
selected `brynja-sanitization` adapter and does not authorize additional unsafe
code or replace Brynja's mandatory v0.11.0 primitive.
