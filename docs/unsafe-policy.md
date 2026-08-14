# Unsafe Rust Policy

Status: five exact source-hash-bound modules approved; every other unsafe site forbidden

Workspace lints deny unsafe code by default. Repository policy permits unsafe
Rust in only five exact modules: the private core volatile clearer, the
SHA-256 session attestation boundary, the x86_64 SHA kernel, the AArch64 SHA2
kernel, and the opt-in standard-library runtime detector. Each complete source
is pinned by SHA-256 with exact unsafe-block, unsafe-item, local safety-proof,
target-feature, intrinsic, and detector invariants. Any byte change reopens
review before semantic checks run. Every other Rust source rejects unsafe,
local unsafe allowances, assembly, FFI, and code inclusion. Foreign source,
native objects, build scripts, native links, and external C cryptographic
modules remain forbidden repository-wide. Rust sources must be regular files
beneath non-symlink package directories.

A future exception requires a versioned milestone, written necessity analysis,
safe alternative analysis, isolated module or crate, documented invariants,
Miri/sanitizer and adversarial tests, platform review, an external audit, and
explicit amendment of this policy. Assembly and FFI are treated as unsafe even
when hidden behind build tooling.

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
through 1.97.1 on x86_64 Linux and Rust 1.97.1 across Linux, Windows, FreeBSD,
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
