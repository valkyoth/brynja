# Unsafe Rust Policy

Status: one v0.11.0 exception approved; every other unsafe site forbidden

Workspace lints deny unsafe code by default. Repository policy permits exactly
one documented block in the private
`crates/brynja-core/src/secret_memory_volatile.rs` module and rejects unsafe
blocks, unsafe items, local lint allowances, assembly, and FFI everywhere else.
The approved module is pinned by SHA-256. Any byte change reopens review before
semantic checks run. Every other Rust source is rejected if it contains any
complete identifier in the fail-closed set `unsafe`, `unsafe_code`, `extern`,
`asm`, `global_asm`, `llvm_asm`, `naked_asm`, `include`, or `path`. This broad
rule intentionally also matches comments and ordinary identifiers, so Rust
comments cannot be used as token whitespace and nested attributes cannot hide
code inclusion. Library targets must resolve to their classified `src/lib.rs`,
and Rust sources must be regular files beneath non-symlink package directories.

A future exception requires a versioned milestone, written necessity analysis,
safe alternative analysis, isolated module or crate, documented invariants,
Miri/sanitizer and adversarial tests, platform review, an external audit, and
explicit amendment of this policy. Assembly and FFI are treated as unsafe even
when hidden behind build tooling.

## Reserved CPU-Acceleration Boundary; No Low-Level Site Approved

Versions 0.13.1 and 0.13.2 establish capability and package policy contracts
only. The latter reserves `brynja-crypto-cpu` and
`brynja-crypto-cpu-std`, eight machine-readable backend identities, and exact
future amendment duties while admitting zero active kernels and zero new
low-level allowances. Version 0.13.3 implements evidence and test contracts
without admitting a native result, backend, or low-level site. None of these
milestones permits another unsafe site. Later
primitive-specific acceleration milestones may request exact intrinsics or
assembly inside the separately classified `brynja-crypto-cpu` package. Each
request must identify the primitive and operation, exact source symbol and
hash, compiler and CPU feature bundle, ABI and vector-state assumptions, safe
wrapper preconditions, register and spill residuals, scalar reference,
known-answer test, quarantine behavior, native hardware, side-channel and
performance evidence, and FIPS disposition. Approval for one symbol never
extends to another architecture, primitive, operation or compiler path.

The optional `brynja-crypto-cpu-std` package may later request only the smallest
boundary needed for first-party runtime feature detection where safe standard
library macros are insufficient. It may not contain a cryptographic kernel,
entropy or general OS integration. Compile-time `target_feature` evidence and
safe standard-library detection remain preferred. A public platform-attestation
constructor is unsafe by contract, thread-bound unless CPU migration is proven
safe, and cannot bypass a direct backend KAT. Until the applicable milestone
amends the machine inventory and passes its exceptional external review, the
current scanner must continue to reject all such code.

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
