# Unsafe Rust Policy

Status: seventy-two exact source-hash-bound exceptions inventoried; reachability follows the explicit API contracts below; every other unsafe site forbidden

Workspace lints deny unsafe code by default. Repository policy permits unsafe
Rust in only seventy-two exact modules: the private core volatile clearer; the
SHA-256 and Keccak session-attestation boundaries; the x86_64 SHA and AVX2
Keccak kernels; the AArch64 SHA2/SHA-512 and SHA3 Keccak kernels; the RISC-V
RV64 Zknh kernel; the opt-in standard-library runtime detector; and the three
isolated legacy SHA-1 and MD5 session/x86/AArch64 candidate modules; plus the
runtime owner constructor and its private hosted platform bridge; and the
separate legacy SHA-1 hosted platform bridge and hardened secret authority; and
the ordinary MD5 hosted platform bridge; the hardened MD5 authority and kernels;
and the ordinary SHA-224/256 batch platform import, AVX2/NEON kernels and hosted
bridge; and the corresponding ordinary SHA-512-family batch platform import,
AVX2/NEON kernels and hosted bridge; plus the independent-state Keccak batch
platform import, AVX2/NEON kernels and hosted bridge; and the distinct hardened
SHA-224/256, SHA-512-family and Keccak batch platform imports and AVX2/NEON kernels,
with three distinct hosted hardened-batch platform imports. These modules use fixed-size
arrays and documented whole-lifetime feature authority. Portable safe Rust
cannot express the required SIMD intrinsics; unsafe remains confined to these
instruction/import boundaries, never framing or output ownership. The dedicated
x86 SHA-512 module is the additional development exception described below. Each
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

## v0.24.49 Dedicated x86 SHA-512 development exception

`x86_sha512.rs` owns the stable Rust SHA512 intrinsics with the exact `sha512,avx2,avx`
bundle. Safe Rust cannot express these instructions; portable SHA-512 remains
the safe alternative. The ordinary entry uses fixed 80-word schedule storage
and bounded unaligned vector stores. Every schedule offset is an internal fixed
round index; caller lengths and pointers never enter the kernel. It uses all
three dedicated instructions. Rust implicitly enables AVX2 for SHA512, so the
authority explicitly checks that requirement too. AVX-512 is not required.

The separate hardened entry uses the existing clearing schedule/vector owner,
never the ordinary kernel or its arrays. Two private modules,
`x86_sha512/secret.rs` and `aarch64_sha2/secret512.rs`, keep SHA-512 secret loads,
schedule expansion, rounds, feed-forward, scratch erasure and working-register
erasure inside one opaque assembly block each. No secret Rust value leaves the
block; no call or stack access occurs inside it. The `repr(C)` owner's exact
size and field offsets are compile-time assertions before its exclusive borrow
is viewed as 704 initialized bytes. The existing operation guard still clears
both regions on success/error and recoverable unwind.

The SHA-224/256 ports add `x86_sha/secret.rs` and `aarch64_sha2/secret256.rs`
under the same exact-layout/opaque-block contract. They read the first 64 input
bytes and update the first 32 state bytes, preserving unused state capacity;
all 704 scratch bytes are erased. X86 still requires only SHA/SSE2 and uses four
XMM registers, not AVX/SSE4. Constants need only u32 alignment; vector loads are
explicitly unaligned. Arm uses NEON/SHA2 and V0–5, preserving D8–15. The obsolete
Rust schedule helpers were removed rather than leaving secret arithmetic outside
the new boundary. Byte-offset and constant-alignment tests cover these accesses.

The single-state Keccak ports add `x86_avx2_keccak/secret.rs` and
`aarch64_sha3_keccak/secret.rs`. Exact owner offsets bind the 576-byte view:
all 576 bytes clear after output is committed to separate caller-owned state.
Theta/rho/pi, AVX2 or SHA3 chi, iota and cleanup stay in the same opaque block.
All addresses are fixed or public-loop bounded; there is no dynamic indexed
Rust helper, stack use or call in the secret computation. X86 erases four GPRs
and YMM0–3; Arm erases five GPRs and V0–3. Import and output transfer occur inside
the same opaque block. Higher-level framing remains separate audit work.
Guard-page, differential and mutation tests
supplement ASan, which cannot instrument opaque assembly internally.

The SHA-224/256 batch ports add `sha256_hardened_batch/{x86,arm}/secret.rs`.
The exact 2,752-byte owner layout retains only packed output at 2304..2560;
initial words, expanded schedule and round temporaries are erased. AVX2 uses
YMM0–3 and three integer temporaries; little-endian NEON uses V0–3 and three
integer temporaries, explicitly zeroing inactive output capacity. The complete
schedule, rounds, feed-forward and cleanup stay inside the opaque block.
`sha256_hardened_batch/transfer.rs` separately owns state/block packing and output
commit. Safe Rust slice copies can leave secret words in compiler temporaries;
the private pointer-only transposition therefore uses one opaque scalar block
on x86-64 or little-endian AArch64, with fixed 8/16-word layouts and bounded
lane count. It uses no SIMD or additional ISA requirement. Only RAX or X4 carries
secret words; it and the working counters are erased before returning. Typed
disjoint array borrows establish all bounds; private safe entry points cap lanes
at eight, and the workspace API rejects pack widths other than four/eight.
The health/counter check still separates compression from transactional output
commit. No caller buffers are erased. Miri/Kani and other targets retain the safe
reference mapping, not a register-cleanup claim. Higher-level input packing,
portable compression and output ownership remain separate work. This exception
adds no public API or authority bypass; external retest/native qualification is
still pending along with the other v0.24.49 cleanup changes.

The SHA-512-family batch ports add `sha512_hardened_batch/{x86,arm}/secret.rs`.
The exact 3,264-byte owner layout retains packed output at 2816..3072 and
clears all initial words, schedule words and round temporaries. These are
four-lane AVX2 or two-lane NEON 64-bit kernels, not dedicated SHA512
instruction paths. They use the same three integer/four vector working-register
inventory as the narrower batch kernels. All 80 rounds and the complete
schedule expansion remain inside the opaque block; inactive Arm output capacity
is zeroed. `sha512_hardened_batch/transfer.rs` extends the same private opaque
packing/commit boundary to 64-bit words in two/four active lanes. Its fixed
8/16-word layouts, scalar registers, pointer-only inputs, erasure and modeled
fallback have the same restrictions as the narrower transfer module. It adds
no dedicated SHA512 requirement and retains the health/counter check before
caller-state commit. SHA-384, named truncations and general SHA-512/t framing remain in
their existing callers, outside this kernel-boundary claim.

The packed Keccak ports add `keccak_hardened_batch/{x86,arm}/secret.rs`.
Their exact 1,920-byte owner retains state only at 0..800 and clears all columns,
deltas and staging at 800..1920. Four AVX2 or two NEON independent permutations
keep theta/rho/pi/chi/iota and cleanup inside the opaque block. Arm also erases
inactive output halves. Three integer/four vector working registers and flags
are cleared; no Arm SHA3 or x86 AVX-512 prerequisite is added. The repr(C)
byte fields retain their original size and alignment.
`keccak_hardened_batch/transfer.rs` imports and commits the 25-word states using
two private opaque transpositions with fixed 800-byte source/destination bounds.
Only RAX or X4 holds secret words; it and all public working counters/offsets
are erased before return. Canonical little-endian bytes need no reversal on the
supported x86-64/little-endian Arm targets. This adds no SIMD/ISA prerequisite.
The existing health/counter check still precedes output commit; failed operations
preserve caller state and clear workspace storage. Miri/Kani/other targets retain
the safe model without a register-cleanup claim. Higher-level sponge absorption,
squeezing and owner copies remain separate work.

The legacy SHA-1 ports add `cpu/{x86_sha1,aarch64_sha1}/secret.rs` inside
`brynja-legacy-sha1`. Fixed 20-byte state, 64-byte input and 320-byte schedule
references bound the single opaque computation. Endian conversion, schedule,
rounds, feed-forward and schedule clearing remain inside that block. SHA/SSE2
uses only EAX and XMM0–3 for secret temporaries, including on 32-bit x86;
Arm SHA-1 uses X4–6 and V0–5. These registers and flags are erased before return.
Unaligned operands are supported without adding SSSE3, SSE4 or AVX requirements.
The caller's owner and failure-guard clearing remain unchanged; framing and
portable processing still need their separate audit.

The legacy MD5 ports add `cpu/{x86_secret,arm_secret}/kernel.rs` inside
`brynja-legacy-md5`. Exact repr(C) layout assertions bind the 864-byte owner;
initial state/message/temporary storage clears, leaving only work at 640..768.
Eight AVX2 or four NEON lanes retain their existing ISA requirements. Arm also
clears inactive output half-lanes. All 64 rounds, feed-forward and erasure of
the three integer/four vector working registers stay in the opaque block.
The public 80-word constant table includes the sixteen rotation counts and is
checked against an independent RFC 1321 sine construction. MD5 remains broken;
these cleanup properties do not restore collision resistance.

MD5's private `cpu/transfer.rs` packs each fixed 16-byte state and 64-byte
block, advances the 128-byte inter-block result, and commits the lane state
through four opaque transpositions. Only EAX or X4 holds secret words; working
registers and flags clear before return. Lane indices outside 0..8 reject before
mutation. These scalar transfers add no ISA requirement. Miri/Kani/other targets
retain a safe model, without a register-cleanup claim. The existing authority,
work limits and cancellation boundaries remain unchanged. Portable processing,
scalar final padding, output copies and higher-level owner moves remain separate
work; this is not an end-to-end register-erasure guarantee.

MD5's `compress/native.rs` adds a baseline scalar boundary on x86-64 and
little-endian AArch64, including default-feature-disabled ordinary/hardened
processing and scalar batch tails. It does not require SIMD or crypto features
and does not acquire accelerated authority. Only typed state/block/table pointers
enter; all rounds and feed-forward stay in one stack/call-free block. Seven
volatile x86 working registers plus a public counter, or X4-X11 on Arm, clear
before normal return. ABI-preserved caller registers are restored, not erased.
The existing owner clears its block afterward. Other architectures and Miri/Kani
retain the Rust model with its original residue limitations. Input framing,
padding, output copies and owner moves remain outside this narrow boundary.

SHA-1's `compress/native.rs` similarly adds a baseline x86-64/little-endian
AArch64 scalar boundary, using fixed 20-byte state, 64-byte input and 320-byte
owned schedule pointers. Its 80 rounds, feed-forward and complete schedule
clearing stay inside the opaque stack/call-free block. Seven volatile x86
working registers and a public offset, or X4-X12 and condition flags on Arm,
clear before return. Baseline integer instructions need no acceleration
authority. Other targets and Miri/Kani retain the existing Rust model; outer
framing/output/owner copies remain separate work.

SHA-2's `hardened/compress32/native.rs` provides the corresponding baseline
x86-64/little-endian AArch64 boundary for hardened SHA-224/256, not ordinary
public hashing. Fixed 64-byte state, 128-byte input, 640-byte owned scratch and
64-word public constants pointers enter. Only 32 state bytes and 64 input bytes
participate; the remainder is preserved. Schedule and round state are stored
explicitly in owned scratch, never compiler stack storage, and all 640 bytes
clear inside the stack/call-free block. EAX/ECX/EDX/R8/R10 or X4-X10 clear before
return. The remaining portable model and high-level copies are not qualified.

These sixteen kernel boundaries are under implementation-author verification, not
complete qualification of the caller, other backends, or portable fallbacks.
Pre-existing caller registers and caller-owned buffers are not erased. Abort,
interruption during computation, OS snapshots and platform storage remain
outside this normal-return boundary. See the source-bound
[register-cleanup checks](../assurance/register-cleanup/README.md).

Static construction requires the complete compiler bundle and deployment-wide
CPU/OS support. Unsafe platform import retains its lifetime-wide obligation;
generic hosted x86 detection still cannot supply a migration guarantee. Startup
KATs, operation identity and quarantine apply before instruction entry.
This is a source-bound development review, not native qualification, independent
review or release acceptance. See [dedicated SHA-512](x86-sha512-execution.md).

## v0.24.48 Hardened SHA-224/256 batch foundation

Five development exceptions isolate `sha256_hardened_batch/platform.rs`,
`x86.rs`, `arm.rs` and their two private `secret.rs` kernels. Safe Rust cannot
express these AVX2/NEON instructions;
existing portable hardened hashing remains the safe alternative. The new
default-off feature enables only the first-party clearing dependency, not
ordinary batch execution. All packed arrays belong to the distinct clearing
Workspace: initial words, full schedule, working words and six round temporaries.
Loads/stores borrow exact initialized 32-byte arrays; AVX2 touches all 32 bytes,
little-endian NEON touches the first 16. Inactive capacity is cleared too.

The session guard clears every region before return and on recoverable unwind.
State commits only after post-dispatch health and checked accounting succeed;
backend failures and unwind revoke authority. The public platform import is an
explicit lifetime-wide instruction-safety obligation, not runtime provenance
proof. Compiler-created copies/registers, abort and caller-owned states/blocks
remain outside the workspace erasure guarantee. This development inventory is
not independent review or native qualification. Full milestone assurance remains
pending; see [hardened multibuffer owners](hardened-multibuffer-owners.md).

The SHA-512-family has five separately pinned development exceptions in
`sha512_hardened_batch/platform.rs`, `x86.rs`, `arm.rs` and their private
`secret.rs` modules. The same necessity and
authority/cleanup contracts apply, but these are distinct 64-bit kernels:
four AVX2 lanes or two little-endian NEON lanes, 80 schedule words and 128-byte
input blocks. Every packed vector still occupies an owned 32-byte region;
NEON reads/writes its first 16 bytes and teardown clears its inactive half.
Safe framing, exact-t output identity and destination ownership stay outside
the instruction boundary. No ordinary packed owner is reused for secrets.

Three further development exceptions isolate `keccak_hardened_batch/platform.rs`,
`x86.rs` and `arm.rs`. Their distinct AVX2/NEON permutation kernels store packed
state, column parities, theta deltas and rho/pi/chi staging in four clearing
regions (800, 160, 160 and 800 bytes). The v0.24.49 opaque ports above replace
their intrinsic implementation with bounded accesses to that same initialized
owner storage. NEON uses its first two lanes and owner cleanup erases all
four lanes. Raw caller states remain caller-owned; byte and word entry points
commit only after revalidation and checked accounting. Caller copies,
abort and platform-authority limitations still apply. Hash framing and final native
qualification remain pending.

## v0.24.47 Independent-state Keccak SIMD

Four new exceptions isolate the raw multibuffer `keccak_batch/platform.rs`,
`x86.rs` and `arm.rs` modules and the hosted `keccak_batch/platform.rs` bridge.
Necessity: portable safe Rust cannot express the AVX2/NEON vector intrinsics;
the scalar Keccak implementation remains the explicit safe alternative.
The public framing, cursor, scratch ownership and output-commit layer contains
no low-level code. Fixed-size local arrays back every unaligned vector load
and store: exactly four initialized u64s for AVX2 or two for NEON. Exclusive
state references forbid aliasing; every computed word destination is checked.
All rotations and round control depend only on public FIPS 202 constants.

The sealed authority's exact CPU/OS lifetime contract and a direct vector KAT
precede instruction entry. Pre/post health checks, staged state commits,
checked counters and unwind guards preserve fail-closed authority semantics.
These ordinary states and temporaries do not erase secrets. New source hashes
and exact unsafe counts bind this development inventory; native qualification
and exceptional pentest remain pending, not supplied by these hash entries.
See [Keccak batch execution](keccak-batch-execution.md).

## v0.24.4 Keccak CPU-Intrinsic Exceptions

Version 0.24.4 adds exact first-party x86_64 AVX2 and AArch64 SHA3
Keccak-f[1600] candidates. The x86 module owns fixed-width AVX2 intrinsics; the
AArch64 module owns the architecture's `eor3`, `rax1`, and `bcax` intrinsic
path. `keccak.rs` owns the associated attestation constructor but no unsafe
block. Both kernels accept fixed arrays and execute fixed 24-round work. They
were originally exposed through architecture-checked, thread-bound, direct-KAT-gated
evidence sessions. The v0.24.31 static authority below also exposes ordinary
raw execution. They contain no FFI, external assembly, native object,
build script, allocation, I/O, or pointer-length public API.

Both remain unadmitted through the original high-level/detection routes.
Supplemental QEMU and emitted-instruction
evidence cannot establish native correctness, CPU-migration safety,
performance, side-channel behavior, secret-state erasure, independent
cryptographic verification, or FIPS validation. RISC-V remains scalar-only
for Keccak because the pinned ratified authorities contain no qualifying
route. Any additional activation is a reviewed architectural change, never a
source-hash-only edit.

## v0.24.34 Hardened SHA-2 Scratch

Separate secret-bearing functions in the existing x86 SHA and AArch64 SHA2
exception modules use owner-backed schedule/vector storage. No additional
unsafe module, foreign implementation or platform detector is added. Necessity:
the ordinary kernels' source-owned stack arrays cannot satisfy hardened cleanup;
reusing them for secrets would violate the documented API separation. Portable
hardened compression remains the safe explicit alternative.

The new kernels receive fixed `[u8; 64]` state and `[u8; 128]` blocks. Vector
loads/stores use fixed in-bounds offsets, unaligned operations where applicable,
and the aligned scratch owner. Full static/hosted authority and a direct
hardened KAT precede entry; incomplete operations quarantine the owner. The
private scratch guard clears both owned regions after each operation and on
recoverable unwind; the outer hash clears its eight owned regions on terminal
paths. Exact unsafe block/item counts and source hashes bind this amendment.
Native Arm/Mac review and exceptional pentest remain pending. Registers,
compiler copies/spills, caches and platform storage are not erased by this claim.
See [the complete hardened boundary](sha2-hardened-execution.md).

## v0.24.31 Ordinary Static Execution

The default-off `static-execution` feature exposes six ordinary raw kernels:
x86 SHA-256, x86 SHA-512, x86 AVX2 Keccak, Arm SHA-256, Arm SHA-512 and Arm SHA3 Keccak.
`static_execution::Authority` requires the complete compiler feature bundle,
the specialized executable platform contract and a direct kernel KAT.
Sessions recheck owner health and generation before mutation. This is an
explicit reachability amendment, not a new unsafe-module allowance.
Default hash constructors remain portable. High-level hash dispatch, hosted,
hardened, legacy and RISC-V activation are not granted by this feature.
Neither native observations nor a KAT establish independent review, FIPS
validation, migration safety or secret erasure. The full deployment and
ownership contract is in [static CPU execution](static-cpu-execution.md).

## v0.24.32 Hosted Runtime Execution

The default-off `runtime-execution` feature adds one low-level platform-proof
constructor and one private hosted call site. The safe hosted adapter authorizes
only complete AArch64 feature bundles through the reviewed system interfaces;
generic x86 and unreviewed platforms never gain authority from current-core flags.
The core constructor has a lifetime-wide CPU/OS/migration safety obligation.
No feature bool, report or downstream trait implementation can call it safely.
Actual kernel startup tests precede sessions; quarantine never triggers fallback.
No new pointer operation, foreign call, assembly or cryptographic kernel is added.
Necessity: platform detection lives in the optional std crate while kernels remain
no_std (the separate hardened feature alone adds the first-party clearing owner).
Moving detection into the core or trusting safe booleans
would violate those boundaries. The two small source-hash-bound modules are the
reviewed bridge, not blanket permission for hosted low-level code.
See [hosted CPU execution](hosted-cpu-execution.md) for the platform audit,
unsupported-platform disposition and exceptional pentest requirements.

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
implementations make no register/spill erasure claim. Their original
high-level/detection routes remain unadmitted; the v0.24.31 amendment above
separately permits ordinary raw static execution. Cross-compilation or QEMU
alone does not establish a compatible deployment. Approval never extends
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
is forbidden. The v0.24.22 refresh of the v0.11.1 admission permits exact
first-party `sanitization 2.1.0` only for the separate v0.11.2 adapter; it does not become
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

The current v0.24.22 re-review records unsafe code inside exact `sanitization 2.1.0` as
part of the adapter's inherited trusted computing base. Its necessity,
invariants, Miri, emitted-code, target, and external-review evidence are
recorded in the admission artifact. Approval applies only to the separately
selected `brynja-sanitization` adapter and does not authorize additional unsafe
code or replace Brynja's mandatory v0.11.0 primitive.

## v0.24.21 legacy SHA-1 candidates

The separate v0.24.42 hardened API adds `cpu/secret.rs` as a reviewed exception
and owner-backed secret functions in the two existing SHA-1 kernel modules.
Necessity: ordinary vector/schedule temporaries do not satisfy secret cleanup;
using their public-data authority would erase the profile boundary. Safe
alternative: `hardened_execution::Executor::portable()` or `HardenedSha1`.
The distinct authority requires a complete lifetime-wide feature bundle, a
backend-specific revalidation callback and a KAT through the actual hardened
kernel. Borrowed exact arrays, checked views, six existing owner regions and
one additional 16-byte scratch region bound all loads/stores. Failure/unwind
destroys owned state and permanently quarantines authority. Source, compiled
cleanup mutants, Miri, native ASan, compiler-endpoint emission and fresh native
capture are mandatory; independent review remains pending, not claimed.
See [hardened execution](legacy-sha1-hardened-execution.md). Registers, spills,
compiler copies and platform storage remain residual risks.

The v0.24.41 default-off operational API reuses the reviewed kernels through
a separate KAT-gated authority. Its additional exact unsafe boundary is
`crates/brynja-legacy-sha1-std/src/execution/platform.rs`: the allowlisted
AArch64 platform feature ABI authorizes the leaf's unsafe constructor. A
current-core x86 CPUID observation cannot authorize hosted execution. Static
binaries instead require the full deployment-wide target-feature bundle.
Neither route authorizes secret-bearing input; see the
[operational contract](legacy-sha1-execution.md). The candidate entry points
described below retain their original admission gates.

Three additional hash-bound exception modules live only under
`crates/brynja-legacy-sha1/src/cpu`: `session.rs`, `x86_sha1.rs`, and
`aarch64_sha1.rs`. The session owns the documented external execution authority
and guards private exact-width intrinsic entrypoints. Local load/store safety
comments cover the fixed live arrays. No modern CPU crate changes. All candidates
remain unadmitted, hardened SHA-1 stays portable, and a feature check alone is
not a migration-safe authority. See [the contract](legacy-sha1-acceleration.md).

## v0.24.22 legacy MD5 candidates

Three additional private modules contain the session authority and fixed-width
AVX2/NEON loads/stores. Arrays have exact initialized widths; no untrusted pointer
or buffer length enters a kernel. Fixed transposition/round indices are public.
Only ordinary public-data batches can use the session; hardened batches compose
the existing clearing MD5 owners and have no instruction route. Unique two-key
evidence gating has no cfg(test) exception. Native records, QEMU and benchmarks
cannot admit execution. See [MD5 acceleration](legacy-md5-acceleration.md).

## Ordinary MD5 operational authority

The default-off `execution` API imports a distinct lifetime-wide static/platform
authority through the existing MD5 session module. The old candidate constructor
still rejects before execution. The new authority executes the real full-width
startup KAT and exposes no raw session; revalidation failure and unwind quarantine
before caller-output commit. No kernel arithmetic or pointer boundary changed.
The separate hosted MD5 platform module has one reviewed unsafe call importing
the supported AArch64 OS contract. Generic x86 current-core detection is not
treated as authority. These ordinary APIs require public classification and have
no hardened output path. See [ordinary MD5 execution](legacy-md5-execution.md).

The separate default-off hardened MD5 feature adds four exact exceptions:
`cpu/secret.rs`, `cpu/x86_secret.rs`, `cpu/arm_secret.rs`, and the hosted
`hardened_execution/platform.rs`. These accept only their distinct authority
and private clearing scratch, never an ordinary session or caller boolean.
AVX2 loads/stores exactly 32 bytes from fixed owner arrays; NEON loads/stores
16 bytes from the same 32-byte owner slots, clearing unused upper storage too.
Every pointer is derived from a live fixed shared/exclusive byte borrow; no
caller-controlled pointer or length enters these kernels. Feature authority
covers the entire operation and every schedulable CPU, including OS YMM support
for AVX2. Failed revalidation/dispatch clears scratch and quarantines authority.
No full register/spill erasure, migration monitor, FIPS or independent review is
claimed. See [hardened MD5 ownership](legacy-md5-hardened-execution.md).
