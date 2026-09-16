# Brynja v0.24.48

Development in progress: hardened multibuffer hash owners. Not released; no
crates selected for publication. The narrow and wide SHA-2 CPU and leaf batch
APIs, Keccak CPU/leaf batching and distinct hosted adapters are implemented;
scheduled, streaming and threaded ParallelHash leaf groups are implemented.
Complete qualification remains pending.

## Scope

- Distinct clearing owners for SHA-224/256, the complete SHA-512 family including
  general SHA-512/t, and SHA-3/SHAKE/cSHAKE independent-message batching.
- Default-off AVX2/NEON execution with typed secret outputs and explicit public
  declassification. Ordinary non-erasing owners cannot substitute.
- Eligible batched ParallelHash leaves with bounded scheduling, exact leaf/root
  identity, deterministic merge and failure cleanup.
- Destructor, mutation, ownership, scalar/SIMD, compiler-cleanup and fresh native
  evidence before any claim of completion.

The [design](../docs/hardened-multibuffer-owners.md) records the implementation
order and acceptance obligations. No release-gate or publication rule changes.

Standalone development sanitizer execution now covers all six hardened batch
layers with required SIMD tests and forced fatal ASan/LeakSanitizer settings.
Local AVX2 execution passed 117 tests; driver regressions reject seven weakened
enforcement variants. This is not native platform qualification or independent
review, and no release/tag-gate rule changed.

## Opening changes

Version metadata and downstream fixture pins advance to v0.24.48. Two rustdoc
comments now quote `Keccak-f[1600]` as code instead of an unresolved link. This
does not change executable Rust, kernels, algorithm domains or dispatch.

## Limitations

A standalone package-consumer check now exercises the hardened feature graph
from extracted `.crate` archives, tests ownership and ordinary/hardened type
separation, and rejects compiled cleanup/dispatch mutations. This is development
acceptance, not complete qualification; release-gate rules are unchanged.
Development compiler checks now cover narrow/wide SHA-2 batch workspace cleanup
on both compiler endpoints and three targets under abort/unwind. Six bounded Kani
proofs cover the actual hardened SHA-2/Keccak work controls. SHA-3 batch frame and
whole-workspace emitted cleanup now passes the same compiler/target matrix; four
further Kani proofs cover local ParallelHash range and completion predicates.
Secret-output LLVM and assembly iteration now check every slot shape with symbolic
nonempty lengths; assembly tracks ABI clobbers and full-slice call arguments.
ParallelHash workspace/transport/stream cleanup passes MIR/LLVM/assembly
inspection; worker-storage teardown has MIR, exact LLVM-loop and complete
assembly-loop checks under the valid Vec allocation invariant. These
pass the same matrix with compiled omission/shortening mutation tests. The
worker coordinator's local Drop ordering is now checked through normal/error and
recoverable-unwind MIR paths, with five compiled ownership/guard mutants. Broader
caller-to-cleanup lifecycle and machine-level coordinator qualification remain
pending. The standalone worker destructor now has LLVM/assembly checks binding
the original Vec base and complete live length to the clearing loop, with three
additional compiled argument mutations. Retained drop glue now checks original
buffer arguments and clear-before-deallocation in LLVM, plus the machine entry
prefix. An additional complete normal-path machine check binds capacity testing,
deallocator identity/base/size/alignment and returning epilogues on all nine
retained rows, rejecting 216 post-clearing artifact mutations and 420 focused
regressions. This assumes valid Vec headers and non-unwinding callees; it does
not qualify exception tails or CFI. Fully inlined coordinator LLVM now checks
cleanup-call reachability after
native worker-spawn attempts across normal/error/unwind exits. An additional
LLVM fixed-point analysis checks original buffer pointer/live-length arguments
and header non-escape/immutability after spawn for ten memory-backed rows.
The two 1.98.1 Arm abort rows fully scalar-replace that header; a separate
allocation-bound check follows their original base/count to cleanup. All twelve
rows now pass inlined LLVM argument qualification, rejecting 96 artifact
regressions; compiled slot-discard/truncation/removal mutations are rejected
under both Arm panic profiles. A separate emitted-assembly CFG check now requires
cleanup on post-spawn normal return paths across all twelve rows and rejects
48 assembly-only bypass mutations. It does not qualify instruction data flow,
argument registers, unwind tables or broader lifecycle obligations; those remain
pending.
A further local stack-owner-to-ABI handoff check covers eight rows (all 1.90.0
targets and 1.98.1 x86, both panic profiles), rejecting 48 assembly-only argument
and offset substitutions plus 62 focused regressions. It checks stable frame
offsets and full-width field/address setup on post-spawn normal cleanup paths;
it does not prove preceding memory/alias provenance or exception recovery. The
four register-held 1.98.1 Arm rows now have a separate allocation/count-bound
register/spill check, rejecting 64 assembly-only mutations and 77 focused
regressions. It follows full-width copies, stack spills, joins, loops and call
clobbers under explicit private-spill/callee non-aliasing assumptions. Hidden
aliases, complete memory provenance and exception recovery remain unproved.
A separate unwind-profile check now binds the emitted exception table to native
worker creation and follows its landing pad to cleanup before return/resume.
All six compiler/target rows pass; 24 assembly-only mutations fail while the
normal-return check still passes, alongside 78 focused regressions. This assumes
valid cleanup arguments and non-unwinding clear/deallocator contracts; it does
not prove all throwing-call coverage, CFI restoration, exception-path arguments
or linked/runtime unwinding.
A complementary entry-origin walk covers later recorded exceptional edges after
worker creation. LLVM invoke and assembly landing-pad call inventories agree on
all six unwind rows; 286 artifact mutations and 33 focused regressions fail as
expected. This is multiset correspondence, not individual call-site identity or
proof that LLVM retained every needed invoke. The same cleanup contracts and
exception-argument/CFI/runtime limitations remain. Release gates are unchanged.
The exception-only Storage destructor additionally checks the original stack
owner's full-width address and rejects ordinary/exceptional entry past argument
setup. All six fresh compiler/target runs pass, with 36 artifact mutants and 45
focused regressions rejected. This assumes a correctly restored stack frame;
CFI, preceding header memory/alias provenance and runtime unwinding remain outside
the claim. No production implementation or release gate changed.
Separate runtime tests now exercise coordinator unwinding with live workers
across all four ParallelHash identities and three launch positions. All twelve
cases pass under pinned Miri, split into four exact-name invocations; the earlier
combined timeout is not counted as passing. The tests check worker completion,
Storage clearing, root cancellation and rejected-secret-output clearing. This
is bounded runtime evidence, not exhaustive scheduling or native SIMD evidence.
New compositional Kani harnesses exercise actual transfer consumption
and completion-token finalization with modeled sponge results and byte clearing;
they do not establish hashing correctness, arbitrary input flushing or threading.
A bounded buffering Kani harness also follows two real byte updates at B=1,
with symbolic payloads up to twelve bytes, all split points and modeled consumer
failures. It checks ordered full-group handoff, pending bytes, counters and
cancel/Drop clearing. Hashing, partial-bit tails, arbitrary sizes and machine
erasure are outside this compositional proof.
A separate bounded partial-tail proof follows real final-input copying and
flushing with pre-existing pending bytes. It checks canonical partial-byte
handoff, exact bit/leaf accounting, root-bound completion and failure cleanup
for B=1 and up to eight total bytes; hashing and root output remain modeled or
excluded rather than claimed as proven.
No release gate changed.

The new `brynja-crypto-cpu/sha256-hardened-batch` feature supplies distinct
Authority/Session/Workspace types and clearing AVX2/NEON compression kernels.
It enables only the existing first-party clearing dependency. Workspace cleanup
covers all packed initial words, schedule, working words and six temporaries,
including inactive lanes. Backend errors, checked counter overflow and unwind
quarantine authority without committing caller state. Raw caller states/blocks
remain caller-owned at this low-level boundary.

`brynja-hash-sha2/hardened-batch-execution` adds the separate `hardened_batch`
module. It handles SHA-224/256 canonical arbitrary-bit input, mixed identity,
inactive slots and uneven lengths through clearing storage. Exact-width secret
destination borrows move into a non-copying output owner and clear on failure
or Drop; public output requires explicit declassification and commits atomically.
Budgets include padding; routine rejection/cancellation permits executor reuse,
while backend/invariant failures and unwind quarantine it.

`brynja-crypto-cpu/sha512-hardened-batch` and the leaf
`brynja-hash-sha2/hardened-batch512-execution` extend these contracts through
distinct wide owners and kernels: four AVX2 lanes or two NEON lanes, SHA-384,
SHA-512, named /224 and /256, and all 510 general SHA-512/t parameters. Secret
outputs preserve exact parameter identity and canonical final bits. Finite work
includes general IV derivation as well as padding. Ordinary batch storage and
public digest importers are not used for secret state. Full qualification is
still pending. Keccak now
has a distinct default-off `brynja-crypto-cpu/keccak-hardened-batch` permutation
foundation with four AVX2 or two NEON lanes. Word/byte state entry points clear
all packed state, parity, delta and rho/pi/chi staging on every exit and commit
caller state only after health/accounting validation.

`brynja-hash-sha3/hardened-batch-execution` adds distinct SHA-3/SHAKE/cSHAKE
leaf batching with four optional slots, per-lane domains/rates and arbitrary-bit
messages/customization/output. Virtual framing cursors and clearing scalar
tails avoid ordinary batch storage. Secret outputs retain exact identity and
bit count; every supplied secret destination clears on failure, while public
destinations remain unchanged on failure. Entire caller staging and owned
workspace clear on every exit, including unused capacity. Finite budgets count
prefix, padding and squeezing work. Required eligibility is checked before
secret processing; routine rejection permits reuse, backend/invariant/unwind
failures revoke execution. This feature does not enable ordinary batching.

The three separate hosted `sha256-hardened-batch`, `sha512-hardened-batch` and
`keccak-hardened-batch` features borrow those exact clearing leaf executors.
They never enable ordinary batch features. Portable avoids probing; Prefer may
select portable only on initial unavailability, not after KAT/health failure.
Generic x86 remains portable/unavailable without a build-specialized AVX2
deployment. Allowlisted little-endian AArch64 uses the OS NEON feature ABI;
cached detection does not prove arbitrary migration safety. CPU revocation
affects every borrowed accelerated executor, not unrelated portable executors.

The separate `brynja-hash-parallel/hardened-batch-execution` feature now adds
bounded scheduled SHAKE leaf groups for all four ParallelHash identities.
Plan-bound affine results retain exact indices and clear on merge/drop; the
collector validates provenance and order before absorbing CVs. Per-slot actual
vector participation drives worker policy and reports. Require rejects
incomplete groups; Prefer explicitly permits clearing scalar tails. Failure or
unwind cancels the root and clears workspace/results. The existing streaming
completion proof remains required. Distinct `execution::batch::Stream` owners
buffer exactly 4B caller-owned bytes across small updates, retain a borrowed
clearing executor and support arbitrary-bit final tails plus fixed/XOF output.
They construct a root-bound completion token only after checking zero pending
bytes and the exact expected leaf count. Cancellation is polled at buffering
boundaries; Drop/error/unwind clear pending storage and nested hash workspaces.
`brynja-hash-parallel-std/runtime-batch-execution` adds bounded worker-local
multibuffer executors. Only completed, plan-bound clearing CV loans cross worker
boundaries; authorities and unfinished state remain thread-local. Every started
worker is joined, results merge in submission order, and errors clear unmerged
results and cancel the root. Worker count, SIMD width, per-group permutation
budget and complete-input leaf limit are distinct. Actual vector/scalar work is
reported separately. Complete qualification remains pending.
Coordinator-panic tests now cover all four identities with zero, one or two
workers already started. Channel ordering checks worker completion and cleared
Storage at destruction, followed by terminal root/output checks. These add
runtime lifecycle evidence, not a general thread-joining or abort-erasure proof;
production behavior and release gates are unchanged.

Batch shape, configured limits and scheduling are public; callers must pad when
traffic-analysis resistance is required. Explicit clearing cannot guarantee
erasure of registers, compiler-created copies, caches, swap, dumps or DMA storage.
Drop requires normal return or recoverable unwinding, not abort/forced termination
or `mem::forget`. Independent cryptographic review, FIPS validation and military
deployment approval are not claimed.
