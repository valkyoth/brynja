# v0.25.1 — Isolated legacy HMAC compatibility

Status: in progress; not release-ready or published.

## Implemented scope

- New allocation-free `no_std` `brynja-legacy-hmac` package, with sealed SHA-1 and
  MD5 identities separate from modern HMAC and all modern facades.
- Explicit legacy-use acknowledgement, long-key normalization, streaming,
  consuming finalization, typed public/clearing secret tags and verification.
- Preselected 10-byte through full-length legacy tags, including RFC 2202's
  96-bit examples; modern HMAC's minimum remains unchanged.
- Canonical high-bit-order message tails; byte-aligned keys and truncation.
- Source-only archive allowlist: runtime sources, Cargo metadata, README and
  licences. Tests and assurance artifacts remain in the repository.
- Default-off `sha1-execution` with `execution::Sha1Hmac`: borrow one hardened
  executor, admit all empty streams before keys, reject portable authority and
  retain no fallback route. Fatal update or recoverable unwind destroys both
  inner and outer owners; atomic message-length rejection preserves them.
- Default-off `md5-batch`: explicit eight-slot HMAC-MD5 with real AVX2/NEON
  ipad/opad work, aggregate constant-time verification, typed public/secret
  tags and one compression budget spanning all phases. Ineligible shapes reject;
  normalization chooses scalar or SIMD before processing, never after failure.

## Verification and limits

The initial author tests exercise all fourteen RFC 2202 examples, all admitted
byte truncations, key/message boundaries, streaming partitions, malformed tag
lengths, public destination preservation and secret destination clearing.
Real extracted archives pass these checks in debug and release, plus 140 byte
comparisons against Python `hmac`/`hashlib` and 176 bit-message comparisons
against separate Python hash models per profile. Byte-aligned controls also
check the bit models against Python's standard-library HMAC. Fourteen acceptance
tests reject archive, graph, feature/default and oracle-population mutations.
Twenty-one all-feature compile-fail doctests enforce affine/local state and output
constraints. Twenty-eight additional extracted-consumer negatives reject lifetime,
authority, algorithm-substitution, private-rebind and forbidden-export mistakes.
Strict Clippy for the new crate, Rust 1.90 tests, bare-metal
`x86_64-unknown-none` and Apple Silicon cross-compilation pass. Cross-compilation
is not native execution. The all-feature Clippy command requires `--no-deps`
for this scoped result: the unchanged SHA-1 CPU implementation triggers four
Rust 1.99 `chunks_exact_to_as_chunks` style warnings under a dependency-wide
`-D warnings` invocation. No shared implementation was changed to silence them.
These checks do not establish independent security or compiler cleanup qualification.

Explicit SHA-NI development runs on the local AMD x86-64 host pass in debug and
release, both from the workspace and extracted archives: 70 byte cases with
every admitted truncation and mismatched byte position, 88 bit cases with
streaming splits, and malformed-output/revocation tests. The native driver
independently checks exact populations and byte/bit results, and rejects absent
host features rather than substituting portable execution. Four driver tests
cover malformed populations, forged results and incomplete host feature probes.
Three private liveness/drop tests also pass under pinned Miri
`nightly-2026-09-11`; no full sweep was started or claimed.

The MD5 secret kernels and ordinary hash paths are unchanged. The hardened batch
driver now supports a borrowed prefix block per lane, and accumulates its length
before existing vector-tail processing. Focused portable and AVX2 regressions
cover all 256 active masks, canonical bit tails, padding/block boundaries, exact
work accounting and every cancellation/revocation/unwind checkpoint. Existing
MD5 batch tests also pass. The source-binding inventories are development drift
checks, not independent approval or a refreshed native qualification.

Native AVX2 HMAC author tests cover all masks, every admitted truncation, 70 byte
cases and 88 bit cases checked against independent Python models, both scalar
and SIMD long-key normalization, all tag-byte mismatch positions, exact budgets
and each cancellation/revocation/unwind boundary. Separate explicit native tests
do not silently pass on generic builds. No new unsafe or kernel code was added.
The three native HMAC-MD5 tests also pass under AddressSanitizer with
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:exitcode=1` and
`LSAN_OPTIONS=exitcode=23` on pinned `nightly-2026-09-11`. This is a runtime
memory-safety check, not proof of cleanup of compiler-created copies.
A separate bounded portable-prefix Miri test passes on the same pinned nightly,
covering prefix/padding budget rejection, a partial-bit tail, output clearing
and subsequent reuse. It does not claim to interpret the SIMD assembly.

Existing hash qualification does not qualify the new composition. Default constructors stay portable even under
dependency feature unification. The separate SHA-1 execution API is explicit.
No modern, FIPS, protocol negotiation,
protected-memory, register-erasure or fatal-path guarantee is inferred.

### Apple Silicon author check

Commit `6c3f34b3` was exported into a fresh directory on the Apple M2 Pro builder
(macOS 27.0.1, Rust 1.99.1). The source archive's SHA-256 was
`6dfa89b45230ad6988bfe80b4947bdd8ddb009a3a525cc584a60c93d6d961c6e`,
reconciled locally and remotely before extraction. No GitHub push was required.

- `python3 scripts/legacy-hmac/legacy_hmac_native.py`: two explicit SHA-1
  native tests per profile, debug and release, with `+neon,+sha2`; exact marker
  populations and 70 byte / 88 bit outputs checked independently by Python.
- `python3 scripts/legacy-hmac/legacy_hmac_md5_native.py`: three explicit NEON
  HMAC tests per profile, debug and release, with `+neon`; all 256 slot masks,
  70 byte / 88 bit cases and lifecycle/failure tests passed. The four-lane route
  exercises partial eight-slot batches that cannot be eligible on AVX2.
- `cargo test -p brynja-legacy-md5 --features hardened-execution
  --test hardened_execution --test prefixed_execution`, debug and release,
  with `RUSTFLAGS='-C target-feature=+neon'` and
  `BRYNJA_REQUIRE_HARDENED_MD5=1`: all nine tests passed per profile, none ignored.

These are source-bound author-operated functional checks, not signed runner
attestations, independent review, complete cleanup qualification or release
native-admission records. Existing approvals were not replaced.

## Work remaining before completion

The owner approved including protected/resident APIs in this version. Initial
`brynja-legacy-hmac-std` Linux scalar sessions now preacquire guarded, locked,
dump/fork-excluded workers and separate buffers for SHA-1/MD5 HMAC. Keys and
intermediates are processed on the joined worker; no arbitrary callback or
ordinary-memory fallback is exposed. Native author checks cover real mapping
flags, long keys, bit tails, truncated tags, all mismatch positions, cancellation,
worker/consumer unwind, forgotten output loans and reuse after rejected work.
Extracted debug/release archives pass 26 ownership/classification negatives and
ten compiled cleanup/admission mutation runs. The new source-only archive is
about 16 KiB; evidence stays in the repository. This is not independent/native
qualification, register-erasure proof or a modern/strict facade export.

The bounded Miri checks pass two hosted metadata/unsupported-model cases and
the three relocated private retained-owner tests. Native ASan with enforced
LeakSanitizer and fatal sanitizer exits passes five hosted lifecycle/bit tests;
the real-residency observation test is excluded from instrumentation because
sanitizer-managed stacks do not establish the native mapping guarantee. These
diagnostic checks do not replace compiler/timing or native platform qualification.
Rust 1.90 and 1.99.1 builds, strict scoped Clippy, and Apple/Arm cross-compilation
also pass. The earlier test-source inclusion was moved into its actual private
module so the existing no-code-inclusion policy remains unchanged.

Focused Apple Silicon rejection check: the committed source subset
`b23578e1` (archive SHA-256
`620800325b691a8ddb353f6b4783d9a0c124723d4bd57352422ac7b1d3363641`)
passed both metadata/unsupported-profile tests and five documentation checks in
debug and release on `macosbuilder` with Rust 1.99.1. Linux strict construction
rejects there instead of silently becoming resident-only. This is author-operated
rejection evidence, not an implemented or qualified macOS legacy HMAC session.

Subsequent macOS implementation: default-off `macos-resident` now supplies
separate scalar SHA-1/MD5 sessions, bounded requests, typed output loans and
worker-side verification. It uses safe `ResidentBytes`/`ResidentStack` wrappers
over the existing Darwin adapter; no low-level implementation or cryptographic
kernel changed. These resources are guarded, locked and fork-excluded, but not
dump-excluded. The generic resource callback API documents ordinary host closure
captures and caller-created copies; HMAC exposes no arbitrary callback and
creates keyed state only on its joined worker.

Author-operated Apple Silicon checks passed six resident tests in extracted
debug/release archives, 28 compiled ownership/algorithm/profile-separation
negatives with both Cargo features enabled, and ten cleanup/admission mutation
runs. The existing ten Darwin resource tests also passed, plus the new native
resource placement/clearing/reuse test in debug/release and five resource
ownership compile-fail examples. The nine added/changed Rust resource/session
files were reconciled byte-for-byte between the tested Mac copy and local
candidate. Linux extracted tests still pass; opposite-platform constructors
reject, and four bounded Miri metadata/model-rejection tests pass. Native Mac
hosted acceleration was still pending at that scalar checkpoint. Full composition
qualification and independent review remain pending. Source-drift inventories
were refreshed, not native evidence approvals.

Subsequent SHA-1 hosted acceleration: the separate default-off
`strict-sha1-acceleration` and `macos-resident-sha1-acceleration` features now
expose distinct `Sha1CompiledSession` owners. Required static authority is
constructed/probed only on the corresponding worker before keys are accepted;
every request reconstructs the same backend there. HMAC normalization, inner and
outer processing use the existing hardened SHA-1 composition. No kernel,
low-level resource adapter, modern facade, dependency version or release gate
changed. Generic scalar sessions stay scalar under feature unification.

The wrapper arms quarantine before thread launch. Backend revocation, wrong
backend/result shape and worker unwind remain terminal; public admission errors,
canonical-bit rejection, cancellation and mismatch allow reuse. Only the two
existing pre-entry thread-setup error variants restore reuse after launch fails.
Native tests inject revocation, cancellation and unwind at every seven
authentication/six verification checkpoints, plus post-output failures, forgotten
loans, malformed shapes and explicit quarantine. Linux also inspects the actual
worker state and staging/output mapping flags. No register/whole-image erasure
or macOS core-dump-exclusion guarantee is inferred.

Author-operated GNU/Linux SHA-NI and Apple Silicon SHA-1 extracted-package
checks each pass ten runtime tests in debug/release, 39 compiled
ownership/lifetime/profile-isolation negatives, ten scalar cleanup/admission
mutations and fourteen compiled authority/cleanup mutations. The independent
byte/bit oracle for the underlying leaf remains the earlier composition check;
the new hosted differential compares against the portable leaf, not a new
independent cryptographic review. All eighteen profile implementation/test Rust
files were reconciled byte-for-byte between local and tested Mac copies; only
the crate-root documentation was subsequently updated.

Focused validation also passes MSRV 1.90 compilation; scoped native Clippy on
Linux/Mac; eight Miri metadata/unsupported-model tests; and the native hardware
failure-boundary test under ASan with forced LeakSanitizer/fatal exits. The
sanitizer run is diagnostic, not a protected-stack placement claim. Generic
all-feature builds reject missing native features/platforms without fallback;
the three README examples and twelve ownership compile-fail doctests pass.
Workspace/README/unsafe policy regressions remain intact. No full sweep or
native evidence approval was performed in this implementation pass.

Subsequent hosted MD5 SIMD implementation: separate default-off
`strict-md5-batch` and `macos-resident-md5-batch` features now expose
`Md5BatchSession`, bounded borrowed lane descriptors and clearing
`Md5BatchOutput` loans. All eight output slots and staging bytes live in
preacquired profile-specific mappings. Required AVX2/NEON authority and every
key-derived intermediate are constructed on the joined worker, never moved from
the host stack. The leaf's full-group requirement, scalar suffix/padding and
preselected scalar normalization for ineligible long-key groups are preserved;
errors never select an alternative HMAC implementation.

One configured compression budget is shared across all phases of each request.
Public lane/key/message/bit/candidate admission occurs before worker execution;
canonical secret tail contents are checked on the worker. Returned backend,
width, active population and actual inner/outer SIMD work are checked before
releasing output or a verification decision. Post-error health revalidation
ensures revocation cannot masquerade as ordinary cancellation/budget exhaustion.
Backend, malformed-result and unwind failures quarantine the wrapper; ordinary
request errors preserve reuse. No raw authority or arbitrary worker callback is
exported. Linux strict and Apple resident types remain non-interchangeable;
Apple memory still has no core-dump exclusion.

Author-operated Linux AVX2 and Apple Silicon NEON package checks each pass eleven
runtime tests in debug/release, 47 compiled ownership/lifetime/algorithm/profile
negatives, ten scalar cleanup mutations and 22 MD5 authority/cleanup/verification
mutations. The matrix covers all 256 slot masks, all canonical final bit widths,
key and message block/padding boundaries, every byte of all supported truncated
tags, scalar/SIMD normalization and every observed control/post-write failure
point. These differentials compare the hosted route against the portable legacy
leaf; they do not replace the earlier independent leaf oracle or a fresh review.
Forgotten loans, early cancellation, malformed inputs, resource limits, wrong
backend/reports and explicit quarantine are exercised. Linux checks actual worker
and buffer mapping flags. The source-only hosted archive is about 45.5 KB and
contains no evidence bundle.
All 29 hosted Rust implementation/test files were reconciled byte-for-byte with
the final tested Mac copy. Combined native all-feature builds pass 21 tests on
each platform, including the opposite profile's unsupported-target rejection.

Focused checks also pass MSRV 1.90 compilation, native scoped Clippy, twelve
Miri metadata/unsupported-model tests, and the complete MD5 control-failure test
under ASan with forced LeakSanitizer/fatal exits. Instrumented execution is
diagnostic only, not residency qualification. The four README examples and
sixteen compile-fail doctests pass. No unsafe code, cryptographic kernel,
low-level platform adapter, external dependency version or release gate changed.
This implementation pass does not approve native evidence or start a full sweep.

### Bounded timing and scratch-compiler diagnostics

The isolated `assurance/legacy-hmac-timing` fixture covers explicit portable,
static SHA-1/MD5, protected Linux scalar/compiled and resident Apple
scalar/compiled selections. A generic host probe must succeed before the runner
enables static instruction features. Required MD5 routes check the full native
lane width and actual inner/outer SIMD work; no failure selects a portable route.
Before collecting samples, both key classes must produce the expected tags and
accept correct candidates; first/last mismatch classes must both reject. Four
source-compiled mutations (no-op output, fixed key, always accept, always reject)
are rejected for each algorithm. Generic builds reject unavailable acceleration;
baseline AArch64 NEON is not incorrectly treated as unavailable.

Each route/family measures eight fixed-public-shape campaigns: 10-byte/full tags,
32-/200-byte keys, mismatch position and key content. It retains 512 interleaved
pairs after warm-up, with four operations per measurement. The paired diagnostic
threshold is 10, not a release security threshold. Hosted measurements include
worker start/join and per-request compiled-authority reconstruction; they do not
measure session construction. Scheduling noise can obscure a leak. These are
synthetic data tests, not proof of constant time, cache isolation, protected
output-copy behavior or independent qualification.

On the local AMD x86-64 host, all eight route/family combinations completed:
portable, required static, Linux protected scalar and Linux protected compiled,
each for SHA-1 and MD5. All 64 campaigns had zero diagnostic alarms. Raw final
observations are retained locally outside `target/` in
`release-reports/v0.25.1-timing/`, with compiler/binary/source hashes, exact commands
and complete output. An earlier development run was also quiet; the final run
followed timeout-preservation tooling changes, not an attempt to hide a signal.
The runner refuses overwrites and preserves failed/malformed/signalling output,
including partial output from a deadline failure. Parser/failure/probe regressions
and the compiled fixture controls pass. At that checkpoint Mac timing remained
pending because the builder was unreachable; the Apple follow-up below supplies
separate timing data, not an inference from native functional tests.

The separate `assurance/legacy-hmac-cleanup` fixture imports the actual runtime
`Scratch` source. Five fixed probes cover the 1-byte comparison accumulator,
20-byte digest staging, 64-byte pad, mask transform and an unwinding observer.
The existing fail-closed LLVM path checker is loaded by exact path, with a
separate exact legacy probe population. It requires clearing of the same complete
allocation before every reachable normal/error/recoverable-unwind exit and before
lifetime end; another branch's clearing cannot satisfy the obligation. MIR
destructor identity and emitted assembly symbols are also checked. Removed and
half-range destructor clears are rejected after successful compilation; emitted
artifact mutations test clear identity, pointers, extents, early return, unwind
bypass, post-clear writes and missing/duplicate probes.

All twelve compiler/profile/target combinations pass: Rust 1.90.0 and 1.99.1,
`panic=abort` and `panic=unwind`, targeting GNU/Linux x86-64, GNU/Linux AArch64 and
Apple AArch64. The two Arm lanes are cross-compiled inspection, not native runs.
Fatal abort does not run destructors. This establishes only these fixed Scratch
probes; it does not complete HMAC caller, MD5 row-owner or hosted-worker cleanup
qualification, nor assert whole-frame/register erasure. Both fixtures pass scoped
Clippy and formatting. No production implementation or release gate changed.

### Portable caller ownership qualification

`assurance/legacy-hmac-engine-cleanup` now emits eighteen real public consumers:
construction, cancellation, update followed by an unwinding observer, and
public/secret/verification finalization with byte or bit tails, for both legacy
identities. The bounded LLVM checks cover two cancellation graphs, two
update/error/unwind graphs, fourteen constructor/finalizer scratch graphs,
twelve consuming-finalizer owner graphs and two constructor owner graphs.

The constructor checker tracks complete inline initialization before use,
normalization-owner consumption, owner-copy provenance, cleanup on rejection or
recoverable unwind, and transfer of the inner/outer owners to their exact result
fields. Success requires both transfers and the correct Result discriminant;
failure cannot export an owner. Returned ownership remains tracked so a later
store cannot silently overwrite it. Finalizer checks follow the actual inner and
outer hash states through moves and consuming hash-finalizer/destructor calls.
Outlined Engine routines are resolved from the actual consumer call, whose
owner argument must be bound to the complete input-state copy; all caller exits
must follow that dispatch. Wrong algorithms, partial copies, missing cleanup,
unknown pointer aliases and unreviewed calls fail closed.

The shared, existing LLVM interpreters are loaded by exact repository path with
origin checks. Legacy-specific identities, layouts and scratch populations use
private module instances; modern HMAC's configuration is unchanged. Regressions
exercise graph populations, import origins, cleanup pointers/extents, unwind
bypasses, incomplete initialization, wrong returned fields/discriminants,
post-export overwrites and wrong outlined-call input pointers. Three additional
source-compiled mutations forget a cancelled owner, forget an owner on update
error, or remove the observer path; each compiles successfully and is rejected
by the checker. These tests validate the checker, not a new production fix.

All twelve compiler/profile/target combinations pass: Rust 1.90.0 and 1.99.1,
abort/unwind, GNU/Linux x86-64, GNU/Linux AArch64 and Apple AArch64. Arm results
are cross-compiled inspection, not native execution. Hash destruction and core
clearing retain their separately reviewed non-panicking callee contracts;
safe-Rust non-aliasing remains a premise. This is caller ownership/cleanup
dispatch qualification, not proof of erasing every compiler-created copy,
register, spill, caller input, OS snapshot or fatal-abort path. It does not
qualify the distinct accelerated SHA-1, MD5 batch-row or hosted worker paths.
No production source, dependency version, native approval or release gate was
changed. Mac timing was still pending at this checkpoint; see the follow-up below.

### Accelerated SHA-1 retained-owner qualification

The new `assurance/legacy-hmac-execution-cleanup` fixture contains real public
consumers. Its first qualified subset is cancellation, borrowed update and
consuming update/cancellation with an unwinding observer. The checker emits and
inspects both the downstream fixture **and the actual legacy-HMAC library**:
these non-generic public calls are otherwise opaque in the downstream artifact.
Module identities remain separate, so a fixture cannot substitute its own
definition for the leaf implementation. Constructor/finalizer consumers are
present for subsequent work but are not counted as qualified by this check.

The bounded interpreter follows the real retention guard and its outlined
cleanup helper. It checks the exact inner-stream/input binding, complete owner
moves, allocation bounds, liveness discriminant, both SHA-1 owner destruction
dispatches, and result classification. Successful updates and atomic length
rejections retain the engine; fatal errors and recoverable unwind destroy both
owners and empty the retention slot. Empty-state operations never dispatch to
the primitive. Consuming callers must clean up on both update rejection and
observer unwind. Unknown instructions, callees, aliases, result encodings and
unresolved cross-module calls fail closed.

Independent constant-result probes bind the compiler's actual Result ABI and
public owner size. The interpreter explores empty and both live boolean-niche
values, every signed byte payload for each public stream-result variant,
including the unused success payload, and the update/observer unwind paths.
The payload population deliberately includes a conservative superset of
inhabited errors. No secret input values are modeled.

Regressions include wrong/partial owner moves, wrong cleanup pointers/extents,
missing fatal-slot transitions, incorrect preservation/result classification,
unwind bypasses, unknown pointer aliases and fixture/leaf substitution. Three
downstream source mutants forget cancellation, forget update-error cleanup or
remove the observer; three real retention-guard source mutants preserve every
failure, destroy state on atomic length rejection or forget the removed engine.
Mutants must compile successfully; compilation failures do not count as
successful detection. The unmodified extracted fixture/library is validated
before applying these changes.

All twelve compiler/profile/target combinations pass: Rust 1.90.0 and 1.99.1,
abort/unwind, GNU/Linux x86-64, GNU/Linux AArch64 and Apple AArch64. Arm artifacts
are cross-compiled inspection, not native execution. This check retains the
separately reviewed, non-panicking primitive-destructor contract; it establishes
logical ownership and cleanup dispatch, not erasure of compiler-created copies,
registers, spills, caller buffers, OS storage or fatal-abort paths. No production
source or release-gate behavior changed. Accelerated constructor/finalizer,
MD5-row/batch and hosted-worker qualification remain separate unfinished work.

### Apple timing follow-up and accelerated finalizer cores

The Apple M2 Pro builder returned online with macOS 27.0.1 (26A434) and Rust
1.99.1. Its timing preflight exposed a test-only portability issue: mocking
`subprocess.run` also intercepted the subprocess used by Python's macOS
`platform.platform()` implementation. Commit `a6fad4a5` isolates platform
identification in that synthetic test and asserts exactly one mocked measured
child call. All eight preflight tests, including compiled no-op/key/decision
negative controls, pass on both Linux and macOS. Production code, measurement
logic, populations and thresholds are unchanged.

A clean Mac checkout at `a6fad4a54521b8db462382677ca8c4fee5ea6358`
completed eight route/family combinations: portable, required static hardware,
resident scalar and resident compiled hardware, each with SHA-1 and MD5.
All 64 campaigns completed with zero diagnostic alarms; the largest absolute
paired statistic was approximately 2.47, below the unchanged threshold of 10.
The compiled routes passed the generic CPU-feature preflight before instruction
entry; compiled MD5 used complete four-lane NEON groups. Resident scalar and
portable records retained generic build flags. This is a coarse diagnostic
screen, not a constant-time proof, independent review or release approval.

All eight JSON observations were downloaded outside `target/` to
`release-reports/v0.25.1-timing/mac-a6fad4a5/observations/` and reconciled against
the remote file SHA-256 values. Each record's complete raw output was parsed
again, its output digest and all eight campaign statistics recomputed, and all
701 source SHA-256 bindings recomputed against the local source files.
The remote checkout remained clean. No failed or signalling timing capture was
discarded or rerun; the failed preflight above was synthetic, before collection.

The accelerated SHA-1 compiler checker now additionally checks the real public
tag and verification Engine cores called by both byte and bit finalizers.
It follows both 448-byte stream owners through complete moves and exact
consuming stream-finalizer/SHA-1 owner-destruction dispatches, including outer
updates and recoverable unwind. Three full scratch graphs cover public tags,
secret tags and verification, including inner digest, tag and comparison
accumulator storage. The secret scratch check includes its actual retained
wrapper, but does **not** establish that wrapper's stream-owner transfers.
The shared interpreter uses a private accelerated configuration; portable and
modern HMAC configurations remain unchanged.

Regressions reject wrong finalizer identities, partial stream copies, wrong
owner pointers, missing/misdirected/short scratch clearing, early exits and
byte/bit methods redirected to a different core. The twelve compiler/target/
panic combinations pass again. The outer retained-engine transfer and the
constructor's admission/normalization ownership still require their own checks;
these core/scratch results do not close those obligations. No production code
or release gate changed in this follow-up.

### Accelerated SHA-1 retained finalizer handoffs

The subsequent `legacy_hmac_execution_handoff.py` check closes the retained
transfer obligation left open above. It follows both 448-byte stream owners
from the optional engine through LLVM's split byte copies and scalar moves
into the actual public/verification Engine cores or the inlined secret-output
graph. Empty and both live niche values are explored separately. Live owners
must be consumed exactly once on every modeled normal-return or recoverable
unwind exit; absent state must not dispatch to a primitive, and empty-state
secret finalization must clear the exact supplied destination and length.

The secret closure's captured pointer is tracked through its private storage,
copies and loads. Only its public tag-width prefix read is admitted, while a
stream-byte pointer, incomplete capture copy, overwritten pointer, dead source
or owner-aliasing auxiliary argument is rejected. The six actual downstream
byte/bit consumers must forward their own owner and original output/candidate
and tail arguments. Byte-secret forwarding requires a live, path-dominating
`None` tail initialization rather than merely finding a store somewhere in
the function text.

Eight new regression groups mutate real emitted graphs, including partial
owner moves, missing scalar pieces, wrong owner/output/tail pointers, capture
redirection and lifetime errors, unwind bypasses, missing empty-output clearing,
missing/repeated consumer dispatch and non-dominating tail stores. Three
downstream source mutants also compile successfully before being rejected:
forgotten finalization, dropped bit-tail processing and changed candidate length.
The existing twelve retained/core regression groups continue to pass. The full
twelve-combination Rust 1.90.0/1.99.1, abort/unwind, GNU/Linux x86-64/AArch64 and
Apple AArch64 inspection matrix passes with the checks composed together.

This remains bounded logical ownership/cleanup-dispatch qualification under
safe Rust non-aliasing and the separately checked primitive/core/destructor
contracts. It is not proof of erasing compiler-created copies, register/spill
contents, caller buffers, OS state or fatal-abort paths. Cross-compiled Arm
inspection is not native execution. No production code, timing capture,
native approval or release-gate policy changed. Accelerated constructor
admission/normalization, MD5 row/batch and hosted-worker qualification remain
unfinished and are not covered by this result.

- Complete the remaining qualification-specific failure-injection checks;
  focused native x86/Arm functional execution now passes.
- Qualify both accelerated compositions and their protected/resident owners,
  including MD5 prefix handling, without silently downgrading their guarantees.
- Complete accelerated SHA-1 constructor admission/normalization,
  MD5-row/batch and hosted-worker cleanup-codegen qualification; portable caller ownership, fixed
  Scratch probes, accelerated SHA-1 retained update/cancellation and Linux
  and Apple timing screens now pass, as do the public/verification finalizer
  core owner graphs, three finalizer scratch graphs and retained-finalizer
  handoffs.
- Register API/capability owners and a separately scoped evidence family.
- Obtain independent retest and run the affected release checks and GitHub.

No crates.io publication or release tag is authorized by this work-in-progress.
