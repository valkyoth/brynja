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

The CI integration follow-up repairs stale current-facade fixture identities
(six direct consumers and the combined hash fixture), excludes only the new
hosted legacy HMAC adapter from OS-less workspace builds, and moves the legacy
SHA-1/MD5 dependencies into shared workspace declarations without changing
their default-feature behavior. Standalone mutation/package consumers retain
the same disabled-default dependency contract. MD5 integration-test helpers use
standard module layout instead of forbidden module-path attributes; their bodies
are unchanged. No production Rust implementation changed.
The current MD5 operational-delta inventory now includes the prefixed path and
its tests, with explicit current pins rather than changes to historical captures.
Regression coverage rejects 46 facade identity/source/default-feature mutations
and 15 prefixed-MD5 inventory mutations; the existing bare-metal regression also
rejects accidentally retaining the hosted adapter or omitting the portable leaf.
These integration checks do not qualify the pending HMAC compiler/worker paths,
grant independent review, or alter the release gate or native approval records.

A subsequent CI run exposed the remaining KMAC and final SP 800-185 fixture
locks and the pre-legacy-HMAC SBOM. These now describe the current checkout;
the fixture preflight rejects 55 version/source/default-feature mutations across
the nine public-API facade fixtures. Modern-HMAC scope regression data is bound to its
actual v0.25.0 endpoint instead of assuming every later HEAD edit is HMAC-only.
A current shared-memory inventory change must still select the wider CPU scope.
The scope classifier and evidence-reuse rules themselves are unchanged.
The TupleHash facade-fixture review pin is refreshed for the version-only change;
the cheap metadata preflight now runs its ordinary validator too, with missing
and stale fixture-pin regressions. Historical native evidence remains untouched.
The README-status inventory now includes the hosted legacy HMAC crate and the
existing leaf execution rows, retaining all independent-review and pending
qualification limits; claim/table and inventory mutation tests cover both.
The shared Apple resident-resource row is likewise inventoried without a dump
exclusion or cryptographic-admission claim. The extracted MD5 initialization-order
mutation now targets the current `run_parts` call; it compiles and is rejected
in debug/release, and restored test populations pass. This is a test-anchor
correction, not a production lifecycle change.
The release dependency-order inventory also includes the hosted legacy HMAC
adapter after its dependencies; regression tests reject moving it ahead of them.
The internal milestone still authorizes no publication.
All 181 bounded push-CI commands passed across the initial run and corrected
suffixes, including workspace all-feature tests, both Clippy profiles and
documentation. The current SBOM and assurance metadata checks also pass.
These are author checks, not a full release-qualification sweep.

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

### Accelerated SHA-1 pre-key constructor admission

The constructor checker now follows the actual emitted entry graph up to, but
not beyond, the first pad lifetime. It requires the 10–20-byte tag predicate,
a non-portable report and two successful starts (three for keys longer than
64 bytes), all through the original executor, before that frontier. Every
modeled start failure and recoverable unwind must destroy already acquired
owners. No pre-frontier instruction may read or escape the key pointer.
Complete byte provenance binds the admitted streams to the ordered iterator
slots, with its cursor, end, optional third slot and empty caches checked.
Invalid tags and portable authority return their own rejection identities.

Six additional constant/type probes bind stream size, start-result and
constructor-error niches, portable-report identity and the nested-option
iterator-cache encoding independently of the implementation under inspection.
The downstream constructor preserves the original executor, key and tag width;
the actual default constructor forwards to the same body with a 20-byte tag.
These are cross-compiled ABI probes, not execution of hardware instructions.

The constructor's complete pad/digest scratch graph is now checked, including
normal-return and recoverable-unwind clearing. In unwind builds, the actual
outlined iterator destructor is additionally inspected across 2,048 bounded
metadata inputs: two/three initial streams, four cursors, independent boolean
niches for all five slots, both cache occupancy bits and normal/unwinding
entry. Its actual remaining-owner destruction events must match exactly.
This helper population is deliberately a conservative superset of constructor
states. It does not bind the later caller's evolving metadata to those inputs.

Under panic=abort LLVM instead inlines the iterator destruction into the
constructor. The diagnostic explicitly reports no outlined helper there:
the scratch and pre-key admission checks pass, but the inlined iterator owner
paths remain part of the unfinished post-admission obligation. No helper-name
search or scratch-only success is called complete constructor qualification.

Nine new regression groups reject changed admission predicates, executor/key
substitution, partial stream copies, missing earlier-owner cleanup, unwind
bypasses, corrupted iterator metadata/destruction, short scratch clearing and
ABI/forwarding drift. Four real leaf-source mutants compile before rejection:
changed long-key threshold, weakened tag minimum, portable-report substitution
and key-pointer exposure before admission. Existing retained/finalizer tests
continue to pass. The composed twelve compiler/target/panic combinations pass
on Rust 1.90.0/1.99.1 and GNU/Linux x86-64/AArch64 and Apple AArch64.
Arm results are cross-compiled inspection, not new native observations.
No production implementation, timing capture, native approval or release-gate
policy changed; source-owned logical cleanup is not register/spill erasure.
All sixteen existing Linux/Mac timing source closures were recomputed and
remain unchanged; no timing campaign was repeated for these assurance edits.

### Accelerated SHA-1 post-admission constructor ownership

The next composed check closes the post-admission **stream-ownership** obligation
left open by the preceding checkpoint. It starts from the pre-key admission
states, follows the actual iterator cursor and each complete 448-byte stream
through split copies/scalar moves, and requires the long-key stream to be
updated and consumed by normalization before the inner/outer pair is returned.
Both pad-update calls must use the correct ordered owner and 64-byte pad;
normalization must receive the original key and a 20-byte digest destination.
Successful returns preserve the selected backend and tag width, with the
correct inner/outer stream pair and no additional live logical owner. Modeled
errors and recoverable unwinds must consume every admitted stream.

For outlined cleanup, the current caller cursor, optional third slot and empty
caches are bound to the independently inspected iterator helper. Its actual
normal/unwind outcomes are used, rather than assuming helper calls cannot
unwind. For panic=abort, the same post-admission walker follows the inlined
iterator pointer arithmetic and destruction paths directly. The separately
reviewed, source-bound non-unwinding `clear_owned_region` contract applies to
the return-temporary scratch clear; it is not inferred from a symbol substring.

Seven regression groups cover all three update roles, normalization handoff,
split returned owners, tag/backend metadata, remaining-iterator cleanup,
unwind leaks and unexpected indirect calls. Four real source mutations must
compile before rejection: swapped returned owners, updating inner instead of
outer, ignoring the long key, and replacing the requested tag width. The
inlined abort cleanup mutation removes the reachable array-owner destruction,
not merely the unreachable empty-cache calls. Earlier checkpoints' scratch,
retained/finalizer and pre-key checks remain composed with this analysis.

This is bounded ownership and initialization-dispatch inspection, under safe
Rust and the existing primitive/Drop contracts; it does not independently prove
pad contents, primitive cryptographic correctness, register/spill erasure or
cleanup after fatal abort. All twelve Rust 1.90.0/1.99.1, abort/unwind and
GNU/Linux x86-64/AArch64/Apple AArch64 combinations pass. The seven new groups,
existing twelve retained/core, nine admission and eight handoff groups pass,
as do the legacy HMAC Rust tests/doctests; their five explicit native-only
tests remain ignored in that generic run, not newly qualified. Matrix logs
are retained locally under `release-reports/`. Cross-built Arm artifacts are
inspection only. No production Rust, native observation,
dependency or release-gate policy is changed by this checkpoint.

### Accelerated MD5 batch row cleanup

A separate compile-only consumer now binds public output, secret output and
verification to the actual MD5 batch methods, preserving their selection,
input, destination/candidate and control arguments. The emitted LLVM control
flow is inspected for the 512-byte pad and three 128-byte row owners, the
actual normalization helper's 128-byte owner, and the actual comparison
closure's one-byte accumulator. Every modeled normal return and recoverable
unwind must dispatch full-width clearing before ending a live row's lifetime.
Unknown calls conservatively invalidate prior clearing; pointer-root analysis
exempts only provably disjoint stores. Exact source-bound clearing destructors
are non-refilling premises, not substitutes for explicit row clearing.

The actual workspace destructor is separately followed through all eight
113-byte lane owners, including unwind paths. Caller binding requires its
distinct 912-byte workspace allocation. These source-integrity pins and
compiled-artifact checks are author checks, not independent approval.

Eight regression groups reject missing/short/substituted clears, late writes,
indirect callbacks, damaged workspace lane dispatch, source-premise drift,
captured/unknown pointer aliases and changed downstream arguments. Three real
leaf-source mutations compile before rejection: clearing only the first row,
replacing clearing with `black_box`, and forgetting a populated row owner.
All sixteen configurations pass: Rust 1.90.0/1.99.1 with abort/unwind, generic
x86-64 plus AVX2 x86-64 and NEON Linux/Apple AArch64 inspection. Local matrix
logs are retained in `release-reports/v0.25.1-md5-row-{generic,simd}.log`.
The fixture itself is compile-only and contains no runtime tests. Separately,
the existing native AVX2 lifecycle/byte/bit-oracle checks pass all three
explicit tests in both debug and release, and the three native-validator
regressions pass. No new native Arm execution is claimed by this checkpoint.

This closes the row-storage cleanup checkpoint, not whole-caller qualification:
MD5 admission, prefix handling, output transactions and quarantine binding,
and the protected/resident worker paths still require their remaining checks.
It does not establish register/spill erasure, fatal-abort cleanup, primitive
correctness or release approval. No production implementation or release-gate
policy changed.

### MD5 pre-workspace admission and three-profile native failures

The emitted constructor is now inspected up to its first `Workspace::new`
call. Its exact unsigned tag-range predicate must admit only 10..=16 bytes;
invalid tags return before reading authority, and portable authority returns
the distinct unavailable error. Accepted paths must pass the original executor
and a separate 912-byte destination to the real workspace constructor. No
unexpected call, external write or early successful return is accepted before
that boundary. Downstream type probes independently bind the error layouts,
backend observation/niche and constructor forwarding. This checkpoint stops
before workspace initialization/readiness and does not claim those later
caller operations are qualified.

The composed cleanup/admission suite passes ten regression groups, including
predicate, authority, rejection identity, side-effect and probe substitutions.
Its five real compiled source mutants include two widened tag ranges alongside
the three row-cleanup mutants. All sixteen generic/AVX2/NEON compiler/target/
panic configurations still pass. Logs are local under
`release-reports/v0.25.1-md5-admission-{generic,simd}.log`.

Native failure injection now measures and tests callback boundaries separately
for public output, secret output and verification, with both scalar and SIMD
long-key normalization. Cancellation preserves reuse; revocation and unwind
are terminal. Revocation during scalar normalization is observed at the next
executor readiness check, not necessarily immediately on callback return.
Malformed candidates cover every lane and admitted tag width, including
active/inactive mismatches, and must reject before spending work or invoking a
callback. Verification now also covers every insufficient work budget and
retained-token revocation. Native AVX2 and Apple NEON runs pass all three
explicit tests in debug and release, with updated required population markers.
The Mac used a private source snapshot of `7c29e8ba` plus the test-only overlay;
local native logs record its archive digests. These are author-operated focused
tests, not independent review or release qualification. All-feature leaf tests,
doctests and focused Clippy pass; no production Rust changed.

### MD5 final-readiness and consumer ordering

The actual final `Workspace::with` cancellation helper is now inspected before
accepting its use as the output fence. For each of four error discriminants
and success, all 256 byte payloads are modeled (1,280 normal outcomes), plus
readiness/cancellation unwind in unwind builds. The helper must use its
workspace's authority, initialize the scope and eight public IV slots, cancel
only after successful readiness, destroy the scope with the right completion
flag, and preserve the readiness result. Primitive readiness and non-panicking
clear/quarantine behavior remain separately reviewed callee premises. The
scope and quarantine sources are hash-bound for drift detection, not external
review authentication or a new transitive machine-code proof.

All three emitted callers must dispatch that inspected helper with their
912-byte workspace and check the returned success discriminant before handing
off their 128-byte truncated rows. Cutting that success edge must make the
consumer unreachable; neither error nor unwind edges may reach it. The success
block permits no intervening callback or computation. Public output is bound
to the original destination and full extent; verification uses the original
candidate pointer and selected tag width. Secret output permits only the
24-byte initialization-capture move before its actual consumer closure.
This does not yet prove that capture's entire earlier ownership history, all
other output writes, the preceding HMAC phases or the final returned report.

Five new regression groups reject altered helper authority, completion flags,
IV copies, result/error propagation, missing scope cleanup, swallowed unwind,
caller edge bypasses, late callbacks and substituted row/consumer inputs.
The composed ten-group suite now also compiles and rejects removal of the
final fence and moving it after consumption (seven compiled source mutants
in total). All sixteen compiler/target/panic configurations pass; the focused
native AVX2 debug/release checks still pass. No production Rust, root manifest,
release gate or native approval changed. The compile-only fixture adds a direct
first-party MD5 dependency solely for its independent readiness-result type
probe. Local logs are `release-reports/v0.25.1-md5-handoff-{generic,simd}.log`.

### MD5 phase argument and closure transport

The emitted public, secret-output and verification callers now bind workspace
construction to the original selection's executor. Normalization must use the
original input/control arguments and selected backend, and the same 512-byte
pad and 912-byte workspace used by the hashing phases. The inner call must
receive the 256-byte message descriptors and 128-byte inner rows. The outer
call must receive a distinct 256-byte outer descriptor array and 128-byte final
rows, transported with the pad/control pointers through the actual 32-byte
closure record. All four capture fields and the actual outlined helper's loads
and forwarding are inspected. Partial/repeated writes, aliases, escapes, wrong
offsets, premature lifetime ends and intervening effects are rejected.

Construction must dominate normalization; normalization must dominate each hash
dispatch; outer dispatch must dominate the final readiness fence. This is not
yet a proof of inner-result success propagation into the outer phase: older
compilers merge readiness errors and digest results through phi/switch nodes,
so simple CFG dominance alone cannot establish that property. Per-lane
descriptor contents, key normalization/pad transformation, full output-owner
history, returned reports and quarantine classification also remain separate
unfinished obligations. Pointer transport is not a whole-composition claim.

Eight new artifact-regression groups cover phase arguments/callees, selection
fields, allocation extents, capture fields/lifetimes/escapes, outlined helper
forwarding and control-flow bypasses. The ten-group composed suite additionally
compiles and rejects substituting original messages for outer descriptors and
substituting a different inner-output buffer (nine compiled source mutants in
total). All sixteen compiler/target/panic configurations pass, together with
the five readiness/handoff regression groups, native AVX2 debug/release tests,
fixture formatting/Clippy and script-layout checks. The fixture remains compile
only, with zero runtime tests; Apple/Arm code generation is not native execution.
No production Rust, release gate or approval changed. Local compiler logs are
`release-reports/v0.25.1-md5-phases-{generic,simd}.log`.

### MD5 inner error propagation

The three actual emitted MD5 callers now also exclude inner readiness errors,
inner digest errors, and their unwind paths from outer hashing. The readiness
call must use the workspace's executor and dominate both hashing dispatches;
none of its four error discriminants may enter either dispatch. Cutting the
inner call must also make outer dispatch unreachable after readiness success.
Error payloads
remain unknown, covering all payload values conservatively rather than choosing
a convenient representative. The inner digest's error discriminator is derived
from a separate compiled `Result<(OwnedSecretRegion, Report), Error>` probe,
not guessed from the caller's own branch. Both SIMD backend success niches must
retain a possible outer-dispatch path, preventing vacuous rejection of all work.

The bounded reachability check follows byte/bool values through predecessor-
specific, simultaneous phi nodes, comparisons, branches and switches. Unknown
predicates explore every possible edge. Unknown calls, potentially aliasing
writes, atomic/value-producing effects and result-storage lifetime changes
invalidate modeled memory. Already loaded SSA values remain distinct from that
memory. Unparsed control flow and exhaustion of the analysis state bound fail
closed. This establishes error exclusion, not exact returned error mapping,
report validity, full output ownership, quarantine classification, per-lane
prefix contents or whole-caller erasure.

Ten new regression groups include actual artifacts from both Rust 1.90.0 and
1.99.1, plus conservative-analysis tests for unknown values, effects, cycles,
parallel phi assignments and unsupported control flow. Existing composed row,
readiness/handoff and phase suites pass, including all nine compiled source
mutants. All sixteen compiler/target/panic configurations pass; native AVX2
debug/release tests also pass. Fixture fmt/Clippy and script-layout checks pass.
The compile-only fixture now directly names its already-transitive first-party
core dependency for the actual result type; there are no new external packages
or production changes. It still has zero runtime tests. Local compiler logs are
`release-reports/v0.25.1-md5-results-{generic,simd}.log`. Cross-compilation is not
native Apple/Arm qualification, and no release gate or approval changed.

### MD5 distinct-lane native controls

The prior independent byte/bit checks repeated one key and message across all
eight lanes. The mixed-shape activity test used the project's portable HMAC as
its reference. A new explicit native test closes that functional coverage gap
with 96 batches and 768 individually checked per-lane records: four key layouts,
three message layouts and eight independently rotated key/message placements.
Equal-length inputs carry different bytes; boundary and fractional-bit inputs
exercise distinct descriptor lengths and final-bit counts. Key layouts cover
64-, 65- and 129-byte keys plus mixed empty/short/long keys through 1,024 bytes.
Assertions require the actual scalar or SIMD normalization route implied by each
group's public shape on eight-lane AVX2 and four-lane NEON.

Every batch exercises public output, secret output (including clearing on drop)
and verification at all seven tag widths. Replacing each lane's candidate with
its neighbor's tag must reject. Reports must retain the selected width and
active-lane count. All 768 full tags are checked by the separate Python bit
model; its 576 byte-aligned cases are additionally controlled against Python's
standard-library HMAC/MD5. Fractional-bit checks are a separate project model,
not an external certification or independent standardization claim. Acceptance
rejects missing, duplicated, substituted and rotated records. Generic test
runs now require one passed/four ignored; native runs require four passed/zero
ignored, and the extracted-package population was updated accordingly.

Native AVX2 and Apple M2 NEON debug/release runs pass, as do extracted Linux
debug/release native tests, leaf all-feature tests/doctests, focused strict
Clippy, five native-driver regression groups, fourteen package regressions and
script-layout checks. The Mac used a private snapshot of `6f044e0e` with the
test/driver overlay (archive SHA-256
`14715f9d69cd7f6c5589459894aaf1ead5bcbdc62c8e1f82a2d7b96f598edf5d`).
Local logs are `release-reports/v0.25.1-md5-lanes-native-{linux,macos}.log` and
`release-reports/v0.25.1-md5-lanes-package-linux.log`. Production Rust and gates
are unchanged; these are author-operated functional checks. Per-lane compiler
provenance/cleanup qualification remains unfinished, not inferred from passing
test vectors.

### MD5 inner message descriptor provenance

A separate emitted-LLVM check now follows message descriptors from the original
eight-slot immutable input borrow into the inner hash in `authenticate`,
`authenticate_secret` and `verify`. Independent compiled Some/None probes bind
the input/message layouts and null niches. For every one of the 256 activity
masks, conditional on reaching descriptor construction, the check tracks byte
origins through fixed address offsets, pointer loads/stores, temporary buffers,
memcpy and predecessor-specific simultaneous phi nodes. Each active lane must
retain all 32 bytes of its own message descriptor; each inactive lane must
retain the null niche. Inactive payload bytes are deliberately not treated as
initialized or meaningful.

Temporary lifetime changes invalidate their modeled contents. Bounds,
non-overlapping memcpy regions, address-definition dominance and read-only input
ownership are checked. Unsupported effects, unknown branch predicates, cycles
and descriptor escapes reject. The constructed array must remain intact and
live until its correctly bound inner-hash argument is used. This is a
descriptor-transport result, not qualification of key normalization, ipad/opad
contents, outer descriptors, returned output/report ownership or quarantine.

Eight focused regression groups use real LLVM from both compiler versions and
reject lane-offset, activity, phi-source, copy-width, temporary-lifetime,
late-write/escape, probe-layout and unsupported-flow mutations. The existing
compiled source-mutant suite now additionally rejects swapping lanes 0/7 and
rotating the descriptor array: eleven compiled source mutations in total.
The sixteen existing compiler configurations pass (Rust 1.90.0/1.99.1, abort
and unwind, generic x86-64 plus AVX2 and Linux/Apple AArch64 NEON). Existing row,
handoff, phase and error-path regression suites, fixture fmt/Clippy and script
layout checks pass. Local logs use the prefix
`release-reports/v0.25.1-md5-descriptors-`.

No production Rust, dependencies, release gates or approval records changed.
These are author-operated compiler checks, not fresh native execution or
independent qualification; the prior native functional results are separate.

### MD5 conditional inner-prefix construction

The emitted-code checks now inspect the actual post-normalization `pads` loop.
All three callers must supply the same freshly zeroed 512-byte pad owner, with
no intervening overwrite or escape. Separate compiled ABI probes bind the
optional normalized-region fields and copy/XOR/result discriminants. The loop
evaluator tracks public cursors and distinct symbolic source bytes: short keys
must reach their own lane, long keys must select that lane's 16-byte normalized
digest, tails must remain zero before XOR, and every active row must receive
exactly 64 byte operations with `0x36`. Inactive rows remain zero.

This is a **conditional, case-based compiler check**. It starts after
normalization with a supplied normalized-owner state; it does not establish
that the preceding scalar/SIMD normalization actually returned that owner or
the correct digest. Copy/XOR behavior is a separately source-bound primitive
premise, not a new proof of those kernels. No outer `0x5c` conversion, report
return, final output ownership, quarantine or whole-caller erasure claim follows.

Each of the sixteen compiler/target/panic configurations passes 393 scenarios:
every short-key length 0–64 in every lane, all 256 activity masks with distinct
key shapes, missing/null/short/exact normalized-region boundaries, and selected
primitive failures. A ten-group focused mutation suite additionally checks
every one of the eight copy and 512 byte-XOR failure positions on both Rust
versions. Primitive failures must reach the error frontier without further
copy/XOR work; emitted unwind edges cannot re-enter construction or its success
frontier. Unknown instructions, unbound values, out-of-bounds/overlapping access,
analysis-bound exhaustion and untraced pad-address uses fail closed.

Two new compiled source mutations change the ipad constant and select a
neighboring normalized key; both reject. The composed cleanup suite now rejects
thirteen compiled source mutations. Existing descriptor, error-path, phase and
handoff suites, fixture fmt/Clippy and script-layout checks pass. Logs use
`release-reports/v0.25.1-md5-pads-`. Production code, dependencies, gates and
approvals are unchanged; cross-compilation is not a fresh native run.

### MD5 normalization-result owner transport

The emitted-code inspection now covers the missing handoff from scalar and
SIMD normalization results into the optional owner used by the ipad loop.
Three independent compiled probes bind the scalar success/error and SIMD
success layouts, alongside the existing SIMD error probe. The actual digest
calls must receive the expected key-array, separate 128-byte destination,
workspace/scalar-owner and control arguments. The SIMD Scope's setup and
non-escaping address uses are checked before dispatch; its workspace-only
destructor behavior remains an explicitly source-bound premise.

Returned pointer and length bits retain distinct symbolic identities. This
includes the optimized SIMD pointer split across two bytes and a 48-bit field,
then shifted, merged and converted back to a pointer. All modeled paths that
reach the pad-loop entry must preserve the original owner, length and Some
discriminant, with live storage. Result errors, backend mismatches and digest
or cleanup unwind edges cannot enter that loop. Unknown report fields explore
both branch outcomes rather than inventing successful values; every modeled
successful backend also requires a non-vacuous entry witness. Unrecognized
effects, out-of-bounds access, lifetime misuse and cycles reject.

Thirteen focused regression groups use real LLVM from both Rust versions and
exercise bit reconstruction, ABI layouts, owner substitution, incorrect lengths,
error guards, predecessor-specific phi values, Scope setup/drop, late writes,
expired/repopulated storage, unknown effects and unwind redirection. Two more
compiled Rust mutations reroute the digest destination and discard its returned
owner; both reject. The composed cleanup suite now rejects fifteen compiled
source mutations. All sixteen compiler configurations pass, as do existing
handoff/phase/result/descriptor/pad regressions, fixture fmt/Clippy and script
layout checks. Local logs use `release-reports/v0.25.1-md5-normalization-`.

This is owner transport, not a new proof of the digest primitives or full
normalization. Key-descriptor construction, route selection, the no-long-key
branch and complete report validation remain separate obligations. Outer pad
conversion, output/return ownership, quarantine and hosted-worker qualification
remain open. Production code, dependencies, gates and approval records are
unchanged; these are author-operated compiler checks, not native execution or
independent review.

### MD5 normalization key descriptors and shape routing

The next emitted-LLVM check starts at the actual `pads` helper entry and follows
the eight key slots to scalar/SIMD setup or the no-normalization pad-loop entry.
Each active long key must call the exact bit-string constructor with its own
pointer, unchanged length and eight valid bits. Its returned descriptor retains
lane-specific byte provenance through the temporary payload copies; short and
inactive slots keep the null niche. Reads of inactive input payloads, expired
temporaries, overlapping copies and unknown effects reject. Independent compiled
success/failure probes bind descriptor/result layouts; the unchanged bit-string
constructor's semantics remain a source-hash-bound premise, not a new proof of
that primitive.

For both four- and eight-lane selections, the observed route must agree with the
long-key pattern: no normalization for zero long keys, SIMD only when a complete
group exists, otherwise preselected scalar normalization. The no-long-key path
must retain an absent normalized owner. The separate 128-byte destination must
be freshly zeroed at setup. Constructor failures must report message-length
failure before later construction, backend setup, digest or pad work. Address
uses are reconciled beyond the setup frontiers to reject later key-array writes
and escapes before digest consumption.

This is **bounded scenario-based inspection**, not exhaustive verification over
all possible lengths or a whole-normalization proof. Each compiler configuration
runs 1,152 scenarios: all 256 long-key masks with remaining slots either occupied
by short keys or absent, both backend widths, per-lane empty/short/64/65-byte and
bit-length overflow boundaries, and constructor-failure injection in every lane.
The source-bound full-byte constructor performs no partial-tail inspection.
LLVM's unvisited AArch64 remainder prologue is allowed only pure address/read
operations before setup, not hidden writes or escapes; focused mutations check
that distinction. Backend setup/readiness internals and full report validation
are not inferred from these route checks.

Eleven regression groups cover emitted x86-64 code from both compilers and
AArch64 from Rust 1.99.1, including vector and scalar activity counters, pointer
and length substitutions, threshold/niche changes, payload copies, error-path
re-entry, lifetime/escape faults, signed/unsigned arithmetic and exact shifts.
Three compiled source mutations change the long-key threshold, route on message
occupancy instead of long-key occupancy, and bypass one-key normalization; all
reject. The composed source-mutant suite now contains eighteen mutations.
All sixteen compiler configurations and the existing focused suites pass;
fixture fmt/Clippy and script-layout checks pass. Logs use
`release-reports/v0.25.1-md5-keys-`. No production implementation, dependency,
gate or approval changed, and no native execution/review is claimed by this
compiler-only checkpoint.

### MD5 normalization initialization, readiness and reports

The composed caller check now follows normalization setup after the source-bound
workspace clear. All eight 16-byte MD5 IV copies must target the distinct expected
lane offsets. Scope initialization, its workspace pointer and incomplete flag,
and the executor pointer supplied to readiness are checked before digest entry.
Every readiness error and setup unwind edge must exclude scalar/SIMD digest and
pad work; readiness success must reach SIMD without switching to scalar. Scalar
initialization must lead directly to its digest without intervening effects.
The normal-return Scope destructor also requires the completed flag.

Independent compiled probes bind the work-report and execution-report fields.
The actual key-descriptor/shape model supplies pre-dispatch facts to the result
transport model. Each configuration checks 662 scenarios: all long-key masks for
both backend widths, valid and malformed report widths/active counts, vector-work
boundaries and backend mismatches. Scalar report fields and SIMD work counters
retain symbolic bit identities through the pad-loop preheader into the eventual
success stores. The no-long-key path must return a zero report. Report SSA must
be defined before the loop; result-pointer uses after the success frontier are
reconciled to reject overwrite, escape or substitution. This remains conditional
on the separately checked pad loop and source-bound digest contracts, not a
whole-caller or arbitrary-input formal proof.

Focused emitted-code mutations exercise IV bytes/placement/copy extent,
readiness guards and unwinds, authority binding, completion flags, report ABI,
guard comparisons and report provenance/late writes. Two additional compiled
Rust mutations remove the normalization report check and discard the scalar
report; the composed source-mutant suite now contains twenty mutations. All
sixteen compiler configurations pass. Eleven new focused regression groups,
the previous 65 handoff/phase/result/descriptor/pad/normalization/key regression
groups, the ten-group source/artifact suite, fixture fmt/Clippy on both compilers,
and script-layout checks pass. The new tests also cover AArch64's separate
scalar report stores rather than assuming x86's vectorized store form.
Logs use `release-reports/v0.25.1-md5-reports-` and
`release-reports/v0.25.1-md5-setup-reports-tests.log`. No production implementation,
dependency, release gate or approval record changes in this checkpoint.

### Conditional MD5 outer-prefix and descriptor construction

The emitted-code inspector now follows the public, secret-output and verification
callers from outer-descriptor initialization to the actual outer dispatch. Given
the earlier inner-pad bytes and a valid, distinct 128-byte inner-result owner,
every active lane must XOR each of its 64 prefix bytes exactly once with
`0x36 ^ 0x5c`; inactive prefixes remain unchanged. The inner owner's pointer and
length premises are attached to its actual stores, not arbitrary loop operands.
This does **not** yet establish that owner's complete binding to the preceding
digest result, or the inner report checks.

Each active outer descriptor must use its own 16-byte inner digest and eight
valid bits. Constructor payloads keep lane-specific byte provenance through
temporary storage and partial copies. Inactive descriptors retain the null
niche; the final destination must be freshly zeroed. The actual closure capture
must carry those prefixes, descriptors, final destination and control into the
outer helper. Unknown effects, cross-owner copies, overlapping transfers,
expired storage, malformed geometry and construction after a primitive failure
reject. Constructor and XOR unwind paths cannot reach outer dispatch.

Each caller/configuration checks 280 scenarios: all 256 activity masks, XOR
failures at both ends of every lane, and constructor failure in each lane.
These include conditional shapes that earlier admission would reject; they are
construction coverage, not claims that such workloads execute through the API.
Constructor and XOR semantics remain tied to unchanged source hashes. Fatal
abort cleanup, full output ownership and general LLVM correctness are not claimed.

Focused regressions mutate real LLVM from Rust 1.90.0 and 1.99.1 on x86-64 and
1.99.1 on AArch64, across all three callers. Three compiled Rust mutations change
the outer XOR mask, shorten the inner digest, and invert lane activity; the
source-mutant suite now contains twenty-three mutations. Logs use
`release-reports/v0.25.1-md5-outer-`. Production crypto, dependencies, release
gates and approval records are unchanged.

All sixteen compiler/target/panic configurations pass, with 840 conditional
scenarios per configuration across the three callers. Seven new regression
groups and the existing ten-group source/artifact suite pass; the 45 shared
pad/key/normalization/report regression groups and script-layout checks also
pass. These are author-operated compiler checks, not fresh native qualification
or independent pentest results.

### MD5 inner-result owner handoff (author compiler checks)

The three actual HMAC callers now trace the inner digest's returned pointer and
length through split loads, bit reconstruction, phi nodes, scoped-workspace
cleanup and report branches to outer-input construction. Independent emitted
Result-layout probes bind the source offsets. Pointer and length remain symbolic
provenance, not convenient constants; unknown report predicates explore both
edges. Error results, absent backends and unwind must not reach that construction.
Only the matched Scope and inner owner may be written during the handoff, and
expiry or reinitialization of the inner destination prevents acceptance.

The digest primitive's valid returned region and the Scope destructor's
non-refilling behavior remain source-bound premises. This is owner transport,
not proof of report acceptance/transport, complete output ownership, quarantine,
native qualification or independent review. Six artifact-mutation groups cover
pointer/length replacement, split reconstruction, phi substitution, Scope
completion/identity, expiry/clobber/unknown effects/cycles and unwind bypasses.
Logs use `release-reports/v0.25.1-md5-inner-owner-`.

All sixteen focused compiler/target/panic configurations pass: Rust 1.90.0 and
1.99.1 on x86-64 GNU/Linux, plus 1.99.1 on GNU/Linux and Apple AArch64, with
generic/SIMD and abort/unwind builds. The six new regression groups and all
24 existing normalization/setup/report groups pass. The existing ten-group
cleanup suite, including its 23 compiled source mutations, also passes.
Cross-compilation is not native platform execution. Production Rust,
dependencies, release gates and native approval records are unchanged.

### Conditional MD5 inner-report admission

The emitted-code checker now evaluates inner-report admission in the public,
secret-output and verification callers against their actual immutable selection
and input loads. The selected backend byte is bound to its store in the real
constructor. Each of the eight input-presence niches supplies its own activity
bit; the verifier follows the emitted checked-width activity sum and backend
width selection instead of inventing either value from a successful comparison.
Both LLVM's branch/phi and select-based width calculations are covered.
Conflicting constructor output writes, overlapping writes and escaping output
aliases reject even when the expected backend store is also present.

Each caller checks 1,136 scenarios: all 256 activity masks for both backend
selections, mismatched active counts, and representative width, backend and
vector-work boundary values, including `u64::MAX`. A valid report must reach
outer-input construction with the original inner owner; invalid reports must
not reach it. These are conditional handoff scenarios, including shapes that
earlier workload admission rejects, not new claims about executable workloads.
Scalar-work provenance and complete report return transport remain separate.

Seven regression groups mutate actual emitted artifacts from both x86 compiler
versions and AArch64. They cover predicates/branches, activity loads and sums,
width/backend selection, report offsets, the selection constructor, predecessor
effects/cycles/overflow/borrow assumptions, and independent ABI probes. Four
additional compiled Rust mutants remove the backend, width, vector-work and
active-count guards individually; the source-mutant suite now contains 27
mutations. Logs use `release-reports/v0.25.1-md5-inner-report-`.

These are author-operated, bounded compiler checks. They do not qualify whole
callers, final output ownership, quarantine, native execution or independent
review. Production Rust, dependencies, release gates and native approval records
are unchanged.

All sixteen compiler/target/panic configurations pass, including a final rerun
of the strengthened constructor binding: Rust 1.90.0 and 1.99.1 on GNU/Linux
x86-64 and 1.99.1 on GNU/Linux and Apple AArch64, generic/SIMD, abort/unwind.
Each configuration checks 3,408 conditional scenarios across the three callers.
The seven new regression groups, 30 existing owner/normalization/report groups,
and the ten-group cleanup suite including all 27 compiled source mutants pass.
Acceptance-metadata, assurance and script-layout checks also pass.

### MD5 outer-result, truncation and counter-return qualification

This larger author-verification checkpoint connects three additional sections of
each public, secret-output and verification caller:

- Independent compiled constructors bind the nested outer digest result's owner,
  report and two distinct error niches. Outer admission checks the actual
  selected backend, lane width, activity and vector-work threshold while retaining
  the returned owner pointer/length. Neither nested error nor unwind may enter
  truncation. Each caller exercises 1,136 report scenarios and ten error cases.
- The real truncation loop is evaluated for every activity mask and every selected
  tag length from 10 through 16 bytes. Every active row must receive its own outer
  digest prefix exactly once; inactive rows and truncated tails remain zero.
  Copy errors in all eight lanes and copy unwinding cannot reach final readiness.
  This is 1,848 scenarios per caller, conditional on the source-bound digest's
  valid returned region and the separately checked owner handoff.
- Independent report/result constructor probes bind the locations of inner and
  outer work counters in all three returned object layouts. Phase-specific symbolic
  scalar/vector values retain their bits through emitted SSA to the actual field
  stores, including separate AArch64 stores and packed x86 stores. All activity
  masks and both backend selections are exercised. Cross-phase substitutions,
  constants, overlapping writes and escaping result aliases reject.

Some compiler configurations reuse a value from the accepted inner report when
checking the outer report. That value is taken from the actual earlier accepted
state, with dominance checks; it is not seeded as an arbitrary successful fact.
Regression tests corrupt/remove that state to confirm the binding is required.
The copy, owner and cleanup semantic premises remain source-hash-bound.

Nine new artifact-regression groups cover two x86 compiler versions, AArch64,
and the generic abort configuration that performs this reuse. Five additional
compiled Rust mutations swap whole inner/outer reports, substitute only the
outer scalar count, shift the copied digest slice, invert truncation activity,
and contaminate a zero tail. The source-mutant suite now has 32 mutations.
Logs use `release-reports/v0.25.1-md5-output-path-`.

These are bounded compiler/byte-provenance checks, not native execution or an
independent retest. Report field-write provenance is conditional on reaching
those writes: complete return-object success-discriminant/every-return coverage,
normalization report copying, final consumer ownership and quarantine remain
separate obligations. No production Rust, dependency, release gate or native
approval record is changed by this checkpoint.

All sixteen focused compiler/target/panic configurations pass: Rust 1.90.0 and
1.99.1 on GNU/Linux x86-64, plus 1.99.1 on GNU/Linux and Apple AArch64,
generic/SIMD and abort/unwind. A targeted generic-build refresh also passes with
the final phase-specific counter tokens. The nine new regression groups, 44
shared owner/normalization/report/outer groups, and ten-group cleanup suite with
all 32 compiled Rust mutants pass. Fixture fmt/Clippy on both compilers,
acceptance metadata, assurance and script-layout checks pass. No all-family
Miri/Kani/ASan sweep or native collection was started for this tooling checkpoint.

### MD5 returned-report composition checkpoint

The next connected compiler-assurance block binds the remaining report metadata
and normal-return population, without changing production Rust or release gates:

- Normalization's 24 report bytes are traced from the independently checked
  `pads` result through every emitted temporary and into the returned report.
  This includes Rust 1.90's packed 30-byte temporary and its four-copy chain,
  as well as the newer compiler's direct and two-copy paths. Every derived
  address use is accounted for; overwrites, unexpected calls, alias escapes,
  overlapping return writes and expired source/destination storage reject.
  Normalization rejection and unwind cannot reach any accepted report copy.
- Returned backend and vector width are bound to the actual immutable selection,
  for both backend values and all 256 activity masks. Late pure casts/selects
  must dominate their stores and use already bound operands. Split width stores
  and their upper zero bytes are checked, not treated as arbitrary padding.
- Independent error constructor probes bind each compiler's `Result` niche.
  Rust 1.90 uses the first activity byte for public/secret outputs, whereas the
  newer compiler uses the backend field. The verification result uses its backend
  field. Success niches must retain the selected backend or actual first-lane
  activity; an error write cannot count as a successful report field.
- A finite control-flow traversal includes both ordinary and exceptional edges,
  without assuming branch conditions true. Every normal return must have a bound
  variant; every success return must have all 81 semantic report bytes written.
  Report padding is excluded. Missing fields, early returns, missing error tags
  and fabricated activity niches reject. Return writes must stay within the
  ABI-bound object, and narrowing must not wrap or produce poison. This composes with the separately
  checked normalization, inner/outer counter and header provenance.

This is report/variant transport, not a proof that a consumer returned the right
success/error, nor full output-owner lifetime or quarantine classification.
Those obligations, and hosted-worker compiler qualification, remain open.
The test suite adds twelve artifact-regression groups and four compiled Rust
mutations (normalization substitution, scalar-count replacement, wrong width and
wrong backend), increasing the cleanup suite to 36 compiled mutations.
All sixteen combined configurations pass: Rust 1.90.0 and 1.99.1 GNU/Linux
x86-64, and Rust 1.99.1 GNU/Linux/Apple AArch64, generic/SIMD and abort/unwind.
A final return-only refresh also passes all sixteen configurations with the
last narrowing/bounds checks. All twelve new regression groups, 53 shared
groups and the ten-group cleanup suite including 36 compiled Rust mutants pass.
Fixture fmt/Clippy on both compilers, acceptance metadata, assurance,
script-layout and diff-whitespace checks pass. Logs are under
`release-reports/v0.25.1-md5-return-metadata-`. These are author-operated compiler
checks, not native collection, independent review or a full release sweep.

### MD5 final-consumer transport checkpoint

The next connected assurance block follows the final consumer's result into the
returned output object, without changing production Rust or release gates:

- The public copy's actual success value must select the successful output
  construction. Its error branch and the consumer unwind edges cannot reach
  those field stores. Every use of the exclusive public destination is accounted
  for: only the final checked copy and the returned pointer are allowed.
- Independent region success/error probes bind the secret consumer's result
  representation. The caller must check that result before constructing success;
  its returned pointer and extent must come from the actual consumer result.
  Every derived result address, load and lifetime marker is checked, including
  older-compiler speculative field loads. Overwrites, escapes, wrong offsets and
  reads after storage expiry reject.
- The verification decision must be the exact final consumer return value,
  rather than a constant or replacement. Public and secret tag metadata must
  retain the selected width and all eight actual activity bytes, checked across
  both backends and all 256 lane masks.
- Emitted public and secret tag accessors independently bind field meanings,
  row addressing and lane visibility. The focused scenarios cover every activity
  mask, lanes 0 through 9 and every supported tag length, plus zero, short,
  oversized and maximum-length boundaries. These are bounded model checks of
  the emitted accessors, not a general LLVM proof or native execution.
- Result layout is obtained from the current emitted probes, not assumed from
  a compiler version. Adding the accessor instantiations changes a nested Result
  niche in some configurations. Negative tests target the resolved function
  identity, including aliases, rather than the first identical body in a module.

This closes caller-side consumer gating and result/metadata transport only.
Secret-region initialization, the consumer's own failure/unwind cleanup,
verification comparison semantics, quarantine classification and hosted-worker
compiler qualification remain separate unfinished obligations. In particular,
transporting a returned region does not prove how that region was initialized
or cleared. No independent retest, native qualification or release approval is
claimed by this checkpoint.

All sixteen combined compiler configurations pass: Rust 1.90.0 and 1.99.1 on
GNU/Linux x86-64, and Rust 1.99.1 on GNU/Linux and Apple AArch64, with
generic/SIMD and abort/unwind builds. The consumer/view-only projections also
pass all sixteen configurations. Eight new artifact-regression groups and
26 adjacent return-metadata/output-path/handoff groups pass, as do five native
output-parser regression groups. The ten-group cleanup suite passes with 42
compiled Rust mutations: the six added cases invert returned activity, replace
selected width, discard copy failure, replace verification with a constant,
substitute a tag lane and invert accessor activity. Each mutant must compile
before the checker is required to reject it. Fixture fmt/Clippy on both compilers and
acceptance-metadata, assurance, script-layout and whitespace checks pass.
Logs are under `release-reports/v0.25.1-md5-consumer-`.

CodeQL alerts #10, #11 and #12 were inspected at `336200d5` and dismissed with
owner approval as false positives. Their hex formatters emit only reproducible
public synthetic HMAC test tags: fixed `0xa7` keys and `0x39` byte messages, or
masked `0xa5` bit messages. The output feeds differential oracle checks; no
application secret reaches these sinks. These test files are excluded from the
crate archive. Neither production logging nor the security rule was changed.

### MD5 final-consumer internal checkpoint

The final secret-output and verification closure bodies now have connected,
bounded compiler checks. This changes assurance code and downstream probes,
not the production HMAC implementation or release gates:

- Independent downstream constructors bind the core region-result ABI and the
  conversion from every core memory error to the value-free HMAC error. The
  secret consumer must write the complete 128-byte row buffer through the
  incoming initialization, check the write result, move the same initialization
  record into `finish`, and return that primitive's pointer and extent. Short
  writes, discarded failure, substituted captures/results, invalid lifetimes
  and unknown effects reject.
- All four write-error values, a failed `finish`, and recoverable write unwind
  are modeled. The initialization must be consumed by `finish` or dropped on
  error/unwind; a successful result cannot be fabricated from failure. Core
  write/finish/Drop behavior is an explicit source-pinned premise. Fatal abort
  and a second panic during cleanup are not erasure guarantees.
- Verification is evaluated for all 256 activity masks and tag widths 10–16.
  Every active lane must compare exactly the selected row bytes with the same
  candidate lane/byte, in order, with no omitted or repeated comparisons. The
  accumulator starts at zero, cannot be reset, and is cleared before normal
  return or recoverable unwinding. Every comparison and final-decision unwind
  boundary is exercised for full batches at each supported width.
- Secret byte values are not interpreted as public control-flow values. The
  final primitive produces an opaque decision bound to the complete comparison
  trace; it must survive return unchanged. Inspecting that decision to choose
  a branch, replacing it with a constant, introducing an unknown effect, or
  deriving an address outside the bound allocation rejects. Primitive XOR/OR,
  predicate and clearing semantics remain source-pinned premises, not freshly
  re-proved assembly. This is not a general constant-time proof.
- Linux Arm's four-byte alignment for the one-byte scratch allocation is
  supported without widening its extent. Public-width `freeze` is accepted only
  for an already known value, never as a source of invented metadata. The
  regression population includes that generic abort configuration as well as
  both Rust versions and Apple Arm.

These checks start at the final closure boundary. The secret initialization's
caller-side creation/moves/early-failure cleanup and verification candidate
shape/length admission remain separate obligations, as do quarantine and hosted
worker qualification. The caller must supply an exclusive 128-byte destination
initialization owner and matching candidate metadata; these are not inferred
from a passing closure model. No native or independent-review claim is added.

All sixteen combined configurations pass: Rust 1.90.0/1.99.1 GNU/Linux x86-64
and Rust 1.99.1 GNU/Linux/Apple AArch64, generic/SIMD and abort/unwind. A final
consumer-only refresh with the address-bound checks also passes all sixteen.
Ten new regression groups pass across six representative
configurations, including the generic Linux Arm abort build; twenty earlier
consumer-return/report-layout groups also pass. The ten-group cleanup suite
passes all 48 compiled Rust mutants. The six added mutants discard a write
failure, shorten the write, forget initialization on error, skip a comparison
byte, reverse candidate traversal or initialize the difference to a nonzero
value. Every mutant must compile before rejection counts. Fixture fmt/Clippy on
both compilers, metadata, assurance and script-layout checks pass. Logs are under
`release-reports/v0.25.1-md5-consumer-internal-`; no full-family verification or
native collection was started.

### MD5 caller initialization and candidate admission

Two further author-operated compiler projections now inspect the actual public
MD5 batch callers, without changing production Rust or release-gate policy.

The initialization projection binds `SecretRegionInitialization::begin` to the
exclusive 128-byte caller destination at function entry. Independent emitted
constructor probes establish its Result representation. Every affine copy from
that result through the final consumer capture must retain all 24 owner bytes;
Rust 1.90's intermediate 30-byte allocation is tracked at its actual offset.
The walker follows normal and exceptional control-flow edges, resolving public
drop flags and predecessor-specific phi values, including the older compiler's
reuse of a switched result discriminant. Early failures and recoverable unwinds
must dispose of the initialization exactly once; the final consumer must instead
receive it exactly once. Unknown alias uses, partial copies, expired storage,
early effects and bypassed admission are rejected. The already source-bound
core begin/Drop semantics and separately checked final consumer remain premises.
This does not establish the lifetime of the *returned* OwnedSecretRegion through
all subsequent caller teardown, nor erasure after fatal termination.

The verification projection symbolically derives the complete pre-executor
acceptance predicate using reduced ordered decision diagrams. All 24 independent
booleans—input presence, candidate presence and selected-length equality for each
of eight lanes—must give exactly the intended eight-lane predicate. The rejected
population must be its complement and return the independently probed TagLength
variant. Before admission only the required metadata reads, stack declarations,
alias annotations and rejection writes are allowed; payload reads and callbacks
fail the check. The model permits speculative absent-Option length loads, but
acceptance cannot depend on their value. It permits only equality with the
selected width, not arbitrary length arithmetic. Candidate Option/slice layout
is bound by a separate emitted probe. Constructor/selection, input layout and
post-admission comparison checks remain separate composed obligations.

The final caller projections pass sixteen configurations: Rust 1.90/1.99.1
x86-64 GNU/Linux and Rust 1.99.1 GNU/Linux/Apple AArch64, each generic/SIMD and
abort/unwind. Ten new regression groups pass across six representative
configurations, with independent Boolean truth tables and emitted-code mutations
covering every candidate lane, every owner move, normal/unwind destruction,
drop-flag reversal, pre-admission payload/callback use and ABI drift. Logs are
under `release-reports/v0.25.1-md5-caller-`. These are scoped author checks, not
native qualification, independent review or a release-readiness claim.

The ten-group cleanup regression suite also passes all 54 compiled Rust
mutations. Its six new cases delay initialization until the final consumer,
forget that consumer on early workload rejection, accept oversized candidates,
accept extra candidates in inactive lanes, skip the eighth admission check, or
reverse candidate order. Each must compile before its emitted behavior is
rejected. Twenty prior return/metadata regression groups, fixture fmt/Clippy on
both compilers, script-layout, acceptance-metadata and assurance checks pass.
The combined cleanup driver also passes all sixteen configurations with the new
checks integrated; the final versions of both new caller projections were
additionally refreshed across the same sixteen configurations.

### MD5 returned-owner teardown and quarantine outcomes

Two further projections inspect the emitted authenticate, authenticate-secret
and verify callers, composing with the existing initialization, consumer and
row-cleanup checks. No production Rust implementation changed in this checkpoint.

The successful post-consumer suffix must be a closed cleanup-and-return path:
four exact row clears, both internal region destructors and the complete
eight-lane workspace destructor. Each occurs once before return, while its
storage is live. Only independently bound return-field stores, report copies,
metadata narrowing/width selection and lifetime endings are permitted. New
callbacks, writes elsewhere, omitted/repeated destructors or expired storage
reject. The returned secret region's pointer and extent can flow only into their
return slots; they cannot escape to another call or be destroyed during teardown.

This suffix uses explicit, source-pinned nonthrowing premises for core clearing,
valid region destruction and MD5 owner destruction. Workspace destructor dispatch
is separately checked in emitted code. Only those particular cleanup invokes'
normal continuations are followed; arbitrary destructors are not assumed
nonthrowing. This is not an erasure guarantee for fatal termination, instrumentation,
caller frames, CPU registers or platform diagnostic storage.

Independent emitted probes bind all eight error discriminants and the executor's
actual revocation layout. The final classifier is evaluated for every error and
all three authority-tag states: routine length/policy/work-limit/cancellation
errors preserve the executor, whereas memory and execution integrity failures
revoke it. Low-byte provenance through casts and predecessor-matched phi trees
binds the classified error to the returned error, including verification's
prewritten error storage. Every escaping unwind after workspace entry must pass
through revocation. Unknown suffix effects and success after revocation reject.
The Rust 1.90 abort layout's inlined destruction is restricted to the eight exact
live workspace lanes. This does not independently re-prove every earlier
primitive's error mapping or the underlying CPU authority implementation.
The current source enum population must also remain exactly the modeled eight
variants; adding a variant, payload or explicit discriminant requires review
instead of silently extending this finite model.

Regression coverage includes mutations of actual compiler artifacts and seven
additional compiled Rust defects: forgetting either internal region or the
workspace, adding an effect after consumption, preserving ExecutionFailed,
quarantining Cancelled, or removing the operation's revocation. These are scoped
author checks, not native qualification or an independent security retest.

The cleanup suite passes all 61 compiled Rust mutations, and the 20 existing
return/metadata regression groups pass. Thirteen new regression groups pass
across six representative compiler configurations, including direct unwind
bypass, inlined lane-cleanup lifetime and error-domain expansion mutations.
The final versions of both new projections pass all sixteen configurations:
Rust 1.90.0/1.99.1 GNU/Linux x86-64 and Rust 1.99.1 GNU/Linux/Apple AArch64,
each generic/SIMD and abort/unwind. Fixture formatting and Clippy pass on
both Rust versions, as do script-layout, assurance and acceptance-metadata checks.
The combined cleanup driver also passes all sixteen configurations with the new
checks integrated; the final new-projection refresh additionally covers the
inlined-workspace lifetime and error-domain guards on that same matrix.
Local logs use the `release-reports/v0.25.1-md5-teardown-` prefix. No broad
verification sweep, native collection, release-gate change or publication was
performed for this checkpoint.

### Hosted launch storage and stack reclamation

A separate downstream fixture now emits eight real consumers: compute and
verify for scalar SHA-1, scalar MD5, compiled SHA-1 and compiled MD5 batching.
The compiler checker binds their incoming arguments through the outlined public
adapters where present, then requires four distinct typed executors and their
exact native worker callbacks. It does not infer qualification from unused
helper probes or from the presence of a symbol alone.

Before native launch, the attribute constructor must receive the current
reviewed session stack field, its error branch must not reach `pthread_create`,
and its success must dominate launch. Linux attribute bytes are traced through
complete, bounded, nonvolatile copies, including Rust 1.90's intermediate copy;
Apple's boxed attribute pointer must come from the constructor's success result.
Local constructor/transfer storage cannot be overwritten or passed to unrelated
helpers; the native attribute implementation and Apple's heap pointee remain
resource-contract premises. Handle,
Job and attribute-transfer allocations must have the expected geometry and live
lifetimes at use. These checks bind the current emitted layout; they are not a
new public ABI guarantee or an independent proof of the native constructor.

An isolated adapter reuses the existing modern-HMAC host lifecycle checker and
its source-pinned, non-unwinding resource premises without changing that shared
checker. Create/join results control the path; join must use the created handle.
The selected worker stack can be cleared only after failed creation or successful
join, before Job/handle storage ends. Failed join must terminate rather than
return or reclaim a potentially live worker. Unknown calls and effects while a
worker remains unjoined reject. Only exact resident-buffer helper names and two
pure integer intrinsics are adapted; native status and control flow are not
rewritten.

The focused matrix covers sixteen configurations: Rust 1.90.0/1.99.1 GNU/Linux
x86-64 and Rust 1.99.1 GNU/Linux/Apple AArch64, each generic/SIMD and abort/unwind.
Thirteen regression groups pass. They mutate real emitted artifacts and compile five safe-Rust
consumer defects covering algorithm substitution, cancellation substitution,
candidate truncation, key-input substitution and batch-candidate substitution.
Fixture formatting and strict Clippy checks pass on both compiler versions,
as do script-layout, acceptance-metadata and assurance checks.
Local logs use the `release-reports/v0.25.1-hosted-lifecycle-` prefix.

This checkpoint changes only assurance fixtures, checkers, tests and notes. It
does **not** yet qualify Job capture contents, keyed worker computation, complete
output transactions, public return conversion or session quarantine. Those
remain separate hosted-worker obligations. This is compiler inspection, not
native execution, independent review or whole-worker erasure qualification; no
release-gate change or broad verification sweep is included.

### Hosted captures, worker completion envelope and buffer destructor

The host checker now traces the actual launch-record bytes for all four legacy
executor types. It binds scalar Request descriptors, candidate descriptors,
cancellation, preselected width/backend, MD5 input slots and compression budget,
staging/output pointers and extents, the result destination and initial completion
flags to their exact caller/session origins. Borrowed locals must retain their
reviewed geometry and lifetime through launch; the preceding create/join checker
rejects intervening effects while the worker is live. Additional, late,
conditional, overlapping or escaping capture writes reject. Descriptor source
declarations are checked separately, so these are borrowed input descriptors and
public policy metadata, not host-created keyed owners. Padding is not a secret
owner or an erasure claim. This remains a current-layout projection, not a public
ABI guarantee.

A worker-side envelope check binds direct accesses to the same Job field layout.
Capture reads precede the Option take; subsequent direct Job writes are limited
to that take and the completion/panic flags. The result pointer cannot escape and
its status writes stay within the two-byte result. The result discriminant is
written before completion, with no result rewrites afterward. A caught-panic flag
requires the actual runtime catch cleanup and cannot overlap the completed path.
These checks do **not** interpret the keyed computation or authenticate its result
value; they do not establish full worker success/error-path qualification.

The actual outlined Buffers destructor is also interpreted for both keep states:
staging must clear exactly once, followed by output exactly once only when keep
is false. Wrong owner, changed order, repeated/missing calls, additional effects
or an unreviewed branch reject. This uses the existing pinned resource-clearing
premises and a new reviewed pin for the thin ResidentBytes wrappers. Pins detect
drift, not independently authorize source changes. Admission of the host keep
decision and complete output/quarantine transactions remain separate obligations.

The expanded suite covers twenty regression groups, including 744 missing or
substituted capture-field writes, lifetime/escape/conditional-write cases,
descriptor-declaration drift, worker take/result/completion/panic mutations and
buffer-destructor mutations. Sixteen additional compiled safe-Rust defects are
tested across Linux and Apple: changed tag width or budget, scalar/accelerated
staging-output swaps and skipped/reversed clearing. The previous five compiled
consumer-provenance defects remain in the same suite. Mutants must compile;
compilation failure is not counted as rejection by the checker. Restored private
source copies are revalidated, without editing production files.

The complete hosted driver is refreshed across all sixteen configurations:
Rust 1.90.0/1.99.1 GNU/Linux x86-64 and Rust 1.99.1 GNU/Linux/Apple AArch64,
each generic/SIMD and abort/unwind. Fixture formatting and strict Clippy cover
both compilers. All sixteen configurations and twenty regression groups pass;
the final overlapping-write and explicit-mutant-path cases also pass a two-group
focused refresh. Script-layout, acceptance-metadata and assurance checks pass.
Logs use the `release-reports/v0.25.1-hosted-capture-` prefix.
This checkpoint does not change production Rust, the shared modern-HMAC checker,
release policy, dependencies or publication state. It is compiler inspection and
author testing, not native qualification or an independent pentest.

### Hosted accelerated authority and selection-input checkpoint

The hosted compiler driver now composes worker-local authority checks for
compiled SHA-1 and MD5 batching with the existing launch/envelope projections.
It binds the exact required-mode constructor, all 24 result-to-owner bytes,
constructor-error exclusion, permitted borrows and live storage through the
worker's HMAC calls. Partial/reordered/overlapping copies, hidden aliases,
overwrites and lifetime endings before reads or consumers fail closed. The
required-mode discriminant is tied to the reviewed enum declarations and the
compiler identity is checked rather than inferred from a convenient error niche.

The SHA-1 constructor key pointer/length and tag width, and the MD5 selection tag
width, are bound to the verified launch captures. Captured scalar references
cannot gain writes or escaping aliases. Backend predicates are evaluated for
both valid captured backend values and all three owner Option values, including
None; only a matching backend may reach keyed selection. This checks the
worker's emitted comparison, not OS/CPU suitability or the implementation of a
called authority primitive. Those remain separate review/qualification premises.

Compiled-out workers are checked separately as rejection-only bodies: no crypto
calls, extra input reads or writes outside the status envelope, and no successful
result. They are not counted as successful accelerated authority execution.
The generic Arm targets can still contain baseline NEON routes; those receive
the full authority checks when actually emitted.

Regression coverage includes every authority-transfer write, mode/factory and
consumer identity, error-branch polarity, early lifetime endings, unknown
pointer uses, hidden extra arguments, captured inputs, backend mismatch/None
exclusion, compiler identity and rejection-only workers. The compiled private
host-source mutation set grows from sixteen to thirty: the additional fourteen
cover changed constructor modes, key/tag-width substitution and reversed
backend comparisons on Linux and Apple. The earlier five compiled consumer
mutations remain. No malformed/uncompilable Rust mutant counts as a detected
defect. Logs use the `release-reports/v0.25.1-hosted-authority-` prefix.

All sixteen compiler/target/generic/SIMD/panic configurations pass, as do all
twenty-eight regression groups (258.850 seconds), including 135 authority-copy
and 744 capture-field mutations. Both compiler fixture formatting/Clippy checks,
script-layout, acceptance-metadata, assurance and diff checks pass. The final
suite targets backend mutations at the actual Executor report, rather than an
unrelated later verification-result extraction of the same LLVM aggregate shape.

This remains author compiler inspection, not native evidence or an independent
pentest. No production Rust, dependency, shared modern-HMAC checker or release
gate is changed. The worker keyed-owner lifecycle, complete output transactions,
quarantine and final MD5 composition review are still separate open obligations.

### Hosted compiled keyed admission and retained-dispatch checkpoint

The compiler checker now follows compiled SHA-1's 912-byte constructor Result
through admission into retained state and both by-value terminal handoffs. The
MD5 batch selector receives its own 24-byte Result/borrow model; it is not
misclassified as a key owner or consuming finalizer. The existing shared
byte-provenance interpreter is reused without changing its modern-HMAC behavior.
Constructor success and error outcomes, normal and exceptional returns, copy
extent/order, live storage and consumer identity/arguments are checked. Missing
or unrelated representations cannot become admitted state. Storage checks cover
constructor temporaries, retained state and terminal copies, including scalar
accesses, actual memcpy extents, aliases and lifetime boundaries.

A separate compiled SHA-1 caller walk requires the retained object to reach
either the actual destructor or one of the two consuming finalizers on every
normal/recoverable-unwind exit. The actual emitted outlined destructor is
interpreted for both populated retained niches and the empty niche; both
Sha1Owner cleanup obligations must be discharged when populated. The primitive
Sha1Owner destructor's non-panicking behavior and the leaf update/finalizer
implementations remain explicit separately qualified callee premises. A failed
update may already have cleared the engine, but the caller must still discharge
its affine object instead of silently forgetting it. Unknown owner borrows,
late writes/reads, second consumption and lost update/finalizer unwind edges
are rejected. MD5's admitted selector allows only its two consumer borrows and
lifetime completion; no post-admission overwrite or escape is accepted.

The driver now supplies the panic profile explicitly. It is not inferred from
the presence of an exception personality: optimized standard-library catch
machinery can occur in a module even for a panic-abort consumer build. The
source/release gate policy is unchanged.

Focused mutations cover constructor bytes/error guards, terminal transfers,
storage lifetimes, retained caller exits and the actual destructor owner offsets.
The private compiled Rust host mutation set grows to thirty-two, adding Linux
and Apple forget-on-cancellation defects. Those two cases must be rejected by
the retained cleanup obligation, not an unrelated source pin. The earlier five
compiled consumer-provenance defects remain in the suite. Logs use the
`release-reports/v0.25.1-hosted-keyed-` prefix.

Validation passes all thirty-two regression groups (270.554 seconds), including
261 constructor-admission, 94 terminal-handoff, 227 storage-lifetime and 83
retained-cleanup/selector mutations. The final driver passes all sixteen
compiler/target/panic/SIMD configurations: Rust 1.90.0 and 1.99.1 on x86 Linux,
and Rust 1.99.1 on Linux AArch64 and Apple AArch64, each with generic/SIMD and
abort/unwind profiles. Both compiler fixture formatting and strict Clippy checks
pass, together with script-layout, acceptance-metadata, assurance and diff checks.
The matrix is compiler inspection, not native execution on the cross targets.

This is an author-operated compiler checkpoint, not independent review or native
execution. No production Rust, dependencies, release gates or shared modern-HMAC
checker changed. Compiler copies/register residue and fatal abort are not
claimed erased. Scalar worker internals, complete input/tail/lane provenance,
checkpoint/callee composition, output/loan/quarantine transactions and final
MD5 composition reconciliation remain open before release qualification.

### Hosted scalar retained-state and cleanup checkpoint

The actual scalar SHA-1 and MD5 worker emissions now have a separate retained
state projection. It binds the 880-byte/240-byte engine, its two non-overlapping
hash-owner fields, the tag-width value loaded from the verified launch capture,
and both consuming terminal moves. Partial, duplicated or overlapping field
transfers, substituted tag widths, wrong terminal identities/arguments and
escaped storage are rejected. Rust 1.90's optional six-byte trailing padding
copy is bounded separately: padding does not acquire a logical cleanup token,
and removing that copy alone is a passing regression case.

The existing scalar owner interpreter is reused in an isolated legacy binding;
modern-HMAC modules are not modified. Only the exact legacy update name is
adapted for its typed-call comparison. The walk tracks both logical hash owners
through message updates, cancellation, normal returns, recoverable unwinding,
inlined primitive destructor calls, actual outlined destructor bodies and
consuming finalizers. It rejects missing/repeated cleanup, updates of the wrong
owner, lost update/finalizer unwind edges, early lifetime endings and caller
reads after consumption. Primitive non-panicking destructor and consuming
finalizer behavior remain separately reviewed callee premises, not newly
established leaf-body guarantees.

The scalar constructor is inlined, unlike the accelerated constructors. This
checkpoint deliberately starts its cleanup obligations at the completed
retained-field transfer. Source-slot geometry and distinctness are checked,
but do not establish their prior initialization or key provenance. The inlined
constructor's key normalization, scratch cleanup and error-path composition
remain explicit work, as do complete message/tail provenance and output/loan/
quarantine transactions. Compiler-created copies, register residue, fatal abort
and whole-worker erasure are not claimed covered.

Regression coverage uses real compiler emissions for both scalar algorithms,
including positive SSA renaming, initialization/terminal corruptions, storage
lifetime/escape mutations and actual destructor-body mutations. The private
compiled host set grows from thirty-two to thirty-four defects: Linux and
Apple scalar forget-on-cancellation changes must compile, then fail specifically
on an unconsumed-owner obligation. This is author-operated compiler inspection,
not new native evidence or independent review. Logs use the
`release-reports/v0.25.1-hosted-scalar-` prefix. No production Rust, dependency,
shared modern-HMAC checker or release gate is changed.

Focused checks reject 330 initialization/terminal defects, 302 storage defects,
258 caller cleanup/read-boundary defects and 18 actual destructor-body defects.
The final complete hosted regression suite passes all thirty-five groups in
372.491 seconds, including all thirty-four compiled host defects and the five
existing compiled consumer-provenance defects; no prior group was dropped.
The final driver passes all sixteen existing compiler/target/panic/SIMD
configurations. Fixture formatting and strict Clippy pass under both Rust
1.90.0 and 1.99.1; script-layout, acceptance-metadata and assurance checks pass.
Cross-target compiler inspection is not reported as native execution.

### Hosted inline scalar constructor ownership checkpoint

The scalar SHA-1/MD5 projection now starts at the actual worker entry, following
the emitted control-flow graph through the existing retained-state handoff.
It does not replace the constructor with a synthetic proof function. Constructor
roles are inferred from typed finalizer/retained transfers and storage geometry,
not compiler-generated local names. Complete public-byte initialization must
precede owner birth; complete moves preserve logical ownership, and partial,
overlapping, escaped or prematurely ended storage is rejected.

The normalization hash update and short-key pad copy are bound to the launch
capture's key pointer and length. Inner/outer updates require the same 64-byte
pad and the ordered XOR masks 54 then 106. Update/mask and short-copy error
edges cannot reach retained state. The normalization hash owner must be
consumed; both live inner/outer owners must arrive in their correct retained
fields. The actual pad and normalization scratch require full typed clears on
normal and recoverable-failure paths. Before handing an exception to the checked
catch envelope, all logical owners must be discharged and scratch cleared;
the reachable catch suffix cannot reuse constructor storage.

The checked scope is ownership/scratch and the stated input/phase bindings,
not complete constructor cryptographic provenance. Public initialization does
not independently prove the primitive's IV constants. Normalization-result
discriminants/descriptors and the normalized-result-to-pad copy still need
their own provenance checks. Primitive consuming finalizers, non-panicking
owner destructors and core clearing remain reviewed callee premises. Compiler
copies/register residue, fatal cleanup abort and whole-worker erasure are not
claimed covered.

The regressions mutate actual compiler emissions: initialization, full-width
moves, key operands, pad widths/masks, result guards, owner cleanup, raw reads,
scratch extents, aliases and catch-boundary reuse. Positive local-name renaming
is accepted. The private compiled-host set grows from thirty-four to thirty-six:
Linux and Apple scalar constructors using the message tail instead of the key
must compile, then fail specifically on constructor-input provenance. No prior
regression group is removed. Logs use the
`release-reports/v0.25.1-hosted-construct-` prefix.

The new constructor groups reject 390 initialization/transfer defects, 570
key/pad/status/cleanup defects and 282 scratch/escape/catch defects across the
twelve representative scalar emissions. The complete driver passes all sixteen
compiler/target/panic/SIMD configurations. The complete hosted regression suite
passes all thirty-eight groups in 450.447 seconds, including all thirty-six
compiled host defects and the five existing compiled consumer defects.
Fixture formatting and strict Clippy
pass under Rust 1.90.0 and 1.99.1; script-layout, acceptance-metadata and assurance
checks pass. Cross-target inspection does not establish native execution.

This is author-operated compiler inspection, not independent review or new
native execution. No production Rust, dependency, shared modern-HMAC checker,
release gate or approval record changes in this checkpoint.

### Hosted scalar constructor provenance completion

The remaining scalar constructor provenance projection now composes with the
ownership/scratch interpreter and retained-state checks. It follows the actual
worker graph from pad initialization to the first keyed pad phase, and follows
live normalization-region ownership through recoverable failure/unwind cleanup.
It partitions the full captured key-length domain into empty, 1–64-byte and
long-key routes rather than checking just a few concrete key lengths. Changed
thresholds or routes, skipped normalization/copies and nonzero/overwritten pads
are rejected.

Independent typed probes in the downstream fixture establish each primitive's
initial-owner bytes and the success/error `Result<OwnedSecretRegion, _>` layout.
All three inlined hash initializations must match the independently emitted
`HardenedSha1::new` / `HardenedMd5::new` probe. This replaces the previous
public-byte-only initialization premise; primitive cryptographic correctness
remains separately qualified. The fixture adds direct dependencies on three
already-resolved local packages, with no additional package or third-party
dependency in its eleven-package closure.

The normalized digest's result discriminant and pointer/length fields are
bound to the actual typed finalizer. The region move must retain that provenance
through its lifetime, borrow for the pad copy and exactly one logical Drop.
Error results cannot supply payloads or reach the pad phase. The copy must use
the normalized 20-byte SHA-1 or 16-byte MD5 result, not the original key or an
unrelated buffer. Its success discriminator is independently pinned; all error
encodings share the checked failure path. The region is consumed and scratch
cleared before successful retained-state construction. Raw metadata escapes,
substituted fields, premature lifetime endings, descriptor reuse and omitted
normal/error/unwind cleanup are rejected. The existing typed finalizer and core
region-destructor bodies remain callee premises; compiler copies/registers,
fatal abort and whole-worker erasure are not covered by this projection.

Focused regressions reject 198 route/copy/error defects, 288 descriptor/lifetime/
Drop defects and 132 typed-layout/initialization defects. Positive SSA renaming
is accepted. Twelve additional private Rust constructor mutations compile on
Linux x86-64 and Apple AArch64 and are then rejected on constructor provenance:
wrong key-length thresholds, inverted empty-key handling, raw-key substitution,
digest truncation and discarded copy failure. Private source overrides remain
exact-path test parameters, not command-line release-validator options, with
their default rejection and explicit-path checks tested. No repository runtime
source is mutated by these tests. Logs use the
`release-reports/v0.25.1-normalization-` prefix.

Final validation passes all sixteen compiler/target/panic/SIMD configurations,
plus fixture formatting and strict Clippy on Rust 1.90.0 and 1.99.1. The full
forty-two-group regression invocation completed in 467.736 seconds with
forty-one passes and one harness error: the older consumer-mutation enumerator
mistook a new layout probe for a host API consumer. Its corrected enumeration
requires all eight exact application entry points, including alias resolution;
the new probes retain their separate tests. That corrected group and the
fixture dependency/path group both pass on rerun in 61.203 seconds. Thus every
group has a passing result, but this is explicitly a combined validation, not
a claim that the original full invocation passed. Script-layout,
acceptance-metadata, assurance and diff checks pass.

This completes the scalar constructor provenance block under those stated
callee premises. It does not complete message/tail/lane provenance, hosted
output/loan/quarantine transactions or final MD5 composition reconciliation.
No production cryptography, published API, release gate, native approval or
shared modern-HMAC checker changes. Cross-built artifacts remain compiler
inspection, not native execution or independent review.

### Hosted streaming input/output and scalar checkpoint qualification

The real hosted-worker emissions now compose the earlier constructor/owner
checks with complete-byte chunk iteration and partial-bit-tail provenance for
scalar SHA-1, scalar MD5 and compiled SHA-1. Paired pointer/length PHIs, captured
slice boundaries, the exactly-once tail prefix, 4096-byte update steps, successful
update admission and failure exclusion are checked in the actual worker CFG.
The full and partial `BitString` constructors are bound to captured arguments,
and their admitted descriptor bytes must reach both finalizers unchanged.
Constructor hash updates remain in their separate, already checked prefix:
the input projection does not rewrite or replace any LLVM instruction.

These three streaming routes also bind verification candidates, staging and
destination buffers, returned secret-owner fields and the destination copy.
Success admission, descriptor lifetimes, escape rejection and owner destruction
on normal/error/recoverable-unwind paths are checked. Constructor-only copies
and destructors are excluded from output selection only when unreachable from
the retained-state handoff; their instructions remain in the original graph.
Ending a consumed Result descriptor before copying its separate live owner is
legitimate and is not misreported as an owner-lifetime defect.

Scalar workers additionally bind all six cancellation checkpoints to initial
admission, chunk selection, each nonempty update part, finalization, pre-copy
and final result handling. Failed checkpoint bytes must survive transport to
the worker Result. The emitted cancellation callees must perform the exact
acquire load and return Cancelled/Ok; source names alone do not establish this.
Compiled SHA-1/MD5 checkpoints have different backend-session construction and
cleanup, so this scalar callee result is not credited to them.

Focused validation: all 16 existing compiler/target/panic/build configurations
pass. Across 16 available streaming workers in six representative emissions,
1,208 input/tail defects and 777 output-provenance/cleanup defects are rejected;
nine repeated-update loops are rejected by the path interpreter itself. Scalar
checkpoint tests reject 504 boundary/result-transport defects and 72 callee
mutations. All 42 private Rust worker defects compile and are rejected on Linux
x86-64 and Apple AArch64, with restored baselines passing. This is cross-built
compiler inspection, not fresh native execution or an independent retest.

The final complete hosted regression invocation passes all 48 groups in
633.025 seconds, including the existing compiled capture/constructor defects
and all new streaming/checkpoint cases. Script-layout, acceptance-metadata,
assurance, Python syntax, Rust formatting and diff checks pass.

No production Rust, dependencies, shared modern-HMAC checker, release gate or
approval record changes. The hosted qualification block is not yet closed:
eight-lane MD5 input/report/output transport, accelerated checkpoint/callee
composition, full worker-result/host quarantine transactions and public loan
composition remain. The separate final MD5 composition reconciliation also
remains required.

### Accelerated hosted SHA-1 checkpoint composition

The hosted checker now follows the actual accelerated SHA-1 checkpoint callee
and its inlined temporary streams. Independent typed downstream probes bind
the 448-byte Stream/Result representation, its rejection niche and the 433-byte
primitive owner destructor. A bounded interpreter follows both admitted Stream
niches, rejected construction and every cancellation-byte value. It requires
exact executor provenance, live/nonoverlapping storage, unchanged transfers,
one logical-owner Drop before the acquire cancellation load, and the correct
Ok/Cancelled/failed-authority result. Unknown effects fail closed. SSA/allocation
renaming remains accepted; source spelling alone is not the proof.

Inlining is handled in the original worker CFG, without manufacturing a
replacement function or assuming a fixed number of outlined calls. The model
tracks all inlined temporary Stream transfers and rejects escaped, overwritten,
consumed or prematurely ended storage. All six checkpoint sites are bound to
initial admission, chunk selection, each nonempty update part, finalization,
pre-copy and post-output/comparison. Both authority and cancellation rejection
must exclude further cryptographic work. Each narrow success/error status is
followed through the actual worker Result write; this is not a claim about
arbitrary error-payload bytes or the later host quarantine transaction.

Focused regressions reject 224 outlined-callee mutations, 434 mutations across
nine inlined temporary streams (including lifetime hoisting out of the loop),
128 placement/result mutations and 18 typed
layout-probe mutations. Thirty-eight actual private Rust defects compile and
are rejected on Linux x86-64 and Apple AArch64: forgotten streams, altered
authority-error mapping, ignored cancellation, reversed/duplicated health
checks, delayed cleanup, and each individually removed/ignored checkpoint.
Restored compiler baselines pass. Private fixtures use the existing exact-path
test-only overrides; no repository production source is changed by these tests.

The complete hosted suite passes all 53 groups in 727.591 seconds. That run
started before the final same-block lifetime-start tightening; it is not
misrepresented as a fresh full-suite run of the later tree. The final tightening
passes all eight checkpoint-related groups in 118.613 seconds, the separate
434-mutation inline/hoisting test in 13.553 seconds, and the complete 16-profile
compiler matrix. This is combined validation. The matrix covers Rust 1.90.0
and 1.99.1 on Linux x86-64, plus 1.99.1 on Linux/Apple AArch64, each with generic
and SIMD compilation and abort/unwind profiles. Both fixture Clippy versions,
formatting, Python syntax, script-layout, acceptance-metadata, assurance and
diff checks pass. Local logs use `release-reports/v0251-hosted-checkpoint-`.

Executor-start semantics and primitive-owner clearing remain separately
reviewed callee premises. The primitive destructor is assumed nonpanicking;
constructor unwind before returning a Stream owns no admitted temporary.
This establishes logical-object transfer/cleanup, not erasure of compiler
copies, padding, registers, fatal-abort state or an entire worker image. The
cross-built Apple/Arm artifacts are compiler inspection, not fresh native runs.

The hosted block remains open for MD5's checkpoint/health/selector composition,
eight-lane input/report/output transport, full worker-result/host quarantine
and public output-loan transactions. Final MD5 composition reconciliation also
remains separate. No production cryptography, dependency, shared modern-HMAC
checker, release gate or approval record changes.

### Hosted MD5 health and checkpoint composition

The actual outlined MD5 checkpoint and all three inlined health probes now
have compiler-data-flow checks. These bind each short-lived, 24-byte borrowed
selector to the admitted executor, check its discriminant and error payload,
and reject storage aliases, escapes, shifted fields, missing lifetime boundaries
and reordered health/cancellation checks. Rust 1.90's extra nonnull-pointer
reconstruction is checked explicitly rather than ignored. `Md5Batch::new`'s
authority-revalidation semantics remain a separately reviewed callee premise;
this selector is not a secret owner and has no destructor obligation.

Both batch-consumer continuations must revalidate before proceeding, including
when the consumer returns an error. The initial, pre-copy and final checkpoints
are bound to the captured cancellation pointer and to the real keyed-consumer,
report and output-copy landmarks. Rejected paths cannot resume those operations.
A symbolic bit-level Result model preserves both the error classification and
every error-payload bit through the actual cleanup branches and final worker
store; it rejects cycles, skipped stores, forged payloads and tag substitution.
Existing envelope and retained-owner checks supply the separate unwind,
completion ordering and selector-borrow obligations.

The final focused suite passes four groups in 77.032 seconds: 111 outlined
callee defects, 403 inlined health/admission/result/lifetime defects and 30 real
compiled Rust defects are rejected, with restored baselines passing. Symbolic
payload tests also reject overlap/carries, unknown payloads and cyclic
continuations. The 16-profile matrix passes on Rust 1.90.0/1.99.1 Linux x86-64
and Rust 1.99.1 Linux/Apple AArch64, with generic/SIMD and abort/unwind builds.

The complete hosted regression suite passes all 57 groups in 776.803 seconds.
It began before the final rejected-health-to-report/output exclusion was added;
the four-group focused run and full 16-profile matrix above include that final
check. This is combined validation, not a claim that the earlier process
reloaded later Python changes. Formatting, Python syntax, script layout,
acceptance metadata, assurance, documentation links and diff checks pass.
Local logs use `release-reports/v0251-hosted-md5-` and are not shipped artifacts.

The post-consumer marshalling prefix is checked for mandatory revalidation
ordering only: lane/report/output byte provenance, control/cancellation callback
transport, complete host output-loan/quarantine transactions and final MD5
composition reconciliation remain open. No whole-worker/register-erasure or
fresh native-qualification claim is made by these compiler checks. Production
Rust, dependencies, shared modern-HMAC checkers and release gates are unchanged.

### Hosted MD5 report admission and active-count provenance

Independent downstream Rust probes now bind six report fields, backend lane
widths and all eight input-presence niches to their emitted layouts. The private
fixture adds a direct edge to the already present first-party legacy-HMAC crate;
no package/version or production dependency changes. The exact fixture graph
check and the private constructor-mutation fixture follow that explicit edge.

The actual optimized report helper is interpreted over six independent
Boolean predicates for each backend: backend identity, vector width, inner and
outer active counts, and inner and outer unsigned minimum-vector thresholds.
All 128 abstract combinations must return success exactly when all six hold,
otherwise `Invariant`. This is not sampling selected numeric counter values:
only the exact typed equality/unsigned-threshold predicates are accepted;
unknown arithmetic, loads, effects, cycles, SSA redefinitions and unvisited
instructions fail closed. The immutable validation result is memoized only by
the full signature/body/compiler bytes within the process; changed bytes or
an unreviewed compiler cannot reuse a prior result.

Both real report call sites must use the captured backend and a sum of all
eight distinct input-presence bits, with dominating pointer reads and the typed
slot geometry. Duplicate, omitted, substituted or inverted slots are rejected.
The report rejection branch must preserve `Invariant` through the worker Result
and cannot resume keyed work, another report, output copying or a checkpoint.
This does not yet prove transport of the report bytes from the batch-consumer
Results, input key/message lane payloads, control callback transport or complete
host output-loan/quarantine transactions. These remain separate composing
obligations, together with final MD5 reconciliation.

Focused regressions reject 90 typed-layout substitutions, 150 report-decision
mutations and 245 count/backend/rejection mutations. Thirty actual Rust worker
defects are separately compiled and rejected on Linux x86-64 and Apple AArch64;
restored baselines pass. The existing 12 private scalar-constructor mutations
and graph-identity suite also pass with the updated fixture edge. Both compiler
Clippy runs and the 16 generic/SIMD, abort/unwind compiler profiles pass. These
checks are reconciled by a complete 61-group hosted regression run on the final
checker/test sources (849.371 seconds, all passing). These
are author-operated compiler checks, not fresh native execution or independent
qualification. Production Rust, shared modern-HMAC checkers, release gates and
approval records are unchanged. Local logs use
`release-reports/v0251-hosted-md5-reports-`.

### Hosted MD5 consumer Result-to-report transport

Independent typed projections bind the 96-byte verification Result's report
at offset 8 and the 120-byte authentication Result's report at offset 32,
including their different error-niche positions. The emitted worker checker
now composes those layouts with the actual consumer/report association, normal
return, map-error branches, post-operation health revalidation and report call.
Verification's split byte loads and 86/7-byte temporaries must reconstruct the
same 88-byte report; authentication must copy its returned Result intact and
pass that copy's report. Constant replacement, field substitution, missing or
short copies, wrong offsets, wrong report arguments and failed-consumer paths
reaching a report are rejected. No fixed SSA naming or source-file hash is used
as a substitute for these checks.

The transport roots must be distinct and allocated before use. Their exact
start markers, pre-report lifetime bounds, duplicate end markers and hidden
writes/escapes are checked. Authentication's mapped Result is still used after
the report for secret-tag output/drop handling: completeness of those later
cleanup paths is explicitly outside this report-transfer projection. Likewise,
lane payloads, output copying, control/cancellation callbacks and complete host
output-loan/quarantine transactions remain open; this is not whole-worker
erasure or fresh native qualification. Production Rust, dependency manifests,
release gates and approval records are unchanged.

Validation: the composed 12-group MD5 report/health/graph regression run passes
in 217.917 seconds. New cases reject 54 typed-layout substitutions, 635 emitted
byte/guard/lifetime/escape mutations and 24 compiled Rust report corruptions;
the existing 60 compiled health/report defects and their restored baselines
also pass. Both compiler Clippy runs, formatting, script inventory, documentation
links, metadata checks and all 16 selected compiler profiles pass. This is
focused author-operated compiler validation, not a new full-family sweep or
native capture. Logs are retained locally under
`release-reports/v0251-hosted-md5-result-`.

### Hosted MD5 lane-payload provenance

Typed downstream probes now bind the five captured input fields, the 40-byte
input-slot layout, the 48-byte private batch `Input` constructor, its inactive
niche, the 384-byte eight-lane array and the successful 32-byte `BitString`
Result projection. The actual emitted worker must initialize all slots inactive
and visit slots zero through seven exactly once. Each slot's presence test
reads its captured key pointer; only its active branch may validate that slot's
message pointer, length and valid-bit count, then transfer that returned
descriptor together with the same slot's key pointer and length. The split
descriptor loads and 22-byte scratch copy must preserve all 32 descriptor
bytes. Both consumers must borrow the same completed eight-lane array.

The checker verifies the complete predecessor/continuation chain, rather than
sampling activity masks: skipped slots stay inactive, successful active slots
continue to the next slot, and invalid bit messages end both temporary lifetimes
and return `InvalidBits` without reaching another constructor or keyed consumer.
Hidden lane/scratch reads, writes and escapes, early array lifetime ends,
duplicate end markers and extra bypass/reentry edges are rejected. Constructor
and descriptor validation semantics remain separately reviewed callee premises;
this does not claim caller-input erasure or native execution. Post-consumer array
end completeness, control/cancellation callback transport, output copying and
full host output-loan/quarantine transactions remain separate obligations.

Validation: the composed seven-group lane/report/health/graph run passes in
248.648 seconds. New cases reject 102 typed-layout substitutions, 2,222 emitted
slot/payload/lifetime/admission defects and 16 compiled Rust lane defects;
restored Linux and Apple baselines pass. The existing 245 report-count, 635
Result-transport and 403 health/admission mutations also pass. All 16 selected
compiler/target/panic/SIMD profiles pass, together with Rust 1.90.0/1.99.1
fixture Clippy, workspace/fixture formatting, metadata, script inventory and
documentation-link checks. No production implementation, dependency or release
gate changed. This is focused author-operated compiler validation, not a native
capture or full-family sweep. The final regression log is retained locally at
`release-reports/v0251-hosted-md5-lanes-final-regressions.log`.

### Hosted MD5 budget and cancellation transport

Independent typed constructor and remaining-budget probes now bind the
24-byte `Md5BatchControl` representation: callback context at offset zero,
vtable at eight and budget at sixteen. Both actual worker consumers must
borrow that same fully initialized control. Its budget must come from the
captured `Parameters::budget`, not the tag size or a substituted allowance;
its eight-byte callback context must hold the captured cancellation pointer.
The checker rejects hidden reads/writes/escapes and early or duplicate lifetime
ends, and requires initialization to dominate both consumer calls.

The emitted constant vtable is followed to both actual call targets. Its
reviewed 64-bit layout must have no destructor, an eight-byte context and the
matching worker's `FnOnce` shim and `FnMut` closure. Each emitted target must
load the original flag pointer from its context, acquire-load the flag and
return precisely whether it is nonzero, with no extra effects. This rejects
stale snapshots, inverted or constant decisions, an unrelated cancellation
flag, weakened atomic ordering and a disabled observer. Consistent SSA storage
renaming still passes; acceptance is not tied to compiler-local variable names.

These checks bind public work-control metadata and callback dispatch, not the
reviewed leaf consumer's charging semantics or a guarantee about scheduling.
Post-consumer cleanup completeness, candidate/decision transport, output copies
and complete host output-loan/quarantine transactions remain separate
obligations. No production implementation, dependency or release gate changes.

Validation: the combined seven-group control/lane/report/health/graph run passes
in 246.939 seconds. New cases reject 66 typed constructor/budget mutations,
190 transport/lifetime mutations, 90 vtable/callback mutations and 18 compiled
Rust defects; restored Linux and Apple baselines pass. The existing 2,222 lane,
635 Result-transport and 403 health/admission mutations also pass. All 16
selected compiler/target/panic/SIMD profiles pass, as do fixture Clippy on Rust
1.90.0 and 1.99.1, workspace/fixture formatting, metadata, script inventory,
assurance policy and documentation links. This is focused author-operated
compiler validation, not a fresh native capture or full-family sweep. The
combined regression log is retained locally at
`release-reports/v0251-hosted-md5-control-final-regressions.log`.

### Hosted MD5 candidate mode and public decision transport

Typed downstream probes now bind the borrowed candidate `Option` slot, the
verification Result's decision projection, its public nonzero conversion and
all three host success encodings (`Some(false)`, `Some(true)`, `None`) on both
reviewed compilers. The worker must read the candidate array pointer exactly
once from the captured Option slot, select verification only on its non-null
branch and pass the original 128-byte array to the existing leaf verifier.
Authentication must instead use the originally captured staging buffer.
Unreviewed uses of either the candidate slot or its loaded array pointer fail
the check, apart from precisely parsed reference-validity assumptions.

The previously checked consumer Result transfer now exposes the proven
verification byte to a separate public-decision checker. It must be converted
only on the accepted report branch, merged with authentication's `None` value,
and passed through the final checkpoint. The symbolic Result continuation
checks all three payloads through the actual worker Result store, retaining
the compiler-specific success tag. Inverted/constant decisions, confused
compute/verify modes, substituted candidate or staging arrays, and altered
success payloads are rejected. This does not re-prove the leaf comparison
algorithm, qualify the tag-to-output copies or complete host transactions.
Production cryptographic code, dependencies and release gates are unchanged.

Validation: the composed eight-group decision/report/health/control/graph run
passes in 124.424 seconds. New tests reject 72 typed candidate/layout/Boolean/
status substitutions, 106 emitted mode/operand/payload defects and 16 compiled
Rust defects; restoring both Linux and Apple source baselines passes. Earlier
54 typed Result, 635 Result-transport, 403 health and 280 control/callback
mutations also pass. All 16 selected compiler/target/panic/SIMD profiles pass,
as do fixture Clippy under Rust 1.90.0/1.99.1, workspace/fixture formatting,
metadata, script inventory, assurance policy and documentation links. This is
focused author-operated compiler validation, not native capture or a full-family
sweep. The combined regression log is retained locally at
`release-reports/v0251-hosted-md5-decision-final-regressions.log`.

### Hosted MD5 tag-to-output copy routing

The actual emitted authentication continuation now has a bounded copy-path
checker. For every active-lane mask and supported tag length, each exposed tag
must reach only its corresponding 16-byte output row, with matching source and
destination lengths and no skipped, repeated or reordered active lanes. Inline
accessor instructions are evaluated; Rust 1.90's outlined accessor is modeled
only at its exact owner/index boundary. Typed downstream probes bind the copy
Result's success and four error encodings on both reviewed compilers.

Additional isolated-lane and boundary scenarios cover zero, oversized and
overflowing widths. Each copy-error variant is injected at each lane, requiring
an immediate stop to copying and the existing invariant-error worker Result.
Successful and rejected copies must reach the original returned owner's Drop,
and no copy may resume after that cleanup admission. These are compiler-path
checks, not new API acceptance of otherwise invalid tag parameters.

Returned tag layout, active metadata, disjoint backing storage and outlined
accessor semantics remain reviewed callee premises. This projection ends at
normal-return owned-region Drop admission: it does not yet establish complete
post-copy or unwind erasure, nor the full hosted output-loan/quarantine
transaction. No production code, dependency or release-gate policy changes.

Validation: the three new groups pass in 189.493 seconds, rejecting 30 typed
status, 1,443 emitted operand/guard-binding/effect and 14 compiled Rust defects;
restored Linux and Apple baselines pass. Consistent tag/output SSA renaming also
passes. The five neighboring decision/Result/health/control/graph groups pass
in 102.605 seconds, retaining their 106, 635, 403 and 280 mutation cases.
All 16 selected compiler/target/panic/SIMD profiles pass, as do fixture Clippy on
Rust 1.90.0/1.99.1, workspace/fixture formatting, metadata, script inventory,
assurance policy and documentation links. These are focused author-operated
compiler checks, not native capture or a full-family sweep. Local logs:
`release-reports/v0251-hosted-md5-tag-copy-debug.log`,
`release-reports/v0251-hosted-md5-tag-copy-composed.log`,
`release-reports/v0251-hosted-md5-tag-copy-renaming.log` and
`release-reports/v0251-hosted-md5-tag-copy-matrix.log`.

### Hosted MD5 returned-tag destruction paths

A separate checker now follows all normal and recoverable-unwind continuations
from the qualified authentication report call, where the returned `SecretTags`
owner is fully initialized. It requires exactly one destruction of that owner's
embedded region before normal result storage or runtime panic handoff. Normal
completion also requires the 32-byte owner's lifetime end. Copying, exposing,
reading, writing or escaping tag storage after destruction, premature/repeated
lifetime ends, unreviewed calls or writes, missing unwind edges and cyclic or
unbounded cleanup paths fail the check.

The `OwnedSecretRegion` destructor's clearing and nonthrowing behavior for valid
regions remain the existing source-bound core premise. Only its normal return
edge is used; this is not a claim of fatal-abort, instrumentation, caller-frame
or whole-process erasure. The check stops at the separately checked worker
Result store or the exception-pointer runtime handoff. Ownership before the
Result-to-`SecretTags` transfer, and complete hosted output-loan/quarantine
transactions, remain separate obligations. No production code, dependencies or
release-gate policy changes.

Validation: the composed seven-group run passes in 164.092 seconds. It rejects
197 cleanup dispatch/lifetime/escape/edge mutations, three unwind-only defects
that pass the earlier copy checker, and ten compiled Rust defects; restored
Linux and Apple baselines pass. The existing tag-copy scenarios and 30 typed,
106 decision, 635 Result-transport and 403 health mutations still pass. All 16
selected compiler/target/panic/SIMD profiles pass, as do formatting, metadata,
script inventory, assurance policy and documentation links. These are focused
author-operated compiler checks, not native capture or a full-family sweep.
Logs remain local at
`release-reports/v0251-hosted-md5-tag-cleanup-composed.log` and
`release-reports/v0251-hosted-md5-tag-cleanup-matrix.log`.

### Hosted MD5 pending-Result ownership and lifetime completion

The mapped authentication Result now has its own ownership-path check across
all three discriminant encodings: the two successful active-lane Boolean
values carry an owner, while the error encoding carries none. Each is followed
through both successful health-selector encodings, health rejection and, for
unwind builds, health-call unwinding. The actual discriminator loads and
branches must transfer the successful owner only after health admission, or
destroy its embedded region exactly once before rejection/panic handoff.
An error Result must never dispatch that destructor.

The preceding source-to-mapped-Result move and tag-byte transfers retain their
independent typed transport checks. Normal error completion must end the
120-byte mapped Result lifetime; after transfer, the returned-tag checker now
also requires that lifetime to end exactly once after tag destruction and
before worker Result storage. Reuse, interior lifetime ends, wrong-owner Drop,
missing cleanup and unreviewed effects are rejected. No production Rust,
dependencies or release-gate policy changed.

This composes existing source-bound nonthrowing core Drop and reviewed leaf
consumer cleanup premises. It does not add a fatal-abort or whole-process
erasure claim, nor qualify complete host output-loan/quarantine transactions.
Final cross-projection reconciliation and those host transactions remain open.

The focused pending-Result regressions cover 54 ownership/health outcomes and
reject 183 emitted-artifact mutations, including eight missing-drop defects
that pass the preceding projections. Six compiled Rust defects are rejected;
restored Linux and Apple compiler baselines pass. All 16 selected
compiler/target/panic/SIMD profiles pass. The composed nine-group regression
run passes in 226.945 seconds, retaining the prior returned-tag, tag-copy,
decision, Result-transport, health and dependency-graph checks. Formatting,
metadata, script inventory, assurance policy and documentation links also pass.
These are author-operated compiler
checks, not native capture or a full-family sweep. Logs remain local at
`release-reports/v0251-hosted-md5-result-cleanup-final-composed.log` and
`release-reports/v0251-hosted-md5-result-cleanup-matrix.log`.

### Hosted output admission and session reuse transactions

The host-side checker now follows the actual post-join control flow for scalar
SHA-1/MD5, compiled SHA-1 and MD5 batch sessions. It tests every current worker
error payload, all three success payloads, compute/verify mode, cancellation,
and incomplete/panicked workers. Only successful compute may retain output;
verification, rejected shape, errors and cancellation must clear it. Staging
must clear on every modeled return. The result category, meaningful error
payload and verification decision must survive transport unchanged.

Accelerated sessions must arm quarantine before native launch. Their different
benign-error sets are checked explicitly: SHA-1 permits cancellation, invalid
bits and message length rejection; MD5 also permits its reviewed tag, batch
shape and compression-budget rejections. Backend/invariant/protocol failures
must not rehabilitate the session. The shared pre-entry campaign checks armed
mapping, attribute and unsuccessful thread-create rejections separately. Exact
initial output/staging clears also dominate every host return, covering bytes
left by a forgotten prior output loan. Both inlined buffer clears and outlined
guard destruction are supported without rewriting emitted instructions.

This composes the existing launch/join, capture, worker-result and buffer-Drop
projections. Reviewed resource clear/destructor paths remain source-bound
nonthrowing premises; fatal abort and process-wide erasure are not claimed.
Full pre-arm request validation, public output-loan factories/lifetimes and
final cross-projection reconciliation remain open. No production Rust,
dependency or release-gate policy changes.

Validation: the composed nine-group run passes in 118.336 seconds. It includes
3,480 transaction outcomes across 24 emitted host profiles, 468 rejected
artifact mutations, 20 rejected compiled Rust defects and restored Linux/Apple
baselines. Source-domain, buffer destructor, launch identity/status, stack
clearing, attribute failure and dependency-graph regressions also pass. All 16
selected compiler/target/panic/SIMD profiles pass, as do formatting, metadata,
script inventory, assurance policy and documentation links. These are focused
author-operated compiler checks, not new native qualification or a full-family
sweep. Local logs:
`release-reports/v0251-hosted-transactions-composed.log` and
`release-reports/v0251-hosted-transactions-matrix.log`.

### Ordinary hosted output-loan construction and consumption

Real downstream fixture calls now expose the ordinary Output methods for
scalar SHA-1, scalar MD5 and compiled SHA-1. Their successful compute factories
must borrow the session's retained output field, never staging or a different
owner. Every current error category and meaningful nested payload must remain
an error with no loan pointer. The factories compose with the previously
checked execute transaction and its compute/verify shape admission.

The emitted expose, declassify and Drop paths are checked for every supported
legacy tag width. Borrowed exposure must preserve the storage pointer and span.
Exact-width declassification must copy to the supplied public destination and
clear the retained owner once; wrong-width requests must leave that destination
untouched and still clear. Conservative first/second resident-access unwind
edges also require clearing before propagation. Source-bound resource helpers,
safe Rust exclusive borrowing and valid caller slices remain explicit premises;
caller copies, fatal abort and whole-process erasure are not claimed.

The distinct active-lane MD5 batch output representation is not covered by
these ordinary-loan checks. Batch loan factories/methods, full pre-arm request
paths and final cross-projection reconciliation remain open. Production Rust,
dependencies and release-gate policy are unchanged; only assurance fixtures,
checkers, regression tests and these progress notes changed.

The focused loan campaign covers 54 emitted method profiles with 928 outcomes
and 18 factory profiles with 546 outcomes. It rejects 390 method mutations,
228 factory mutations and 12 compiled Rust defects; restored Linux and Apple
baselines pass. Missing/duplicate probe populations are rejected, while a
consistent SSA rename remains accepted. The hosted crate's 20 unit/integration
tests and 16 doctests pass, including output-loan escape and simultaneous-borrow
compile-fail tests. All 16 selected compiler/target/panic/SIMD profiles pass.
The composed nine-group run passes in 160.475 seconds, retaining host
transactions, source contracts, buffer clearing, dispatch and graph checks.
Formatting, metadata, script inventory, assurance policy and doc links pass.
These are focused author-operated checks, not new native qualification or an
independent retest. Local logs are
`release-reports/v0251-hosted-loans-composed.log`,
`release-reports/v0251-hosted-loans-matrix.log` and
`release-reports/v0251-hosted-loans-crate-tests.log`.

- Complete the remaining qualification-specific failure-injection checks;
  focused native x86/Arm functional execution now passes.
- Qualify both accelerated compositions and their protected/resident owners,
  including MD5 prefix handling, without silently downgrading their guarantees.
- Complete MD5 batch caller and hosted-worker cleanup-codegen qualification; portable caller ownership, fixed
  Scratch probes, accelerated SHA-1 retained update/cancellation and Linux
  and Apple timing screens now pass, as do the public/verification finalizer
  core owner graphs, three finalizer scratch graphs and retained-finalizer
  handoffs. SHA-1 pre-key admission, constructor scratch, post-admission stream
  ownership and the outlined/inlined iterator cleanup paths now pass. MD5 row
  cleanup, normalization/comparison scratch, workspace lane-drop dispatch and
  pre-workspace tag/authority admission now pass. The final readiness helper
  and success-edge ordering into all three consumers also pass. Phase pointer
  arguments and the outer closure transport now pass. Three-profile
  native failure coverage and inner readiness/digest error-path exclusion pass;
  compiler-level inner message descriptor provenance and conditional ipad
  construction, normalization result-owner transport and bounded normalization
  input/route/no-long-key scenarios now pass. Normalization setup/readiness and
  bounded report guard/transport composition now pass. Conditional outer
  prefix/descriptor construction and inner-result owner transport now pass.
  Conditional inner/outer report acceptance, outer owner transport, truncation
  through final readiness and inner/outer counter field-write provenance now pass.
  Normalization return-copy lifetimes, selected report metadata and report
  completeness on every normal success return now have dedicated checks.
  Final consumer gating, public destination isolation, secret result transport,
  verification decision transport and returned tag metadata/view checks now
  pass their focused projections. Secret consumer write/finish/error/unwind
  handling and complete comparison traces/cleanup now have dedicated checks.
  Caller-side initialization creation/moves/early-failure cleanup and symbolic
  candidate shape/length admission now have dedicated checks. Returned-owner
  success teardown and returned-error-bound quarantine classification now have
  dedicated projections. Hosted public dispatch, native launch storage,
  create/join/stack-reclaim ordering, launch capture provenance, worker envelope
  result/completion ordering and buffer destructor dispatch now have dedicated
  checks. Accelerated worker-local authority transfer/admission, backend matching
  and captured constructor-input provenance now have composing checks. The
  compiled keyed admission/storage, SHA-1 retained destructor/consumer dispatch
  and MD5 selector borrow boundaries now have dedicated projections. Scalar
  retained-state field/terminal transfers, storage lifetimes and both hash-owner
  cleanup dispatches now have dedicated checks. Inlined scalar constructor
  initialization/ownership, key operands, pad phases, scratch and pre-retention
  cleanup paths now have dedicated checks. Normalization-result/descriptor
  provenance, its result-to-pad copy, empty/short/long-key routing and independent
  typed initial-owner/Result layout binding now also pass. Streaming chunk/tail
  provenance, returned output ownership/cleanup and scalar checkpoint/callee
  result handling now have composing checks. Accelerated hosted SHA-1's real
  checkpoint callee, inlined temporary Stream ownership, all six checkpoint
  positions and worker Result status transport now also have composing checks.
  MD5's health-selector lifetimes, three checkpoints, post-consumer revalidation
  and rejected Result payload transport now also have composing checks. Typed
  report predicates, backend/count operands and rejected report status now have
  dedicated checks, as do typed Result-to-report byte transfers and success/error
  admission. Typed lane payloads, the complete eight-slot chain and invalid-bit
  rejection now have dedicated checks. Budget/cancellation control transport and
  both actual callback targets now have dedicated checks. Original candidate and
  staging operands, compute/verify selection and public decision transport through
  final Result storage now have dedicated checks. Tag-to-output copies and their
  normal-return copy-error continuations now have dedicated checks. Post-transfer
  tag destruction/lifetime paths now cover normal and recoverable unwind exits.
  Pending Result ownership, its health-failure/unwind destruction and the
  moved Result's final lifetime now have dedicated composing checks. Post-join
  output admission, result transport, quarantine classification and armed
  pre-entry rejections now have composing host checks. Ordinary output-loan
  creation, exposure, explicit declassification and consuming clearing now also
  have dedicated projections. Batch output loans, full pre-arm request paths
  and final cross-projection reconciliation remain open.
- Register API/capability owners and a separately scoped evidence family.
- Obtain independent retest and run the affected release checks and GitHub.

No crates.io publication or release tag is authorized by this work-in-progress.
