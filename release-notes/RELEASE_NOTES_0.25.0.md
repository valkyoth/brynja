# v0.25.0 — Complete Generic HMAC Construction

Status: in development; no tag, publication or qualification claim.

## Initial implementation

- Added the unpublished `brynja-mac-hmac` leaf with sealed adapters over the
  existing hardened SHA-224/256/384/512, SHA-512/224, SHA-512/256 and SHA3-224/256/384/512
  owners. No hash, backend or core cleanup implementation was changed.
- Implemented byte streaming, full-length one-shot tags, long-key normalization,
  exact protocol-selected byte truncation, consuming verification and typed
  secret/public outputs. Empty keys are mathematically supported, not secure.
- Added all seven RFC 4231 cases, lifecycle/output tests, negative ownership
  rustdoc cases, and an explicit 1,100-case Python/OpenSSL differential campaign.
  These are author tests, not an independent review or full qualification.
- Started source-only packaging with an explicit HMAC include list. Evidence,
  standalone tests and oracle tooling remain in GitHub, not the crate archive.

## Portable acceptance follow-up

- The real extracted archive now rejects 118 public API/ownership misuse probes
  with checked Rust diagnostics, including all ten algorithm owners, consumed
  streams, cross-algorithm/secret-public tag substitution and secret borrow escape.
- Eleven compiled algorithm/comparison mutations are rejected by executing the
  relevant RFC, bit-answer or lifecycle test; compiler errors are not counted as successes.
- A private copied-source fixture injects 328 synthetic hash errors/unwinds and
  verifies owner release, transactional public output, clearing secret output and
  scratch destruction while storage is alive. Five debug/release tests and four
  compiled lifecycle/policy mutants cover this contract. This fixture never
  adds a public fault-injection feature or enters the published archive.
- Extracted `no_std` consumers instantiate all ten named algorithms and two
  general SHA-512/t widths. HMAC-specific
  compiler erasure, real hash exhaustion and timing remain pending;
  synthetic adapter faults do not establish those properties.

## Canonical final-bit messages

- The ten named algorithms accept partial final messages through distinct
  SHA-2 high-bit and FIPS 202 low-bit input types. Streaming prefixes remain
  byte-based; public output, clearing secret output and verification all consume
  the state. Keys and tag truncation remain byte-based.
- Added a 1,040-case differential campaign against separate repository Python
  hash models, including padding/rate boundaries and byte-aligned OpenSSL
  controls. These are author-generated cases, not independent qualification.
- Extracted-package negatives reject the wrong bit-order type and reused
  consumed states. Executed mutants reject dropping final bits and rounding
  them to bytes. Error/unwind injection covers all three bit-finalization paths.
- The focused SHA-256 and SHA3-256 Miri tasks passed with the new bit path.
  ASan/LSan passed all 41 native tests, including forced leak detection under
  hostile parent settings. Rust 1.90.0 and 1.99.1 tests passed. This is not a
  refreshed full Miri campaign or HMAC compiler/timing qualification.

## Scoped verifier registration

- HMAC is now an independent change-impact family. Its source, tests, scripts
  and isolated fixtures select HMAC, not a full old-family fallback. Changes to
  shared SHA-2, SHA-3 or core implementations still select affected HMAC work.
- Command ownership is separate from downstream change propagation: an HMAC
  change cannot accidentally select upstream sanitizer or compiler campaigns.
  Foreground and detached Kani selection agree; an old hash-family receipt does
  not cover the new HMAC proofs.
- Thirteen bounded, independently resumable Miri tasks cover all ten named
  adapters, two general widths and consumer unwinding. Full native matrices remain intact. ASan
  enforces fatal leak detection even under hostile ambient settings. Two Kani
  proofs compile the actual runtime public-length predicates; they are not
  proofs of HMAC cryptographic security or the hash implementations.
- The bounded detached catalog now accommodates the extended Miri population
  plus new-family tasks. No prior task is removed, and over-capacity records
  still fail closed. Focused regressions cover selection, verifier identity,
  missing test populations and the command-capacity boundary.

## General SHA-512/t composition

- Added the distinct `Sha512T<T>` HMAC identity using the existing hardened
  general hash owner. The public constructor retains the HMAC minimum of
  128 tag bits: 383 parameters (128..=511 except 384) are admitted; smaller
  mathematical hash parameters remain rejected, not hidden behind a feature.
- Full tags preserve exactly t bits with canonical unused low bits, while
  explicit truncation selects a complete-byte prefix. Both output owners report
  the exact tag width; general and named identities cannot substitute tag types.
- Inner digests enter the outer hash at their exact bit length. Long-key
  normalization zero-extends the canonical digest into the block-sized key pad.
  A 6,128-case author differential campaign covers every admitted parameter,
  byte/bit messages and four key sizes against a separate Python model.
- Constructor failure is now part of the sealed adapter contract. Synthetic
  fault tests cover 328 error/unwind sites. Dedicated compiled mutations reject
  rounding the inner digest to bytes and weakening the minimum-tag policy.
- General /224 and /256 controls match the named algorithms. Extracted-package
  tests, MSRV checks and focused Miri tasks exercise the new composition; none
  establish FIPS approval or independent cryptographic qualification.

## Remaining work before completion

### Explicit static execution slice

- Added `execution::Hmac` behind an optional `hardened-execution` feature.
  It borrows static CPU authority across normalization, inner and outer hashing,
  using only the existing hardened SHA-2/Keccak owners. Default constructors
  remain portable, and output tag identities are unchanged.
- All required empty owners are admitted before reading key bytes. Backend
  failure and recoverable unwinding release both retained hash states and make
  the stream terminal; atomic SHA-2 length rejection preserves it. SHA-3 overflow
  is terminal because the leaf's operation guard has already cleared its owner.
- Real local SHA-NI narrow SHA-2 and AVX2 Keccak comparisons cover byte/bit
  messages, long keys, truncation, output errors and revocation. Dedicated
  SHA-512 and Arm execution were initially pending; the M2 Pro follow-up below
  supplies author-operated Arm execution, not independent qualification.
- Extracted-package checks add twelve positive accelerated identities and 66
  diagnostic-checked misuse probes. Four instruction-free lifecycle tests and
  four compiled behavioral mutants exercise retained-state failure handling.
  A fourteenth bounded Miri task and sanitizer coverage select these tests
  without executing instructions under the interpreter.
- No existing hash/backend implementation changed. Hosted detection, batching,
  protected/resident HMAC, compiler cleanup and timing qualification remain work,
  and none of these author tests substitutes for independent review.

### Hosted HMAC execution follow-up

- Added default-off `runtime-execution` to the HMAC leaf and `hmac-execution`
  to the hosted CPU adapter. The new `Authority::hmac` factories borrow existing
  platform authority and use the same hardened hash owners as the static path;
  no detector, raw kernel, ordinary hash or cleanup implementation changed.
- `Ok(None)` reports portable selection before key processing. Once an
  accelerated owner is selected, wrong-operation, tag-policy, startup or
  revocation failures remain errors, including under `Prefer`; they never
  become a request to fall back. The existing platform migration limits apply.
- On an Apple M2 Pro, all three static hash routes passed debug/release tests.
  Hosted generic builds (without global target features) also passed all ten
  named algorithms and general /129 and /511, including truncation, retained
  revocation and clearing output after failure. These were author-operated
  development tests; dedicated x86 SHA-512 and independent qualification remain
  pending. The Mac log is retained locally, not used as a release receipt.
- Extracted HMAC packages reject 66 static and 68 runtime API/lifetime probes.
  Extracted hosted packages exercise portable/unavailable behavior in debug
  and release and reject authority escape and access without the hosted feature.
  The new optional dependency remains exact, first-party and default-off;
  workspace tests reject 34 feature-graph mutations.
- The fifteenth HMAC Miri task covers hosted portable/unavailable selection and
  passed. ASan/LSan passed 54 tests with mandatory fatal leak detection; the
  hardware-only hosted test is explicitly ignored there and executed on the Mac.
  Rust 1.90.0/1.99.1 tests and scoped Clippy passed. No full old-family sweep or
  HMAC-wide Miri campaign was repeated.

### Protected scalar HMAC follow-up

The protected scalar slice now adds default-off `strict-hmac` to the hosted
crate: typed reusable resources, exact preselected tag policy, bounded requests,
worker-side verification and clearing output loans. Secret state is first
constructed on the existing protected worker stack; launch captures contain
borrows/public metadata, not keyed HMAC values. It does not alter resource
syscalls, native thread ownership or hash/kernel implementations.

The Linux author tests cover all named identities and two general widths,
long/empty keys, byte/bit messages, truncation, canonical partial tags, mapped
state/output residency, cancellation and recoverable unwind before/after writes.
Faults during verification cannot release a decision after cancellation.
Protected acceleration, Mac residency, Windows HMAC, compiler cleanup/stack
qualification and independent review are not established by these tests.
No strict-facade export is added before this profile's qualification.

The extracted-package debug/release checks pass three downstream tests and
reject 25 ownership/API probes with compiler diagnostics. Four compiled mutants
demonstrate that failed-output clearing, message absorption, comparison and
message budgets are enforced; compilation failures do not count as killed
mutants. The six in-crate native tests pass in debug/release and under Rust
1.90.0. On the M2 Pro, two public-policy/unsupported-target tests pass in both
profiles: this verifies rejection, not Mac protected execution.

A sixteenth HMAC Miri task checks metadata and unsupported model admission.
ASan adds one public-policy test; it does not claim native protected-worker
qualification under instrumentation. The new source/commands remain HMAC-scoped,
while changes to shared resource implementations retain their wider consumers.

### Protected compiled HMAC follow-up

Default-off `strict-hmac-acceleration` adds a distinct `CompiledSession<A>`:
explicit typed kernel selection, protected-worker authority construction and
permanent quarantine after backend, invariant or worker failures. Cancellation,
invalid requests and ordinary mismatches preserve reuse. The scalar `Session`
does not change algorithms with feature unification. Static target features still
require a matching CPU/OS deployment guarantee; no detection or migration
guarantee is inferred.

Local SHA-NI SHA-224/256 and AVX2 SHA-3 routes pass debug/release author tests and
actual extracted-consumer execution. Long/empty keys, exact final bits, explicit
truncation, comparison, protected state/authority mappings, cancellation,
revocation, unwind, clearing and forgotten loans are covered. Four compiled
behavioral mutants per executed route reject broken quarantine, absorption,
comparison and output clearing. Twelve typed package constructors compile and
15 compiled-profile API/ownership rejection probes supplement the 25 scalar
probes. Dedicated SHA-512 and native Linux Arm execution remain pending; cross
compilation is not execution evidence.

The repository unsafe-source policy now passes without widening exceptions:
HMAC uses normal test-module resolution, type macro fragments and the existing
workspace lint. Its archive still omits tests, and an injected unsafe block is
rejected by the extracted crate's inherited lint. The Mac's unsupported-platform
tests verify fail-closed behavior, not protected Mac computation. Existing
historical acceptance bindings remain to be reconciled before release.

### Still required

1. Close remaining modern profile and precise bit/key/tag policies, plus the
   error/fault and no_std consumer contracts. General SHA-512/t now has a
   portable implementation under the existing 128-bit HMAC minimum.
2. Finish qualification for accelerated hash routes and
   protected/resident HMAC composition without weakening host-memory boundaries;
   finish required API/profile/requirement inventories. The modern no_std
   facade integration is implemented below; strict-facade admission is pending.
3. Extend the registered HMAC verifier tasks for the completed profiles and
   finish HMAC-specific compiler cleanup and timing campaigns. Reuse unchanged
   hash evidence; changes to shared implementations still require their affected
   consumer checks. No long whole-repository sweep is launched here.
4. Finish package/downstream, mutant, timing and cleanup qualification, then
   exceptional independent pentest/retest and final release checks.

The completed v0.24.55 consolidation is the baseline, not deferred work.
Legacy HMAC-SHA-1/MD5 remains v0.25.1; cumulative public/package acceptance and
the publication checkpoint remain v0.25.2. Nothing is selected for publication
in this development milestone.

## Apple Silicon resident HMAC development slice

Default-off `macos-resident-hmac` now provides typed complete-request scalar
sessions, bounded work, exact tag policy, worker-side verification and clearing
secret-output loans. `macos-resident-hmac-acceleration` adds explicit Arm SHA-256,
SHA-512 and Keccak selection, using existing hardened owners and static authority
constructed on the joined worker. Backend/invariant/worker failures quarantine
the compiled session; ordinary rejection and cancellation preserve reuse.

This is the existing macOS guarded/locked residency profile, **not core-dump
exclusion or strict admission**. Caller buffers, register/interruption state,
privileged diagnostics and fatal termination retain the documented exclusions.
No OS primitive, unsafe block, hash kernel or strict-facade default is changed.
Generic and unsupported builds fail closed; scalar sessions remain scalar.

The focused acceptance driver explicitly distinguishes Linux protection from
Apple Silicon residency, shares downstream test bodies without changing their
assertions, and rejects an incompatible host/profile before running them.
HMAC-scoped Miri/matrix/sanitizer entries cover the new public-policy and
unsupported-model cases; those checks do not establish native Mac residency.
Native/extracted-package and regression results are author checks, not an
independent pentest, timing/cleanup qualification or release receipt.

On the M2 Pro, six scalar tests and three extracted-consumer tests pass in
debug/release; the scalar suite also passes Rust 1.90.0. Each of the three
compiled routes passes its explicit native test and extracted consumer in both
profiles, plus four executed behavioral mutants. The package rejects 25 scalar
and 15 compiled ownership/API probes and compiles twelve typed constructors.
Native tests observe guarded, wired mappings and check that authority/state and
output storage lie inside owned ranges. Final resource-budget regressions,
generic rejection tests, Mac/Linux Clippy and documentation examples pass.
The new four-case public-policy/model Miri task passes; Linux ASan/LSan passes
60 tests with mandatory leak detection, without claiming native Mac coverage.

## Modern HMAC facade development slice

`brynja::crypto::hmac` and `brynja_crypto::hmac` now expose a curated portable
HMAC namespace, including all ten named algorithms and general SHA-512/t.
Default-off `hmac-hardened-execution` and `hmac-runtime-execution` forward the
required leaf features and expose borrowed CPU-authority execution. Enabling
the leaf through another dependency does not expose a facade execution namespace.
No HMAC export is added to `brynja-strict` before protected qualification.

Focused acceptance builds actual current-version archives without changing the
historical hash-package catalog. Each facade passes four downstream tests in
debug/release with defaults on/off and rejects 118 diagnostic-checked API and
ownership probes. Portable consumers build for `x86_64-unknown-none`; explicit
execution opt-ins are type-checked there and compiled for the native generic
target. The bare target uses a soft-float ABI and is not claimed as a working
accelerated code-generation target. Six independently resolved protocol
consumers retain CPU-free closures, including six rejected activation mutants.

The HMAC leaf remains runtime-source-only. These are author-operated facade
tests, not new native qualification, timing/cleanup evidence or an independent
review. Hash kernels, protected storage and release approval records are unchanged.

## HMAC development inventory

The [composition inventory](../docs/hmac-development-inventory.md) records
15 declared owner/output/guard types, scratch lifetimes, eight execution
profiles and requirement-to-check links. Focused regressions reject untracked
fields, missing operations/adapters, scratch-size/clearing drift and accidental
promotion to global completion. These are source-level inventory checks, not
compiler erasure or independent execution proofs; the global HMAC capability
remains pending until its compiler-owner contract and qualification are closed.
The leaf README now accurately records modern facade and Mac resident support.

## Focused scratch compiler follow-up

An unpublished fixture compiles the actual HMAC `Scratch<N>` source for the
1-byte comparison accumulator, 64-byte digest scratch and 144-byte key pad.
Five fixed probes cover borrowed observation, callback unwind and pad masking.
On Rust 1.90.0 and 1.99.1, x86-64 Linux and cross-compiled AArch64 Linux pass
under both `panic=abort` and `panic=unwind`.

The LLVM control-flow checker requires clearing the exact owned allocation and
length before every reachable normal/error return or recoverable unwind resume,
and before its lifetime ends. MIR destructor and assembly-symbol checks
corroborate the calls; this is not a separate assembly control-flow proof.
Double-panic termination remains outside recoverable cleanup. Regression cases
remove paths, redirect pointers, shorten clears, bypass unwind cleanup and write
after clearing. Two actual source mutants compile successfully but fail the
checker: erased destructor clearing and half-length clearing.

This establishes the stated five scratch probes only. It does not establish
cleanup of every monomorphized `Engine` caller, transitive hash implementation,
register/spill copy, hosted worker or instrumented build. HMAC-wide cleanup,
timing, native and independent-review qualification remain pending. The fixture
and emitted-artifact tooling stay in GitHub, outside the runtime crate archive.

## Real-consumer cancellation compiler follow-up

An unpublished fixture emits 72 real public HMAC consumers: six operations for
each named identity and general SHA-512/129 and /511. The bounded checker
currently checks only the twelve cancellation consumers. Rust 1.90.0 and
1.99.1 pass on x86-64 Linux and cross-compiled AArch64 Linux, under abort and
unwind profiles. Compiler aliases are resolved, not counted as distinct bodies.

The LLVM graph binds the inner and outer cleanup calls to their actual owner
offsets, before every normal return, recoverable unwind resume and owned-slot
lifetime end. It checks dispatch to the existing hash destructors/wipe methods,
not their transitive implementation: a throwing destructor is counted as an
attempt, and double-panic termination is outside the claim. Other operations
are emitted for subsequent inspection, not marked qualified.

Focused regressions reject missing/duplicate probes, cyclic/external aliases,
wrong owner offsets/copy extents, early returns, unwind bypass, premature
lifetime end, duplicate cleanup and post-cleanup writes/calls. A real leaf
`cancel` mutant using `mem::forget` must compile and then fail the checker,
between passing original/restored baselines.

The compiler moves by-value state into an owning slot; these checks do not
establish erasure of moved-from caller bytes or other compiler-created copies.
No whole-frame, register, assembly-flow or complete HMAC cleanup qualification
is claimed. Construction, finalization, verification and update/error caller
paths remained pending at this stage. Runtime sources and release-gate policy
are unchanged.

## Real construction/finalization scratch follow-up

The real-consumer checker now also tracks the local scratch lifetimes of
48 construction, public/secret finalization and verification consumers. It
requires each started key pad, normalized key digest, inner digest, tag and
comparison accumulator to reach its exact full-range clear dispatch before
lifetime end, return or recoverable unwind resume. It explores branches and
switches, resolves compiler aliases, and treats other calls/writes as potentially
dirtying all live scratch, including pointers captured in closures. The separate
caller-output initialization guard has an explicit, storage-bound exception:
safe Rust excludes that guard aliasing the local scratch allocations.

All eight Rust 1.90.0/1.99.1, x86-64/AArch64 Linux, abort/unwind configurations
pass. AArch64 remains cross-compiled evidence, not native execution. Regressions
exercise all twelve identities and reject missing scratch, shortened/wrong
clears, early exits, unwind bypass, stale/unknown edges, premature lifetime end,
post-clear operations and writes after lifetime end. Three copied-source
mutants compile but are rejected: forgotten cancellation, absent scratch
clearing and half-range scratch clearing. Each is followed by a passing restored
baseline.

This is caller-side **clear-dispatch** evidence. A clear invocation on an unwind
edge is an attempted call, not proof that a throwing callee erased memory;
the core clear's separately reviewed non-panicking contract remains a premise.
The check does not establish transitive hash-owner cleanup, complete frame or
compiler-copy erasure, bit-finalization variants, accelerated/hosted worker
paths or timing behavior. Those remaining qualification tasks are not marked
complete. No production implementation, native approval or gate policy changed.

## Bit-finalization and update/error caller follow-up

The unpublished fixture now emits 108 public consumers. In addition to twelve
cancellations, twelve update/error consumers track cleanup of both inner/outer
owners through success, rejected updates and callback unwinding. The checker
follows ownership into the actual moved slot, binds field offsets and copy
extents, and inspects emitted drop-helper definitions rather than trusting their
names. Unwind-profile update and callback calls must have explicit cleanup edges.
Abort termination and a throwing destructor's completed erasure remain outside
this dispatch claim.

The other 84 consumers cover construction plus byte and typed-bit public/secret
finalization and verification for the twelve identities. Adding bit consumers
causes LLVM to share some out-of-line `Engine` methods. The checker resolves
the exact emitted method call and checks its complete scratch graph; missing,
cyclic or wrong-method resolutions fail. Shared bodies are not independent
implementations or independent reviews.

Both compiler versions, both Linux targets and both panic profiles pass.
The focused suite rejects wrong owner pointers, changed copy ranges, bypassed
unwind cleanup, altered helper bodies/signatures, false panic identities and
576 scratch-population/range/pointer mutations. Five compiled mutants are
rejected between passing original/restored baselines: forgotten cancellation,
missing/partial scratch clearing, forgotten state on update error, and a
`ManuallyDrop` wrapper that omits callback-unwind cleanup. The latter two must
fail for their specific missing-cleanup diagnostics, not merely a compile error
or unsupported layout.

These remain bounded caller-side dispatch checks. They do not establish full
construction/finalization hash-owner cleanup, transitive leaf/kernel erasure,
compiler-copy erasure, accelerated/hosted worker coverage or timing qualification.
Production cryptography, runtime package contents, native approvals and
release-gate policy are unchanged.

## Owner-directed package footprint

Before v0.25.2 publication, audit every selected package and its first-party
dependency closure. Ship runtime sources, required build inputs, licences,
README and Cargo metadata only; exclude evidence, native captures, assurance
fixtures, standalone tests/tools and generated audit reports. Retain every file
needed by build scripts or source includes, and prove the extracted packages
build as downstream consumers rather than relying only on a filename filter.
Record actual archive inventories and sizes in repository verification output,
without putting that evidence back into the published packages.
