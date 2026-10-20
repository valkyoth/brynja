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

### Still required

The repository-wide unsafe-source policy currently rejects tokens in the new
HMAC leaf (`algorithms.rs` is its first reported file). This integration check
has not passed; focused HMAC test results do not replace it. Existing historical
acceptance bindings also remain to be reconciled before a release candidate.

1. Close remaining modern profile and precise bit/key/tag policies, plus the
   error/fault and no_std consumer contracts. General SHA-512/t now has a
   portable implementation under the existing 128-bit HMAC minimum.
2. Finish qualification for accelerated hash routes and
   protected/resident HMAC composition without weakening host-memory boundaries;
   finish facade integration and required API/profile/requirement inventories.
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

## Owner-directed package footprint

Before v0.25.2 publication, audit every selected package and its first-party
dependency closure. Ship runtime sources, required build inputs, licences,
README and Cargo metadata only; exclude evidence, native captures, assurance
fixtures, standalone tests/tools and generated audit reports. Retain every file
needed by build scripts or source includes, and prove the extracted packages
build as downstream consumers rather than relying only on a filename filter.
Record actual archive inventories and sizes in repository verification output,
without putting that evidence back into the published packages.
