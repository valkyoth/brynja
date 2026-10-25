# Hosted legacy HMAC: author-operated compiler checks

This document describes the bounded compiler checks for the four Linux
protected and Apple Silicon resident legacy HMAC routes. It is **not** an
independent review, a native qualification record, certification, a claim that
MD5/SHA-1 are suitable for new protocols, or a whole-worker/register-erasure
guarantee. The published API limits in the
[hosted crate README](../crates/brynja-legacy-hmac-std/README.md) remain in force.

## Connected checks

The entry point is
[`check-legacy-hmac-hosted-cleanup.py`](../scripts/legacy-hmac/check-legacy-hmac-hosted-cleanup.py).
It emits the real hosted crate and a separate downstream consumer fixture,
checks their dependency graph and compiler/target identities, then validates
all four executor/callback pairs. Generic compiled-out workers are checked as
rejection paths, never counted as accelerated execution.

| Boundary | Checked connection |
| --- | --- |
| Request to admission | Actual inlined/outlined validation, independent finite shape oracle, initial clearing, cancellation and compiled quarantine arming |
| Admission to launch | The checked storage-access boundary dominates native launch; launch, capture and transaction projections refer to the same executor artifact |
| Host to worker | Exact callback and launch allocation; every consumed field has captured bytes, including the two-byte result destination and initially false completion flags |
| Worker computation | The existing scalar/compiled constructor, authority, input, checkpoint, result, tag-copy and normal/recoverable-unwind ownership projections run on that same callback |
| Worker to joined host | The actual created handle is joined before stack reclaim and status inspection; borrowed locals survive join and every later host read |
| Setup rejection | Attribute, mapping-admission and unsuccessful-create errors clear staging/output and return the modeled error; ordinary and compiled owners both have explicit campaigns |
| Host to caller | Compute constructs the checked output loan; verification preserves false/true and meaningful error payloads, rejects an absent decision, and forwards the result unchanged through compiled consumers |
| Output loan | Exposure, explicit declassification, consuming clearing and lifetime/ownership constraints compose with the host result |

Reconciliation results are emitted to an optional in-memory collector only
after all four complete chains pass. Partial failure cannot leave a successful
summary. This collector is diagnostic data, not an approval receipt. Its
objects and same-repository source pins do not authenticate a runner or reviewer.

## Selected compiler matrix

| Target | Compilers | Modes |
| --- | --- | --- |
| GNU/Linux x86-64 | Rust 1.90.0 and 1.99.1 | Generic/SIMD, each with `panic=abort` and `panic=unwind` |
| GNU/Linux AArch64 | Rust 1.99.1 | Generic/SIMD, each with both panic strategies |
| Apple Silicon | Rust 1.99.1 | Generic/SIMD, each with both panic strategies |

These are 16 compiler profiles. Emitting AArch64 or Apple artifacts on Linux
does not establish native execution. Rust 1.90 AArch64/Apple is not claimed by
this selected full-profile matrix. Checking an abort profile does not imply
that destructors execute after fatal abort.

The request campaign covers finite boundary shapes, both compute/verify
compiler branches, all MD5 activity masks, per-lane limits, candidate presence,
bit tails and cancellation/quarantine outcomes. It does not prove arbitrary
loop lengths or allocate native buffers of the modeled extreme sizes. Public
verification tests exhaust all padding-byte values for unit errors: padding
must not select a public result category or decision. That is a finite result
conversion test, not a general proof about LLVM undefined behavior.

## Premises and exclusions

- Valid safe-Rust input descriptors, exclusive session borrowing and correctly
  constructed resource/session objects are premises. Inputs and application
  copies remain caller-owned; these compiler models do not read secret bytes.
- Resource/clearing and pthread contracts are reviewed source premises. They
  include the guarantee that failed creation starts no worker and failed join
  does not return to reclaim live storage.
- An allocation without LLVM lifetime intrinsics lives for the invocation.
  Marked borrowed allocations must retain their lifetime through join and the
  final host use; an orphan lifetime end is rejected.
- Linux protected memory and macOS resident memory remain distinct. Nothing
  here adds macOS dump exclusion, CPU migration safety, or unsupported targets.
- Caller frames, arbitrary registers, OS/TLS/panic internals, snapshots,
  hibernation, external thread cancellation and fatal termination remain outside
  the stated owned-storage cleanup guarantee. Stack size is not a depth proof.
- Functional/native tests, independent retest, capability registration and
  release qualification are separate requirements. Passing this compiler
  checker alone does not make the release ready.

## Verification scheduling

The `legacy_hmac` release family owns both compatibility crates and their
fixtures. Its own implementation changes do not select modern HMAC or unrelated
hash families. Shared SHA-1/MD5 implementations, protected-resource code and
shared HMAC verifier/compiler helpers still select the consuming family.

The release catalog includes the five compiler-check drivers, their mutation
suites and both extracted-package consumers. Expensive compiler/mutation checks
remain qualification work, not routine push CI. The hosted driver is scheduled
for the 16 profiles above. Compatibility tests cover both crates; native
hardware and residency observations remain separately collected evidence.

Dynamic-analysis coverage has deliberately bounded, explicit meanings:

- Eleven individually schedulable Miri tasks cover short/long-key portable
  lifecycles, output unwinding, retained-owner state transitions and public
  hosted metadata/rejection models. They do not execute native protected workers.
- ASan/LeakSanitizer covers portable vectors/contracts and public hosted metadata,
  with leak detection and fatal sanitizer exits forced in the child environment.
- Two Kani harnesses prove invalid tag-width rejection through the real public
  MD5/SHA-1 HMAC constructors for symbolic widths and one-byte keys. This is not
  a proof of HMAC cryptographic correctness, all key lengths or valid construction.

An older hash-family or modern-HMAC receipt does not cover these new commands.
Local focused development runs are not detached release receipts or independent
review. Scheduling a check does not claim it has run on every target.

## Saved timing observations

`scripts/legacy-hmac/review-legacy-hmac-timing.py` reconciles the existing eight
Linux x86-64 and eight Apple Silicon observations without rerunning measurements.
It requires both complete host populations, recomputes statistics from raw samples,
rejects signals/failures and binds all recorded source hashes to an explicitly
selected committed snapshot. The only recognized manifest difference is the
exact SHA-1/MD5 direct-to-workspace dependency declaration move; versions, paths,
default features, lockfiles and all other source bytes must remain unchanged.

This is an author diagnostic, **not approval or authenticated evidence**. Adjacent
hashes do not establish who ran a command. The output preserves original capture
HEADs and lists any source mismatches at those HEADs. Recorded compiler/executable
digests are not reauthenticated: the original binaries are not supplied. A later
snapshot matching recorded bytes does not rewrite the capture's history or make a dirty capture
clean. The release gate does not consume this report as a receipt. No timing
signal may be discarded by this tool, and its report cannot replace independent
review, native functional qualification or constant-time analysis.

The author-run regression results and local log locations are recorded in the
[v0.25.1 development notes](../release-notes/RELEASE_NOTES_0.25.1.md).
