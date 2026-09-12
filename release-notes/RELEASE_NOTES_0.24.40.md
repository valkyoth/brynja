# Brynja v0.24.40

Status: exceptional pentest and remediation retest passed; not yet
release-qualified. Scoped development gates and local detached real-campaign
acceptance passed. Three-platform native ParallelHash collection and artifact
review passed; final release qualification remains pending.

## ParallelHash execution

Adds default-off execution APIs for ParallelHash128/256 and
ParallelHashXOF128/256. Hardened roots and workers preserve arbitrary-bit
framing, identity, input order, exact plan provenance and bounded work.
Complete-input serial/caller-scheduled APIs and incremental caller-workspace
streams remain allocation-free and `no_std`. The separate optional std executor
uses bounded worker slots, fallible allocation/spawning and ordered joins.

Portable, preferred and required routes are explicit. Root and worker choices
are independent; supplied backend errors never silently authorize fallback.
Required-static x86 AVX2 and Arm Keccak execution use thread-local authorities;
generic x86 hosted execution remains unavailable. Thread width and instruction
execution are reported separately. No acceleration is enabled by default.

The initial pentest identified a Low defense-in-depth gap in internal streaming
completion. Finalization now requires an unforgeable, root-bound completed-input
loan, checked against pending storage and the exact expected leaf count. Compiled
bypass probes and executable mutants cover the invariant. The public API had
already flushed correctly; the fix prevents an accidental internal shortcut.
The owner-supplied retest of `7d101cb7` closed the finding with no new issues.
That verdict is recorded separately from project-owned tests and native evidence.

Errors and recoverable unwind clear owned root, leaf, metadata and output
staging. Public-output errors are transactional; secret-output errors clear
their destinations. Finalization consumes fixed owners; exclusive readers
cannot reopen finalized state. These guarantees do not cover registers,
compiler-created copies, spills, caches, dumps, swap, DMA, abort, forced
termination or forgotten owners. Caller-owned inputs/copies remain the
caller's responsibility. CPU scheduling and VM feature stability remain
deployment requirements.

See [ParallelHash execution](../docs/parallelhash-execution.md) for the tested
development scope and remaining qualification. The reviewed three-platform
native index now binds Intel AVX2, AWS Arm and Apple M2 Pro results to
`7d101cb7`, with unchanged source inputs. Debug/release campaigns passed 8,704
comparisons on Intel and 13,824 on each Arm lane, including portable controls.
All lanes additionally passed the four kernel lifecycle tests and the
1,024-permutation actual-kernel check. These are project-owned native
observations, not remote attestation, migration assurance or certification.

## Verification workflow and documentation

The new [detached runner](../docs/detached-verification.md) freezes the existing
verification plan, source, tools and exact commands outside the checkout.
Start/status/collect/cancel, independent bounded shards and validated phase
reuse let an operator close the initiating session and return later. It does
not grant full-run approval, turn partial results into success, or publish/tag.
The real affected Miri/Kani two-shard campaign passed, was collected in a fresh
invocation and was reused without rerunning either phase. The edited main
checkout correctly rejected that earlier snapshot's receipt. This development
demonstration is not final release authorization or remote platform evidence.
Subsequent candidate-local Miri/Kani/ASan collection and Linux SSH-disconnect
ASan collection/reuse also passed on `ead83b48`. The exact receipts and resource
observations are recorded in the detached-runner documentation.

The release-tooling follow-up preserves dated nightly identity verification
while reporting newer daily nightlies separately, with an explicit strict
maintenance check. A narrowly checked TupleHash native carry-forward permits
only the consumer fixture's facade-version pin and its reviewed digest change;
all native code and original three-platform artifacts remain bound. The
user-requested project-owned tooling retest passed, including fault injection
against the validators and the real shell fallback control flow. An invalid-pin
regression was added without changing the existing guard. Current-snapshot
qualification and GitHub checks remain separate release requirements.

All 39 crate READMEs now focus on capability/independent-review tables,
hardware/SIMD availability, limitations and usable API examples rather than
release timelines. All 35 Rust examples pass on Rust 1.90.0 and 1.98.1 in an
unpublished first-party documentation fixture. Installation guidance avoids
hardcoded release pins and distinguishes checkout-only APIs. Shared baseline
checks validate the documentation without selecting unrelated Miri campaigns.

No new third-party dependency or production unsafe code is introduced. The
existing sanitization dependency remains unchanged. This internal milestone
publishes no crates; every release selection remains `publish = false` and
the next crates.io checkpoint remains v0.25.2. Project-owned testing is not
independent cryptographic verification or FIPS validation.
