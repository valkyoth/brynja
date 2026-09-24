# v0.24.49 register-cleanup qualification status

Updated 2026-09-24. This is a work checklist, **not a new release gate**.
The [pentest ledger](../../security/pentest/v0.24.49.md) retains the historical
checks and their limitations. Earlier checkpoint paragraphs are not a current
todo list: several were superseded by later implementation and tests.

## Already implemented

- All sixteen existing accelerated kernel entries have opaque computation and
  working-register cleanup implementations. The baseline x86-64/AArch64 scalar
  SHA-2, Keccak, SHA-1 and MD5 ports and shared borrowed secret operations exist.
- Scoped caller-owned APIs exist for the hash families, KMAC, TupleHash,
  ParallelHash and applicable accelerated/batch/threaded paths. Their framing,
  buffering and output-transfer remediations and lifecycle regressions are
  recorded in the ledger. These are not still awaiting initial implementation.
- KMAC comparison differences remain in owned memory; only the authentication
  decision is exposed. Its long focused Miri test passed historically. Loss of
  that log to Cargo clean is recorded, not represented as retained evidence.
- The retained optimized portable KMAC bulk/final reader chain now composes
  metadata, ownership, error/unwind, counter, staging, mask and cleanup checks.
  The current [KMAC diagnostic record](kmac-verify/README.md) lives under ignored
  `dist/`, outside Cargo's `target/` directory.
- Accelerated KMAC bulk/final entry forwarding and consuming reader cleanup now
  bind to the actual same-row producer, destructor, engine-memory wipe and core
  clearing functions. The producer entry also binds complete destination
  initialization before state/authority work, the full ownership-descriptor
  transfer, and initialization-failure cleanup. Completion now binds original
  output ownership, failed-finish clearing and recoverable-unwind cleanup to the
  actual core finish and operation guard. Producer valid-bit/state/authority
  admission, bounded loop progress, final-byte masking and owned writes now
  compose with those boundaries and the actual helper checks. These retained
  optimized checks do not qualify debug call chains or whole-call spills.
- Debug KMAC bulk-reader bridges now bind to the actual same-configuration
  SHA-3 wrappers and error-conversion helpers. Their descriptor-only handoff
  preserves the borrowed owner, destination, length, success ownership and exact
  errors; a synthetic producer unwind propagates without publishing a result.
  The debug producer body remains an explicit unchecked boundary in this check,
  not an inferred cleanup guarantee.
- Accelerated debug consuming-final bridges now bind fourteen-function
  handoff/destructor/core-clear closures. Normal success, each backend error and
  synthetic producer unwind request complete same-owner engine/staging/domain
  clearing before publishing the exact result or resuming the original
  exception. Producer and volatile primitive bodies remain explicit boundaries
  of this check; the existing volatile-helper checks retain their own scope.
  Portable debug consuming-final bridges and whole debug verifier paths remain
  outstanding.
- The portable debug final-output constructor now binds its nineteen-function
  shape/checked-length closure, including the actual separately emitted
  `brynja-hash-core` range helper. All 256 final-bit values are modeled across ten
  selected length boundaries in all eight debug configurations. The eight extra
  helper files were verified against the protected original archive and pinned
  separately; they were not silently added to the original runtime record.
  Constructor qualification does not establish the consuming caller's handoff,
  producer cleanup or whole-call register/spill behavior.

Implementation completion is not qualification completion. Marker-free return
observations alone do not prove absence of transformed secrets or stack spills.

## Before the next independent pentest

1. **Finish the remaining instantiated KMAC path review.** Complete debug
   caller/reader coverage beyond bulk and accelerated consuming-final bridges,
   including portable consuming-final, producer, error and unwind paths, and
   reconcile the
   optimized caller-to-reader/dependency coverage before claiming the whole
   instantiated path qualified. Individual helper checks are evidence to reuse,
   not a reason to assume an unchecked call-chain link is correct. The optimized
   portable bulk/final chain and accelerated producer admission/loop/completion
   boundaries are no longer the next unfinished items.
2. **Complete the wider caller and worker emitted-code review.** Check the
   remaining scoped SHA-2/SHA-3, legacy, TupleHash and ParallelHash call boundaries
   against their stated contracts, including actual worker handoff/return paths.
   Coordinator observations after joining threads do not establish worker
   register or spill cleanup. Fix any concrete secret-copy/residue path found
   within the intended qualified boundary and add a regression for it.
3. **Reconcile the exact guarantee and coverage.** Keep supported compiler,
   target, ABI, feature and normal-return boundaries explicit. Existing movable
   APIs and other-target portable models must not inherit a stronger guarantee
   merely because a scoped x86/Arm path passes. Preserved caller state, signals,
   abort and platform snapshots remain outside the stated kernel contract.
   Any unresolved in-scope behavior must remain visible to the reviewer.
4. **Finish targeted validation and the review handoff.** Reuse unchanged,
   source-bound results; rerun affected correctness, ownership/error, cleanup,
   sanitizer and performance checks when their inputs actually changed. Refresh
   the existing review bindings/documentation and commit a stable candidate with
   an accurate finding disposition. Do not mark F1 closed on author checks or
   delete root `PENTEST.md` while remediation/retest remains outstanding.

These are qualification work packages, not a claim that each needs a new
implementation or a full verifier sweep. Missing local artifacts must be
reported accurately; recover only the evidence needed for the current review.

## After a clean pentest, before release

- Collect/review fresh source-bound native Linux x86, Linux Arm and macOS
  evidence, plus native Windows ABI/runtime evidence for the Windows claims.
  Cross-compilation and QEMU are not substitutes for those native lanes.
  Dedicated x86 SHA512 is still SDE-only in the observed fleet; label it as
  emulation unless a suitable native host becomes available.
- Run the owner-approved final verification using the existing planner, gates
  and evidence-reuse rules; check GitHub, then request tag/push authorization.
  This checklist changes none of those mechanisms.

F2–F5 have implementation/test changes awaiting independent retest. F1 remains
open for the wider qualification described above; the original sixteen-kernel
rewrite is not missing. No military suitability, independent verification or
FIPS validation is claimed.
