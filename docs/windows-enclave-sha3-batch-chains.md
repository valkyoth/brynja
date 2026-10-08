# Windows SHA-3 batch private-chain review

This is completion package 6's partial author review, not a release gate,
independent retest, new enclave execution or whole-image cleanup qualification.
It replays the saved, development-signed images and their original source/build
bindings. Production code and release-gate policy are unchanged.

## Bound populations

| Route | Emitted functions | Cleanup funclets | Exact prior helpers |
| --- | ---: | ---: | ---: |
| Sequential scalar | 54 | 0 | 30 |
| Sequential single-state AVX2 | 54 | 2 | 23 |
| Four-message Keccak AVX2 | 58 | 17 | Not yet reconciled |

Function counts include cleanup funclets. The checker inventories the actual
Rust object, rejects omitted/added bodies, and binds complete function bytes,
relocations, linked destinations, cleanup metadata, read-only constants and
local dispatch tables. It also replays the existing worker/transport bindings.
The four-message route has 15 indirect calls; recording their population and
callback table does **not** qualify their arguments or lifetime provenance.

The sequential helper matches require a fresh replay of the earlier scalar or
AVX2 SHA-3 semantic review followed by exact code, relocation, extent-kind and
resolved LLVM ABI equality. Similar names or an old PASS report are insufficient.
The current batch callers still need their own argument/lifetime composition.
Two AVX2 copy helpers have broader LLVM length ranges than the earlier review;
they are not included in the 23 exact matches. Their explicit widened-range
review is described below; batch caller lifetime composition is still pending.

## Sequential plan admission

Both complete emitted plan validators and their nine identity-table entries are
checked. Eight 24-byte descriptors require valid identities, inactive zero
shapes, fixed SHA-3 widths of 28/32/48/64 bytes, and valid XOF final-bit metadata.
The validators reject an all-empty plan, reject totals above 1,024 output bytes,
and accumulate those widths with an overflow check. Their LLVM arguments retain
the full 192-byte, nonescaping, read-only descriptor contract.

This is metadata admission, not a proof that later computation preserves the
plan, frames, output pointers or authority. The full emitted validator is bound
to the saved object/image in addition to the instruction and dispatch review.

## Sequential lifecycle and widened copy review

The complete emitted `operation`, `clear`, `seal`, `cancel` and operation-guard
destructor bodies are now checked on both sequential routes: 339 scalar and
409 AVX2 instructions/branch labels. Expected paths are constructed from the
reviewed layouts and transitions, not extracted from the body being checked.
The contracts cover phase admission, nonwrapping next-sequence equality,
failure status, output clearing, logical metadata reset and quarantine.
AVX2 admission also requires the expected Keccak kernel and healthy authority
before committing the new sequence. Cancellation accepts phases 1–4 and clears
before returning to empty; sealing requires every active slot's completion bit.
An unfinished operation guard clears and quarantines. The LLVM contracts retain
the complete exclusive owner extent, disjoint operation-result storage and
bounded phase/completion representations.

These are method-body contracts, not proof of every caller or unwind path.
The state-destructor composition below joins these particular method bodies;
validity of retained pointers and cleanup-funclet reachability remain separate
work. In particular, resetting the eight slots'
logical fields does **not** individually erase their padding or moved state
copies, and this checkpoint does not qualify complete private-frame erasure.

The AVX2 `copy_bytes` and `copy_secret_region` helpers permit lengths in
`[0, 2^63)` instead of the prior `[0, 1025)`. Their complete instruction paths
are now separately reviewed and bound; the ABI comparison permits only that
specific range change, preserving every other resolved attribute. The wrapper
rejects unequal source/destination lengths. In the leaf, `offset + remaining = n`;
each eight-byte access requires at least eight remaining bytes and each byte
access requires a positive remainder. Zero length performs no memory access,
and offset cannot exceed `n <= isize::MAX`. This does not prove that a caller
supplied live, sufficiently large, nonoverlapping allocations or that the
destination is eventually erased; those remain caller-composition obligations.

## State destruction and initial plan placement

Both batch state destructors are now explicitly rebound to their previously
reviewed counterparts using complete code, relocation, extent-kind and renamed
LLVM ABI equality. Their current complete instruction paths are also checked:
61 scalar instructions/labels and 43 AVX2 instructions/labels. The scalar
dispatch table is checked for all eight entries, covering empty, fixed-output,
XOF and setup states; the ninth valid state follows the setup branch. All wipe
callees must belong to the exact helper population whose earlier semantic review
was reproduced. This joins typed payload destruction to the five checked
lifecycle methods; it does not assert that the entire state allocation,
padding, moved copies or inactive payload bytes are individually erased.

The complete `begin` methods add 70 scalar and 85 AVX2 instructions/labels.
They admit the empty phase and sequence, validate the entire plan, then copy
exactly 192 bytes into the owner before recording the budget and collecting
phase. Failed validation follows the checked cleanup/quarantine path. The
scalar copy uses the already-bound shared `memcpy` boundary (whose implementation
remains package 8); AVX2 uses six bounded 32-byte transfers. Source and destination
are disjoint under the checked private LLVM argument contract. The state, plan,
output, sequence and budget subobjects are bounded and mutually disjoint.

This composition assumes the caller provides a live, valid owner and plan.
The state spans are `[16, 1152)` inside the 2,400-byte scalar owner and
`[1216, 2208)` inside the 2,272-byte AVX2 owner. It does not yet establish the
retained owner's full lifetime, every later input/output caller, cleanup-funclet
coverage or whole-frame erasure. Those remain explicit package-6 work.

## Remaining package-6 work

- Complete slot selection and subsequent state/copy-helper caller arguments,
  including retained-owner and input/output allocation lifetimes.
- Complete distinct setup, final-bit framing, squeeze, retained-output and
  export paths for both sequential routes.
- Review four-lane Keccak kernel/transposes, compaction, per-lane pointers,
  authority/cancellation calls and their normal/error/unwind paths.
- Assign every private temporary and frame's cleanup responsibility, keeping
  typed erasure, backing-page retirement and enclosing-window reclamation distinct.

Shared SDK/runtime implementation, cumulative stack depth and final protected
window reclamation remain package 8. The current direct-reference graph and
individual frame sizes are not a whole-image stack or erasure proof.

## Validation checkpoint (2026-10-08)

All 12 tests pass on Linux (11.050 seconds) and Windows (29.106 seconds).
The saved-artifact regressions reject 88,058 complete-body byte mutations,
166 validator instruction/label deletions, 18 identity-table changes and
14 descriptor-ABI changes. Additional tests cover missing/added functions,
relocation/extent changes, required prior-review replay and unbound dispatch.
Parsed reports match, including 162 current checker-source hashes. The
[checkpoint observation](../assurance/windows-protection-observations/sha3-batch-inventory-progress-20261008.json)
records those results without claiming completion of package 6.

The subsequent lifecycle/copy checkpoint passes all 19 tests on Linux (18.292
seconds) and Windows (35.152 seconds), with matching parsed reports and 164
current checker-source bindings. It adds 1,496 lifecycle instruction/label
mutations, 56 operand/escape changes, 66 lifecycle ABI changes, 78 copy-loop
instruction changes and 13 copy-ABI/population changes. All preceding inventory
and plan regressions are replayed. The
[lifecycle observation](../assurance/windows-protection-observations/sha3-batch-lifecycle-progress-20261008.json)
records these results and the still-unqualified caller/unwind/frame boundaries.

The state-storage checkpoint passes all 26 tests on Linux (88.013 seconds) and
Windows (165.161 seconds). Parsed reports match, including 165 current checker
bindings. New regressions reject 518 destructor/`begin` instruction mutations,
nine dispatch-table changes, 34 ABI changes, nine missing-helper/prior-review
changes and twelve isolated rebinding changes. Tests require lifecycle, plan
and integrated storage checks to execute; previous regressions also pass.
The [storage observation](../assurance/windows-protection-observations/sha3-batch-storage-progress-20261008.json)
retains the live-owner precondition and the remaining caller/frame obligations.
