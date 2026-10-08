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
they are explicitly pending, not included in the 23 exact matches.

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

## Remaining package-6 work

- Join batch-specific lifecycle, slot selection and caller arguments to the
  earlier state/helper reviews, including both changed copy-helper ABIs.
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
