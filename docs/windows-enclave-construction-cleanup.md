# Saved Windows constructor and prefix cleanup review

This is a selected author review of the original copied-input ParallelHash
scheduler object/image, not whole-image qualification, independent review or a
new release gate. It follows the [engine review](windows-enclave-slot-cleanup.md#engine-operations-and-transfer-helpers).
Neither production code nor the saved development-signed image changed.

The [2026-10-05 record](../assurance/windows-protection-observations/construction-cleanup-20261005.json)
binds seven emitted bodies, their complete code/unwind identities, relocations,
selected admission/cleanup branches and linked constants:

| Saved body | Bytes | Reviewed responsibility |
| --- | ---: | --- |
| `State.initial` | 1,028 | Authority checks, public startup KAT, initialized owner |
| ParallelHash `State.leaf` | 248 | Four leaf identities mapped to SHAKE128/256 |
| `State.setup_chunk` | 491 | Exact declared prefix length, returned-error cancellation |
| `State.finish_setup` | 395 | Complete-prefix admission before absorbing messages |
| `Prefix.bytes` | 187 | Bulk absorption or fractional-byte continuation |
| `Prefix.bits` | 312 | Checked bit packing and pending-byte clearing |
| `Prefix.advance` | 565 | Customization transition, final padding and exact byte count |

## Construction and specialization

`initial` rejects the wrong kernel or unhealthy authority before constructing
scratch, checks generation/instruction identity again before the KAT, and checks
the moved session before returning an engine. The KAT input is 200 public zero
bytes. Its six 32-byte comparison constants are resolved from the actual image
and checked in nonwritable, nonexecutable mapped data; the final lane is an
instruction immediate. All 25 lanes match the existing zero-state reference.
A mismatch quarantines the authority and rejects construction. Active scratch
is wiped after permutation and on the reviewed rejection paths.

This emitted constructor is specialized to algorithm discriminants 4–7:
SHAKE128/256 and cSHAKE128/256. The linked rate table is exactly
`[168, 136, 168, 136]`, indexed by the discriminant minus four. It is **not** a
generic checked lookup for arbitrary integers or all SHA-3 algorithms. The leaf
caller rejects identities outside 1–4 and maps the four supported identities to
`[4, 5, 4, 5]`. Root-side inline construction still needs its separate caller
review; this record does not infer its complete initialization from the table.

Successful construction moves already-cleared scratch through two temporary
regions before initializing engine memory. The KAT output and session metadata
are public. These constructor copies are not individually volatile-erased by
`memcpy`; neither this review nor the existing destructor claims otherwise.
The 32-byte-aligned constructor allocates 2,112 bytes after seven saved GPRs;
the leaf constructor allocates 2,032 after five. Those local frames are not a
transitive root-to-kernel stack bound.

## Prefix admission and returned errors

`setup_chunk` admits only a live Setup-phase owner, healthy matching authority,
and the currently expected name/customization phase. A checked 128-bit subtraction
rejects input longer than the declared remaining length. Whole-byte and last-byte
bounds precede access. Remaining length commits only after successful byte/bit
absorption, then `advance` runs. Any returned helper error reaches the owner's
cancellation path: engine memory is wiped, any pending prefix byte is volatile-
cleared, and the owner becomes terminal. Empty owners return without touching a
nonexistent live state.

`finish_setup` independently requires all four conditions: Complete phase,
zero remaining length, zero pending-bit count, and emitted length equal to the
expected padded length. Failure cancels; success clears the pending byte,
removes the prefix and enters Absorbing. This is a conjunction, not merely an
upper bound on progress.

`bytes` keeps the bulk path when no fractional byte is pending. Emitted byte
accounting uses checked 128-bit addition and commits after successful absorption.
The fractional path invokes `bits` with eight valid bits per input byte.
`bits` admits 1–8 valid bits and fewer than eight pending bits, checks both
position additions, flushes a complete byte, then volatile-clears that byte
before resetting its count. Some helper errors leave a pending byte until the
enclosing owner cancels: **these private helpers do not independently establish
complete prefix cleanup on every error**.

`advance` waits for the current declared input to finish, appends the encoded
customization length, transitions to customization, and finally flushes any
fractional byte. It rejects a zero rate and padding lengths beyond the 168-byte
zero buffer; the complete buffer is checked against actual immutable image data.
It checks padded-length arithmetic and exact expected/emitted equality before
marking Complete. The emitted `left_encode_u128` and `__umodti3` calls remain
explicit semantic boundaries of this selected review, not implicitly qualified
because their relocation names look correct. Encoding/count temporaries are
public metadata; the pending fractional content remains in owned prefix memory.

## Tests, reuse and remaining work

Five inspector tests pass on Linux and Windows. They cover instruction/branch
landmarks, relocation identity and operands, complete body identity, every byte
of the selected image constants, section bounds/permissions/overlap, and rejection
of a wrong object/image before parsing. The saved-image run rejects all 3,226
single-byte changes to the seven code bodies; these are review-pin tests, **not
3,226 cryptographic execution tests**. Both hosts produce identical parsed records.

The earlier native AVX2 component campaign is reused, not reported as a new run:
eleven tests, twenty-one compiled mutation rejections and six ownership negatives
per host. Its 240-entry source maps match between hosts and still match the
checkout. The saved constructor/prefix source copies also match current bytes.
That campaign includes incomplete/excess/overflow prefix rejection, fractional
customization and large streamed setup. These are ordinary process tests, separate
from the completed native VBS image/dump campaigns.

Reproduce the offline inspection with
`python3 scripts/cryptography/windows_enclave_construction_review.py OBJECT IMAGE --mutate`.
The Windows result is preserved in
`release-reports/windows-local-20261005-construction-review/`.
Inline root prefix initialization, remaining session/runtime callees, outer-root
and SDK returns, transitive frame reconciliation and other image families remain
separate work before independent retest. Arbitrary exceptions, fatal paths,
caller copies, production signing and Windows ARM are not qualified here.
