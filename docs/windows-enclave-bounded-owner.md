# Saved bounded SHA-256 owner clearing and placement

The [saved observation](../assurance/windows-protection-observations/bounded-owner-20261005.json)
continues the [borrowed-input](windows-enclave-bounded-input.md) and
[rehash](windows-enclave-bounded-rehash.md) reviews. It binds the complete
148-byte workspace wipe at RVA 11,664 and 439-byte placement hash at RVA 13,552
to the original signed bounded image. The archive and extracted object are
unchanged; no production binary was rebuilt.

All four previously reviewed hash/receive/rehash/compute callers resolve their
wipe reference to this body. Receive resolves its placement-hash call to this
body too. Both new bodies and all four callers agree on the same previously
reviewed volatile-clearing leaf. The full function sections, relocations and
runtime extents are checked, not only their symbol names or entry instructions.

## Complete workspace wipe

The emitted wipe preserves the workspace pointer, makes seven direct calls and
finishes with a tail jump to the volatile byte clearer. Its decoded pointer and
length operands cover these regions in the listed call order:

| Region | Byte offset | Bytes |
| --- | ---: | ---: |
| Chaining state | 1,024 | 64 |
| Partial input | 0 | 128 |
| Message length | 1,152 | 16 |
| Phase | 1,168 | 2 |
| Message schedule | 128 | 640 |
| Block copy | 768 | 128 |
| Padding block | 896 | 128 |
| Output staging, tail call | 1,088 | 64 |

Sorted by address, the eight regions cover exactly `[0, 1170)` with no hole,
overlap or empty region. The decoder verifies the complete straight-line
instruction shape, including pointer-register use, every call relocation and
the final tail-jump relocation. It separately checks the region identities/order
and complete coverage. The final tail call executes before returning to the
original caller; it does not allocate an additional wipe frame.

This closes the previously pending wipe semantics for these exact saved callers
and the initialized 1,170-byte workspace they supply. It is not a guarantee for
an arbitrary pointer, a different compiler layout or unreviewed image.

## Placement hash and publication

The placement routine clears the 32-byte staging buffer before checking retained
state. Only idle state enters the hash operation. Quarantined and closed states
return their corresponding errors; other nonidle states return Busy. Those
early state rejections do not themselves rewrite the retained result; the
enclosing receive error path has its separately reviewed quarantine behavior.

For idle state, a maximal generation is rejected before increment, clears the
retained result and quarantines the owner. Otherwise the generation advances,
the retained destination is cleared and the workspace is wiped before its
public SHA-256 IV is installed. The borrowed input pointer and length are then
forwarded to update. The input bounds are established by the reviewed receive
path, not by a newly inferred generic pointer check in this routine.

An update or finalization error wipes workspace, clears the retained result,
quarantines it and returns the Fill error. On success, the returned exposed
secret-output slice must be nonnull and exactly 32 bytes before two 16-byte
loads are copied into retained storage. The returned secret output is cleared,
workspace is wiped, and only then are the identity/generation token and Ready
state published. All normal outcomes converge on a 32-byte staging-clear tail
call after the local ABI epilogue.

The impossible output-shape mismatch retains its emitted length-mismatch call
and `ud2`. It is not a returning error, and no cleanup guarantee for that fatal
path is inferred. Correct output shape still depends on the finalization
callee, which is a remaining review item.

## Stack and register limits

Placement pushes 64 bytes and allocates 56. In the reviewed receive chain its
RSP is `H-3488`; its nested wipe pushes eight and allocates 32, reaching
`H-3536`. The fixed frames agree with their single unwind extents. Saved GPRs,
the 24-byte finalization return and incoming input-pointer/length arguments fit
the existing 64-KiB wrapper-cleared window. The wipe has no secret-valued local
buffer; it retains pointer metadata while calling the byte clearer.

Placement uses vector registers while copying the secret digest. These and all
compiler-created copies are not claimed individually erased by its local
epilogue. Normal return through the enclosing clearing wrapper remains required.
Update/finalize transitive depth is still unknown in the model; no arbitrary
exception, fatal-abort, snapshot or application-copy guarantee is added.

## Validation and next work

Seven focused tests pass on Linux and Windows, with matching saved-image reports.
All 587 actual body-byte mutations are rejected per host. The wipe decoder is
also tested independently of the body hash against every instruction/operand
byte change, altered call relocations and coverage gaps/overlaps. Other tests
cover placement generation/commit/error branches, complete body pins, all four
incoming wipe references, image/clearer identity and fixed-frame inventories.
The geometry is checked at three window bases.

These are offline inspection regressions, not fresh native crypto tests or an
independent retest. Next are the SHA-256 update/finalize and copy/observer/runtime
callees, followed by other distinct worker families. Whole-image qualification
remains incomplete. No production code, signed image, native campaign or
release-gate policy changed.

```sh
python3 scripts/cryptography/test-windows-enclave-bounded-owner.py
python3 scripts/cryptography/windows_enclave_bounded_owner.py SAVED_DIRECTORY EXTRACTED_OBJECT --mutate
```
