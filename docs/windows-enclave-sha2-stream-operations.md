# Saved scalar SHA-2 owner operations

The [saved report](../assurance/windows-protection-observations/sha2-stream-operations-20261005.json)
continues the [owner lifecycle review](windows-enclave-sha2-stream-lifecycle.md)
for the same scalar streaming image. It binds five complete operation bodies,
their relocations and frames, and six seven-entry algorithm dispatch tables.
This is an offline author review of the callers, not qualification of all
their transitive callees or of the separate SHA-NI resident worker.

| Operation | RVA | Bytes | Fixed frame, including pushes |
| --- | ---: | ---: | ---: |
| Begin | 10,144 | 314 | 1,224 |
| Update | 18,288 | 261 | 1,240 |
| Finish | 14,096 | 523 | 2,456 |
| Rehash | 17,376 | 910 | 1,368 |
| Public export | 4,864 | 565 | 1,240 |

Each receiver call must resolve to this exact body. Each operation must call
the previously reviewed admission function, workspace wipe and volatile clearer
at their actual linked addresses. Complete body/reference identity supplements
the instruction-level checks; matching a few warning strings or erasure markers
alone is not sufficient. Table sections must be complete and read-only, and
each object relocation and linked destination must target the selected function.
Rehash has three adjacent tables: each has its own relative-address base.

## Admission and retained-state transitions

Begin requests the empty phase; update and finish request streaming; rehash and
export request retained output. Admission errors propagate without entering
the operation. The reviewed admission has already performed failure cleanup.
An admitted but incomplete guard takes the inline quarantine path on rejection:
copy the 1,174-byte state enum out, mark the original absent, wipe any active
1,170-byte workspace, clear all 64 output bytes, mark the algorithm absent and
set the quarantined phase. Export's successful path performs the same cleanup
but returns the owner to empty. The sequence is preserved.

The previous receiver supplies the nonzero sequence and at-most-1,024-byte
payload preconditions. In particular, update and finish do not have a separate
payload-limit comparison in these emitted bodies. This review does not claim
that arbitrary direct calls to their internal addresses accept unbounded input
safely. Rehash dispatch also relies on the private algorithm enum invariant
established by begin; it is not a validator for corrupted owner storage.

Begin decodes identities 1 through 6 and general SHA-512/t identities
`0x1001..=0x11ff`, excluding `0x1180` (t=384). It stores the algorithm, calls
`State::new`, wipes any prior active workspace, copies the new 1,174-byte state
into owner offset 72, and commits the streaming phase. The constructor's
initialization and error/cleanup behavior remain a separate callee review.

Update dispatches tags zero/one to the narrow updater and tags two through six
to the wide updater. The general-t workspace is at owner offset 76; the other
variants use offset 73. Success preserves streaming. An absent state or a failed
update goes through quarantine. This caller inspection does not qualify the
internal compression paths or counter arithmetic of the update callees.

## Finalization and rehash

Finish accepts an empty tail only with zero final bits. Nonempty tails require
one through eight final bits; a fractional byte calls the mask predicate and
requires its success before constructing the bitstring. Named output widths
are 28, 32, 48, 64, 28 and 32 bytes. General-t width is rounded up from bits,
bounded to 64 bytes. The state is taken before the finalization call: its first
two bytes and remaining 1,172 bytes reconstruct the moved enum at stack offset
1,242. Successful `State::finish` commits retained phase; failure quarantines.
Erasing the consumed state and the finalizer's own scratch is a transitive
obligation, not established merely by the caller's take operation.

Rehash decodes the new identity and preserves the old output's exact bit length,
including a general-t fractional final byte. Its partial-byte predicate must
succeed. It constructs a fresh state and a 64-byte temporary output, then calls
`State::finish` on the prior retained output. Success clears the entire previous
64-byte output before the checked secret copy into it. Only a successful copy
commits the new algorithm. The temporary is cleared on success and on every
post-staging rejection; earlier decode/bit rejections quarantine without
pretending an uninitialized temporary was an active secret buffer. Retained
phase remains unchanged on success. Finalizer, predicate and copy internals
remain explicitly listed as pending in the report.

## Export and storage lifetimes

Export checks the exact requested identity, not only output width, and passes
the corresponding output slice to the fixed `PublicSha2Output` adapter. A zero
adapter result takes the successful cleanup-to-empty path. Identity, size and
copy failures clear retained state and quarantine. This is not a claim of
transactional rollback of bytes already written by a failing host-copy adapter;
the adapter and its SDK connection still need their own review in this image.

As in the lifecycle review, inactive enum bytes in the original protected owner
remain dependent on final page teardown. Stack copies, tag/alignment bytes and
register temporaries are not all individually wiped by the workspace destructor;
the enclosing reviewed stack-window boundary remains necessary. These are
normal-return observations, not new promises about arbitrary exceptions, fatal
termination, privileged snapshots or caller-owned copies.

## Geometry and validation

With window high address H, the operation frames reach H-2,608 (begin), H-2,624
(update/export), H-3,840 (finish) and H-2,752 (rehash). Their nested admission
frames reach H-3,840, H-3,856, H-5,072 and H-3,984 respectively. Every selected
state/staging/bitstring span remains in the clearing window at three address
bases. Callee entry/home space is recorded without claiming complete transitive
frame depth. The finalizer's internal frames, including the general-t path,
remain to be reviewed.

Eight focused tests pass on Linux and Windows; parsed saved-image reports are
identical. Per host, all 2,573 actual body-byte and 168 actual table-byte
mutations are rejected. Separate tests exercise instruction and cleanup
landmarks without the body-hash check, callee/frame mismatches, table mutations,
read-only mapping bounds and translated stack geometry. These are regression
checks on the reviewed artifact and interpretation, not a formal proof or a
new native cryptographic campaign. Production code, images and release gates
are unchanged; independent retest and whole-image qualification remain open.

The subsequent [state construction/consumption review](windows-enclave-sha2-state-review.md)
binds the constructor and state finalizer in this image. Their update/finalize,
render/copy and runtime implementations remain separate obligations.
