# Saved scalar SHA-2 owner lifecycle

The [saved report](../assurance/windows-protection-observations/sha2-stream-lifecycle-20261005.json)
continues the [streaming entry review](windows-enclave-sha2-stream-entry.md).
It binds four emitted lifecycle functions and reconnects their workspace wipe
to the previously reviewed implementation. It does not review the separate
SHA-NI resident owner or finish the scalar hashing operations.

| Function | RVA | Bytes | Fixed frame, including pushes |
| --- | ---: | ---: | ---: |
| `Owner::quarantine` | 10,032 | 106 | 1,224 |
| `Owner::operation` | 10,464 | 257 | 1,224 |
| `Owner::cancel` | 13,840 | 252 | 1,224 |
| `Owner::drop` | 18,560 | 99 | 1,224 |

Full object bodies, relocation lists and linked frame extents are pinned. The
worker's quarantine/destructor references and the receiver's cancellation
reference must resolve to these functions; cancellation must call this exact
operation-admission body. All four use the same linked `memcpy`, workspace wipe
and volatile byte clearer. This establishes callee identity, not by itself the
semantics of this image's memory-runtime implementation.

## Moved state and clearing scope

The compiler implements `state.take()` by copying a 1,174-byte enum region from
owner offset 72 into a stack temporary, then writing the absent tag back into
the original owner. If the temporary is present, tags below six select the
workspace at temporary+1; the general SHA-512/t variant selects temporary+4.
The same 148-byte workspace wipe as in the bounded image clears eight regions
covering exactly 1,170 bytes. Its complete object body, references and clearing
plan are rechecked and its linked address is 6,208 here. It calls the same
105-byte volatile clearer as the streaming entry.

Each path then clears the full 64-byte retained output at owner offset zero
and marks the algorithm absent. Quarantine additionally sets the phase to
three. Owner destruction does not add that phase transition. These operations
do not reset the public sequence counter.

**Taking and wiping the moved state does not erase the original inactive enum
bytes.** Those remain in the protected owner page until the already reviewed
full-page teardown. The complete stack enum copy also includes tag/alignment
bytes outside its active workspace wipe; the enclosing stack-window cleanup
remains necessary. This is the existing storage-lifetime boundary, not a newly
claimed immediate whole-owner erase or a change to production behavior.

## Admission and sequence boundaries

`operation` first requires the expected phase and rejects the quarantined
phase. Failure performs the copy/wipe/output-clear sequence, sets quarantine,
and returns the state error. It otherwise compares the requested sequence with
the stored successor; mismatch performs the same cleanup and returns the
sequence error. Only success updates the stored sequence and returns an
incomplete operation guard. Completion or dropping of that guard in other
algorithm operations remains part of their subsequent review.

The emitted increment/comparison has no separate zero-request or overflow
branch. The saved LLVM IR explicitly marks this internal function's sequence
argument as nonzero (`range(i64 1, 0)`), and the previously reviewed receiver
rejects zero before dispatch. With that precondition, incrementing the maximum
stored sequence produces zero, which cannot equal an admitted request: wrap
cannot reopen sequence one. A focused boundary model checks this equivalence
to checked successor admission, including the maximum values. It also shows
that removing the ingress check would invalidate the reasoning. This is not a
standalone guarantee for arbitrary calls to the internal machine-code address;
other operation callers still require their normal call-chain review. Both the
saved IR identity and its exact internal nonzero signature are checked.

## Cancellation and normal destruction

Cancellation accepts only streaming or retained phases. Other phases perform
the clearing sequence and quarantine with a state error. Valid phases go
through the reviewed sequence admission. An admission failure is propagated;
its cleanup has already occurred. On success, cancellation clears the moved
state and retained output, marks the algorithm absent, sets the phase to empty
and returns success. A successful cancellation preserves the accepted sequence
so a subsequent begin must use the next one.

The entry's normal teardown now has its selected owner-destructor link reviewed:
the destructor clears state/output as above, then the entry clears the live
pointer and all 4,096 page bytes. Fatal termination, arbitrary exception paths
and compiler-created copies outside the established protected window remain
outside this review.

## Stack and validation

The direct worker-to-quarantine/destructor path reaches `H-2,496`; cancellation
under receive reaches `H-2,608`, and its nested admission call reaches
`H-3,840`. The 1,174-byte state copies and either 1,170-byte active workspace
placement remain inside the clearing window at three tested address bases.
The wipe adds its previously reviewed 40-byte frame. Memory-runtime entry/home
space is recorded without pretending it is the complete callee footprint.
Other algorithm-operation frames and whole-image maximum depth remain open.

Seven focused tests pass on Linux and Windows with identical parsed reports.
All 714 actual lifecycle-body byte mutations are rejected per host. Regressions
also cover complete reference identity, copy/wipe/metadata ordering, admission
branches, nonzero sequence boundaries, IR preconditions, callee/frame identity
and stack geometry. The entry, workspace-wipe, leaf-binding and frame regressions
also pass locally. These are offline author-review results, not a new native
campaign, independent retest or whole-image qualification. Production code,
signed images and release-gate policy are unchanged.

The subsequent [operation caller review](windows-enclave-sha2-stream-operations.md)
adds begin/update/finish/rehash/export in this same saved image. Its transitive
state, cryptographic, copy and runtime callees remain separate obligations.
