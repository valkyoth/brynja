# Saved scheduler outer-root return review

This continues the [memory-runtime review](windows-enclave-memory-runtime.md)
on the same original copied-input scheduler image. The
[saved observation](../assurance/windows-protection-observations/root-return-20261005.json)
binds `PrivateWaveRoot`, `InputFrame::finish`, `PrivateSchedulerComplete`,
`PrivateInputOutput` and `PrivateWaveRootRegion`: 4,131 emitted bytes, their
complete relocation inventories and their linked destinations. This is an
author inspection aid, not a release gate or independent qualification.

## Normal-return ordering

After the last generation is joined, reduced and retired, the root calls
`InputFrame::finish`. That function requires an active frame, a present request
and exact equality between consumed and requested input bits. Both success and
returned error clear the 128-byte header, 1,024-byte customization buffer and
4,096-byte wave buffer. They also clear the request tag and consumed counter,
then mark the frame terminal. This is not a claim that every metadata byte or
padding byte is individually cleared by that function.

Only successful input completion proceeds to the previously reviewed owner
finalization. Native scheduler completion then requires a bounded wave count
(at most 16,384), the exact fully retired generation word, an equal successful
wave-copy count and the one-shot completion transition from zero to one.
The emitted references resolve to the same scheduler state used by native
retirement, and the same completion word used by the output gate. These checks
do not establish arbitrary atomic interleavings or permit concurrent mutation
of the trusted registration data.

The root initializes a 1,024-byte public-output staging region from its zero
template, checks its placement in the registered root window, and calls the
owner's explicit declassification operation. Output bit length was already
bounded during construction; rounding to bytes here is therefore bounded too.
Only successful declassification reaches `PrivateInputOutput`. Whether that
copy succeeds or returns an error, the root clears all 1,024 staging bytes,
destroys the owner, clears the three copied-input regions again, and returns
through the common epilogue. Earlier ordinary errors after owner construction
take the destructor/state-cleanup path before that same copied-input cleanup.
The initial null/already-claimed rejection precedes payload work. The explicit
fast-fail path is not a returning cleanup path.

The temporary owner-construction region is reused for output staging only after
the slots have been retired. This does **not** individually erase every earlier
compiler-moved state copy: the enclosing clearing window and register-return
boundary remain necessary, as described in the earlier reviews.

## Native output and containment

The native output gate requires completed registration, length at most 1,024,
completed scheduling and a source span inside the admitted root window. It
reserves export with a zero-to-one atomic transition before calling the SDK.
Zero-length output skips the copy. Successful export marks the state two;
SDK failure increments the error count and leaves export reserved, so it cannot
be retried. The bound region predicate relies on the existing valid window
registration, including a sufficiently large, ordered address range; it is not
a general validator for forged global bounds or arbitrary pointer arithmetic.

**Host output is not transactional.** An SDK copy failure may leave part of
the explicitly public output in the host destination. The root's normal-return
staging cleanup still occurs. The C adapter manipulates pointers, lengths and
status; this observation records its exact SDK target but does not yet reconcile
that target's complete implementation and return chain with the separate SDK
review. It does not claim host rollback, OS-exception cleanup or SDK erasure.

`InputFrame::finish` and `PrivateInputOutput` each have a 40-byte fixed frame
(including a saved nonvolatile register, excluding the incoming return address).
The completion and region helpers have no local stack allocation and no unwind
entry; their instructions, not absence of metadata alone, establish that scoped
frame statement. Their complete code is anchored by calls from the reviewed
root, with exact nonrelocated bytes and consistent writable, non-executable
global targets. Existing general unwind/leaf decoders were not broadened.

## Validation and remaining scope

Seven focused inspection tests pass on Linux and Windows. They reject changed
instruction/branch targets, body populations and bytes, relocation identities,
wrong-image anchors, ambiguous/writable/unmapped code, overlapping runtime
entries and inconsistent shared globals. The actual saved-image pass rejects
4,131 single-byte body mutations on each host; parsed reports are identical.
These are inspection-tool regressions, not cryptographic comparisons, live
enclave executions or a universal machine-code proof.

Next are the remaining SDK/output-return reconciliation and coverage of the
other image families, followed by independent retest. Whole-image cleanup is
still not qualified. Arbitrary exceptions, fatal termination, caller copies and
privileged snapshots retain their documented limits. No production code, image
or release-gate policy changed, and the completed enclave/dump campaigns were
not repeated.

```sh
python3 scripts/cryptography/test-windows-enclave-root-return.py
python3 scripts/cryptography/windows_enclave_root_return.py SAVED_RUST_OBJECT SAVED_C_OBJECT SAVED_IMAGE --mutate
```
