# Saved bounded SHA-256 rehash callers

The [observation](../assurance/windows-protection-observations/bounded-rehash-20261005.json)
binds the complete `rehash` (906 bytes, RVA 7,264) and `compute` (1,378 bytes,
RVA 8,176) routines in the original bounded SHA-256 image. It follows the
[borrowed-input review](windows-enclave-bounded-input.md), without rebuilding
the archive or signed image. Full body/reference pins, runtime extents and
incoming dispatcher-to-rehash-to-compute edges agree. Both routines use the
same retained owner and volatile clearer as the dispatcher, and the same
workspace-wipe address as the previously bound borrowed-input hash.

This reviews emitted caller behavior, including the inlined retained-slot
transform. It does not qualify the transitive SHA-256 update, finalization,
workspace wipe, observer or memory-runtime implementation merely by resolving
their addresses.

## Admission, token and commit behavior

`rehash` initializes a workspace and two 32-byte arrays. Before entering
`compute`, it checks an exact 65,536-byte window and complete, nonwrapping spans
for the 1,170-byte workspace, candidate, staging and 64-byte observation report.
An admission failure clears the retained digest, quarantines a nonterminal
owner and returns 190 with no token. Its common return calls the workspace wipe.

`compute` resets the workspace and clears candidate/staging before inspecting
the retained state. Ready state (two) becomes busy (one). Quarantined, terminal
and other ineligible states select their respective 107, 108 and 102 errors;
they do not enter hashing. For a ready owner, two 16-byte comparisons cover the
entire four-word token. A mismatch clears the retained result, writes quarantine
state three and selects 103. The next generation is calculated with an increment
and zero-result overflow branch; exhaustion selects 106 and the same clearing
path rather than reusing generation zero.

An accepted operation supplies exactly the retained 32-byte binary digest to
the SHA-256 update callee, followed by secret finalization into staging. An
update/finalization error wipes workspace, clears the retained result,
quarantines it and selects 104. No public digest copy is added by this path.

The successful finalization result is checked for a nonnull, exactly 32-byte
exposed slice before its two 16-byte loads are copied to candidate. Its owned
output is cleared before the subsequent workspace wipe. Candidate is then copied
to the retained slot, the checked generation is stored and the state is set to
ready. Candidate and staging are cleared on the shared normal completion path.

Before publishing success, `compute` reads back all 1,170 workspace bytes and
all 32 bytes in each candidate/staging array. These checks short-circuit on a
dirty byte; a clean path covers both final workspace bytes as well as every
full unrolled group. Dirty storage overrides the result with 191, clears the
retained digest and quarantines a nonterminal owner. Only a successful transform
with clean scratch returns status eight and the new four-word token. All normal
returns share the ABI epilogue.

`rehash` reports the old/new generations, epoch, status and whether status was
different from 191. A returning observer response other than one suppresses the
token and clears/quarantines the retained result. An acknowledged response adds
bit 32 to the returned status, then takes the common workspace-wipe epilogue.
That bit records observation acknowledgement, not cryptographic success or clean
scratch: a reported rejection, including 191, may still be acknowledged.

## Abort and compiler-copy limits

The emitted output-shape check has a length-mismatch call followed by `ud2`.
This is the fail-stop path corresponding to the fixed-size copy's invariant;
it is not a returning error and is **not** covered by normal-return cleanup.
The inspector preserves that branch and does not invent an unwind guarantee.
The expected output shape depends on the finalization callee's contract, which
still requires its own emitted-code review.

The inlined copy/commit uses vector registers containing digest bytes. Those
registers, compiler copies and saved registers are not all erased at this local
return. Their cleanup depends on returning through the enclosing clearing
wrapper, as in the preceding caller reviews. This step neither adds nor claims
protection for fatal abort, arbitrary interruption, privileged snapshots or
application-created copies.

## Known frame geometry

The dispatcher RSP is `H-464`. Rehash pushes 56 bytes and allocates 2,448, so its
RSP is `H-2976`. Compute pushes 64 and allocates 120, so its RSP is `H-3168`.
The fixed sizes match their single unwind extents. Modeled spans include saved
GPR/XMM registers, the compute result and token copy, candidate at rehash RSP+144,
staging at +192, report at +232 and workspace at +1262. The upper-window and
staging-pointer stack arguments are also inside the window. All modeled spans
fit the existing 64-KiB clearing window at three tested base addresses.

This is not a maximum transitive depth proof: unknown callees remain bounded
only at their entry/home-space boundary in this model. It is not a fresh runtime
placement observation.

## Validation and next step

Six focused inspection tests pass on Linux and Windows; reports from the saved
artifacts match. All 2,284 actual body-byte mutations are rejected on each host.
Regressions also cover token/overflow/commit/cleanup and abort instruction
landmarks, branch targets, complete relocations, call-edge and image identity,
shared storage/clearer/wipe addresses, and complete fixed-frame inventories.
These tests guard this offline inspection, not a fresh cryptographic campaign
or independent retest.

The subsequent [owner review](windows-enclave-bounded-owner.md) binds placement
hashing and the full workspace wipe. The [SHA-256 operation review](windows-enclave-bounded-sha256.md)
adds update/finalize, scalar compression and both copy helpers. Next: enclosing C
copy/observer/runtime callees, followed by other distinct worker families. Whole-image qualification
remains incomplete. Production code, images and release gates are unchanged;
the completed native/dump campaigns were not rerun.

```sh
python3 scripts/cryptography/test-windows-enclave-bounded-rehash.py
python3 scripts/cryptography/windows_enclave_bounded_rehash.py SAVED_DIRECTORY EXTRACTED_OBJECT --mutate
```
