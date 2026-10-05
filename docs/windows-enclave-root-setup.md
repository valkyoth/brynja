# Saved Windows ParallelHash root initialization review

This selected author review extends the [constructor/prefix review](windows-enclave-construction-cleanup.md)
into the actual saved scheduler's inlined root setup. It is not independent
qualification, a new release gate or a claim that every image's call graph is
closed. Production code, compilers, the saved image and runtime policy are unchanged.

The [2026-10-05 record](../assurance/windows-protection-observations/root-setup-20261005.json)
binds the emitted `Waves.new` body (2,390 bytes), its two retained destructor
funclets (74/65 bytes), public `left_encode_u128` (487 bytes), and the specialized
block-size encoder (160 bytes). Code, relocations and associated unwind metadata
are matched to the original object and linked development-signed image. The
retained funclets are identified in that constructor's own metadata; this does
not assert that arbitrary OS exceptions run Rust cleanup inside an enclave.

## Admission, domain separation and completion

The constructor admits only identities 1–4, block sizes 1–1,024 bytes, and
customization/output lengths at most 8,192 bits. Kernel and health checks precede
state creation. Multiplication by eight is safe after that block-size bound, and
the nonzero divisor is established before either emitted division form. The
rounded-up leaf count is rejected above 65,536 before construction proceeds.

The admitted identities select cSHAKE discriminants `[6, 7, 6, 7]`, closing the
root-side input-domain obligation for the specialized constructor reviewed
previously. Its actual immutable rate table is `[168, 136, 168, 136]`. The name
comes from a separately bound immutable image span containing exactly
`ParallelHash`, used as twelve bytes/96 bits. It is not inferred merely from a
relocation name or a source comment.

Inlined prefix initialization computes the encoded rate/name/customization
lengths, adds the fixed 96 name bits and declared customization bits, rounds to
bytes, and pads to the selected rate. The bounds above justify the optimized
fixed-width arithmetic and removed checks in this particular image. The name
length is nonzero even when customization is empty, so the configured domain
suffix is `0x04` with width three, not SHAKE's empty-name/customization suffix.
The root installs the prefix, absorbs the name, optionally absorbs customization,
and requires successful `finish_setup` before adding the encoded block size.

The block encoder is specialized to the constructor's admitted block range:
one or two payload bytes, with a two/three-byte complete encoding. It clears the
17-byte destination and one-byte length first, writes the encoding, and publishes
length last. Its retained panic edge for an invalid shift is not an admitted
path for these block sizes; it is **not** qualified as a general u128 encoder.
The separate public `left_encode_u128` body scans the big-endian input for its
minimal width, preserves a byte for zero, zero-initializes the unused output tail,
and publishes the encoded length. Its input/output temporaries and control flow
represent declared public lengths here, not secret integer processing.

## Ownership and temporary copies

Before the prefix is installed, returned failures clear the local pending byte,
cancel engine memory and destroy active scratch. After installation, failed name
or customization processing drops the corresponding live state. Block-framing
failures drop both the framing storage and state. Success moves the live state
and zero-initialized 1,024-byte output into the new owner, initializes progress
counters and Working phase, and destroys the temporary block encoding.

The compiler emits several moves. The frame model distinguishes the full working
state at offsets `0x300`, `0x12a0`, `0x6e0` and `0xec0` from the two **943-byte
payload-only** move regions at `0x1a39` and `0x168a`; their first byte and trailing
metadata are held separately. It also records the uninstalled prefix, its two
move regions, and the later reuse of initial-core storage for block framing.
The two retained funclets target the live states at `0x12a0` and `0x6e0`, not
every earlier moved region.

The reviewed root constructor has eight saved GPRs, a 7,672-byte allocation and
32-byte alignment. Its local regions fit inside the modeled 64-KiB root window
through the already reviewed root-entry chain. Earlier moved copies are **not
individually erased** by the active state's destructor; normal-return clearing
of the complete window remains responsible for them. The model does not yet
bound every reachable runtime/kernel frame, qualify OS exception dispatch, or
extend the existing guarantee to fatal exits or external caller copies.

## Verification and remaining boundaries

Seven focused inspector/model tests pass on Linux and Windows. They reject
changes to admission/cleanup landmarks, branch destinations, relocation operands,
body size/content/population and object/image identity. Actual saved-image runs
reject all 3,176 single-byte body-pin mutations, with identical parsed records
on both hosts. These are integrity regressions, not cryptographic case counts.
Arithmetic-model comparisons cover all 8,193 admitted customization lengths for
each identity and all 1,024 block sizes, including exact/excess leaf boundaries.
They supplement inspection and do not execute the compiled image.

The prior native component campaigns remain separate and are reused, not rerun:
the state campaign's 240 source hashes and wave campaign's 256 source hashes
still match the checkout. Original saved constructor/framing sources also match.
Those campaigns include actual AVX2 oracle, lifecycle, compiled mutation and
ownership checks; no new native VBS or dump observation is claimed here.

Reproduce with
`python3 scripts/cryptography/windows_enclave_root_setup.py OBJECT IMAGE --mutate`.
The Windows record is saved under `release-reports/windows-local-20261005-root-setup/`.
Direct runtime boundaries remain explicit: `__chkstk`, `__umodti3`, `memcpy`,
`memset`, and the out-of-domain panic target. Remaining permutation-session,
outer-root/SDK return and cross-image reconciliation precede independent retest.
Production signing and Windows ARM remain outside this development-only result.
