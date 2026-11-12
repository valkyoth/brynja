# Apple final-linked AES kernel bodies — v0.27.3 development

Six complete hardware function bodies in each of the sixteen retained Apple
executables now pass an offline Mach-O review. This advances the earlier
capture-only observation; it does not approve the surrounding caller,
admission, cleanup, unwind or complete program.

## Input identity and reproduction

The input remains the [native Apple capture](../../assurance/aes-native-observations/v0.27.3/apple-linked-capture-20261111.json):
Apple M2 Pro, Rust 1.90.0/1.99.1, direct/facade consumers, static/hosted
admission, abort/unwind profiles, opt3/fat-LTO/cgu1/overflow. The original
sixteen executables already ran the known-answer, clearing and quarantine
fixture. This review does not rebuild or execute them and collects no timing
samples. Original capture reports remain unchanged with
`machine_review: not-performed`; the subsequent review is a separate record.

For any retained binary, use its exact hash from the capture report:

```sh
python3 scripts/aes/check-aes-apple-linked.py PATH_TO_RETAINED_BINARY --sha256 CAPTURED_BINARY_SHA256
```

The runner requires a regular, nonsymlinked input no larger than 64 MiB and
checks the supplied capture hash before parsing. It returns a body-only JSON
record; any failure exits 2 without emitting a review record. The expected
hash is an identity binding supplied by the operator, not authentication or
independent provenance. No new release gate or implicit native rerun is added.

## Mapping and boundary rules

The reviewer reads the binary directly; it does not depend on a disassembler's
text spelling or inferred symbol sizes. Accepted images must be thin,
little-endian ARM64 executables, not x86, arm64e, fat/universal, ELF, objects or
encrypted images. Load-command lengths and counts, segment/file ranges,
permissions, section alignment and address-to-file translations are checked.
Overlapping segment mappings, section ranges or metadata tables are rejected.
The instruction section must reside in the uniquely identified read/execute
`__TEXT` segment. Symbol strings, symbol records and function-start data must
reside in `__LINKEDIT` within the file.

`LC_FUNCTION_STARTS` is decoded using bounded, canonical unsigned LEB128
deltas. Starts must increase, be instruction-aligned and remain within
`__TEXT,__text`; the list must terminate, with only zero padding afterward.
Exactly six distinct AES symbols must be actual definitions in that section:
three AArch64 transforms and three AArch64 hardware expansions. STAB debugging
records may repeat names and are excluded from the definition population.
Legacy and v0 Rust symbol spellings are handled explicitly; generic widths
must agree with the matched body.

Each selected symbol must start at a function-list boundary and have a following
boundary. The entire interval between those boundaries is checked, including
anything after a return. Extra instructions or padding are not silently cut off.
No boundary is inferred from finding a familiar byte sequence or the first
return instruction. Missing/changed metadata or encodings require explicit
review rather than automatic policy regeneration.

## Instruction policy and result

The exact AArch64 encodings are reused from the existing independently described
[round-body](aes-accelerated-linked-kernels.md) and
[expansion-body](aes-accelerated-linked-expansion.md) policies. The Linux target
identifier passed to the template generator selects those ISA encodings only;
no Linux ELF mapping or symbol-size claim is applied to Mach-O. Darwin and
Linux share these particular observed instruction sequences. Exact matching
binds every instruction, register, loop bound, branch displacement and trailing
clear/return instruction, without textual or byte wildcards.

Each executable contains three 152-byte/38-instruction transform bodies and
three 196-byte/49-instruction expansion bodies, covering AES-128/192/256.
All **96 bodies across 16 binaries** matched. Hashes, source/capture identities,
review-script hashes, symbol names, addresses and file extents are in the
[Apple body review record](../../assurance/aes-native-observations/v0.27.3/apple-kernel-bodies-20261111.json).
All 192 first/last-byte mutation controls against the actual retained binaries
were rejected. The separate synthetic suite rejects a one-bit change at each
of the 1,044 reference-body byte positions.

Sixteen new regression tests cover both symbol formats, metadata corruption,
wrong targets/protections, truncation, aliases, missing or extended boundaries,
invalid function deltas, invalid symbol strings, width mismatch, hash binding,
symlinks and CLI failure behavior. They are included in the repository tooling
suite, which passed all **834 tests** after the change.

## What this does not establish

The record remains an unauthenticated observation of the captured uncommitted
working tree. It is not validation of an arbitrary Mach-O file, a signature,
the dynamic loader, or a complete Mach-O security parser. Future compiler or
linker layouts can be rejected even when legitimate; they require review.

The complete AES function encodings are now covered, but their invocation and
surrounding state are not. Apple-specific capability admission, dispatch,
owner/caller lifecycle, error/unwind cleanup, linked constants and startup
checks still need their own review. Timing observations, previous timing alarm
dispositions, physical power/EM/fault protection and register/spill erasure
remain separate. The native capture mode therefore stays capture-only and
does not claim these open reviews as current verification passes.

The subsequent [retained cleanup-body review](aes-apple-linked-cleanup.md)
covers the volatile zeroizer and two destruction functions, not all of those
caller or error/unwind obligations. Original body-review and capture records
remain historical records of their respective review steps.

The later [session review](aes-apple-linked-sessions.md) adds exact admission
checks, direction/width-bound calls and a scoped static unwind-import review;
it does not close the remaining higher-level caller or platform obligations.
