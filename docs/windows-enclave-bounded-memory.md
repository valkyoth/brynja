# Saved bounded-image memory runtime

The [saved report](../assurance/windows-protection-observations/bounded-memory-20261005.json)
continues the [bounded export review](windows-enclave-bounded-export.md). It
reconciles this image's four memory routines with the previously reviewed
scheduler runtime, without assuming that similarly named functions are equal.

| Routine | Bounded-image RVA | Bytes | Local saved-register bytes |
| --- | ---: | ---: | ---: |
| `memcpy` REP leaf | 24,256 | 16 | 16 |
| `memcpy` dispatcher/vector body | 24,272 | 1,677 | 0 |
| `memset` REP leaf | 25,984 | 16 | 8 |
| `memset` dispatcher/vector body | 26,000 | 908 | 0 |

## Exact relocation reconciliation

The inspector validates twelve RIP-relative instructions, including the image
base and mutable CPU/runtime selectors, and eight indexed dispatch instructions.
Every actual destination must match its reviewed bounded-image address **before**
normalization. Only those twenty four-byte operands are replaced with the prior
image's values. The complete normalized bodies must then match the prior hashes
and instruction/branch checks byte for byte. Separate hashes pin the original
bounded-image bodies. No other byte difference is ignored.

All eight sixteen-entry jump tables are mapped read-only and nonexecutable,
and every entry is the expected relocated destination inside the corresponding
reviewed body. Exact runtime extents and raw unwind metadata are also bound.
The REP leaves' version-two unwind records are retained without broadening the
existing decoder or claiming exceptional-unwind correctness. The four runtime
selectors must be completely mapped, writable and nonexecutable. Their live
values and future platform correctness are not established by inspecting a file.

## Actual bounded callers

Every executable relocation in the saved Rust worker object and native C object
is scanned for `memcpy`/`memset` references. The expected population is exactly
five direct, zero-addend calls in two previously reviewed Rust functions, and
none in the native C object. Their complete object bodies and relocations remain
pinned, actual linked calls resolve to the routines above, and the emitted
argument setup is checked explicitly:

- Rehash zero-fills 896 bytes at RSP+232, then copies 1,024 bytes from RSP+232
  to RSP+1,262.
- Borrowed hashing zero-fills 896 bytes at RSP+238, then copies 1,024 bytes
  from RSP+238 to RSP+1,326. It subsequently zero-fills 1,088 bytes at RSP+238.

The copy ranges do not overlap and all spans fit the previously bound caller
frames inside the 64-KiB clearing window. These constructor fills/copies are
not substituted for the separately reviewed volatile secret-clearing routines.
The executable-relocation inventory concerns these two saved objects, not all
CRT startup functions, arbitrary dynamically resolved calls or other images.

The vector routines add no fixed frame. Their REP transfers are tail branches,
not extra calls: allowing for the helper return address and its largest saved
GPR area gives `H-3,000` under rehash and `H-3,080` under borrowed hashing.
The existing forward-vector arithmetic model covers the relevant bounded
lengths and alignment residues; it is not native helper execution or a general
`memmove` correctness proof.

## Cleanup and assurance limits

These routines do **not** independently erase their payload registers or saved
register slots. Those remain covered only by the previously reviewed enclosing
window/normal-return cleanup boundary. The reconciliation does not extend that
boundary to aborts, arbitrary exceptions, kernel state or privileged snapshots.
It does not establish the maximum depth of the whole image or live selector
initialization. Other retained worker families still need their own review.

Nine focused tests pass on Linux and Windows, with identical parsed saved-image
reports. Each host rejects all 2,617 actual body-byte mutations and 512 actual
table-byte mutations. Regressions also exercise altered operands, incomplete
populations, unenumerated body differences, unsafe mappings, unwind extents,
caller arguments/destinations and translated window geometry. The prior runtime,
bounded export, borrowed-input, rehash and frame-geometry regressions also pass
locally. These are author inspection/regression results, not an independent
retest, new native enclave run or whole-image qualification. Production code,
signed images and release gates are unchanged.
