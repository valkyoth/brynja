# Saved SDK unwind-engine frame review

This extends the [saved SDK frame review](windows-enclave-sdk-frames.md), using
the same saved `vertdll.dll` version 10.0.26100.9444, not an independently
identified loaded enclave module. The
[observation](../assurance/windows-protection-observations/sdk-unwind-20261004.json)
binds three complete ranges: engine `0xcf78..0xd861`, chained-entry helper
`0xc4e8..0xc530` and code-slot helper `0xc904..0xc944`. Together these contain
2,417 bytes. Nine direct calls and the helper's eleven-byte read-only table
at RVA `0x23d10` are separately checked.

Eight focused tests pass on Linux and Windows, and their saved-file inspection
reports match. Each of 2,417 single-byte body mutations and eleven table-byte
mutations is rejected. The table must occupy one bounded, nonwritable,
nonexecutable section. These checks establish identity and drift detection
for manually reviewed bytes, **not unwinder correctness**. The inspectors do
not execute SDK instructions or add a native enclave campaign.

## Selected stack accounting

The engine pushes six registers and reserves 120 bytes, for a fixed 168-byte
frame below its entry RSP. It saves three argument registers in caller home
space, writes a mode word to another home slot and stages outgoing arguments,
decode state and pointers in its local allocation. Its normal epilogue restores
registers but does not erase the saved slots.

One working flag is at **engine RSP+256 = adapter RSP+80**. It is a caller-owned
slot, not part of the engine's 168-byte allocation. The adapter's existing
frame accounts for that slot; the new regression checks this equality rather
than inventing a larger engine frame. Returned handler/address slots at
adapter RSP+96 and +104 are also represented.

The chained-entry and code-slot helpers each reserve 40 bytes. The latter
saves its two-byte opcode in home space. A separate nested runtime-lookup
call adds a 72-byte frame and writes its image-base result into an engine
local. Its deeper callees are not silently absorbed into this first-frame
calculation.

| Selected RSP, direct formatter-invalid path at capacity 512 | Copy-result path | CallEnclave error path |
| --- | --- | --- |
| Engine | H - 15312 | H - 15568 |
| Either metadata helper | H - 15360 | H - 15616 |
| Nested runtime lookup | H - 15392 | H - 15648 |

The conservative wide-helper-invalid origin shifts these by 128 further bytes.
Nine selected spans fit the existing clearing window for all four diagnostic
capacities. This is not a maximum transitive stack-depth or exception-cleanup
bound.

## Writes and remaining boundaries

The engine reads unwind metadata and instruction bytes, and updates the
supplied context's register bank, stack pointer and instruction pointer.
Optional outputs can receive handler addresses and saved-register locations.
Neither this review nor its geometry proves bounds for arbitrary metadata,
context pointers or output destinations. Selected range checks in the engine
must not be presented as a complete validation proof.

Both metadata helpers and the engine can call the previously reviewed recursive
status raiser. Only the first exceptional frame is mapped, with transitive
depth explicitly unknown. No all-path erasure claim follows from these frames.

This engine-only record stopped at `0xc538` (epilogue interpreter) and `0xc94c`
(unwind opcode decoder); the subsequent review below accounts for their
selected frames and context writes. Exception dispatch, fatal
paths, loaded-module identity, external storage and kernel behavior also remain
outside qualification. Earlier lock/node-reclamation limits still apply.
Production cryptography and release-gate policy are unchanged.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-unwind.py
python3 scripts/cryptography/windows_enclave_sdk_unwind.py PATH_TO_SAVED_VERTDLL --mutations
```

## Epilogue and opcode decoders

The [decoder observation](../assurance/windows-protection-observations/sdk-decoders-20261004.json)
binds both complete bodies: `0xc538..0xc8fa` (962 bytes) and `0xc94c..0xcf70`
(1,572 bytes). Three direct calls reach the already-reviewed slot helper and
status raiser. The fixed-frame prologues and paired vector-load/store sequence
have additional instruction checks independent of the whole-body hashes.
Nine regressions and 2,534 actual-body byte mutations pass on Linux and Windows;
the saved-file reports match. This remains offline, implementation-author review.

The epilogue interpreter pushes seven registers and reserves 80 bytes: a
136-byte fixed frame. The opcode decoder pushes four registers and reserves
120 bytes: a 152-byte fixed frame. Both reuse argument home slots and local
scratch for counters and pointers. Their slot-helper calls add 40-byte frames;
the decoder paths are alternatives, not nested together.

| Selected RSP, direct formatter-invalid path at capacity 512 | Copy-result path | CallEnclave error path |
| --- | --- | --- |
| Epilogue interpreter | H - 15456 | H - 15712 |
| Opcode decoder | H - 15472 | H - 15728 |
| Epilogue slot helper | H - 15504 | H - 15760 |
| Opcode slot helper | H - 15520 | H - 15776 |

The wide-helper-invalid origin shifts these by another 128 bytes. Nine selected
stack spans per origin fit the clearing window at each diagnostic capacity.
Restore instructions do not erase these saves or locals.

For the two modeled invalid-argument origins, the captured context begins at
engine RSP+576. The selected scalar-register writes occupy offsets `0x78..0xf8`,
the instruction-pointer write `0xf8..0x100`, and the sixteen vector slots
`0x1a0..0x2a0` (end-exclusive). The stack pointer is inside the scalar bank.
All fit inside that caller's previously reviewed 768-byte context envelope.
Tests enumerate every four-bit register selector and reject model inputs beyond
the inspected range; they do not add validation to Windows itself.

Each vector slot is restored using **two eight-byte loads and stores**, covering
sixteen bytes. This is not a claim about complete AVX/YMM/ZMM or other extended
processor state. Nor does the known-context bound apply to arbitrary context
pointers, malformed metadata, reads from a reconstructed stack, or optional
saved-location arrays supplied by other callers. Those arrays may receive
source addresses and remain outside this bounded destination claim.

Excessive chained metadata makes the epilogue interpreter return an error;
the opcode decoder can instead invoke the recursive status raiser. Slot-helper
errors can also raise. Only first exceptional frames are represented; transitive
depth and exception cleanup remain unknown. The decoder frame review adds no
new unreviewed ordinary callees, but it does not prove general unwind correctness,
loaded-module identity or whole-image cleanup. No production code, native
campaign or release-gate policy changed.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-decoders.py
python3 scripts/cryptography/windows_enclave_sdk_decoders.py PATH_TO_SAVED_VERTDLL --mutations
```
