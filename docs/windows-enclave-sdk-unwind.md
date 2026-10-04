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

The next unreviewed normal decoder boundaries are `0xc538` (epilogue
interpreter) and `0xc94c` (unwind opcode decoder). Exception dispatch, fatal
paths, loaded-module identity, external storage and kernel behavior also remain
outside qualification. Earlier lock/node-reclamation limits still apply.
Production cryptography and release-gate policy are unchanged.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-unwind.py
python3 scripts/cryptography/windows_enclave_sdk_unwind.py PATH_TO_SAVED_VERTDLL --mutations
```
