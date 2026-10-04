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

## Exception and fatal storage boundary

The [exceptional-storage observation](../assurance/windows-protection-observations/sdk-exception-20261004.json)
binds the complete exception body `0xbc90..0xbea6`, cookie-failure body
`0x1160..0x12d5`, and two eleven-byte syscall stubs. Eighteen direct calls,
eight instruction anchors and fifteen RIP-relative global references have
separate checks. Ten regressions pass on Linux and Windows; all 929 body-byte
mutations are rejected on each host, and the saved-file reports match.
These remain offline author-review results, not SDK execution or a new gate.

The exception function pushes three registers and reserves 336 bytes, making
a 360-byte fixed frame. It saves three other registers in caller home space,
initializes a 216-byte history table and uses fixed locals for its cookie,
context size, image base and unwind outputs. Unlike the previously reviewed
invalid-argument and fatal callers, its runtime lookup receives a **non-null
history table**. Accounting for that table is not a proof of arbitrary history
write bounds or general unwinder correctness. It also modifies the supplied
exception record's flags and instruction-pointer field.

The context size comes from a helper and is loaded as an unsigned DWORD.
The emitted caller rounds `(size + 15)` down to a multiple of sixteen in
64-bit arithmetic, probes the stack, and subtracts the result from RSP.
Even `0xffffffff` rounds to `0x100000000`, not zero. Model regressions cover
zero, alignment edges, the maximum DWORD and crossing the clearing-window
boundary. These are arithmetic tests, **not observed runtime sizes**.

The context pointer is dynamic RSP+64. A pointer and an allocation are not
the same as a proven write envelope: context initialization/capture and their
feature-dependent storage still need review. The saved observation therefore
leaves actual dynamic allocation, context write extent and maximum transitive
depth unknown. The normal epilogue resets RSP and restores registers without
an explicit context wipe. Dispatch, context restoration, recursive raising,
stack-probe page addresses and kernel state are not qualified by this record.

The cookie checker tail-jumps to the fatal function, reusing its return slot.
The fatal function reserves 136 bytes and stages pointers, arguments and two
security-cookie copies on its stack. Crucially, its register-capture destination
is **SDK global storage at RVA `0x28860`**, with the previously inspected
capture helper's 768-byte envelope. Selected fatal-record writes occupy an
envelope at RVA `0x287c0` of 40 bytes. Both must belong to one writable,
non-executable image section; zero-initialized virtual storage need not have
raw bytes in the file. Neither region belongs to the clearing stack window.
The review does not claim these globals are erased, resident, concurrency-safe
or covered by a successful-return guarantee.

For the selected diagnostic-buffer origin at capacity 512, the exception fixed
RSP is H-12960 and the fatal RSP is H-12736 on the copy-result path. The
CallEnclave-error path shifts each by another 256 bytes. Twelve selected fixed
spans fit the existing window at all four diagnostic capacities. No fixed
number here includes the runtime context allocation or every transitive callee.
The two syscall stubs identify transitions only; their presence does not prove
kernel cleanup or unconditional termination.

This narrows the remaining work to extended-context helpers, dispatch/restore,
fatal diagnostic callees and the previously recorded loaded-module, external
storage and whole-image limits. It does not expand the product guarantee to
fatal failure or arbitrary exception handling. Production cryptography and
release-gate policy are unchanged.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-exception.py
python3 scripts/cryptography/windows_enclave_sdk_exception.py PATH_TO_SAVED_VERTDLL --mutations
```
