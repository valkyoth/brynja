# Selected Windows SDK transition frames

This is a build-specific, author-reviewed extension of the
[scheduler caller review](windows-enclave-whole-image-cleanup.md), not production
or whole-image qualification. The [observation record](../assurance/windows-protection-observations/sdk-frames-20261004.json)
binds a file copied from the development VM's `System32` directory:
`vertdll.dll`, file version `10.0.26100.9444`, SHA-256
`f5bfb961d19775123c93b8cdf4318238acdf9647bb4518bf009d1969b4d2612f`.
The copied file is saved outside `target/`, in the ignored
`release-reports/windows-local-20261004/sdk-system32-review/` directory.
No Microsoft DLL is committed or redistributed in the repository.

The offline checker binds six complete instruction bodies and the full file
hash. Six focused tests pass on Linux and Windows; 338 single-byte mutations,
missing/extra bodies and truncated/extended bodies are rejected. The actual
file inspection also passes on both platforms. These tests do not execute SDK
code or constitute a new native enclave campaign.

## What the inspected instructions show

`CallEnclave` saves RBX, allocates 32 bytes and uses a caller home-space slot
for the argument/result. It calls `RtlCallEnclave`. That routine allocates
312 bytes, saves XMM6–15 and eight nonvolatile general registers, calls an
11-byte syscall stub, then restores the saved registers before returning.
The restores do **not** erase the saved stack slots. The enclosing Brynja
normal-return window clearing remains necessary.

Using the separately bound scheduler caller geometry, with `H` the exclusive
upper address of its 64-KiB window:

| Selected location | Offset from H |
| --- | --- |
| RtlCallEnclave frame base | -12016 |
| XMM6–15 save region (160 bytes) | -11968 |
| Eight GPR saves (64 bytes) | -11768 |
| Transition syscall return address | -12024 |
| Copy entry frame base | -11488 |
| Copy syscall return address | -11496 |

The 22 selected spans, including the outer argument/result slot and saved RBX,
fit inside the cleared window. This extends the earlier entry/home-space-only
calculation for this specific file; it is not a maximum transitive stack-depth
proof. The model derives its starting positions from the previous caller model,
not a second independent set of scheduler offsets.

Both copy exports allocate 40 bytes, select a direction flag and call the same
11-byte syscall stub. The reviewed entry bodies and stubs do not load payload
bytes or create a software payload copy. They tail-call a status conversion
helper after restoring their stack pointer. The conversion helpers and
kernel-side transfer implementation are outside this selected-body review.
The follow-up below extends this selected review to their immediate status
helpers, while retaining an explicit stop at the deeper diagnostic routine.
Microsoft documents the [copy API's input and result contract](https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclavecopyintoenclave),
not an internal spill-erasure guarantee. Likewise,
[CallEnclave](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-callenclave)
defines the callback/return interface, not where the kernel preserves context.

## Limits and reproduction

The System32 file hash does not establish which module bytes were loaded in a
historical enclave run. No loaded-module identity, kernel storage, arbitrary
exception/fatal cleanup, other SDK builds or other linked callees are qualified.
These are evidence limits, not a claim that the SDK has a vulnerability. The
existing full-window cleanup and scoped native transition/dump observations
remain separate evidence. Production APIs and release gates are unchanged.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-frames.py
python3 scripts/cryptography/windows_enclave_sdk_frames.py PATH_TO_SAVED_VERTDLL
```

The checker rejects any different SDK file. A Windows update requires a new
review, not rotating its hash and assuming identical behavior. The existing
limited unwind decoder does not support this SDK routine's frame encoding;
this review uses exact instruction bytes and does not relax that decoder.

## Status and error-path follow-up

The [additional status-path record](../assurance/windows-protection-observations/sdk-status-20261004.json)
binds six further complete bodies in the same saved file: the copy-result
converter, the CallEnclave error adapter, status-to-error conversion and lookup,
the last-error setter and the diagnostic entry. Eight focused tests pass on
Linux and Windows. They reject 478 single-byte body changes, missing/extra or
truncated/extended bodies, changed transfer targets and invalid code-section
mappings. Inspection of the actual saved file produces identical reports on
both platforms. This is offline inspection, not execution of those SDK paths.

The two copy exports restore RSP before tail-jumping to their converter. Its
frame therefore replaces the copy-entry frame; it is not an additional nested
call. The CallEnclave error path, by contrast, calls its adapter from inside
the existing CallEnclave frame. Both adapters call the status conversion and
lookup chain. The lookup can call the diagnostic entry three times for an
unmapped status; those calls are sequential, not three simultaneous frames.

| Selected post-prologue RSP | Copy-result path | CallEnclave error path |
| --- | --- | --- |
| Status adapter | H - 11488 | H - 11744 |
| Status-to-error converter | H - 11536 | H - 11792 |
| Lookup | H - 11584 | H - 11840 |
| Diagnostic entry | H - 11664 | H - 11920 |
| Deeper diagnostic callee entry | H - 11672 | H - 11928 |

Fifteen selected spans cover the status home-slot spill, saved RBX, diagnostic
RCX/RDX/R8/R9 home slots, varargs pointer and last-error leaf return/home area.
They fit inside the same scheduler clearing window. The diagnostic entry saves
all four argument registers, including values not established here as payload
or non-payload; this is not an argument that caller residue cannot exist.
Its deeper callee at RVA `0x16910` is explicitly outside this frame model.
Neither its frame size nor maximum transitive depth is inferred from its
entry/home-space area.

There are also **non-stack writes**: the converter stores a four-byte incoming
status at offset `0x1250` from the pointer read at `GS:0x30`; the last-error helper
stores a four-byte converted error at offset `0x68` from that pointer. Those are
status values in these inspected paths, not copied hash/key payload. Their
storage is not established as inside Brynja's clearing window and is not
claimed erased by it. The setter also has a conditional `INT3`; arbitrary
interruption/debug handling remains outside the normal-return review.

No SDK bytes, production cryptography or release gates changed. Loaded-module
identity, kernel context storage, deeper diagnostic behavior and remaining
linked callees still require separate treatment. The earlier six-body record
is preserved with its original narrower scope.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-status.py
python3 scripts/cryptography/windows_enclave_sdk_status.py PATH_TO_SAVED_VERTDLL
```

## Diagnostic retry and formatter-frame extension

The [diagnostic observation](../assurance/windows-protection-observations/sdk-diagnostic-20261004.json)
extends the earlier stop at `0x16910` for the **same saved SDK file**. Eight
complete bodies (1,039 bytes) cover the retry wrapper, diagnostic buffer owner,
stack probe, two formatter adapters, debug output/trap and cookie checker.
Eight regressions pass on Linux and Windows, rejecting every single-byte body
mutation, changed direct-transfer targets, format-string changes including NUL
terminators, and ambiguous/truncated/writable section mappings. Actual saved-file
inspection reports are identical on both hosts. This is not SDK execution.

The retry caller starts at 128 bytes and increments by 128 only after a truncated
result, stopping at 512. These are sequential calls, not cumulative live buffers.
The buffer routine rounds this capacity to 16 bytes, then allocates it below its
328-byte fixed frame. The modeled output begins 32 bytes above the resulting
RSP. The three pinned status messages contain one `%lx` conversion in total;
there is no string-pointer conversion in those messages. This observation does
not qualify the formatter's complete implementation or arbitrary callers.

| Selected RSP at capacity 512 | Copy-result path | CallEnclave error path |
| --- | --- | --- |
| Retry wrapper | H - 11744 | H - 12000 |
| Diagnostic fixed frame | H - 12080 | H - 12336 |
| After dynamic allocation | H - 12592 | H - 12848 |
| Formatter adapter | H - 12656 | H - 12912 |
| Formatter wrapper | H - 12768 | H - 13024 |

Fifteen selected spans per path account for GPR/home saves, format and thread
pointers, output descriptor/buffer, a 152-byte exception record, cookie and probe
register saves. All four caller-provided capacities fit the modeled window.
The probe also touches pages using a `GS:0x10` stack-limit value: those addresses
are **not** qualified merely by accounting for its 16-byte save area. No maximum
transitive stack depth or arbitrary exception/unwind cleanup is established.

The routine sets and clears bit 2 in a two-byte field at offset `0x17ee` from the
pointer read at `GS:0x30`. That is outside the proven stack-window storage. It
does not wipe the complete diagnostic buffer in its own body. Normal-return
window clearing therefore remains necessary, and cannot establish cleanup of
thread-relative storage, debug traps or exception machinery.

Explicit remaining callees are the formatter at `0x2968`, termination helper at
`0x2958`, invalid-argument path at `0x1058`, exception-record initialization at
`0x1f030`, exception dispatch at `0xbc90`, and fatal cookie path at `0x1160`.
Loaded-module identity and kernel storage also remain unqualified. Earlier
records retain their original scope; this extension adds no native campaign,
production signing claim, production-code change or release-gate change.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-diagnostic.py
python3 scripts/cryptography/windows_enclave_sdk_diagnostic.py PATH_TO_SAVED_VERTDLL
```

## Formatter scratch and output-helper review

The [formatter-frame record](../assurance/windows-protection-observations/sdk-formatter-20261004.json)
adds ten complete instruction ranges from the same saved file, totaling 3,030
bytes. These are the format engine, character/padding/string output helpers,
output-error helper, thread-relative error pointer, count-output enable check,
fill thunk and two fill implementation ranges. Their hashes bind this manual
frame/call review; they are not a proof of general formatting correctness.

Seven synthetic regressions pass on Linux and Windows. Separately, inspection
of the **actual saved DLL** rejects all 3,030 single-byte body mutations on both
hosts, without relying on the outer whole-file hash to reject them. Nineteen
selected direct call/tail-transfer targets are checked. Both hosts produce
identical inspection reports. No SDK instructions are executed by these tools.

The format engine pushes seven GPRs and allocates `0x280` bytes (696 bytes total
below entry RSP), plus a saved RBX in caller home space. Its scratch is 512 bytes
at post-prologue RSP + 112; a six-byte wide-character temporary and cookie follow
it. The output helpers allocate fixed 40-byte frames and restore their saved
registers without wiping those save slots. Their loops reuse the same frames.
The enclosing normal-return clearing window is still required.

| Selected RSP at diagnostic capacity 512 | Copy-result path | CallEnclave error path |
| --- | --- | --- |
| Format engine | H - 13472 | H - 13728 |
| String/padding helper | H - 13520 | H - 13776 |
| Character helper | H - 13568 | H - 13824 |
| Output-error leaf return address | H - 13576 | H - 13832 |

Eleven selected spans per path, at each of the four retry capacities, fit the
modeled window. The last row is a selected chain's low address, **not** a maximum
transitive bound for all formatter or exception paths.

The earlier record called `0x2958` a termination helper. Its complete body shows
the more precise role: it sets bit `0x20` in the output descriptor and returns
`-1`; it does not clear the buffer. The write helper can also read a four-byte
error value through the pointer returned from `GS:0x30` + `0x1500`. That storage
is not established as inside the clearing window. The fill thunk tail-jumps,
so it adds no second return address; the large-fill branch's optional RDI save
is included conservatively. Initialization with zeros is not an exit wipe.

The exception routine inspected during this pass computes a dynamic context
allocation from another runtime helper's result. It is intentionally **not**
assigned a guessed fixed size. Wide-character conversion (`0x33f4`), invalid
arguments (`0x1058`), exception dispatch (`0xbc90`), fatal cookie failure
(`0x1160`), probe page touches and kernel/interruption handling remain outside
this qualified frame subset. Loaded-module identity is still unproven.
No production code, release gate, native campaign or production claim changed.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-formatter.py
python3 scripts/cryptography/windows_enclave_sdk_formatter.py PATH_TO_SAVED_VERTDLL --mutations
```

## Wide conversion and invalid-argument context

The [conversion/context record](../assurance/windows-protection-observations/sdk-conversion-20261004.json)
binds five more complete bodies (641 bytes) in the same saved DLL: the wide
adapter, wide helper, conversion leaf, invalid-argument helper and its context
capture helper. Eight focused regressions and 641 real-body byte mutations pass
on both Linux and Windows; the saved-file reports are identical. This remains
offline, implementation-author inspection, not execution or independent review.

The conversion leaf at `0x5468` is just `mov eax, 0xc00000bb; ret` in this build.
After that failure, the wide helper writes four-byte value 42 through the
thread-relative error pointer (`GS:0x30` + `0x1500`) and returns 42. It does not
perform a successful character conversion on that branch. This is not a claim
about every Windows SDK build, and the thread-relative write is not erased by
the modeled stack window.

The adapter and helper each use a 56-byte fixed frame. The invalid-argument
helper pushes RBP and allocates `0x5e0` bytes, totaling 1,512 bytes below entry.
Its context destination is post-prologue RSP + 256. The inspected capture stores
scalar state there and performs a 512-byte `FXSAVE` at destination + 256. Those
destinations fit below the invalid-argument helper's cookie. This accounts for
the observed stores, not complete extended processor state or erasure: the
capture helper does not wipe its destination before returning.

| Selected RSP at diagnostic capacity 512 | Copy-result path | CallEnclave error path |
| --- | --- | --- |
| Wide adapter | H - 13536 | H - 13792 |
| Wide helper | H - 13600 | H - 13856 |
| Invalid argument, direct from formatter | H - 14992 | H - 15248 |
| Invalid argument, conservative wide-helper branch | H - 15120 | H - 15376 |

The wide-helper invalid branch requires a size greater than `0x7fffffff`; the
formatter's inspected calls supply 6 or 512. Its frame is nevertheless modeled
conservatively, not asserted reached by those calls. Six conversion spans and
eight spans for each selected invalid-argument entry fit the window for all
four diagnostic capacities. Unknown callee bodies are not included in that
claim.

The invalid-argument helper can call the diagnostic entry again. The previously
bound buffer routine tests thread-relative bit 2 before dynamic allocation and
formatting, so nested formatting is skipped **if that flag remains set**. This
records the cycle and guard rather than treating the graph as acyclic. It is
not proof of the guard's behavior across arbitrary exceptions or interruption.
Runtime lookup (`0x8b60`), unwind processing (`0xc320`), exception dispatch
(`0xbc90`) and fatal cookie failure (`0x1160`) still need separate treatment.
Loaded-module identity, kernel storage and maximum transitive stack depth remain
unqualified. No production code, release gates or native evidence changed.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-conversion.py
python3 scripts/cryptography/windows_enclave_sdk_conversion.py PATH_TO_SAVED_VERTDLL --mutations
```

## Runtime lookup and unwind adapters

The [runtime-adapter record](../assurance/windows-protection-observations/sdk-runtime-20261004.json)
binds nine further instruction ranges (1,718 bytes): runtime lookup, module
lookup, entry normalization, the unwind adapter, context-flag validation and
its two helpers, a module-query syscall stub and the directory-query adapter.
Eight regressions and 1,718 actual saved-body byte mutations pass on Linux and
Windows; reports from the saved DLL are identical. Eleven direct transfers are
checked. These are author-reviewed adapters, **not** a verified Windows unwinder.

The lookup uses a 72-byte fixed frame; module lookup adds 88 bytes, while its
directory adapter adds 40. The unwind adapter is a separate branch from the
invalid-argument caller, with a 136-byte frame; context validation adds 40.
The flag adapter tail-jumps to a leaf which saves RBX in caller home space:
there is no additional nested return address for that tail jump.

| Selected RSP, direct formatter-invalid path at capacity 512 | Copy-result path | CallEnclave error path |
| --- | --- | --- |
| Runtime lookup | H - 15072 | H - 15328 |
| Module lookup | H - 15168 | H - 15424 |
| Directory adapter | H - 15216 | H - 15472 |
| Unwind adapter (separate branch) | H - 15136 | H - 15392 |
| Context validator | H - 15184 | H - 15440 |

The conservative wide-helper-invalid entry shifts these by a further 128 bytes.
Eighteen selected spans per entry account for GPR saves, staged arguments and
results, module descriptors, leaf return/home areas and the known context-flags
destination. Both invalid-argument entries and all four diagnostic capacities
fit the existing modeled window. These are not bounds for deeper callees.

Lookup writes an output image base and can mutate a **non-null caller-supplied
history table**. The inspected invalid-argument caller passes null for history,
but the generic lookup body must not be described as read-only. Module lookup
reads cache globals and can call cache lock/unlock helpers, a syscall and image
directory parsing. Their external storage and concurrency behavior are not
qualified by accounting for local stack slots or pinning the syscall bytes.

Context validation can update four-byte flags at context offset `0x30`. For
the known invalid-argument caller, this destination lies in its reviewed stack
context. Extended-context metadata reads have conditional paths; this review
does not establish bounds for arbitrary context pointers or malformed metadata.
The leaf can also write an optional result pointer; the reviewed validator
passes null. Saved registers are restored, not erased by these helpers.

Remaining boundaries include module-cache locking (`0x9650`, `0x96e0`), directory
parsing (`0xdf94`), the actual unwind engine (`0xcf78`), exception dispatch
(`0xbc90`) and fatal cookie failure (`0x1160`). Kernel storage, loaded-module
identity, arbitrary unwinding and maximum transitive depth remain unqualified.
Production code, existing native records and release gates are unchanged.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-runtime.py
python3 scripts/cryptography/windows_enclave_sdk_runtime.py PATH_TO_SAVED_VERTDLL --mutations
```

## Directory-result and image-header frames

The [directory record](../assurance/windows-protection-observations/sdk-directory-20261004.json)
extends the same saved-file review through the directory-result wrapper, parser,
header finder, RVA translator and section finder: five complete ranges, 668
bytes and four direct calls. Seven focused regressions and 668 actual-body byte
mutations pass on both Linux and Windows; the saved-file inspection reports
match. Hash mutations establish drift detection, not semantic correctness.
The frame and storage interpretation below is an implementation-author review.

The result wrapper pushes RBX and reserves 64 bytes (72 total). Its parser
pushes three registers and reserves 32 bytes (56 total), saving three other
registers in caller home space. Header finding adds a separate 72-byte frame;
the alternative RVA-translation call adds 40 bytes and calls a section-finder
leaf with no stack adjustment, stores or calls. These sibling calls must not
be added together as though nested.

| Selected RSP, direct formatter-invalid path at capacity 512 | Copy-result path | CallEnclave error path |
| --- | --- | --- |
| Directory-result wrapper | H - 15296 | H - 15552 |
| Directory parser | H - 15360 | H - 15616 |
| Header finder | H - 15440 | H - 15696 |
| RVA translator (alternative) | H - 15408 | H - 15664 |
| Section leaf entry | H - 15416 | H - 15672 |

The wide-helper-invalid origin shifts these by 128 further bytes. Eleven
selected spans per origin account for pushes, home saves, outgoing arguments,
result pointers and header status/offset/pointer locals. The known caller's
NT-header destination is its own home slot, and the directory-result pointer
is the wrapper's local slot. All selected spans fit the modeled clearing
window for capacities 128, 256, 384 and 512. The helpers restore registers
without clearing the slots; this remains dependent on enclosing cleanup.

This is **not an arbitrary-image bounds proof**. The parser invokes the header
finder with flag 1 and size 0, disabling that helper's optional size checks.
The call setup is explicitly byte-bound and mutation-tested. Header finding
still checks signatures and selected offset conditions; that does not make
untrusted pointers or malformed PE metadata safe. Directory sizes and returned
pointers are written through supplied destinations. Image/section reads and
exception-handler behavior are outside this selected stack-slot conclusion.

The directory branch's ordinary fixed frames are now accounted for; cache
locking/slow paths, the unwind engine, exception dispatch and fatal-cookie
paths remain separate unfinished work. No SDK code was executed by these
inspectors, no native enclave run was added, and loaded-module identity,
maximum transitive depth and whole-image cleanup remain unqualified.
Production cryptography and release gates are unchanged.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-directory.py
python3 scripts/cryptography/windows_enclave_sdk_directory.py PATH_TO_SAVED_VERTDLL --mutations
```

## Cache-lock frames and exceptional stop boundary

The [locking record](../assurance/windows-protection-observations/sdk-locking-20261004.json)
binds nine additional ranges (1,216 bytes) and eleven direct transfers: lock,
unlock, slow acquisition, queue linking, waking, backoff, two syscall stubs and
status raising. Eight focused regressions and 1,216 actual-body byte mutations
pass on Linux and Windows; the saved-file reports match. As before, hashing
detects drift in manually reviewed code; it does not prove concurrency safety.

The module lookup passes the saved image's shared lock at RVA `0x28d68`.
Lock and unlock each reserve 40 bytes. Slow acquisition adds three pushes and
80 bytes of local space (104 total), with a 48-byte wait node at current RSP+32.
Backoff is a leaf but writes a counter in caller home space and updates its
supplied counter. The queue helper is also a leaf; its tail jump to the waking
helper reuses the existing return address. Waking adds 40 bytes, saves RBX in
home space and pushes RDI. A direct unlock-to-wake call is a separate path.

| Selected RSP, direct formatter-invalid path at capacity 512 | Copy-result path | CallEnclave error path |
| --- | --- | --- |
| Lock/unlock | H - 15216 | H - 15472 |
| Slow acquisition | H - 15328 | H - 15584 |
| Wake reached through queue tail jump | H - 15376 | H - 15632 |
| Its syscall return address | H - 15384 | H - 15640 |
| Wake called directly from unlock | H - 15264 | H - 15520 |

The wide-helper-invalid origin shifts these by 128 further bytes. Thirteen
selected spans per origin cover saved registers, the wait node, counters and
leaf/syscall return slots, for all four diagnostic capacities. The syscall
stubs have no software stack adjustment; their kernel storage is not modeled.

Slow acquisition **publishes a tagged pointer to its stack wait node** through
the shared lock state. Queue/wake code follows and updates linked nodes, which
can belong to other threads. This review does not prove node reclamation,
external-storage erasure, lock correctness or progress under contention. The
node is initially zeroed and then populated; that is not an exit wipe. Saved
registers are restored without erasing their slots. Reads of thread/system
data, pauses, timing instructions and wait/signal calls are not execution-tested
by the Python inspectors.

Invalid unlock state can call the status raiser (`0xbeb0`). That routine has a
1,432-byte fixed frame and calls itself on one path, adding another 1,440 bytes
including the return address each time. Only the **first** frame is accounted
for; the result explicitly leaves transitive depth unknown. Its context/raise
helper (`0x1b50`), recursion, exceptions and interruption cleanup are not
qualified. No finite exceptional bound is inferred from the ordinary frames.

The ordinary cache-lock frames are now accounted for. The actual unwind engine,
exception/fatal paths, loaded-module identity and broader whole-image cleanup
remain unfinished. No production cryptography, native campaign or release gate
changed in this review.

```sh
python3 scripts/cryptography/test-windows-enclave-sdk-locking.py
python3 scripts/cryptography/windows_enclave_sdk_locking.py PATH_TO_SAVED_VERTDLL --mutations
```

The subsequent [unwind-engine frame review](windows-enclave-sdk-unwind.md)
accounts for its fixed allocation, caller-owned flag slot and two metadata
helpers. It retains explicit decoder, exception and generic-context limitations.
