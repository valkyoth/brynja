# Native public-request enclave observations

Status: **OBSERVATIONS_ONLY — not Windows strict qualification**.
Source `334180d9e44d99c5d2b625084fdd628994ed3563`, 2026-09-29.
The [request design](windows-enclave-request-design.md) ran on the existing Azure
AMD EPYC 9V45 development host: Windows Server 2025 build 26100.33438,
VBS/HVCI running, Secure Boot off, vTPM ready, test signing enabled.
No confidential input was used, no production implementation changed, and Windows
strict remains unsupported. Release gates and Linux guarantees are unchanged.

## Native outcomes

Eleven scenarios each completed three calls (33 total). Every successful worker
return reported restriction enabled, complete workspace/snapshot/output clearing,
and all sixteen window pages locked before admission and after outer clearing.
Reported storage is disjoint and within the 64 KiB payload: output at offset
63024 (32 bytes), snapshot at 63056 (1072 bytes), workspace at 64142 (1170 bytes).

| Scenario | Observed outcome |
| --- | --- |
| [Publish](../assurance/windows-protection-observations/window-request-publish-334180d9.json) | Public messages of 0, 56 and 1024 bytes match Python hashlib; output canaries unchanged |
| [Post-copy host mutation](../assurance/windows-protection-observations/window-request-mutate-334180d9.json) | Changing host length and payload does not change the private snapshot's digest |
| [Discard](../assurance/windows-protection-observations/window-request-discard-334180d9.json) | Digest remains internal and is cleared; host destination unchanged |
| Bad version, excessive length, absent public flag, overflowing destination | Status 10; rejected before hashing/export |
| [Unreadable source](../assurance/windows-protection-observations/window-request-bad-source-334180d9.json) | Copy-in rejection, status 11; no post-copy callback |
| [Unwritable destination](../assurance/windows-protection-observations/window-request-bad-destination-334180d9.json) | Copy-out rejection, status 12; internal storage clears |
| [Denied snapshot hook](../assurance/windows-protection-observations/window-request-hook-deny-334180d9.json) | Status 13; no hashing/export |
| [Overlapping public destination](../assurance/windows-protection-observations/window-request-overlap-334180d9.json) | Output overwrites host wire payload correctly without changing private input |

The copy API failure observations are not a guarantee of transactional host
output. A local test explicitly models a failed copy that writes a prefix. Only
public output is permitted; no secret declassification authority is established.
Likewise, one snapshot avoids later rereads, but does not make the initial copy
atomic against a concurrently modifying host.

## Negative controls and unexpected termination code

Four mutated images were rejected: reread the source after its host mutation,
omit snapshot clearing, omit the public-output flag check, or omit outer clearing.
The first three fail the exact request/cleanup check, and the fourth fails the
separate outer-window check. Each returns runner exit 1 and emits no success JSON.
The [initial outcome list](../assurance/windows-protection-observations/window-request-run-exits-334180d9.json)
contains eleven normal scenarios plus these four mutations.

The fifth mutant replaces the explicit copy-in API with a raw host `memcpy`.
Its child terminated with **0xc0000409 (fail-fast)**, not the anticipated
0xc0000005 access violation. Therefore the initial orchestration correctly
[stopped on an unexpected cause](../assurance/windows-protection-observations/window-request-run-stderr-334180d9.txt).
That failed run is preserved, not relabeled as an all-green run.

A separate confirmation invoked the same image for publish and discard. Both
[terminated with the same code](../assurance/windows-protection-observations/window-request-raw-control-exits-334180d9.json),
without success JSON; the exact stderr streams are retained. This distinguishes
observed raw-read fail-fast from the normal copy-API path. It is **not** proof of
the precise internal exception path, successful fatal-exit cleanup or continued
operation after a crash. No restriction was relaxed to make the control run.

## Build, tests and evidence integrity

Rust 1.98.1 / LLVM 22.1.8 cross-compiled the three first-party crates and request
worker with no optional crypto features. MSVC linked six images under
`/std:c11 /W4 /WX`; actual imports include EnclaveCopyIntoEnclave,
EnclaveCopyOutOfEnclave and EnclaveRestrictContainingProcessAccess. The DLL imports
remain `ucrtbase_enclave.dll` and `vertdll.dll`, not an ordinary Rust std runtime.
The emitted worker allocates 2368 stack bytes and the operation helper 96 bytes.
Owned-memory clearing and existing borrowed-copy/scalar kernel erase markers
remain present. Compiler saves/caller frames outside those blocks still exist;
this is not a new whole-call-graph register-clearing qualification.

All five new local Python tests passed, including actual compilation/execution of
five Rust tests and three rejected compiled mutants. The Rust campaign compares
every allowed length (0..1024) and covers malformed requests, partial copy failure,
discard and cleanup. The four non-compiler Python tests passed on Windows, as did
the prior ten guard and fourteen locking regressions (28 native host-side tests).
Mocks and local comparisons are not counted as native enclave measurements.

All 184 source bindings in each of the eleven native records match the capture
commit. Four native Rust archives match the local cross-build byte-for-byte;
compiler identity, signed-image hashes and canonical record contents were checked.

- Raw archive: `ba428b316700b37f8065248d700b336dd381450bc26f64b49b1958017071ed28`.
- Normal image: `44fcf89f020a56f377e75cf3e306075e62512d07b996d482b56932eda0a2703e`.
- Normal Rust archive: `46d34f01e5239f02a915681f5221f97d3f18ddea4c40e0907e80dc080e494aa4`.
- Emitted assembly: `c0a52648ad1cf93d67e3850f4f5d5d18b578b479edd17afd2ba503a68737c6e3`.
- Linked disassembly: `8b63f7a79eee641d650e2fa7191b58e9ab48969663fb574757020231ffbf140b`.

The local archive checksum matches the server. Raw files, build/run helpers,
cross-build assembly/IR and review script are saved under ignored
`release-reports/windows-azure-replacement-2026-09-29/`, outside Cargo target.
Committed JSON preserves values; text only normalizes line endings/whitespace.

[Signing](../assurance/windows-protection-observations/window-request-sign-stderr-334180d9.txt)
retains the compatibility warning (SignTool exit 2 for all six images and failed
wrapper exit 1). After inspection, only development research proceeded. The
ephemeral machine-store signing certificate/private key was removed; no trust root
was installed. [Cleanup](../assurance/windows-protection-observations/window-request-cleanup-334180d9.json)
found zero probe processes and zero temporary certificates. No dump was requested.

## Still required

This finishes a bounded **public** request/copy experiment, not secret ingress or
a production ABI. Authenticated confidential ingress, result-handle lifetimes,
exact worker/runtime/TLS dump coverage, concurrency, production signing and
supported-platform qualification remain separate work. Existing diagnostic
exports and a caller-supplied public-output flag must not be mistaken for those
controls. Windows strict stays unsupported until its required contract is met.
