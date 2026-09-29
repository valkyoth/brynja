# Native scoped hardened-owner observations

Status: **public-vector ownership experiment, not Windows strict qualification**.
Source `0abd2f8263c7d82c261b24f4f2c1b08547c61647`, 2026-09-29.
The [design](windows-enclave-hardened-owner-design.md) ran on the existing Azure
AMD EPYC 9V45 development machine, Windows Server 2025 build 26100.33438 with
VBS/HVCI running, Secure Boot off, vTPM ready and test signing enabled.
Production crypto, release gates and the unsupported Windows strict result are
unchanged.

## What ran

The existing portable `hardened_in_place::Sha256Workspace`, typed input
initialization and secret output ownership ran inside the guarded/locked window.
No optional acceleration feature was enabled. Every message and expected digest
was public test material, not an application key or confidential message.

All [15 controls](../assurance/windows-protection-observations/window-hardened-run-exits-0abd2f82.json)
matched expectations: eight complete observation records and seven deliberate
failures. Each normal mode ran three times, both with and without a caught C
exception **before** Rust entry. No exception crosses Rust and no Rust panic
recovery is claimed.

| Mode | Per-call observation |
| --- | --- |
| [Success](../assurance/windows-protection-observations/window-hardened-success-0abd2f82.json) | 40 digest comparisons and 40 complete input/state/output lifecycles |
| [Cancellation](../assurance/windows-protection-observations/window-hardened-cancel-0abd2f82.json) | 20 actual `state.cancel()` calls after updates; workspace/input cleared |
| [Invalid output](../assurance/windows-protection-observations/window-hardened-invalid-output-0abd2f82.json) | 20 `OutputLength` rejections; complete 33-byte destination, workspace and input cleared |
| [Forgotten state](../assurance/windows-protection-observations/window-hardened-forgotten-state-0abd2f82.json) | 20 deliberately forgotten handles; independent scope guard clears workspace |

Across the 24 normal calls this totals 240 digest comparisons and 600 checked
lifecycles. These repeat the same twenty messages; they are not independent random
vectors. Successful comparisons exercise whole-message and seven-byte updates.
The secret output owner remains alive after scope exit, while the workspace is
already cleared. Output and input clearing are then checked after their respective
owners are dropped, before the enclosing buffer/window cleanup runs.

Native storage ranges were stable across all records:

| Storage | Offset above payload low | Size |
| --- | --- | --- |
| Input | 63072 | 1024 bytes |
| Output | 64096 | 33 bytes |
| Workspace | 64142 | 1170 bytes |

All are disjoint and entirely inside the 65536-byte window. All sixteen payload
pages were observed locked before admission and after the outer full-window
zero readback. The complete workspace byte check uses the source/size/alignment
restrictions documented in the design; it is not an unchecked read of an arbitrary
opaque object's padding or a read after destruction.

## Negative controls

The generated SHA-2 fixture with an early return from the actual owner `wipe`
failed in **all four modes**, including the
[forgotten-handle path](../assurance/windows-protection-observations/window-hardened-missing-owner-forgotten-state-0abd2f82.txt).
The [forgotten-output mutant](../assurance/windows-protection-observations/window-hardened-forgotten-output-0abd2f82.txt)
failed before the later buffer guard could hide the missing output Drop.
The [forced comparison-failure control](../assurance/windows-protection-observations/window-hardened-wrong-digest-0abd2f82.txt)
also failed. Unlike the earlier ordinary SHA-256 experiment's digest-byte mutant,
this control forces rejection after the comparison; it does not mutate the hash
algorithm or the digest bytes.

The seventh control omits outer assembly clearing and fails the separate outer
execution/cleanup check. Each rejected control exits 1 and produces no success
JSON. No production source was edited to create mutants; their generated-copy
mutation and hashes are in the
[build manifest](../assurance/windows-protection-observations/window-hardened-rust-build-0abd2f82.json).

## Compiler and validation scope

Rust 1.98.1 / LLVM 22.1.8 cross-compiled the first-party three-crate closure from
Linux to Windows x64. Native MSVC linked four Rust archives into five images.
The [native build](../assurance/windows-protection-observations/window-hardened-build-stdout-0abd2f82.txt)
passed `/std:c11 /W4 /WX`. No ordinary Windows Rust standard-library runtime was
linked; the final imports remain `ucrtbase_enclave.dll` and `vertdll.dll`, including
the existing CRT/TLS/exception dependencies. Those dependencies are not newly
qualified by this test.

The emitted Rust worker subtracts 2328 stack bytes; its campaign subtracts 1320.
Owner wipe, input/output volatile clearing and the borrowed-transfer boundary
remain as real calls. The existing scalar compression's opaque block retains
`BRYNJA_SCALAR_BEGIN`, `ERASE` and `END`, clears its schedule and working GPRs,
and contains no stack accesses. The copy block retains its erase marker too.
Nonvolatile saves and caller frames still exist outside those blocks. This is
an inspection of this build, not whole-call-graph register/spill erasure or proof
about asynchronous capture. Full linked disassembly, assembly and LLVM IR are
retained locally.

Six new local Python tests passed. They include real normal/mutant compilation,
three passing normal Rust tests, three rejected compiled mutants, malformed and
overlapping report regressions, failure teardown and five rejected source-layout
mutations. The five non-compiler tests plus the prior ten guard/fourteen lock
tests passed natively (29 total). The prior nine ordinary SHA-256 tests and those
24 guard/lock tests were rerun locally as regressions. These mock/unit tests are
not additional native enclave measurements.

## Evidence integrity and cleanup

All 178 source hashes in each of the eight records match the capture commit.
Native archive copies match the local build byte-for-byte; image and compiler
identity bindings were verified too. Normal Rust archive SHA-256:
`9edbe39ea7409089780c71b23063548efa9b4062803442376a5d9f22936e5fb0`.

- Normal image: `6f7597f201f48a3c6efa2f7b84542e1093cf3e7b5c9913a957f7df99276d7ce6`.
- Missing owner clear: `6bc3a6f0c496030d88532983108dc951c667037416589e8f70347b89faedc41c`.
- Forgotten output: `5a179af78aacda14c4ccb6e97bc6e44f59b41f6e9bcb84b9edc12bf3e218b6e1`.
- Forced comparison failure: `963338ec6d252aa9a2e947e7b8aaca7d5f1ca7ff4a5f4e40de75b08963d5f93b`.
- Missing outer clear: `65224b79977f7aaaa0b1c8cee621e555cbfa2caa0f62ab8ad7319d474454c366`.

Downloaded raw archive SHA-256 matches the server:
`1b56789cf84d43cc2e7d0eb758d6960d80a97a64210a65c09900fc0c4aa056ac`.
Linked disassembly SHA-256:
`9e34e45966c17fa427a0dc261fc75efc0e0db37ff386d296b92da629133daede`.
Normal emitted Rust assembly SHA-256:
`86b44aa327f460c28a93e35a32586add3f9c82522406032fda2bee2c92b30f32`.
Raw binaries, generated mutant source, helpers and logs are saved under ignored
`release-reports/`, outside Cargo target. Committed records normalize only line
endings/trailing whitespace, preserving JSON values.

[Signing stdout](../assurance/windows-protection-observations/window-hardened-sign-stdout-0abd2f82.txt)
and [stderr](../assurance/windows-protection-observations/window-hardened-sign-stderr-0abd2f82.txt)
retain compatibility-warning exit 2 for each image and failed wrapper exit 1.
After inspection the images were used only for development research. The
ephemeral machine-store signing certificate/private key was removed; no trust
root was installed. [Cleanup](../assurance/windows-protection-observations/window-hardened-cleanup-0abd2f82.json)
found zero probe processes and zero temporary certificates. No dump was requested.

## Remaining boundary

This advances from ordinary hashing to actual scoped hardened ownership inside
the tested window. It still is not a production secret-ingress/result-handle
protocol. Bounded ingress/egress and handle lifetimes, exact worker-layout dump
exclusion, runtime/TLS/caller coverage, concurrency, production signing and supported
platform qualification remain separate work. Public diagnostic comparisons and
zero predicates must not become a general interface exposing arbitrary secret
state. Keep Windows strict unsupported until the whole required contract holds.
