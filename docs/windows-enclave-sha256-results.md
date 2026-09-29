# Native public SHA-256 enclave observations

Status: **public-vector functional/lifecycle observations only, not Windows
strict qualification**. Existing production implementations and release gates
are unchanged; Windows strict remains unsupported.

Source: `c18b8d7876a4476f5bdbf68ff74f810578832986`, 2026-09-29.
The [experiment design](windows-enclave-sha256-design.md) ran on the same Azure
AMD EPYC 9V45 development host: Windows Server 2025 build 26100.33438,
VBS/HVCI running, Secure Boot off, vTPM ready and test signing enabled.

## Native results

All [18 controls](../assurance/windows-protection-observations/window-sha256-run-exits-c18b8d78.json)
matched their expected outcomes. Eight normal-mode records contain 24 calls;
six missing-local-clear control records contain 18 calls. Each record includes
three repetitions, with exact mode, page-lock, guard, cleanup and teardown checks.

| Mode | Required comparisons per call | Observation |
| --- | --- | --- |
| [Success](../assurance/windows-protection-observations/window-sha256-success-c18b8d78.json) | 40 | Twenty public vectors match through both APIs; local and outer clearing pass |
| [Synthetic cancellation](../assurance/windows-protection-observations/window-sha256-cancel-c18b8d78.json) | 20 | Stops after ten messages; local and outer clearing pass |
| [Pre-work rejection](../assurance/windows-protection-observations/window-sha256-reject-c18b8d78.json) | 0 | No hashing; local and outer clearing pass |
| [Post-work error](../assurance/windows-protection-observations/window-sha256-error-c18b8d78.json) | 40 | Reports the synthetic error after hashing; local and outer clearing pass |

Each mode ran with and without the caught C exception **before** Rust entry.
Across these normal-image calls, 600 digest comparisons passed. These are repeated
checks of twenty fixed messages, not 600 independent vectors. No exception crosses
the Rust ABI, and Rust panic recovery was not tested.

The public input array was consistently 64208 bytes above the payload low address,
entirely within the locked 65536-byte window. All sixteen payload pages were
observed locked before admission and after complete outer zero readback.

The missing-local-clear image reports failed local zero readback despite successful
outer cleanup; it is detected, not qualified. Both reversed normal/mutant
expectations fail. The [corrupted-digest control](../assurance/windows-protection-observations/window-sha256-wrong-digest-c18b8d78.txt)
fails result validation, and the [missing outer clear](../assurance/windows-protection-observations/window-sha256-missing-clear-c18b8d78.txt)
fails execution/cleanup validation. All four rejected controls exit 1 and emit
no successful JSON record.

## Build and emitted-code review

Rust 1.98.1 / LLVM 22.1.8 cross-compiled from Linux to Windows x64, using the
unchanged first-party portable implementation without Cargo features. Native
MSVC linked the three distinct Rust archives into four separate enclave images.
Windows had no Rust installation. The exact Rust commands and archive identities
are retained in the [build manifest](../assurance/windows-protection-observations/window-sha256-rust-build-c18b8d78.json);
the [native build transcript](../assurance/windows-protection-observations/window-sha256-build-stdout-c18b8d78.txt)
records successful `/std:c11 /W4 /WX` compilation.

Review of the emitted Rust assembly finds these fixed allocations:

| Function | Stack subtraction | Saved general registers |
| --- | --- | --- |
| Public worker | 1512 bytes | 8 |
| Portable update | 136 bytes | 8 |
| Portable compression | 288 bytes | 8 |
| Finalization | 32 bytes | 3 |

The worker calls portable update/finalization and `memcpy`/`memset`; update and
finalization call portable compression. Explicit local zeroing and readback remain
in the emitted worker. Nonvolatile vector saves and ordinary hash-state/schedule
stack traffic are present: this is **not** an individually erasing hash kernel or
register-erasure proof. Fixed frame sizes are observations, not a complete bound
on the CRT, exception, callback or panic call graph. Panic paths call the fatal
adapter and are not successful cleanup paths.

The linked image imports only `ucrtbase_enclave.dll` and `vertdll.dll`. Their CRT
allocation, TLS, exception and synchronization imports remain visible in the
transcript; no claim is made that this experiment qualifies their lifecycle.

Nine new Python tests passed locally, including actual compilation of the
three-crate closure, three Rust unit tests and both compiled mutants rejected
by the intended tests. Eight non-compiler tests ran on Windows, along with ten
guard and fourteen lock tests (32 total). Mocked tests are validation regressions,
not additional native observations. Script inventory and documentation links pass.

## Evidence and cleanup

All 178 recorded source hashes in each of the fourteen records match the capture
commit. Native archive copies match the original cross-build byte-for-byte;
compiler identity and image bindings were also rechecked. Normal archive SHA-256:
`d632b54d83bd9285895040a876cecb21958a0f2d910a757a71c786a46d47710f`.

- Normal image: `278f5a5814fb1bc32570762efae69a2d269fb9b91c45be2b9edd5c8872b247f6`.
- Missing outer clear: `46e7389ec93242538e4efef31d1ceec6e2af984f87fe123da05f988850065432`.
- Missing local clear: `b2b4395aafb2fb3675eb11ada0261d60beff3ba7aba05791a316e0addd3b4797`.
- Wrong digest: `b7ea929c7af5d85e59dfda4d0755e480860515df07de4d6f5d3e9bf4611d30d8`.

Raw archive SHA-256 matches remotely and after download:
`2cbeb7becea17131a9303a4cf0193edfc54d50f4d828e14a277c8813b07ca29b`.
Linked disassembly SHA-256:
`2c5404b4ec901191ca3567b8b0305e1dff10fe49c87fcb28aec9de207992e94c`.
Normal emitted Rust assembly SHA-256:
`df42d0c07bca5da138b26ebb7bba4230468b5bf68a99da0ad158da089b6e663f`.
Raw images, archives, LLVM IR/assembly, helpers and logs are preserved locally in
ignored `release-reports/`, outside Cargo target. Committed text normalizes line
endings and trailing whitespace without altering JSON values.

The exact [signing stdout](../assurance/windows-protection-observations/window-sha256-sign-stdout-c18b8d78.txt)
and [stderr](../assurance/windows-protection-observations/window-sha256-sign-stderr-c18b8d78.txt)
retain compatibility warning exit 2 for all four images and the failed wrapper.
After inspection, these images were used only for development experiments, not
treated as a clean production-signing pass. The temporary machine-store signing
key and certificate were removed. [Final cleanup](../assurance/windows-protection-observations/window-sha256-cleanup-c18b8d78.json)
found no remaining probe processes or temporary signing certificates; no trust
root was added and no dump was requested.

## What remains

Real Brynja hashing now works in the tested enclave window. That does not make
ordinary SHA-256 a protected secret owner. Next is the bounded protected-operation
and input/result ownership boundary, using existing hardened Rust APIs rather
than relabeling this ordinary public-vector worker. Full worker/caller/runtime
cleanup, exact-layout dump exclusion, concurrency, production signing and supported
OS/compiler qualification remain open. Windows strict must stay unsupported until
the required protection contract is actually established.

The subsequent [scoped hardened-owner experiment](windows-enclave-hardened-owner-results.md)
now exercises the existing hardened API's separate state/input/output lifetimes
inside this window, still with public vectors and without strict activation.
