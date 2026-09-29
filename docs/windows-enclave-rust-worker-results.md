# Native Rust-in-window observations

Status: **synthetic ABI/lifecycle observations only; not a strict backend**.
No cryptographic operation or secret input was used. Windows strict constructors
still return unsupported. Production Rust, release gates and Linux guarantees
are unchanged.

Source: `d1243bb6469284f590dbeb8391c17bbfa2a8e21c`, 2026-09-29.
The [fixed-worker design](windows-enclave-rust-worker-design.md) ran on the same
Azure x86-64 development host as the depth experiment: AMD EPYC 9V45, Windows
Server 2025 10.0.26100.33438, VBS/HVCI running, Secure Boot off, vTPM available,
test signing enabled. This remains a development configuration, not a production
deployment baseline.

## What actually ran

Rust 1.98.1 / LLVM 22.1.8 on Linux cross-compiled the public worker into a Windows
x64 COFF object. The native MSVC build linked that exact object into the C/assembly
enclave scaffold. Rust was not installed on the Windows host, and no ordinary
Windows Rust standard-library runtime was linked into the enclave.

Every mode used the same fixed 1024-byte Rust local marker and returned a four-word
C-layout diagnostic structure. Its native address was consistently 64352 bytes
above payload low, leaving the entire marker inside the 65536-byte locked window.
C and Rust size/offset checks passed; repeated native calls additionally exercised
the aggregate-return ABI. These facts do not qualify arbitrary Rust values or FFI.

| Mode | Rust observation | Enclosing window observation |
| --- | --- | --- |
| [Success](../assurance/windows-protection-observations/window-rust-success-d1243bb6.json) | Status 1, 1024 marker bytes written, complete local clearing | Complete payload zero readback before unlock; boundary restoration and teardown |
| [Cancellation](../assurance/windows-protection-observations/window-rust-cancel-d1243bb6.json) | Status 2, 512 bytes written, complete local clearing | Same successful outer cleanup |
| [Pre-work rejection](../assurance/windows-protection-observations/window-rust-reject-d1243bb6.json) | Status 3, no marker writes, zero local readback | Same successful outer cleanup |
| [Operation error](../assurance/windows-protection-observations/window-rust-error-d1243bb6.json) | Status 4 after 1024 bytes written, complete local clearing | Same successful outer cleanup |
| Compiled missing-local-clear mutant, success/cancellation/error modes | Status 0 and failed local zero check; correct mode-specific write count | Outer payload clearing still succeeds; it cannot disguise failed local cleanup |
| Missing outer clear | Runner rejects execution/cleanup outcome | No success record |
| Wrong Rust status or deliberately reversed normal/mutant expectations | Runner rejects Rust outcome/local clearing | No success record |

Each of the four normal modes and three local-clear-mutant modes ran both with
and without an exact caught C exception **before** Rust entry. Each ran three
calls per enclave: 24 normal calls and 18 correctly detected mutant calls.
There was no foreign exception crossing Rust, no Rust panic experiment and no
claim of Rust unwind recovery. The `c_exception_before` field deliberately names
this limit; `rust_unwind_qualified` remains false in every record.

All [eighteen runner outcomes](../assurance/windows-protection-observations/window-rust-run-exits-d1243bb6.json)
matched expectations: fourteen observation records and four failures. Expected
mutant detection is not approval to process secrets with the mutant. The sixteen
payload pages were observed valid/locked before admission and again after full
outer clearing on every successful observation call.

## Compiler and artifact review

The [build record](../assurance/windows-protection-observations/window-rust-build-d1243bb6.txt)
preserves exact Rust and native commands, including `panic=abort`, optimization
level 2, forced unwind tables, and `/std:c11 /W4 /WX`. An initial build omitted
C11 mode and failed to compile the static assertions. The corrected command
retained those assertions; the failed build log remains in the raw archive.

The [Rust object symbol table](../assurance/windows-protection-observations/window-rust-object-symbols-d1243bb6.txt)
has one undefined external, `memset`, and no nonempty data/BSS or TLS section.
The final image imports only the enclave `ucrtbase_enclave.dll` and `vertdll.dll`.
The [emitted worker](../assurance/windows-protection-observations/window-rust-frame-d1243bb6.txt)
reserves 1056 bytes and saves five nonvolatile registers; it calls `memset`, retains
marker writes, local zeroing and readback, then restores its frame. This is not a
register-erasure proof or a bound on the complete CRT/exception call graph.
Unwind metadata exists, but the Rust object was built with aborting panic policy.

Eight new Python tests passed locally, including real compilation/execution of
three Rust unit tests and two independently compiled mutants that fail the
intended clearing/outcome test. Seven orchestration tests passed on Windows;
the compiler-driving eighth test ran locally, not on the Rust-free Windows host.
The existing ten guard and fourteen lock tests also passed natively. The Python
mock cases establish validation durability, not additional native measurements.

All sixteen source hashes in all fourteen records match the capture commit.
Their supplied object hashes match both the original cross-compiled objects and
downloaded Windows copies. Compiler identity is recorded as a Linux host with
Windows target, not misreported as a Windows-hosted Rust compiler. Normal object
SHA-256: `6f21357036dedf617bbd1f6b992e47457d579e0fc8c2b4e90d6d47d43b01d58b`.

Signed image SHA-256:

- Normal: `4685e1f418eac2c9cfeac9dcffe0093c5822ce4e2c901073efa4aac5f137e08e`.
- Missing local clear: `2d2acc75de946a78fcc342ec7b521f1d17019342557da63f069ed6134cc42e70`.
- Wrong result: `871b327fd7ea1c51684320744fd6bd080eb530bb15d5c38c20c3862e8c17cdbf`.
- Missing outer clear: `3de106392818b0cabc00bb6ab1096190615ed93ddaff1fb779c6b5f10017dee1`.

Raw archive SHA-256, identical remotely and after download:
`958d655336ca9e6a6c4b0bbc144b5932a2177166c939d2a3b02c8ea71162e0e1`.
Raw linked disassembly SHA-256:
`c0e602de872c3d9c4fddbe54331281d5a66a3d30589aefd90c3269498965a185`.
Full images/objects, LLVM IR/assembly, helpers and raw logs remain in ignored
`release-reports/`, outside Cargo target. Committed records normalize line endings
and trailing whitespace; only the first-party emitted worker is reproduced.

[Signing observations](../assurance/windows-protection-observations/window-rust-sign-observation-d1243bb6.txt)
retain compatibility-warning exit 2 for each image and failed wrapper exit 1.
Images were deliberately used only for development experiments after warning
review. The ephemeral non-exportable machine-store signing key/certificate was
removed, no trust root was added, and [cleanup](../assurance/windows-protection-observations/window-rust-cleanup-d1243bb6.json)
found zero remaining probe processes or temporary signing certificates. No dump
was requested or downloaded.

## Next boundary

This establishes a narrow, abort-on-panic, noncryptographic Rust operation inside
the locked window. It does not establish full TLS/runtime/register cleanup,
cryptographic constant-time behavior, protected key/result ownership, input-copy
protocols, concurrency, production signing, exact-worker-layout dump exclusion
or supported OS/compiler baselines. Next is a bounded operation adapter using
existing first-party Rust implementation code with public vectors, accompanied
by call-graph/import/frame review—not activation of the strict facade.

That subsequent [public SHA-256 experiment](windows-enclave-sha256-results.md)
now runs the existing portable implementation successfully. It retains the
distinction between ordinary public data and protected secret processing.
