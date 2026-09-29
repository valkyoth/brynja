# Native scoped-result lifetime observations

Status: **public-vector research, not Windows strict qualification**.
Source `614f61f525947731fa89c8773ec5a021a50b723d`, 2026-09-29.
The [scoped-result design](windows-enclave-result-design.md) ran on the existing
Azure AMD EPYC 9V45 host, Windows Server 2025 build 26100.33438, with VBS/HVCI
running, Secure Boot off, vTPM ready and development test signing enabled.
Production crates, Linux guarantees and release gates are unchanged.

## What passed

All [13 native controls](../assurance/windows-protection-observations/window-result-run-exits-614f61f5.json)
matched their expected outcomes: eight normal observation records and five
deliberate failures. Each normal mode ran three calls, with and without a caught
C exception **before** Rust entry. No exception crosses Rust; the native images
use `panic=abort`, not recoverable Rust panic handling.

| Mode | Per-call lifecycle checks |
| --- | --- |
| [Success](../assurance/windows-protection-observations/window-result-success-614f61f5.json) | 40 digest comparisons, followed by rejected second export without invoking its copy callback |
| [Cancel/abandon](../assurance/windows-protection-observations/window-result-cancel-614f61f5.json) | 10 explicit cancellations with replay rejection and 10 abandoned handles cleared at scope exit |
| [Wrong token/public flag](../assurance/windows-protection-observations/window-result-wrong-token-614f61f5.json) | 10 stale-sequence and 10 missing-public-flag rejections, each terminal |
| [Copy failure](../assurance/windows-protection-observations/window-result-copy-failure-614f61f5.json) | 20 internal failed-copy simulations with valid digest comparison and replay rejection |

Across 24 normal calls: 600 checked result lifecycles and 240 successful-mode
digest comparisons. The copy-failure mode additionally compares the input digest
before returning false, but does not perform a host write. These repeat the existing
twenty public vectors; they are not 600 independent random vectors. No digest or
live result handle leaves the enclave in this native campaign.

After each scope, the full output region, exact-layout workspace and typed input
are checked clear before outer-buffer/window clearing. Native offsets above the
64 KiB payload low were input 63109 (1024 bytes), output 64133 (33 bytes), workspace
64166 (1170 bytes); all are disjoint and inside the admitted window. All sixteen
pages were observed locked before admission and after outer zero readback. Guards
were restored and host locks released before enclave termination/deletion.

## Rejected controls

The separately compiled result models that retain a consumed owner, forget the
output owner, ignore token matching or ignore the public-output flag all failed
the inner ownership check. The unchanged missing-outer-clear assembly mutant
failed its separate outer check. All five exited 1, with exact failure causes
and no success JSON. A successful outer clear could not disguise an inner failure.
No production implementation was modified to generate these test variants.

## Local verification and build identity

Six local model tests and three exact-worker tests passed. Four compiled mutants
failed both suites. A positive downstream consumer compiled, followed by 17
rejected ownership/privacy/non-escaping/non-reentrant consumers. Local tests also
cover all input lengths 0..1024, partial copy failure, wrong-instance identifiers,
future sequences, terminal cancellation, recoverable Rust unwinding and sequence
exhaustion. Those latter checks are not claimed as native enclave observations.
The previous request experiment's five local tests passed unchanged.

The five new native runner tests and prior ten guard/fourteen locking regressions
passed on Windows (29 host-side tests). Rust 1.98.1 / LLVM 22.1.8 cross-built the
first-party dependency closure with no optional crypto features; MSVC linked the
five Rust archives into six enclave images under `/std:c11 /W4 /WX`. The build
manifest's `native_executed: false` describes cross-building alone; the separate
native records document actual execution without upgrading `strict_qualified`.

All 182 source hashes in each native record match the capture commit. Native Rust
archives match the local cross-builds byte-for-byte. Compiler identity, signed
image hashes and canonical records were rechecked against the raw artifacts. Emitted worker
and campaign frames allocate 2360 and 1304 stack bytes respectively. Existing
borrowed-copy/scalar kernel erase markers remain; caller saves outside those
blocks remain a limitation, not a newly established whole-call-graph guarantee.

- Downloaded raw archive: `ea8b5c8838c2952bd822247d9addced9236129f293644d629bb52cff5e50d6c0`.
- Normal image: `42d19de59686ea692b11ae6556675a74264b6366f098bce7ba90a9e75d81eaa3`.
- Normal Rust archive: `375aedf8cb82ba6b6f82e4850c641f2ac1c0a8cf1c8548231f10b7ab3f298111`.
- Emitted assembly: `0229e77fa2cf2eccc14b2309a5a528f80350ff72e659a86e5f00d342e2ec480b`.
- Linked disassembly: `8e19ffb360e129d6d7f7991da2ee0ff2ebb04b105ba41c5470a61ec8860e36c8`.

The archive checksum matches the server. Raw artifacts, cross-builds, helpers
and review script are saved in ignored `release-reports/`, outside Cargo target.
Committed records preserve JSON values and normalize only text whitespace.
SignTool's compatibility warning exit 2 for every image and failed wrapper exit 1
are preserved; after inspection only development research proceeded. The ephemeral
signing key/certificate was removed. [Cleanup](../assurance/windows-protection-observations/window-result-cleanup-614f61f5.json)
found zero probe processes and temporary certificates. No dump was requested.

## Remaining boundary

This establishes the scoped model's lifecycle inside the tested worker, not
authenticated host handles. The fixed diagnostic identity resets with each
worker campaign and is not production instance authority. Host-wire integration
needs enclave-established instance identity and scope-bound routing; persistent
results would need separate storage/residency ownership. Confidential ingress,
exact worker/runtime/TLS dump coverage, concurrency, production signing and
platform qualification remain open. Windows strict stays unsupported.
