# Native Rust-owned Windows host observations

Status: **research only; Windows strict support remains unavailable**. This
records execution of the [host binding](windows-enclave-native-host-design.md),
not production qualification, independent review or a confidential channel.

The campaign ran on the existing Azure Windows Server 2025 VBS development host
on 2026-09-29 at 11:27 UTC, using host source
`ac1bddb8958c8003d8007bf99ec6e38efc324dfd`. Rust 1.98.1 cross-built three host
archives for x86-64 Windows; native MSVC 14.44.35207 linked them with warnings
treated as errors. The unchanged signed enclave image from `53ec2efe` was reused:
SHA-256 `4bb0192b984a45e101e7031fdab8bc9e48667d300397b5344a37d52282288ba5`.
No new enclave certificate, signing operation or system configuration change was
needed. The existing development-signing limitations remain.

The [source-bound observation](../assurance/windows-protection-observations/native-host-ac1bddb8.json)
contains 14 host source hashes, three Rust archive hashes, seven executable hashes,
compiler identity, exact counter records and the raw archive hash. Its nested
`build.native_executed: false` describes cross-compilation; the enclosing
`host_native_executed: true` describes the subsequent Windows campaign.

## Observed results

| Native executable | Result |
| --- | --- |
| Normal | 20 independent public SHA-256 vectors each exported, cancelled and subjected to real platform copy-out rejection; 60 operations. Three further fault cases quarantined without committing output, and attempted reuse made no additional native call. Five created instances were deleted, including the unused Drop-owned instance; no retained owner or cleanup error. |
| Fail after create | Constructor rejected; one created instance deleted before return, no native operation. |
| Fail after image load | Same complete startup cleanup. |
| Fail after initialization | Same complete startup cleanup, including termination. |
| Synthetic deletion failure | After 60 operations, explicit close failed and Drop retried. One instance remained recorded as retained, zero deletions were claimed and two cleanup failures were recorded. The child exited. This injects failure before deletion; it is not a naturally occurring Windows deletion failure. |
| Early-output Rust mutant | Rejected at the uncertain-reply test with result 21 / exit 97. Three instances created and deleted, 62 native calls. |
| Ignored-cleanup Rust mutant | Rejected at the withheld-cleanup test with result 21 / exit 97. Four instances created and deleted, 63 native calls. |

The three normal fault cases deny the first exchange, discard a successful native
reply, or withhold outer-cleanup confirmation. They test the distinction between
actual native completion and what the host ledger is permitted to accept. Copy-out
failure instead uses an invalid destination in the actual enclave copy operation;
it is terminal for that result but leaves the correctly completed session reusable.

All expected failures require exact status, counters and exit code. A crash,
timeout, different error, retained normal instance or missing cleanup cannot count
as success. The two Rust mutants execute the real bound host against the unchanged
enclave, not just a mocked transport.

## Local regression checks

- Existing host model suite: 10 Rust tests at O0/O2, six compiled mutants at both
  levels, 24 ownership/privacy rejections, saved native transcript replay and the
  actual paired Rust worker.
- New bridge: two tests at O0/O2; early-commit and ignored-cleanup mutants rejected
  at both levels. Result validation rejects 126 changed/type-confused counter
  fields plus seven extra-field records.
- Existing scoped-wire suites: two model/compiler tests and five native-driver
  validation tests passed.
- Script inventory, documentation links, first-party crypto boundary, unsafe
  policy and whitespace checks passed. No full release sweep was run.

Raw binaries, archives, generated sources, stdout/stderr and build helpers are
preserved outside Cargo `target/` in the local ignored recovery directory
`release-reports/windows-azure-replacement-2026-09-29/`. The native archive hash is
`80e2e00f51f637848347b1e9a17e4ca2bf7588500116f688185cec8aa34bc69c`.
The source-binding review checked every recorded source against both the capture
commit and current bytes, and every executable/archive against its preserved file.

## Remaining boundaries

This completes a tested **research host ownership/lifecycle binding**, not the
Windows release. Confidential attested ingress, protected persistent outputs,
complete runtime/TLS/caller-frame and dump coverage, production signing, wider
algorithm integration and platform qualification remain unresolved. All test
input, request copies and host staging here are public data. The containing
process is not treated as trustworthy merely because Rust field privacy is used.
The old signed enclave, production cryptography, Linux behavior and release gates
were not changed.
