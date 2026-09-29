# Native scoped-result wire observations

Status: **public-vector research, not Windows strict qualification**.
Source `53ec2efe1b39d70619b1f0b530f5d1865fc421f8`, 2026-09-29.
The [wire design](windows-enclave-wire-design.md) ran on the same Azure AMD
EPYC 9V45 / Windows Server 2025 build 26100.33438 development host used by the
[previous scoped-result experiment](windows-enclave-result-results.md).
Production cryptography, Linux guarantees and release gates are unchanged.

## Native outcomes

All [22 controls](../assurance/windows-protection-observations/window-wire-run-exits-53ec2efe.json)
matched their expected outcomes: thirteen normal records and nine deliberately
failing controls. Each normal scenario ran three calls. The cross-instance scenario
also created, exercised and destroyed a donor enclave before creating the receiving
instance: **42 normal calls total, including the three donor calls**.

| Scenario | Observed outcome |
| --- | --- |
| [Publish](../assurance/windows-protection-observations/window-wire-publish-53ec2efe.json) | Public SHA-256 matches for lengths 0, 56 and 1024; each second export is spent |
| [Mutate](../assurance/windows-protection-observations/window-wire-mutate-53ec2efe.json) | Replacing the original header/message after the offer does not change the snapshot digest |
| [Cancel](../assurance/windows-protection-observations/window-wire-cancel-53ec2efe.json) | No digest export; second cancellation is spent |
| [Foreign identity](../assurance/windows-protection-observations/window-wire-foreign-53ec2efe.json) | Changed identity rejects and consumes the result |
| [Previous scope](../assurance/windows-protection-observations/window-wire-stale-53ec2efe.json) | First call succeeds; later calls reject the preceding call's token |
| [Different instance](../assurance/windows-protection-observations/window-wire-cross-instance-53ec2efe.json) | A fresh instance rejects the destroyed donor's token, including when epochs and slots match |
| [Missing public flag](../assurance/windows-protection-observations/window-wire-no-public-53ec2efe.json) / [bad slot](../assurance/windows-protection-observations/window-wire-bad-slot-53ec2efe.json) | Rejected, terminal, no host digest write |
| [Bad version](../assurance/windows-protection-observations/window-wire-bad-version-53ec2efe.json) / [bad source](../assurance/windows-protection-observations/window-wire-bad-source-53ec2efe.json) | No result exchange; local storage clears |
| [Bad destination](../assurance/windows-protection-observations/window-wire-bad-destination-53ec2efe.json) | Actual platform copy-out fails; result is consumed and replay rejects |
| [First callback denied](../assurance/windows-protection-observations/window-wire-deny-first-53ec2efe.json) / [second denied](../assurance/windows-protection-observations/window-wire-deny-second-53ec2efe.json) | Scoped owner clears; no implicit retry or fallback |

These are small deterministic public vectors, not a new independent random-vector
campaign. Thirteen public outputs were compared with host `hashlib` SHA-256,
including donor outputs. Thirty second commands reported spent. The remaining
calls deliberately stop before, or interrupt, the two-command exchange.

The instance namespace remained stable across each enclave's calls and epochs
advanced 1, 2, 3. The donor and receiving namespaces differed. This demonstrates
the tested routing, not collision impossibility, authenticated identity, attestation
or authorization against a malicious host. All token values in the records are
public metadata. Native entropy-quality assessment was not performed.

For every normal call, input-plus-command (1136 bytes), output (32 bytes) and
workspace (1170 bytes) were disjoint inside the 64 KiB window, at offsets 62998,
64134 and 64166 respectively. Owned bytes were checked clear before outer-window
clearing. All sixteen pages were observed locked at admission and after outer
zero readback; guards were restored and the host lock released before teardown.
Partial host-copy rollback is not promised. No Rust unwind was injected in these
`panic=abort` images, and no fatal termination is counted as cleanup success.

## Negative controls and local checks

Five Rust controls ignored identity, ignored epoch, retained a consumed result,
forgot the result owner, or omitted wire-buffer clearing. Each was rejected for
its expected protocol/cleanup failure. A separate omitted outer-clear assembly
control failed the outer cleanup check. Three C admission controls forced entropy
failure, an all-zero identity, or an exhausted epoch. Each rejected before producing
a live worker window. These three native runs test the first rejection; permanent
failure latching and repeated exhaustion are covered by the compiled local C test.

All nine failing controls exited 1 with their specific rejection reason and no
success JSON. There were no native child crashes or timeouts. The raw error logs
are retained alongside the normal records rather than relabeled as successful
qualification evidence.

Five local Rust tests passed, including all lengths 0..1024 and partial-copy,
callback, malformed-input and cleanup cases; five compiled Rust variants failed
the corresponding tests. The extracted actual C admission function passed its
mock-entropy campaign and rejected four state-machine mutations. Five new
host-runner tests passed locally and on Windows, alongside the previous ten
guard and fourteen lock tests. The previous five result-runner tests passed
locally unchanged. Mocks and cross-compilation are not native enclave evidence.

## Source binding and saved artifacts

All **189 source hashes** in each native record match the capture commit. The six
Rust archives match their local cross-builds byte-for-byte. Rust 1.98.1 / LLVM
22.1.8 produced the Windows x64 archives; MSVC linked ten images with
`/std:c11 /W4 /WX`. The build manifest's `native_executed: false` correctly
describes cross-building alone. Canonical native records, image/compiler hashes
and committed JSON values were separately rechecked. The emitted worker allocates
2472 stack bytes; this does not establish whole-call-graph register/spill erasure.

- Raw archive: `e308ab08a180f0f134ce2c0bbb3362080c609f597fcb4b437c1b2618ece24d00`.
- Normal image: `4bb0192b984a45e101e7031fdab8bc9e48667d300397b5344a37d52282288ba5`.
- Normal Rust archive: `8b9a56954c8fd7dbae0a90d234c419184ee182dfaf9ef5f315dac62051e79311`.
- Emitted assembly: `c2369cd37988a1cfee00c9e5ecad13a34fa0d650064a80236d93360ef0ad55c1`.
- Linked disassembly: `fee2aeb3b022dba533ba5154746ba7a30c73003d31e97eeebf9e8910cd171226`.

The archive checksum matches the server. Raw artifacts, build/sign/run helpers,
cross-builds and the review script are saved under ignored `release-reports/`,
outside Cargo target. SignTool's compatibility-warning exit 2 on every image and
wrapper exit 1 remain recorded; only development research proceeded after
inspection. The temporary signing key/certificate was removed.
[Cleanup](../assurance/windows-protection-observations/window-wire-cleanup-53ec2efe.json)
found zero probe processes and temporary certificates. No dump was requested.

## Still required

The scoped wire model is connected, but no production host-side session API or
authenticated confidential channel is implemented. Persistent results would need
separate residency/ownership design. Exact-worker dump coverage, runtime/TLS and
caller-frame boundaries, concurrency, production signing and platform qualification
remain open. Diagnostic exports and callbacks have not become shipping APIs.
**Windows strict stays unsupported.**
