# Portable AES native ARM observations

The 2026-11-08 collection used an operator-supplied AWS machine reporting two
ARM Neoverse-V2 r0p1 cores, one thread per core, Linux 7.0.0-1014-aws and glibc
2.43. Provider identity is not independently attested. No accelerated AES API
was enabled: consumers resolve only the reviewed portable package graph.

[`aws-aarch64.json`](aws-aarch64.json) records the transferred source archive
identities, host, dates, timing statistics, binary identities and artifact
hashes. The candidate was an uncommitted working tree based on the recorded
commit, **not** that commit's clean tree. The current record is the versioned
0.27.2 candidate collection. The earlier pre-version collection is preserved
unchanged in [`aws-aarch64-pre-version.json`](aws-aarch64-pre-version.json),
along with its original local bundles. Later local edits are not automatically
covered.

Commands executed on the native host, separately for Rust 1.90.0 and 1.99.1:

```sh
python3 scripts/aes/check-aes-fixed-random.py --toolchain 1.90.0
python3 scripts/aes/check-aes-aarch64-native.py --toolchain 1.90.0
```

The pre-version timing invocations failed during workspace preflight, before builds
or measurements, because Ubuntu's default umask made `target` group-writable.
Both logs remain in the observations archive. The task directory was secured
and a restrictive umask selected; each compiler then completed its **first
measurement** with zero alarms and zero inconclusive contrasts. No measured
alarm was discarded, cropped or retried. Collection was sequential on logical
CPU 0; host CPU isolation, fixed frequency and disabled boost are not claimed.

After the facade/consumer version and packaged README changes, a new source
archive was collected in a separate private directory. Both compiler endpoints
again completed exactly one candidate measurement, with zero alarms and zero
inconclusive contrasts, using the unchanged fixture, population and thresholds.
This was source-identity reconciliation, not a retry of an alarm. The original
measurements remain available and have not been relabeled as candidate passes.

Both timing outputs were independently reprocessed locally from all raw samples
and reproduced the remote summaries exactly. Both native correctness runs
passed all four direct/facade, abort/unwind configurations. Together they cover
144 known-answer operations, 576 normal lifecycle cases and 192 caller unwinds.
The sixteen executables and their symbol/disassembly files were copied back;
all 48 artifact hashes match the original logs. Collection alone is **not**
emitted-code review; the separate offline review registration checks the
candidate bundle against its existing instruction policies and mutation suite.

Large source, sample and ELF bundles remain local under the `target/` paths in
the JSON record, not in Git or `verification/results.json`. Preserve those
bundles before cleaning `target`; a digest alone cannot reproduce an uncommitted
snapshot. The remote copy also remains in the dedicated collection directory.
This record is an unauthenticated developer observation, not a signed receipt.

Future explicit runner entry points are:

```sh
brynja-verify run aes packaged-fixed-random-arm-msrv
brynja-verify run aes packaged-fixed-random-arm-current
brynja-verify run aes packaged-arm-native-msrv
brynja-verify run aes packaged-arm-native-current
```

They require a native Linux AArch64 host. This collection invoked the underlying
scripts directly, so it has **not** been inserted as runner-owned attempts or
current passes in the local result index. Do not rerun timing merely to populate
that index. No release-gate coupling is added.

Still separate: the recorded offline instruction/control/address/cleanup review,
other compiler/profile configurations, hardware attestation, physical fault
and power/EM protection, and full compiler-spill/register erasure.
