# v0.24.54 native observation review

Capture commit: `1f8f4e1527f9e91b1b1d26b61b8cfc95339ca835`.
Forty author-operated captures passed on four hosts, with three additional
public-consumer campaigns per host. These are functional and workload-specific
observations, not independent review, side-channel approval or FIPS validation.

The [artifact manifest](../assurance/native-observations/v0.24.54/manifest.json)
binds every public artifact, original raw SHA-256 and path-redaction count.
Absolute checkout prefixes alone were replaced with `<checkout>` where present.
No source hash, compiler, command, result, timing or capture identity was changed.
Original downloads and failed attempts are retained locally outside Cargo target.
Public derivatives were compared byte-for-byte with that declared transformation
and checked using the existing family result/source validators. Historical
artifacts remain unchanged; historical schema versions are not release labels.

## Coverage

| Host | Observed CPU | Coverage and limit |
| --- | --- | --- |
| AMD Linux | Ryzen 9 9950X3D | SHA-NI/AVX2; strict scalar, accelerated and grouped consumers |
| Intel Linux | Xeon 6975P-C | SHA-NI/AVX2; same three strict consumers |
| Arm Linux | Neoverse-V2 | Arm SHA-2/Keccak and NEON; same three strict consumers |
| Apple Silicon | M2 Pro | Arm instructions/NEON; resident scalar/keyed, batch and ParallelHash consumers |

Each host supplied hardened SHA-2, SHA-1, Keccak, KMAC, TupleHash and ParallelHash;
ordinary SHA-224/256, SHA-512-family and Keccak batch records; and a hardened
batch runtime record. The shared three-lane indexes select Intel, Arm Linux and
Apple; AMD records remain supplemental. SHA-1 and ordinary batch indexes include
all four hosts. Existing ordinary/hardened MD5 records are retained separately,
subject to their existing validators, not represented as new .54 captures.

Historical collectors actually used **Rust 1.98.1**. The additional consumer
campaigns actually used **Rust 1.99.1**. One does not qualify the other.
Linux consumer commands were `check-strict-public-consumer.py`,
`check-strict-accelerated-consumer.py --native-simd` and
`check-strict-group-consumer.py --native-simd`, all with `--toolchain 1.99.1`.
Apple used `check-macos-resident-package.py --accelerated --keyed`,
`check-macos-resident-batch-package.py` and
`check-macos-resident-parallel-package.py`, also with `--toolchain 1.99.1`.
The manifest binds complete consumer transcripts, including command/time output.

Both AWS initial consumer preflights correctly rejected group-writable checkout
directories before running tests. Only checkout/target permissions were tightened;
the retry used a private umask. All three consumers then passed on each host.
The ten earlier captures per host were hash-checked unchanged across the retry.
Initial failures are preserved and labelled, not counted as successful execution.
The Mac and local AMD campaigns passed directly.

## Workload-specific performance

Counts below derive from the recorded seven-sample medians. Ratios are portable
divided by selected time across eight ordinary SHA workloads. "Not faster"
includes equality; tiny differences are not significance tests. No dispatch
policy or default was changed in response to these results.

| Host | SHA-224/256 ratio | SHA-512-family ratio | Keccak vector rows not faster | Hardened batch rows not faster | Threaded ParallelHash rows not faster |
| --- | --- | --- | --- | --- | --- |
| AMD | 1.44–2.95 | 1.20–1.59 | 0/32 | 517/640 | 66/96 |
| Intel | 1.53–3.70 | 1.30–2.09 | 0/32 | 428/640 | 71/96 |
| Arm Linux | 1.17–1.48 | 0.96–0.97 | 96/96 | 576/640 | 64/96 |
| M2 | 1.29–2.30 | 1.16–1.44 | 96/96 | 589/640 | 68/96 |

Ordinary Keccak has 128 rows per host, including scalar fallback rows; only rows
with nonzero vector calls are in its column. Hardened batching includes fallback
and balanced/ragged shapes; among actual vector rows, not-faster counts are
respectively 40/114, 40/114, 335/362 and 362/362. Actual SIMD execution therefore
does not imply a performance benefit. Threaded comparisons use the scheduled
implementation as baseline, with requested worker counts 1, 2 and 4; not every
input starts workers. Measure workloads when choosing an explicit route. These
results establish neither universal thresholds nor an advantage over dedicated
single-stream instructions.

Elapsed time and peak RSS in consumer transcripts cover compilation and the
whole acceptance harness, not per-operation memory/stack bounds. Benchmark
timing is not secret-dependent timing analysis. No fresh constant-time campaign,
compiler cleanup matrix, Miri, Kani or sanitizer qualification is claimed here.

## Preserved limitations and remaining work

- Neither inspected x86 CPU exposes dedicated x86 SHA512. Earlier SDE evidence
  remains emulated; AVX-512 availability alone is not this instruction set.
- Apple resident protection is not dump exclusion or the Linux strict profile.
- Windows has no new native execution in this collection. Its prior VBS
  development bundle retains its original source/compiler; .53 facade checks
  are compile-only, not updated image loading or production-signing evidence.
- Intel Mac, Windows ARM64 and native RISC-V remain unavailable/unqualified.
- Hardened batch raw `owner_review: pending` is preserved. This author review
  reconciles runtime results; it does not convert that standalone record into
  independent qualification or a release-admission receipt.
- The owner-directed full consolidation remains v0.24.55. Ordinary CI and final
  non-sweep release verification remain separate; this document is not a tag PASS.
