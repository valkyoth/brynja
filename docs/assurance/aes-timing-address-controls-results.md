# AES address/value controls — results, 2026-11-10

**The investigation remains open; none of the eight control observations is a
timing pass.** The [predeclared experiment](aes-timing-address-controls.md) ran
once per compiler on AWS Neoverse-V2, using one retained binary for its four
control invocations. No production cryptographic code changed. All package
hashes match the [original experiment](aes-accelerated-fixed-random-results.md).

## Results

| Compiler | Control | Alarm campaigns | Noise-inconclusive campaigns |
| --- | --- | ---: | ---: |
| 1.90.0 | separate-values | 0 | 3 |
| 1.90.0 | shared-values | 0 | 4 |
| 1.90.0 | separate-identical | 0 | 3 |
| 1.90.0 | shared-identical | 0 | 3 |
| 1.99.1 | separate-values | 1 | 4 |
| 1.99.1 | shared-values | 0 | 3 |
| 1.99.1 | separate-identical | 0 | 6 |
| 1.99.1 | shared-identical | 0 | 4 |

All **2,555,904 fixed/random pairs** (5,111,808 timed samples, excluding warmup)
were retained. Every summary was reproduced from raw output locally, all
1,872 independent oracle comparisons for the two measured binaries were
rechecked, and binary/generated-source/package identities were verified.
The [complete compact record](../../assurance/aes-native-observations/v0.27.3/timing-address-controls-20261110.json)
contains every campaign, not only the alarm cases.

The sole alarm is Rust 1.99.1, `separate-values`, AES-256 cached `public-key`:
fixed/random means 92.434/91.707 ns per four-operation sample, absolute Welch
t 23.827 and paired t 28.781. Its class CV values are 0.0220/0.0204, so it is
not noise-flagged. It remains an unresolved signal. It is a different campaign
from the original `public-block` and `decrypt-block` alarms.

## What this establishes—and does not

The shared-address fixed/random controls had no alarms in this finite
experiment. This is consistent with investigating input-address/layout/setup
effects, but **does not establish that address differences caused the original
alarms**. Even `separate-values` uses a newly built control harness, not the
original binary; code and process layout, setup work and time can differ.
The original alarm campaigns did not alarm here, but their original observations
remain unchanged and unresolved. An absence of alarms in a later control is
not a retrospective pass.

Identical-input controls did not alarm, so this experiment does not demonstrate
a label-only false-positive mechanism. They did exceed the noise limit in
several campaigns. Those failures and the shared-value noise are not discarded
or excused by a low t statistic. No outlier filtering, threshold relaxation or
replacement measurement was used. No new AMD timing run was performed.

Eight native compiler/route control-fixture correctness configurations passed,
with eight Rust tests and 936 OpenSSL comparisons each. The local baseline
fixture registrations were also refreshed in correctness-only mode. The
tooling/registry suite passed 804 tests, including seven new control tests.
These correctness passes remain separate from timing acceptance.

## Original binary inspection

The [offline round-body comparison](../../assurance/aes-native-observations/v0.27.3/original-timing-kernel-review-20261110.json)
verified all three 152-byte AES round bodies in each original ARM executable
against the existing exact AArch64 instruction templates. The existing ELF
mapping helper's AArch64 template key was reused only for machine type and
executable byte mapping; no musl or complete GNU-consumer qualification is
claimed. All six bodies match; this is not a complete timing proof.

Inspection of the original Rust 1.99.1 AES-256 cached timer confirms:

- the timer begins at `0xa6f0` and ends at `0xad1c`;
- public mode-string selection includes a `bcmp` call at `0xa798` inside it;
- the selected input pointer is loaded at `0xa884`, and its 16-byte block
  loaded at `0xa888`, before being staged in scratch;
- the public path calls the AES-256 round body at `0xa9d4`, stores the result
  and clears scratch, then bypasses formatting when measuring;
- the measured repetition loop is bounded by four operations.

This narrows the investigation to the actual fixture/consumer as well as the
host; it does not justify attributing the signal to a particular instruction.

## Retention and next step

Remote scratch: `/home/ubuntu/brynja-aes-timing-controls-0273-h36g56Ve`.
Local retrieved data: `target/aes-native-timing-controls-20261110/aws/`.
The original source bundle remains unchanged. The control overlay is
`target/aes-timing-controls-overlay-20261110.tar.gz`, SHA-256
`5baa68d6b8c394cfe928eab57fc854232068249bfd65b34d1b749c4e74d50037`.
The retrieved bundle is `target/aes-native-timing-controls-20261110/observations.tar.gz`,
SHA-256 `575ad6cd63d51ea438f77dd2a14c21c81466101d52d3852763da642fa2b555f5`.
These are working-tree diagnostic artifacts, not authenticated certification
receipts or clean-tag evidence.

The next step is to qualify a measurement path with stable input addresses and
operation selection outside the timed section, and quantify the timer/setup
contribution. The present four-operation batches are short enough that brief
host delays materially affect the noise screen. Any longer-batch or timer-only
control must be a separately justified, predeclared experiment, not a silent
change to this policy. Preserve the original and controlled results, and do not
close timing acceptance until the remaining signals/noise have a reviewed
disposition supported by evidence.
