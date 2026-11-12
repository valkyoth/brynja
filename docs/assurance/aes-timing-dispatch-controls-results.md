# AES dispatch and timer controls — results, 2026-11-10

The [separately declared experiment](aes-timing-dispatch-controls.md) completed
once for each compiler on the AWS Neoverse-V2 host. There were **no timing alarms
in the eight AES controls**, but every control had noise-inconclusive campaigns.
Neither compiler observation is a timing pass. The original alarms and the
earlier address/value-control alarm remain unresolved, not superseded.

## Complete AES results

Each cell counts campaigns out of 39, with 8192 retained pairs per campaign.

| Compiler | Control | Alarms | Noise-inconclusive |
| --- | --- | ---: | ---: |
| 1.90.0 | separate-values | 0 | 3 |
| 1.90.0 | shared-values | 0 | 5 |
| 1.90.0 | separate-identical | 0 | 6 |
| 1.90.0 | shared-identical | 0 | 4 |
| 1.99.1 | separate-values | 0 | 5 |
| 1.99.1 | shared-values | 0 | 1 |
| 1.99.1 | separate-identical | 0 | 3 |
| 1.99.1 | shared-identical | 0 | 2 |

All 2,555,904 AES pairs and 32,768 overhead pairs were retained: **5,177,344
individual durations** in total. No trimming, outlier rejection, adaptive
stopping, threshold changes or retry occurred. Both runner invocations exited
with status 2 after preserving the four declared AES controls and their
non-pass summaries.

## Timer and materialization diagnostics

Means below include every sample, including large delays; they are not
outlier-filtered latency estimates. Units are nanoseconds per four-operation
sample, not per AES block. The two columns correspond to class labels with
identical input values.

| Compiler | Diagnostic | Class 0 mean | Class 1 mean | Maximum | Alarm | Noise |
| --- | --- | ---: | ---: | ---: | --- | --- |
| 1.90.0 | timer | 32.05 | 38.62 | 53,932 | no | yes |
| 1.90.0 | copy | 54.30 | 52.89 | 11,808 | no | yes |
| 1.99.1 | timer | 31.44 | 31.46 | 125 | no | no |
| 1.99.1 | copy | 51.39 | 49.56 | 14,978 | no | yes |

For scale, the AES-256 cached public-block campaign means in this new binary
were approximately 84–89 ns per four operations across the eight controls.
The clock bracket is therefore a material part of these very short samples.
Large delays also occur without AES and with identical values. This establishes
a measurement limitation; it does **not** show that every original alarm is
caused by the timer or that AES is constant-time. The copy control is not an
exact substitute for AES setup, and no overhead was subtracted from AES data.

Changing the fixture also changes code layout and optimization. The absence of
an alarm after moving operation selection cannot isolate string dispatch as
the cause of a previous alarm. Identical-value controls did not alarm either.

## Correctness and bounded binary review

- Eight native correctness configurations passed: AMD/AWS Arm, Rust
  1.90.0/1.99.1, direct/facade routes. Each passed ten Rust tests and 936 OpenSSL
  comparisons. Registry checks remain correctness-only.
- All 811 tooling/registry tests passed. The original four timing-fixture and
  four address/value-control correctness registrations also passed after the
  runner extension. Plan, documentation-link and diff-integrity checks passed.
- Every raw AES summary and overhead summary was replayed locally. All 1,872
  oracle comparisons from the two observation binaries were rechecked locally.
  Binary hashes and all 21 package hashes matched their recorded identities;
  production package hashes also matched the original timing experiment.
- All six 152-byte AArch64 round bodies in the new observation binaries match
  the existing exact templates. This does not qualify the GNU loader, callers
  or whole consumer.
- A bounded inspection of Rust 1.99.1's AES-256 cached public timer at
  `0xdea0` found its start/end clock calls at `0xdec0`/`0xe0b0` and four calls to
  `encrypt_block_public` at `0xdef4`, `0xdf64`, `0xdfd4`, `0xe044`. The timer
  body has no mode-string selection or normal-path output formatting. Error
  formatting remains on error paths. This is one inspected specialization,
  not complete timer-boundary or whole-program qualification.

## Retained records

Machine-readable summaries and identities:

- `assurance/aes-native-observations/v0.27.3/timing-dispatch-controls-20261110.json`
- `assurance/aes-native-observations/v0.27.3/dispatch-timing-kernel-review-20261110.json`

Remote scratch: `/home/ubuntu/brynja-aes-dispatch-0273-urIP1hCB`.
Local retained bundle: `target/aes-native-timing-dispatch-20261110/observations.tar.gz`,
SHA-256 `f0db8f9e1c1b8db89f4befdb34eeafc8a2b7566fbcdae1dd875c7f7342f4b9eb`.
It includes logs, overlay, correctness artifacts, both observation binaries,
all raw populations and summaries. Extracted copy is under the adjacent `aws/`.

The pre-measurement overlay was
`target/aes-timing-dispatch-overlay-20261110.tar.gz`, SHA-256
`acd6ced0a0044a0ee8c301b520fa2e97de08f47cd9394908ba9724a598e313d4`.
It overlays the original source bundle, SHA-256
`7a90292b5bf4aa89bb133090a2f4175ec9f707d7c6f574f09882d674955fc6b8`.
These are byte-checked working-tree observations based on v0.27.2, not clean
tagged-release certification receipts. No production crypto changed here.

## Next step, not closure

Before collecting another population, separately declare an amortized-timer
experiment whose batch size is justified by timer overhead and desired
measurement duration, not by which size passes a significance test. Keep
identical-input controls, the original alarms, all samples and thresholds;
review the actual measured specialization. A different operation batch is a
different experiment, not a repaired historical result. Timing acceptance and
broader v0.27.3 platform qualification remain open. No new release gate or
hardware requirement is added.
