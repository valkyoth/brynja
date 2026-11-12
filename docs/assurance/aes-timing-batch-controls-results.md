# AES amortized-timer controls — results, 2026-11-11

Both [predeclared 1024-operation observations](aes-timing-batch-controls.md)
completed once on the replacement AWS Neoverse-V2. Every AES control satisfied
the unchanged statistical screen: zero alarms and zero noise-inconclusive
campaigns. This is a successful bounded observation, **not proof of constant
time or retroactive clearance of the earlier alarms**.

## Complete results

Each row contains all 39 campaigns and 8192 retained pairs per campaign.

| Compiler | Control | Alarms | Noise-inconclusive |
| --- | --- | ---: | ---: |
| 1.90.0 | separate-values | 0 | 0 |
| 1.90.0 | shared-values | 0 | 0 |
| 1.90.0 | separate-identical | 0 | 0 |
| 1.90.0 | shared-identical | 0 | 0 |
| 1.99.1 | separate-values | 0 | 0 |
| 1.99.1 | shared-values | 0 | 0 |
| 1.99.1 | separate-identical | 0 | 0 |
| 1.99.1 | shared-identical | 0 | 0 |

The largest absolute Welch score was 4.023533 and the largest absolute paired
score was 4.136220, below the unchanged 4.5 threshold. No thresholds, samples,
control order or batch size were changed after collection began. All 2,555,904
AES pairs and 32,768 overhead pairs remain available: 5,177,344 individual
durations. Both runner invocations exited successfully; no observation was
retried.

## Measurement scale and limits

Mean AES sample durations ranged from about 12.1 to 450.9 µs across the complete
population, meeting the planning aim of at least roughly 10 µs on the shortest
paths. AES-256 cached public-block means ranged from about 14.7 to 17.4 µs.
These are whole 1024-operation sample means, not single-call latency claims.

| Compiler | Overhead control | Class 0 mean, ns | Class 1 mean, ns | Alarm | Noise |
| --- | --- | ---: | ---: | --- | --- |
| 1.90.0 | timer/empty loop | 415.08 | 411.58 | no | no |
| 1.90.0 | copy | 5195.18 | 5192.53 | no | no |
| 1.99.1 | timer/empty loop | 396.68 | 396.10 | no | no |
| 1.99.1 | copy | 4094.65 | 4098.95 | no | no |

The timer control includes **1024 empty opaque operations and loop overhead**,
not just the two clock calls. Its approximately 0.4 µs duration is a few
percent of the shortest AES samples; it must not be confused with the earlier
31–39 ns four-operation control or the declaration's clock-only planning
estimate. Copy-control outliers reached 110,951 ns and are retained. No
overhead was subtracted and no outlier was rejected.

This new batch shape and the replacement host both differ from the original
experiment. The results support the usefulness of amortizing the timer for
this observation; they do not identify the cause of every earlier alarm.
All original alarms, noisy populations and exact binaries remain part of the
record. Review their disposition explicitly before claiming broader timing
acceptance; do not keep changing batches or repeating experiments to accumulate
green results.

## Validation and retained binaries

- Eight native fixture correctness configurations passed (AMD/AWS Arm,
  two compilers, direct/facade). Each passed ten Rust tests and 936 OpenSSL
  comparisons. The new four local registrations are correctness-only.
- All 816 tooling/registry tests passed. Twelve earlier local timing-fixture
  registrations were also refreshed successfully. No production crypto changed.
- Every AES and overhead summary was recomputed locally from the raw samples.
  The 1,872 oracle comparisons from the observation binaries were checked
  again locally. All binary/source hashes and 21 production archive hashes
  matched the recorded identities; archive hashes also match the original
  timing experiment.
- All six complete 152-byte ARM round bodies match the existing templates.
  That check is not a GNU ABI, loader or full caller qualification.
- Bounded manual inspection of Rust 1.99.1's cached AES-256 public timer at
  `0xd3b8` found the initial clock call at `0xd3e0`, loop count `0x400` at
  `0xd3e8`, AES call at `0xd440`, public loop decrement/test at
  `0xd424`/`0xd428`, and final clock call at `0xd490`. Normal completion
  performs 1024 AES calls before stopping the clock. Error paths return early
  and are rejected by the runner. There is no mode-string selection or normal
  output formatting in this timer. This is one inspected specialization, not
  complete timer or whole-program qualification.

## Evidence locations

- `assurance/aes-native-observations/v0.27.3/timing-batch-controls-20261111.json`
- `assurance/aes-native-observations/v0.27.3/batch-timing-kernel-review-20261111.json`
- Local bundle: `target/aes-native-timing-batch-20261111/observations.tar.gz`,
  SHA-256 `aa98695a1b33a7c4214b1a9b54a5af5cb9743df2aa0fb87468261591b391393d`.
- Extracted logs, binaries and raw data: adjacent `aws/` directory. Offline
  replay and inspection scripts, their output and the timer excerpt are in
  `target/aes-native-timing-batch-20261111/`.
- Remote scratch: `/home/ubuntu/brynja-aes-batch-0273-J5Ya5T4S` on the replacement
  host `13.60.220.169`. Both toolchains and build prerequisites were installed
  before testing; setup logs are under `/home/ubuntu/brynja-build-setup-20261111`.
- Source overlay: `target/aes-timing-batch-overlay-20261111.tar.gz`, SHA-256
  `a712c5653bff89f23fa2d942909889278f8cc0291b253265513bc026e86fcc54`.
  Base source bundle SHA-256:
  `7a90292b5bf4aa89bb133090a2f4175ec9f707d7c6f574f09882d674955fc6b8`.

The earlier server crashed after its observations had been copied locally.
The three older local bundles remain present with their recorded hashes.
These are unauthenticated working-tree observations based on v0.27.2, not
clean tagged-source certification receipts or physical side-channel/fault
qualification. No release gate or HSM requirement is added.
