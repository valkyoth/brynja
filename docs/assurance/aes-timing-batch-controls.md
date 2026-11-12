# AES amortized-timer experiment — declaration, 2026-11-11

This is a separately declared experiment, not a repeat or replacement of the
[dispatch-isolated four-operation observations](aes-timing-dispatch-controls-results.md).
Original alarms and all noisy observations remain recorded and unresolved.

## Fixed batch rationale

The prior timer-only means were 31–39 ns; AES-256 cached public-block means
were 84–89 ns per four operations. As a rough planning estimate, that leaves
about 12 ns per operation after the clock bracket. Choose **1024 operations
per sample**, the first power of two above 10,000/12, to aim for at least 10 µs
for short operation paths and a clock contribution below about 0.4 percent.
This is a design estimate, not sample subtraction or a measured guarantee.
No sample is shortened, normalized or corrected using overhead measurements.
Do not change the batch size based on significance scores or whether it passes.

The fixture changes only the repetition constant from four to 1024 in the
dispatch-isolated Rust source. Const-generic preflight still exercises one
operation per vector; the oracle inputs are unchanged. The actual measured
specializations, including repetition and clock boundaries, need inspection.
Longer repetition may change optimization, cache and CPU behavior; conclusions
apply to this shape, not arbitrary consumers or the original binary.

## Unchanged policy and controls

Keep 39 AES campaigns, 8192 retained pairs per campaign, 256 warmup pairs,
seed `0x0272_f17e_d00d_0001`, and randomized class order. Keep absolute Welch
and paired thresholds at 4.5 and the original zero-variance/CV-greater-than-one
noise rules. Retain every raw sample. No trimming, outlier rejection, adaptive
stopping, threshold relaxation or retry-to-pass is permitted.

Use one binary per compiler. First collect `timer` and `copy` diagnostics with
the same 1024 repetitions and identical inputs/classes. Then collect the four
AES controls once each in this order: `separate-values`, `shared-values`,
`separate-identical`, `shared-identical`. Each control has the same 39 campaigns.
All four controls must pass 234 OpenSSL comparisons each before measurement.
Overhead summaries are descriptive only, never AES acceptance or subtracted
from AES durations. Statistical non-passes do not skip later declared controls.
Executable mutation or malformed output is not permission to retry.

## Hosts and named runs

The user reported that the previous server crashed overnight and supplied a
replacement at `13.60.220.169` (ubuntu, same client authentication key). Its
initial probe reports four Neoverse-V2 r0p1 CPUs, AArch64 AES/NEON, Linux
7.0.0-1014-aws and OpenSSL 3.5.5. Prior observations were already copied and
hashed locally. The replacement is a different machine: differences from the
previous observations cannot be attributed solely to batch size.

Declare exactly these two direct/static `aarch64-unknown-linux-gnu` runs on the
replacement, in order, after native correctness passes on both compilers and
direct/facade routes:

1. `aws-arm-batch-controls-msrv-20261111`, Rust 1.90.0.
2. `aws-arm-batch-controls-current-20261111`, Rust 1.99.1.

Release profile remains opt-level 3, fat LTO, one codegen unit, overflow checks
enabled and panic abort. Pin the measurement process to one CPU; run no other
verification on that host during collection. Each subprocess retains its
existing 600-second timeout. A timeout is retained, not retried or extended
after seeing data. There is no new AMD timing run in this declaration.

Record source overlay and package hashes, compiler and oracle identity,
retained binary hashes, host metadata, probe/tests/preflight logs, all raw
populations and all summaries. Each named directory must be new. An explicit
`--observation` is required; registry checks collect no statistical populations.

```sh
python3 scripts/aes/check-aes-accelerated-fixed-random.py \
  --toolchain 1.90.0 --route direct --controls --isolate-dispatch --long-batch
```

The four `aes-timing-batch-fixture` registrations establish correctness only:
ten Rust tests and 936 oracle comparisons each. A successful control is not
proof of constant-time behavior, physical protection or closure of old alarms.
No production crypto, API, release gate or hardware requirement changes.
