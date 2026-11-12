# AES timing address/value control experiment

## Purpose and predeclaration — 2026-11-10

The [initial observations](aes-accelerated-fixed-random-results.md) contained
ARM timing alarms and noisy AMD/ARM campaigns. They are retained unchanged.
This is a separately declared diagnostic experiment, not a replacement run or
an attempt to retry until those observations pass. Production AES is unchanged.

The original fixture passes `pair[class]` into the timed trial. Inspection of
the retained Rust 1.99.1 ARM binary confirms that the selected input pointer is
loaded inside the cached-operation timer: `aes256` calls its cached timer at
`0xd5f8`; the timer starts at `0xa6f0`; the public path loads the input through
that pointer at `0xa884..0xa88c`. Public mode-string checks also occur inside
the timer (`bcmp` at `0xa798`), adding harness work. These observations identify
possible confounds, not a cause of the data-class timing difference and not a
complete emitted-code qualification of this GNU executable.

## Controls

One executable per compiler contains all four controls, selected at runtime.
The measurement loop, trial, timing boundaries, corpus, class order and
statistical policy are shared. Copying/selecting controlled inputs is outside
the existing timer. The controls run in this fixed order:

| Control | Input addresses used by the trial | Values in the two classes |
| --- | --- | --- |
| `separate-values` | Original distinct pair entries | Fixed/random |
| `shared-values` | One aligned common buffer | Fixed/random |
| `separate-identical` | Original distinct pair entries | Both fixed |
| `shared-identical` | One aligned common buffer | Both fixed |

The common buffer is allocated once per campaign, aligned to 64 bytes, with
key and block in that same slot. `black_box` materializes the buffer references;
correctness tests verify both addresses and complete values in both class
orders. Identical-value controls deliberately exercise the same original
sample population/order but replace class-one values with class-zero values.
All four controls receive independent OpenSSL preflight comparisons before any
measurement. This confirms operations and selected values, not timing behavior.

All four run in separate invocations of the **same retained binary**, each pinned
to the lowest allowed CPU. Existing measurement policy is unchanged: 39
campaigns, 8,192 pairs, four repetitions, 256 warmups, the original public seed,
absolute Welch/paired t alarm at 4.5, zero variance or CV above 1.0 inconclusive.
No cropping, outlier removal, adaptive stopping, threshold changes or retries.
Each control gets retained raw output, host context and summary, including
failure/timeout output. A non-pass control does not cause its repetition or
skip the remaining predeclared controls. Identity changes abort further work.

## Fixed native run list

After correctness validation, collect exactly two direct/static GNU-target
experiments on AWS Neoverse-V2, sequentially with no concurrent verification
on that host:

1. `aws-arm-address-controls-msrv-20261110`, Rust 1.90.0: all four controls.
2. `aws-arm-address-controls-current-20261110`, Rust 1.99.1: all four controls.

No AMD timing run is added in this experiment; its earlier noise remains open.
Both direct/facade routes and both compilers get correctness-only checks.
The registered `aes-timing-controls-fixture` checks never measure implicitly.

## Interpretation fixed before measurement

An alarm in an identical-value control demonstrates that the measurement can
distinguish labels even when cryptographic inputs are equal. It does not by
itself explain every original alarm. A difference between shared/separate
controls is evidence to investigate buffer/layout/setup effects, not a proof
that the AES implementation is constant-time. Different setup and process
layouts remain confounds; absolute durations across processes are not a paired
performance comparison. A shared-values alarm remains an unresolved signal.

All results, including apparently clean controls, must be reported together.
No outcome of this experiment alone erases the original observations, qualifies
arbitrary compilers/targets, establishes physical resistance, or closes the
v0.27.3 timing investigation automatically. Record results separately so this
declaration stays fixed.
