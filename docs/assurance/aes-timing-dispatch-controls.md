# AES dispatch and timer controls — declaration, 2026-11-10

This is a new diagnostic experiment, not a rerun or replacement of the
[original observations](aes-accelerated-fixed-random-results.md) or the
[address/value controls](aes-timing-address-controls-results.md). All their
alarms and inconclusive results remain open. No production crypto changes.

## Question and fixed design

The original harness selects the operation by string inside each timed
repetition and tests a measurement/formatting flag there. The new, separately
identified fixture selects encrypt/decrypt/public-output before entering a
dedicated timer closure. Measurement versus oracle-preflight is const-generic,
so formatting and import-validation encryption are absent from the measured
specialization. Key construction, output-owner Drop and cached-schedule Drop
retain their original measurement boundaries. Exact emitted-code inspection
is still needed before calling this complete timer-boundary qualification.

Keep the original 39 campaigns, 8192 retained pairs, four operations per sample,
256 warmup pairs, public seed `0x0272_f17e_d00d_0001`, randomized pair order,
absolute Welch/paired threshold 4.5, and zero-variance/CV-greater-than-one noise
policy. Do not lengthen batches based on the results of this experiment.

For each compiler, use one binary for all four controls, in this order:
`separate-values`, `shared-values`, `separate-identical`, `shared-identical`.
The shared variants reuse the existing aligned input buffers. Identical
variants retain class labels/order but supply class-zero values to both.
Every variant must first pass all 234 OpenSSL comparisons (936 total).

Before these four controls, collect two overhead diagnostics from that binary:

- `timer`: the same clock bracket around four `black_box(())` operations.
- `copy`: the same bracket around four opaque reads/materializations of a
  fixed aligned 32-byte key and 16-byte block, with identical values and
  addresses in both classes. This is not an exact model of all AES setup.

Each overhead diagnostic uses 8192 pairs and 256 warmups, with corpus/order
indices zero and one respectively. Retain raw integer durations and the same
statistical summaries, including noise/alarms. They are descriptive lower-level
controls, not AES passes. Never subtract them from AES measurements, discard
outliers, crop samples, change thresholds or retry to obtain a pass.

## Named observations

Exactly two observations are declared on the user-provided AWS Neoverse-V2
host, using packaged direct static ARM AES, one CPU affinity, no concurrent
verification work on that host, release opt-level 3, fat LTO, one codegen unit,
overflow checks enabled and panic abort:

- `aws-arm-dispatch-controls-msrv-20261110`: Rust 1.90.0.
- `aws-arm-dispatch-controls-current-20261110`: Rust 1.99.1.

Run them in that order, once each, after native correctness validation on both
compilers and direct/facade routes. Retain the source overlay/hash, byte-checked
package hashes, compiler, oracle and binary hashes, probe, logs, host metadata,
all raw samples and all results. Continue through the four declared controls
despite statistical non-passes; malformed output or an executable identity
change is not permission to retry. New-directory creation prevents overwrite.
No AMD timing observation is declared in this slice.

Correctness commands omit `--observation` and never collect these populations:

```sh
python3 scripts/aes/check-aes-accelerated-fixed-random.py \
  --toolchain 1.90.0 --route direct --controls --isolate-dispatch
```

The `aes-timing-dispatch-fixture` registry category contains the four local
compiler/route correctness configurations, ten Rust tests plus 936 oracle
comparisons each. Its success is not timing acceptance. A lack of alarms in
a modified binary cannot erase an alarm in an older binary or establish
constant-time behavior, physical resistance, or a general compiler guarantee.
