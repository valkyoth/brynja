# Prospective AES value-timing screen — 2026-11-12

The original class-coupled fixture remains available for correctness and
historical replay, but is no longer an admissible new value-timing observation.
This change corrects a measurement confound, not AES arithmetic. Frozen earlier
declarations, raw samples, statistics and verifier history are not rewritten.

## One executable, separate questions

New explicit observations require both `--controls --value-controls` in
`scripts/aes/check-aes-accelerated-fixed-random.py`. Correctness-only registered
commands still do not measure. The four existing controls are built together
and independently checked against OpenSSL before measurement:

| Control | Role in the new screen |
| --- | --- |
| `shared-values` | Primary fixed/random value comparison at the same key/block addresses. |
| `shared-identical` | Negative control: identical inputs at those shared addresses. |
| `separate-values` | Class-coupled address/context diagnostic; not a value verdict. |
| `separate-identical` | Label/address diagnostic with equal values; not a value verdict. |

Both shared controls must have zero alarms and zero noise flags for a completed
screen. Separate-control alarms and noise remain fully visible in their raw
output and summaries, labelled **not a timing pass**. Invalid samples, process
failures, stderr, timeouts or changed binaries in any control still fail the
experiment; the diagnostic label cannot bypass data validation. There is no
best-control selection or fallback from a failed primary comparison.

The shared buffer is already implemented and tested: one 64-byte-aligned
`Common` per campaign, key at offset zero and block at offset 32. Each input
is copied there before entering the original trial/timer, in either class
order. Regression tests check complete values, stable/equal addresses and
invalid-class rejection. Production APIs, AES kernels, timers, corpus and
sample thresholds are unchanged. Cached-key setup can still influence later
timing; a shared buffer does not remove every execution-history confound.

The runner rejects new baseline observations and mixing this policy with the
separate dispatch, long-batch or crossover experiments. Historical fixture
correctness and strict parsers remain usable. Crossover's within-slot class
comparisons and between-slot comparisons remain separately named diagnostics;
neither the old nor the new runner automatically imports them as current passes.

## Finite collection, not repeated attempts to pass

This document changes comparison roles, **not** population or cutoff rules:
8,192 pairs, 256 warmups, four operations per duration, absolute Welch/paired
threshold 4.5, CV limit 1.0 and zero-variance inconclusive. Keep every sample,
alarm and noise flag. Never trim data to produce a pass, stop adaptively,
subtract diagnostic offsets, or pool process launches into an undeclared test.

An invocation still requires a separately frozen host/compiler/run declaration
and a new destination. No new acceptance measurement is authorized merely by
running correctness checks. If future declarations use multiple process
layouts, specify their complete finite count, ordering and interpretation
before collecting data; retain every launch. The exploratory 800-run sweep is
evidence about the confound, not a newly adopted requirement for every release.

For an explicitly DIT-required ARM experiment, also use `--require-dit`. This
selects a baseline DIT-capability probe, static `+dit` compilation and required
scoped admission; identity records name the policy. Omitting the option retains
the existing optional policy and must not be described as a DIT-required run.
Correctness runs with this flag are still not measurements, and the
[DIT qualification record](aes-dit.md) keeps remaining binary review and timing
work explicit.

The [fourth-alarm declaration](aes-fourth-alarm-declaration.md) is a bounded
exact-binary diagnostic with a different question, not a run of this prospective
acceptance screen. The [acceptance inventory](aes-acceleration-acceptance.md)
continues to distinguish functional correctness, scoped timing observations and
remaining qualification. No HSM requirement or publication gate is added.
