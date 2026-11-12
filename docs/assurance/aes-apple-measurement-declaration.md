# Apple AES observations — declaration, 2026-11-11

This declares the first integrated-expansion performance and fixed/random
observations on the user-provided Apple M2 Pro, macOS 27.2.1 (26B131), before
collecting samples. Existing ARM/AMD timing alarms and noise remain unresolved.
These observations fill the Apple measurement gap; they are not retries of
those experiments, certification, a new release gate or a constant-time proof.

## Source, prerequisite checks and placement

Use the development source based on
`56a1b7805c9517fbdb5e3c28b137ea8c9108cf7e`, with the tested macOS runner path
and complete AES/PMULL/NEON baseline probe. Select only native
`aarch64-apple-darwin`, static `ArmAes`, and `+aes,+neon`. Retain the actual
package, fixture, compiler, oracle and binary hashes; do not substitute a clean
tag claim for a working-tree capture. The hosted PMULL refresh is separate.

Before measurement, all runner regression tests and eight native correctness-only
configurations must pass: performance and timing fixtures, both Rust 1.90.0 and
1.99.1, direct and facade. Performance requires four Rust tests and 48
known-answer/clearing cases per configuration. Timing requires ten Rust tests
and 936 OpenSSL comparisons per configuration. Each measured binary repeats
its own tests, baseline ISA probe and exact-binary preflight. Correct setup or
fixture failures before collecting samples; retain them, and never treat a
partial measurement as a successful preflight.

**Apple observations are unpinned.** The runner does not expose a portable
macOS CPU-pinning API or pretend Linux affinity calls work there. It records
`logical_cpu: null`, explicit unpinned status, OS/build, CPU description,
logical/physical CPU counts and load before collection. Scheduler placement,
performance/efficiency-core migration, DVFS and power policy are uncontrolled.
These limitations can make a result inconclusive; they do not authorize noise
filtering or relaxed thresholds. Linux continues to require pinning and restore
the original affinity, failing rather than silently falling back to this policy.

Do not run other builds, tests, measurements or bulk transfers on the Mac
during collection. Do not change power settings, workload, sample population
or core-selection policy in response to observed significance scores.

## Finite run list and unchanged statistical policy

Run the following four direct/static observations once, sequentially:

1. `apple-integrated-performance-msrv-20261111`, Rust 1.90.0.
2. `apple-integrated-performance-current-20261111`, Rust 1.99.1.
3. `apple-batch-controls-msrv-20261111`, Rust 1.90.0.
4. `apple-batch-controls-current-20261111`, Rust 1.99.1.

Performance keeps the [existing policy](aes-accelerated-performance.md):
opt3/fat-LTO/cgu1/overflow/unwind, 48 cases, eight warmup batches, nine samples
of 64 operations and alternating portable/accelerated order. Retain all 432
samples per observation. There is no speed pass/fail threshold.

Timing keeps the [1024-operation policy](aes-timing-batch-controls.md):
opt3/fat-LTO/cgu1/overflow/abort, 39 campaigns per control, 8192 retained pairs,
256 warmup pairs, seed `0x0272_f17e_d00d_0001`, absolute Welch/paired threshold
4.5 and the existing zero-variance/CV-greater-than-one noise rules. Use one
binary per compiler. Collect timer/copy diagnostics first, then
`separate-values`, `shared-values`, `separate-identical`, `shared-identical`.
The batch size reuses the declared amortized-timer design; do not tune it to
Apple results. Overhead is diagnostic, never subtracted from AES durations.

Keep 600-second subprocess limits. Retain all raw and partial outputs, failures,
exit statuses, host metadata and summaries. New observation directories cannot
be overwritten. Do not trim, retry, stop adaptively or skip later declared
controls because of a statistical non-pass. A setup or malformed-output failure
is not a valid statistical observation. Never run either observation binary
again to seek a better result. Correctness-only commands remain non-measuring.

## Interpretation and remaining work

Replay every summary from raw samples, verify all retained identities and
inspect the actual measured timer/operation specializations before drawing a
bounded conclusion. Apple scheduling differs from the Linux experiment; it
cannot establish a cross-host controlled comparison or explain earlier alarms.
Even a successful screen would not prove constant-time behavior, arbitrary
consumer safety, physical side-channel/fault resistance or register/spill
erasure. Do not mark earlier experiments green or remove their retained data.
