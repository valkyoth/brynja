# Intel AES observations — declaration, 2026-11-11

This declares new native observations on the user-provided AWS Intel Xeon
6975P-C (four logical CPUs, Linux 7.0.0-1014-aws), before collecting any
performance or fixed/random samples on this host. These are development
diagnostics, not a new release gate, a constant-time proof, or a replacement
for earlier AMD/ARM results and unresolved alarms.

## Scope and prerequisites

Use the same uncommitted integrated-expansion source and retained source/fixture
bundles as the [Intel correctness record](../../assurance/aes-native-observations/v0.27.3/intel-native-20261111.json).
No production or fixture change is required for these observations. Native
ISA probes must pass; require static `X86AesNi`, target
`x86_64-unknown-linux-gnu`, and flags `+aes,+sse2`. Do not admit hosted x86,
VAES, emulation, or a portable fallback as measured acceleration.

Before measurement, run both existing Python runner regression suites and
correctness-only modes for each compiler/API combination for both fixtures:
Rust 1.90.0/1.99.1, direct/facade. Performance correctness requires four Rust
tests and 48 known-answer/clearing cases; the timing fixture requires ten Rust
tests and 936 independent OpenSSL comparisons. Each observation repeats its
own checks and exact-binary preflight. Stop on a correctness/setup failure;
retain it and correct its cause before collection. Do not rerun already
collected measurements under new names to obtain a desired result.

## Fixed order and policies

Run these four direct/static observations sequentially, once each:

1. Performance `aws-intel-integrated-msrv-20261111`, Rust 1.90.0.
2. Performance `aws-intel-integrated-current-20261111`, Rust 1.99.1.
3. Timing `aws-intel-batch-controls-msrv-20261111`, Rust 1.90.0.
4. Timing `aws-intel-batch-controls-current-20261111`, Rust 1.99.1.

Performance uses the unchanged [performance policy](aes-accelerated-performance.md):
opt3/fat-LTO/cgu1/overflow/unwind, 48 cases, eight warmup batches and nine
samples of 64 operations, alternating portable/accelerated order. Retain all
432 samples per observation. There is no speed threshold or pass/fail verdict.
Do not subtract timer overhead or filter slow samples.

Timing uses the unchanged [1024-operation policy](aes-timing-batch-controls.md)
with `--controls --isolate-dispatch --long-batch`: opt3/fat-LTO/cgu1/overflow/abort,
39 campaigns per control, 8192 pairs, 256 warmup pairs and seed
`0x0272_f17e_d00d_0001`. Collect timer/copy diagnostics first, then
`separate-values`, `shared-values`, `separate-identical`, `shared-identical`,
using one binary per compiler. Keep absolute Welch/paired alarm threshold 4.5
and zero-variance/CV-greater-than-one noise rules. Every statistical non-pass
remains visible and does not skip later declared controls or the second
compiler. Overhead summaries are descriptive, never subtracted from AES data.
The batch size is chosen in advance to reuse the previously declared
amortized-timer design, not adjusted after observing Intel significance scores.

Keep existing 600-second subprocess limits, fixed sample populations and
affinity restoration. Each measuring subprocess is pinned to the lowest
eligible logical CPU. Do not run concurrent builds, verification, benchmark
jobs, or artifact transfers on this host during sample collection. Record
load, topology/SMT, governor and boost rather than tuning them until tests pass.
Do not trim samples, change thresholds, stop adaptively, or retry measurements.
If an observation fails, retain all partial output and its exit status. Later
declared configurations may continue, but a malformed/mutated artifact does
not become accepted data merely because a later configuration passes.

## Retention and limits

Retain declaration/source/package/fixture hashes, compiler and oracle identities,
exact binaries, test/probe/preflight logs, host context, raw samples, summaries,
failure reports and exit statuses. Named observation directories must be new.
Replay raw-output parsers and all binary/fixture hashes locally after retrieval.

This VM is not a controlled-frequency lab. CPU migration/lifetime contracts,
virtualization, SMT, cache state, scheduling and compiler specialization limit
inference. The exact 1024-operation specialization still needs bounded
emitted-code inspection. Neither successful statistics nor measured speed
qualify arbitrary consumers, physical power/EM/fault resistance, spill erasure,
Apple binaries, or the earlier four-operation timing experiments.
