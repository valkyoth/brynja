# Accelerated AES fixed-versus-random observations

This v0.27.3 development harness observes the integrated accelerated owners,
not the portable implementation and not an isolated candidate kernel. It is
not a proof of constant-time execution or resistance to physical observation.
No additional publication gate is introduced.

## Fixture and correctness

`scripts/aes/check-aes-accelerated-fixed-random.py` adapts the existing
`assurance/aes-fixed-random/timing.rs` with counted, reversible substitutions:
only the imported API, authority argument, and authority setup change. The
operation timer, population, class order, warmup, repetitions and public
corpus remain unchanged. A forced healthy authority rejects portable fallback;
static ISA admission is probed before any specialized executable runs.

The default command is correctness-only. Four Rust tests and 234 independent
OpenSSL comparisons cover all 39 campaigns, all three key widths, ephemeral
and cached encrypt/decrypt/public output, and cached import/clear. Both direct
and facade consumers use byte-checked package archives. Registered checks use
this default and never collect timing samples implicitly.

## Fixed experiment policy

Explicit `--observation NAME` creates a new directory under
`target/aes-accelerated-fixed-random`; existing names are rejected. Each
measurement invocation is one-shot, with no adaptive stopping, sample
rejection, cropping or retry-to-pass. All campaigns run before analysis.

- Native Linux x86-64 AES-NI or AArch64 AES; no emulator measurements.
- Rust 1.90.0 and 1.99.1; GNU host target; static authority; opt3, fat LTO,
  one codegen unit, overflow checks, panic abort. Rust unit-test executables
  use the test harness's unwind behavior; the measured executable uses abort.
- 39 campaigns; 8,192 fixed/random pairs each; 256 warmup pairs per campaign;
  four operations per timed sample. Cached import times construction/Drop,
  not a block operation. Cached-operation construction/Drop is outside timing.
- Deterministic public SplitMix64 corpus, seed `0x0272_f17e_d00d_0001`, XORed
  with campaign index. Per-pair class order is generated before measurement.
- Pin the process to the lowest allowed logical CPU, record host/governor/SMT
  context, and restore affinity on every exit. Run no concurrent verification
  workload on that host during collection.
- Absolute Welch or paired t statistic at least 4.5 is an alarm. A zero class
  variance or class coefficient of variation above 1.0 is inconclusive.
  An alarm and noise can coexist; noise never excuses or removes an alarm.
- Persist process output, errors, timeout partial output and parsed summaries
  before deciding pass/failure. Retain the executable, package/fixture hashes,
  compiler identity and OpenSSL identity. Check executable identities before
  measurement and afterward, including failure paths.

These finite diagnostics cannot exclude smaller effects, untested inputs,
other compiler/target/profile combinations, register/spill remnants, power/EM
leakage or physical faults. Raw samples and binaries are local diagnostic
artifacts, not authenticated certification receipts.

## Predeclared run list (2026-11-10)

After correctness-only validation, collect exactly these four direct/static
GNU-target observations, sequentially on each host, with the policy above:

1. `amd-integrated-msrv-20261110`: local AMD, Rust 1.90.0.
2. `amd-integrated-current-20261110`: local AMD, Rust 1.99.1.
3. `aws-arm-integrated-msrv-20261110`: AWS Neoverse-V2, Rust 1.90.0.
4. `aws-arm-integrated-current-20261110`: AWS Neoverse-V2, Rust 1.99.1.

These are separate declared configurations, not retries of a failed experiment.
Complete the declared list even if another configuration alarms; do not replace
an alarm/noisy observation with another run. Facade correctness is checked
separately, but this experiment makes no facade timing or hosted-admission claim.
Results will be recorded separately so this declaration remains unchanged.
