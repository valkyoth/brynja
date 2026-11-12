# AES class/address crossover — design, not an executed observation

Status: AES fixture integration and strict validation pass on both compiler
endpoints locally and on native ARM. Exact ARM round/expansion bodies match;
review of the actual crossover caller/timer paths remains a prerequisite.
**No measurement is authorized by this draft alone.** Freeze a concrete run
declaration with source/binary identities and the named host before collecting
samples. Do not change the design in response to collected outcomes.

## Question and limits

The [retained ARM diagnostics](aes-retained-timing-diagnostics.md) leave four
non-noise alarms unexplained. Existing separate-address controls bind class
zero to slot zero and class one to slot one; shared-address controls remove the
slot distinction. Neither crosses both values over both slots within one run.

The new question is whether, in a single new executable and process, a measured
difference follows the **input value class**, the **input slot**, or their
interaction. It is not whether another run can obtain a timing pass. The old
host was replaced and the new harness changes code/layout; even an informative
crossover cannot automatically establish the cause in an old executable.

The [control primitive](../../assurance/aes-accelerated-campaigns/timing-slot-crossover.rs)
contains no cryptography or clock calls. It owns two 48-byte input slots and
materializes both classes in both slots before invoking an operation callback.
Both slots are written in slot order on each stage, not fixed-class-then-random
order; neither value class is always the most recently written input.
The callback must use the existing four-operation cached trial and start its
timer only after this setup. It must not place class/slot-dependent bookkeeping
inside the measured operation. Actual input addresses must be recorded and
checked outside the timer, rather than assumed from Rust source layout.

## Finite intended scope

- AArch64 Linux, direct static API, original optimized/LTO profile, compiler
  endpoints 1.90.0 and 1.99.1; one observation per compiler, no retries.
- Only three cached paths: AES-192 decrypt-block, AES-256 public-block and
  AES-256 public-key, covering the four reported alarms across the compilers.
- Each path has a values control and an identical-input control. All controls
  run in the same retained binary/process per compiler. The identical control
  keeps both class labels and slots but uses the fixed input for both labels.
- Each control retains 8,192 rounds after 256 warmup rounds. Every round visits
  all four class/slot cells once: 196,608 measured cell durations per compiler,
  393,216 across the entire two-compiler experiment. Each duration brackets
  four operations, unchanged from the alarm-producing fixture.
- Fixed/random inputs reuse the original corpus and campaign identities for
  these three paths. Scheduling uses a separate public seed. Both mapping
  orders and each stage's class order are balanced across eight patterns;
  warmup and retained sections are shuffled separately before measurement.
- Prepare inputs, slots, order, output storage and bookkeeping outside timers.
  Retain every cell duration and its order, including interruption/failure
  artifacts. A failed invocation is not replaced.

## Analysis fixed before measurement

For each control, retain the full four-cell population and report:

1. Fixed versus random within slot zero and within slot one.
2. Slot zero versus slot one within the fixed class and within the random class.
3. Signed class-by-slot interaction and descriptive order/time strata.

Use the existing 4.5 alarm and 1.0 CV diagnostic thresholds on the four
conditional comparisons, without removing samples or subtracting overhead.
These related comparisons are not independent tests or certification. Report
all outcomes; do not choose the comparison or aggregation that passes. The
interaction and grouped descriptions add no new acceptance threshold.

A slot effect with no detected within-slot class effect would support an
address/layout contribution in **this** fixture, not prove absence of a value
effect. A class effect at both slots needs further investigation. An
identical-input class-label effect indicates a fixture/order/environment
confound. Mixed effects, noise or failure remain inconclusive. Absence of all
signals means non-reproduction, not retrospective clearance. No outcome alone
marks the previous observations passed or establishes universal constant time.

## Required checks before collecting

1. Integrate the primitive with the existing cached trial, retaining key/block
   semantics, authority checks, clearing and timer boundaries. Check every
   crossover cell against independent AES answers in correctness-only mode.
2. Validate the strict record parser with malformed/missing/reordered records,
   changed addresses, failed child processes and synthetic class/slot signals.
3. Build and run fixture tests on both compiler endpoints; inspect the actual
   linked measured paths and input locations for the declared ARM binaries.
4. Freeze the host, identities, exact command/control order and finite run list
   in a declaration before execution. No AMD, Intel, Apple or broad AESAVS
   campaign is required merely to investigate this ARM-specific question.

Six pure control tests cover balanced scheduling, complete cell visits and
values, stable distinct addresses, identical-input labels, invalid patterns and
fail-fast callback errors. All six pass on Rust 1.90.0 and 1.99.1, both
unoptimized and optimized/fat-LTO with overflow checks and warnings denied
(24 test executions). They do not yet establish native AES integration.
The production API, existing timing-experiment behavior, thresholds and release
gate are unchanged. This proposal introduces no mandatory HSM or deployment
profile.

## Correctness integration completed, 2026-11-11

The [driver](../../assurance/aes-accelerated-campaigns/timing-slot-driver.rs)
calls the original cached AES trial; it does not replace AES arithmetic or
timer logic. It records stable input addresses outside the timer and rejects
address drift. Scheduling has matching full-sequence regression checks in Rust
and Python. Original campaign IDs 22, 37 and 36 preserve the intended input
corpora. The identical-input control retains all class/slot labels.

The [Python validator](../../scripts/aes/aes_timing_slot_crossover.py) checks
all 576 preflight cells against OpenSSL (three sample positions, eight patterns,
four cells, two controls and three paths). Its measurement parser validates the
full six-campaign population, exact sample indices/patterns, positive durations,
completion marker and disjoint 48-byte-stride input slots. It reports all four
conditional contrasts, interaction and order/time descriptions; it emits no
overall timing-pass claim. Seventeen synthetic tooling tests include malformed
records, address overlap/drift, failed processes/oracles, class versus slot
signals, noise, registration inputs and refusal of observation mode.

`check-aes-accelerated-fixed-random.py --slot-crossover` is correctness-only.
It rejects `--observation` and mixing with the previous experiment switches
before executing commands. The existing experiment branches and thresholds
are unchanged. Four `brynja-verify` registrations use category
`aes-timing-crossover-fixture`; they validate only native x86 fixture correctness.
The new code and fixtures are included in their input fingerprints.

Six packaged configurations passed 13 Rust tests and 576 oracle cells each:
local x86 direct/facade and AWS ARM direct, all on Rust 1.90.0/1.99.1. The
[compact correctness record](../../assurance/aes-native-observations/v0.27.3/crossover-fixture-correctness-20261111.json)
binds the binaries, generated fixture and logs. All 21 production archive
hashes agree across the six configurations; all 3,456 oracle cells were also
replayed locally. Both retained ARM executables matched six complete
round/expansion bodies each, with 2,610 mutation rejections in total. The
AArch64 ELF mapping does not transfer musl ABI or whole GNU-consumer
qualification. Crossover callers and actual timer boundaries still need review.

The fresh ARM checkout is
`/home/ubuntu/brynja-aes-crossover-0273-PW2RT0Qm` on `13.60.220.169`.
Artifacts are retained locally in `target/aes-crossover-native-20261111/`.
The first setup attempt rejected a group-writable scratch target before
building; private permissions corrected that. An initial MSRV correctness pass
used the older base source bundle and is excluded from current-source coverage.
Current crates/scripts were then supplied and archive identities checked for
both compiler runs. Both earlier records remain retained. No timing samples
were collected during any of these attempts, and no timing alarm was cleared.
