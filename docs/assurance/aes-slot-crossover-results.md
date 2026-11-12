# ARM class/address crossover results — 2026-11-12

Disposition: **diagnostic experiment completed; timing acceptance remains
open**. The two predeclared invocations completed once each on the new ARM
host. There were no retries, filtered samples or threshold changes. One
conditional comparison raised a non-noise slot-related alarm; four comparisons
were noise-flagged. These results do not clear the earlier four ARM alarms.

## Scope and retained evidence

The [frozen declaration](aes-slot-crossover-declaration.md) was copied to the
host before sampling and has SHA-256
`f40c5321531863f8e276e1236ab0cc452c85c9cc0a88a9f33575128d47c4fa0f`.
It names both reviewed executables, original source/fixture identities, exact
commands, compiler/control order, CPU 0 affinity, timeout and analysis rules.
Both restored binaries passed 576 independent oracle cells on the fresh host
before measurement. All before/after binary hashes matched. Production code
was not rebuilt or changed for this experiment.

The [compact observation record](../../assurance/aes-native-observations/v0.27.3/crossover-observation-20261112.json)
retains all 48 conditional comparison summaries, actual addresses, interactions,
eight order strata and eight chronological strata per control, plus log and
artifact hashes. Full raw output and host context are retained locally under
`target/aes-crossover-native-20261112/observation/` and remotely under
`/home/ubuntu/brynja-aes-crossover-0273-9G4pbevM/observation/`.
The raw bundle SHA-256 is
`75be676f7db1c235384601bf5e7fe122b03443454c8968eca616c96ba3762a32`.
These locations are not a durable external archive.

The host is the owner-confirmed fresh Neoverse-V2 instance `13.49.18.65`.
It is not the original alarm host. The declaration and per-run host logs
identify Linux/glibc/loader context; CPU governor and boost state were
unavailable. Load before collection was approximately `0.03 0.05 0.01`.
Cloud scheduling and physical-machine sharing are uncontrolled. No exclusive
or physically qualified environment is claimed.

Both invocations started and completed within the wall-clock second
`2026-11-12T15:36:24Z`; the per-cell clock retains nanosecond durations.
Each stdout contains 49,167 lines including authority, policy, address and
completion records. Both exit codes are zero and both stderr files empty.
Strict parsing accepted six controls per compiler, 8,192 rounds per control,
four cells per round: **393,216 durations**, with no dropped records. Each
duration brackets four AES operations. The fixture reports the same two
stable 48-byte-stride input slots across the six controls within each process.

## All control outcomes

Each row below summarizes four comparisons: class at each slot and slot within
each class. `Largest statistic` is the maximum absolute Welch/paired statistic
across those four comparisons, not a selected passing comparison. The linked
JSON retains every statistic and both CVs. Thresholds remain 4.5 for alarms
and 1.0 for CV noise; no overall timing-pass verdict is inferred.

| Compiler | Cached path | Control | Largest statistic | Alarm comparisons | Noise comparisons |
| --- | --- | --- | ---: | ---: | ---: |
| 1.90.0 | AES-192 decrypt-block | values | 4.225 | 0 | 0 |
| 1.90.0 | AES-192 decrypt-block | identical | 1.088 | 0 | 0 |
| 1.90.0 | AES-256 public-block | values | 1.017 | 0 | 0 |
| 1.90.0 | AES-256 public-block | identical | 1.355 | 0 | 0 |
| 1.90.0 | AES-256 public-key | values | 0.449 | 0 | 0 |
| 1.90.0 | AES-256 public-key | identical | 0.856 | 0 | 0 |
| 1.99.1 | AES-192 decrypt-block | values | 12.582 | 1 | 2 |
| 1.99.1 | AES-192 decrypt-block | identical | 1.623 | 0 | 0 |
| 1.99.1 | AES-256 public-block | values | 1.790 | 0 | 0 |
| 1.99.1 | AES-256 public-block | identical | 0.766 | 0 | 2 |
| 1.99.1 | AES-256 public-key | values | 0.600 | 0 | 0 |
| 1.99.1 | AES-256 public-key | identical | 1.853 | 0 | 0 |

### Slot-related alarm

For current-compiler AES-192 decrypt-block, `values`, the fixed class has
mean cell durations **153.072754 ns at slot zero versus 152.584351 ns at slot
one**, difference **+0.488403 ns**. Welch is **12.503195** and paired is
**12.582306**, with CVs **0.016231 / 0.016485**. This is a non-noise alarm
comparing the same fixed key/block at different input slots, not a detected
fixed-versus-random AES timing difference. It supplies evidence of slot/context
sensitivity in this new fixture, but does not identify the responsible machine
effect or explain the earlier executables' signals.

The corresponding MSRV slot comparison is below the frozen threshold
(Welch 4.224855, paired 4.214671). It is retained as recorded, not promoted to
an alarm by rounding or given a new threshold.

### Noise and class comparisons

No within-slot class comparison crossed the alarm threshold. This is not proof
that class effects are absent: the current AES-192 values slot-zero class
comparison is inconclusive, with random-slot-zero CV **1.723780** and maximum
duration **24,494 ns**. The slot comparison within the random class shares
that cell and is also noise-flagged.

For current AES-256 public-block's identical-input control, the fixed-label
slot-one cell has CV **1.199777**, maximum **10,142 ns**. Its within-slot class
comparison and fixed-label slot comparison are the other two noise flags.
They are two comparisons sharing one noisy cell, not independent observations.
All long-duration samples remain included; none is removed as an assumed
interrupt or scheduler event.

## Retained-data follow-up review

This follow-up uses the already recorded order patterns and chronological
eighths. It is a same-implementation review, **not independent approval**.
No native executable was run, samples removed, or acceptance statistic added.

For the current-compiler AES-192 values control, fixed-slot-zero minus
fixed-slot-one is positive in all eight chronological eighths, ranging from
**+0.293945 to +0.784180 ns** per four-operation duration. It is not confined
to one time segment. Across the eight balanced order patterns, however, the
differences are:

| Pattern | Fixed slot-zero minus slot-one, ns |
| --- | ---: |
| 0 | +1.248047 |
| 1 | -0.432617 |
| 2 | +0.593750 |
| 3 | +0.571289 |
| 4 | +1.408203 |
| 5 | -0.475586 |
| 6 | +0.707031 |
| 7 | +0.287109 |

Each pattern contains 1,024 rounds. These are descriptive means, not eight
new significance tests. The two negative patterns prevent treating the
aggregate difference as a uniform address penalty independent of order.
The source materializes both slots before each mapping stage and balances
mapping and first-class order, but that does not equalize all prior execution
history or machine state. The exact linked review places materialization and
cached-key construction before the timer; their effects on the following
timed work are not thereby excluded.

The identical-input control uses the same slot addresses within the process,
but was collected later as a separate control. Its absence of an alarm is
not a simultaneous counterfactual for the values control. Compiler comparisons
also change binary layout and observed input alignment: key/block addresses
modulo 64 are `(48, 16), (32, 0)` on MSRV and `(0, 32), (48, 16)` on current.
These are address arithmetic observations, not proof of a cache-line effect.
Neither comparison isolates an instruction-level cause.

The unchanged strict parser reproduces every recorded comparison from raw
output, including the one alarm and four noise flags. The frozen declaration,
collector, parser, policy and retained artifacts still match their recorded
hashes. This establishes reproducibility of the summaries, not independence
of samples, correctness of a causal explanation, or timing acceptance.

## Interpretation and next boundary

The new slot alarm shows why class-to-address assignment matters to a short
timing harness. However, the values control also contains noise, and the
identical control does not reproduce a significant slot alarm. This does not
establish a clean slot-only explanation, much less transfer one to the old
host, runtime and binary layouts. All earlier alarms and noisy observations
keep their prior disposition.

The finite experiment is complete. Do not add samples until a desired result
appears. A focused independent review can now use the
[original alarm-path review](aes-arm-alarm-path-review.md),
[retained population diagnostics](aes-retained-timing-diagnostics.md),
[crossover linked review](aes-slot-crossover-linked-review.md), declaration and
these unfiltered results. A justified harness correction or production defect
has not been established. A decision to narrow timing claims or accept residual
qualification risk belongs to the owner; it is not implied by functional
correctness or this experiment. No new publication gate or hardware-provider
requirement is introduced.

For the next independent pentest review, the bounded questions are:

1. Does any actual successful timed path use key/block contents in a branch,
   address calculation or variable-work operation missed by the exact-binary
   reviews? Name the executable hash and instruction/source path for a finding.
2. Does the retained evidence establish a particular harness defect, rather
   than merely a possible confounder? Distinguish the four original alarms
   from the new slot alarm and retain the noisy comparisons.
3. If neither is established, state that the cause remains unresolved and
   identify the claim that cannot be supported. Do not turn later non-alarming
   runs into clearance, prescribe an unbounded rerun, or infer a physical
   protection guarantee from functional tests.

A reviewer may conclude that further work or an explicit scope decision is
needed. This handoff does not approve such a decision, close other measured-path
coverage, or change the existing release process.
