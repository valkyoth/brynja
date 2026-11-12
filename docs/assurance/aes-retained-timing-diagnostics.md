# Retained ARM timing-data diagnostics — 2026-11-11

**Timing acceptance remains open.** These are exploratory, post-observation
descriptions of existing samples, not new acceptance criteria or fresh timing
measurements. No samples were removed, thresholds changed, production code
modified or measurement binaries executed.

## Reproduction and scope

The optional [offline analyzer](../../scripts/aes/analyze-aes-retained-timing.py)
reads the original MSRV/current ARM observations and the current
`separate-values` address-control observation. It verifies each raw measurement
file against the hash in its existing compact observation record, requires a
successful measurement process with no diagnostics, checks authority/control
markers, and uses the unchanged original parser to validate every sample's
campaign, index, class order and duration. It then reproduces and compares the
entire original summary, including every alarm and noise flag.

The [diagnostic record](../../assurance/aes-native-observations/v0.27.3/retained-timing-diagnostics-20261111.json)
contains all 117 campaigns / 958,464 pairs, not only the four non-noise alarm
campaigns highlighted below. Script, policy, source-record and raw-measurement
hashes bind the calculation. This is local diagnostic provenance, not an
authenticated external receipt. The raw files remain at the locations in the
[original results](aes-accelerated-fixed-random-results.md) and
[address-control results](aes-timing-address-controls-results.md).

With those artifacts present, reproduce to a new file with:

```sh
env -u LD_LIBRARY_PATH python3 scripts/aes/analyze-aes-retained-timing.py --output /tmp/aes-retained-review.json
```

The tool refuses to overwrite that file. Successful exit means the diagnostic
calculation completed, **not** that AES passed timing acceptance. It neither
updates `brynja-verify` nor adds a release gate. Twelve synthetic regressions
cover signed block arithmetic, zero variance, lag correlation, population and
transition accounting, digest validation, failed/incomplete measurements and
authority/control markers.

## Descriptive method and limits

For every campaign, the signed difference is **fixed minus random**, in
nanoseconds per original four-operation sample. The analyzer reports:

- both first-class order strata and all four transitions from the preceding
  pair's first class;
- all eight chronological 1,024-pair means;
- difference-series lag correlations at 1, 8 and 64 pairs;
- non-overlapping blocks of 64, 256 and 1,024 pairs, including sign counts,
  full-population mean, block-mean standard error and their signed ratio;
- the six most common recorded integer durations for each class, with counts.

All full-population statistics include every retained pair. The transition
description alone has 8,191 pairs because the first retained pair has no retained
predecessor; that omission is explicit and does not alter any verdict. Block
sizes divide the entire 8,192-pair campaign without trimming.

The windows/lags are diagnostic choices made after the original experiments.
No new statistical cutoff, corrected p-value, stationarity assumption or
independence guarantee is introduced. Block ratios are descriptive: a smaller
ratio cannot erase an original alarm, and adjacent blocks need not be independent.
The duration bins describe the recorded nanosecond values, not a measurement of
the hardware clock's resolution. These analyses cannot identify which
instruction, address, value or host condition caused a difference.

## Four retained non-noise alarms

| Campaign | Mean fixed minus random, ns | Same-sign 64-pair blocks | Same-sign chronological eighths | Means with fixed first / random first, ns |
| --- | ---: | ---: | ---: | ---: |
| Original MSRV AES-256 cached public-block | -1.2888 | 122/128 | 8/8 | -1.1728 / -1.4046 |
| Original current AES-192 cached decrypt-block | +2.5453 | 121/128, one zero | 8/8 | +2.6505 / +2.4416 |
| Original current AES-256 cached public-block | +0.4044 | 97/128 | 6/8 | +0.4130 / +0.3959 |
| Address-controls current AES-256 cached public-key | +0.7275 | 128/128 | 8/8 | +0.7831 / +0.6705 |

All four order-transition strata also retain each campaign's overall sign.
Therefore a simple imbalance in which class runs first does not explain away
the observed differences. In particular, the address-control signal is spread
through the run: its eight chronological means range from +0.6807 to +0.7744 ns,
and every 64-pair block is positive. It cannot be dismissed as one isolated
slow measurement.

The original current AES-192 decrypt campaign varies more over time: eighth
means range from +0.5049 to +7.4170 ns. The original current AES-256 public-block
campaign has two negative eighths despite a positive overall mean. Their
descriptive block ratios decrease with larger blocks, illustrating sensitivity
to grouping; this is **not** a replacement significance test or grounds to mark
either campaign passed. The exact original statistics and flags remain in the
record. No cause or exploitability conclusion follows from these descriptions.

## Harness finding and next review

Source and the [exact alarm-path inspection](aes-arm-alarm-path-review.md)
confirm class-correlated input locations in the original harness: the fixed and
random inputs occupy different entries of `pair`, passed by reference. The
timer also includes public operation selection, authority checks, staging and
cleanup around four operations. The cached-key constructor is outside the
cached-operation timer, but its schedule is consumed inside it. These are
real design confounders, not a demonstrated cause of any particular signal.

The separately executed address controls vary address sharing and input
equality, but absence of an alarm in another invocation does not identify the
cause in an earlier executable/environment. This review does not weaken that
boundary or silently convert the noisy controls into successful controls.

A focused independent review should address:

1. Whether class-dependent setup, locations or execution history can account
   for the exact retained signals; any explanation must identify its evidence,
   not rely solely on hardware AES or later green runs.
2. Whether the actual timer/operation paths leave an unreviewed dependency on
   key or block contents beyond the bounded inspection already recorded.
3. Whether a new, finite experiment can distinguish the remaining hypotheses,
   with its controls and decision rule declared before sampling. If the old
   environment cannot be reproduced, say what the new experiment can and cannot
   establish about it.

There is no demonstrated production defect to patch from this analysis alone.
There is also no justified timing pass. Retain the original evidence and keep
the [acceptance inventory](aes-acceleration-acceptance.md) open pending that
disposition. This is focused timing qualification work, not a requirement to
repeat unrelated AES correctness campaigns or introduce a mandatory HSM.
