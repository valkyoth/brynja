# Post-collection DIT sensitivity and scope review — 2026-11-12

This addendum addresses the owner-supplied review of the
[finite results](aes-dit-finite-results.md). It does not change a declaration,
sample, threshold or original verdict. Both host screens remain inconclusive.
No new timing measurements were collected. **Zero observed alarms does not
exclude the historical sub-nanosecond to few-nanosecond effects.**

## Observed threshold scales, not statistical power

For every campaign in all 64 launches, the offline helper
`scripts/aes/describe-aes-dit-sensitivity.py` checks the original result/process/
output hashes, reproduces the frozen strict-parser result, then computes:

```text
Welch scale = 4.5 × sqrt((variance(fixed) + variance(random)) / 8192)
Paired scale = 4.5 × sqrt(variance(fixed - random) / 8192)
```

These are the observed mean-difference scales corresponding to the cutoff at
the observed standard errors. They are **not** a minimum detectable effect,
an upper bound on leakage or a power calculation at a specified false-negative
rate. Noise, sample dependence and changing variance matter. Zero standard
error is explicitly labelled degenerate, not perfect sensitivity.

Medians across both compilers and all four `shared-values` launches per compiler
(units: ns per **four-operation duration**, not per block):

| Host / owner | Campaign observations | Welch scale | Paired scale |
| --- | ---: | ---: | ---: |
| Linux / cached | 144 | 6.104 | 6.152 |
| Linux / ephemeral | 144 | 14.011 | 13.997 |
| Linux / cached import | 24 | 13.082 | 13.116 |
| Apple / cached | 144 | 3.195 | 2.883 |
| Apple / ephemeral | 144 | 19.353 | 17.501 |
| Apple / cached import | 24 | 22.452 | 19.957 |

The historical roughly 0.4–2.5 ns effects are below these medians. Individual
campaign scales differ; a median is not a bound for every campaign. A zero
alarm count cannot establish their absence. The complete per-campaign scales
are retained for [Linux](../../assurance/aes-native-observations/v0.27.3/dit-finite-linux-sensitivity-20261112.json)
and [Apple](../../assurance/aes-native-observations/v0.27.3/dit-finite-apple-sensitivity-20261112.json).

## Post-hoc trimmed descriptions

The helper additionally reports the difference of independently trimmed class
means and the trimmed mean of paired differences, with 81 values removed from
**each tail** of each 8,192-element sequence (integer floor of 1%). These are
labelled post-observation diagnostics for every campaign. They never replace
untrimmed input to the frozen statistic, discard the original samples or
produce a new pass/fail verdict. This estimator was not predeclared.

Selected Rust 1.90.0 Linux descriptions below are the trimmed **class-mean
differences**, fixed minus random, in round order 1–4, ns per duration:

| Campaign | Separate values | Separate identical |
| --- | --- | --- |
| AES-256 ephemeral public-key | −3.417, −3.285, −3.429, −3.387 | −3.403, −3.271, −3.378, −3.319 |
| AES-256 ephemeral public-block | −3.319, −3.303, −3.385, −3.364 | −3.354, −3.217, −3.488, −3.364 |
| AES-256 cached encrypt-block | −1.172, −1.243, −1.132, −1.158 | −1.181, −1.134, −1.279, −1.173 |

The report's generic “public path” row mixed the public-key value sequence
with the public-block identical sequence. Both correctly labelled paths are
shown here; the broad sensitivity concern remains. Each listed original
population had zero frozen alarms. The similar offsets for identical inputs
do not require a secret-value difference and expose a limitation of interpreting
zero alarms as absence of stable small address/context effects. Exact hardware
causation is not established by these post-hoc estimates.

The selected shared-identical AES-192 ephemeral public-key description is
−0.839, −1.600, −1.197, −1.360 ns. Its post-hoc selection and the large number of
possible contrasts prevent treating it as a separately validated discovery.
It reinforces the need not to overstate shared-address cancellation.

## Raw-kernel scope and capacity

DIT is enabled around raw AES expansion and round kernels. Destination
clearing, key/block staging, output copy and scratch cleanup run under the
caller's prior DIT state, which may be on or off. An ephemeral block operation
uses separate expansion and transform scopes. This is not whole-owner/API
timing qualification, and x86 AES-NI selection carries no whole-wrapper timing
guarantee either.

The existing entry/readback/ISB/restoration sequence has a material cost that
deployments must measure for capacity and deadlines. The hosted default
`IfAvailable` may also enable DIT on supported ARM hosts; overhead is **not**
limited to callers explicitly selecting `Require`.

A descriptive comparison of the retained original GNU/Linux 1.99.1 record
`aws-arm-integrated-current-20261110` with the four new musl/Linux 1.99.1
`shared-values` launches gives the following. For each matching campaign, take
the average of the two class means, the median across the four new launches,
subtract the old mean and divide by four; then take the median across campaigns
within that owner family:

| Owner | Old campaign means (ns/duration) | New median campaign means (ns/duration) | Median difference (ns/operation) |
| --- | --- | --- | ---: |
| Cached | 90.463–177.075 | 363.195–462.589 | +68.400 |
| Ephemeral | 885.023–1289.577 | 1288.722–1691.666 | +101.941 |
| Cached import | 1318.050–1778.773 | 1614.887–2089.700 | +76.908 |

The old record's `summary.json` hash and contents were checked against
`integrated-fixed-random-20261110.json` (record SHA-256
`e05a0aafa5cac7e014ff50eac62b6ddef7b40b0b814b1d07dc2c51e863e8f523`).
This comparison changes executable, address policy, libc/target, host instance
and observation time. It is **not a controlled measurement of DIT-only cost**
and does not establish that the entire difference comes from DIT barriers.
It motivates capacity qualification, not a new remotely exploitable DoS claim.
Application admission limits and deadlines must account for the selected path;
no capacity or DoS-resistance guarantee follows from this screen.

Widening scopes, avoiding redundant nested writes or removing ISBs would change
the implementation and require architecture-specific reasoning and renewed
correctness/linked review. No such optimization is justified solely by this
historical comparison. The present conservative scope is retained without
claiming that its ISBs are architecturally mandatory.

## Validation

Seven added regressions cover exact standard-error formulas, degenerate
populations, tail counts, preserved untrimmed verdicts and samples, shifts,
invalid populations and hash rejection before analysis. The full registry
suite passes 995 tests. Both original JSON result hashes, the collector,
population/statistic parser and frozen declaration remain unchanged.
