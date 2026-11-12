# DIT-required finite shared-address screen — 2026-11-12

**Disposition: complete collection, timing screen inconclusive on both hosts.**
There were no above-threshold shared-input alarms, but the frozen noise rule
was not satisfied. This is not a timing pass or release approval.

**Post-collection clarification:** the [sensitivity/scope addendum](aes-dit-sensitivity-review.md)
quantifies observed cutoff scales, small trimmed address/context offsets and
the historical latency contrast. Zero alarms does not exclude the earlier
0.4–2.5 ns effects. Raw-kernel DIT does not cover all wrapper handling. The
addendum preserves the original declarations, samples and verdicts.

The [frozen declaration](aes-dit-finite-declaration.md) was followed once:
four rounds, two compilers, four controls, 32 processes per host. The reviewed
executables were not rebuilt, and baseline DIT probes succeeded before any
measurement. All process exits were successful, stderr was empty, hashes
matched, and the strict parsers accepted every sample population and order.
No retries, omitted launches, trimming, pooling or changed thresholds occurred.

Linux collection ran from 17:53:52 to 17:54:30 UTC on Neoverse-V2, pinned to
CPU 0. Apple collection ran from 17:53:54 to 17:54:53 UTC on M2 Pro with normal
OS scheduling and no affinity claim. The complete dataset contains 2,496
campaign observations, 20,447,232 pairs and 40,894,464 retained durations.

## All-control totals

Each row is eight process launches / 312 campaign observations across both
compilers. Counts are campaign observations, not distinct cryptographic defects.

| Host | Control | Alarms | Noise flags | Role / disposition |
| --- | --- | ---: | ---: | --- |
| Linux ARM | shared-values | 0 | 1 | Required comparison; inconclusive |
| Linux ARM | shared-identical | 0 | 0 | Required negative control; clean in this finite sample |
| Linux ARM | separate-values | 0 | 4 | Address/context diagnostic, not a timing pass |
| Linux ARM | separate-identical | 0 | 2 | Address/context diagnostic, not a timing pass |
| Apple | shared-values | 0 | 20 | Required comparison; inconclusive |
| Apple | shared-identical | 0 | 16 | Required negative control; inconclusive |
| Apple | separate-values | 4 | 25 | Address/context diagnostic, not a timing pass |
| Apple | separate-identical | 5 | 18 | Address/context diagnostic, not a timing pass |

Linux's single shared noise flag is round 2, Rust 1.90.0, cached AES-256
`public-key`. Fixed/random means were 361.775/368.132 ns; maxima were
4,986/57,670 ns. The random-class CV was 1.728, above the declared 1.0 limit;
Welch and paired absolute statistics were about 0.897, below 4.5. These
descriptions retain the long delay; they do not justify deleting it or establish
its cause. No value-dependence alarm was observed in that population.

Apple shared-control noise occurs with both compilers and across multiple key
sizes and owner/operation routes, including identical-input populations.
All nine separate-address alarms are on Rust 1.90.0 and are not noise-flagged.
Five occur with identical inputs. That demonstrates that these diagnostic
alarms do not require a secret-value difference; it does not identify the
microarchitectural cause or prove every other effect is benign. No diagnostic
offset is subtracted from a required comparison.

## Reproducibility and retention

The [Linux results](../../assurance/aes-native-observations/v0.27.3/dit-finite-linux-results-20261112.json)
and [Apple results](../../assurance/aes-native-observations/v0.27.3/dit-finite-apple-results-20261112.json)
retain every launch's command, times, exit status, raw-output hashes and all
39 campaign statistics. Both contain `screen_passed: false`. These are
unauthenticated local observations, not signed certification evidence.

Full stdout/stderr and process metadata remain on both builders at their
declared destinations and locally under `target/aes-dit-finite-20261112/`
(`linux/` and `apple/`). The approximately 946 MiB of raw files are Git-ignored;
the two bounded result records together are about 1.36 MB. Reanalyze with
`scripts/aes/analyze-aes-dit-finite.py DIRECTORY DECLARATION SHA256 NEW_OUTPUT`.
The analyzer checks frozen tool hashes and retained command/output integrity,
delegates to the original strict population/statistics parsers, and cannot
collect measurements. Its output destination must be new.

Frozen declaration hashes:

- Linux JSON: `41c5e33426f32d14be2e6b683989459adfaabc083f089286ca14bd82d9829cc0`
- Apple JSON: `87dbf26fe08958bfc4f4406b372cfb6d293a93e5fec81102e615a6785ab62067`
- Prose declaration: `ae33c2c54a6c3ce52ddcdd41babc0146fb78c398c7e4d1943276a5cc8331b9ba`

The bounded review in `aes-dit.md` is the frozen pre-measurement checkpoint;
its final “remaining” paragraph describes that checkpoint, not current status.
This result record supersedes the pending collection item without editing the
hash-bound checkpoint or earlier evidence.

## Tests and next decision

The collector's 11 regressions cover finite ordering, no retries after errors
or timeouts, retention of partial output, capability rejection, hash changes,
no destination reuse and Linux affinity restoration. Eight analyzer regressions
cover every-launch analysis, shared alarm/noise rejection, separate diagnostic
retention, malformed data, tampering, wrong markers and incomplete/extra runs.
The complete verification-registry suite passes **988 tests**; the existing
accelerated timing-tool suite passes **44 tests**. No production Rust changed
in this collection/analysis step.

The next step is an explicit review of this **inconclusive** disposition, not
another attempt to get a clean launch. Functional DIT support and the bounded
machine-code review remain separate completed work. Continuing toward release
with incomplete timing qualification requires an explicit owner scope/risk
decision; requiring a stronger timing claim instead requires a separately
designed, prospective experiment. Neither choice can rewrite these results.
No mandatory HSM, new military profile or additional publication gate is added.
