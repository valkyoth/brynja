# Exact fourth-alarm diagnostic — 2026-11-12

This is the completed [finite declaration](aes-fourth-alarm-declaration.md), not
a new acceptance campaign. All 32 invocations ran once. No trimming, sample
filtering, threshold changes, replacement runs or optional extension occurred.

The retained address-controls executable has SHA-256
`4b98b2d41e709b455a104729f442b07c3ec2349d18d827b19ca06d404373dbee`.
Only the three declared corpus stores differ in its identical-input copy;
instruction layout and the measured kernels are unchanged. Both preflights
passed independent AES checks (234 vectors each); all 117 patched class pairs
have equal values and outputs.

## Unfiltered primary comparison

The declared focus was AES-256 cached public-key. Values below use every sample
and the unchanged Welch/paired/noise policy, not the earlier exploratory trimmed
estimates. Differences are class 0 minus class 1.

| Binary | Launches | Mean difference (ns) | Alarm launches | Noise launches | Positive launch differences |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original | 16 | 0.5732803345 | 1 | 0 | 15 |
| Identical-input copy | 16 | 0.5970764160 | 1 | 1 | 15 |

The full [machine-readable replay](../../assurance/aes-native-observations/v0.27.3/fourth-alarm-identical-20261112.json)
retains every campaign summary and raw-file hash: 1,248 campaigns,
10,223,616 pairs and 20,447,232 durations. It includes padding strata and every
alarm/noise flag, not only the primary comparison. The compressed raw bundle
SHA-256 is `dfe2f851a2c1934c67d6e741f57946f707ed37c2ad6efc9d8d2559a64eaf1e02`.
It is retained locally at `target/aes-fourth-alarm-20261112/observation.tar.gz`
and remotely in the declaration's isolated workspace, not added as a large Git
object. The archive contains the frozen declaration, collector, preflight,
identity metadata and raw outputs. The local analyzer is
`target/aes-fourth-alarm-20261112/analyze.py`; its hash is recorded in the replay.

## Disposition

An alarm and similarly signed offsets remain with identical class values in a
copy of the exact fourth-alarm executable. Therefore this harness can distinguish
class/address/context without any input-value difference. Combined with the
independently replayed exploratory controls for the other three alarms, this
supports treating all four original observations as **confounded measurements**,
not established AES key/block-value dependence and not clean timing passes.

The result is not a formal equivalence test between binaries and does not exclude
a smaller coexisting value-dependent effect. It does not identify the precise
microarchitectural cause. The original alarm classifications and raw data stay
unchanged. The one noisy patched launch is retained, not replaced.

The exploratory audit separately replayed 800 raw crossover runs under the
original policy: 9,600 within-slot class comparisons had zero alarms and 318
noise flags; 9,600 slot comparisons had 935 alarms and 320 noise flags. These
runs were not predeclared acceptance evidence. Their independent replay is in
`target/aes-claude-review-20261112/crossover-replay.json`. The binary-patch audit
and independent preflight checks are in the same local review directory.

New observations follow the [shared-address value policy](aes-value-timing-policy.md).
The [DIT implementation](aes-dit.md) is separate production work, not an attempt
to erase an address-confounded alarm by changing the CPU setting.
