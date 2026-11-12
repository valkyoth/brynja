# Integrated accelerated AES timing observations — 2026-11-10

**Timing acceptance remains open. None of these four observations is a pass.**
All four predeclared direct/static configurations completed their full sample
population once. No sample was discarded, no threshold changed and no failed
observation was repeated. This is a development investigation, not a new
publication gate or a claim that an exploitable side channel has been proved.

The [experiment declaration](aes-accelerated-fixed-random.md) fixes the policy.
The [compact observation record](../../assurance/aes-native-observations/v0.27.3/integrated-fixed-random-20261110.json)
contains every campaign summary, host context, compiler, package and binary
identity, and raw artifact hashes. All four summaries were reproduced locally
from the retained raw output. Binary hashes, generated-fixture hashes, common
package hashes and the 234 oracle comparisons per observation were rechecked.

## Results

Each observation contains 39 campaigns × 8,192 fixed/random pairs, with four
operations per timed sample. The four observations retain **1,277,952 pairs**
(2,555,904 timed samples), excluding warmup.

| Host | Compiler | Alarm campaigns | Noise-inconclusive campaigns | Disposition |
| --- | --- | ---: | ---: | --- |
| AMD Ryzen 9 9950X3D | 1.90.0 | 0 | 5 | Inconclusive |
| AMD Ryzen 9 9950X3D | 1.99.1 | 0 | 6 | Inconclusive |
| AWS Neoverse-V2 | 1.90.0 | 1 | 5 | Alarm; additional noisy campaigns |
| AWS Neoverse-V2 | 1.99.1 | 2 | 6 | Alarms; additional noisy campaigns |

The three alarm campaigns are **not** noise-flagged. Noise elsewhere cannot
dismiss them. Mean durations below describe a four-operation sample, not one
AES operation:

| ARM compiler | Campaign | Fixed mean ns | Random mean ns | Absolute Welch t | Absolute paired t |
| --- | --- | ---: | ---: | ---: | ---: |
| 1.90.0 | AES-256 cached public-block | 96.319 | 97.608 | 40.096 | 46.240 |
| 1.99.1 | AES-192 cached decrypt-block | 164.397 | 161.852 | 5.035 | 5.048 |
| 1.99.1 | AES-256 cached public-block | 99.232 | 98.827 | 8.943 | 12.926 |

The fixed/random difference persists with the same sign within both first-class
order strata and both chronological halves of each alarm campaign. This is an
exploratory, post-observation diagnostic of the original samples, not a changed
acceptance test. It does not identify the cause or establish exploitability.
The AES-256 public-block difference reverses sign between compilers.

The AMD noise flags include long individual delays relative to sub-microsecond
samples. For example, the first MSRV ephemeral campaign has a 50,706 ns maximum
against a roughly 280 ns class mean. Such delays exceed the declared coefficient
of variation limit; they are retained, not trimmed or attributed to a particular
host cause without evidence.

## Correctness and tooling are separate

All eight host/compiler/direct-or-facade correctness configurations passed:
four Rust fixture tests and 234 independent OpenSSL comparisons per configuration.
The local four are registered under `aes-accelerated-timing-fixture`; those
passes establish fixture correctness only. They must not be interpreted as
timing passes. The tooling/registry suite passed 797 tests, including eleven new
adapter/orchestration regressions and the existing shared timing-policy tests.

One initial local correctness build failed on a test-fixture error conversion
from a boxed error to `String`. The conversion was corrected before the run
declaration and before any measurements. Its `tests.json` remains in
`target/aes-accelerated-fixed-random/check-1.90.0-direct-8awifl4l/`.
Production cryptographic code did not change in this slice.

## Retained artifacts

- Local AMD directories:
  `target/aes-accelerated-fixed-random/amd-integrated-{msrv,current}-20261110`.
- AWS source directory: `/home/ubuntu/brynja-aes-timing-0273-PN3WyGPI`.
- Retrieved ARM logs and artifacts:
  `target/aes-native-timing-20261110/aws/`.
- Source bundle: `target/aes-accelerated-timing-source-20261110.tar.gz`, SHA-256
  `7a90292b5bf4aa89bb133090a2f4175ec9f707d7c6f574f09882d674955fc6b8`.
- Retrieved ARM bundle: `target/aes-native-timing-20261110/observations.tar.gz`,
  SHA-256 `7579c570d29768d76e9360ae7c7ea23c2b301be90bab05e9c1fdf8db038804ae`.

The measured binaries use byte-checked working-tree packages based on
`56a1b7805c9517fbdb5e3c28b137ea8c9108cf7e`, not a clean tagged checkout.
Raw samples and binaries remain local artifacts; the compact record is not an
authenticated external receipt. GNU targets are measured; prior musl linked
reviews do not qualify these complete GNU timing executables automatically.

## Required investigation before timing closure

1. Inspect the exact retained timing executables, including the wrapper and
   timer boundaries, not just previously reviewed AES assembly bodies.
2. Investigate the fixture's class-correlated input addresses: the two classes
   occupy different entries in `pair`, passed by reference into the trial.
   Address/cache/layout effects are a possible confound, **not an established
   explanation**. Also consider clock resolution, optimizer effects and host
   conditions without assuming any of them explains the alarms.
3. If a controlled follow-up is needed, declare its purpose, input-address
   controls, fixed workload, thresholds and finite run list before collecting
   new samples. Preserve these original observations and distinguish a new
   experiment from retrying this one to pass.
4. Any actual code or harness defect needs a tested fix. Do not relax the
   threshold or label these results green merely because functional tests pass.
