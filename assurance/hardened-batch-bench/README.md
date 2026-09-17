# Hardened batch comparative benchmark

Non-published development fixture using public synthetic messages only. Its
ordinary reference buffers, comparisons and printed metadata must not be used
as a confidential-input application interface.

| Coverage | Implemented |
| --- | --- |
| Narrow SHA-2 | SHA-224/256, one through eight active slots |
| Wide SHA-2 | SHA-384/512, named /224 and /256, general t=17/224/256/511, one through four slots |
| Keccak family | All eight SHA-3/SHAKE/cSHAKE identities, one through four slots |
| Workloads | Empty, one block/rate, 4096 and 16384 bytes; balanced and unequal lengths |
| Output | Typed secret owners, validated public-vector bytes, clearing Drop, inactive slots and canaries |
| Acceleration | Separate default-off hardened AVX2/NEON owners; actual vector work checked |
| Independent review / FIPS | No / no |

From the repository root:

```sh
python3 scripts/cryptography/check-hardened-batch-bench.py
python3 scripts/cryptography/test-hardened-batch-bench.py
```

On a matching native host, add `--lane amd-x86_64`, `--lane intel-x86_64`,
`--lane aws-aarch64` or `--lane apple-m2-aarch64` to each command. The driver
checks the platform bundle before enabling target features. Stable scheduling
and CPU capabilities remain deployment obligations. Without a lane the driver
uses a generic build and compares two portable executors, not accelerated work.

The benchmark covers 640 workload rows. Each row warms both routes, alternates
their order over seven samples and retains both medians, even when the selected
route loses. Threshold 1 is an explicit test setting, not a recommended crossover.
Every timed invocation includes digest execution, public-reference validation
and secret-output Drop. Allocations, authority construction/KAT, input/output
poisoning, cleanup checks and formatting are outside the timer. Keccak also
checks all caller staging, including excess capacity, after each invocation.
An incorrectly unchanged output is rejected because destinations start with
the bitwise complement of the expected bytes.

Finite work reports must match charged work. Actual SIMD calls must remain
stable across samples. The driver checks every row's family/identity/shape,
exact SHA-2 common-block vector work and Keccak vector eligibility, rejects
missing/duplicate rows, and never rejects a result just because it is slower.
The standalone regression runner also compiles six temporary fixture mutations;
compilation failures do not count as runtime rejection, and restored source
must pass again.

This is a comparison to hardened portable batching, not an independent digest
oracle, a dedicated single-stream-instruction comparison, a threaded ParallelHash
benchmark, a constant-time test or native qualification receipt. Seven samples
are exploratory, not statistical confidence or a universal throughput claim.
Use an otherwise idle host and retain raw results. Production APIs, release
gates and publication rules are unchanged.
