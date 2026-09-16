# Hardened SHA-224/256 batch oracle adapter

Non-published development fixture for the distinct hardened batch APIs. All CLI
input and printed digests are public generated test vectors, not confidential
application data. Its ordinary CLI buffers are not secret owners.

| Coverage | Behavior |
| --- | --- |
| Algorithms | Mixed SHA-224 and SHA-256 lanes with their distinct IVs |
| Input | Eight optional slots, canonical arbitrary bits, bounded input lines |
| Output | Borrowed secret outputs, consumed declassification, direct public outputs |
| Lifecycle | Exact identity/width, Drop/declassification clearing, inactive capacity |
| Execution | Portable or hosted prefer/require; explicit AVX2/NEON build bundle |
| Independent review | Not independently reviewed or FIPS validated |

Run from the repository root:

```sh
python3 scripts/cryptography/check-hardened-sha256-batch-oracle.py
python3 scripts/cryptography/test-hardened-sha256-batch-oracle.py
```

Add `--lane amd-x86_64`, `--lane intel-x86_64`, `--lane aws-aarch64` or
`--lane apple-m2-aarch64` to both commands on a matching native machine to
exercise SIMD and compiled regressions. The operator remains responsible for
stable platform capabilities. Execution here is development evidence, not a
native qualification receipt, independent security review or release-gate change.

The driver reuses the existing independent Python SHA-2 bit oracle corpus. Its
384 batches cover every eight-slot activity mask, both algorithm identities,
partial bits, unequal lengths and padding boundaries. Required mode runs the
128 full batches with eligible message blocks; short/sparse cases run in portable
and prefer modes. Every batch exercises three output/lifecycle paths and compares
all printed digests with the independent oracle. Vector counters must be zero
for portable execution and nonzero for the accelerated campaigns.

Compiled regressions copy this fixture into temporary storage and check skipped
Drop, corrupted output, false SIMD routing and counter overflow. Production
sources are not edited; restored source must pass after each mutation.
