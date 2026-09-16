# Hardened SHA-512-family batch oracle adapter

Development-only, non-published fixture for the distinct hardened batch APIs.
Input and printed output are public test vectors, never real confidential data.
The fixture does not provide an application-facing secret-input protocol.

| Coverage | Behavior |
| --- | --- |
| Algorithms | SHA-384, SHA-512, named /224 and /256, general SHA-512/t |
| Input | Four optional slots, canonical arbitrary bits, bounded input lines |
| Output profiles | Borrowed secret outputs, explicit declassification, direct public outputs |
| Lifecycle | Exact identity/width, output Drop clearing, consumed-output clearing, inactive capacity |
| Execution | Portable or hosted prefer/require; explicit AVX2/NEON build bundle |
| Independent review | Not independently reviewed or FIPS validated |

Run from the repository root:

```sh
python3 scripts/cryptography/check-hardened-sha512-batch-oracle.py
python3 scripts/cryptography/test-hardened-sha512-batch-oracle.py
```

On a matching native host, add `--lane amd-x86_64`, `--lane intel-x86_64`,
`--lane aws-aarch64` or `--lane apple-m2-aarch64` to both commands. The check
requires the corresponding CPU feature bundle; the operator remains responsible
for stable platform capabilities. This is development execution, not a native
qualification receipt or release-gate change.

The driver reuses the existing independent Python SHA-512/t and bit-level SHA-2
oracle corpus: 4,846 mixed batches, including all 510 valid t values, sparse slots
and padding boundaries. Required mode runs the 4,590 eligible full batches;
short/sparse cases still run in portable/prefer mode. Three real API calls per
batch check secret/declassified/public agreement; the driver checks every printed
digest against the independent answer and validates performed-vector counters.
The compiled regressions copy the fixture into temporary storage, never edit
production sources, and reject skipped Drop, corrupted output, false SIMD routing
and counter overflow before rechecking restored source.
