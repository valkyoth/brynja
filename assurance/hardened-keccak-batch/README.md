# Hardened Keccak-family batch oracle adapter

Non-published development fixture. CLI messages, names, customizations and printed
outputs are public generated test vectors, not confidential application data.
The ordinary CLI buffers do not provide an application secret-processing API.

| Coverage | Behavior |
| --- | --- |
| Algorithms | SHA3-224/256/384/512, SHAKE128/256, cSHAKE128/256 |
| Input | Four optional slots, mixed domains/rates, arbitrary-bit message/N/S |
| Output | Fixed digests and finite XOF bits, including zero and partial bytes |
| Profiles | Borrowed secret outputs, consumed declassification, direct public outputs |
| Lifecycle | Identity/bit/byte widths, Drop/declassification clearing, full staging, canaries |
| Execution | Portable and explicit hosted prefer/require AVX2/NEON |
| Independent review | Not independently reviewed or FIPS validated |

Run from the repository root:

```sh
python3 scripts/cryptography/check-hardened-keccak-batch-oracle.py
python3 scripts/cryptography/test-hardened-keccak-batch-oracle.py
```

Add `--lane amd-x86_64`, `--lane intel-x86_64`, `--lane aws-aarch64` or
`--lane apple-m2-aarch64` to both commands on a matching native host to exercise
SIMD and compiled regressions. Stable CPU capabilities remain an operator
obligation. This is development execution, not a native qualification receipt
or release-gate change.

The existing independent Python FIPS 202/SP 800-185 oracles provide 256 full
mixed batches and are cross-checked against pinned NIST vectors. Sixteen extra
batches cover every activity mask and distinguish inactive slots from active
zero-bit XOF outputs. Required SIMD runs the full batches; portable/prefer modes
also run sparse batches. Every batch exercises three real output/lifecycle calls.
The complete staging buffer, including its excess capacity, must clear; extra
destination canaries must remain unchanged.

The result checker rejects missing/incorrect outputs, counts and routing markers.
Compiled fixture mutations check skipped Drop, dirty staging, corrupted encoding,
portable routing masquerading as SIMD and counter overflow. Each mutant must
compile; restored source must pass afterward. Only temporary fixture copies are
modified, never production sources.
