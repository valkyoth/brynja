# Hardened ParallelHash batch oracle adapters

Non-published development fixture. All CLI inputs and printed outputs are public
generated vectors; its ordinary CLI buffers are not an application secret-input
interface.

| Coverage | Behavior |
| --- | --- |
| Identities | ParallelHash128/256 and ParallelHashXOF128/256 |
| Input/output | Arbitrary canonical bits, partial-bit customization and output, bounded B |
| Profiles | Transactional public output and borrowed clearing secret output |
| Threading | One, two and three workers, independently of SIMD width |
| Local execution | Scheduled collector, byte-chunk stream, block-crossing stream, final-input-only stream |
| Routing | Portable root; portable/prefer/require hardened multibuffer leaves |
| Cleanup | Output Drop, full public scratch including excess capacity, destination canaries |
| Independent review | Not independently reviewed or FIPS validated |

Run from the repository root:

```sh
python3 scripts/cryptography/check-parallelhash-batch-oracle.py
python3 scripts/cryptography/test-parallelhash-batch-oracle.py
python3 scripts/cryptography/check-parallelhash-local-batch-oracle.py
python3 scripts/cryptography/test-parallelhash-local-batch-oracle.py
```

On a matching native machine, add `--lane amd-x86_64`, `--lane intel-x86_64`,
`--lane aws-aarch64` or `--lane apple-m2-aarch64` to both commands. The operator
remains responsible for stable CPU capabilities. These commands produce
development results, not native qualification receipts or release approval.

The driver reuses the independently composed Python SP 800-185 oracle for 256
bit-level cases across all four identities. Every case runs with each worker
count. Required mode selects 48 nonempty cases whose leaf count is divisible by
four, so no incomplete group requires a portable tail on AVX2 or NEON. All other
cases still run in portable/prefer modes; they are not dropped from coverage.

Each request compares public and secret outputs and their reports, checks exact
leaf/group/accelerated-leaf counts and reported worker width, then clears secret
output via Drop. The driver compares every output to the independent oracle and
requires nonzero vector work on accelerated campaigns. Reported thread width is
not a measurement of simultaneous CPU-core utilization or scheduler fairness.

Six compiled fixture mutants check skipped Drop, dirty scratch, corrupted output,
false SIMD routing, counter overflow and reduced worker count. Only temporary
fixture copies are changed. Mutants must build and restored source must pass.
The threaded driver does not exercise the separate scheduled/streaming APIs.

The `local` binary and local driver apply the same corpus and group eligibility
to those APIs in four layouts. Each uses both public and secret outputs, checks
scratch/output cleanup and canaries, and streams additionally check pending
storage clearing and rejection of updates after XOF finalization. A second
borrowed session reads the authority's actual vector-call counter, including
calls during consuming finalizers; scheduled reports must agree with it.
The root remains portable. Six compiled local-fixture mutations test output
Drop, encoded output, false routing, counter overflow, dirty pending storage and
skipped streaming updates. Each applicable layout is tested separately for all
four identities, so an early fixed-output failure cannot mask XOF paths.
These checks are not full lifecycle/compiler qualification or independent review.
