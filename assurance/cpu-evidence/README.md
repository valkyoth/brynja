# CPU Backend Evidence Records

This directory accepts committed, reproducible evidence only after an exact
backend implementation becomes a candidate. Version 0.13.3 intentionally
contains no `manifest.toml`: every backend remains unimplemented, unmeasured,
and unadmitted.

Each future run occupies one directory:

```text
assurance/cpu-evidence/<run-id>/
├── manifest.toml
└── raw/
    ├── forced-backend.txt
    ├── required-mode.txt
    ├── unsupported-feature.txt
    ├── known-answer.txt
    ├── quarantine.txt
    ├── scalar-differential.txt
    ├── concurrency-isolation.txt
    ├── emitted-code.txt
    ├── code-size.txt
    ├── cold-start.txt
    ├── latency.txt
    ├── throughput.txt
    └── side-channel.txt
```

The exact record fields, bounds, lane registry, workload sizes, harness
inventory, noise ceiling, order-balance rule, and admission thresholds live in
`../cpu-evidence-policy.toml`. Every raw artifact must be a regular file under
the run's `raw/` directory and match the size and SHA-256 recorded in the
manifest. Symlinks, paths outside the run, stale results, mixed logical CPUs,
missing feature evidence, non-finite values, noisy measurements, and false
native labels fail closed.

Validate a future run with:

```bash
scripts/validate-cpu-evidence.py assurance/cpu-evidence/<run-id>/manifest.toml
python3 scripts/check-cpu-evidence.py
```

QEMU runs may populate supplemental instruction-coverage evidence, but they
can never satisfy native performance or side-channel gates. An unavailable
runner or a CPU without the exact required ISA remains explicitly unadmitted
and never blocks the portable scalar build.
