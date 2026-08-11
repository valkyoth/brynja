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
    ├── forced-backend.json
    ├── required-mode.json
    ├── unsupported-feature.json
    ├── known-answer.json
    ├── quarantine.json
    ├── scalar-differential.json
    ├── concurrency-isolation.json
    ├── emitted-code.json
    ├── code-size.json
    ├── cold-start.json
    ├── latency.json
    ├── throughput.json
    └── side-channel.json
```

The exact record fields, bounds, lane registry, workload sizes, harness
inventory, noise ceiling, order-balance rule, and admission thresholds live in
`../cpu-evidence-policy.toml`. Every raw artifact must be a regular file under
the run's `raw/` directory and match the size and SHA-256 recorded in the
manifest. Every JSON document has an exact schema and must match the run,
source commit, measured binary, backend, lane, primitive, operation, complete
manifest context, declared status, and harness-specific measurements. Symlinks,
paths outside the run, stale results, mixed logical CPUs, missing feature or
exact operating-state evidence, non-finite values, noisy measurements, and
false native claims fail closed.

These files prove only repository integrity and internal schema consistency.
They do not authenticate who ran a harness or prove that it executed. No
trusted-runner trust root or reviewed signature verifier is admitted in
v0.13.3, so every candidate status and every native performance, side-channel,
or admission claim is rejected. A future schema revision must bind a verified
attestation to the source, measured binary, environment, manifest, and artifact
hashes before any backend can become eligible.

Validate a future run with:

```bash
scripts/validate-cpu-evidence.py assurance/cpu-evidence/<run-id>/manifest.toml
python3 scripts/check-cpu-evidence.py
```

QEMU runs may populate supplemental instruction-coverage evidence, but they
can never satisfy native performance or side-channel gates. An unavailable
runner or a CPU without the exact required ISA remains explicitly unadmitted
and never blocks the portable scalar build.
