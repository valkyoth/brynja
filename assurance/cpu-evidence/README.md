# CPU Backend Evidence Records

This directory accepts committed, reproducible evidence for exact backend
candidates. Versions 0.22.1 through 0.23.3 implement x86 SHA, AArch64 SHA2,
AArch64 SHA-512, and RV64 Zknh SHA-256/SHA-512 candidates but intentionally
contain no `manifest.toml`: no candidate has authenticated complete native
evidence, and every backend remains unadmitted. The private v0.23.3 native
candidate bundles are non-authorizing observations and are not formal records
in this directory.

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

Artifact JSON accepts only signed 64-bit integers. Floating-point values,
non-finite constants, oversized integers, and duplicate object keys produce a
controlled evidence error; they cannot escape the validator as a parser
traceback.

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

The separate detached candidate runner under `scripts/manage-cpu-evidence.py`
produces transferable clean-commit native observations before formal manifests
exist. Its bundles are validated by `scripts/validate-cpu-evidence-run.py` and
always say `authority=non-authorizing-native-candidate-observation`. They are
input for later review, not entries in this directory and not backend admission
evidence by themselves.

QEMU runs may populate supplemental instruction-coverage evidence, but they
can never satisfy native performance or side-channel gates. An unavailable
runner or a CPU without the exact required ISA remains explicitly unadmitted
and never blocks the portable scalar build.
