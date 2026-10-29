# Miri coverage by release

Miri checks memory/ownership behavior of executed Rust paths, not cryptographic
correctness or native SIMD/assembly behavior. These are author-operated results,
not independent certification. A tag or green CI badge does not imply Miri ran.

## Release policy (owner-approved 2026-10-28)

Set `[release].verification = "affected"` in `release-crates.toml` for routine
releases, including crates.io releases. Publication alone does not invalidate
unchanged results. Register new families and their dependencies before release;
unknown scope stops for review rather than silently skipping tests.

| Release type | Miri requirement | Other release checks |
| --- | --- | --- |
| Development tag (`stage = "internal"`, `verification = "affected"`) | Optional; report when not run. Targeted safety investigations remain available. | Normal tests, relevant regressions/native checks, selected sanitizers/proofs, packaging and release integrity |
| Crates.io release (`stage = "public"`, `verification = "affected"`) | Routine boundary/lifecycle tasks for changed implementations and affected consumers; validated receipt reuse for unchanged covered tasks | Affected selection plus public review/publication requirements |
| Explicit assurance checkpoint (`verification = "full"`) | All registered extended tasks; routine coverage cannot replace extended coverage | Full verification/compiler matrix, with explicit execution approval |

Owner-approved refinement, 2026-10-29: the current checkpoint catalog deliberately
uses **bounded ParallelHash Miri coverage plus exhaustive native tests**. Its
matrix tasks carry `bounded-parallelhash-v1`, use the registered routine
boundary/input samples, and retain all registered fault/join/ordering/lifecycle
cases. This is reduced interpreted coverage, not an exhaustive Miri pass.
KMAC setup and TupleHash width products remain complete but separately resumable.
Other families retain their existing coverage. See [decomposition and measured
samples](test-decomposition.md). Historical receipts below keep their original
catalogs; the refinement does not rewrite them or convert incomplete runs to PASS.

v0.25.2 remains an explicitly selected **full** checkpoint at the owner's
request. Set `verification = "affected"` when starting the next release; do not
carry this one-off `full` selection into every version. Historical configurations
without this field retain their old stage-based meaning when sealed receipts
are reconstructed. They are not rewritten or granted additional coverage.

Routine compiler compatibility checks use MSRV and the pinned stable compiler;
full mode retains the complete registered list. Relevant ASan/Kani and native
checks still follow implementation dependencies. Unsafe/shared-core changes can
legitimately select several families. Failed relevant checks remain failures.

Explicit Miri runs remain available through `run-verification.py miri` or the
detached runner, even for development tags. Only the tag wrapper applies the
optional distinction, printing **no Miri pass claimed** when not required.
See [focused assurance](../focused-assurance.md) and
[detached verification](../detached-verification.md) for selection and resume.

## Recorded coverage

Only reconciled observations belong here. Older releases not listed have **no
consolidated coverage claim in this table**; their original reports retain their
own scope. This is not a claim that every path in a release was interpreted.

| Version | Tested source | Coverage/profile | Result and provenance |
| --- | --- | --- | --- |
| v0.25.1 | `44eac32b5cf1ccd017f174588de3ff3466e5ab0c` | Routine, 587 tasks across eleven selected families; Linux x86-64, `nightly-2026-09-11` | PASS at that snapshot. Two AWS partitions (294 + 293) combined without re-execution; logs and receipt validated. Later candidate checks/reuse remain separate. |
| v0.25.2 | `c7ae3f72c49add27b13d92faa72fe80c18348d22` | Extended checkpoint: 2,962 of 4,122 tasks passed; four in-flight tasks cancelled; 1,160 tasks remain without a completed pass | **PARTIAL / OWNER-CANCELLED**, 2026-10-29. Both terminal records, frozen sources and logs downloaded and historically validated. Not a full campaign PASS or release authorization. |

The v0.25.1 receipt is
`623c2febf6aa0c97db7ed63ba7e6913741e5ca0e483466f1d6822a50d12ded54`.
Its manifest records Miri `0.1.0 (67eda617e6 2026-09-10)` and 587 successful
commands at the source above. See the
[v0.25.1 report](../../security/pentest/v0.25.1.md). Local archives are outside
disposable Cargo target storage; this table does not replace their validation.

Add a row for each subsequent release: exact source, profile, families,
toolchain and receipt. Distinguish **fresh PASS**, **validated reuse**,
**partial/incomplete**, **failed**, and **not run (development tag)**. Reuse cites
the original tested commit. Missing coverage is not a pass.
