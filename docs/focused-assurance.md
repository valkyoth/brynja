# Impact-selected verification from v0.24.34

The repository and local release gates select expensive campaigns by affected
implementation, dependency, fixture and verifier inputs. A short native workspace
build/test/lint baseline and repository/release integrity checks remain mandatory.
This is project-owned testing, not independent cryptographic verification.

| Change | Expensive verification |
| --- | --- |
| SHA-2 source or its consumer fixture | SHA-2 and affected integrations |
| MD5 or SHA-1 source | Changed primitive and legacy consumer |
| Shared Keccak/SHA-3 source | SHA-3, KMAC, TupleHash and ParallelHash |
| Shared core/CPU authority | Registered affected consumers, including SHA-2 |
| Documentation or local version-only change | Metadata checks; reuse unchanged cryptographic campaigns |
| Verifier change | Explain the affected verifier evidence; require approval for unexpected broad renewal |
| Public crates.io checkpoint | Complete registered suite, automatically |
| Unclassified, malformed or unauthenticated scope | Stop before expensive execution; release verification is incomplete |

## Inspect before running

Run this read-only command to see the selected groups, uncertainty reasons and
exact plan fingerprint:

```sh
python3 scripts/release/run-verification.py plan --check
```

An uncertain internal plan exits with code 3 and `scope review required`.
The coding agent must explain why, which suites would run and any credible
runtime estimate, then ask the owner whether to correct classification or approve
the full run. No approval means stop, not skip and not PASS. Automated CI cannot
ask interactively: it reports the blocker and stops.

After explicit owner approval, use the fingerprint printed for that exact plan:

```sh
scripts/tag_gate.sh v0.24.34 --approve-full PLAN_FINGERPRINT
```

Approval is not a permission to release or publish. A different HEAD, changed
input or relevant build environment invalidates the fingerprint. Do not invent
approval or reuse a stale token. Public checkpoints need no exceptional full-run
approval because complete verification is the scheduled policy.

For an exceptional CI rerun, the repository owner can set the Actions variable
`BRYNJA_FULL_VERIFICATION_APPROVAL` to the fingerprint printed by that failed CI
plan, then rerun the job. Remove it afterward: a stale nonempty value is rejected.
Local and CI plans have different HEAD/build environments and must not share
approval tokens. Fixing the classification is preferable when scope is knowable.

## Execution

- `scripts/checks.sh`: selected repository checks, plus the cheap shared baseline.
- `scripts/tag_gate.sh vX.Y.Z`: approve scope first, then repository, selected
  native/QEMU, compiler-matrix, sanitizer, Miri and Kani checks, online authority
  and dependency checks, SBOM, committed report and release readiness.
- `scripts/ci/check-rust-version-matrix.sh`: the same affected selection across
  the twelve registered compiler versions.
- `scripts/zeroization/check-zeroization-miri.sh --selected sha2`: the exact
  selected group, with no interpreter smoke run of unrelated families.
- `scripts/checks.sh --full-catalog` and
  `scripts/ci/check-rust-version-matrix.sh --full-catalog`: explicit full
  diagnostic runs, not the default incremental release workflow. Do not invoke
  them to bypass a requested scope review.

The full shell catalogs remain the canonical command inventory. The incremental
dispatcher accepts only their reviewed straight-line grammar and validates every
command owner before running the first command. Unknown syntax/owners stop
planning. It never treats a failed or unclassified command as successful evidence.
The catalog and dispatcher tests must evolve together.

## Evidence boundaries

Selection compares staged, unstaged, deleted, renamed and nonignored untracked
inputs against an authenticated signed ancestor. At a clean tagged checkout it
uses the preceding tag; dirty new work after a tag uses that current tag.
Old and new dependency graphs are considered so removed edges cannot hide
consumers. A fixture may remove optional workspace dependency edges, but cannot
change package identities, versions, registry checksums or add unexpected edges.
The explicitly registered SHA-2 nested consumer is checked recursively.

Miri uses a separate dependency closure from native CPU integration tests. A CPU
change does not rerun portable SHA-3, KMAC, TupleHash or ParallelHash ownership
suites when both baseline and current lock graphs prove those crates have no CPU
dependency. A new or removed CPU edge retains the broader checks. Shared core or
SHA-3 changes still select those consumers. Missing or malformed dependency proof
requires scope review; public checkpoints still run every Miri group.

Version-only local pins and exact digest rebinding do not imply changed algorithms.
Numeric source-span corrections inside the registered MIR caller-header table
also do not change runtime code. The selector compares both Python syntax trees,
ignoring only those numeric spans in that exact table. Changed paths, owners,
cleanup targets, contracts or executable Python retain broad verification;
malformed inputs remain fail-closed. The actual compiler/MIR gate, its regression
tests and API-profile checks are mandatory even with no selected crypto groups.
Editing the compiler checker's regression test alone does not renew unrelated
Miri/ASan/Kani evidence. Real checker or shared implementation changes still do.
Reused evidence remains attached to its original source, verifier, compiler,
features and target: reuse never becomes a claim of a fresh run. Native correctness
does not prove timing, migration, register erasure or FIPS validation.

New algorithms, shared consumers and command families must be registered with
negative selection/dispatch tests before relying on incremental verification.
Unknown scope is never assumed unrelated. The normal flow remains implementation,
required pentest, local verification, committed report, green GitHub/CodeQL,
then owner-approved signed tag. This workflow does not publish intermediate tags.
