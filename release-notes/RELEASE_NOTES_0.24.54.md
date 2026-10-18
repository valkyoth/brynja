# v0.24.54 - Acceleration Native Evidence Sweep

Status: in progress. Collection/planner preparation only; no new native evidence or
qualification is claimed. No crates.io packages are selected.

This milestone follows signed v0.24.53 public consumer acceptance. It collects
exact-source native correctness, performance, timing and resource observations
using existing family fixtures and validators. Production cryptographic code,
and portable defaults remain unchanged during preparation. The owner has also
approved simplifying evidence selection/reuse for routine releases.

## Affected-scope evidence work

- Native fallback entry points validate unchanged original captures without a
  new release-specific equivalence record. A family dependency projection ignores
  unrelated workspace packages/declarations, not selected dependency or build
  changes. Original commits, artifacts and compiler/platform limits remain intact.
- Workspace dependency-table edits select their actual consuming families,
  including old and new consumers and target/build/dev inheritance. Shared build
  configuration changes and unregistered implementations still require scope
  review; a new family must register its own tests before it can be released.
- Regression fixtures cover the intended HMAC-addition/SHA-2-reuse case, shared
  source changes, dependency checksum/origin/edge changes, build configuration,
  missing/forged inputs and new source/build files. These synthetic fixtures do
  not constitute HMAC implementation or new native evidence.
- The full consolidation checkpoint remains v0.24.55. No old failed or deferred
  observation is made valid merely by introducing the new selection logic.

See [native evidence reuse](../docs/native-evidence-reuse.md) for the operating
rule and remaining conservative cases. No new collection service is introduced.

Author checks for this preparation: eight native-dependency and six workspace-
scope tests, the 62-test existing native-reuse suite, the 114-test detached-runner
suite, verification-plan/scope tests, SHA-2 policy mutations, acceptance metadata
and its regressions, assurance generation, script layout, shell syntax, unsafe
policy, documentation links, release metadata and SBOM checks passed. These are
tooling/regression checks, not an independent retest or completed native sweep.
The current metadata/planner-only delta selects no Miri/Kani/ASan campaign.

## Three bounded work packages

1. Audit collector/fixture compatibility, required compiler pins, source and
   package bindings, result populations and artifact handling. Run focused
   regressions before committing the common capture candidate. Freeze commands
   before remote collection so a stale fixture does not waste all hosts' runs.
2. Collect per-host/per-family evidence in resumable, isolated runs. Record failed
   and unavailable routes explicitly, preserve raw results outside Cargo target
   directories, and review privacy before committing artifacts. Do not relabel
   old captures or turn emulator results into native evidence.
3. Reconcile exact sources, compiler/flags, selected graph, OS/CPU features,
   commands, results and artifact hashes. Document performance/resource/timing
   observations separately from correctness, refresh only supported claims,
   and finish ordinary CI and non-sweep release checks.

## Planned host coverage

| Host | Intended observations | Availability/limits |
| --- | --- | --- |
| Local AMD Linux | Portable, SHA-NI, AVX2, strict Linux and threaded consumers where supported | Recheck actual feature bundles; no dedicated SHA512 claim from AVX-512 alone |
| Intel Linux | Independently measured x86 hardware routes and public/strict consumers | New AWS address needed; inspect features before selecting routes |
| AWS Arm Linux | Arm SHA-2/Keccak, NEON, strict Linux and threaded consumers | New AWS address needed; require reported features and actual route markers |
| Apple M2 | Arm instruction/NEON and Apple resident/clearing consumers | Use macosbuilder; resident protection is not strict dump exclusion |
| Windows x64 VBS development guest | Enclave public APIs, supported accelerated/batch/worker routes | Confirm guest availability; development signing is not production signing qualification |
| Intel Mac, Windows ARM64, native RISC-V | No new qualification | Unavailable/unqualified; do not replace native requirements with QEMU |
| Dedicated x86 SHA512 | Native only if the exact ISA is exposed | Existing SDE development evidence stays explicitly emulated |

The compiler audit must preserve each collector's real pin: several historical
collectors require Rust 1.98.1 while the current public-consumer toolchain is
1.99.1. An observation under one compiler does not qualify another. Review any
collector update before collecting; never edit an existing record's compiler.

## Evidence and verification boundaries

The six exact native-record mismatches documented at v0.24.53 remain pending
fresh collection/reconciliation. A successful functional capture alone does
not establish timing resistance, performance benefit, register/stack erasure,
independent cryptographic review or FIPS validation. Measure each claimed
property or give it an explicit unavailable/pending disposition.

The owner-directed consolidated Miri/Kani/ASan and compiler/repository sweep
remains scheduled for v0.24.55. No full sweep or synthetic completion receipt is
introduced here. Focused regressions, ordinary CI and source-bound evidence
checks remain required. Any necessary execution, unsafe, secret-owner or trust
boundary change reopens exceptional review rather than inheriting v0.24.53's
sign-off. Existing accepted platform limits are not reopened by collection alone.
