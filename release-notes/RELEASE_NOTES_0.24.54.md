# v0.24.54 - Acceleration Native Evidence Sweep

Status: exceptional retest pending; release blocked. Forty source-bound Linux/Apple captures and twelve
current public-consumer campaigns completed; evidence integration and local
non-sweep release checks passed. No independent qualification or crates.io
publication.

The subsequent security review confirmed a High native-evidence substitution
bypass. The approval boundary is corrected and regression-tested, but a focused
independent retest and separate owner approval remain required. Earlier local
checks below are historical results, not current release authorization. See
[the finding and disposition](../security/pentest/v0.24.54.md).
The real isolated replay now rejects the reported KMAC forgery on both paths.
Legacy MD5 additionally needs its historical dependency-closure rejection
resolved before tagging; no new runtime defect or full-sweep requirement is
inferred from that rejection.

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
- Importing result JSON/transcripts in known native-observation directories
  selects metadata validation, not another cryptographic verifier campaign.
  Focused regressions retain selection for implementation, vector fixture,
  collector and build changes alongside those observations. This classification
  does not accept invalid evidence or bypass its existing source/result checks.

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

## Collected host coverage

| Host | Intended observations | Availability/limits |
| --- | --- | --- |
| Local AMD Linux | Ten captures and three strict consumer campaigns passed | Ryzen 9 9950X3D; no dedicated x86 SHA512 |
| Intel Linux | Ten captures and three strict consumer campaigns passed | Xeon 6975P-C; no dedicated x86 SHA512 |
| AWS Arm Linux | Ten captures and three strict consumer campaigns passed | Neoverse-V2; Arm instruction/NEON execution |
| Apple M2 | Ten captures and three resident consumer campaigns passed | M2 Pro; resident protection is not strict dump exclusion |
| Windows x64 VBS development guest | Original development bundle retained; .53 consumer checks compile-only | No fresh native execution; no production signing qualification |
| Intel Mac, Windows ARM64, native RISC-V | No new qualification | Unavailable/unqualified; do not replace native requirements with QEMU |
| Dedicated x86 SHA512 | Native only if the exact ISA is exposed | Existing SDE development evidence stays explicitly emulated |

The compiler audit must preserve each collector's real pin: several historical
collectors require Rust 1.98.1 while the current public-consumer toolchain is
1.99.1. An observation under one compiler does not qualify another. Review any
collector update before collecting; never edit an existing record's compiler.

## Evidence and verification boundaries

Fresh records now cover the six families with exact-record mismatches at
v0.24.53. Their public derivatives pass the existing per-record source/result
validators; all eight committed native-index validators passed. Original
MD5 evidence is retained without an unnecessary refresh. See the
[native review](../docs/native-evidence-v0.24.54.md) for raw/public hashes,
successful retries, workload regressions and remaining platform limits.
A successful functional capture alone does
not establish timing resistance, performance benefit, register/stack erasure,
independent cryptographic review or FIPS validation. Measure each claimed
property or give it an explicit unavailable/pending disposition.

The owner-directed consolidated Miri/Kani/ASan and compiler/repository sweep
remains scheduled for v0.24.55. No full sweep or synthetic completion receipt is
introduced here. Focused regressions, ordinary CI and source-bound evidence
checks remain required. Any necessary execution, unsafe, secret-owner or trust
boundary change reopens exceptional review rather than inheriting v0.24.53's
sign-off. Existing accepted platform limits are not reopened by collection alone.

## Final local verification

On 2026-10-18, the local release checks completed against
`30c4d3141cb52218c742208e13c1e326367de0dc`. The tag-gate sequence passed through
repository/package tests, bare-metal checks, source-bound native validation,
standards freshness, toolchain policy, release controls and dependency bans.
Cargo audit then stopped because the sandbox could not lock its advisory cache;
the audit and every remaining gate step were rerun with the required access and
passed, including SBOM and development-milestone validation. This is a completed
split execution, not a claim that the initial invocation exited successfully.

The planner selected no affected cryptographic verifier groups or full phases.
ASan/Miri selection and Kani policy/reuse checks passed without launching a new
full campaign. The subsequent handoff changes only documentation and its review
hashes; focused checks validate that delta. GitHub must check the final pushed
commit before a separately authorized tag. No crates are selected for publication.
