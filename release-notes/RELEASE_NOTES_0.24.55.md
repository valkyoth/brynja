# v0.24.55 - Opt-In Acceleration Final Closure

Status: preparation in progress; consolidated verification NOT RUN for this
candidate. No tag, crates.io publication or new independent qualification.

Baseline: signed `v0.24.54` at `91c794158099d0c06226c5bfbc23e4d6b1dfcdbd`.
Only the facade release identity advances. Support-crate versions, portable
defaults and cryptographic implementations are unchanged by preparation.

## Work packages and completion criteria

1. **Inventory and candidate preparation.** Reconcile the availability contract,
   public/leaf examples and status tables against actual callable ordinary,
   hardened, batch and threaded routes. Assign every gap an explicit disposition:
   implemented opt-in, experimental opt-in, or a concrete follow-up; retain the
   owner-approved hardware-dependent RISC-V exception. Review source/build and
   dependency changes before deciding which native claims remain reusable.
   Complete focused metadata, feature-graph and public-consumer checks before
   freezing the candidate. Any new implementation or security-boundary fix
   requires its own tests and exceptional pentest/retest; this document grants
   no advance acceptance.
2. **Consolidated verification.** Plan the full repository/compiler-matrix,
   Miri, Kani and ASan checkpoint covering the campaigns deferred from
   v0.24.52–v0.24.54. A metadata-only delta from v0.24.54 selecting no expensive
   tasks does NOT satisfy this separately scheduled checkpoint. Inspect the
   explicit baseline, complete command population and Miri profile before
   launch. Use the existing detached runner with bounded shards, source-bound
   receipts and results stored outside Cargo target directories. Preserve
   failed/timeout runs; resume only validated individual passes. Record exact
   coverage, not an ambiguous generic “full Miri” claim. No hours-long local
   desktop run is started by this preparation.
3. **Reconciliation and handoff.** Account for every required command and
   original evidence source, validate approved native reuse on the final
   candidate, and reconcile the sanitization 2.1.1 metadata-only deferral.
   Refresh only genuinely changed native inputs. Update documentation with
   actual results, run final scoped checks, obtain green GitHub/CodeQL for the
   exact candidate, and request authorization before tagging. HMAC work starts
   only after the consolidation is complete.

## Evidence boundaries retained

- [v0.24.54 native observations](../docs/native-evidence-v0.24.54.md) retain
  their original commit, compiler, platform, commands and result digests.
  Approved artifact integrity is not authenticated runner provenance.
- [Native reuse](../docs/native-evidence-reuse.md) requires the externally
  supplied owner-approved manifest digest. Do not derive it from the candidate
  or change the approved snapshot merely to accommodate a version bump.
- Windows development evidence, Apple resident protection, dedicated x86
  SHA512 emulation and hardware-dependent RISC-V deferral remain distinct.
  No unavailable platform or instruction receives native qualification here.
- Ordinary public-only APIs do not become secret-erasing owners. Strict and
  resident profiles retain their documented platform and caller-copy limits.
- Independent cryptographic review and FIPS validation remain separate from
  project-operated tests, native observations and release completion.

## Progress

- Release identity and public acceptance fixture pins: updated for preparation.
- Current status: v0.24.54 tagging and green CI recorded accurately.
- Source/API availability inventory: reviewed in the
  [closure inventory](../docs/acceleration-final-closure.md); local packaged
  public acceptance passed on `9695e91f`. Final evidence reconciliation pending.
- Consolidated detached sweep: not started; final task list and host allocation
  remain to be established before launch.
- Final release verification, GitHub and tagging: pending.

Preparation checks passed: release metadata and all 2,159 ordered roadmap
sections; acceptance/hash bindings and their mutations; SHA-2/SHA-3 public-API
regressions; SP 800-185 policy and executable output mutations; 16 dependency-
scope, nine evidence-scope, 13 approval and 62 historical-reuse tests; planner
selection/no-launch regressions; facade all-feature tests; the acceleration
contract tests and mutations; documentation links, script layout and SBOM
comparison. These are preparation checks, not the consolidated sweep.

The unchanged planner, with explicit baseline `v0.24.51`, selects all twelve
groups and all five phases. Catalog inspection (no execution) counts 263
repository commands, 280 compiler-matrix commands, 49 sanitizer commands and
twelve Kani groups. The existing internal Miri profile has 562 tasks; the
separate extended profile has 4,094. The planned internal checkpoint uses the
complete routine catalog, as in the earlier two-host campaign, with its profile
explicit in receipts; it is not an extended-profile qualification. Final counts
and the approval fingerprint must be rechecked after inventory closure.

The author-tested TupleHash/ParallelHash metadata correction composes the
existing exact fixture-version/pin proof with externally approved validator
changes. Approved original/intermediate bytes, source/build populations and
artifact identity remain checked; the approval digest is unchanged. All 82
historical-reuse regressions pass, including 20 added composition cases; four
in-memory mutations removing either structural predicate are rejected. This
verification-path change requires an exceptional retest before release, recorded
as pending in [the security report](../security/pentest/v0.24.55.md).

All eight real native-reuse paths now pass, retaining their original observations
and the unchanged external approval digest. The two corrected paths passed on
clean commit `7f51eee2`. Focused facade-harness, approval, release-planning,
family-inventory, metadata/hash, documentation and script checks also pass.
No production cryptographic implementation changed. This is not completion of
the frozen public-consumer acceptance or the consolidated verification sweep.

The supplied dual review of `d70b83bd` prompted focused tooling corrections:
bind approval imports before family loading, register all three missing fallback
review modules, diagnose missing capture inputs, and bind approval pairs to raw
Git bytes. The author suites now pass 88 reuse tests, 15 approval tests and 21
hardened gate-policy mutations. No cryptographic code or external approval pin
changed. The [review record](../security/pentest/v0.24.55.md) retains the findings
and the distinction between local drift pins and independent verifier approval;
the corrective retest and consolidated sweep remain pending.

The next retest identified the same import-shadowing pattern in the generic
fallback and additional helper-pin/raw-hash gaps. The follow-up preloads the
entire fallback checker chain, checks module identities and extends raw-byte
hash checks to historical reviews/setup/tooling substitutions. All 217 existing
historical digest values match without any review/receipt rewrite. The suites
now pass 92 reuse tests, 15 approval tests and 24 gate-policy mutations, including
42 planted-checker cases across all seven generic fallback families. The Medium
finding was kept open at that stage, not dismissed as an intentional limitation.
The supplied retest of `7d7dfdbf` subsequently confirmed those corrections and
reported no new problems, including 112 planted helper/standard-library module
probes. The [security report](../security/pentest/v0.24.55.md) now records zero
outstanding confirmed findings. No cryptographic implementation or external
approval digest changed.

The optional MD5 digest cleanup was completed in `9695e91f`: all eleven command
profile pins now compare raw committed bytes, retaining their existing expected
digests. The dependency suite passes 17 tests; a normalized-reader mutant fails
all 22 CRLF rejection cases. All eight real native-reuse paths pass on that clean
commit. This last cleanup is author-verified, not claimed as part of the earlier
independent retest. Final review disposition and the consolidated checkpoint
remain pending; a clean tooling retest is not a completed release sweep.

## Local public-consumer acceptance

Author-operated checks completed on 2026-10-19 with Rust 1.99.1, Linux x86-64,
AMD Ryzen 9 9950X3D. Implementation, tests, fixtures and package inputs match
`9695e91f`; only release-note/inventory documentation changed during the run.

- `python3 scripts/repository/check-facade-package.py --toolchain 1.99.1 --native-simd`
  passed in approximately eleven minutes. Both extracted facade packages passed
  feature/default isolation, no_std checking, debug/release execution, ownership
  negatives and compiled algorithm/output/cleanup mutations. Coverage includes
  SHA-2, SHA-3/SHAKE/cSHAKE, KMAC, TupleHash, ParallelHash, batching/threading and
  separate ordinary/hardened legacy SHA-1/MD5 packages. Available static x86
  routes executed; unsupported dedicated SHA512 and generic hosted migration
  routes remain explicitly unavailable, not counted as kernel execution.
- `python3 scripts/repository/check-strict-public-consumer.py --toolchain 1.99.1`
  passed: 6,004 scalar cases per debug/release campaign, 56 compiled
  ownership/lifetime/classification negatives and 32 compiled mutation runs,
  followed by successful restored-source campaigns.
- The README fixture passed all 64 doctests with zero failures or ignored tests.
  Facade/strict harness regressions, the 17 family-completeness tests, verification
  status, release metadata, script layout and documentation links also passed.

Logs are retained locally outside `target/`. These are public-consumer acceptance
checks, not independent qualification, new cross-platform captures or detached
checkpoint receipts. The approved original native records and their external
digest remain unchanged. Reinspection of the `v0.24.51` consolidation baseline
still selects 263 repository commands, 280 matrix commands, 49 sanitizer commands,
twelve Kani groups and 562 routine Miri tasks. No consolidated job has launched.
