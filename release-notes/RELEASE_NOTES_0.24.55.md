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
  [closure inventory](../docs/acceleration-final-closure.md); frozen public
  acceptance and final evidence dispositions still pending.
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
