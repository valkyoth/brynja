# Impact-selected verification from v0.24.34

The repository and local release gates select expensive campaigns by affected
implementation, dependency, fixture and verifier inputs. A short native workspace
build/test/lint baseline and repository/release integrity checks remain mandatory.
This is project-owned testing, not independent cryptographic verification.

| Change | Expensive verification |
| --- | --- |
| HMAC source, fixture, or exact HMAC-only facade/hosted registration | HMAC; independent shared changes retain their own scope |
| SHA-2 source or its consumer fixture | SHA-2 and affected integrations |
| MD5 or SHA-1 source | Changed primitive and legacy consumer |
| Shared Keccak/SHA-3 source | SHA-3, KMAC, TupleHash and ParallelHash |
| Shared core/CPU authority | Registered affected consumers, including SHA-2 |
| Documentation or local version-only change | Metadata checks; reuse unchanged cryptographic campaigns |
| Verifier change | Explain the affected verifier evidence; require approval for unexpected broad renewal |
| Public crates.io checkpoint | Complete registered suite, automatically |
| Unclassified, malformed or unauthenticated scope | Stop before expensive execution; release verification is incomplete |

The HMAC integration classifier recognizes only the registered dependency edge,
exact opt-in feature lists and exact module-registration edits. It compares the
rest of each manifest/source unchanged and traverses both lock graphs. Adding or
removing the HMAC edge in a facade does not itself change another primitive;
changing a hash, CPU authority, shared feature, build setting or other dependency
still selects its affected consumers. New HMAC compiler/timing fixture locks must
be unpublished and match the corresponding workspace dependency identities and
edge subsets. Unknown fixtures and malformed graphs still fail closed.

This classification is not an evidence PASS or permission to discard shared
testing. In particular, the v0.25.0 shared CPU verification-driver changes retain
their broader consumer selection. Pure HMAC changes select HMAC; the complete
release plan is the union of all independently classified changes.

## Inspect before running

When a completed detached sweep is available, retain its original job and
receipt and set `BRYNJA_DETACHED_JOB` / `BRYNJA_DETACHED_RECEIPT`. The runner then
compares implementation inputs against that validated commit, not repeatedly
against the previous release tag. It documents carried-forward checks and runs
the current baseline plus affected or uncovered checks. A documentation/tooling
commit is not a reason to repeat unchanged Miri/Kani/ASan campaigns. See
[carry-forward](detached-verification.md#carry-forward-verified-implementation-checks).

Historical receipt reconstruction reads the frozen snapshot's registered group
tuple and corroborates it against that snapshot's shell inventory, without
executing archived Python. A family introduced later cannot be retroactively
required of the old campaign or credited as covered by it. Frozen source,
command, result, log and tool checks still apply. Today's mandatory repository
checks and new-family verification remain separate requirements.

Run this read-only command to see the selected groups, uncertainty reasons and
exact plan fingerprint:

```sh
python3 scripts/release/run-verification.py plan --check
```

An uncertain internal plan exits with code 3 and `scope review required`.
The coding agent must explain why, which suites would run and any credible
runtime estimate, then ask the owner whether to correct classification or approve
the full run. No approval means release verification stops, not skips or passes.
Ordinary CI uses a separate diagnostic mode described below.

After explicit owner approval, use the fingerprint printed for that exact plan:

```sh
scripts/tag_gate.sh v0.24.34 --approve-full PLAN_FINGERPRINT
```

Approval is not a permission to release or publish. A different HEAD, changed
input or relevant build environment invalidates the fingerprint. Do not invent
approval or reuse a stale token. Public checkpoints need no exceptional full-run
approval because complete verification is the scheduled policy.

Ordinary push/PR CI runs `plan --check --ci` and `scripts/checks.sh --ci`.
It neither reads the Actions approval variable nor consumes or grants release
approval. A stale repository variable cannot block those checks. The explicit
`scripts/ci/push-catalog.toml` partitions every repository command into bounded
baseline, bounded affected checks, or release qualification. Missing, duplicate
or newly unclassified commands fail planning. This does not remove commands from
the full release catalog or change its evidence-reuse rules.

For affected checks, CI searches up to 300 successful main-branch push runs of
this workflow. It accepts only a completed successful run whose commit is a
strict ancestor and whose workflow, catalog and selection contract match the
current checkout. The diff starts at that ancestor, including intervening failed,
cancelled or untested commits. PR/fork runs and caller-supplied `--base` values
cannot establish this baseline. A dirty checkout, unavailable API, changed CI
contract, absent compatible success or unknown scope runs **all bounded checks**;
it does not launch a deep campaign. Manifest/lock/shared-driver changes likewise
select all bounded checks. Shared policy/build/lint/tests always run.

Each bounded command logs elapsed time and has a five-minute limit. A timeout or
test failure fails CI and stops its child process group; it is never a PASS or
reused result. The repository job has a 25-minute overall budget. The independent
audit job runs dependency policy, RustSec, SBOM and release-control checks even
if repository diagnostics fail. Existing native host, no_std, compiler-smoke,
CodeQL and SDE jobs remain independent.

Public-API host jobs execute the source fixtures directly. Exhaustive isolated
package/negative/mutation checks and cleanup compiler campaigns belong to release
qualification, not every push. Apple Silicon still executes native resident
debug/release tests and lint on pushes (`--stage tests`); its complete codegen
and package checks remain available through the existing `--stage all` command
and native qualification workflows. Successful CI is **not** a release receipt,
packaged-consumer qualification or compiler-erasure qualification.

Before pushing, run the same complete bounded preflight locally on Linux:

```sh
python3 scripts/release/run-verification.py plan --check --ci
scripts/checks.sh --ci
```

Without a GitHub Actions environment this always runs all bounded groups. It
also validates current acceptance/review pins before compiling. It does not
contact Actions or consume detached receipts. Passing it reduces avoidable CI
failures but does not replace GitHub's independent checks or the release gate.

`--ci` is accepted only for plan/repository diagnostics, never for Miri, ASan,
Kani, compiler-matrix or arbitrary command execution. It produces no release
receipt. The local release/tag gate does not use this mode: uncertain scope still
requires exact owner approval, and public checkpoints retain complete verification.
Pentest/native evidence and release-readiness checks remain release requirements,
not prerequisites for ordinary code checks or GitHub CodeQL scanning.

## Execution

- `scripts/checks.sh`: selected **release** repository checks; may be expensive.
- `scripts/checks.sh --ci`: bounded push diagnostics/local pre-push preflight.
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

## Frozen nightly qualification

Online release checks validate the pinned nightly's date, Rust revision, Miri
availability and execution toolchain against its dated official distribution
manifest. A newer daily nightly is reported, but does not automatically replace
the compiler used for completed evidence. Upstream identity mismatch, unavailable
pinned Miri, malformed responses and network failure still stop verification.
Other verifier release/tag freshness checks remain mandatory and unchanged.

Before the next qualification cycle, explicitly check for nightly updates:

```sh
python3 scripts/assurance/check-assurance.py --network --require-latest-nightly
```

This maintenance mode fails if a newer nightly exists. Review and update pins
before collecting replacement evidence; never relabel older runs as using a
new compiler. This freeze is not an exemption for known verifier defects.

## TupleHash native metadata carry-forward

The tag gate first applies the unchanged exact-source native validator. Its
separate fallback permits only the public consumer fixture's exact facade-version
replacement and the corresponding single reviewed digest replacement. The facade
versions must match their respective committed manifests. Every other native
input must match the capture commit. Changed code, features, other review pins,
capture commands or artifacts are rejected. All three reviewed native lanes and
their original commit, compiler, CPU and results remain mandatory.

This prevents an unrelated facade version bump from requiring a new hardware
campaign. It does not turn old observations into a new capture, authorize a
backend. Detached verification has its separate implementation-delta
carry-forward rules; neither mechanism rewrites a historical capture.

## Inactive HMAC additions in older native inventories

Detached selection separately recognizes the exact optional HMAC archive
addition in the Mac legacy package helper. Its companion test-only change is
bound to two reviewed raw-byte hashes, not exempted by filename or directory.
The current package regression command remains a mandatory baseline check in
both local release verification and bounded push CI. Changed command selection,
features, graph validation, tests or unrelated shared code retain their ordinary
affected scope. This classification does not approve native tooling or supply
missing HMAC verification results.

The remaining shared HMAC integration is also classified separately: exact
guarded worker-test suffixes, optional archive/patch additions, and reviewed
HMAC-only hosted-validator changes select HMAC. CPU and batch review inventories
may add only registered HMAC source rows with matching current digests; existing
paths and non-digest policy fields cannot disappear or change. The actual source
diff is classified independently, so an inventory update never hides a kernel
or worker change. Current CPU, SHA-2 and batch policy regressions remain mandatory.

The separately byte-bound SDE output-parser correction does not change the
implementation scope of Miri/Kani/ASan. It does not establish successful SDE
execution: a changed command driver still reruns, and its tests still reject
timeouts after printed PASS output, missing populations and disabled leak checks.
Exact before/after tooling identities are reviewed scope limits, not signatures
or runtime attestations. Unknown edits retain conservative selection.

The SHA-2, Keccak, KMAC, TupleHash and ParallelHash inventories include the
whole hosted CPU crate. Their pre-HMAC command profiles do not enable HMAC.
The bounded HMAC projection checks those commands against an immutable reviewed
snapshot, retains the old fixture manifests and rejects any changed feature
selection. Cargo metadata regressions independently check the resolved feature
unions without compiling or running cryptography.

Reuse permits only the exact guarded module declarations, optional dependency
and feature definitions, known inactive source additions and two byte-pinned,
feature-gated appended tests. Existing source prefixes, kernels, dependency
versions, configuration, build scripts and other feature definitions remain
unchanged. Unknown additions, removed guards, symlinks and changed commands
reject reuse. The facade fixture's version-only pin adjustment composes with
this proof; it does not authorize other review-pin changes.

The optional HMAC archive additions in the legacy packaging helpers similarly
leave their reviewed feature selection unchanged. MD5 and SHA-1 have separate
source-bound command profiles: their historical collectors do not enable the
optional strict-host dependency. Unknown profiles remain conservative; changing
defaults, the optional edge or any command invalidates that dependency proof.
**Neither structural proof approves
changed validation tooling.** Such changes still require exact before/after
digests in the externally approved native-review manifest. Original artifacts,
CPU/compiler identities and capture commits remain authenticated separately.
No historical hash result qualifies HMAC, a new compiler or a new platform.

## Evidence boundaries

Selection compares staged, unstaged, deleted, renamed and nonignored untracked
inputs against an authenticated signed ancestor, or the clean ancestor commit
of a fully validated successful detached run. At a clean tagged checkout it
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
The generated `standards/protocol-surfaces.json` has an explicit 8 MiB scope-read
cap because the complete registry exceeds the ordinary 4 MiB source/TOML cap.
This exact-path allowance does not change its metadata classification or exempt
it from mandatory standards/schema/reproducibility checks. Code, locks and other
JSON retain their existing cap. Both baseline and current inputs remain bounded
and regular-file checked; an exceeded cap still requires scope review. Metadata
content remains bound into the plan fingerprint. A concurrent crypto change
still selects its affected campaigns; public checkpoints still run the full suite.

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
