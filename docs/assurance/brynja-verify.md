# brynja-verify: everyday verification

`brynja-verify` is a small local terminal tool. It answers: what is registered
for this component, what actually ran, and do the relevant inputs still match?
It is not a release gate. An empty or outdated row does not automatically block
an unrelated release or start a test.

## Build the tool once

From the repository root:

```sh
cargo install --path tools/brynja-verify --locked
brynja-verify --help
```

This builds the developer tool, not the cryptographic workspace. It has its own
workspace and lockfile; its dependencies are not shipped in Brynja crates.
The first build may download tool dependencies. Status commands themselves do
not download anything, install toolchains, compile code, discover tests, or
contact services. Run commands from the repository root, or put `--root PATH`
before the command.

Version one executes checks on Linux and macOS. Windows execution is explicitly
unavailable until process-tree cancellation is supported there. No GUI,
background scheduler, remote runner or database is needed.

## Daily commands

| Command | What happens |
| --- | --- |
| `brynja-verify md5` | Read MD5 inputs and show MD5's status. Run nothing. |
| `brynja-verify md5 --category asan` | Refresh only MD5's sanitizer status. Run nothing. |
| `brynja-verify sha1` | Read SHA-1 inputs and show its status. Run nothing. |
| `brynja-verify run md5 known-answers` | Execute only that registered MD5 check. |
| `brynja-verify run md5 --needed --category portable` | Execute only portable MD5 checks without a current successful result. |
| `brynja-verify run md5 --all --category portable` | Explicitly rerun every portable MD5 check, even current passes. |
| `brynja-verify run md5 --needed --category asan` | Run only MD5 sanitizer registrations needing execution. No Miri/Kani/repository selection. |
| `brynja-verify md5 --category kani` | Inspect MD5's bounded-proof status. Run nothing. |
| `brynja-verify run md5 --needed --category kani` | Explicitly execute only MD5's existing bounded proofs when needed. |
| `brynja-verify full-check` | Scan all registered inputs and refresh statuses. **No tests run.** |
| `brynja-verify report` | Regenerate Markdown from saved state, without scanning inputs. |
| `brynja-verify list md5` | List MD5's runnable checks and existing catalog assessments. Run nothing. |
| `brynja-verify list md5 miri` | List just MD5's catalogued Miri configurations. Run nothing. |
| `brynja-verify list md5 miri-routine` | List only the routine Miri profile. Run nothing. |
| `brynja-verify show md5 CHECK_ID` | Show the exact registration or catalog command, limitations and original history. |

`--needed` and `--all` are sequential. An executed failure stops the sequence;
completed results stay saved and remaining checks are listed. Missing inputs
or tools are reported as unavailable, not passed. Unknown components/checks are
errors, never a request to run a larger scope.

Unbound assessment entries are **visible but not yet executable through the Rust
runner**: their scoped inputs, meaningful completion signals and platform/tool
requirements have not been migrated. A named `run` refuses these with an explicit
reason. `--needed`/`--all` run only available scoped registrations and report the
unresolved catalog entries; exit status 1 can therefore mean incomplete scope,
not a failed executed test. It never launches the old whole-component campaigns
to fill those gaps. The old scripts/dashboard remain available for deliberately
selected diagnostic execution, but those results are not automatically current
passes in this tool.

Supporting script entry points, workflow jobs and retired task identities are
listed separately as **references, not unfinished checks**. They do not make
`--needed` fail or schedule work. A category filter also excludes unresolved
assessments in other categories. Unknown categories fail without execution.
Where overlapping Miri profiles are registered, `--needed` and `--all` require
an explicit category. Otherwise the command refuses before starting anything.
Use `portable`, `asan`, `miri-routine`, `miri-extended` or `miri-existing-full`.
For components without overlapping profiles, the unfiltered forms remain valid.
Selecting one exact check ID never requires a category. Inspect `list` before
choosing a batch; a profile can still take hours despite independently bounded tasks.

Use Ctrl+C to interrupt a run. The runner stops its child process group and
records interruption. A force-killed/crashed runner leaves a running attempt;
the next scan of that component identifies it as interrupted, without guessing
an end time. Inspect its log before restarting. A host crash or force-kill can
leave child processes outside the runner's control: check those before retrying.

Do not edit relevant inputs while a check runs. The tool compares them before
and after execution. A changed-input run is recorded but is not a current pass.
This is a best-effort guard, not execution from an immutable source snapshot.

## Reading results

HKDF has package-external usability checks: `packaged-public-api` runs the
MSRV/current endpoints and `public-api-matrix` runs all supported host compilers.
Both are available for `hkdf` and `legacy_hkdf`; neither publishes packages.
See [HKDF public API acceptance](hkdf-public-api.md) for scope and prerequisites.

Terminal status is grouped by the command being run, within each component and
category/profile. For example, the many `md5-bulk:N` cases appear under one
`md5-bulk` group per Miri profile. Different commands, working directories,
platform bindings and stdin inputs remain separate. Environment/case variations
are counted as configurations, not collapsed into one execution or one pass.

Each group shows outcome and freshness counts, current passes out of all its
configurations, source information, latest execution activity and last successful
execution. Dates are the latest individual member dates, **not** a claim that
the whole group ran then. Incomplete attempts use their original start time.
Historical observations have a separate date because a reuse record is not a
new execution. Mixed sources are explicitly labeled.

Use `list md5 miri-extended` for individual IDs and `show md5 CHECK_ID` for exact
commands, sources, dates, failure details and concrete freshness explanations.
Named runs still display their individual result; the Markdown report retains
per-check detail. Grouping changes presentation only, never `--needed` selection,
fingerprints, saved attempts or verification requirements.

Execution outcome and freshness are separate. `failed` with current inputs is
still a failure. `passed` with outdated inputs is historical evidence, not a
current pass. A current pass needs a completed successful attempt whose before
and after inputs match today's selected inputs and settings.

The table shows the source actually tested and actual execution time in UTC.
Dirty-source runs say `working tree based on COMMIT` and record the exact scoped
fingerprint. Committing identical tested bytes later does not require a rerun
or change the original execution identity/date.

Later unsuccessful attempts are never hidden behind old successes. If inputs
return to an earlier state, a matching success can be reused only without hiding
a newer failure for that state. Original timestamps remain original. The
terminal also shows the last successful execution separately from the latest
failure or incomplete attempt.

A component scan leaves other components' saved views alone. The report's
status-change timestamp changes only when meaningful status changes; a repeated
identical scan does not rewrite files merely to update the clock. It is not a
heartbeat or a new execution date. Run `full-check` only when you want the
repository-wide registered status view refreshed.

## Files and history

- `verification/checks.toml`: human-maintained check registry.
- `verification/miri-checks.json`: explicit generated registrations for existing
  Miri tasks, included by the main registry. No runtime discovery.
- `verification/kani-checks.json`: explicit bindings for nine existing proof groups.
- `verification/catalog.json`: generated full existing inventory and original
  historical observations, without current-pass claims.
- `verification/results.json`: local attempts and views, with content IDs for
  before/after snapshots (schema 2). Not authenticated certification evidence.
- `verification/snapshots/<sha256>.json`: complete input snapshots, stored once
  per unique content hash. Track these alongside the index in Git.
- `docs/VERIFICATION_RESULTS.md`: generated report, not a database.
- `docs/VERIFICATION_CATALOG.md`: every catalog assessment and its latest
  historical outcome; use `show` to see all older successes/failures as well.
- `verification/.runner/logs/`: ignored local execution logs, referenced and
  hashed in attempts. Preserve relevant logs with your other local evidence.

### Results storage migration

Update the installed runner before opening a checkout containing schema 2:

```sh
cargo install --path tools/brynja-verify --locked --offline --force
brynja-verify migrate-results
```

The offline install assumes dependencies are already available locally.
`migrate-results` requires an existing results file and takes the same exclusive
state lock as execution. It does not load the registry, inspect inputs/tools,
run checks, recover running attempts, rewrite the report, or change outcomes,
dates, sources, failures, saved freshness or historical references. Repeating it
on unchanged state does not rewrite the index or create duplicate objects.
Normal status/run saves also upgrade schema 1; `show` and `report` can still
read schema 1 without migrating it. Old binaries fail on schema 2: upgrade them,
do not delete results or manufacture a new pass to work around that error.

Each object ID is SHA-256 over the complete snapshot file, including its final
newline, not merely the recorded input fingerprint. All referenced objects are
loaded and hash-checked before state is used. Missing, corrupt, malformed or
symlinked objects produce an error before execution; they never become an empty
history or a successful check. Restore the exact missing/corrupt objects from
the matching Git revision or backup. `show` still expands complete snapshots.
Content hashes protect integrity, not authenticity against someone who can
rewrite both snapshots and the index. Records remain local observations.

Objects are written before atomic index replacement, with file and directory
sync on Unix. A failed write can leave complete unreferenced objects or a
PID-specific `.verify-*.tmp` diagnostic file; it does not replace the old index
with references to partial objects. No automatic history pruning or object
garbage collection occurs. Preserve the index and all referenced objects when
copying a checkout. Snapshot outputs are excluded from verification inputs.

This removes duplicate snapshots and splits future growth across immutable
files; the index still grows with attempt metadata. It does not prune history;
the artifact budgets below stop over-limit loads/saves. Previously committed
large blobs remain in Git history, and a push
containing those old commits can still warn. No history rewrite, force-push or
Git LFS migration is performed.

### Artifact resource limits

Schema-2 references share immutable `Arc<Snapshot>` allocations: repeating an
object ID does not duplicate its maps or strings in memory. Freshness still
compares full snapshot contents, not pointer identity. The disk schema and
stored content hashes are unchanged.

The runner enforces fixed budgets, not values supplied by an artifact:

- Results index: 64 MiB, including legacy schema-1 input.
- Individual schema-2 snapshot: 2 MiB.
- Total distinct referenced snapshot-file bytes per load/save: 256 MiB.
- Attempts: 10,000 across all groups, enforced during JSON deserialization
  before accepting another row, and again before saving.
- Expanded `show` JSON: 64 MiB, serialized directly from borrowed data into a
  bounded buffer, without first expanding snapshots into a JSON value tree.

Byte limits include final newlines. File metadata is checked before reading;
the read itself is also bounded so file growth cannot bypass that check.
Totals use checked arithmetic, and repeated object references are charged only
once. Legacy inline snapshots are bounded by the index limit rather than the
schema-2 object limits. Byte budgets bound serialized data, **not total process
RSS**: parsed maps/strings, allocator overhead and other tool data use additional
memory. This is not an OS sandbox for an untrusted checkout or its commands.

Over-budget artifacts fail closed before execution; no automatic truncation,
history deletion or current-pass substitution occurs. Saving enforces the same
budgets and never publishes an index the loader would reject for these limits.
An oversized detail response fails without printing partial JSON or changing
state. Preserve the complete store when arranging explicit archival/rotation
at a limit; do not delete evidence merely to silence the error. As with other
save failures, a limit reached while completing a run leaves the durable
starting record and local log, not a fabricated successful completion.

### Snapshot storage follow-up review — 2026-11-04

The [owner-supplied review](../../security/pentest/v0.27.0-snapshot-storage-review-input.md)
identified Medium snapshot-reference memory amplification. The remediation is
shared immutable snapshots plus the parsing/serialization budgets above. It also
removes the intermediate expanded JSON value from `show`; otherwise that path
could recreate the same amplification after loading. No disk schema, content
hash, cryptographic implementation or recorded verification result changed.

Regression coverage includes 10,000 attempts sharing one 140 KiB object through
20,000 references (allocation identity is asserted), rejection of the next row
before parsing it, exact and exceeded byte/count/cumulative budgets, growing
streams, sparse oversized files, checked-add overflow, failed-save preservation,
and bounded detailed output without partial JSON. Existing tests continue to
cover malformed IDs, hash mismatches, symlinks, legacy migration, interrupted
writes, matching-input reuse and failure precedence.

Local validation: all 69 verifier tests passed on Rust 1.90.0 and 1.99.1,
including an isolated MSRV build directory; Clippy with `-D warnings`, formatting,
280 registry tests, 25 scoped-release tests and diff-integrity checks passed.
The updated installed runner's migration and detail-read smoke checks left the
real index, report and all 410 objects byte-identical. These observations are
not an independent retest or release approval. The accompanying AES observations
retain their [existing dispositions](aes128-pentest-remediation.md); physical
leakage/qualification limits are not claimed fixed by this storage change.

The scoped runnable registry contains **5,687 checks/configurations**: 27 portable,
48 sanitizer, 4,933 Miri, nine Kani, 350 compiler compatibility and 320 component
fixture/script checks. The portable checks cover MD5, SHA-1, SHA-2,
SHA-3/SHAKE/cSHAKE, KMAC, TupleHash, ParallelHash, HMAC and legacy HMAC. SHA-2
and SHA-3 checks are separated by their existing algorithm harnesses; the other
families use named vector, boundary or API harnesses. It is **not** a claim to
inventory every existing Brynja assessment or to finish all qualification by
running these portable checks. The original 32 ASan/LSan registrations comprise
30 single-component Cargo test commands and the two native MD5 AVX2 harnesses.
They cover core, MD5, SHA-1, SHA-2, SHA-3, KMAC, TupleHash and ParallelHash.
The registrations require Linux x86-64 and the locally installed pinned
`nightly-2026-09-11`; missing prerequisites do not trigger installation.
Leak detection stays enabled. The two native MD5 harnesses require AVX2 and
their existing backend completion markers. The other sanitizer checks claim
their selected test coverage, not execution of every optional hardware route.

For example, after reinstalling the updated tool:

```sh
brynja-verify list md5 asan
brynja-verify show md5 asan-106c9d5d31321a06
# The following commands execute checks; the two above do not.
brynja-verify run md5 asan-106c9d5d31321a06
brynja-verify run md5 --needed --category asan
```

Sanitizer scopes use declared crate closures, selected lock rows and relevant
workspace fields, plus the tested crate's test directory. Automatic `build.rs`
paths are recorded even when absent, so adding one invalidates the dependent
check. These scopes are deliberately conservative within each selected crate;
they are not a semantic per-function dependency analysis.

### Miri registrations

Another **4,933** registrations are all the cataloged Miri tasks:
697 routine, 4,125 extended and 111 original-full selections. These profiles
overlap; they are alternatives, not three required campaigns. The original
task IDs, test arguments, interpreter case selectors and coverage labels remain
intact. Each case requires its existing marker exactly once and exactly one
passed test; remaining aggregate selections require nonzero successful tests.
No interpreter safety checks are disabled. Each task has a one-hour limit;
timeout is recorded as incomplete/failed, never as passing coverage.

```sh
# Inspection only:
brynja-verify list md5 miri-routine
brynja-verify md5 --category miri-routine
brynja-verify show md5 CHECK_ID_FROM_LIST
# Explicit execution, only when you actually want these checks:
brynja-verify run md5 CHECK_ID_FROM_LIST
brynja-verify run md5 --needed --category miri-routine
```

Miri registrations currently require Linux x86-64 and locally available
`nightly-2026-09-11` Cargo, rustc, cargo-miri and miri executables. Status scans
only locate/hash local tools. Actual execution can prepare Miri's sysroot/cache;
no setup happens while inspecting status. Inherited interpreter/compiler
overrides are rejected with an explanation rather than weakening the check.
The registration invokes the existing Cargo-Miri task directly, not an ordinal
that could silently select a different test after catalog edits.

Shared input groups are read once within a status scan for practical performance.
That cache is discarded afterwards. Before/after execution snapshots always read
fresh inputs. Named/category runs refresh only their selected checks' views;
they do not rescan other categories after every task.

This includes eighteen selections in six separate fixture workspaces. Their
registrations use each workspace's own selected lock rows, manifests, source
and shared fixture files, rather than assuming the main workspace's lock applies.
Every assessment in the migrated catalog now has a runnable binding or an
explicit owner-approved manual disposition. There are no remaining unbound
assessment rows. This completes registration, not execution: unavailable tools,
unmapped historical inputs and checks not run remain clearly distinguished from
current passes. Supporting entry points and retired history remain references.

Five hardened assessment bindings preserve the existing MD5/SHA-1 source and
synthetic-artifact regressions, the SHA-2 compiled finalizer mutations, and the
SHA-2/SHA-3 hardened API acceptance commands. The latter require every named
Rust test (15 for SHA-2, 14 for SHA-3), and retain their downstream bare-metal
compile check. That compile check is not execution on bare-metal hardware.
The MD5 sanitizer-driver regressions use mocked subprocesses; their success is
not an ASan execution. The SHA-2 mutation command really compiles and runs
mutated fixtures when explicitly requested; registering it does not do so.

The HMAC inventory and acceptance-checker bindings are not native HMAC tests.
The inventory checks declared owners, profiles and documentation; its regression
suite requires eleven tests. The acceptance-checker suite requires twelve tests,
including five imported fault-driver tests, with compiler/native commands mocked.
In contrast, the acceleration-model regression command compiles its existing
debug/release mutants and Clippy probes when explicitly run. Its two required
summary markers cover 20 policy/source, 18 compiled, six driver and five lint
regressions. Registering or inspecting any of these commands runs none of them.

The HMAC timing-regression row is also distinct from a timing campaign: its
eight tests combine synthetic timing samples with a compiled portable smoke
test and four correctness mutations. The SHA-512/t CPU-regression row has five
tests covering feature/ownership compiler errors, ordinary-build rejection and
synthetic capture controls; it does not execute candidate acceleration or QEMU.
Both require the local Rust 1.99.1 toolchain and are currently registered for
Linux x86-64. The ten-test protected/resident HMAC checker row uses mocked
native/compiler commands and needs Python only. Missing or skipped tests cannot
count as a pass for these rows.

Some original source-policy checks deliberately read raw reviewed manifests,
gate text or workflow text. Those inputs belong to the individual policy row:
for example, the old SHA-1 source-review test hashes the root manifest. A
manifest change can make that policy result outdated without reopening SHA-1
runtime tests or proofs. Registering these commands neither updates their old
review pins nor claims they currently pass.

The default MD5/SHA-1 execution wrappers, hardened SHA-2/Keccak package checks,
and shared static/hosted CPU acceptance commands are now individually runnable.
They retain the original ownership, cleanup and compiled-mutation checks. Their
default preferred routes may remain portable; they are not required-native
captures. The compiled Keccak layout check also needs an installed AArch64
target, but does not execute it. Some cleanup subchecks explicitly use Rust
1.98.1 alongside the wrapper's compiler; both are declared inputs where needed.
The SHA-2 gate regression and CPU-boundary policy commands inspect source or
use fake subprocesses rather than starting the campaigns they describe.
Native/QEMU/write options are not added implicitly. Any missing prerequisite
or failure in an original policy remains visible for that selected check only.

### Compiler, fixture and additional sanitizer registrations

The 350 `matrix` registrations cover 25 existing selections on each of the
14 recorded compiler versions. They require installed local tools; inspection
does not download compilers. Each command is locked/offline and has a twenty-minute
limit. Ordinary compatibility suites may leave native-only tests ignored, but
must execute at least one passing test and report zero failures. An ignored test
is never native qualification. Mac-specific selections require macOS Arm64.
Acceptance programs retain their named completion marker; the SHA-512/t vector
program receives its declared input file through stdin, which is fingerprinted too.

The 27 `repository` fixture registrations run selected API, policy, doctest or
Clippy checks, not the old entire repository campaign. Another 16 sanitizer
registrations cover existing shared CPU, hosted-policy and native harnesses with
their original completion signals and forced leak checking. None ran during
registration migration.

Another 27 `repository` registrations bind existing scripts: 14 foundational
contract checks/regressions, three constant-time checker checks, one mocked MD5
sanitizer-checker regression, and nine independent hash/HMAC comparisons.
Source-policy checks establish only their stated structural contracts, not native
qualification or cryptographic proofs. The comparisons retain their existing
oracles, corpus completion signals and selected fixture dependencies. Their Rust
commands use the pinned local compiler and offline dependency resolution.
Optional CPU/hosted inputs are excluded from portable comparisons where unused.
Adding these bindings did not execute the comparisons or refresh their history.

Eight more source-policy/mutation checks cover DER, ASN.1, record framing and
the CPU-backend contract. Use `pki`, `protocol` and `static_cpu` to inspect those
components. Their scopes include the exact files inspected by each policy, not
transitive cryptographic implementations that the source checker never executes.
Package-policy checks select only their relevant TOML fields. The paired
mutation tests copy and replace literal TOML text, so those tests conservatively
track the whole manifest/policy files: even formatting can break their mutation
anchors. They are small structural-checker tests, not a reason to repeat native
or cryptographic qualification. Original IDs, commands and historical records
remain linked despite correcting the old blanket repository ownership labels.

Twelve additional `repository` bindings preserve existing HMAC scratch-cleanup
compiler profiles and compiled-mutation tests, two HMAC proof-inventory commands,
cSHAKE vector reproduction, ParallelHash execution comparisons and a mocked
Keccak sanitizer-driver regression. Scratch checks inspect emitted artifacts;
they neither execute a native backend nor establish whole-composition erasure.
They require the selected local compilers/target support and retain each original
compiler/panic completion marker. Python test suites require their existing
nonzero test count and an unskipped `OK` summary.

Seven portable HMAC caller-cleanup bindings add modern x86/Linux Arm and legacy
x86/Linux Arm/Apple Arm emitted-code checks, plus their two mutation suites.
Each selection retains its original compiler versions and abort/unwind profiles;
cross-compiling for Arm does not mean running on Arm. The modern mutation suite
requires 27 tests (including eight inherited constructor cases), and the legacy
suite requires nine. Their helper modules and relevant crate closures are
fingerprinted; mutation suites also track raw fixture manifests and locks because
they copy and edit that text. Accelerated/hosted owners and whole-frame erasure
are outside these checks. These registrations add no release obligation.

Eighteen legacy HMAC-MD5 checker-regression suites are also individually runnable.
They cover the existing descriptor, key, normalization, report, output, caller
and teardown checker boundaries. Each requires its exact existing unittest count
and an unskipped `OK` summary. Their scripts retain the original compiler,
target, panic and SIMD-emission selections; these inspect compiler output rather
than executing native cryptography. The shared MD5 checker helpers, relevant
legacy crate sources and raw mutation fixture manifests are fingerprinted.
The separate native test driver is not included in these bindings. As with the
other migrated checks, registration does not turn saved history into a current
pass or require a new execution.

The hosted HMAC checker now has 59 runnable selections: 22 modern and 37 legacy
groups, retaining all 171 selected unittest methods. Each group remains a
separate command; `run hmac CHECK_ID` does not run its neighboring groups.
Another 28 commands cover the existing HMAC hosted, accelerated, static and
MD5 compiler profiles and mutation suites. Twelve leaf code-generation commands
cover MD5, SHA-1, SHA-2, Keccak, KMAC, TupleHash and ParallelHash. These commands
inspect emitted code, including cross-target artifacts where originally selected;
they do not execute Arm/Apple cryptography or claim native qualification.
They retain the original compiler pins, not an automatic upgrade to the latest
compiler. Missing local compiler/target support is a prerequisite problem, not
permission to install tools or run another campaign.

The hosted checkers prefer `llvm-cxxfilt` when available and otherwise use
`c++filt`. Their bindings record the optional tool's presence/content as well
as the required fallback. Installing, changing or removing that optional tool
can change these checks' freshness; it does not invalidate unrelated checks.
Returning to an earlier successfully tested tool configuration may reuse that
original result without changing its date.

The two `--policy-only` commands report declared proof populations, **not executed
proofs**; use the separate `kani` registrations for actual proof execution.
cSHAKE reproduction checks stored vectors against the existing Python oracle,
without compiling Rust. ParallelHash requires all seven existing modes in both
debug and release, plus explicit “native/static not requested” summaries; prefer
modes may use portable execution. These are optional named assessments, not new
release requirements. None executed during registration migration.

```sh
# These only list/inspect:
brynja-verify list md5 matrix
brynja-verify list kmac repository
brynja-verify show md5 CHECK_ID_FROM_LIST
# This explicitly executes one selected check:
brynja-verify run md5 CHECK_ID_FROM_LIST
```

Shared registrations have one owning component. Another component's `list`
shows `use run OWNER ID`; `show` displays that same registration and its history.
It does not create a duplicate check or silently broaden a run.

Three HMAC checker registrations cover facade isolation (five tests), strict
consumer policy (nine tests) and package acceptance regressions (twelve tests,
including three combined-graph cases). They mock builds and test summaries;
they do not build the actual packages or execute HMAC. Their scopes include the
imported checker helpers and the specific fixtures they read. The facade/strict
policy tests also inspect package names and versions, so those metadata fields
affect these policy rows only—not previous HMAC execution results.

Six record/source-policy bindings cover the offline sanitization admission and
its regression suite, SHA-256/SHA-512/Keccak batch policy regressions, and the
historical combined-hash claim checker. SHA-2 batch sanitizer calls are mocked;
these selectors execute no compiler, sanitizer, native backend or proof. They
retain the raw manifests, locks and gate/review text actually inspected by those
old policies. Such changes affect these policy rows only, not other results.
Registering a historical policy does not guarantee that its old pins or wording
still pass; any failure is recorded as that check's result, not a request to
repeat the computations represented by its historical evidence.

### Manual diagnostics

An earlier binding group added 17 shell/compiler checks, six synthetic checker
suites, three differential commands and 13 source-policy checks. Each retains
its existing completion signals and selected inputs. The source-policy rows
may inspect old review pins or gate text; that makes those files inputs to the
policy row only, not to every cryptographic result. Registering these commands
did not execute them or upgrade their old observations to current passes.

The following group adds ten legacy source-policy/model selections and two
synthetic checker suites. The MD5/SHA-1 optimized-invariant selectors also run
their existing two Rust tests; their registrations require exactly two passes.
The legacy timing checker uses synthetic observations and excludes its optional
`--compiled` mode. The macOS package checker tests archives, corpus generation
and manifest closure without running Apple code. Their names are not claims of
fresh timing, sanitizer or native qualification.

With owner approval, 112 catalog entries remain **manual diagnostics**: 95
repository/release/reference/evidence-tooling tasks, 14 whole-workspace compiler commands and
three combined/native sanitizer diagnostics needing their original setup or
review context. They retain their original category, command and historical
observations. `list` labels them and `show` explains why. They are not current
passes, unfinished component requirements, or automatic `--needed` work.
To use one deliberately, inspect its original command and prerequisites first;
the tracker does not implicitly run it or promote its old result.
The evidence-tooling entries include eight native-record/schema and capture
regression commands, plus seven ledger, bundle and CI-binding diagnostics. Some
compile synthetic test-output fixtures or mock sanitizer drivers; they are not
native cryptographic captures. Actual native HMAC and sanitizer execution checks
are not covered by this classification. Revisit these diagnostics when their
specific tooling changes, not whenever another cryptographic component changes.
Twelve exact historical campaign-selection, review-inventory and whole-workspace
metadata selectors are also included. Their execution variants are not exempted.
The retained `test-verification-plan.py` diagnostic still expects the old CI
preflight and does not pass against the new scoped workflow. It is not in the
new finite CI list; do not restore the blanket preflight to satisfy that old
assertion. The current handoff has separate scoped-release regression tests.
Five historical multi-family acceptance rollups are also manual campaigns:
legacy portable/final acceptance, combined modern-hash acceptance and the two
SP 800-185 acceptance wrappers. Unlike status scans, explicitly invoking these
can compile and run substantial tests. Their individual fixture/package/policy
checks remain separately registered or visibly unresolved; retaining a rollup
does not mark those checks passed or erase them from the migration backlog.

### Package and execution-oracle registrations

Nineteen additional `repository` bindings expose the existing MD5/SHA-1
portable package checks, SHA-2/SHA-3 public consumers and their regression
suites, ordinary SHA-2/SHA-3 execution packages, SHA-256/SHA-512/Keccak batch
packages, KMAC/TupleHash/ParallelHash execution packages, and the portable
KMAC/TupleHash execution-oracle commands. Use `list COMPONENT repository` and
`show COMPONENT ID` to inspect each exact command before running it.

These are real compilation/runtime/mutation checks when explicitly run, not
status scans. Native, QEMU, sanitizer and proof modes are not selected by these
bindings. Preferred or protected paths do not establish a required native
backend pass. Package checks track the selected archive contents, fixtures,
helpers and dependency rows; packaging-identity changes do not reopen separate
algorithm evidence. The original policy inputs are retained where a wrapper
actually checks them, including old review/gate text. Such a policy may fail
against the current repository; a runnable binding is not a claim it passed.

The registration tests use fake compiler/process results and static inventories.
They do not execute these original campaigns. Existing historical observations
retain their dates and remain historical until input compatibility is established.

The owner and legacy graph bindings distinguish three kinds of work:

- API-profile and composed HMAC owner regressions inspect source contracts and
  historical pins. They do not execute the checks referenced by those pins.
- The two legacy-HMAC package regression suites inspect offline Cargo metadata
  and test synthetic graphs/oracles. Hosted wrapper parity is source inspection,
  not a protected-worker execution.
- The direct secret-owner compiler check builds test discovery and inspects MIR
  under Rust 1.90.0 and 1.98.1. Test discovery does not run the discovered tests,
  and this command does not establish composed HMAC or native qualification.

The four SP 800-185 and legacy acceptance regression commands include real
compiled disposable mutations when explicitly requested. Their historical
policy checks are retained, but they do not launch the old milestone rollups.
The SP 800-185 capture tests use fake hosts and processes, not new native records.
Registration regressions use fake compiler children to test all 42 portable
SP 800-185 corruptions, four execution corruptions, and the legacy batch controls.

The final eight bindings cover the six modern/legacy HMAC package, protected,
facade and strict commands and the general SHA-512/t check/regression pair.
These existing commands include real compiled consumers and mutation controls
when requested; registering them does not execute them. They may take longer
than a simple known-answer check. Inspect their command with `show` first.

Four package wrappers now accept `--toolchain`; their registrations explicitly
select installed Rust 1.99.1 after removing ambient compiler flags. The facade
packager also uses the same compiler as its downstream consumers. Original
catalog commands and historical observations are unchanged; old ambient-toolchain
results are not silently promoted to this configuration. The facade requires an
installed `x86_64-unknown-none` target. Protected consumers require GNU/Linux.
The general SHA-512/t check also uses its original Rust 1.90.0/1.98.1 emitted-code
profiles; its regression command uses Rust 1.99.1. Missing prerequisites fail
without installation, fallback or an unrelated campaign.

These archive assessments track their actual packaged crate trees, copied
fixtures, imported helpers and selected dependency rows. That wider archive
scope does not apply to independent algorithm checks. Old source-policy pins
remain historical: a changed wrapper may make its old policy check fail, but
does not invalidate earlier cryptographic executions or create a release gate.

### Kani registrations

Nine runnable groups cover the existing MD5, SHA-1, SHA-2, SHA-3, KMAC,
TupleHash, ParallelHash, HMAC and legacy-HMAC bounded proofs. These establish
specific length, boundary or control properties, not cryptographic security.
No proof or assumption was added or changed for this migration.

The seven leaf groups use their original Cargo-Kani arguments, without the old
unrelated repository-wide inventory preflight. Each command must report its
exact existing successful proof count and zero failures. The two HMAC groups
retain their existing wrappers and completion checks. Each group uses a fresh
private build directory, offline Cargo resolution, and the existing five-minute
per-command limit; the runner also caps each group at twenty minutes.

Kani currently requires Linux x86-64, Rust 1.90.0, and the installed Kani 0.68.0
distribution (CBMC 6.11.0). Status scans read local tool identities, including
the Kani distribution's binaries, libraries, proof-model sources and linked
compiler. They do not execute Kani or install anything. A missing installation
is unavailable, not a pass. Nonstandard Kani-home overrides are not supported.

Five old catalog selectors—core, sanitization, legacy, acceleration and
static_cpu—ran only inventory/setup validation, not proof harnesses. They remain
visible as `inventory-only` references with their original observations; they
are neither current proof passes nor missing proof obligations.

### Complete catalog

The separate complete discovery inventory now includes 6,237 current entries:
4,933 Miri configurations across routine, extended and original-full profiles;
415 repository tasks; 364 compiler-matrix entries; 51 ASan commands; nine Kani
groups; five inventory-only references; 449 standalone script entry points/helpers;
and 11 workflow jobs.
It also retains 382 historical task identities no longer in the current catalogs,
for 6,619 entries in total. Profiles and aggregate commands overlap; these are
not counts of distinct assertions or new execution requirements. Standalone
entry points may require arguments or be helper modules: they are not presumed
safe executable tests simply because a file exists.

Status output groups these by component/category, with runnable registrations
removed from the unresolved list. `list` shows individual IDs;
`show` explains the command and history. Historical success, failure, cancellation
and reuse remain historical. In particular, a reuse campaign's source commit is
not substituted for an unknown original execution commit. The catalog covers the
repository's declared command catalogs, script entry points and workflow jobs;
it cannot enumerate arbitrary future feature/platform combinations or every
assertion inside an aggregate suite.
The [older dashboard](test-dashboard.md), [Miri history](miri-coverage.md) and
[evidence index](../evidence-index.md) remain available. Historical combined
commands and aggregate receipts are not silently converted into fresh passes
for the registered command/configuration. `Not run` here means no mapped execution
for this registration, not that the algorithm was never tested.

`verification/historical-index.json` inventories 47 preserved local dashboard
files by digest, with 10,020 observation rows and their original date ranges.
These include overlapping imports and reused observations, not 10,020 distinct
fresh executions. None exactly matches the 27 registered commands and their
new scoped/tool-identity schema, so **zero current passes were imported**.
The local files remain under `../brynja-evidence/dashboard/`; the index is a
reconciliation reference, not an attestation or a requirement to rerun them.

All migrated bindings retain their corresponding catalog history in `show`.
Until a scoped execution is recorded, the status/report also shows the latest
historical outcome and original timestamp, explicitly as **historical inputs
unmapped**, never as a current pass. New commands add locked/offline resolution
and explicit runtime settings where needed; historical snapshots do not contain
the new scoped/tool fingerprint. No current compatibility is invented. A new
failed or interrupted attempt takes precedence over imported history.
`show` and the terminal/report use the same historical presentation. “No
execution recorded by this runner” does not mean the preserved older check
never ran, nor is it an instruction to rerun it.

Add further registrations when their command, configuration, scope and completion
signal are known. Import historical success only with its real source snapshot,
settings, tool identity, command and execution dates; otherwise retain an
explicit historical/unmapped reference. Do not initialize the tracker by
rerunning all cryptography. Version one does not turn legacy receipts into current
passes. It reconciles their original observations into the browseable catalog.

After adding/removing tests or changing command catalogs, explicitly rebuild the
discovery inventory (not the verification results):

```sh
python3 scripts/release/export-verification-catalog.py --write
# After reviewing changes to the existing Miri task definitions/scopes:
python3 scripts/release/export-miri-registrations.py --write
# After reviewing changes to existing bounded proof commands/scopes:
python3 scripts/release/export-kani-registrations.py --write
python3 scripts/release/export-verification-catalog.py --write
brynja-verify report
```

This reads existing catalog definitions and the digest-bound saved dashboard
files referenced by `verification/historical-index.json`. It executes no test,
proof, remote command or test discovery subprocess. If a saved file is missing
or changed, reconciliation stops rather than discarding history. Without
`--write`, it compares the current declarations with the saved catalog; it does
not require the external logs. Status commands never run this exporter and
never silently rediscover or schedule checks. The table is an explicit inventory
snapshot, not a claim that unregistered future tests have been discovered.

The Miri exporter translates existing task definitions using explicit reusable
package scopes, not Cargo execution or a general dependency resolver. Unknown
packages/features fail for review. Regeneration does not change any execution
record. Do not initialize newly registered rows by rerunning old campaigns.

The tool never stages, commits, tags, pushes or publishes. Review and manually
commit registry/results/report changes when useful. Execution state is saved
before report rendering; if rendering fails, fix the destination and use
`report`. The execution does not need to be repeated. Mutating commands hold an
OS lock and atomically replace the state; concurrent commands fail clearly.

## Registering a check

Use stable component/check names and one entry per independently runnable task
and meaningful configuration. Reuse existing command/harness boundaries, not
one row per assertion. The current TOML contains complete examples.

Declare what the check establishes; executable/arguments and working directory;
safe necessary environment overrides; input groups; success markers; and a
time/output limit. Arguments execute directly, without shell interpolation.
Use an existing script when a shell pipeline is genuinely needed. Registry
commands are trusted local code, not a sandbox. Never store secrets in arguments,
environment overrides or output. The runner does not copy the whole environment.

Input groups support:

- explicit files or directories (recursive, regular files; symlinks rejected);
- optional paths whose absence or presence is also part of the fingerprint;
- fixed-depth file patterns, such as `patterns = ["crates/*/Cargo.toml"]`;
- selected dotted TOML fields instead of whole workspace manifests;
- selected lockfile package rows instead of the global lockfile;
- local executable hashes, including installed pinned rustup tools.

Patterns support `*` within a path segment, not recursive `**`, `?` or bracket
expressions. Start with a literal directory. For example,
`scripts/sha2/*sha256*batch*.py` includes new matching helpers without selecting
SHA-512 helpers or nested directories. Empty matches are recorded, so the first
matching addition changes freshness. Selected names and bytes are fingerprinted;
matching symlinks and non-files are rejected. Patterns never run discovery
commands, and generated state/reports and build directories stay excluded.

An ordinary PATH tool may declare `optional = true` when the existing command
has a deliberate fallback. Its absence is then an explicit input value, not a
missing required prerequisite. This does not make Rust toolchains or proof
bundles optional. Status scans never execute optional tools to identify them.

Resolved relative paths and bytes detect additions, removals and renames. Build
outputs, results/report files and runner logs are excluded. A release number in
a local lockfile row is not an implementation change; external versions,
sources, checksums and dependency edges are retained. Ambiguous/missing package
rows or unavailable tool binaries are unresolved, not presumed equivalent.
Ambient Cargo configs are currently rejected as unresolved rather than silently
ignored. This includes custom `CARGO_HOME` locations, including registry
environment overrides. Compiler wrapper files are fingerprinted by content,
not just by their filename. Tool lookup uses the registered environment overrides.

The registry is an explicit model, not automatic dependency analysis. Include
the relevant transitive implementation, build inputs, oracle, fixture and
configuration. Review it when those relationships change. Changes to selected
features, command, bounds, completion signals and effective environment affect
freshness. Increment `execution_semantics` for a substantive change to shared
execution/acceptance behavior, not for help text or report formatting. Do not
include the runner's whole source tree in every cryptographic check.

The selected registry definition is re-read before and after execution as well
as the input files. Editing a command, completion marker, bound or declared scope
mid-run cannot create a current pass. An edit to a later selected check stops
that stale selection before it executes; inspect and select again.

Exit zero alone is insufficient. Reuse a check's existing meaningful completion
markers. For libtest, `minimum_tests` additionally requires nonzero passing
population and zero failed/ignored tests; exact markers can require a specific
test or backend. Do not add crypto assertions just to satisfy the tracker.
`unique_lines` requires each named line exactly once. For an existing driver
whose completion line includes an artifact-dependent diagnostic suffix,
`unique_prefixes` requires exactly one line starting with each declared profile
prefix. These are literal matches, not regular expressions or test discovery.
Declare full compiler/target/profile identities, not a generic `PASS` prefix.

## Testing the tool itself

```sh
cargo test --manifest-path tools/brynja-verify/Cargo.toml --locked
cargo clippy --manifest-path tools/brynja-verify/Cargo.toml --locked --all-targets -- -D warnings
```

These use temporary repositories and fake commands. They test isolation,
freshness, history, failure, cancellation, locking and reporting—not cryptography.
