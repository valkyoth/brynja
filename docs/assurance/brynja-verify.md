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
| `brynja-verify sha1` | Read SHA-1 inputs and show its status. Run nothing. |
| `brynja-verify run md5 known-answers` | Execute only that registered MD5 check. |
| `brynja-verify run md5 --needed` | Execute MD5 checks without a current successful result. |
| `brynja-verify run md5 --all` | Explicitly rerun every registered MD5 check, even current passes. |
| `brynja-verify full-check` | Scan all registered inputs and refresh statuses. **No tests run.** |
| `brynja-verify report` | Regenerate Markdown from saved state, without scanning inputs. |

`--needed` and `--all` are sequential. An executed failure stops the sequence;
completed results stay saved and remaining checks are listed. Missing inputs
or tools are reported as unavailable, not passed. Unknown components/checks are
errors, never a request to run a larger scope.

Use Ctrl+C to interrupt a run. The runner stops its child process group and
records interruption. A force-killed/crashed runner leaves a running attempt;
the next scan of that component identifies it as interrupted, without guessing
an end time. Inspect its log before restarting. A host crash or force-kill can
leave child processes outside the runner's control: check those before retrying.

Do not edit relevant inputs while a check runs. The tool compares them before
and after execution. A changed-input run is recorded but is not a current pass.
This is a best-effort guard, not execution from an immutable source snapshot.

## Reading results

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
- `verification/results.json`: authoritative attempts, fingerprints and views.
- `docs/VERIFICATION_RESULTS.md`: generated report, not a database.
- `verification/.runner/logs/`: ignored local execution logs, referenced and
  hashed in attempts. Preserve relevant logs with your other local evidence.

The catalog registers 27 existing portable checks across MD5, SHA-1, SHA-2,
SHA-3/SHAKE/cSHAKE, KMAC, TupleHash, ParallelHash, HMAC and legacy HMAC. SHA-2
and SHA-3 checks are separated by their existing algorithm harnesses; the other
families use named vector, boundary or API harnesses. It is **not** a claim to
inventory every existing Brynja assessment or to finish all qualification by
running these portable checks.
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

Add further registrations when their command, configuration, scope and completion
signal are known. Import historical success only with its real source snapshot,
settings, tool identity, command and execution dates; otherwise retain an
explicit historical/unmapped reference. Do not initialize the tracker by
rerunning all cryptography. Version one does not provide a bulk receipt importer.

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
- selected dotted TOML fields instead of whole workspace manifests;
- selected lockfile package rows instead of the global lockfile;
- local executable hashes, including installed pinned rustup tools.

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

## Testing the tool itself

```sh
cargo test --manifest-path tools/brynja-verify/Cargo.toml --locked
cargo clippy --manifest-path tools/brynja-verify/Cargo.toml --locked --all-targets -- -D warnings
```

These use temporary repositories and fake commands. They test isolation,
freshness, history, failure, cancellation, locking and reporting—not cryptography.
