# Test dashboard: everyday guide

The dashboard helps you answer three questions: **What tests exist? What ran
last time? How do I run just one check?** It prints tables in your terminal;
despite the `gui` filename, there is no separate window or mouse interface.

Opening the dashboard does not start tests. You choose a task before running it.
It does not automatically run the next task, rent an AWS server, or publish a
release. Some tasks still contain a suite of tests; the dashboard warns you
before starting those.

## Quick start: run one MD5 sanitizer check

Open a terminal in your Brynja checkout. On the development PC:

```sh
cd /home/eldryoth/Work/codex-projects/brynja
```

1. Show the available MD5 sanitizer tasks:

   ```sh
   python3 scripts/release/brynja-test-gui.py --phase asan --family md5 list --tasks
   ```

2. Copy one value from the `ID` column. Inspect it before running it:

   ```sh
   python3 scripts/release/brynja-test-gui.py show asan-106c9d5d31321a06
   ```

3. Start that one task, allowing up to 30 minutes:

   ```sh
   python3 scripts/release/brynja-test-gui.py run asan-106c9d5d31321a06 --seconds 1800
   ```

   Type `y` and press Enter when asked. Any other answer starts nothing.
   Keep this terminal open until the command finishes. The final line tells
   you the result, elapsed time and where its full log was saved.

4. Check the updated summary:

   ```sh
   python3 scripts/release/brynja-test-gui.py --phase asan --family md5 list
   ```

The example ID currently selects ordinary MD5 AVX2 ASan/LeakSanitizer, **not all
four MD5 sanitizer tasks**. Always list first: IDs change when a task's meaning
changes. This example requires suitable x86 AVX2 hardware and the tools needed
by that test; selecting it on a Mac does not turn it into an Arm test.

The time limit is a maximum budget, not an estimate. `300` is five minutes,
`1800` is 30 minutes and `7200` is two hours. The default is 300 seconds; the
largest accepted limit is 86400 seconds (24 hours). Reaching the limit records
`timed_out`, not a pass. You can later choose to run that task again.

## Browse without starting anything

Run from the Brynja checkout:

```sh
python3 scripts/release/brynja-test-gui.py
python3 scripts/release/brynja-test-gui.py --phase miri --family kmac list
python3 scripts/release/brynja-test-gui.py --phase miri --family kmac list --tasks
python3 scripts/release/brynja-test-gui.py --phase miri --family kmac list --tasks --offset 50 --limit 50
python3 scripts/release/brynja-test-gui.py slow
```

No compiler, verifier, network operation or test is started by listing. No
third-party terminal/UI dependency is needed. This first interface is a command
dashboard, not a mouse or arrow-key application. Filters precede the subcommand.
Times are UTC. `--profile routine` lists routine Miri tasks; the initial default
is extended to make the incomplete v0.25.2 campaign visible. Listing that profile
does not authorize running the campaign or change release requirements.
Task pages show 50 rows by default and shorten long labels to fit the terminal;
`show TASK_ID` always exposes the full resolved definition and command.

The summary groups the existing repository, compiler matrix, sanitizer, Miri
and Kani work-item catalogs by implementation. `list --tasks` shows task IDs,
last result/date, duration and resolved tests/case selectors. These are runnable
work items, not a promise that every Rust test already has its own row: broad
suite commands are retained and flagged when launching. Platform-native capture
records, manual reviews and GitHub jobs are not yet included in this dashboard.
ParallelHash matrix rows explicitly show `bounded-parallelhash-v1`: the owner
approved bounded interpreted cases plus exhaustive native matrices. This label
is not an exhaustive Miri claim, including when selected under `--profile extended`.
New TupleHash width and KMAC setup rows have distinct IDs; old unsplit results
remain historical and are not automatically credited to the new rows.

## Commands and filters

| Command | What it does |
| --- | --- |
| No command, or `list` | Shows a summary grouped by implementation and check type. |
| `list --tasks` | Shows individual task IDs and their latest results. |
| `show TASK_ID` | Shows the complete task definition, command and latest saved result as JSON. |
| `run TASK_ID` | Runs that one task after asking for confirmation. |
| `slow` | Shows up to 20 slowest latest observations, useful when choosing work to split. |
| `history` | Prints every indexed observation as JSON, including earlier attempts and retired task IDs. |
| `import-job PATH --receipt HASH` | Validates a saved detached job and adds its results to the local history. Does not rerun tests. |
| `--help` | Shows the available options. Use `run --help` for run-specific options. |

Replace `TASK_ID`, `PATH` and `HASH` with actual values; do not type those
placeholders literally. `history` is an advanced inspection command and does
not apply the family or phase filters.

Put these general options **before** the command:

| Option | Meaning |
| --- | --- |
| `--family md5` | Only show MD5 tasks. Other examples: `kmac`, `tuplehash`, `parallelhash`, `legacy_hmac`. |
| `--phase miri` | Select a check type. Repeat it to select several types. |
| `--profile routine` | Select the routine Miri task list. The default is `extended`. |
| `--store /absolute/private/path` | Use another local history directory instead of the default. |

The check types are:

| Phase | Plain-English explanation |
| --- | --- |
| `repository` | Repository policy, packaging and other project checks. |
| `matrix` | Compatibility checks across configured compiler/build combinations. |
| `asan` | Tests compiled with sanitizers to detect memory errors; some commands also check leaks. |
| `miri` | Rust interpreter checks for invalid memory and language operations on the selected paths. Often slower than native tests. |
| `kani` | Bounded model-checking proofs for the registered harnesses. |

`routine` and `extended` select different Miri coverage. `existing-full` exposes
the original broad commands and can be very slow; it is not a recommended
shortcut for daily work. The profile does not change the other check types or
approve a release sweep.

For a routine task, keep the profile when inspecting and starting it:

```sh
python3 scripts/release/brynja-test-gui.py --profile routine --family kmac --phase miri list --tasks
python3 scripts/release/brynja-test-gui.py --profile routine show TASK_ID
python3 scripts/release/brynja-test-gui.py --profile routine run TASK_ID --seconds 300
```

Individual task lists show 50 rows at a time. `--offset 50 --limit 50` shows the
next 50; `--offset 100 --limit 50` shows the following page. These options go
after `list`. The maximum page size is 1000.

## Read the table

For example:

```text
IMPLEMENTATION   CHECK       PASSED/TOTAL  STATUS          LAST RUN (UTC)        LONGEST
md5              asan        2/4           partial         2026-10-29T08:07:38Z  0m00s
```

This means two of the four currently listed tasks have a latest recorded pass.
It does not mean that the other two failed. Use `list --tasks` to see which
ones are missing, interrupted or failed.

- `LAST RUN` is the most recent recorded timestamp in that row, in UTC, not
  necessarily the time every task completed. An active attempt uses its current
  saved observation; the table is not a live process monitor.
- `LONGEST` is the longest duration among the latest observations for those
  tasks, not a total runtime or estimate of time remaining.
- `0m00s` can mean a duration below one second, or no observations yet.
- In `list --tasks`, `DURATION` belongs to that individual task's latest attempt.
- Long names are shortened on screen. `show TASK_ID` displays the full name.

## Inspect and refresh another check

Copy an ID from the list (replace `TASK_ID` below):

```sh
python3 scripts/release/brynja-test-gui.py show TASK_ID
python3 scripts/release/brynja-test-gui.py run TASK_ID --seconds 300
```

Leave the checkout unchanged during execution: editing sources invalidates a
successful run. Do not run `cargo clean` or unrelated commands that modify the
same build directories while a test is running.

Keep the same `--profile` when selecting a routine task. `show` displays exact
arguments, stdin fixture, environment additions and latest provenance. `run`
asks for confirmation; `--yes` confirms that single command noninteractively.
It never retries, launches the next task, starts a family sweep, provisions a
host or modifies gate approval. The default timeout is five minutes; an explicit
larger budget is possible. Logs are bounded at 16 MiB. Ctrl-C requests graceful
runner cancellation and retires child processes; timeout/cancellation is not PASS.

The local runner supports POSIX hosts (Linux/macOS). Use the existing dedicated
Windows workflows for Windows-specific checks. Native commands still require
their proper target, features, hardware, toolchain and protected approval input;
the dashboard does not synthesize those prerequisites.

## Watch progress, stop a test and find its log

You can open a second terminal and run `list --tasks` or `show TASK_ID` while
the first terminal runs the test. These commands only read the saved state;
there is no automatic screen refresh. Run them again when you want an update.

Find the `log` path in `show TASK_ID`, then read it with:

```sh
tail -f /actual/path/from/show/output.log
```

Replace that example path with the real one. Ctrl-C in the `tail` terminal
stops watching only. **Ctrl-C in the original `run` terminal cancels the test.**
Wait for cancellation to finish before starting another task. A quiet log can
mean compilation or a slow test, so silence alone is not a failure diagnosis.

Only one dashboard runner can run at a time for a given store. Browsing is
still allowed. Do not bypass that lock with a different `--store` to run tests
against the same checkout/build directories at the same time.
The dashboard does not detach a run from your terminal or
automatically resume it after a reboot. A retry of a small task is a new attempt;
it does not restart every task in the family.

## Where results are kept

Results live outside the checkout and disposable Cargo target directories in
`../brynja-evidence/dashboard/` (0700; result/log files 0600).
Those permissions mean only your user can access the stored results.
`--store` selects another private directory. Each attempt has its own log and
timestamp; failed refreshes remain visible rather than hiding behind older
passes. A lock prevents concurrent dashboard runners sharing build directories.
After a hard kill or power loss, inspect the PID in `runner.lock` and the latest
record before manually removing a stale lock. A remaining `running` observation
is not proof that a process is alive or that the command completed.

Source and tool inventories are compared before/after local runs; drift
invalidates a nominally successful result. This is a cooperating developer tool,
not a sandbox for hostile source or a substitute for frozen verification jobs.

## Import saved AWS or local detached evidence

This is for an existing downloaded verification job, not for launching work on
AWS. You need the directory containing its saved manifest/results and its
original receipt SHA-256. Do not substitute a source commit for the receipt.

```sh
CARGO_BUILD_JOBS=2 python3 scripts/release/brynja-test-gui.py import-job /absolute/path/to/saved/job --receipt RECEIPT_SHA256
```

Use the original build-environment identity (the v0.25.2 AWS runs used
`CARGO_BUILD_JOBS=2`). Import invokes the trusted local historical validator:
source closures, command populations, original tool records, terminal result and
log hashes must validate before indexing. It does not execute archived code.
For relocated parent dependencies, add
`--locations ../brynja-evidence/receipt-locations.json`. This is only a local
receipt-to-directory map, not an approval or substitute for validation. Keep
original archives and receipts: the dashboard index is not their replacement.

For example, with placeholders replaced by your actual job and receipt:

```sh
CARGO_BUILD_JOBS=2 python3 scripts/release/brynja-test-gui.py import-job /absolute/path/to/saved/job --receipt RECEIPT_SHA256 --locations ../brynja-evidence/receipt-locations.json
```

Completed commands from cancelled/partial jobs retain their actual individual
passes; interrupted commands remain interrupted. Unexecuted tasks remain
`never run` in this local index. That label means no indexed observation, not
that nobody has ever run the test. `history` includes old IDs absent from the
current catalog. Reimporting does not inflate the summary's unique task count.

## Read status honestly

- **all observed:** every displayed task has a latest recorded pass; this can
  combine historical runs and is not current-source or release qualification.
- **partial:** some observations exist, but coverage is incomplete or interrupted.
- **failures:** the latest attempt for at least one task failed/was invalidated.
- **never run:** no observation has been imported or generated for that task ID.

Individual tasks also show `running`, `passed`, `failed`, `timed_out`,
`cancelled`, `interrupted`, `log_limit` or `invalidated`. `log_limit` means the
output reached the safety limit. `invalidated` means the run cannot be accepted,
for example because its source or tool inventory changed during execution.
A newer failure remains visible even if an earlier attempt passed.

Current applicability is deliberately **not assessed** by the dashboard. Task
IDs bind command meaning (including Miri selectors/profile), not proof that a
past implementation/toolchain still matches today's checkout. `show` exposes
the original commit, source identity, log and provenance. Local diagnostic runs
do not produce detached release receipts. External owner approval, native review
and existing reuse validators remain separate; no dashboard status authorizes a
tag/publication. A forged local JSON file is not authenticated evidence.

## Common questions

**Why does it say unknown task ID?** List current IDs again and use the same
Miri profile you used when selecting the task. A changed test definition can
have a new ID; old IDs remain available in `history`.

**Why does it say never run when we ran it on AWS?** That result may not have
been imported into this store, or it may belong to an older task definition.
Import the validated saved job; do not manually mark the new task passed.

**What must be installed?** Browsing needs Python and the repository's local
scripts. Running additionally needs the tools named by the selected command,
such as its Rust compiler, Miri, Kani or a sanitizer-capable toolchain. The
dashboard does not install them. A missing tool or unsupported CPU is not a
cryptographic test pass; inspect the log before retrying on a suitable host.

**What if a crash leaves a running row or lock?** Check whether the original
process and its children are still alive. Do not delete `runner.lock` while a
test is active. After confirming no runner remains, a stale lock can be removed
manually; keep its log and result record. Do not change the record to passed.

**Can I delete build files?** After tests stop, `cargo clean` does not remove
the separate dashboard history. However, other evidence may still live under
`target/`; preserve anything needed before cleaning. Back up
`../brynja-evidence/` separately, including saved jobs referenced by the index.

**Does a green table mean we can publish?** No. It tells you what was observed.
Source/tool compatibility, owner approval and release qualification are separate
checks. A local diagnostic pass is not a detached release receipt.

See the [decomposition audit](test-decomposition.md) for why long tests were
split, and [Miri coverage](miri-coverage.md) for the coverage policy.
