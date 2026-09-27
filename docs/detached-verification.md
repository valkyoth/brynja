# Detached verification

Status: **implemented; local Miri/Kani/ASan and Linux SSH-disconnect ASan
collection/reuse passed. Final release qualification remains pending.**

The detached runner is an operator tool for running the existing verification
commands without leaving a terminal or assistant conversation open. It does
not grant approval, independently verify cryptography, or authorize publication.
Miri coverage is explicitly selected by the profile described below, not inferred
from a generic PASS. The ParallelHash acceleration work remains a
separate required deliverable of this milestone.

## Lifecycle

Run from a trusted Brynja checkout on Linux or macOS, with Git, Python 3.11+
and the required Rust/verifier tools already installed. Prepare the Cargo
caches as for the foreground gate. The runner does not install tools for you.
Use a dedicated machine or container when the checkout or test programs are
untrusted. Do not run as root.

First inspect the existing plan:

```sh
python3 scripts/release/run-verification.py plan --check
```

If this asks for full-run approval, review its explanation and obtain explicit
owner approval. Detachment does not approve that fallback. Pass the exact
approved fingerprint through `--approve-full` when starting the run.

Choose a **new** result directory outside the source checkout. Its parent must
already exist, and the path must have no symlink components. On macOS, use a
real path such as `/private/tmp/...` rather than the `/tmp` symlink.

```sh
python3 scripts/release/detached-verification.py start /tmp/brynja-verification-my-run --phase miri
```

Save the printed job path and launch receipt outside the job directory. The
receipt binds the frozen manifest, not merely a file named `PASS`. By default,
multiple `--phase` options run serially in the requested order. Available phases are
`repository`, `matrix`, `asan`, `miri`, and `kani`; their selected commands are
compared against the foreground runner in regression tests. A phase with no
affected work does not manufacture evidence that the unchanged tests reran.

The defaults allow four hours and 256 MiB of command logs **for the entire
job**, not per command. `--seconds` and `--log-bytes` set explicit budgets,
capped at one day and 1 GiB respectively. Exceeding either budget fails the job.
For independent build shards, pass `--shards N --workers W`, with
`1 <= W <= N <= 8`. Each shard gets its own source/build directory; Miri and
Kani group lists are expanded into exact per-group commands. New schema-2 jobs
split Miri further, at each Cargo invocation in the existing full-group driver,
and into registered matrix cases under the selected profile.
Other commands are unchanged. Commands are partitioned round-robin;
order within each shard is retained, but global phase order is not promised.
Use serial mode if a local operation outside the registered workflow depends
on earlier phases' generated build artifacts. Do not set `CARGO_TARGET_DIR`
for multiple shards. Cargo downloads share only the normal cache locks.

The total log allowance is divided between shards, so one noisy shard can
fail before the whole job uses its allowance. The global deadline does not
reset between commands or shards. `--workers` bounds simultaneous verifier
commands, not compiler subprocess counts or physical RAM usage. Each source
snapshot is bounded to 1 GiB excluding Git objects and generated build output;
provision disk space for all requested snapshots/builds. Use host/container
quotas for hard CPU, RAM and disk limits. This runner does not change those
process-wide deployment policies.

The terminal result includes POSIX child user/system CPU time and runner/child
maximum-resident-memory observations, normalized to bytes on Linux and macOS.
Child CPU time includes children reaped by this fresh worker (including its
validation probes), not only the verifier. Child maximum RSS is the OS-reported
high-water observation, **not** the sum of simultaneous shard memory or a RAM
quota. Elapsed host time and log bytes are recorded separately. These numbers
help size future machines; they are not security or performance certification.

After the command returns, the invoking terminal/SSH connection can close.
Use these commands in a fresh session, replacing `RECEIPT` with the saved value:

```sh
python3 scripts/release/detached-verification.py status /tmp/brynja-verification-my-run --receipt RECEIPT
python3 scripts/release/detached-verification.py collect /tmp/brynja-verification-my-run --receipt RECEIPT
python3 scripts/release/detached-verification.py cancel /tmp/brynja-verification-my-run --receipt RECEIPT
```

Start on the AWS host through a normal authenticated SSH session using the
same commands. Do not place SSH keys or credentials in the job directory.
Manual macOS users run and collect locally; the assistant does not require
remote access. Copy the complete records and logs for review, keeping the
launch receipt separately. Transfer alone does not establish native execution
or authorize substituting one platform's tests for another platform's lane.

## Carry forward verified implementation checks

### Resume interrupted work and combine partitions

New jobs use schema 2: every successful command is source/plan/tool checked
before and after execution, before its checkpoint is published. Logs are flushed
as output arrives. Miri tasks print their group/task identity, test names, a
host-clock elapsed duration on completion, and interpreter progress stacks.
Progress output is not proof of success; a nonzero exit or zero passed tests
fails the task. Miri safety checks remain enabled.

To resume a cancelled, timed-out, or log-limited **schema-2** job, repeat the
original selection and approval arguments, but use a new destination:

```sh
python3 scripts/release/detached-verification.py start /tmp/brynja-verification-resumed --phase miri --resume /tmp/brynja-verification-my-run RECEIPT
```

Completed commands are copied and validated; interrupted commands start from
the beginning. Sources, tools, profile, command selection and approved plan must match.
Budgets and worker counts may change. Retain the original directories and
receipts: parent evidence is revalidated at collection. A failed test, changed
input, missing log, running/lost worker, or schema-1 job is not automatically
resumable. In particular, the cancelled v0.24.49 sweep is still cancelled;
its historical command records lack the new post-command attestations.

To distribute one identical command set across prepared matching Linux hosts,
use `--partition 0/2` on one and `--partition 1/2` on the other (zero-based;
at most eight partitions). Each uses an independent new job directory. These
jobs finish **partial**, not passed, and cannot qualify the release separately.
Bring their complete job directories back without changing frozen files,
then combine them into another new job:

```sh
python3 scripts/release/detached-verification.py start /tmp/brynja-verification-combined --phase miri --resume /tmp/brynja-part-0 RECEIPT_0 --resume /tmp/brynja-part-1 RECEIPT_1
```

The combined job validates all parents and runs any still-missing commands.
It can pass only when the complete original task set is present. Repeated
passes do not count as missing tasks; a failed parent cannot be hidden by a
passing copy. All hosts must have matching tool identities and source/plan
inputs. This is not cross-platform substitution. Multi-host operation has
local separate-process regression coverage and a real two-host interrupted
transfer/resume trial, recorded below. A complete successful multi-host Miri
campaign has not yet been collected.

### Miri profiles

New foreground and detached runs default to **routine** for internal tags and
**extended** for public checkpoints. Routine deliberately samples the registered
SHA-1, MD5, SHA-3, KMAC, TupleHash and ParallelHash matrices: 451 case/chunk tasks
rather than 3,983 extended tasks. KMAC chunks use representative byte values;
ParallelHash uses smaller inputs for small leaf sizes. Full native matrices
remain unchanged. The other 83 Cargo invocations retain their original
selections, minus the registered matrices, nine SHA-3 lifecycle tests, four KMAC
API tests, nine TupleHash scoped/API tests and six ParallelHash API tests now
executed separately. SHA-3 retains each identity's rate boundaries and every
registered partial-bit combination; its original integration invocation still
discovers new tests not registered for separate execution.
KMAC's scoped fixed/XOF lifecycle splits retain all 34 cases in both profiles.
ParallelHash's hosted-worker splits retain all 27 scenarios in both profiles;
each scenario keeps its original cooperating threads and join/cleanup checks.
ParallelHash's scoped leaf sampling retains every input length and tail width,
and both strengths and output-clearing assertions within each selected case.
Its buffering matrix covers both strengths, all block sizes, length classes and
tail widths with 16 routine / 672 extended cases, retaining fixed/XOF framing
and clearing checks in every case.
All 22 scheduled-owner lifecycle cases, all 12 official KMAC/KMACXOF vectors
and all 12 official ParallelHash/ParallelHashXOF vectors
remain selected in both profiles; only their scheduling is split.
MD5 batch masks run as 20 routine cases covering empty/full, each lone/absent
lane and alternating occupancy; extended and native tests retain all 256 masks.
Every selected mask keeps the original input lengths, bit tails and cleanup
comparisons. Remaining batch failure checks stay in their broad invocation.

Use `start --miri-profile extended` for an internal extended campaign, or
`--miri-profile existing-full` for the legacy unsplit matrices. A public job
cannot select routine. The profile is frozen in the receipt; resume cannot
change it, and routine evidence cannot satisfy extended requirements. The
legacy full profile can still contain very long inner loops.

Each selected case must emit its exact completion marker and pass exactly one
test. Case selectors are explicit interpreted-environment inputs used only under Miri; ambient
selectors are rejected by the runner. No aliasing, race, alignment, validity
or leak check is disabled. See [the design and measured limitations](miri-verification-design.md).
These profiles do not yet guarantee short total execution across all families.
Miri-only task catalog/runner edits select Miri without themselves selecting
ASan/Kani; concurrent implementation changes and unknown scripts retain their
normal conservative scope. Full-fallback approval still applies.
Approval is not a request to expand every verifier: `full_phases` records which
phases actually need a fallback, and foreground/detached execution honors it.
Historical plans without that field retain their conservative interpretation.
No automatic sweep is started by collecting results.

### Reuse after later metadata changes

After a successful job on the matching host/toolchain, the foreground runner
validates its original snapshot and compares the current checkout against that
tested commit. An unchanged implementation does not need another expensive run
just because release notes or release tooling changed:

```sh
python3 scripts/release/run-verification.py miri --detached-job /tmp/brynja-verification-my-run --detached-receipt RECEIPT
```

For the existing multi-step release gate, set `BRYNJA_DETACHED_JOB` and
`BRYNJA_DETACHED_RECEIPT` to the same values in the invoking shell. The runner
revalidates the original manifest, frozen sources, execution plan, tools,
successful exit records and logs. The tested commit must be a clean ancestor.
The original result is never rewritten to claim it tested a later commit.

Each current command is reported as `REUSE` or `RUN`, with a reason:

- Documentation, version-only pins, review-digest rebinding and release
  orchestration edits run the current build/test/lint/policy baseline. They do
  not by themselves rerun unchanged cryptographic campaigns.
- Changed implementation, dependency/feature, fixture or family test-driver
  inputs rerun that family and its affected consumers. Both dependency graphs
  participate; removals and dirty/untracked inputs count as changes.
- Miri/Kani groups are considered separately. An old combined run may cover an
  unchanged group without forcing the other groups to repeat.
- A new or altered command without matching successful evidence runs normally.
  Changed command drivers and explicit stdin inputs also run again.
- Unknown scope still stops for explanation and full-run approval. A new public
  release checkpoint still requires its full suite; later metadata edits within
  that successfully tested public version may carry it forward.

The plan prints the original commit, receipt, completed-command count, current
commit and changed paths. Record that provenance in the release/pentest ledger,
along with the newly run checks. Keep the job and its receipt: commit history
proves what changed, while the validated results prove which checks passed.
No fabricated receipt, failed/missing log, dirty baseline or non-ancestor can
qualify a skip. Tool identity changes still invalidate the imported evidence.
CI diagnostics cannot import local evidence. Reuse grants no release approval.
Records from another platform cannot silently replace this host's verifier runs.

## Frozen inputs and result validation

The worker uses a separate Git checkout with independent objects and a copy of
tracked/non-ignored source inputs. Uncommitted edits, additions and tracked
deletions are included. Admitted local references are copied explicitly;
ignored credentials and build caches are not copied. The source inventory is
bounded and includes content hashes and executable flags. The original source
must remain stable while that snapshot is created.

The worker checks the snapshot and approved plan before each command and after
the campaign; schema-2 jobs also check sources and tools after each successful
command. It records tool/compiler identities, commands, timestamps,
statuses, exit codes and bounded log hashes. Collection requires every selected
command to have completed successfully, the original launch receipt, complete
matching logs, and an unchanged source/execution plan for the snapshot being
collected. Explanatory reason text is not execution identity; fingerprints,
groups, verifier selection and approval requirements remain checked. Direct
`collect` against an edited checkout remains an error. The foreground runner
instead collects against the unchanged historical snapshot and independently
classifies the current delta for the carry-forward rules above.

Selected Miri and Kani jobs bind the actual verifier's `--version` output as
well as the installed Rust compiler identities. Changing a verifier without
changing `rustc` therefore invalidates reuse. Policy-only Kani checks and
repository diagnostics do not require installing an unused proof engine.

Failures stop subsequent work and cancel running sibling shards. Cancellation
is cooperative at the runner boundary and kills active command process groups.
Results are stored in original command order, not completion order. A cancelled, incomplete,
timed-out, log-limited or corrupted run cannot be collected as successful.
Jobs are not restarted in place and existing output is never overwritten by a
second start. A lost/killed worker can leave a pending/running record; that is
**incomplete**, not successful evidence. Do not signal a stored PID manually:
PIDs can be reused. A cancellation request is a file observed by the owner.

Command children run in a fresh POSIX session. Process-group cleanup covers
normal compiler/test descendants; it is not containment for malicious programs
that create their own sessions. VM/container teardown, host reboot, forced
worker termination, disk exhaustion or loss of the worker's service scope can
interrupt the run. In particular, start outside an ephemeral agent command
sandbox, which can destroy its entire process namespace when the command ends.
The runner makes no survival claim across host reboot.

Job records are owner-controlled evidence, not independently authenticated
attestations. SHA-256 bindings detect accidental or partial corruption; a
malicious operator able to replace the entire execution result and its hashes
can forge self-attested evidence. Restrict access to the directory, retain the
launch receipt separately, and review the records before use. Logs can contain
data printed by tests; the runner must only execute approved assurance commands
with synthetic/public inputs, never production secrets.

## Remaining acceptance before closing v0.24.40

The planner validates both sides of the ParallelHash differential fixture's
lockfile against their corresponding workspace graph. Importing unchanged CPU
packages into that test fixture selects ParallelHash, not every CPU consumer.
Production CPU/source/graph changes still select their consumers; malformed,
foreign or missing dependency records require explicit scope review. The
current development delta selects only ParallelHash for Miri, ASan and Kani.

- Local real-campaign shard, collection and phase reuse passed; the Linux
  SSH-disconnect/reconnect hand-off also passed, as recorded below.
- Freeze the final reviewed release source before creating evidence for that
  source. A development acceptance receipt cannot qualify later edits.
- Finish final ParallelHash release qualification; reviewed native evidence now
  covers Intel AVX2, AWS Arm and Apple M2 Pro on `7d101cb7`. That algorithm
  capture does not itself qualify the remote detached-verification hand-off.
- Keep the completed 39-crate README audit and 35 compiled examples in the
  shared baseline checks; documentation alone must not select crypto Miri work.

The initial real-checkout smoke campaign ran the planner-selected Kani
**policy-only** command (no affected proof groups), survived its initiating
command and was collected in another invocation. This checks orchestration,
not Miri execution, full Kani proofs, hardware qualification or release readiness.

A subsequent two-shard development run exercised the real ParallelHash Miri
and Kani commands and survived the initiating command/session. Kani passed.
Miri found a test-only five-second channel deadline in the reversed-worker
test; the run failed after approximately 1,104 seconds and collection rejected
it. The test now synchronizes by channel completion/disconnection, not hashing
speed; the outer verifier still bounds deadlocks. That failed receipt remains
failed; neither the failure nor its successful sibling qualifies a release.

The corrected two-shard run on 2026-09-12 passed the actual affected
ParallelHash Miri and Kani commands. It survived the initiating command and was
collected in a fresh invocation against its frozen source checkout. Both
foreground phase commands reported `REUSE (validated detached snapshot)`;
the two command-log hashes were unchanged. Collection from the main checkout,
which had subsequently received repository-policy fixes, correctly failed with
`detached source closure changed`.

That run took 1,327.895 seconds (about 22 minutes), with 1,328.599 child user CPU
seconds, 3.901 child system CPU seconds, 1,442,209,792 bytes of child maximum RSS
and 42,172,416 bytes of runner maximum RSS. These are this development host's
observations, not a performance promise. Its launch receipt was
`e1f7e92945e3f563d8a8c6b68e2f689ffed6b8a480f69e51f95abf3f333d009d`.
This proves the local detached lifecycle and exact-snapshot reuse, not final
release authorization or native Arm/macOS qualification.

## Release-candidate and remote hand-off observations

On source `ead83b48390bf1deef7fa0b0e2743d978b3a229f`, the local two-shard
Miri/Kani/ASan run passed all 15 selected commands in 1,405.809 seconds. Collection
and all three foreground phase reuses passed without rerunning tests. Receipt:
`210934ea2cd65e4f84e969ef7a014de78236ab6787925cce8462952044cf7537`.

A separate Ubuntu x86-64 host ran the 13 selected ASan commands on that same
source with two shards/workers. The initiating SSH session closed; fresh SSH
sessions observed the running job, collected its successful result and consumed
the ASan phase with `REUSE (validated detached snapshot)`. Runtime was 163.559
seconds; child maximum RSS was 375,291,904 bytes and runner maximum RSS was
43,819,008 bytes. This is an observed run, not a sizing guarantee.

- Launch receipt: `fbc4448bfc6ef04a56349a96d8f264506e17ca9ee8f7dbae8db5e2161b937fad`.
- Result SHA-256: `5b2045dfc5eac2fbfc3635f6111dc474aa5bf129b6880e16ba91ebe743170b36`.
- All 13 downloaded command-log hashes matched the terminal result after reuse.

This closes the real Linux remote hand-off demonstration, not reboot survival
or remote Miri execution. Subsequent release-tooling edits require their own
checks. These receipts still identify the original snapshot; they cannot be
imported as exact-snapshot evidence for a later commit.

## Bounded two-host Miri resume trial

On 2026-09-27, two Ubuntu x86-64 hosts with Intel Xeon 6975P-C CPUs, four
logical CPUs and approximately 8 GiB RAM each ran complementary routine Miri
partitions on `83fbbd04443d64fb08b4fffe720268651395d11b`. Both used Rust 1.98.1,
Miri `nightly-2026-09-11`, Python 3.14.4, independent frozen source/build trees
and an explicit 120-second budget per job. SSH launch sessions disconnected;
fresh sessions inspected terminal records.

The parent jobs timed out with four and 24 completed commands. The second job
was transferred to the first host without build caches. A new job imported all
28 passes without rerunning them, then restarted a missing MD5 command. When
its own 120-second budget expired, all 28 imported command records and logs were
still byte-for-byte identical, present in the terminal result and accepted by
the source/tool/checkpoint validator. Full collection correctly rejected the
incomplete campaign. No timeout was marked PASS.

- First parent receipt: `9d359dcf07998167871e71120e565c8263eda1d7b7edf1a68fad89c6e4add8f9`.
- Second parent receipt: `dc4159f2f13176dd0da469ee6a3aba9a628fc7549cf743535bf71747c74e3c57`.
- Resumed receipt: `bc922b04c16a3b13d76d80314746fe319aa999e3084a1a74b605e84b6c936ac8`.
- Archived frozen jobs/logs SHA-256: `82992263df13fe8e852b4be7502b7931091160a65e9462586954b9ea1303221b`.

This demonstrates real remote transfer and checkpoint preservation across a
second interruption, not successful all-task union, full Miri qualification or
release authorization. The earlier failed trial remains immutable; its
bookkeeping defect and regression fix are recorded in the
[Miri design notes](miri-verification-design.md). Both archives are stored
outside Cargo output directories and survive `cargo clean`.

## Complete two-host routine Miri campaign

On 2026-09-27, the owner-approved routine Miri campaign completed all 562 tasks
on source `d689f75a7040071184383b777079a45215c6beb7`. The same two Ubuntu hosts
described above each ran one complementary 281-task partition, with two workers,
independent source/build trees and a 14,400-second limit. All assigned tasks
passed: the first host took 8,724.770 seconds (2 h 25 min), and the second took
9,113.646 seconds (2 h 32 min). These are observed campaign durations, not a
future-suite timing guarantee. No Kani or ASan campaign ran as part of this job.

- First partition receipt: `ab3e6251c65901605abc1891da90cda358c837185e8cf475914a6d06ee95332c`.
- Second partition receipt: `4a23fe532f65557d868c4d2a7b367d8fe3a4b897a17563b1ae492865376b94ff`.
- Combined receipt: `a4ead907f7261f13e3f9681f964401a1fbd5fa3412c5f89b67741d72072421ae`.
- Combined result SHA-256: `ca6cfd24214c72b78cdec68cacfdaa37c081aef65689fe6bf82b67ac59b77be2`.
- Complete archive SHA-256: `a828b44ed8ba1815be2746172838851571bc44b69baf1d91630567510c23c760`.

The second partition was transferred without build caches. A new immutable
combined job imported the 562 passing records; the collector validated complete
coverage, log hashes, unchanged inherited records, source snapshots and tool
identity. Both original partition results remain `partial`, correctly describing
their individual coverage. The combined result is `passed`. Its 10.433-second
elapsed time measures collection/bookkeeping, **not** execution of the tests.

The foreground Miri verifier consumed this receipt on the same source and
reported `562 unchanged checks; 0 current checks passed`: every requirement
was reused, and no tests reran. The full archive, including both parents, their
Git snapshots, the combined job and all command logs, is retained locally as
`release-reports/miri-routine-d689f75a-complete.tar.gz`, outside Cargo output
and ignored by Git. Build caches are excluded. Restore the recorded parent
paths and matching tools when using the existing collector; the archive is not
a path-independent or tool-independent receipt.

This closes the complete real two-host routine Miri transfer/union demonstration.
It does not qualify the extended profile, replace native/ASan/Kani evidence,
import legacy partial evidence, or authorize publication or tagging.
