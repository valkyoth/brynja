# Detached verification

Status: **implemented; local detached Miri/Kani collection and phase reuse
passed development acceptance. Release qualification remains pending.**

The detached runner is an operator tool for running the existing verification
commands without leaving a terminal or assistant conversation open. It does
not change test coverage, grant approval, independently verify cryptography,
or authorize publication. The ParallelHash acceleration work remains a
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
Kani group lists are expanded into exact per-group commands with identical
coverage. Other commands are unchanged. Commands are partitioned round-robin;
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

## Resume a verified phase

After reviewing and collecting a successful job on the matching host/toolchain,
the foreground runner can consume the exact phase without executing it again:

```sh
python3 scripts/release/run-verification.py miri --detached-job /tmp/brynja-verification-my-run --detached-receipt RECEIPT
```

For the existing multi-step release gate, set `BRYNJA_DETACHED_JOB` and
`BRYNJA_DETACHED_RECEIPT` to the same values in the invoking shell. The runner
revalidates the complete manifest, source, plan, tools, successful exit records
and logs before reuse. Phases or exact standalone commands not covered by the
job run normally. A stale, failed or malformed supplied job is an error, not a
successful shortcut. Existing full-scope approval is still required separately;
a receipt cannot approve a plan. CI diagnostics reject detached imports.

Changing the checkout or tools requires fresh evidence; even documentation-only
reuse is not inferred. Records from another platform may be reviewed as native
evidence but cannot silently replace this host's required verifier commands.

## Frozen inputs and result validation

The worker uses a separate Git checkout with independent objects and a copy of
tracked/non-ignored source inputs. Uncommitted edits, additions and tracked
deletions are included. Admitted local references are copied explicitly;
ignored credentials and build caches are not copied. The source inventory is
bounded and includes content hashes and executable flags. The original source
must remain stable while that snapshot is created.

The worker checks the snapshot and approved plan before each command and after
the campaign. It records tool/compiler identities, commands, timestamps,
statuses, exit codes and bounded log hashes. Collection requires every selected
command to have completed successfully, the original launch receipt, complete
matching logs, and an unchanged current source/plan. Source edits after launch
do not affect the running snapshot, but invalidate collection against the edited
checkout. Automatic documentation-equivalence reuse is not currently provided.

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

- Review the platform-specific remote hand-off during native qualification;
  local real-campaign shard, collection and phase-reuse acceptance passed.
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
