# Scoped releases from v0.25.3

Evidence collection and release authorization are separate responsibilities.
The [component completion rule](../assurance/component-completion.md) is the
default: implement, verify the finite agreed scope, record, close, move on.

## Publication sequence

1. Implement the component and its necessary integrations, with their agreed
   checks. Resolve known blocking findings.
2. Commit the candidate, obtain its scoped pentest/retest disposition, then
   commit only the accurate approval report with its `Reviewed-Commit` identity.
3. Run the finite final release checks for that candidate.
4. Push the candidate and wait for its GitHub checks, including CodeQL, to pass.
5. Create the signed release tag and publish that same clean candidate.

The passing scoped pentest/retest requirement also applies to development
releases, including 0.26.x. This does not change the separate crates.io
checkpoint cadence or require a full cryptographic campaign for each tag.

If GitHub finds a problem, fix and test that problem, update any affected review
disposition, push again and wait for green. Do not automatically repeat completed
component campaigns or the entire final gate. A substantive change still needs
its affected checks and review. Never treat a previous commit's green status as
the new commit's status.

### Review binding from v0.27.1

A PASS disposition must contain exactly one `Reviewed-Commit: <full 40-digit
commit ID>` identifying an available ancestor of the release candidate. The
candidate tree must match that reviewed commit everywhere except its own
`security/pentest/vVERSION.md` file. Code, assurance, CI, documentation, evidence,
file-mode and type changes after review require an updated scoped disposition;
the gate does not guess which edits are harmless. Complete and commit these
changes before the review, then add only the versioned approval record.

This is a two-commit workflow, not a requirement to retest every cryptographic
primitive: review the intervening delta and run its affected tests. If final
contents are restored exactly to the reviewed tree, intermediate changes do
not invalidate that content identity. Legacy reports through v0.27.0 retain
their historical format; newer PASS records cannot omit the binding.
`RETEST REQUIRED` may be inspected with `--allow-pending`, but never authorizes
the final gate or publication. CI may still run without a PASS record.

The binding prevents accidental reuse of stale approval. It does not authenticate
the reviewer: a party allowed to rewrite both code and approval can still forge
the record. Owner review, repository permissions and signed release identity
remain separate controls. Approved-reviewer key infrastructure is not claimed.

## The finite gate

The explicit list is `scripts/release/final-checks.toml`. Its version and scope
must match the intended release. Review the list at the start of component work;
do not grow it after completion merely to add confidence. It is a list of existing
commands and their limits, not another evidence framework.

```sh
scripts/tag_gate.sh v0.25.3 --list
scripts/tag_gate.sh v0.25.3
scripts/tag_gate.sh v0.25.3 --check release-regressions
```

`--list` executes nothing. The full finite list requires a clean committed
candidate and a committed PASS pentest/retest with no open findings. It stops
on failure. `--check` executes only a named correction check; it does not claim
the whole list ran again. Retain the earlier successful output and record the
final disposition in the release notes. There is no new automated receipt chain.
An error selecting the current flow stops immediately; it never falls back to
the historical gate or requests a larger verification campaign.

For .3, the list covered the tracker, release regressions, package metadata/content
and dependency policy/advisories. It does not repeat hash/MAC qualification.
Future components need their own agreed functional/integration commands in this
list; missing registration is not permission to omit necessary tests.

### Current 0.26.0 candidate

The current list selects 21 finite checks for HKDF development: modern/legacy
functional and API tests, scoped lint/format, facade compilation, helper and
registry regressions, package/requirements/API metadata, SBOM and dependency
policy/advisories. CI selects the first 18; its separate audit job retains SBOM,
dependency/advisory checks, standalone-tool advisories and release controls.
The proof-adapter and timing-parser entries test the tools with fixtures; they
do not execute proofs or timing measurements. The list never invokes the
verification runner, historical catalog or dynamic/compiler campaigns.

Use `scripts/tag_gate.sh v0.26.0 --list` to inspect without execution. The actual
gate still requires a clean committed candidate and its genuine scoped PASS
pentest/retest. Candidate preparation cannot supply that approval. The release
stage is internal, so no crates.io uploads are selected. See the
[candidate notes](../../release-notes/RELEASE_NOTES_0.26.0.md).

## Publication does not run the gate again

```sh
python3 scripts/release/release_crates.py --version 0.25.3
```

Publishing is an owner-authorized operation after the sequence above. The owner
is responsible for the recorded final-gate completion; the publisher does not
manufacture or require a new proof receipt. It retains package-order/version,
clean-tree and signed-tag identity guards, reads the committed pentest disposition,
and checks existing GitHub results for the exact commit. These are handoff guards,
not new test executions. The publisher does not launch the gate, tests, audits,
Miri, Kani, sanitizers, compiler matrices or evidence refreshes.

Cargo publishes with `--no-verify --locked` after this handoff: no redundant
package compilation at upload time. Packaging, registry communication and
dependency indexing are still necessary upload operations. `--start-at NAME`
retains the existing interrupted-publication resume behavior.

Old evidence options/validators remain available for explicitly inspecting
historical records; they do not become .3 publication prerequisites. Missing or
outdated optional tracker rows do not block unrelated releases. Evidence remains
honest about source, platform, date and limitations; this is not certification
or an authenticated runner-attestation system.

Legacy `--detached-receipts` and `--native-review-sha256` arguments are ignored
with a warning on the modern publication path. Even a missing old receipt file
cannot start or block publication checks. Only explicit `--evidence-check`
invokes the historical diagnostic; it is not a publication step.

For 0.25.3, the owner accepts the existing tested data as-is. Preserve original
results, dates and provenance, including unmapped historical status. This is a
release decision, not a claim of new executions or universal current passes.
The .3 pentest, finite release checks and exact-candidate GitHub/tag guards
still apply; their actual disposition is recorded in the versioned report and
release notes, not inferred from tracker status.

## Transition status

The standalone runner, finite CI selection, gate/publication handoff and .3
publication metadata are implemented. The 27 portable, 48 sanitizer, 4,933 Miri,
nine Kani, 350 compiler compatibility and 320 component fixture/script runnable
registrations are separate from the complete browseable inventory. All assessment
bindings are migrated; helpers and retired history are references, not unfinished
work. One hundred twelve owner-approved manual diagnostics retain their commands
and history without becoming component obligations. Registration completion does
not mean every check was executed or historical inputs were mapped. The historical
index preserves the old dashboard records without fabricating current passes;
see [migration details](../assurance/brynja-verify.md#files-and-history).

Routine pushes run the explicit `ci_checks` subset plus the existing independent
dependency audit and CodeQL checks. The former native/compiler jobs are retained
in the manually started `qualification.yml` workflow, with an explicit lane
selection. Dedicated SHA-512 qualification is also manually started. Neither
workflow is triggered just by a version bump or unrelated source change.
`scripts/checks.sh --full-catalog` remains an explicitly requested historical
catalog run, not the routine default.

The .3 owner-supplied scoped pentest and finite final checks have passed; see
the [review](../../security/pentest/v0.25.3.md) and
[final-gate record](../../release-notes/RELEASE_NOTES_0.25.3.md#final-gate--pass-2026-11-01)
for exact ranges, execution commit and limitations. The exact-candidate green
GitHub and signed-tag handoff are still required. Do not publish .2 or infer
publication authorization from this document alone. Existing captures and the
GitHub-only .2 tag are unchanged.
