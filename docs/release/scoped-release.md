# Scoped releases from v0.25.3

Evidence collection and release authorization are separate responsibilities.
The [component completion rule](../assurance/component-completion.md) is the
default: implement, verify the finite agreed scope, record, close, move on.

## Publication sequence

1. Implement the component and its necessary integrations, with their agreed
   checks. Resolve known blocking findings.
2. Obtain a clean pentest/retest disposition and commit the accurate report.
3. Run the finite final release checks for that candidate.
4. Push the candidate and wait for its GitHub checks, including CodeQL, to pass.
5. Create the signed release tag and publish that same clean candidate.

If GitHub finds a problem, fix and test that problem, update any affected review
disposition, push again and wait for green. Do not automatically repeat completed
component campaigns or the entire final gate. A substantive change still needs
its affected checks and review. Never treat a previous commit's green status as
the new commit's status.

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

For .3, the list covers the tracker, release regressions, package metadata/content
and dependency policy/advisories. It does not repeat hash/MAC qualification.
Future components need their own agreed functional/integration commands in this
list; missing registration is not permission to omit necessary tests.

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

## Transition status

The standalone runner, finite CI selection, gate/publication handoff and .3
publication metadata are implemented. The 27 registered portable checks are
not a replacement inventory for every historical assessment. The historical
index preserves the old dashboard records without fabricating current passes;
see [migration details](../assurance/brynja-verify.md#files-and-history).

Routine pushes run the explicit `ci_checks` subset plus the existing independent
dependency audit and CodeQL checks. The former native/compiler jobs are retained
in the manually started `qualification.yml` workflow, with an explicit lane
selection. Dedicated SHA-512 qualification is also manually started. Neither
workflow is triggered just by a version bump or unrelated source change.
`scripts/checks.sh --full-catalog` remains an explicitly requested historical
catalog run, not the routine default.

The .3 scoped pentest/retest, final committed-candidate gate and green GitHub
handoff are still required. Do not publish .2 or call .3 release-ready based on
this document. Existing captures and the GitHub-only .2 tag are unchanged.
