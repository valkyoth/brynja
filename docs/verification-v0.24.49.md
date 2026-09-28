# v0.24.49 implementation verification

Owner-authorized verification completed and collected on 2026-09-28. This is
implementation-author evidence, separate from the two owner-supplied independent
retests in the [security report](../security/pentest/v0.24.49.md). It does not
authorize a tag. The final-gate result and remaining GitHub requirement are
recorded below.

## Completed non-Miri run

Source: `f68d3a4d379197a4248698d3507cc2df1bfd1780`; verified baseline `v0.24.48`.
Two isolated workers completed all 558 commands in 1,729.106 seconds (28m 49s).

| Phase | Passed commands |
| --- | ---: |
| Repository tests, lint, policy and acceptance | 257 |
| Supported compiler matrix | 240 |
| AddressSanitizer | 49 |
| Kani | 12 |

Launch receipt:
`93db49dd544a0d2eb202d7fd585e9fbb1ca7fdd6b1f77979c190834d38c4dd93`.
Terminal result SHA-256:
`89ad66a6498aa0d7786ca23944e320b8ade33b7dfa1af7d0b844077888a6349b`.
The collector validated every exit record/log, source snapshot, command catalog
and tool identity. Neither worker failed, and no command was waived or imported
from the earlier cancelled/failed attempts. Their original records remain intact.

The retained local job directory is
`brynja-verification-v02449-nonmiri-f68d3a4d`, alongside the source checkout,
not inside `target/`. Logs and complete manifests are local evidence, not
embedded in this summary. Receipt digests detect drift/corruption; they are not
remote attestation against a malicious evidence owner.

## Completed Miri coverage

The original two-host routine campaign at
`d689f75a7040071184383b777079a45215c6beb7` passed all 562 tasks. The
[detached workflow record](detached-verification.md#complete-two-host-routine-miri-campaign)
retains its timings, archive hash and combined receipt. Original source/tool/log
seals and parent receipts were validated after relocating the archive locally.

At `f68d3a4d`, foreground phase reuse accepted 560 unchanged tasks and executed
the two affected `legacy` tasks: two and four tests passed respectively, with
no failures or ignored tests. The other Miri tasks were not rerun.
The complete local log `release-reports/v02449-miri-f68d3a4d.log` has SHA-256
`d28a9c8dcdfbd0d796cd896509d81f4eb9ff96b137fda3deab27cb2d4efe3f97`.
This is the registered internal routine profile, not the public extended profile.
Miri does not qualify native assembly or OS protected-memory implementations.

## Release hand-off

The complete unchanged `scripts/tag_gate.sh v0.24.49` passed on 2026-09-28
at `6c26d54ef5b6b02831ff382cb5ea232eb91548e9`. Its local log is
`release-reports/v02449-final-gate-6c26d54e.log`, SHA-256
`d693e80ea9a82707c8149c7179fbf11b6c6cac2a2afab5c6efdada01e81fb07f`.
This includes current repository checks, native-evidence validation,
supplemental CPU/timing checks, live standards/freshness and tool checks,
sanitization admission, GitHub release controls, dependency audit, SBOM and
committed-report readiness. All 240 compiler-matrix, 49 ASan and 12 Kani
commands were reused after validation. Miri reused 560 tasks and passed the
two current legacy tasks. The standards refresh and action-pin parser repair
changed no production implementation or gate requirement. This hand-off note
is a documentation-only follow-up, not a claim of new cryptographic execution.

The phase registry `release-reports/v02449-phase-receipts.json` routes Miri to
the original combined AWS receipt and the other phases to the new completed
job. Existing rules compare each tested ancestor with the release checkout;
current repository baseline checks still run. Documentation edits do not claim
fresh cryptographic execution. The two short legacy Miri tasks may run again
through the normal foreground gate without repeating all 562 tasks.

Native observations retain their original capture commits and the exact
[reviewed test/tooling delta](native-evidence-reuse.md). Dedicated x86 SHA512
still has SDE evidence only; Windows/macOS strict protected sessions still
reject. No certification or wider platform qualification is claimed.
The internal release plan selects **zero crates** for crates.io publication.
Green GitHub checks for the pushed candidate and owner authorization remain
necessary before tagging. Nothing has been published or tagged by this check.
