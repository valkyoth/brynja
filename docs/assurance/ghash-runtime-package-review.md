# GHASH package acceptance — v0.28.3 review disposition

Reviewed range: `v0.28.2..23505c33`. The combined owner-supplied report
had SHA-256 `8204fa89efe528555a5d03fc6cc87b11a45407cadc83cc15e0e497cd2cc470bc`.
Neither reviewer reported incorrect GHASH arithmetic or a new crate
vulnerability. Two tooling findings required changes; **scoped retest pending**.

| Finding | Disposition |
| --- | --- |
| Runtime acceptance missing from the gate (reported High) | Confirmed release-assurance gap. The final gate now runs the packaged Linux x86-64 fixture. A dedicated push/PR job runs the same command alongside the portable package checks, once rather than duplicating it in generic CI. It uses the real host for acceleration and QEMU only for instruction absence. No timing or remote campaign is required. |
| Wrong startup answer left installed in the temporary sources (Low) | Fixed. The harness restores the original bytes when the quarantine scenario exits, including on an exception. Quarantine build artifacts remain in their own target directory. Regressions cover successful and failing consumers and missing or ambiguous mutation sites. |
| Suggested second startup vector (Low) | The premise that the existing vector misses the second reduction is incorrect. Reversing the published wire operands into polynomial order gives degrees 124 and 126; their product has degree 250. Independently multiplying and folding modulo x¹²⁸ + x⁷ + x² + x + 1 leaves overflow 0x2 after the first fold. Omitting the second fold fails the published answer. The single vector does not test every lane or fault; the exhaustive basis-pair campaign is separate. No new admission rule or physical fault claim. |
| Direct CPU bridge (Info) | Accepted repeat. Its re-exports are already doc-hidden, not private. The [v0.28.2 disposition](ghash-acceleration-review.md) records the public low-level contract and curated facade boundary. |
| Replay provenance (Info) | The [release notes](../../release-notes/RELEASE_NOTES_0.28.3.md) now distinguish the baseline and versioned replays. macOS was observed separately, not attested by the local Linux verifier or covered by x86 CI. |

Unresolved PMULL timing, register/spill clearing, stable CPU instruction
support and the distinction between raw GHASH and a GCM authentication tag
remain as documented. No production Rust or dependency change was made in
response to this review. Retest the archive restoration and the x86 package
check's inclusion in CI and the final gate; this is not release approval.

Local validation of the follow-up: 9 harness controls, 43 scoped-release
regressions and 1,089 registry tests passed. The portable archive replay
passed on both compiler endpoints. The modified runtime harness passed 12
x86-64, 12 QEMU AArch64 and 16 QEMU RV64 configurations through the direct
crate and facade. Apple Silicon was not rerun for this tooling fix; GitHub
execution remains separate from these local results.
