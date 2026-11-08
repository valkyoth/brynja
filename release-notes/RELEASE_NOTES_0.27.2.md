# v0.27.2 candidate — portable AES-family acceptance

Internal acceptance candidate; no crates.io publication is selected. Candidate
evidence reconciliation passed. Owner pentest/retest, the existing clean-candidate
finite final gate and exact-commit green GitHub/CodeQL remain required.

## Scope

This milestone adds acceptance tooling and observations around the existing
AES-128/192/256 block implementations. It does not change production AES Rust,
introduce dependencies, add modes or acceleration, or require an HSM. Raw AES
remains default-off through `hazmat-aes-block`; the trusted external-provider
contract remains AES-128 only. These primitives are not authenticated message
encryption and do not implement a TLS key schedule.

The [acceptance record](../docs/assurance/aes-portable-acceptance.md) describes
archive-only direct/facade consumers on Rust 1.90.0 and 1.99.1, debug/release
functional checks, paired API probes, archived README examples, feature gates
and Cortex-M compile-only checks. Separate campaigns exercise AESAVS Monte
Carlo/multiblock records and packaged OpenSSL comparisons for all key widths
and both owner forms.

Bounded machine-code reviews cover selected x86_64/AArch64 artifacts and
representative optimized final-linked consumers, including abort/unwind cleanup
boundaries. Native AWS AArch64 execution and fixed-versus-random timing are
retained as explicit source-bound observations, not authenticated receipts.
Timing uses predeclared campaigns and thresholds; it is not a proof of constant
time. Missing or mismatched inputs must not be promoted to current passes.

## Limits and workflow

No complete erasure of compiler spills, registers, caller copies, paging or
dumps is claimed. Power/EM and physical-fault resistance, arbitrary downstream
builds and external unwinder/loader behavior remain outside the bounded checks.
The broader qualification status is not automatically promoted by this candidate.
Hardware backends and optional device integration remain at their roadmap
milestones; ordinary callers are not forced to use hardware.

The facade and its isolated consumer pins advance to 0.27.2; supporting-crate
versions remain unchanged under the internal release-train policy. The finite
release checklist is unchanged. Miri, sanitizer, proof, timing and compiler
campaigns remain separately selected verification, not implicit publication
requirements. Historical observations remain tied to their actual input
snapshots; the version change is not evidence of a new successful execution.

Commit the prepared candidate for the owner's scoped pentest, address and test
any accepted findings, then record the reviewed commit and run the existing
final gate. No approval, tag or publication is authorized by these notes.
