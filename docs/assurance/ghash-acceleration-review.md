# v0.28.2 GHASH acceleration review — scoped retest pending

Two reviews of `v0.28.1..3373a671` found no incorrect field product or
confirmed memory corruption. One recommends against use under a physical or
side-channel-sensitive threat model. This is an internal, opt-in functional
milestone, not approval for that use. Original combined input SHA-256:
`efd8123e20733137b97ce7cea5bbc0dd89559fc0734fbf1c405a6d6860026670`.

| Report item | Disposition |
| --- | --- |
| Daybreak 1: migration and unsupported instructions | A real platform precondition, **not** fixed by a startup KAT or a thread-local owner. See below. No CPU lease was implemented. |
| Daybreak 2; Claude 1–3: PMULL alarm, Arm DIT, RV64 Zkt, Intel DOITM | Retain functional routing, not timing qualification. GHASH does not set or attest any of these controls; AES DIT policy does not transfer to GHASH. Neither a Cargo feature nor a new KAT would establish a timing guarantee. The [original alarm, follow-up and public discussion](ghash-acceleration.md#arm-public-pmull-route) remain separate evidence. No rerun to get a pass. |
| Daybreak 3; Claude 5: subkey, registers and spills | Known residual. The key is borrowed, not retained beyond its borrow; its owner controls its lifetime and clearing. An owned second copy adds exposure and cannot erase the original, vector registers or compiler spills. Workspace and returned secret have separate clearing contracts. No blanket register-scrub claim. |
| Daybreak bridge concern | The CPU handles **are public** to direct users of the separately enabled CPU crate. Doc hiding is not access control. Handle fields and proof construction are private; direct callers must still pass the CPU probe and KAT. The curated facade does not export them. See the packaged route tests for the facade boundary. |
| Claude 4: failed update | After length admission, an error or unwind in a public runtime-feature update clears partial state immediately and retires the owner, independently of CPU-layer health. A test interrupts the second product of a split update, inspects live storage, rejects further calls and verifies that finish leaves output untouched. An over-budget call remains nonterminal and nonmutating. |
| Claude 6: feature unification and exhaustive matches | The public error enum is now non-exhaustive. Downstream archive probes pair a wildcard match that builds with a no-wildcard match rejected with E0004, including in portable-only builds. |
| Claude 7: accidental forcing of experiment code | The three forced-candidate cfgs also require a separate compile-time acknowledgement, `BRYNJA_GHASH_EVIDENCE=1`. No build script or public feature was added. The archive harness rejects missing and incorrect acknowledgement, and runs the acknowledged positive and denied controls. This guards against accidental flags, **not** malicious control of the build environment. |
| Claude 8: all-zero H | Accepted repeat from the [portable review](ghash-review-disposition.md). Zero is a valid field element, not an acceptable fallback after failed derivation. Existing multi-block zero-key tests and warnings stay. GHASH output is not a tag. |
| Claude 9: stale docs, fault detection and completeness | Corrected the CPU crate's platform description. Startup self-tests do not detect per-block physical faults. GCM framing, masks, verification and multi-block optimization are not part of this API. |

## Which constructor to use

`Ghash::new` is the portable choice in ordinary builds. Use it if you cannot
guarantee a stable ISA for the process. `new_with_backend` requires the
advertised features to remain usable on **every CPU the thread can run on**
throughout the operation, including during VM migration or hotplug. `Prefer`
means “fallback if unavailable at admission,” not “recover from an illegal
instruction.” `Require` requires functional acceleration, not DIT, Zkt,
DOITM, affinity, or per-block verification. Portable is not a substitute for
independent timing qualification either.

## What was tested after remediation

The host owner and archive-consumer tests cover both Rust endpoints (1.90.0
and 1.100.0). The forced-candidate controls exercise all three cfgs and check
both missing and wrong acknowledgement values. Public routing is exercised on
native Linux x86_64 and in Linux AArch64/RV64 emulation. Windows x86_64,
Cortex-M and Apple AArch64 were compile checks, not new hardware observations.
The eight previously reviewed **portable update** assembly fingerprints still
match without changing the pins; no timing experiment was collected.
The refreshed GHASH registry reports 46/46 current configurations, including
the new retirement regression. The 1,089 registry tests passed.

Separate from the scoped preflight, the repository-wide
`scripts/repository/check-unsafe-policy.py` rejects an inclusion token in
`crates/brynja-core/src/lib.rs`. The same checker reports the same failure on
the unmodified `3373a671` sources. Neither that source nor its allowlist was
changed here. The reviewers' reported pre-existing x86_64-unknown-none build
failure is also not a qualified target or a claimed fix.

## Platform references

The detectors are not interchangeable: [Rust's x86 detector](https://doc.rust-lang.org/src/std_detect/detect/arch/x86.rs.html)
caches a CPUID-derived result, not a migration lease. Pinning one worker after
process-wide detection is not proof that the cached result describes its CPU.
[Linux arm64 capabilities](https://docs.kernel.org/arch/arm64/elf_hwcaps.html)
and [RV64 Linux hardware probing](https://docs.kernel.org/arch/riscv/hwprobe.html)
provide OS-level feature information; neither is an application-held lease.
Where the platform cannot maintain the contract, native use is unsupported.
No hostile hypervisor, mixed-ISA migration or hotplug resilience was tested.

For deployments with a timing requirement, [RV64 scalar Zkt](https://docs.riscv.org/reference/isa/v20240411/unpriv/scalar-crypto.html)
is distinct from Zbc instruction availability. On relevant Intel processors,
DOITM is OS-managed, not something this Rust crate can set or assume; see
[platform guidance and vendor references](aes-platform-side-channels.md).
The AWS alarm in an identical-input control is neither proof of leakage nor
proof of its absence. None of these deployment restrictions is a pentest pass.
