# AES acceleration acceptance inventory — v0.27.3 development

This index reconciles the chronological development notes. Completed scoped
work is not an instruction to repeat whole campaigns. Historical observations
retain their source identities; this index does not import them as current
`brynja-verify` passes or approve the release.

| Area | Recorded coverage | Remaining boundary |
| --- | --- | --- |
| Portable compatibility | [Unchanged archive consumer replay](aes-acceleration-development.md#unchanged-portable-package-replay), both compiler endpoints, direct/facade, debug/release | No new portable implementation in this milestone. |
| Accelerated ownership/lifecycle | Native static/hosted selection, clearing, quarantine, error and unwind controls; [ARM campaigns](aes-acceleration-development.md#native-aws-arm-integrated-expansion-refresh-2026-11-10), [Apple campaigns](aes-acceleration-development.md#apple-integrated-expansion-refresh-2026-11-11), [Intel](aes-acceleration-development.md#native-intel-correctness-and-linked-review-2026-11-11) | Software controls do not establish physical fault detection. |
| AESAVS and independent differentials | Forced AES-128/192/256 MCT/MMT and OpenSSL comparisons across the named native configurations in the development ledger | Not certification or arbitrary downstream-consumer qualification. |
| Final-linked operation paths | Expansion, round kernels, constructors, cached/ephemeral callers, sessions and clearing reviewed for the declared Linux and Apple consumers | The actual timing specializations still need their own bounded inspection; GNU loader and arbitrary consumer inlining are not inherited from musl review. |
| Startup admission/quarantine | Static startup reviews and executed controls; [corrected Linux/Apple hosted PMULL refresh](aes-acceleration-development.md#native-hosted-pmull-refresh-2026-11-11) | OS/hypervisor trust and target-specialized deployment remain explicit assumptions, not properties a KAT can prove. |
| no_std and feature isolation | [48 builds and 212 paired probes](aes-accelerated-no-std.md), direct/facade, both endpoints | Bare-metal x86 compiler failure is retained; it is not an admitted target. |
| Sanitizer lifecycle | [Native x86 ASan/LSan](aes-accelerated-sanitizers.md), positive lifecycle cases and deliberately failing controls | Not ARM sanitizer qualification or a claim to instrument installed std. |
| Performance | Native AMD, AWS ARM, Intel and [Apple diagnostics](aes-apple-measurement-results.md) retained | Speed has no acceptance threshold; Apple placement is explicitly unpinned. |
| Fixed/random timing | Original results preserved; [64-launch DIT/shared-address screen](aes-dit-finite-results.md) collected and strictly analyzed | Zero shared-input alarms, but 37 shared-control noise flags: inconclusive, not a pass. Owner disposition or a separately designed experiment remains necessary. |
| Optional DIT | [Explicit optional/required API, native restoration tests and bounded changed-path review](aes-dit.md) on both ARM hosts/compilers | Selected caller review is not whole-program qualification. New timing screen is inconclusive; no physical-security claim. |
| Release handoff | Existing finite gate and owner/GitHub workflow unchanged | Candidate metadata, bounded final checks and handoff wait for the named capability's acceptance disposition. |

## Hosted platform boundary: contract, not a pending physical experiment

The crate checks the architecture, byte order and complete AES/PMULL/NEON
bundle before constructing authority. Only reviewed little-endian AArch64 Linux
and macOS system-detection paths are admitted. Generic hosted x86 remains
unavailable: current-core CPUID alone does not establish the required lifetime
contract. Static users retain their explicit compatible-deployment obligation.

The [pinned detector source review](aes-accelerated-hosted-startup.md#detector-source-review-and-pmull-correction-2026-11-11)
and corrected native startup reviews establish the scoped crate boundary. Linux
documents HWCAP as the userspace feature-availability interface and its feature
register ABI as system-wide safe reporting. See
[Linux HWCAP](https://docs.kernel.org/arch/arm64/elf_hwcaps.html) and
[Linux feature registers](https://docs.kernel.org/arch/arm64/cpu-feature-registers.html).
Rust's reviewed Darwin implementation uses system feature queries, with failed
queries treated as absent. The native negative controls substitute detector
observations; they do not emulate all OS failures.

A conforming OS/hypervisor must preserve its advertised process ISA ABI across
scheduling, hotplug and migration. That assumption remains part of the
[hosted contract](../hosted-cpu-execution.md), not unfinished code to be replaced
by a mandatory HSM, affinity query or repeated KAT. Neither thread-bound Rust
ownership nor a finite native experiment proves arbitrary future migration
behavior. Additional operating systems, hostile/defective kernels and arbitrary
hypervisor configurations are not admitted by these records.

## Timing investigation chronology

The paragraphs below record the investigation before the independent identical-
input review. The [2026-11-12 exact-binary follow-up](aes-fourth-alarm-results.md)
now establishes that the original harness can alarm without a value difference.
It supplies a bounded confounding disposition, without changing old verdicts or
claiming a new timing pass. New runs use the [shared-address policy](aes-value-timing-policy.md).

There are four retained non-noise ARM alarm campaigns: three in the
[original experiment](aes-accelerated-fixed-random-results.md) and one in the
[address/value experiment](aes-timing-address-controls-results.md). Their causes
are not established. The later dispatch and 1024-operation controls changed
the measured specialization; the replacement ARM host also changed. Those
results constrain the investigation but cannot retrospectively clear alarms.

The Apple observations are complete and replayed: zero alarms in all eight
controls, with one noisy MSRV campaign. Six complete round/expansion bodies
per measured Apple binary match the existing review; representative cached-public
timer/callee inspection is recorded, without claiming every specialization.

The [retained ARM alarm-path review](aes-arm-alarm-path-review.md) now covers
the successful measured paths for all four non-noise ARM alarm campaigns in
their three original binaries. All 18 complete round/expansion bodies matched;
the caller review found public dispatch and wrapper work inside the timer, but
did not establish the cause of any alarm. Broader measured-path coverage is not
implied by this focused inspection.

The [offline population diagnostics](aes-retained-timing-diagnostics.md)
reproduce all 117 campaign verdicts in those observations and retain all
958,464 pairs. The address-control alarm has the same sign in every 64-pair
block; class-order and chronological descriptions do not establish a benign
cause. No alarm or noise classification changed.

The [class/address crossover experiment](aes-slot-crossover-design.md)
now has tested AES integration and strict validation. Local direct/facade and
native ARM direct configurations pass on both compilers, with matching package
identities. They establish fixture correctness, not timing acceptance. The
[actual crossover caller/timer review](aes-slot-crossover-linked-review.md)
is now complete for the two retained ARM binaries, without identifying a
defect in the inspected paths. After the owner supplied and confirmed a fresh
ARM host, the [declared finite experiment](aes-slot-crossover-declaration.md)
completed once per compiler. The [results](aes-slot-crossover-results.md)
retain all 393,216 durations: one non-noise slot comparison alarm and four
noise-flagged comparisons. No within-slot class comparison crossed the alarm
threshold, but two were noisy. This is not a clean slot-only explanation or
retrospective clearance; timing acceptance remains open.

The subsequent [DIT-required finite screen](aes-dit-finite-results.md) completed
after the bounded changed-path review. All 64 processes and full populations
were retained: zero shared-input alarms, one Linux and 36 Apple shared-control
noise flags. Both frozen screens are inconclusive. The remaining decision is
the explicit disposition of that uncertainty, not missing sample collection.
Do not repeat populations until one passes, change thresholds, or call ordinary
functional tests side-channel evidence. Any acceptance scope/risk change belongs
to the owner; this milestone is not silently marked complete.

The [working-tree pentest dispositions](aes-acceleration-pentest-remediation.md)
and [post-collection sensitivity addendum](aes-dit-sensitivity-review.md)
further limit the interpretation of zero alarms: observed threshold scales
exceed the historical effects in many campaigns, and raw-kernel DIT does not
cover whole-wrapper handling. No frozen result or release gate changed.
