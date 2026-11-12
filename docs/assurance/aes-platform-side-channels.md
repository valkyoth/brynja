# AES platform timing controls and prefetchers

This is deployment guidance, not a new feature, release gate or claim that a
specific brynja key-recovery attack has been demonstrated. The current
[timing screen remains inconclusive](aes-dit-finite-results.md). Neither ISA
availability nor passing startup KATs qualifies an entire deployment.

## Apple data memory-dependent prefetchers

The [GoFetch authors](https://gofetch.fail/) demonstrated key extraction against
several other cryptographic implementations using data memory-dependent
prefetchers (DMPs). Their experiments found that DIT suppresses the observed
DMP on M3, but not M1/M2. They separately report a privileged M1/M2 control
requiring kernel support. This is not a universal statement about later Apple
chips or every OS version; verify the actual platform. Their work does not
by itself establish an exploit against these AES kernels or owners.

Brynja currently scopes DIT around raw expansion and AES rounds only. Wrapper
staging, schedule storage, copies and clearing can execute with the caller's
prior DIT state. **`DitPolicy::Require` is not a whole-owner DMP mitigation**,
and even a wider DIT scope would not establish M1/M2 DMP suppression. Broader
scopes need their own admission, unwind, callback, emitted-code and platform
review; no such mitigation is claimed here. Deployments exposed to hostile
co-resident observers must evaluate supported platform controls and isolation,
not infer protection from our M2 Pro correctness/timing observations.

## Intel Data Operand Independent Timing Mode (DOITM)

[Intel's ISA guidance](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/data-operand-independent-timing-isa-guidance.html)
enumerates DOITM with `IA32_ARCH_CAPABILITIES[12]`; the control is
`IA32_UARCH_MISC_CTL[0]`, scoped to a logical processor. For enumerating CPUs,
deployments relying on the documented DOIT behavior must establish OS-managed
enablement for every eligible processor throughout execution, including
migration. Follow current CPU/microcode guidance rather than assume one Linux
default. Intel also describes CPUs which, with current microcode, do not
enumerate the control and do not require setting it for that behavior.

Brynja neither reads nor writes this privileged MSR. Static AES-NI admission
establishes an ISA contract, not DOITM enablement. DOITM's guarantee concerns
the documented instruction subset, not arbitrary wrapper code, memory-address
effects, speculative execution, power/thermal variation or physical faults.
It is not an AMD/x86-wide policy. This document does not instruct a user-space
crate to write MSRs, enable the mode globally, or require administrator access.

## Scope decision

Ordinary crate use remains possible without an HSM, a military-profile feature,
or a mandatory global timing mode. Stronger deployment claims require a
separately reviewed platform policy. The owner has
[accepted the documented timing limitation](aes-acceleration-acceptance.md#owner-disposition--2026-11-12)
for progressing v0.27.3; these named mechanisms clarify that limitation rather
than convert it into a pass. Optional independently modelled fault detection
remains planned for v0.27.7 and is separate from DIT/DOITM.
