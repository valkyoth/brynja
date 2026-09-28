# Windows enclave stack/unwind comparison

Status: v0.24.50 synthetic platform research. **The separate-stack prototype is
not suitable for strict integration.** No production backend or release rule
changed. See the [worker-ownership review](windows-enclave-worker-design.md).

## Question and method

Can one fixed enclave operation return and unwind safely when its execution
stack is a separately owned mapping? This is deliberately not a cryptographic
test and accepts only public mode integers. A 256-byte local array contains
public marker bytes, cleared/read back by a C `__finally` block. Unwind modes
raise one exact application exception and require the matching outer handler;
an unrelated exception cannot satisfy the check.

The first image used clean commit
`dfce95d5655ce52df0450e89bd8d14e44bd881ab`. After alternate-stack unwinding failed,
the matched-control image at `febff2e2cb054d7264917109a0c547f2d7997b20` added
two modes that use the same assembly frame and fixed call instruction while
leaving RSP on the OS-managed stack. It does not change TEB/OS stack metadata.

Each bounded child allocates a separate guarded 64-KiB payload in the enclave,
locks all 16 pages, checks their valid/locked flags, and verifies where the local
array actually executed. Successful runs require the exact normal/unwind marker
bits, a second locked-page observation, complete owned-region clearing from the
original stack after the work left the region, then unlock/release and enclave
termination/deletion. The OS-stack controls do **not** thereby qualify clearing
of their OS-managed stack; they merely clear the separate payload plus their
test array. A crash or timeout produces no completed observation record.

## Native outcome

The same Azure development host remained on Windows Server 2025 build
26100.33438, native AMD x86-64, VBS/HVCI running, test signing enabled and Secure
Boot disabled. This remains development-only, not production qualification.

| Matched-control mode | Outcome |
| --- | --- |
| [Direct OS stack, normal](../assurance/windows-protection-observations/stack-os-normal-febff2e2.json) | Required markers, frame location and cleanup passed |
| [Direct OS stack, exception](../assurance/windows-protection-observations/stack-os-unwind-febff2e2.json) | Exception caught; `__finally` clearing verified |
| [Owned stack, normal](../assurance/windows-protection-observations/stack-owned-normal-febff2e2.json) | Actual local frame inside owned payload; full owned-region clear/release passed |
| [Owned stack, exception](../assurance/windows-protection-observations/stack-owned-unwind-febff2e2.err) | Child terminated with `0xc0000005`; no cleanup/qualification record |
| [Trampoline on OS stack, normal](../assurance/windows-protection-observations/stack-trampoline-normal-febff2e2.json) | Same assembly call path passed without switching stacks |
| [Trampoline on OS stack, exception](../assurance/windows-protection-observations/stack-trampoline-unwind-febff2e2.json) | Same assembly frame/call path unwound successfully on the OS-managed stack |

The initial separate-stack run failed with the
[same child status](../assurance/windows-protection-observations/stack-owned-unwind-dfce95d5.err).
The matched controls narrow the difference to the alternate-stack execution
path, but do not identify the exact faulting instruction or prove that every
possible Windows stack design must fail. In particular, do not silently label
the access violation a specific OS stack-limit check without further evidence.

The [emitted trampoline/frame excerpt](../assurance/windows-protection-observations/stack-control-frame-febff2e2.txt)
shows the expected RBP save/frame establishment, conditional RSP switch, 32-byte
shadow space, fixed call, stack restoration and return. Its PE unwind entry
contains `SET_FPREG` and `PUSH_NONVOL`, with RBP and zero frame offset. Thus this
was not an experiment with absent trampoline unwind metadata. Metadata presence
and the working OS-stack control are not proof that cross-stack dispatch is safe.

## Reproducibility and cleanup

All nine source hashes in each completed JSON were verified against its exact
commit. Normal and matched-control images have separate build/signing records
and were not overwritten. Both build transcripts include the nine focused
regressions passing natively and warning-as-error C/assembly compilation:

- Initial [build](../assurance/windows-protection-observations/stack-build-dfce95d5.txt)
  and [signing](../assurance/windows-protection-observations/stack-sign-dfce95d5.txt).
- Matched-control [build](../assurance/windows-protection-observations/stack-control-build-febff2e2.txt),
  [signing](../assurance/windows-protection-observations/stack-control-sign-febff2e2.txt),
  [run script](../assurance/windows-protection-observations/brynja-enclave-stack-control-run.cmd.txt)
  and [per-mode exit log](../assurance/windows-protection-observations/stack-control-run-febff2e2.txt).

The signing wrappers again failed on SignTool's compatibility-warning exit 2,
removed their ephemeral identities, and did not call it a clean signing pass.
The resulting signed images were used only for this explicitly developmental
comparison. The [post-run cleanup/configuration observation](../assurance/windows-protection-observations/stack-cleanup-febff2e2.json)
found no retained probe process, temporary signing certificate, copied executable,
dump directory or app-specific WER key. That absence does not prove erasure in
the crashed child. No crash dump was requested or analyzed by this experiment.

Raw download archive SHA-256:
`80b6775715d2223b235d1b8f1e12abf63d7da05bb37a5dc752ceec2598cf022d`.
Full raw disassembly/unwind output hashes (retained with the experiment on the
host; only the relevant first-party trampoline excerpt is committed):

- Initial: `05e22482943c2e85e1bdd1860aa6526932cadb88a04c65e285453c9af80b706a`.
- Matched control: `c71258891377272e232bb9c5e8f51da44203f45056ba9b0be6e3ae93c961526a`.

Record/transcript CRLF and trailing whitespace were normalized for Git.

## Consequence for the design

Do not ship this separate-mapping trampoline or disable unwinding to make it
appear operational. An exception recoverable on the OS stack becomes a fatal
failure here, so normal-return success is insufficient for the existing
recoverable-worker-panic contract.

The next candidate to investigate is a bounded execution region **within** the
OS-managed enclave stack, with demonstrable lifetime/guard ownership, admission
before secrets, and clearing after work but before that region's frame is lost.
This is a research direction, not a confirmed mechanism: bootstrap callbacks,
stack growth, unwind handlers, TLS/runtime copies and clearing code must remain
outside the secret region or be included in its ownership proof. No undocumented
TEB edits are approved. If that cannot preserve the contract, retain Unsupported
and present the limitation rather than weakening the profile.

Even a future C SEH success would not qualify Rust panic unwinding, register
cleanup, concurrent workers, dump exclusion, production signing or all compiler
and architecture combinations. Those remain separate integration requirements.

The follow-up [OS-managed stack window experiment](windows-enclave-window-results.md)
passes its bounded synthetic normal/exception and missing-clear comparisons.
It has not yet established residency, independent guards or Rust panic handling.
