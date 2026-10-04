# Current sequential-image dump checkpoints

This campaign uses the existing signed sequential images without rebuilding or
instrumenting their code. It complements the separate concurrent scheduler
[dump observations](windows-enclave-whole-image-cleanup.md#current-scheduler-dump-observations-2026-10-04).
These are development-platform observations, not whole-image qualification or a
new release gate.

## Results, 2026-10-04

All eighteen sequential images completed four observations each: **72 full WER
dumps**. Every dump contained the complete ordinary positive control; none
contained any bytes from the image's enclave reservation. The live window had
sixteen locked pages at admission. At the retained checkpoint, the worker window
was unlocked and the retained page was locked. The final read-only check found
no remaining application policies, raw-dump folders, copied executables or crash
children, and confirmed VBS remained running.

The [source-bound record](../assurance/windows-protection-observations/current-sequential-dumps-20261004.json)
pins redacted results, cleanup confirmation, the exact image list and repeatable
local verifiers. Together with the six earlier concurrent scheduler observations,
all nineteen current images now have scoped dump observations; their different
checkpoints must not be conflated. Nine new regressions passed on Linux and
Windows. The existing nine scheduler-dump and nine wrapper-binding tests also
passed locally. All eighteen sequential linked images match the tested
`PublicLockedFrame` object's instruction bytes apart from its enumerated
relocations. This is not qualification of those call targets.

## Exact scope

The diagnostic opens the image on native Windows x64 and uses its existing
`PublicRetained` owner-creation operation and callback protocol. All data is
public. Two repetitions are requested at each checkpoint:

- **Admission:** the host has locked and observed all sixteen pages of the live
  64-KiB worker window. The enclave body has not yet run; no retained owner exists.
- **Retained:** owner creation returned successfully, the stack-window clear and
  unlock callback completed, and the separate guarded retained page remains
  locked. This is an initialized owner, not a running compression or a completed
  digest export.

Each disposable child emits only public address/phase metadata and deliberately
fails fast. Its unique executable has an application-specific WER configuration;
the global dump policy is not changed. A full dump must contain an ordinary
8,192-byte positive control with the expected public pattern. The parser counts
all included bytes in the enclave reservation, worker window and retained page;
included zeroes do not count as exclusion. Missing dumps, malformed descriptors,
missing/partial controls, a wrong process/checkpoint or a different crash code
cannot produce a successful observation.

Raw dumps are inspected in the guest and removed before the child campaign
reports success. Temporary executable copies and application-specific dump
policies are also removed. Each child has a 90-second bound; the campaign uses
at most two image runners concurrently. Final records bind the unchanged image,
Python interpreter and loaded diagnostic source files. They contain no raw dump
bytes. The original functional campaigns are reused rather than rerun.

## What this does not establish

The observed checkpoints do not sample mid-compression, mid-copy, all error
branches or every retained state. These tests do not prove fatal-path erasure:
the deliberate crash prevents normal teardown. No assertion is made about
secrets in caller buffers, unrelated host memory, register/context records,
hibernation or privileged snapshots. The ordinary control deliberately remains
visible. Enclave reservation exclusion at these checkpoints is not a universal
OS guarantee or proof that other memory contains no secret-derived copies.

Exact linked-wrapper binding is a separate check. It can establish that the
tested clearing wrapper's instruction bytes are present in each image, allowing
only the enumerated relocation fields; it does not establish semantics of every
linked callee. The remaining caller/runtime qualification and independent retest
must retain that distinction.
