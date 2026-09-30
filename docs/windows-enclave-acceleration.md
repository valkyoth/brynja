# Windows enclave acceleration development

The supported enclave session APIs remain scalar. This pass establishes native
execution of existing hardened kernels in a separate public-vector diagnostic
image. It does **not** enable acceleration in those APIs or qualify secret inputs.
Release-gate policy, dependencies and shipping Rust code are unchanged.

## Platform observations

Microsoft lists `IsProcessorFeaturePresent` among the
[Vertdll APIs available inside VBS enclaves](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/enclaves-available-in-vertdll).
Its [feature definitions](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent)
include SSE2, XSAVE, AVX and AVX2. The diagnostic queries that API inside the
enclave, along with bounded CPUID leaves and guarded XGETBV. It does not copy a
host feature mask into an authority. Faults, malformed queries, missing
prerequisites and changing observations reject the experiment.

The Azure Windows Server 2025 x64 development guest reports AMD EPYC 9V45,
SHA-NI, AVX2 and enabled XMM/YMM state inside VBS. Dedicated x86 SHA-512 is absent;
no dedicated SHA-512 execution is claimed. SHA-512 **batch** compression below
uses AVX2 integer instructions, not the dedicated SHA-512 instruction extension.
Feature discovery and KATs do not prove that arbitrary scheduling, hotplug or VM
migration preserves these features, nor confer production trust or cleanup proof.

## Native public-vector experiment

C performs only OS/CPU queries and bounded routing. Cryptography uses existing
first-party Rust hardened kernels unchanged. The whole Rust image is compiled
with `+sha,+sse2,+avx,+avx2`, so the baseline C entry requires the **complete**
bundle before entering any Rust routine, even the SHA-NI experiment. There is
no fallback or dedicated-SHA512 route. Each campaign revokes its authority and
requires subsequent work to fail.

| Existing hardened kernel | Independent comparisons |
| --- | ---: |
| SHA-256 SHA-NI | 32 |
| Single-state Keccak AVX2 | 16 |
| Eight-lane SHA-256 AVX2 | 256 |
| Four-lane SHA-512 AVX2 | 128 |
| Four-lane Keccak AVX2 | 64 |

All 496 comparisons passed inside the development VBS enclave. SHA-2 expectations
come from Python hashlib; Keccak uses the existing independent Python oracle.
Lane inputs differ; successful batch call counts are checked. Startup KATs run
in addition to these comparisons.

Local and ordinary Windows-process tests pass. Three corrupted oracle tables
cause exactly the five relevant campaigns to fail. Seven Python tests cover
malformed inventory, missing prerequisites, result tampering, timeouts, cleanup
and rejection without execution. A separate test compiles the **actual C entry**
against mock public feature queries and rejects eleven compiled guard mutations.
The mock test is not enclave execution evidence.

The [source-bound observations](../assurance/windows-protection-observations/cpu-kernels-20260930.json)
reference the saved image, emitted assembly, commands and native results. All
166 build/capture source hashes match. Temporary signing certificates/private
keys were removed; enclave deletion succeeded. SignTool reported success with
its SDK compatibility warning; the wrapper returned nonzero. No clean production
signing result is claimed.

## Next integration boundary

- Add explicit opt-in selection to protected session/worker protocols and bind
  it to trusted image policy. Scalar constructors remain scalar; failed
  acceleration must not silently choose scalar execution.
- Keep backend owners and scratch in enclave storage. Preserve streamed
  framing, retained composition, output transactionality and quarantine.
- Inspect Windows ABI/register behavior for the actual integrated image. This
  public diagnostic does not qualify caller frames, stacks, secret placement,
  spills or erasure merely because it invokes hardened kernels.
- Complete differential, negative-selection, cleanup and independent review;
  qualify bounded multicore ParallelHash separately.

These observations concern one development x64 guest. Windows ARM64, production
signing, arbitrary migration and privileged snapshots are not qualified.
