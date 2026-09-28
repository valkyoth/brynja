# Windows enclave worker ownership review

Status: v0.24.50 platform research, not an implemented strict worker adapter.
Production Windows constructors still reject. No release policy or Linux
cryptographic behavior is changed. See the
[enclave feasibility and fixed-buffer experiments](windows-enclave-design.md).

## Native inventory and clearing experiment

On 2026-09-28 the native Azure x86-64 host ran the standalone `worker.c`
experiment from clean checkout `d9f24a41` (the full source commit is recorded
in each observation). The image source was built at `91eb1418` and did not change
between those commits. It used the same development-only VBS/HVCI/test-signing
configuration described in the preceding experiments, not production signing.

Each of three calls wrote known public markers into an 8-KiB local array and
an 8-KiB static TLS array, verified them internally, cleared them with volatile
writes and checked the complete arrays for zero before returning. The normal
image passed. A separately compiled `BRYNJA_PROBE_SKIP_CLEAR` image omitted both
clearing loops and was rejected by the same readback check on all three calls.
The host required exactly one worker actually returned by `InitializeEnclave`,
not merely a requested count. No raw host pointers were accepted by the image.

The [normal record](../assurance/windows-protection-observations/enclave-worker-azure-d9f24a41.json)
and [compiled-mutant record](../assurance/windows-protection-observations/enclave-worker-mutant-azure-d9f24a41.json)
bind distinct image hashes and seven source hashes verified against their commit.
Running the mutant in normal mode and the normal image in mutant mode both
returned exit 1; their [first](../assurance/windows-protection-observations/enclave-worker-wrong-mode-d9f24a41.txt)
and [second](../assurance/windows-protection-observations/enclave-worker-wrong-mutant-mode-d9f24a41.txt)
failure transcripts are preserved. Eight portable failure-injection tests also
passed on Linux and native Windows.

The [build transcript](../assurance/windows-protection-observations/enclave-worker-build-91eb1418.txt)
and [exact build command script](../assurance/windows-protection-observations/brynja-enclave-worker-build.cmd.txt)
identify both compile modes. The [signing transcript](../assurance/windows-protection-observations/enclave-worker-sign-91eb1418.txt)
retains SignTool exit 2 and the compatibility warning for both images. The wrapper
failed rather than calling that a clean signing pass; the produced images were
then deliberately used for these development-only loader tests. The ephemeral
signing identity was removed. The [separate cleanup check](../assurance/windows-protection-observations/enclave-worker-cleanup-azure-d9f24a41.json)
found no retained probe process, temporary signing certificate, copied executable,
dump directory or application-specific WER policy. This worker test collected
no crash dump and changed no working-set limits or privileges.

## What the mapping observations establish

The initial driver assumed that host and enclave `VirtualQuery` would agree on
allocation boundaries. It rejected the native result as
[worker allocation not observed](../assurance/windows-protection-observations/enclave-worker-azure-91eb1418.err).
That attempt is inconclusive, not qualification. The corrected driver records
both views, checks that each covers the complete marker inside the enclave's
bounded address range, and limits host mapping enumeration to 128 descriptors.
A regression rejects conflating the two views.

| Region observed in the normal image | Enclave view | Host view |
| --- | --- | --- |
| Local 8-KiB array | 12-KiB current region; allocation begins at enclave offset 65,536 | 24-KiB committed region covering that address; allocation begins at enclave offset zero |
| Static TLS 8-KiB array | 16-KiB current region; allocation begins at offset 2,293,760 | 20-KiB committed region covering that address; allocation begins at offset zero |

Both layouts were stable across the three observed calls. This does not prove
thread affinity or stability under deeper calls, stack growth, different TLS,
another compiler/runtime, exceptions or concurrency. The host's allocation view
also contains other enclave mappings; it must not be used as permission to erase
the whole allocation. In particular, current region size is not the complete
worker-stack reservation or proof that every page is already committed/locked.

Microsoft's [initialization structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-enclave_init_info_vbs)
returns the actual number of enclave threads. It does not accept caller-owned
stack memory. [Termination](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-terminateenclave)
with `fWait=FALSE` is not a join, and [deletion](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-deleteenclave)
may fail while execution remains. None of these API descriptions establishes a
whole-stack/TLS clearing guarantee. Do not invent such a guarantee from successful
termination of this idle single-worker probe.

## Required lifecycle before production integration

1. Identify every secret-bearing allocation and execution region, including
   padding, stack growth and TLS/runtime-created copies. Either own its full
   lifecycle or prove it never receives secret data. Static array clearing is
   not a substitute for this inventory.
2. Acquire guards and lock every required page before allowing secret input.
   A bounded bootstrap may inspect public geometry, but must not process secrets.
   Lock failure must reject without fallback or implicitly increasing limits.
3. Establish an execution boundary with a reviewed Windows ABI/unwind contract.
   No arbitrary host closures or cross-boundary Rust unwinding. A custom stack
   switch is not approved merely because a synthetic local array works.
4. Stop new entry, drain active calls and finish any relevant TLS destruction.
   Clear owned state and full execution storage only after that storage is no
   longer live, and while protections remain active. Then unlock/release it.
5. Demonstrate failure, cancellation, partial startup and recoverable-unwind
   cleanup, plus compiled mutants and emitted-code checks. Separately qualify
   dump exclusion for the actual worker layout rather than the static-buffer
   image used earlier.

The current probe checks only its two arrays. It does **not** clear the complete
stack, caller/runtime frames, other TLS, allocation padding or registers; it does
not lock these worker regions. `full_worker_cleanup_proved` remains false. The
next design work must resolve ownership and safe post-execution clearing of the
complete worker storage; no current strict API is enabled by this observation.

Downloaded record hashes before CRLF normalization:

| Record | SHA-256 |
| --- | --- |
| Normal worker | `5e234910c5dda6e1a1ffdfc5f7f14289c014feb2208f1d6c40f8ef92c825d7fa` |
| Missing-clear mutant | `aab31145b6f87ca861f0f057cd125d31e6bf30410236a332645abedbd6fe8c0b` |
| Cleanup/configuration | `c9b0f52f1efb7e085796c6eb639848223a96b9660f0c586ef809b93672090244` |

## Follow-up: separately owned allocation lifecycle

The next public-marker experiment, from clean commit
`89e082e749a60f6a1aa9c32d15f717939edb8c0d`, uses a different `owned.c` image.
It does not attempt to clear or replace an OS-managed live stack. Inside the
enclave it reserves 64 KiB, commits only an 8-KiB payload, and checks the entire
allocation geometry: 4 KiB reserved before the payload and 52 KiB reserved after
it. It rejects duplicate allocation, dirty release, premature zero queries and
stale operations. Addresses are public diagnostic integers only.

The [normal Azure record](../assurance/windows-protection-observations/enclave-owned-azure-89e082e7.json)
contains two successful allocation cycles. Host-side `VirtualLock` succeeded
before any nonzero marker was written. Both payload pages had valid/locked
working-set observations before writes, after writes, and after complete internal
zero readback. Only after that readback did the driver unlock and request enclave
release. This establishes this bounded normal-return ordering on the development
host, not full worker protection.

The [compiled missing-clear mutant](../assurance/windows-protection-observations/enclave-owned-mutant-azure-89e082e7.json)
failed zero readback and refused payload release. Its driver did not explicitly
unlock the dirty payload; the synthetic enclave was terminated/deleted instead.
**That teardown is not an erasure result.** Unexpected dispatch/query failures
also remain failures, not successful cleanup observations. The two
[wrong-mode](../assurance/windows-protection-observations/enclave-owned-wrong-mode-89e082e7.txt)
[runs](../assurance/windows-protection-observations/enclave-owned-wrong-mutant-mode-89e082e7.txt)
returned exit 1 as required. Twelve focused regressions passed on Linux and
[native Windows](../assurance/windows-protection-observations/enclave-owned-tests-89e082e7.txt),
covering admission ordering, incomplete/unlocked page observations, dispatch and
cleanup failures, mutation identity, geometry and false qualification claims.

The [build transcript](../assurance/windows-protection-observations/enclave-owned-build-89e082e7.txt)
records successful warning-as-error normal/mutant compilation and enclave-only
imports. The [signing transcript](../assurance/windows-protection-observations/enclave-owned-sign-89e082e7.txt)
again preserves compatibility-warning exit 2, not a clean signing pass, followed
by temporary key removal. Exact
[build](../assurance/windows-protection-observations/brynja-enclave-owned-build.cmd.txt)
and [signing](../assurance/windows-protection-observations/brynja-enclave-owned-sign.ps1.txt)
scripts are retained. The [cleanup record](../assurance/windows-protection-observations/enclave-owned-cleanup-89e082e7.json)
reports no retained probe process, temporary signing certificate, dump directory,
copied executable or app-specific WER policy. Both records' eight source hashes
were checked against their exact commit; transcript whitespace/CRLF was normalized.

This is a candidate owned-storage primitive, not a production adapter. The
enclave cannot independently attest a host `VirtualLock` call: the tested driver
orders it correctly, but an arbitrary caller could bypass that driver. Microsoft
lists enclave allocation/protection APIs, not an enclave `VirtualLock` export.
[Vertdll API list](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/enclaves-available-in-vertdll).
The host-side lock contract is therefore not a claim of residency against a
hostile host. [VirtualLock contract](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock).

No execution stack was switched, no confidential input was accepted, and no dump
was collected. Full stack/TLS ownership, failure-path clearing, ABI/unwind safety,
register cleanup, dump exclusion for the new allocation and production signing
remain to be established before strict Windows integration. The next execution
design must avoid copying secret values onto the unmanaged bootstrap stack or
TLS; successful allocation alone does not meet that obligation.

Downloaded JSON hashes before CRLF normalization:

| Record | SHA-256 |
| --- | --- |
| Normal owned allocation | `7863991ae8141089b944f3854133fc60ad8728c34352c3607a49e8fadf7b7c45` |
| Missing-clear mutant | `87e1fc715ac84978868f0eb08a4823e71802c98daceda030cd3d0fec98e02072` |
| Cleanup/configuration | `32bcf006df64b95dcf7eb29a36372865ed5fee999b8afe2293099c7bc9060d14` |
