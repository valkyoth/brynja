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
