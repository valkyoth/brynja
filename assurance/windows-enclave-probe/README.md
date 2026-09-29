# Synthetic Windows enclave lifecycle experiment

This is **not Brynja cryptography or a strict backend**. The C image operates on
public integer values only. It is not a dependency of any published crate and
must not accept confidential inputs. Success does not qualify residency, dump
exclusion, erasure, production signing, platform portability or Rust integration.

The source sets the non-debuggable enclave policy and one enclave thread. The
host uses the documented Windows enclave API-set DLL and does not wait for an
available thread. A parent process bounds each experiment to 30 seconds; failure
to terminate or delete is an error, never a successful-cleanup observation.

## Preparation (disposable development host only)

Use a native Windows x86-64 guest with working VBS and HVCI, a Windows SDK with
enclave libraries/VEIID/signing tools, and MSVC enclave runtime libraries.
Changing boot policy, installing tools or creating a test certificate is a
separate, explicitly approved operator step. Neither Python command below makes
those changes. See [the design/research record](../../docs/windows-enclave-design.md)
for the tested setup, test-signing limitations and unresolved proof obligations.

In a VS x64 developer command prompt, build in a new temporary directory, using
the absolute path to `synthetic.c` in the reviewed checkout:

```bat
cl /nologo /LD /O2 /W4 /WX /MT /guard:cf /Fesmoke.dll X:\reviewed\assurance\windows-enclave-probe\synthetic.c /link /ENCLAVE /NODEFAULTLIB /INCREMENTAL:NO /INTEGRITYCHECK /GUARD:MIXED /LIBPATH:"%VCToolsInstallDir%lib\x64\enclave" /LIBPATH:"%WindowsSdkDir%Lib\%WindowsSDKVersion%ucrt_enclave\x64" libcmt.lib libvcruntime.lib ucrt.lib vertdll.lib bcrypt.lib
"%WindowsSdkDir%bin\%WindowsSDKVersion%x64\veiid.exe" smoke.dll
copy /b smoke.dll unsigned.dll
```

Check **each command's exit code before continuing**. Page-hash test-sign
`smoke.dll` with an ephemeral certificate containing the code-signing, enclave,
and test author EKUs described by Microsoft. Do not sign `unsigned.dll`. Remove
the ephemeral private key afterward; do not import a test root or use a production
key for this experiment. A signing warning is not a clean automation pass: record
and review its exact meaning before testing the resulting image.
[Microsoft signing instructions](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide).

From the clean reviewed repository checkout, with Git and Python on PATH:

```text
python scripts/cryptography/test-windows-enclave-lifecycle.py
python scripts/cryptography/check-windows-enclave-lifecycle.py X:\temporary\unsigned.dll unsigned
python scripts/cryptography/check-windows-enclave-lifecycle.py X:\temporary\smoke.dll signed
```

Unsigned rejection must be error 577, not an arbitrary load/setup failure. The
signed case checks four exact public results and successful termination/deletion.
Review the PE load configuration/imports separately to confirm non-debug policy,
one thread, image-ID-bound enclave runtime imports and the actual tools used.
Records hash the supplied image and checked-out source, but do **not** prove that
the image was built from that source. Preserve the build/signing transcript and
review that association; these records are observations, not release admission.

## Controlled full-local-dump experiment

`dump.c` includes the same non-debuggable image configuration and adds an
8-KiB volatile **public synthetic** region. `PublicRegion` only fills this fixed
region, returns its diagnostic address, verifies the marker internally, or
clears and verifies it. It does not accept user data or perform cryptography.
Build this file instead of `synthetic.c`, following the same enclave build,
identity-binding, ephemeral test-signing and transcript-preservation procedure.
Do not overwrite an earlier evidence image without retaining its build record.

On an authorized disposable Windows host, from a clean source checkout:

```text
python scripts/cryptography/test-windows-enclave-dump.py
python scripts/cryptography/windows_enclave_dump.py X:\experiment\dump.dll --allow-app-local-dump
```

This deliberately crashes only a uniquely named copied Python child, with a
temporary application-specific WER full-local-dump policy. It first verifies
the enclave marker, clears/readbacks it, then refills/re-verifies it. A separate
ordinary mapping contains a distinct positive-control marker. Analysis requires
the exact child dump and the complete positive control; no dump or failed setup
is **inconclusive**, never evidence of exclusion. Partial or zero-filled enclave
coverage is not reported as absence. The raw dump stays on the host and is
removed along with the owned policy and executable. No signing keys or tool
credentials are passed into the child environment.

Only normal-return/preflight clearing is tested; the intentional fail-fast skips
destructors. Even a genuinely absent enclave region would establish only this
dump-path observation, not nonpageability, arbitrary snapshot protection,
complete worker/TLS/spill cleanup, production signing or strict qualification.

## Host-side residency experiment

The same `dump.c` image can be used without crashing or configuring WER:

```text
python scripts/cryptography/test-windows-enclave-residency.py
python scripts/cryptography/windows_enclave_residency.py X:\experiment\dump.dll
```

This bounded child verifies an ordinary locked positive control, observes all
pages touched by the enclave's synthetic region (including unaligned edges),
attempts host-side `VirtualLock`, and records the complete before/after page
observations and exact lock error. Invalid working-set entries do not establish
either residency or nonresidency; their `Locked` union member is not interpreted.
A successful lock is unlocked even if the follow-up query fails. Normal-return
enclave marker clearing, termination/deletion and control cleanup must succeed.
No working-set limits, account privileges or host configuration are changed.

This only evaluates that host-side locking mechanism. Rejection does not prove
enclave pages are pageable, and success would not establish protection of all
enclave worker stacks, TLS or runtime copies. Production strict support remains
unqualified. This is public-marker research, not secret processing.

For the combined locking/full-local-dump experiment, add `--host-lock` to the
dump command above. It requires a successful enclave lock and valid/locked
observations for **every** touched page before crashing the child; the parent
rejects an unlocked-mode record. The lock is held until that deliberate crash.
This does not claim destructor execution at abort, or protection of any region
beyond the fixed synthetic buffer. Missing/partial positive controls still fail.

## Worker stack/TLS inventory experiment

Build `worker.c` with the same enclave-only build procedure. Also build a
distinct `worker-mutant.dll` with `/DBRYNJA_PROBE_SKIP_CLEAR`; keep separate
artifacts/transcripts and test-sign both with an ephemeral development identity.
The mutant intentionally leaves only public markers, never actual secrets.

```text
python scripts/cryptography/test-windows-enclave-worker.py
python scripts/cryptography/windows_enclave_worker.py X:\experiment\worker.dll
python scripts/cryptography/windows_enclave_worker.py X:\experiment\worker-mutant.dll --missing-clear-mutant
```

The enclave executes three public-marker fill/verify/clear/readback calls using
an 8-KiB local array and an 8-KiB static TLS array. Address/region observations
are diagnostic integers, not exported dereferenceable buffers. The parent
requires exactly one initialized enclave worker and bounds mapping enumeration.
The ordinary run must verify clearing; the compiled mutant must fail that same
check and still provide valid inventory, so setup errors cannot masquerade as
mutation rejection. Both reject unsupported operations and require cleanup.

This clears only those two arrays: not the full stack, caller/runtime frames,
TLS allocation padding, other TLS objects or registers. Observed layout reuse is
not a worker-affinity guarantee. The experiment does not lock these mappings or
change protection bits, and it does not erase a live stack. `full_worker_cleanup_proved`
must stay false regardless of the result. Linux/production APIs are unchanged.

## Owned allocation lifecycle experiment

Build `owned.c` normally and with `/DBRYNJA_PROBE_SKIP_CLEAR` as separate images,
using the same build/signing/transcript procedure. This reserves a distinct
64-KiB enclave allocation with an 8-KiB committed payload between uncommitted
guards. The driver checks the enclave's own allocation geometry, locks both
payload pages before writing public markers, and requires valid/locked working-set
observations before writes, after writes, and after complete zero readback.
Only then does it unlock and request release. Two normal allocation cycles must
pass, including rejection of dirty release, duplicate allocation and stale calls.

```text
python scripts/cryptography/test-windows-enclave-owned.py
python scripts/cryptography/windows_enclave_owned.py X:\experiment\owned.dll
python scripts/cryptography/windows_enclave_owned.py X:\experiment\owned-mutant.dll --missing-clear-mutant
```

The compiled mutant must reject clearing and release, without explicit host
unlock of the dirty payload. Its synthetic-only enclave is terminated/deleted;
that teardown is not claimed as erasure. Setup errors cannot stand in for mutant
rejection. No privilege/working-set changes or crashes are requested.

This tests host orchestration, not an enclave-verifiable lock attestation:
an arbitrary caller could bypass the Python driver. No confidential input is
accepted. The allocation is **not** used as an execution stack, no custom stack
switch is performed, and OS-managed stack/TLS, register cleanup, dump exclusion,
hostile-host residency and production signing are not qualified by this test.

For host-side failure cleanup, run the normal image once for each `--fault`
value: `before-fill`, `after-fill`, `after-clear`, and `after-write-query`.
These inject a one-shot Python exception around real enclave calls/observations;
they do not inject native faults or unwind through enclave code. The driver
must retain the original operation error, clear/readback the payload while
locked, then unlock/release and terminate/delete. A reply lost after successful
clearing is recovered by checking the phase and zero readback, not by assuming
the call never executed. Exact event-order regressions reject missing, repeated
or reordered cleanup. A missing-clear image must fail these recovery checks,
not be reported as successful recovery. Fatal process failures, concurrent entry,
and worker-stack/TLS cleanup are outside this bounded experiment.

## Paired native stack/exception experiment (x64 only)

`stack.c` plus `stack_x64.asm` form a separate **unqualified** synthetic image.
The assembly trampoline declares a frame pointer and unwind metadata, preserves
RBP, reserves the x64 shadow space and calls exactly one public-marker function.
It changes no TEB/OS stack metadata and accepts no arbitrary callback. Build
the assembly with `ml64 /c` and link its object with `stack.c` under the same
enclave-only options. Preserve `dumpbin /unwindinfo /disasm` output as well as
the normal load-configuration/import and signing records. Use a disposable host:
an unsupported alternate-stack exception may terminate the bounded child.

Run the same image separately in `os-normal`, `os-unwind`, `owned-normal`,
`owned-unwind`, `trampoline-normal` and `trampoline-unwind` modes with
`scripts/cryptography/windows_enclave_stack.py`. The two trampoline controls
use the same assembly frame and call instruction without switching stacks,
separating that control from a direct C call on the OS-managed stack.
The original-stack modes are controls, not protected-stack claims. Each run
allocates a guarded 64-KiB payload, locks every page and checks their residency
before entry. The fixed worker writes a public local array and clears it in
`__finally`; unwind modes raise one exact application exception and require its
handler. Mode-specific markers and the actual local array address distinguish
OS-stack execution from the owned stack. After the call leaves the alternate
stack, the driver requires complete owned-region clearing while still locked,
then unlock/release and enclave teardown.

Failure, wrong markers, native crash, or timeout is **inconclusive/failure**, not
an expected rejection that qualifies a platform. A successful normal return
does not establish exception support. Even all six passes would not qualify
Rust panic unwinding, TLS/runtime copies, full ABI/register preservation, stack
growth, cancellation, dump exclusion or production signing. No production
module links this prototype, and Windows strict constructors remain unsupported.

## Guarded OS-stack window and bounded depth

The later `window_lock`, `window_guard` and `window_depth` images preserve the
OS-managed stack and test progressively narrower fixed synthetic bodies. Their
separate records cover [live-window locking](../../docs/windows-enclave-window-lock-results.md),
[persistent boundary pages](../../docs/windows-enclave-window-guard-results.md), and
[fixed-frame admission and unwinding](../../docs/windows-enclave-window-depth-results.md).
The last experiment rejects recursion before consuming a reserved margin;
unchecked deep recursion crashes and is not a cleanup pass. None qualifies
arbitrary callbacks, Rust panics, full worker/TLS ownership or production strict support.

The separate `window_rust.rs`/`window_rust.c`/`window_rust_x64.asm` image then
executes a fixed public-marker `no_std` Rust worker using a C-layout return value.
Its [native observations](../../docs/windows-enclave-rust-worker-results.md) cover
success, cancellation, explicit errors and compiled cleanup/outcome mutants.
It uses `panic=abort`; any C exception completes before Rust entry. It adds no
cryptographic operation, Cargo dependency or Windows strict support.

## Retained allocation experiment

`window_persistent.c` reuses the guarded worker scaffold but gives its public
marker an independent three-page allocation. The [native observations](../../docs/windows-enclave-persistent-slot-results.md)
cover retention across worker returns, two boundary pages, residency through
full-page clearing, free/reuse, denied admission and two broken images. The
separate safe Rust `persistent_result.rs` model tests result lifecycle and token
replay rules; it is not yet linked to that allocation. Neither experiment is a
shipping secret-result API or production Windows qualification.

`retained_digest.rs` connects the lifecycle model to the first-party hardened
SHA-256 workspace in [component tests](../../docs/windows-enclave-retained-digest-design.md),
including independent vectors, cleanup/token mutants and ownership negatives.
It has not yet been placed in the native retained allocation. The consolidated
[v0.24.50 remaining work](../../docs/windows-v02450-remaining.md) distinguishes
these research results from production integration and release qualification.

`retained_placement.rs` adds [checked in-page ownership](../../docs/windows-enclave-retained-placement-design.md),
with component, mutation, ownership-negative and strict-provenance Miri tests.
It drops the retained owner before wiping its borrowed page. This does not yet
connect the Rust owner to the signed native retained-allocation image or attest
enclave residency; that integration remains pending.
