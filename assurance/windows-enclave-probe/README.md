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
