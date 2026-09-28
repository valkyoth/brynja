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
