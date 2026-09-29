# Rust-owned native Windows host experiment

Status: isolated v0.24.50 **public-data research**, not a shipping backend or
Windows strict qualification. Release policy and production crates are unchanged.

The completed [native campaign](windows-enclave-native-host-results.md) records
the normal path, startup cleanup, deliberate deletion failure and compiled mutants.

This binds the [safe host ledger](windows-enclave-host-session-design.md) to a
real Windows enclave. The previously signed scoped-wire DLL is reused byte for
byte; only the host executable changes. Its development signing, platform and
[wire-protocol limitations](windows-enclave-wire-results.md) remain applicable.

## Ownership boundary

The private Rust `Host` owns both `Resource` and `Session`. There is no public
resource getter, raw request interface, generic callback or session reset. Its
fixed research entry point accepts a bounded live C path; C's `wmain` is the only
driver. The fixture is not a library API for downstream use. The existing safe
ledger is copied into a temporary nested module without changing its logic or
unsafe-code prohibition; an appended safe bridge is visible only to the host.

The C resource contains the OS instance and its fixed exports, binds construction,
execution and deletion to the creating thread, and denies concurrent/reentrant
calls. The Rust ledger retains exclusive input/output/session borrows. Stack-local
request, command and staging arrays remain live throughout synchronous `CallEnclave`.
The callback is fixed and uses a thread-local context only during that call; an
unexpected callback thread is rejected. This is not a claim that Windows formally
guarantees callback thread identity. No unwind may cross the FFI boundary.

The callback checks the full window and both guard pages fit inside the instance;
it checks all 16 workspace pages are initially unlocked, locks them, verifies their
working-set lock bits at each exchange, and unlocks only after the enclave's fixed
outer-zero notification. After return, the host independently queries window,
guard, restricted-copy, absorbed-length and cleared-owner diagnostics. The ledger
then validates terminal status and commits staged **public** output. These are
research diagnostics and checks, not attestation against a malicious host.

Confirmed copy-out rejection and cancellation leave the session reusable.
Denied callbacks, uncertain replies, wrong phases and missing cleanup confirmation
quarantine it and leave caller output unchanged. A quarantined session cannot
reach another native call. Failed lock/transport/cleanup paths do not manufacture
a clear confirmation or unlock dirty pages to simulate success.

## Teardown is checked, not assumed

Termination and deletion are separate. `TerminateEnclave(..., FALSE)` requests
termination; `DeleteEnclave` can still report `ERROR_ENCLAVE_NOT_TERMINATED`. The
host retries only that error, up to 100 attempts separated by 1 ms; other errors
fail immediately. This bounds retry count, not OS scheduling or syscall latency.
The parent gives each child a 30-second deadline. See Microsoft's
[termination](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-terminateenclave)
and [deletion](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-deleteenclave)
contracts.

The callback/resource context is freed only after deletion succeeds. Explicit
close reports failure; Drop attempts close but cannot turn failure into successful
evidence. Counters independently track created, deleted, native calls, retained
owners and cleanup errors. A synthetic deletion-failure control deliberately
retains its terminated instance until child-process exit and must record failure,
not a clean teardown. No claim is made that this control causes a real Windows
deletion error or proves cleanup after arbitrary process termination.

## Focused verification

```text
python3 scripts/cryptography/test-windows-enclave-host-session.py
python3 scripts/cryptography/test-windows-enclave-native-host.py
python3 scripts/cryptography/windows_enclave_native_host_build.py <persistent-output-directory>
```

The last command cross-builds a host static library with Rust 1.98.1 for
`x86_64-pc-windows-msvc`, panic=abort, checked overflow and warnings denied. It
generates 20 independent Python `hashlib` public vectors. Native MSVC links
`native_host_main.c`, `native_host_resource.c`, `native_host_transport.c` and
`native_host.lib` with `/std:c11 /O2 /W4 /WX /MT /guard:cf`, `onecore.lib` and
`psapi.lib`. Build `normal.exe` without injection; build `fail-create.exe`,
`fail-load.exe`, `fail-init.exe`, `fail-delete.exe` with the corresponding
`BRYNJA_HOST_FAIL_CREATE/LOAD/INIT/DELETE` definition. Run:

Also build `early.exe` and `cleanup.exe` without a C injection, linking the
generated `early.lib` and `cleanup.lib` respectively in place of `native_host.lib`.
These deliberately bypass deferred output commit or cleanup confirmation in the
actual Rust model. The runner requires their expected nonzero failure exit and
exact failure-stage counters, rather than treating any crash as mutant rejection.

```text
python windows_enclave_native_host_run.py <native-build-directory> <unchanged-signed-wire-DLL>
```

The normal campaign requires 60 vector operations (export, cancel, real OS
copy-out rejection), three uncertain/error-path calls, blocked reuse, explicit
close, and Drop deletion: exactly five created/deleted owners and zero retained
owners/cleanup errors. Startup controls require deletion after creation, loading
and initialization. The deletion control requires one retained owner, zero
confirmed deletions and two failed cleanup attempts after its 60 vector calls.
Raw stdout/stderr and binary/source hashes are retained. A cross-build alone is
not native execution. Native observations are recorded separately.

Two bridge tests run at O0/O2 with early-commit and ignored-cleanup mutants.
The record validator rejects 126 altered/type-confused counter fields and seven
extra-field records. The earlier model tests, six mutants, 24 ownership/privacy
rejections and actual in-process worker comparisons remain separate checks.

## Still outside this experiment

All input and staging is public, ordinary host memory. This does not establish
confidential attested ingress, protected persistent results, resistance to a
malicious containing process, arbitrary callback safety, dump exclusion of the
complete runtime, production enclave signing, other algorithms, broader native
platform qualification or shipping Windows strict support.
