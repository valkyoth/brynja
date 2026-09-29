# Active Rust-host dump experiment

Status: isolated public-data research, **not Windows strict support**. This adds
an observation lane for the [Rust-owned native host](windows-enclave-native-host-results.md)
without changing its sources, the signed enclave DLL, production crypto or gates.

The [native captures and repeats](windows-enclave-active-dump-results.md) record
the two pause points, complete positive controls and cleanup observations.

The previous dump campaign covered a synthetic enclave allocation. This campaign
instead interrupts the actual SHA-256 result exchange while its enclave worker is
active. A temporary copy of the host callback is instrumented immediately after
the complete 16-page lock check and before it invokes the Rust protocol bridge.
The builder requires exactly one matching insertion site. A separate C entry point
allocates an ordinary 8192-byte public marker and starts the same Rust campaign.
Only its first public empty-message operation can reach a fatal checkpoint:

- Event 2: first result offer, epoch 1, slot 1, status 0. The enclave still owns
  its result; the ordinary host output staging buffer must contain 32 zero bytes.
- Event 3: second offer, same epoch/slot, status 1. A public digest has been copied
  into ordinary host staging but the Rust host has not accepted completion. The
  staging buffer must contain the independent SHA-256 digest of the empty message.

The selected checkpoint prints only public addresses, PID, phase and lock count,
flushes them, and raises a fail-fast exception. It does not run destructors and
does not claim post-crash clearing. Microsoft documents that this bypasses
exception handlers and invokes WER when available.
[RaiseFailFastException](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-raisefailfastexception).

## Bounded capture and non-vacuous interpretation

The parent runs only with explicit `--allow-app-local-dump`. It copies the fixed
host executable into its own temporary directory under a random application
name, creates only that application's full-local-dump policy and starts a child
with an environment allowlist. It never changes global WER policy or an existing
application key. WER's per-application settings and full-dump mode are documented
by [Microsoft](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps).

The child has a 90-second deadline. The parent requires the exact fail-fast exit,
PID, phase, epoch, bounded nonoverlapping addresses, and 16 locked pages. It then
requires exactly one matching child dump and validates the full-memory format
using the existing bounded parser. No dump, a truncated dump, missing positive
controls or an unrelated crash is **inconclusive/failure**, not exclusion.

Both controls must be fully present: all 8192 marker bytes and the phase-specific
32-byte Rust staging value. The parser counts included bytes separately for the
64 KiB owned window and the full 256 MiB enclave reservation. Partial coverage,
including zero-filled bytes, is reported as inclusion rather than absence. Bytes
elsewhere in the enclave cannot be silently attributed to the owned window.
An observed inclusion is preserved, not changed into a failed run with no record.

Raw dump contents are not printed or collected. After analysis, the parent removes
its application key, copied executable and temporary directory/dump. Failures in
cleanup prevent a completed observation. Sources, original image and host build
artifacts are bound to the observation. The build/capture source association is
an implementation-author review, not attestation or an independent certification.

## Reproduction

```text
python3 scripts/cryptography/test-windows-enclave-host-dump.py
python3 scripts/cryptography/windows_enclave_host_dump_build.py <persistent-directory>
```

On the prepared Windows development host, compile `native_host_dump.c`,
`native_host_resource.c`, the generated `native_host_transport.c`, and
`native_host.lib` with `/std:c11 /O2 /W4 /WX /MT /guard:cf`, linking `onecore.lib`
and `psapi.lib` as `active-dump.exe`. Do not use the normal campaign main.
For each checkpoint, from a clean committed source checkout:

```text
python scripts/cryptography/windows_enclave_host_dump.py <directory>/active-dump.exe <signed-wire.dll> 2 --allow-app-local-dump
python scripts/cryptography/windows_enclave_host_dump.py <directory>/active-dump.exe <signed-wire.dll> 3 --allow-app-local-dump
```

The focused tests cover phase-specific controls, absent/partial/zero/full memory
descriptors, malformed dumps, bounds/identity/type confusion, callback placement,
unexpected exits, timeout containment and environment minimization. The prior
native-host, WER and dump-parser regression suites remain applicable.

## Explicit limits

An absent range establishes only absence in this WER dump at this checkpoint.
It does not prove absence of all secret-derived data in registers, transition or
OS-owned stacks, TLS, unrelated mappings, privileged snapshots or arbitrary dump
mechanisms. Entire-reservation absence does not prove every secret-bearing object
is located inside that reservation. Host input/staging here is deliberately
public. Fatal termination does not demonstrate normal-return memory erasure.
Confidential ingress, persistent output ownership, production signing and full
platform qualification remain separate obligations.
