# External-key provider API completion — v0.27.6

Status: in progress. On 2026-11-13 the owner chose dependency-free API completion
for all three AES widths, replacing the proposed concrete PKCS#11 adapter.
Applications choose and supply their own adapters. No HSM is required; no
device client, native FFI or OpenBao integration is included in this project
scope. This does not claim hardware support or hardware custody.

The [candidate pentest follow-up](aes-provider-pentest-remediation.md) fixes
permission exhaustiveness, stale/per-width docs and quarantine error precedence.
Its refreshed suite has 17 tests per width (51 total), 408 archive executions
and 1,087 registry regressions passing.
The owner retained the trusted-adapter contract with explicit limits instead of
the breaking width-admission redesign. Added multi-trait owner-separation controls
bring compiler coverage to 180 paired probes per endpoint. This is not release approval.
Counts below describe the initial candidate slice before that follow-up.

## Implemented provider contracts

The existing default-off provider feature now exposes distinct `Aes128Backend`,
`Aes192Backend` and `Aes256Backend` traits with matching provider-key owners.
Existing AES-128 source APIs are retained. A private macro shares the unchanged
output, permissions, quarantine and explicit-destruction mechanics; it does not
bridge one width to another. The adapter remains responsible for verifying the
actual opaque device key's type and width. Implementing a trait is trusted code,
not hardware attestation.

The same sixteen lifecycle/fault tests run at each width, with separate FIPS
197 Appendix C ciphertexts and public ascending-byte test keys. Coverage keeps
both directions, public/secret destinations, output clearing, partial writes,
bad lengths, errors, panics, persistent quarantine, exact permissions, binding
identity, borrowed/owned Drop, explicit destruction and worker transfer.
Software reference adapters are mocks, not a production fallback.

Compiler checks cover all three widths through direct and facade routes:
168 paired probes per endpoint, including each ordered cross-width rejection,
thread traits, ownership, borrowing and independent feature gates. Positive
counterparts must compile and negative probes must emit the expected diagnostic.
The initial direct-constructor cross-width probe emitted duplicate E0277 errors;
it was changed to isolate the call-site bound, not to weaken diagnostic checking.

The existing verifier registrations now require 48 lifecycle tests per run,
168 paired API probes per endpoint, and fingerprint the shared test fixture and
both new width-specific test targets. Historical observations keep their original
snapshots; they are not treated as fresh results for the extended scope.

```sh
brynja-verify run aes --needed --category provider
```

This selects the scoped mock/API, endpoint, Miri, ASan, doctest and Cortex-M
compile checks, not a timing campaign or native hardware qualification.

## Adapter responsibilities, not shipped device support

Implementing a backend is a trusted boundary. Applications must validate the
actual key type and exact width, mechanism, usage, identity and handle lifetime.
Rust's distinct typed bindings prevent accidental cross-width substitution in
safe consumer code; they cannot inspect a device or prove that an adapter tells
the truth. Non-exportability and sensitivity require device-side admission.

Applications also own module selection, login/logout, session concurrency,
authentication-secret handling, handle reconciliation and deployment controls.
Backend thread traits must follow actual session restrictions, not merely a
device locking flag. Do not claim a named device works without testing its
specific module/firmware/client configuration.

All backend operation errors remain terminal for the binding, including a
reported rejection. No safe-retry taxonomy is introduced: a busy/rejected error
does not prove that work never started. Uncertain completion must not cause
automatic retries or software fallback. Explicit destruction remains available
on a quarantined binding and may itself fail; Drop is not a device command.

## Remaining milestone work

Archive-only acceptance is registered as `aes/provider-packaged`. It reuses
the sixteen lifecycle tests per width against byte-checked Cargo archives,
with only the namespace rewritten for facade consumers. Exact test names,
statuses and summaries are required. Both Rust 1.90.0 and 1.99.1 run direct and
facade routes in debug/release: eight configurations and 384 test executions.
Exact dependency/feature graphs reject checkout substitution or extra providers.
Four Cortex-M compile checks cover the
[no_std application helpers](../../assurance/aes-provider-public-api.rs).
Those generic helpers are compile examples, not device execution evidence.

Candidate metadata and [release notes](../../release-notes/RELEASE_NOTES_0.27.6.md)
now identify v0.27.6. Supporting-crate versions stay unchanged, no packages are
selected for publication, and the existing 30 final-check commands and limits
are unchanged. Candidate commit, owner review, commit-bound final gate and green
GitHub remain separate; this worklist does not declare v0.27.6 released.

On 2026-11-13 all 30 working-tree preflight commands passed, including targeted
reruns after a documentation-only reviewed-source hash refresh and a
sandbox-blocked advisory-cache lock. The release notes retain both initial
failures and their dispositions. The archive provider check was rerun on the
0.27.6 facade and passed all eight host configurations and four Cortex-M builds.
No historical timing or native campaign was rerun or relabelled.

Modes/AEAD, other algorithms, timing qualification and the optional fault profile
remain separate work. The former PKCS#11 client proposal is superseded, not a
finished integration or a newly scheduled milestone. OpenBao integration is
explicitly excluded; no Podman service or external module is required to use or
test these contracts.
