# Native affine retained-result host observations

Status: **research observations only**, not production Windows strict support.
The private Rust host owns the actual Windows enclave resource and connects the
[affine session model](windows-enclave-retained-host-design.md) to the unchanged
[retained Rust-owner image](windows-enclave-retained-worker-results.md). All inputs
and digests remain fixed public test vectors. No signing, host configuration or
release-gate changes were needed.

Host source: `c0e5c2cd80b1ea842f18cc011def78cb784cf7e2`.
The [reviewed observation record](../assurance/windows-protection-observations/retained-native-host-c0e5c2cd.json)
binds that source closure, both campaigns, executable hashes and exact outcomes.
The complete archive, including the initial rejected experiment, is saved outside
Cargo's `target/` tree:

```text
release-reports/windows-azure-replacement-2026-09-29/retained-native-host-complete.tar
SHA256 2648e7160c02e646e84098e377b60f30141a5b1a751f9b55ea608392833e786d
```

Archive review checked committed/current source hashes, generated native sources,
Rust archives, both sets of executable hashes and raw stdout/stderr, native build
transcripts and cleanup observations. No probe child remained active; the previous
signed enclave image retained its hash. No signing keys or raw dumps are included.

## Ownership and receipts

`retained_native_host.rs` owns the native instance, generation and live-result
obligation. Its private C adapter serializes operations on the creating thread,
registers a fixed TLS callback only during synchronous calls, and revokes both
callback and output addresses before returning. No application callback or
enclave-private slice is exported. Identity is private resource-routing metadata,
not remotely attested authority.

Every operation validates the worker window, guards, page-lock event order and
exact retained-owner report. Export and cancel are followed by destruction of the
in-page owner and full-page zero readback before unlock/free. Only then can Rust
return a result-cleared receipt and commit a public digest. A later begin creates
a new retained owner; no weaker per-export clearing claim is inferred from a
status code. Failed cleanup never falls back to deleting the enclave as a
substitute for clearing. Unconfirmed OS deletion retains the native allocation.

The host's destructor is not itself proof of successful cleanup. A failed clear
or delete remains an error/retention observation. Fatal process termination and
forgetting the entire session remain outside destructor guarantees.

## Native campaign

Two complete campaigns passed on the existing Azure x86-64 Windows development
host. Each normal campaign made 178 enclave calls and created/deleted seven
resource owners, with zero retained resources or cleanup errors:

- Twenty SHA-256 digests checked against Python-hashlib-generated expectations,
  plus cancellation for every vector.
- Dropped and forgotten pending results block further work; parent destruction
  clears the retained page before actual OS deletion.
- Actual null-destination copy rejection, simulated lost completion after a real
  export, and a deliberately corrupted resource-identity receipt preserve the
  caller destination and quarantine the session.
- Explicit close and parent-only destructor teardown.

Separate startup controls reject after create, load and initialize, with complete
partial-resource deletion. A simulated OS-deletion failure reports one retained
instance, zero deletions and three failed cleanup attempts; it is not a cleanup
PASS. Three compiled broken host variants are rejected: early output commit,
reopening an abandoned result, and ignoring mismatched receipt fields. Expected
process exits are `0, 0, 0, 0, 0, 97, 97, 97`, with exact result/counter checks.

Native builds use MSVC `/O2 /W4 /WX /MT /guard:cf`, Rust 1.98.1 O2 panic=abort and
the existing signed image. The enclave image was neither rebuilt nor re-signed.

## Failure corrected during integration

The initial host required a newly allocated page to have a valid working-set
entry **before** `VirtualLock`. This rejected initialization with status 111.
Before locking, the relevant check is that the page is not already observed
locked by another owner. An invalid entry is not a residency observation and its
`Locked` union member must not be read. After locking, both Valid and Locked are
mandatory. The corrected helper follows that distinction; no post-lock residency
requirement was relaxed. Compiled O0/O2 truth-table tests reject both the original
overrestriction and an always-accept mutant. The original failed run and its
diagnostic executable are preserved separately from the corrected campaigns.

## Scope of verification

Six mocked-ABI Rust tests at O0/O2 cover exact native reports, clearing before
receipts, copy/lost-reply errors, retained cleanup responsibility and teardown
failure. A compiled mutant ignoring native report fields is rejected. The earlier
safe-model ownership/mutation tests and retained-worker tests remain passing.
Mocked ABI tests are not native OS evidence; actual OS runs are described above.

This remains fixed-public-vector research on a test-signing, Secure-Boot-disabled,
VBS/HVCI-enabled x86-64 host. It does not qualify production signing, Windows
AArch64, hostile-host residency attestation, arbitrary worker depth/runtime/TLS
copies, partial-copy semantics, or a confidential-input application API. Original
enclave signing warnings and dump limitations remain unchanged. Production strict
constructors still reject Unsupported. See [remaining release work](windows-v02450-remaining.md).
