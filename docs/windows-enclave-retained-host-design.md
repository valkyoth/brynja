# Affine retained-result host model

Status: isolated safe-Rust component, **not a native Windows adapter or a shipping
strict API**. It complements the [native retained-owner experiment](windows-enclave-retained-worker-results.md).
A separate private research adapter now connects this model to that image;
see [native host observations](windows-enclave-retained-native-host-results.md). Windows strict
constructors remain unsupported. No release-gate policy changes are involved.

`assurance/windows-enclave-probe/retained_host.rs` owns its private transport by
value in a `Session`. A `Pending` result exclusively borrows that session, so a
caller cannot close, move or reuse the owner while using its result. Neither type
implements Send, Sync, Copy, Clone or Debug. There is no public resource pointer,
token constructor, completion callback or secret-buffer view.

## Lifecycle

| Operation | Successful transition | Rejection or abandonment |
| --- | --- | --- |
| Begin one of twenty fixed public vectors | Ready to Busy | Quarantined before transport entry; generation overflow never enters it |
| Consume by explicit public export | Busy to Ready | Output unchanged; session quarantined |
| Consume by cancellation | Busy to Ready | Session quarantined |
| Drop a pending result | Busy to Quarantined | No foreign call in this destructor |
| Forget a pending result | Remains Busy | No new computation; parent still owns the transport |
| Explicit close or session destructor | Closed only after a valid release receipt | Quarantined; adapter must retain unconfirmed native resources |

Every accepted receipt matches the session identity, monotonic generation,
operation, worker clearing, result clearing and deletion status. These checks
detect mismatched reports; they cannot establish that an adapter told the truth.
The private native adapter must derive each field from actual validated native
operations. In particular, a destructor running is not a deletion receipt.

Public export stages bytes privately and copies to the caller only after receipt
validation. The staging buffer is for fixed **public** digests. Its ordinary Rust
fill-on-drop is not a compiler-resistant secret-erasure guarantee. This model
accepts a bounded vector selector, not arbitrary application data or a provenance
assertion. It must not be repurposed as a confidential-result export API.

Dropping a pending result does not invoke cancellation during caller unwinding.
The parent remains quarantined until close/destruction; the adapter must keep
retained storage protected throughout that interval. Forgetting the whole session,
process termination and fatal abort bypass destruction and do not promise cleanup.
The private adapter's release operation must never unwind, must allow safe retries,
and must not free callback/resource storage while OS deletion is unconfirmed.
Those adapter requirements are not guarantees proved by the synthetic driver;
the separate native experiment covers only its stated fixed-vector paths.

## Focused verification

Run:

```text
python3 scripts/cryptography/test-windows-enclave-retained-host.py
```

Seven Rust tests pass at O0 and O2: ownership through export/cancel, dropped and
forgotten results, all six receipt fields across four outcomes, partial-output
errors, transport/caller unwind, failed-release retention and retry, vector bounds
and generation exhaustion. Four compiled mutants fail at both optimization
levels: early output commit, reopening an abandoned result, ignoring receipt
fields and falsely claiming successful close.

A positive downstream consumer compiles, while 23 ownership/forgery consumers are
rejected with their expected compiler diagnostics. A separate mutation removes
the thread marker and confirms Send/Sync consumers then compile with a plain
Send+Sync synthetic driver. Thus the mock's own thread affinity is not accidentally
providing the tested restriction.

The build helper also cross-compiles an x86-64 Windows MSVC rlib and records source,
generated-source and archive hashes. It explicitly records `synthetic_transport:
true`, `native_executed: false` and `strict_qualified: false`. This is compilation,
not a Windows execution or cleanup result. Native builds must not include
`retained_host_fixture.rs`, which exists only for downstream compilation tests.

## Next integration

The private resource-owning adapter now checks native cleanup reports before
producing receipts and has a bounded native lifecycle campaign. Extend this
fixed-vector protocol to borrowed inputs and in-enclave result composition,
including integrated partial-copy and stale/cross-instance protocol controls.
See the
[remaining release work](windows-v02450-remaining.md).
