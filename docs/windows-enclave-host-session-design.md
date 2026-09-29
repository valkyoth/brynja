# Host session ownership model

Status: **v0.24.50 isolated research, not a shipping Windows adapter**. Windows
strict constructors remain unsupported. Production crypto, Linux behavior and
release gates are unchanged. This models the host side of the
[tested scoped wire protocol](windows-enclave-wire-results.md); it does not yet
load, own, terminate or delete a real enclave.

A separate [native host experiment](windows-enclave-native-host-design.md) now
binds a temporary copy of this unchanged model to an OS resource. That fixture
does not turn this model's constructor into a native or production API.

## Ownership and admission

The safe, `no_std` Rust fixture forbids unsafe code. A private-field `Session`
tracks one logical instance's namespace, monotonically advancing epoch and
Ready/Busy/Quarantined state. `prepare` borrows that session exclusively along
with caller-owned public input and, for explicit public export, a destination.
Neither the session nor its pending scope implements Send, Sync, Clone, Copy or
Debug. Callers cannot construct tokens, access staging, supply raw requests,
complete an exchange, change epochs or reset quarantine through its public API.

`Session::new` creates **only a model ledger**, not an OS resource or validated
enclave identity. The future native adapter must own the real instance and this
ledger together, deny access to diagnostic/raw entry points, and never recover an
uncertain call by creating a new ledger for the same instance. These obligations
are not proved merely by private fields in this model.

Input length above 1024 and exhausted epochs reject before a pending operation is
created. Dropping an unentered scope returns the ledger to Ready. Entering burns
the next epoch before transport and never rolls it back. Forgetting a scope keeps
Busy latched, including before entry. Dropping or unwinding an entered but
unconfirmed exchange quarantines. No Drop-based guarantee is claimed for abort.
This guard does not yet perform OS teardown or prove enclave-side cleanup.

## Responses and public output

The private bridge encodes the existing fixed-width request and validates each
copied offer: expected epoch, stable nonzero instance namespace, slot, exact phase,
reserved fields and permitted first-operation status. A second offer must retain
the same token. The bridge sends a second terminal attempt and accepts only spent
status 21. Raw token words remain public metadata, not authentication or an
unforgeable capability outside the Rust API.

Public digest bytes enter a separate ordinary host staging buffer. The caller's
destination is committed only after a complete successful export, the spent
response, and both inner and outer cleanup confirmations. Missing, partial or
duplicate staging rejects; malformed replies, premature/duplicate completion or
missing cleanup quarantine and leave the destination untouched. A confirmed
copy-out failure returns `Error::Copy` without committing and leaves the session
reusable, as does a completed cancellation. Ordinary request failures are not
silently recategorized as permanent backend failures.

The private completion arguments are placeholders for the future adapter's actual
native checks, **not caller-supplied proof or independently verified cleanup**.
Public staging is filled with zero at scope end for bookkeeping; this is not a
compiler-resistant secret-erasure promise. All inputs and output decisions are
public test data. `PublicInput::acknowledge` is a provenance assertion only and
must never be used to declassify confidential input.

## Reproducible local verification

Run from the repository root with Rust 1.98.1, Python and a native Rust linker:

```text
python3 scripts/cryptography/test-windows-enclave-host-session.py
```

The focused suite includes:

- Seven Rust lifecycle/protocol tests, including all lengths 0..1024, exhaustion,
  forgotten scopes, cancellation, copy failures, interrupted exchanges, unwind,
  replay, identity drift, partial/duplicate staging and transactional output.
- All 42 saved native call transcripts from `53ec2efe`, with their 189-source
  bindings and canonical records validated before replay. This is **local replay**,
  not fresh execution on Windows. Each trace is replayed at its recorded epoch;
  separate lifecycle tests cover persistent session reuse/quarantine.
- The actual unchanged enclave Rust worker connected to this model via an isolated
  in-process copy adapter. Twenty independent `hashlib` vectors cover export,
  cancellation and partial-copy failure (60 operations), plus one withheld outer
  cleanup confirmation. This executes both Rust protocol implementations, but
  mocks addresses, entropy, OS copies and the Windows boundary.
- Ten total Rust tests at optimization levels 0 and 2. Six separately compiled
  mutants bypass identity, epoch, spent status, cleanup, interrupted-call quarantine
  or deferred output commit; each must fail its targeted test at both levels.
- One positive downstream consumer and 24 actual compile failures for ownership,
  lifetimes, trait bounds, field privacy and private bridge operations. A mutated
  native source-hash record is rejected without editing the saved observation.

No manifest, dependency, reviewed enclave source or previous native record is
changed. The pair adapter is appended to a temporary copy for testing only.
The model and transport test sources are not published crate dependencies.

## Next integration boundary

A real host adapter must bind this state machine to one owned Windows instance,
retain live command/staging buffers across synchronous callbacks, validate actual
copy/guard/lock/clear results, and handle partial startup, errors and teardown
without releasing live resources. It must not recreate a healthy ledger after an
uncertain native call. Native tests of that binding are still required.

This does not resolve confidential attested ingress, persistent protected results,
exact-worker dump/runtime/TLS/caller-frame coverage, production signing, other
algorithm adapters or platform qualification. No Windows support claim is added.
