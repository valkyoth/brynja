# Saved SHA-NI engine and session review

This implementation-author review extends the
[state construction/consumption review](windows-enclave-sha-ni-state.md) for the
unchanged `sha2/mod.rs::open_sha_ni` development image. It does not add enclave
execution, independent cryptographic review or whole-image qualification.
The [observation](../assurance/windows-protection-observations/sha-ni-engine-review-20261005.json)
binds image, object, reviewer sources and both host reports; the
[inventory](../assurance/windows-protection-observations/sha-ni-engine-20261005.json)
pins eight complete bodies and their relocation populations.

## Engine normal paths

Update checks failed state, checked message length, authority health/generation
and narrow/wide identity before mutating input storage. It checks prospective
block accounting before starting its guarded copy loop. Each full block is
copied into the owned compression buffer before dispatch; successful compression
clears the schedule and block copy, checks/increments accounting, clears partial
input and resets its length. Message length is committed after the loop.
Authority failure and errors during guarded mutation wipe the workspace and
mark the engine failed. Pre-mutation length/work rejection is distinct from
those destructive failure paths.

Finalization checks the total bit length, updates the complete-byte prefix,
stages the partial-byte delimiter, and selects one or two padding blocks. Each
padding compression uses checked accounting and clears its schedule/block-copy
storage. Output is copied to the workspace staging region before the final
byte mask. The consuming state wrapper reviewed previously is responsible for
destruction on returned finalization errors; the engine alone does not promise
immediate erasure on every preflight rejection.

The emitted engine is shared with portable and wide paths. This review records
those references but does not qualify those callees for this image. The selected
SHA-NI route relies on the previously bound constructor supplying a non-null
session and a valid narrow initialized owner. Private compiler preconditions
are explicit: final-output length is in `[28,33)`, padding length in `[64,129)`,
and session state/block borrows cover 64/128 bytes. These ranges are not a claim
that arbitrary raw calls are valid. The outer state selects exactly 28 or 32
output bytes. Invariant-violation panic edges remain recorded and outside this
normal-return review; they are not erased from the call inventory.

## Startup test, dispatch and opaque kernel

The startup self-test stages only public IV, expected digest and `abc` block
data. Six readonly constants are checked in both the object and final image.
It calls the actual session compressor and compares all 64 state bytes with the
expected state, including the zero upper half in narrow mode. The previously
reviewed constructor handles rejection and authority quarantine.

Session entry checks health, generation and operation identity before dispatch.
All five dispatch-table destinations are rebound to the actual session body.
The successful SHA-NI route reaches the exact secret compressor, then clears
session scratch. The failed dispatch path clears scratch and quarantines its
authority. This is not a claim of live CPU migration monitoring or exception-
handler qualification.

The bound compressor uses the existing 256-byte SHA-256 round table, whose bytes
are checked in the object and linked image. Its opaque block uses no stack
access, expands the schedule within scratch, commits the narrow chaining state,
clears all 704 scratch bytes and clears its XMM0–3 and working general registers.
The surrounding prologue/epilogue saves and restores pointer registers. The
session's scratch wipe is separately bound, not inferred solely from the kernel.
The byte-mask adapter and its tail-called helper are also bound; the latter
clears its payload register after the store.

These observations do not erase caller-frame copies. Update saves XMM6, while
update/finalize temporarily spill length/accounting values. They depend on the
enclosing protected stack-window clearing, not individual writes in these
functions. Startup self-test arrays are public test data, not caller secrets.

## Selected stack geometry

The known rehash → constructor → startup-test → session path reaches
`H-13928` at the scratch clear helper, where `H` is the high address of the
64-KiB window. The selected rehash → state-finalize → engine-finalize → update
→ session → scratch-clear path reaches `H-8216`. Saved pointers, length spills,
XMM6 storage and public startup buffers fit the reviewed frames.

This is **not maximum whole-image depth**. Full owner/decoder paths, runtime
dispatch/SDK reconciliation, other families and indirect SIMD paths remain
separate obligations. Arbitrary exceptions, fatal abort and caller-created
secret copies are not newly covered.

## Reproduction and results

```sh
python3 scripts/cryptography/test-windows-enclave-sha-ni-engine.py
python3 scripts/cryptography/windows_enclave_sha_ni_engine.py \
  release-reports/windows-local-20261004 --mutate
cargo test --locked --offline -p brynja-hash-sha2 \
  --features hardened-execution --lib hardened_execution::engine
```

Ten reviewer regressions pass on Linux and Windows, with identical parsed
reports. All 2,903 actual body-byte and 20 dispatch-byte mutations are rejected
per host. These mutations enforce review identity and dispatch binding, not
independent cryptographic correctness. Tests also exercise semantic landmarks,
readonly constants, relocation populations, frame saves, compiler preconditions
and explicit residual claims. Five existing Rust engine tests pass on Linux,
including unwind cleanup, bounded copy, length/work exhaustion, invalid-buffer
cleanup and partial-bit padding/output checks.

Reports are retained outside Cargo target directories at
`release-reports/windows-worker-review-20261005/offline/sha-ni-engine-*.json`.
No production code, saved image or release-gate policy changed.
