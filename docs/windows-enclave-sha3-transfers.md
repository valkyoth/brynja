# Saved scalar SHA-3 transfer and output helpers

This implementation-author review extends the
[state review](windows-enclave-sha3-state.md) for the same saved scalar SHA-3
development image. It covers ten emitted copy, bit-transfer, mask, predicate,
typed-output and public-integer encoding helpers. No production code, native
image or release-gate policy changed. This is not whole-image qualification or
an independent retest.

The [observation](../assurance/windows-protection-observations/sha3-transfers-review-20261005.json)
binds reviewer sources and matching Linux/Windows reports. The
[specification](../assurance/windows-protection-observations/sha3-transfers-20261005.json)
pins complete instruction bodies, relocations and frames. Semantic landmarks,
separate boundary models and connection regressions supplement those pins;
they are not a general machine-code correctness proof.

## Copy and bit helpers

The copy wrapper rejects unequal slice lengths before writing. Its leaf copies
complete eight-byte chunks, then remaining bytes, without reading past the
admitted extent. The saved private compiler ABI specializes lengths to
`[0,1025)`. The review covers that specialization, not arbitrary calls into a
private symbol or overlapping forged borrows.

The XOR wrapper rejects an empty bit range or either public offset exceeding
`8-count`. Its saved private ABI already restricts count and destination offset
to `[0,9)`; these compiler preconditions are checked explicitly. The leaf reads
one source byte, extracts the range and XORs it into the distinct destination
borrow. The fifth stack argument and outgoing mask are public metadata, not
secret spills. Masking modifies only the borrowed byte; the predicate returns
the intentionally requested boolean.

The four opaque leaves clear their secret working registers: copy clears
EAX/ECX/EDX, XOR EAX/ECX, mask EAX and predicate R10D. Pointer registers, public
metadata and the predicate result are not falsely described as erased. Saved
caller registers and earlier copies still need enclosing-window reclamation.

## Typed output and integer encoding

The output helper publishes a region only when its initialized length exactly
matches its capacity. An incomplete region is cleared before returning an error;
an absent optional output remains absent. Successful publication transfers the
region to its clearing owner rather than immediately erasing the result. This
analysis assumes valid Rust layouts and borrows, not attacker-forged pointers.

The integer helper is the emitted **left-encode** specialization for public
u128 lengths. It skips leading zero bytes while retaining one byte for zero,
prefixes the encoded width and initializes the entire 258-byte result, including
unused bytes and the internal length field. Its temporary public-length stack
storage is not claimed to be a secret owner. Actual `memcpy`/`memset` destinations
are bound to the previously reviewed memory-runtime bodies.

All ten helpers are reached from reproduced owner/state call edges in the same
image. Fixed frames and complete outgoing references are checked. Along the
selected rehash-to-fixed-finalizer path, XOR leaf entry reaches `H-8392` and copy
leaf entry `H-8376`, where `H` is the protected window's high address. Selected
argument/save slots lie inside that window, but these values are not maximum
whole-image depth. Prefix/sponge callees and other paths remain to be reconciled.

## Reproduction and results

```sh
python3 scripts/cryptography/test-windows-enclave-sha3-transfers.py
python3 scripts/cryptography/windows_enclave_sha3_transfers.py \
  release-reports/windows-local-20261004 --mutate
cargo +1.98.1 test --locked --offline -p brynja-core --lib secret_memory
cargo +1.98.1 test --locked --offline -p brynja-hash-sha3 --lib sp800185
python3 scripts/cryptography/test-windows-enclave-sha3-stream.py
```

Nine focused tests pass on each host; each rejects 756 actual body-byte
mutations. Tests additionally remove semantic landmarks and erasures, alter
relocations/call targets/frames, and exercise copy extents, all byte values and
public bit ranges, incomplete output and u128 encoding boundaries. Parsed
reports match and are saved outside Cargo target directories under
`release-reports/windows-worker-review-20261005/offline/`.

Seven core helper tests and four SP 800-185 tests pass on Linux. The ordinary-
process worker campaign passes seven component tests, one placement test, ten
compiled mutants, 628 cSHAKE, 76 NIST, 96 hashlib and 512 retained-rehash cases,
plus streamed setup. This is not a new native enclave run. Transitive prefix,
sponge and permutation semantics, arbitrary exception cleanup and other worker
families remain outside this review; see the
[remaining checklist](windows-v02450-remaining.md).
