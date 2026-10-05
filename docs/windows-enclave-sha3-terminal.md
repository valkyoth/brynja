# Saved scalar cSHAKE terminal output

This implementation-author review extends the [finalization/squeezing review](windows-enclave-sha3-finalize.md)
with both rate-specific `squeeze_final_bits_secret_in_place` adapters in the
same saved Windows scalar SHA-3 development image. It is not a new native
enclave run, independent retest or whole-image qualification.

The [observation](../assurance/windows-protection-observations/sha3-terminal-review-20261005.json)
binds matching Linux/Windows reports. The [specification](../assurance/windows-protection-observations/sha3-terminal-20261005.json)
pins both 726-byte bodies, relocations and unwind frames. Actual owner-call
destinations distinguish the two adapters; complete helper-address checks bind
their typed squeezing, copy, mask, permutation and erasure calls to the saved
image. Pair normalization permits only the rate comparison and squeezer symbol
to differ. Exact-byte checks preserve inspected code identity; they are not a
general proof of machine-code correctness.

## Admission, publication and cleanup

An owner outside the squeezing phase returns `StateConsumed` without changing
its phase, clearing its state or touching the output destination. A valid
squeezing owner is marked vacated before any output work. Every subsequent
normal success/error path converges on owner wiping after restoring the frame.

Nonempty output is cleared before initializing its typed region. Checked
128-bit output accounting precedes the complete-byte squeeze. For a partial
final byte, the adapter validates the cursor, permutes at the rate boundary,
copies one byte into staging and masks unused high bits. Its permutation site
immediately clears the 40-, 40- and 200-byte scratch regions. The final write
checks initialized-length addition and capacity; successful writes and rejected
capacity checks clear all 168 staging bytes. Other failures rely on the enclosing
owner wipe for owned staging cleanup.

Publication requires the initialized extent to equal the entire destination
capacity. A failed admitted operation clears the destination again; a successful
operation transfers the initialized output to its typed owner rather than erasing
the returned value. Empty terminal output consumes/wipes the owner without
calling the complete-byte squeezer or touching a destination. A final fractional
byte adds no complete byte to the byte counter, and no later squeeze is allowed.

These private typed paths require valid exclusive borrows and canonical output
metadata supplied by the reviewed owner caller: empty output has width zero;
nonempty output has final width 1 through 8. The worker bounds output to 1024
bytes. The disposition model exercises those preconditions, counter boundaries,
injected inner errors and exact initialization. It does not simulate secret data,
execute the emitted instructions or admit arbitrary forged pointers/metadata.

## Frames and reproduction

Each adapter uses a 136-byte fixed frame, including eight pushed registers.
The selected owner path reaches `H-2912` at the adapter and `H-3088` at its
complete-byte squeezer. The 32-byte typed initialization lies at `H-2872`.
The owner-wipe tail call reuses the restored frame. These are selected extents,
not maximum whole-image depth. Caller register/spill copies still require
enclosing-window reclamation; arbitrary OS exceptions are not qualified here.

```sh
python3 scripts/cryptography/test-windows-enclave-sha3-terminal.py
python3 scripts/cryptography/windows_enclave_sha3_terminal.py \
  release-reports/windows-local-20261004 --mutate
cargo +1.98.1 test --locked --offline -p brynja-hash-sha3 --lib hardened::sponge
python3 scripts/cryptography/test-windows-enclave-sha3-stream.py
```

Nine focused review tests pass on each host, rejecting 1,452 actual body-byte
mutations each, plus changed relocations, cleanup sequences, helper destinations
and unwind frames. Parsed saved-image reports match. Nine actual Rust sponge
tests pass; the unchanged worker campaign passes seven component tests, one
placement test, ten compiled mutants, 628 cSHAKE, 76 NIST, 96 hashlib and 512
retained-rehash cases, plus streamed setup.

Streamed setup helper bodies, scalar permutation internals, deepest paths and
other distinct workers remain separate review work. No production code or
release-gate policy changed. See the [remaining checklist](windows-v02450-remaining.md).
