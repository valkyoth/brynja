# Saved scalar cSHAKE prefix helpers

This implementation-author review extends the [state](windows-enclave-sha3-state.md)
and [transfer/output](windows-enclave-sha3-transfers.md) reviews for the same
saved scalar SHA-3 development image. It covers four emitted encoded-string and
bit-packer helpers, two each for cSHAKE128 and cSHAKE256. The two rate pairs have
identical opcode shapes but distinct sponge-update destinations. Incoming
constructor references disambiguate them; matching bytes alone is insufficient.

The [observation](../assurance/windows-protection-observations/sha3-prefix-review-20261005.json)
records matching Linux/Windows reports and source hashes. The
[specification](../assurance/windows-protection-observations/sha3-prefix-20261005.json)
binds every instruction byte, relocation and fixed frame. These pins accompany
manual control-flow inspection, semantic landmark regressions and bounded
behavior models; they are not a general machine-code proof.

## Framing, bit packing and failures

Each encoded-string helper submits `left_encode(bit_length)` before the complete
input bytes and optional one-to-seven-bit tail. Byte-aligned input uses one bulk
sponge update for each complete fragment; an unaligned pending byte uses the
bit packer instead. Complete-byte and partial-byte accesses check the supplied
slice extent. This private ABI assumes valid canonical Rust bit-string values
and borrows, not attacker-forged layouts.

The bit packer admits widths 1 through 8 and pending-bit counts below 8 before
touching the byte. Each iteration consumes the smaller of remaining input bits
and pending-byte capacity, through the previously reviewed secret XOR helper.
A full pending byte triggers one sponge update. The emitted-byte counter is
checked before that call and committed only after it succeeds. The pending byte
is then volatile-cleared and its used count reset.

On counter overflow or update rejection, the helper **does not itself clear**
the failed pending byte. It propagates the error to the previously reviewed
constructor, which clears the pending byte and active sponge. A string may also
have absorbed earlier fragments before a later error. This is not a transactional
helper or a promise that partial secret work never occurs; terminal construction
failure and enclosing cleanup are essential. Saved-register copies still rely
on protected-window reclamation. Arbitrary OS exception cleanup is not covered.

## Connections and selected stack paths

The constructor reaches both rate-specific string helpers; each reaches its
matching bit packer and 168- or 136-byte-rate update function. Every outgoing
reference is checked against the same saved image. Update bodies receive
identity-only bindings here: their sponge/permutation internals remain separate
review obligations.

The string helper's fixed frame is 360 bytes, including saved registers; the bit
helper's is 120 bytes. Its 258-byte encoded public length and pointer/bit-offset
slots are inside the protected window. On the selected rehash-constructor chain,
the string frame reaches `H-8112`, the bit frame `H-8240`, the encoder `H-8464`
and XOR leaf entry `H-8312`. These are selected paths, not maximum whole-image
depth; deeper sponge calls remain open.

## Reproduction

```sh
python3 scripts/cryptography/test-windows-enclave-sha3-prefix.py
python3 scripts/cryptography/windows_enclave_sha3_prefix.py \
  release-reports/windows-local-20261004 --mutate
cargo +1.98.1 test --locked --offline -p brynja-hash-sha3 --lib sp800185
python3 scripts/cryptography/test-windows-enclave-sha3-stream.py
```

Eight review tests pass on each host; each rejects 1,202 actual body-byte
mutations. Additional regressions remove semantic sequences, alter rate-specific
connections and frames, cover every byte/offset/valid-bit combination, and check
invalid admission, rejected flushes and counter boundaries. Parsed reports match
and are saved under `release-reports/windows-worker-review-20261005/offline/`,
outside Cargo target directories.

The four actual Rust prefix tests also pass, including failed and unwinding sink
cleanup, bulk absorption and independent bit-concatenation comparisons. The Linux
worker campaign passes seven component tests, one placement test, ten compiled
mutants, 628 cSHAKE, 76 NIST, 96 hashlib and 512 retained-rehash cases, plus streamed
setup. No new native enclave execution or independent retest is claimed. No
production code or release-gate policy changed. See the
[remaining checklist](windows-v02450-remaining.md).
