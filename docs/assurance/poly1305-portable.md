# Standalone Poly1305: v0.31.0 development evidence

This record covers the portable one-time MAC, not ChaCha20-Poly1305, a CPU
backend, or an independently verified implementation. RFC answers and
independent differential tests check complete messages. The proofs and
linked inspection answer narrower questions.

## Field arithmetic

From the repository root, run:

```sh
CARGO_NET_OFFLINE=true cargo +1.90.0 kani -p brynja-mac-poly1305 --output-format terse --jobs 2
```

Kani 0.68.0 (CBMC 6.11.0) passed all five [harnesses](../../crates/brynja-mac-poly1305/src/field/proofs.rs),
each with unwind bound 18. They call the field routines used by the crate:

| Property | Domain checked |
| --- | --- |
| Key clamping matches the wire-format masks | Every 16-byte multiplier input |
| Block arithmetic fits and returns normalized limbs | Every normalized five-limb accumulator, key, block and full-block flag |
| Products land in the right column with coefficient 1 or 5 | All 25 pairs of basis limbs in the bilinear product |
| Carry propagation preserves the value modulo 2¹³⁰−5 | Five independent columns below 2⁵⁸, compared with a separately encoded wide reference |
| Finalization reduces before adding the pad modulo 2¹²⁸ | Every normalized accumulator and every 16-byte pad |

These are source-level properties checked with Kani's bundled compiler. They
are not a proof of the streaming API, of every compiled binary, or of timing.

## Emitted tag comparison and clearing

Run `python3 scripts/cryptography/check-poly1305-linked.py` with both Rust
toolchains and LLVM disassembly tools installed. It builds an optimized Linux
x86-64 downstream consumer, checks that its wrapper calls the verifier, and
screens the verifier's normal-return instructions and six comparison/clearing
helpers against reviewed fingerprints. It replays 56 public answers plus an
altered-answer control on the same executable, checking its digest again
after execution. A changed instruction fingerprint requires review.

| Rust | Observed comparison | SHA-256 of replayed ELF |
| --- | --- | --- |
| 1.90.0 | Counted loop visits byte offsets 0 through 15 | `6a5084c9044b1cc5e5f959f4c69dfba130f12e432725c59c6c1e0508754badd7` |
| 1.100.0 | Sixteen unrolled byte comparisons | `bee1a0af3f81348eadeac495777fdd06ad1d2fba4b667b978768b50289c7b12d` |

Both accumulate XOR differences with OR and decide equality only after the
last byte. Normal return clears the difference byte, computed tag (16 bytes),
accumulator (40), tail (16) and original borrowed key storage (32) via the
volatile clearing backend on both match and mismatch.

Both builds also copied the 80-byte owner state on the stack when moving it
into the consuming verifier. Clearing the consumed owner does not establish
that its earlier stack location was cleared. The owner holds a reference to
the caller's key; this observation does not mean the caller's key buffer was
left uncleared. Do not rely on erasure of moved copies, registers or spills.
The screen does not cover exception landing pads, the timing of the whole
MAC, other targets, or physical side channels.

## Lifecycle and interoperability

- The public leaf tests exercise valid and rejected tags and caller unwind,
  observing the original borrowed key buffer after the owner is gone. The
  focused `key_storage_after_verify_and_unwind` test passed under Miri.
  The leaf unit and integration tests also passed under Linux x86-64 ASan
  with leak detection. These checks do not inspect dead stack storage.
- Run `python3 scripts/cryptography/test-poly1305-vectors.py --openssl --rust 1.100.0`
  to compare the public corpus against OpenSSL and the optimized Rust consumer.
  OpenSSL is a test oracle, not a crate dependency.
- Run `python3 scripts/cryptography/check-poly1305-packages.py` for direct,
  composition and façade archive imports at both Rust endpoints. Cortex-M is
  a compile check, not a native execution or target timing result.
