# Portable ChaCha20-Poly1305: v0.31.1 development evidence

This is functional evidence for the portable AEAD leaf. It does not establish
machine-code timing, physical fault resistance, or independent verification.

## Independent answers

Run `python3 scripts/cryptography/check-chacha20poly1305-vectors.py --rust 1.90.0 --oracle --differential`
and repeat with `1.100.0`. Both passed using Python cryptography 50.0.1 as
an offline test oracle; it is not a Cargo dependency. In addition to the two
published RFC 8439 examples, 27 AAD lengths were crossed with 30 payload lengths.
These include empty inputs, every possible pad length, and values immediately
before, on and after a 64-byte payload block boundary. Three longer cases use
4,097 bytes of AAD, payload, or both. Keys, nonces and message bytes are
deterministic public test inputs.

On **each compiler**, the 813 records were sealed and opened in both buffer
layouts: 1,626 ciphertext/tag comparisons, 1,626 valid opens, and 26,016
wrong-tag rejections that checked unchanged destinations and cleared scratch.
Six additional negative controls change the key, nonce, AAD, plaintext,
ciphertext or tag of an otherwise parseable nonempty record. Each deliberately
wrong record must make the consumer fail. These are sampled comparisons, not a
proof for all inputs.

## Nonce, failure and buffer behavior

Run `cargo test --locked -p brynja-aead-chacha20poly1305` (also with
`--release`). The [interruption tests](../../crates/brynja-aead-chacha20poly1305/src/interruptions.rs)
exercise five checkpoints: before and after the payload transform, after
one-time-key derivation, after MAC framing, and immediately before destination
commit. Two operations × two layouts × two interruption types (error and
unwind) × five stages gives 40 cases. Each checks that the injection fired,
the destination stayed unchanged and scratch was cleared. Each interrupted
seal also checks that the next invocation is the last reserved nonce and
that the one after it is rejected. A separate test arms the payload checkpoint
and verifies that a bad tag never reaches it. The checkpoints exist only in
unit-test builds; they do not simulate physical faults or process aborts.

All six leaf unit tests, including the interruption sweep, also passed under
Miri and Linux x86-64 AddressSanitizer with leak detection. These runs used
the pinned `nightly-2026-09-11` (Rust revision `67eda617e`):

```sh
cargo +nightly-2026-09-11 miri test --locked --offline -p brynja-aead-chacha20poly1305 --lib
ASAN_OPTIONS=detect_leaks=1 RUSTFLAGS=-Zsanitizer=address cargo +nightly-2026-09-11 test --locked --offline -p brynja-aead-chacha20poly1305 --target x86_64-unknown-linux-gnu --lib
```

## What Kani proved

Run `CARGO_NET_OFFLINE=true cargo +1.90.0 kani -p brynja-aead-chacha20poly1305 --output-format terse --jobs 2`.
All three source-level harnesses passed with Kani 0.68.0 and CBMC 6.11.0:

| Property | Scope |
| --- | --- |
| Frame admission | For all pairs of 64-bit lengths, accept exactly when the payload fits counters 1 through 2³²−1 and the padded MAC transcript including its length fields fits the underlying MAC's 64-bit byte count. Compared against 128-bit arithmetic without allocation. |
| Nonce allocation | All 4-byte prefixes, starting counters and counts. A valid range produces its exact first nonce; the next is its successor or exhaustion, including repeated exhaustion for a single-element range. |
| Destination commit | Both layouts, arbitrary bytes, and lengths 0–4. A returning callback stages arbitrary bytes; success commits them, error preserves the original, and admitted scratch is cleared in both cases without touching the suffix. |

The last proof is bounded; it is not a proof of all message lengths, crypto
arithmetic, unwinding, or erasure of compiler copies. The nonce proof covers
one owner, not durable allocation by an application. For the earlier
primitive-level evidence see [ChaCha20](chacha20-development.md) and
[Poly1305](poly1305-portable.md). A linked-code review of this AEAD's path to
tag verification and cleanup remains separate.
