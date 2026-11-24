# v0.29.0 — portable AES-GCM development

The default-off `aes-gcm` feature exposes allocation-free detached seal/open
through `brynja_crypto::aes_gcm` or `brynja::crypto::aes_gcm`. It does not
enable either public hazmat feature or select a hardware backend. This is a
development API, not release qualification.

1. **Framing (private, under test).** Validate byte-to-bit conversions and
   the message limit before processing. Use the 96-bit IV fast path or derive
   J0 via GHASH for other nonempty IVs. Increment only the low counter word;
   pad AAD and ciphertext independently before hashing their original bit
   lengths. Replay with `brynja-verify run aes_gcm framing`. This check
   exercises the [SP 800-38D](https://doi.org/10.6028/NIST.SP.800-38D)
   construction and a published intermediate from
   [NIST's GCM examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf);
   it does not encrypt or verify a tag.
2. **Portable composition (private, full tags).** Portable AES-128/192/256
   expanded keys now drive H derivation, counter-mode encryption and tag
   masking. Open compares the full tag before processing any payload. Both
   directions use a disjoint caller-supplied staging buffer, cleared on exit
   after admission; the destination is committed only on success. Replay
   `brynja-verify run aes_gcm portable-composition` for NIST examples 1 and 5
   at all widths, an independently generated 64-bit IV case, all 128 single
   tag-bit changes, input tampering and injected block errors.
3. **Key owner and buffers.** The default sender consumes an externally
   reserved range of deterministic 96-bit IVs. A separate constructor takes
   a key-wide reservation for general or mixed IV lengths (see below).
   Invalid buffer lengths consume nothing. Once a keyed
   operation begins its nonce is spent, even on error or unwind; exhausting
   the range stops sealing but does not stop opening. The owner fixes its tag
   length at construction: 12, 13, 14, 15 or 16 bytes. The restricted 4- and
   8-byte profiles are not enabled. Both exact in-place and disjoint calls use
   separate scratch; a rejected tag leaves the original ciphertext untouched.
   Replay with `brynja-verify run aes_gcm owner-policy`.
4. **External consumer.** `Aes128Gcm`, `Aes192Gcm` and `Aes256Gcm`
   borrow 176-, 208- and 240-byte schedule buffers respectively. Use
   the appropriate range constructor to send or `for_open` to receive without any
   reservation. Both forms authenticate before releasing plaintext.
   `brynja-verify run aes_gcm public-consumer` tests the path dependencies
   through each route separately on Rust 1.90.0 and 1.100.0. It runs host
   known-answer and buffer tests, rejects aliasing and public raw imports,
   and compiles the consumer for Cortex-M (no target execution).
5. **Archive acceptance.** `brynja-verify run aes_gcm packaged-public-api`
   independently builds both public routes from unpacked Cargo archives at
   both compiler endpoints. All [18 NIST worked examples](../../assurance/aes-gcm-consumer/README.md#worked-example-fixture)
   compare generated ciphertext and tags to published bytes, open valid
   ciphertext, and reject an altered tag without changing it. All examples
   use 96-bit IVs. Three additional independent fixtures exercise public
   sealing and opening with 8-, 16- and 60-byte IVs.
6. **Failure atomicity (bounded proof).** Both seal and open use the same
   [caller-output write](../../crates/brynja-crypto/src/aes_gcm/portable/transaction.rs).
   The computation gets read-only input and separate writable scratch. A length
   mismatch rejects before it runs; an error discards its result without writing
   the destination. Only success copies the staged bytes. This is a contract
   about what the caller sees on return, not crash-atomic memory.
   Replay with `brynja-verify run aes_gcm transaction-proof`. Two Kani
   [harnesses](../../assurance/aes-gcm-transaction/src/lib.rs) compile that
   production function. They cover both layouts, independently sized buffers
   from 0 through 17 bytes, arbitrary initial and staged bytes, both callback
   outcomes and unchanged bytes outside the destination slice. Seventeen bytes
   includes a partial second AES block. The proof assumes valid Rust borrows
   and models the callback's result, not the correctness of authentication.
   As a negative control, copying scratch before checking the callback result
   in an isolated copy failed the unchanged-destination assertion in both
   harnesses; the production source was not modified by that experiment.
   Larger lengths, scratch clearing and unwind behavior are not formally proved;
   the owner and composition tests separately exercise real errors and unwinds.
7. **NIST GCMVS response files.** On both Rust 1.90.0 and 1.100.0, the
   direct portable public API matched all 33,750 applicable cases: 16,875
   seals, 8,371 successful opens and 8,504 required authentication failures.
   Each rejection preserved the in-place ciphertext. The campaign checks
   the generated IV, ciphertext and detached tag on seal, plaintext on open,
   and cleared scratch. The six files cover all three AES key sizes, 1-, 12-
   and 128-byte IVs and all five admitted tag lengths. The 13,500 cases with
   4- or 8-byte tags are counted separately, not treated as passes. These
   are functional test results, not CAVP validation or timing qualification.

   **Replay:** download the [original GCM ZIP](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip)
   from [NIST's block-mode vector catalog](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/cavp-testing-block-cipher-modes)
   to `references/local/gcmtestvectors.zip`, then run
   `brynja-verify run aes_gcm nist-gcmvs`. The runner is offline, checks
   SHA-256 `f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023`
   before reading members, and fails if the archive is missing or has changed.
   The public fixtures are reproduced with one-message reservations, not by
   exposing an arbitrary-IV sender API.
8. **Generated boundary differential.** Replay with
   `brynja-verify run aes_gcm boundary-differential`. The standalone
   [Go standard-library oracle](../../assurance/aes-gcm-oracle/boundaries.go)
   generated 11,025 distinct public messages; the runner checks a pinned
   transcript digest before replay. For each key and tag width it crosses all
   AAD and plaintext lengths 0–17, 31–33, 63–65 and 255–257 bytes, and pairs
   4095, 4096 and 4097 bytes with a one-byte opposite field in both orders.
   IV sizes rotate through 1, 3, 4, 5, 8, 11, 12, 13, 15, 16, 17, 128 and
   129 bytes. Expected short tags are prefixes of Go's full authentication tag.
   Each message exercises seal, valid open and a modified input (IV, AAD,
   ciphertext or tag) in **both** buffer layouts. On each Rust endpoint this
   produced 22,050 matching seals, 22,050 matching opens and 22,050 expected
   rejections with unchanged destinations. Go is a host test tool only;
   replay needs neither a network download nor a production dependency.
   Maximum lengths are tested by the framing admission checks, not by allocating
   maximum-sized messages. No target timing was measured.

### Review handoff

[`BRY-REQ-CRYPTO-0007`](../../requirements/domains/cryptography.toml) maps to
the shared subkey derivation and to the [positive and negative composition
tests](../../crates/brynja-crypto/src/aes_gcm/portable/tests.rs). The negative
test injects an error on the first AES call (encrypting the zero input).
For seal and open it requires the AES error, zero GHASH starts, cleared scratch
and an unchanged destination. A test-only counter in the real GHASH constructor
observes one start with a healthy 96-bit IV operation and two with a general
IV (IV hashing and message authentication). Replay with
`brynja-verify run aes_gcm portable-composition`.

### Candidate pentest disposition

The two reviews of `v0.28.3..58ccda55` reported no Critical or High
findings. One identified a new receive-side profile mismatch: a default
96-bit owner could authenticate a valid record from a different IV-width
profile. This was an admission problem, not an authentication bypass.
Both open methods now take `&[u8; IV_BYTES]`, on send-capable and receive-only
owners alike. A receiver for a general IV must name that width; a zero-width
receiver cannot be constructed. The [consumer regressions](../../assurance/aes-gcm-consumer/src/lib.rs)
reject wrong-width calls at compile time; the positive fixtures and corpus
replays still open valid general-IV records.

The other findings do not call for a new release gate:

- A shorter tag already requires an explicit type argument. Keep the 16-byte
  default; provisioning must enforce one tag width across all imports of the
  same key. A Cargo feature would not enforce that cross-owner invariant.
- Portable timing is unqualified; Cortex-M evidence is compile-only. The AEAD
  feature does not expose the raw primitives. Neither review reported a new
  timing observation.
- Bound attacker-controlled AAD and ciphertext before allocating or calling
  the primitive. Choose a protocol IV width that fits the stack; a large
  width reserves space in the owner. A universal 64-byte cap would exclude
  the 128-byte IVs in the checked NIST corpus. One coordinated reservation
  policy per raw key remains the application's responsibility.
- The reported strict dependency Clippy warnings are in unchanged hash crates;
  the changed crate is checked separately with warnings denied.

The [candidate release notes](../../release-notes/RELEASE_NOTES_0.29.0.md)
reflect the change. Scoped retest, final gate and GitHub checks remain pending.

### What the application must preserve

Before constructing a sender, atomically reserve a non-overlapping interval
in durable storage under the selected key policy. Persist the reservation **before**
using any IV. After a crash, abandon the unused part. A restarted process, a
fork or a restored VM must not resume a duplicated reservation: allocate a
fresh disjoint range, or rotate the key if the allocation history is uncertain.
A crate-local counter cannot detect a second import of the same key.

Use one tag length for a given key across imports, devices and directions.
For a key dedicated to deterministic 96-bit IVs, the original
`from_reserved_range` constructor retains its 32-bit context and 64-bit
counter. For a key with other or mixed IV lengths, use
`from_reserved_invocations` **for all its senders**, including 96-bit ones.
Use one durable allocator per raw key for the inclusive number space
`0..=u32::MAX` (at most 2^32 seals total, not per prefix or device).
Count burned and abandoned reservations against it; rotate on exhaustion.
Do not switch profiles on an existing key with unknown usage.

The second const parameter is the IV length in bytes (the first is the tag
length). For 12-byte IVs the layout stays 4+8; otherwise the trailing
`min(IV_BYTES, 4)` bytes encode the invocation number in big-endian order.
The caller supplies exactly the preceding fixed bytes, unique per sending
context for that length and key. For IVs of four bytes or fewer there is no
prefix: use a single context; the shorter field must fit the whole reservation.
Neither profile accepts per-message arbitrary IVs. Both open methods take a
reference to an array of the owner's exact IV width. A wire decoder should
convert a slice to that array reference before allocating message buffers.
Opening does not provide replay protection. See [SP 800-38D §§8.2.1–8.3](https://doi.org/10.6028/NIST.SP.800-38D).
Archive acceptance is separate from release approval. Nothing has been published.

## AArch64 timing stop rule

The [existing PMULL discussion](https://github.com/valkyoth/brynja/discussions/4)
tracks an unresolved GHASH observation, not a result for AES-GCM. If a new
timing campaign alarms, retain the original result, configuration, artifact
identity and public replay instructions. Link that discussion for a repeat;
for a distinct observation, post a reproducible, public-data-only summary
and link it here. Do not change thresholds or repeatedly rerun to get a pass.
No new GCM timing observation has been made in this step.

An inconclusive timing result leaves the affected target/profile unqualified;
unaffected portable work may proceed. A reproducible secret-dependent leak,
wrong ciphertext/tag, or release of unauthenticated plaintext is not cleared
by a discussion post: withhold the affected path until resolved.
