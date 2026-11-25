# v0.29.1 — Portable GMAC

Enable `gmac` on either `brynja-crypto` or the `brynja` facade. The owner
authenticates the supplied bytes; it neither encrypts them nor returns a
ciphertext. Choose one tag width (12–16 bytes) per dedicated key, reserve
sending IVs before authenticating, and transmit the returned IV and tag.
Importing a wire tag as `GmacTag` is not verification: call `verify` with
the received IV, associated data and tag. Applications that need replay
protection have to track freshness separately.

### Repeat the checks

| Command | What it exercises |
| --- | --- |
| `brynja-verify run gmac portable-vectors` | Small public known-answer fixtures at every key width, altered IV/AAD/tag rejection, reserved-range exhaustion and schedule clearing. |
| `brynja-verify run gmac public-consumer` | Standalone, locked path consumer on Rust 1.90.0 and 1.100.0. Direct and facade builds separately generate and verify. Passing a 12-byte tag to an owner expecting 16 bytes is a compile-time error; unsupported widths are rejected at construction, not compilation. GMAC alone does not expose raw AES, GHASH or AES-GCM. Cortex-M is compile-only. |
| `brynja-verify run gmac nist-aad-only` | Full applicable AAD-only subset of the pinned NIST GCMVS archive on both host compiler endpoints and both import routes. |
| `brynja-verify run gmac boundary-differential` | Compare public generation and verification with an offline Go standard-library oracle. Go is a test tool, not a crate dependency. |

For `nist-aad-only`, place the NIST archive from the
[AES-GCM corpus instructions (item 7)](aes-gcm-development.md)
at `references/local/gcmtestvectors.zip` (SHA-256
`f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023`).
The runner validates the entire archive with the existing GCMVS parser, then
selects records with **both ciphertext and plaintext empty**. Checking only
plaintext would incorrectly admit failed decryption cases with ciphertext.
The replay calls only GMAC, with no GCM feature enabled.

The 6,750 distinct records comprise 3,375 tag generations, 1,657 valid
verifications and 1,718 required authentication rejections. They cover
AES-128/192/256, all five admitted tag widths, 1-, 12- and 128-byte IVs,
and the corpus's five AAD lengths (including empty). A generated IV must
match the published IV as well as the tag. The runner checks that an incorrect
expected tag and a rejection mislabeled as a success each fail replay.
The four builds repeat the same records; they are not four distinct corpora.

The independent boundary campaign crosses three key widths, five tag widths,
13 IV lengths (1, 3, 4, 5, 8, 11, 12, 13, 15, 16, 17, 128, 129 bytes) and
14 AAD lengths from empty through 4,097 bytes. For each of the 2,730 messages,
compare the issued IV and tag, accept the correct tag and reject a changed key,
IV, AAD or tag. Go recomputes the changed case to confirm that it must reject.
The runner pins the transcript and deliberately supplies a wrong expected
outcome for each operation. Near-maximum lengths are not allocated here:
the shared GCM framing and reservation checks cover arithmetic limits.

### Scoped review handoff

[`BRY-REQ-CRYPTO-0021`](../../requirements/domains/cryptography.toml) and
`algorithm.gmac` map the AAD-only specialization to the pinned SP 800-38D.
Review [the GMAC wrapper](../../crates/brynja-crypto/src/aes_gcm/portable/gmac.rs)
and the feature gates against `v0.29.0`. The existing GCM engine is reused
with no payload. Check that only reserved IVs can sign, receivers cannot sign,
verification consumes no reservation, and no raw block, hash or ciphertext
operation becomes public via `gmac` alone. Distinct types do not prevent someone
from reimporting the same key into multiple protocols or reusing an IV outside
this owner.

This is functional evidence, not NIST validation, machine-code timing
qualification or an acceleration claim. These builds use path dependencies;
the combined unpacked-package acceptance belongs to v0.29.2. Scoped pentest,
release preparation and the final gate are separate from these checks.

### Candidate pentest disposition

The two owner-supplied reviews of the portable GMAC candidate at `70f78f17`
reported no authentication bypass, nonce-reuse defect, or release-blocking
crate vulnerability. The supplied report's SHA-256 was
`366b75cc20a1cdc1639bc2ca9a2ef27173f33461e60d6aef9a9827b048fbeab9`.
The release baseline is the commit tagged `v0.29.0` (`a5e53ce4`).

- Prefer the default 96-bit IV. A different width already requires an explicit
  type argument. Its smaller counter space (only 256 values for a one-byte IV)
  and the general constructor's key-wide budget are real limits, not automatic
  coordination across senders. Keep the tested general-IV profile without
  another feature gate. This is not a validated deployment profile.
- Keep fallible constructor admission. The public regression tests distinguish
  tag-width and empty-IV errors and check clearing immediately after each
  failure. That is separate from the compile-time mismatch tested downstream.
- This milestone authenticates a contiguous AAD record, not a stream of
  fields. Use the protocol's canonical, unambiguous encoding. Simply joining
  variable-width fields would authenticate ("ab", "c") and ("a", "bc") alike.
- Use separate keys for GMAC and GCM. If the protocol uses HKDF to derive
  them from one master secret, use distinct, protocol- and purpose-specific
  info labels. Neither the tag type nor a local counter can enforce separation
  across raw-key imports. Persist reservations before use and abandon unused
  IVs after a crash; a remaining-count accessor would not make restart safe.
- Clearing depends on Drop running. Forgotten owners and process aborts are
  outside the guarantee, as are registers, spills and dumps. Streaming, error
  formatting and reservation introspection are not required for this scope.

No production behavior or public signature changed in this disposition.
For the subsequent packaged-consumer acceptance, see the
[v0.29.2 fixture](../../assurance/aead-portable-acceptance/README.md).
This v0.29.1 review is not release or deployment certification.
