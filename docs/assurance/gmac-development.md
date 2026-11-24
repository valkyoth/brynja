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
| `brynja-verify run gmac public-consumer` | Standalone, locked path consumer on Rust 1.90.0 and 1.100.0. Direct and facade builds separately generate and verify, reject wrong tag widths at compile time, and show that GMAC alone does not expose raw AES, GHASH or AES-GCM. Cortex-M is compile-only. |
| `brynja-verify run gmac nist-aad-only` | Full applicable AAD-only subset of the pinned NIST GCMVS archive on both host compiler endpoints and both import routes. |
| `brynja-verify run gmac boundary-differential` | Compare public generation and verification with an offline Go standard-library oracle. Go is a test tool, not a crate dependency. |

For the last check, place the NIST archive from the
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
