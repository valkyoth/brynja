# AES-192 NIST single-block KAT fixtures

Source: [NIST CAVP block-cipher vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers),
[KAT_AES.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip),
retrieved 2026-11-05. Archive SHA-256:

`a203b16c9246b2ebae31dee5de21a606be80cf78ceabaca37150236fa098eb60`

GFSbox, KeySbox, VarKey and VarTxt contain 6, 24, 192, 128 records per direction,
respectively: 700 records including ENCRYPT and DECRYPT. Each record is
applied to the single-block primitive, with both ephemeral and cached owners.
This is not an ECB message API, CAVP validation or a full AESAVS campaign.
MCT/MMT remain assigned to v0.27.2. Tests never download these fixtures.

Only CRLF-to-LF and trailing blank-line normalization were applied; fields and
comments are retained, with one final newline. Normalized SHA-256:

| File | SHA-256 |
| --- | --- |
| ECBGFSbox192.rsp | bee6349ecc3ab031db9b6effc3632f54ddd49287d27257693261972c35abb1db |
| ECBKeySbox192.rsp | 0e08371b787b8e1663f92c8941f4cb60d9afc558fd1f25c4b0e29e43772cfc38 |
| ECBVarKey192.rsp | 4d6a3d6f8e4e5d6745f37b0c41191e25f029c32810e69288919d7e85a081944a |
| ECBVarTxt192.rsp | a41f30d494e25a2a6618d4dfd0ca0b33fe563fe1efeb8529134ab602ac2d9a28 |

Registry regressions pin each hash and package inclusion; the Rust parser checks
exact section order, record counts, numbering, field order and byte widths.
Negative controls reject truncated, duplicated, extended and malformed data.
