# AES-256 NIST single-block KAT fixtures

Source: [NIST CAVP block-cipher vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers),
[KAT_AES.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip),
retrieved 2026-11-05. Archive SHA-256:

`a203b16c9246b2ebae31dee5de21a606be80cf78ceabaca37150236fa098eb60`

GFSbox, KeySbox, VarKey and VarTxt contain 5, 16, 256, 128 records per direction,
respectively: 810 records including ENCRYPT and DECRYPT. Each record is
applied to the single-block primitive, with both ephemeral and cached owners.
This is not an ECB message API, CAVP validation or a full AESAVS campaign.
MCT/MMT remain assigned to v0.27.2. Tests never download these fixtures.

Only CRLF-to-LF and trailing blank-line normalization were applied; fields and
comments are retained, with one final newline. Normalized SHA-256:

| File | SHA-256 |
| --- | --- |
| ECBGFSbox256.rsp | 6669478d69cd45d4f64549bb3c78389a0fb01eae149d804a8cccc9713ea0d511 |
| ECBKeySbox256.rsp | 323077de259a06dcb2abf389d4e60cd3399d8608e6253504b103a4ce68b08171 |
| ECBVarKey256.rsp | ae2de0c7f11b8d52867db67a17521e8ef9eaa047febe22339ececb2d02c15329 |
| ECBVarTxt256.rsp | 6541ad108a78256d6ddefe34283c3037112f893626daf7acfab9cca278196c1c |

Registry regressions pin each hash and package inclusion; the Rust parser checks
exact section order, record counts, numbering, field order and byte widths.
Negative controls reject truncated, duplicated, extended and malformed data.
