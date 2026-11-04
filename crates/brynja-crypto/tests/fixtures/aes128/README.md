# AES-128 NIST known-answer fixtures

Source: NIST CAVP [block-cipher test vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers),
[KAT_AES.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip),
retrieved 2026-11-03. Archive SHA-256:

`a203b16c9246b2ebae31dee5de21a606be80cf78ceabaca37150236fa098eb60`

Only the four AES-128 ECB KAT response files are retained. Each record supplies
one block to the primitive; this does not implement or endorse ECB message
encryption. Both ENCRYPT and DECRYPT sections are tested. Counts per direction:
GFSbox 7, KeySbox 21, VarKey 128, VarTxt 128 (568 records in total).

Imported files preserve all fields and comments. CRLF is normalized to LF and
trailing blank lines are removed, leaving one final newline. Normalized SHA-256:

| File | SHA-256 |
| --- | --- |
| ECBGFSbox128.rsp | 8fd29513660c25497cd7a491792b8d16bb209d1a176fa5294ec65d1e71db9b20 |
| ECBKeySbox128.rsp | 4e1f2d023fd7f1c23e9296c0ced224021c0dc83d6259099869e578daa54bbdec |
| ECBVarKey128.rsp | f2af24115a5e5e3b1e050b9652ca49d8027632f0c663fb1db89ba22bd3878b1f |
| ECBVarTxt128.rsp | 0f293b0d0b5958e67403b838f771f9bb78ed413bbce1ec62229331ca0a19b244 |

The registry tests pin these hashes and package inclusion. The Rust parser
requires the exact section, field order, record numbering and population;
negative controls reject missing or extra records and malformed fields. Ordinary
test runs use only the checked-in fixtures, with no downloads.

NIST explicitly distinguishes informal testing with these vectors from CAVP
validation. Passing this subset is not CAVP certification, a full AESAVS campaign,
mode validation, independent review or side-channel qualification.
