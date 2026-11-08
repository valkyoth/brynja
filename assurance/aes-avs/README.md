# AESAVS package-external block campaigns

These are verification fixtures, not a new public ECB/message API. The harness
imports the public AES types through the existing isolated consumer, whose
dependencies are byte-checked Cargo archives. No production module is included
or substituted. All keys and buffers here are public test data.

## Authoritative inputs

Retrieved 2026-11-07 from the
[NIST CAVP block-cipher page](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers):

- [aesmct.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmct.zip),
  SHA-256 `6a2a72c00b1daacb9a7d20ab92617d322fa1c5dee493968660990e3f4571426b`.
- [aesmmt.zip](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmmt.zip),
  SHA-256 `12d1616f7a713e807714055973f04efc402f46a14e3d81869717c7ace4ecbaf0`.

Only the six ECB response files are selected. Other mode families are outside
the raw block API. Normalization changes CRLF to LF and removes trailing blank
lines, leaving one final newline; fields and comments are unchanged. Runtime
checks are offline and verify these normalized SHA-256 values before compiling:

| File | SHA-256 |
| --- | --- |
| ECBMCT128.rsp | `1010757e10a0c7de7ab505e3d935b9e9496d4b4ba5a89dedffb49ce4a4acdc46` |
| ECBMCT192.rsp | `a1ad99e7848f6162fbd96d343acdb33a7676657776b09fca88fc54704bf1dabd` |
| ECBMCT256.rsp | `a70992b1d8a902e2ebf8d8233814b422cf5755f9bbccaffa7fcd2b1c5e02998f` |
| ECBMMT128.rsp | `de5e02b6ca8eaf4c260579c3c8d09d4b57045de359cd5145836dcb7164abb2bb` |
| ECBMMT192.rsp | `284cc490c2c0ae1c0fc5e9935b30ad2e229e4f595b43fb68828b62d42101783c` |
| ECBMMT256.rsp | `14cea8cfcba191b98cb9c8cbf03c57b82edc76164226a2cacd53810dd60115cb` |

## Exact campaign semantics

To independently re-derive the checked-in fixtures from locally retained
original downloads, run this optional offline check:

```sh
python3 scripts/aes/check-aes-avs-provenance.py --mct /path/to/aesmct.zip --mmt /path/to/aesmmt.zip
```

It verifies both original ZIP hashes above, reads exactly the selected response
members without extraction, applies the documented newline normalization and
compares both normalized hashes and checked-in bytes. Missing, duplicate,
symlinked, oversized or changed inputs fail. It downloads/writes nothing and is
not an extra release gate or a requirement for ordinary AESAVS executions.
The pins rely on the trusted repository; this is reproducibility, not a NIST
signature or protection against an attacker who can replace the policy itself.

[AESAVS sections 6.3 and 6.4.1](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf)
define the selected MMT and ECB MCT sequences. The ECB inner loop is exactly
1,000 operations per outer record (j = 0 through 999); the NIST download page's
generic intermediate-file description is not used to choose that bound.

- MCT: 100 records per direction and key width. Each operation's output becomes
  the next input. The next key is derived from the final output (128 bits),
  the last eight bytes of the penultimate output plus final output (192 bits),
  or both complete final outputs (256 bits), XORed with the previous key.
  Every generated next key/input and every final output must match the next
  published record; records are not independently reseeded. Decryption mirrors
  the recurrence with the inverse primitive.
- MMT: ten messages per direction and width, containing exactly one through
  ten independent blocks. The harness slices and compares every block without
  IV, padding or chaining. This tests repeated primitive use, not a mode API.
- Both ephemeral and cached key owners execute every case. MCT has 600 records
  and 1,200,000 block operations per compiler/import configuration. MMT has
  60 records and 330 reference blocks, each checked through both owners;
  encryption also checks the explicitly public output path.
- All owned key/schedule and secret-output destinations are checked for
  clearing. Caller-created test copies are not claimed erased.

The parser requires exact section/field order, numbering, key and message
lengths, both directions and full populations. Negative tests remove every
mandatory line and reject malformed/extra records. Independent harness tests
check iteration counts, penultimate-output selection, all key-update widths,
and rejection of changed outputs, next keys, next inputs and direction flags.

## Explicit execution

Run one registration at a time:

```sh
brynja-verify run aes avs-msrv-direct
brynja-verify run aes avs-msrv-facade
brynja-verify run aes avs-current-direct
brynja-verify run aes avs-current-facade
```

The underlying command is
`python3 scripts/aes/check-aes-avs.py --toolchain 1.99.1 --route direct`.
Supported compilers are 1.90.0 and 1.99.1; routes are direct and facade.
Each runs exactly twelve tests in release mode, with six exact campaign
population markers. Fixture integrity and runner negative controls run in
the existing registry regression suite; the full crypto campaigns do not
run implicitly there or get added to the finite publication gate.

These sample campaigns do not establish CAVP validation, timing properties,
side-channel qualification, physical fault resistance or completeness over
all possible keys/blocks. Missing qualification remains tracked separately.
