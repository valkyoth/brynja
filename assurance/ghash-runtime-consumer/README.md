# Packaged GHASH runtime acceptance

From the repository root, choose the command for the backend under test:

| Command | Execution environment |
| --- | --- |
| `python3 scripts/ghash/check-packaged-runtime.py` | Native Linux x86-64 PCLMUL; QEMU for the missing-instruction control |
| `python3 scripts/ghash/check-packaged-runtime.py --pmull linux` | AArch64 Linux under QEMU; PMULL masked in the absence control |
| `python3 scripts/ghash/check-packaged-runtime.py --rv64` | Linux RV64 under QEMU with explicit Zbc, Zbkc-only and AES-without-Zbc models |
| `python3 scripts/ghash/check-packaged-runtime.py --pmull macos` | Native Apple Silicon; PMULL masked in the absence control |

The runner compiles the same consumer against local Cargo archives through
both `brynja_crypto::ghash` and `brynja::crypto::ghash`, on Rust 1.90.0 and
1.100.0. The caller opts in to `ghash-runtime-execution`; even with that
feature, `Ghash::new` remains portable. `Mode::Require` must report the
requested target's actual backend or fail. `Mode::Prefer` may fall back on
absence, not on a failed startup check. The bad-answer control changes only
the runner's private unpacked copy. No user key material is required.

[route.rs](route.rs) checks the empty input, every prefix of a 32-byte
ciphertext/length fixture, and all 15 distinct intermediate `S` cases in
[NIST's AES-GCM worked examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf).
The runner reuses the literals from the hash-checked portable tests in the
unpacked archive. It does not compute a new expected result. There are five
distinct GHASH inputs for each AES width (examples 5 and 6 differ in tag
length, not in GHASH input or result).
Each accepted route must handle every two-chunk split, including an empty
update and an over-budget rejection between chunks. Partial final blocks
must fail without changing the output. On success only the typed secret
result is exposed; the test checks that clearing it erases the output and
that finalization cleared the workspace in either case.

These inputs are **already framed**. A raw GHASH result is not a digest, MAC
or GCM authentication decision. Use the [portable package fixture](../ghash-public-api/README.md)
for the full frozen NIST vector suite, no_std example and ownership checks.
QEMU checks are functional tests, not measurements of physical hardware or timing.

## First v0.28.3 pass (2026-11-24)

The three Linux commands above passed: 12 x86-64 configurations, 12 emulated
AArch64 configurations and 16 emulated RV64 configurations. Counts include
both entry points and compiler endpoints, and the negative controls; they
are not counts of physical machines. Each successful constructor path
checked 674 splits (561 across the short prefixes and 113 for Example 5).
The Linux runners also compiled the feature-enabled consumer library for
Cortex-M; they did not run it on the microcontroller. This pass did not
replay the expanded fixture on macOS or run a timing campaign.

## Full published-corpus replay (2026-11-24)

All four commands passed against the v0.28.2 crate sources with the updated
consumer. Each successful constructor path checked 1,872 two-chunk splits:
1,311 across the 15 published cases and 561 across the short prefixes.

| Execution | Configurations passed |
| --- | ---: |
| Native Linux x86-64, QEMU for instruction absence | 12 |
| QEMU Linux AArch64 | 12 |
| QEMU Linux RV64 | 16 |
| Native Apple M2 Pro, macOS 27.2.1 | 12 |

These 52 configurations include required-route rejection, permitted portable
fallback, and startup quarantine on both compiler endpoints and both crate
entry points. A rejected constructor was checked for the expected error and
unchanged workspace, not counted as executing vector arithmetic. Nothing in
this replay tests an AES-GCM implementation or resolves the ARM timing question.
