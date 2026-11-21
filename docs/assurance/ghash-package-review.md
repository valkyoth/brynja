# v0.28.1 GHASH package review disposition

The independent review covered v0.28.0 through candidate
`3af01b6ee05a96ca0633af71cc6ce0e235c9c076` and reported no Critical or High
finding. The following dispositions distinguish fixes in the review follow-up
from limitations already accepted for raw GHASH. They are not a review of the
follow-up commit or approval to tag it.

| Finding | Disposition |
| --- | --- |
| Zero hash subkey | Accepted for raw GHASH: zero is a valid field element. Rejecting it would change the primitive without establishing that a caller derived the right key. A future GCM implementation must propagate AES key-derivation errors rather than substituting zero. |
| Compiler output on embedded targets | Closed the missing MSRV comparison. The [assembly screen](ghash-portable-screen.md#reproduction) now checks the inlined update on Cortex-M, RV32 and Android AArch64 for Rust 1.90.0 and 1.100.0. These are compile-only observations, not runtime timing or downstream linked-code guarantees. |
| Residual subkey material | Accepted limitation: clearing the caller's workspace does not clear every register, spill or dump. Treat the hash subkey as key-equivalent and apply the deployment's key-lifetime and memory-disclosure controls. |
| Inexact package test counts | Fixed. Each consumer invocation must report exactly one successful suite of the expected size, with no failed, ignored, measured or filtered tests. The same check covers the README and all-features run. |
| Environment checks on expected Cargo failures | Fixed in the shared package runner. Validate the Cargo environment before starting positive **and** negative probes; a setup failure is not an expected Rust diagnostic. The check applies to both GHASH and HKDF consumers. |
| SBOM changes unrelated to dependencies | Fixed. The existing generator preserves SPDX graph semantics while producing deterministic ordering, creation time and namespace. Two consecutive writes on the same inputs produced identical bytes. |
| Raw primitive misuse and GCM policy | Accepted scope boundary. Raw GHASH does not authenticate messages. GCM framing, length limits, nonce/key-reuse policy, tag masking and constant-time tag verification belong to the GCM layer. |

## Reproducing the follow-up checks

- Run `brynja-verify run ghash --needed` to refresh changed checks without
  repeating unrelated measurements. The archive consumer exercises both the
  direct and facade routes on both Rust endpoints.
- Run `python3 scripts/ghash/test-packaged-api.py` and
  `python3 scripts/ghash/test-portable-host.py` for the checker regressions.
- Run `python3 scripts/release/test-scoped-release.py` for the SBOM regression.
  To reproduce the document, run `scripts/release/generate-sbom.sh --write`.
  By default the creation time comes from the last visible commit touching
  `Cargo.lock`, not the time of the build. Set `SOURCE_DATE_EPOCH` explicitly
  for an uncommitted lockfile, shallow clone or exported source tree.
  `--check` still compares dependency content, not generator UUIDs or timestamps.

No production code, dependency, public API, or release gate changed in this
follow-up.

## Working-tree retest (2026-11-21)

The reviewer reproduced all six cross-target assembly fingerprints, confirmed
the four fixes above, and reported no new security issue. This was a review of
uncommitted changes based on `3af01b6e`, not an attestation for a later commit.
The reviewer did not run the full archive consumer replay. It was run locally
after the retest: both the direct crate and facade passed on Rust 1.90.0 and
1.100.0. All six cross-target assembly checks also reproduced locally.

The raw zero-subkey and register/spill dispositions stand. The planned
[AES-GCM requirement BRY-REQ-CRYPTO-0007](../../requirements/domains/cryptography.toml)
now explicitly requires an injected derivation-failure test at v0.29.0; it does
not claim that GCM or that test exists today. The SBOM timestamp is a
reproducibility input, not evidence of when the graph was verified. The existing
`sbom` and `release-regressions` checks cover that tooling; it is deliberately
not an input to GHASH verification. No additional release gate is needed.
