# Native development image-admission results

Status: OBSERVATIONS_ONLY. The bounded x86-64 admission component and consumer
workflow are implemented and development-tested. Production signing success,
production-facade integration and production qualification are **not** established.
Windows strict constructors remain Unsupported.

## Source and artifacts

- Admission parser, policy build tool and native loader:
  `80a230943dca1147ade72c81faec4902c820c232`.
- Direct OS import-enforcement probe:
  `c710d9299fc1a98056ad358f32b65713aff57e64`.
- Image code baseline: `bce5cd2a9a76fb3908e421b0c8ed06d7b22de18e`, followed by
  the new reviewed import-policy transform and new development signing. It is
  **not** the old image, and older residency/dump evidence is not transferred.
- New signed main image SHA-256:
  `a939358b9abca529c2c59b02c8226bdaf6648629331a29937d53d771afd5b945`.

The [committed observation record](../assurance/windows-protection-observations/image-admission-80a23094.json)
binds the 175-file source closure, both build profiles, policy/artifact hashes,
native transcripts, controls and cleanup. Raw archive:
`release-reports/windows-azure-replacement-2026-09-29/admission-complete.tar`,
SHA-256 `7db7024d2f56e08007132d2deedbdfbb85a1ca28a98dfa370ab5f4f13e4d6825`.
It is saved locally outside `target/`, ignored by Git. A read-only implementation-
author review checked source against its commit, generated policies, binaries,
signed/unsigned image differences, raw outcomes, signing transcripts and cleanup.
This is not an independent retest.

## Native outcomes

All completed campaigns used the existing Azure Windows x86-64 development
configuration: VBS/HVCI running, test signing enabled, Secure Boot disabled.
Rust 1.98.1 cross-builds and native MSVC 17.14.41 links are recorded.

| Control | Repeated outcome |
| --- | --- |
| Reviewed image, development loader | Load, initialize, public-probe call and destruction succeeded |
| Same test-signed image, production loader | Rejected at trust stage 2, status -2146762487; no enclave loading or calls |
| Changed byte or old image/policy | Rejected at stage 1; no loading or calls |
| Production loader with trust rejection deliberately removed | It ran despite failed trust; result validator rejected this compiled mutant |
| Injected file-handle-close failure after rejected input | Fatal exit 3221226505, no false cleanup/success record; not an erasure claim |
| Proper Windows-author import identity | Direct OS control loaded and initialized successfully |
| Wrong import author identity | Loaded, then initialization rejected with error 1114; resource deleted |
| Impossible imported-library security version | Loaded, then initialization rejected with error 1114; resource deleted |

Both main admission campaigns and all three direct OS controls ran twice with
the same outcomes. The direct OS controls never called application enclave
operations. Their code bytes were identical; the unsigned author/security
variants differ only in the intended import identity/version field before
development signing. The old-image rejection includes a full-file hash mismatch;
the parser's specific import-policy rejection is separately covered by compiled
local tests, not inferred from that native hash rejection.

Two intermediate failures are retained rather than hidden:

- The first native build wrapper hit a directory-path error after linking the
  development executable. A corrected bounded wrapper linked the remaining
  variants cleanly; the failed wrapper was not counted as a passing build.
- The first OS negative control incorrectly expected rejection from loading
  alone. Actual rejection occurs at `InitializeEnclave` on this host. The revised
  capture records both stages and does not relabel successful loading as denial.

SignTool returned its VBS compatibility warning and exit 2 for development
signatures. These are not clean production-signing results. Temporary private
keys/certificates were removed. Cleanup recorded zero probe children and temporary
certificates, unchanged original image and no host-configuration change.

## Focused local verification

`python3 scripts/cryptography/test-windows-enclave-admission.py` passed:

- Four compiled Rust parser/policy tests at optimization levels 0 and 2: every
  byte of the synthetic artifact is hash-bound, all truncations reject, malformed
  offsets/configuration/imports reject, and 4,096 deterministic malformed-input
  mutations do not panic.
- Six compiled security mutants were rejected: hash comparison, identity
  comparison, import match kind, import author fields, debug policy and PE flags.
- Trusted-policy schema/profile/type rejection and native result-schema tests.

The existing file-pinning tests also passed. Script inventory, documentation
links, first-party cryptography policy and unsafe-source policy passed. These
focused checks are not a full release sweep or a new pentest.

## Handoff

The [consumer workflow](windows-enclave-image-admission.md) documents the trusted
policy boundary, VEIID/transform/sign order, separate build profiles, import
requirements and load/initialize sequence. Implementation can now move to
production owner/facade integration using that component. Production certificates,
successful production deployment, Windows AArch64, wider algorithms/acceleration
and final security/native qualification remain separate unfinished work. No
release-gate policy or publication scope changed.
