# Development enclave image-file pinning observations

Status: OBSERVATIONS_ONLY. This is a private fixture, not production image
admission. Windows strict sessions still return Unsupported. Signing remains
[consumer-managed](windows-enclave-deployment.md); no signing service was
provisioned or used in this experiment.

## Source and environment

The file-guard and runner source is commit
`48197d67adb092fece961d09a0854dd559023e01`. Rust 1.98.1 was cross-compiled for
`x86_64-pc-windows-msvc`; the C guard was compiled/linked natively with MSVC
17.14.41, `/O2 /W4 /WX`. This is an archive/source-bound build, not a claim
that the remote Git checkout was at that commit.

Two campaigns ran on the existing Azure Windows x86-64 development host with
VBS/HVCI running, test signing enabled and Secure Boot disabled. They reused
the unchanged development-signed image from `bce5cd2a` and concrete facade
executable from `1762987f`; neither was rebuilt or re-signed here.

The [observation record](../assurance/windows-protection-observations/image-pin-48197d67.json)
contains the full source closure, artifact identities, exact outcomes and capture
timestamps. The locally retained raw archive is
`release-reports/windows-azure-replacement-2026-09-29/image-pin-complete.tar`,
SHA-256 `c32140e9756848263c1b7c748ed4f2f673e755e5b1d60efb49c226cbf0cb1c8c`.
It is outside `target/` and ignored by Git. A read-only review checked all 167
source hashes against current and committed source, build artifacts, raw stdout,
executable/image identities, both records and cleanup. This is an implementation
author's artifact review, not an independent pentest.

## What passed

The fixture checks the complete bounded main-file bytes using first-party
SHA-256 and a fixed reviewed digest. It rejects selected ambiguous paths and
reparse-point handles and holds the file and ancestor directory handles while
the reviewed child loads and uses the candidate image. It does not expose a
general application-supplied image policy or production constructor.

| Native control | Both campaigns |
| --- | --- |
| Main file with its first byte changed | Rejected before loading |
| Preexisting conflicting writer | Pin acquisition rejected |
| Unchanged file and compatible reader | Accepted |
| Write access, delete access, file rename and parent rename while pinned | Rejected with sharing violation, error 32 |
| Reviewed facade while main file remains pinned | 281 calls, 14 owners created/deleted, zero retained owners or cleanup errors |
| Same rename/access operations after closing guard | Succeeded, providing positive controls against mere ACL denial |
| Compiled mutant allowing write sharing | Rejected by campaign, exit 97/result 11 |
| Compiled mutant skipping file hash | Rejected by campaign, exit 97/result 10 |

The two faulty variants were deliberately tested; their nonzero exits are
expected mutant rejections, not successful admission. Original source images
were preserved; mutation and rename controls operated on separate copies.
Cleanup recorded no probe children or temporary certificates and no signing or
host-configuration change. Native build stdout contained no warnings/errors.

Local focused checks also passed: three Rust tests at optimization levels 0 and
2, two compiled hash-check mutants at both levels, 22 malformed C path cases
plus null/overlong paths and a valid control, and exact result-schema mutations.
These tests supplement native sharing checks; they do not simulate Windows file
semantics on Linux.

## Limits and next boundary

- A main-file hash does not verify a certificate chain, authorize a signer,
  attest an enclave or bind the bytes/identities of imported DLLs.
- These sharing and rename observations are not an exhaustive filesystem-race
  proof or protection against a privileged host. Only the tested operations and
  configuration are established here.
- The unchanged image and child use bounded public vectors. This does not add
  confidential-data, dump/residency, instrumented-build or production-route
  qualification, or validate wider algorithms/acceleration.
- The guard is an isolated C/Rust fixture around the private facade executable.
  It is not integrated into the production strict API. Windows AArch64 was not
  executed.

Next is reviewed identity/import admission and the deployment constructor, then
the broader work in [v0.24.50 remaining work](windows-v02450-remaining.md).
Consumer responsibility for signing does not waive those implementation checks.
No release-gate or pending-pentest status changed.
