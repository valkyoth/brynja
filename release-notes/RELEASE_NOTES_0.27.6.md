# v0.27.6 candidate — external-key provider API completion

Internal candidate; no crates.io publication is selected. Candidate commit,
owner pentest/retest, the existing finite final gate, exact-commit green
GitHub/CodeQL and explicit tag authorization remain separate. These notes
are not release approval.

## Scope

The default-off provider API now covers all three AES key widths through
distinct `Aes128Backend`, `Aes192Backend` and `Aes256Backend` traits with matching
provider-key bindings. The direct composition crate and facade expose the same
contracts under both `hazmat-aes-block` and `external-key-provider`.
Existing AES-128 source APIs remain compatible. No AES arithmetic or CPU
admission change is made.

A shared implementation preserves captured permissions, guarded secret/public
outputs, exact block-length checks, terminal quarantine, adapter-dependent
Send/Sync and explicit fallible destruction. A binding cannot export key bytes
or extract/replace its adapter. Drop does not destroy an external key; that
operation requires an owned backend and explicit consuming `destroy()`.
Successful block values are not filtered: AES can have fixed-point results.

On 2026-11-13 the owner narrowed the original concrete PKCS#11 adapter proposal
to dependency-free API completion. Applications choose their own modules,
clients and adapters. No cryptoki, vendor driver, native FFI, OpenBao integration,
mandatory HSM or new third-party dependency is added. The former device-client
proposal is superseded, not falsely marked implemented or assigned a new date.

## Verification scope

- Seventeen lifecycle/fault tests for each width cover known answers in both
  directions, permissions, partial output, invalid lengths, errors/unwinds,
  quarantine, clearing, destruction and thread transfer.
- Both compiler endpoints exercise 180 paired API probes across direct/facade
  consumers, including all ordered cross-width rejection cases and feature,
  ownership and thread-trait constraints. Multi-trait owner-type separation is
  compiler-contract coverage, not actual device key-width assurance.
- Native/MSRV, Miri, ASan, doctest and Cortex-M checks remain registered in
  `brynja-verify`. They do not require an external service.
- The new archive-only provider consumer performs 408 lifecycle test executions
  across eight debug/release, direct/facade, MSRV/current configurations and
  four Cortex-M compile checks. Exact dependency graphs and test populations
  reject missing/ignored tests or checkout-source substitution.

See the [completion record](../docs/assurance/aes-provider-completion.md) and
[usage guide](../docs/aes-usage.md). Mock tests establish wrapper contracts,
not actual hardware custody, ciphertext correctness from an arbitrary adapter,
attestation, FIPS validation or physical resistance.

## Limits and release process

Actual key identity/width, mechanism, permissions, non-exportability, session
policy and handle liveness remain trusted adapter obligations. All backend
operation errors remain terminal; an error named busy or rejected does not
establish safe retry. No automatic retry, fallback or new retry taxonomy is
introduced.

Raw AES is not authenticated message encryption. Modes/AEAD and the optional
fault-detecting profile remain separate work. Accelerated timing remains an
owner-accepted unresolved limitation; RISC-V remains evidence-only and
unadmitted. No timing experiment or historical qualification campaign is
repeated merely to make the status display green.

Only the facade advances to 0.27.6; supporting crates retain their internal-train
versions. Consumer pins/lockfiles and the SBOM follow the facade. The existing
30 finite final checks and timeouts are unchanged. Earlier verification records
retain their true snapshots; version changes are not fresh executions.

## Initial candidate working-tree preflight — 2026-11-13

All 30 finite checklist commands passed, with targeted corrections rather than
a repeat of the entire list. The first API-profile checks detected the stale
hash of `aes.rs`: its only change is the provider module's documentation naming
all three widths. After reviewing that exact diff, the source hash and generated
register were refreshed; both API-profile checks then passed. Secret-owner
contracts and enforcement were not relaxed.

The advisory check initially could not lock its read-only sandbox cache.
Rerunning the same command with cache access fetched the RustSec database and
passed. No advisory was waived. The refreshed archive-only provider check also
passed on facade 0.27.6: all 384 lifecycle executions and four Cortex-M builds.

This was working-tree preflight, not clean-commit release approval. The initial
candidate was committed as `14627a63` for the owner pentest.

## Pentest remediation and accepted retest

Commit `f5797b5b` makes permission decisions exhaustive, gives quarantine
precedence over permission errors, and corrects per-width documentation. The
retest confirms those fixes and reports no new security issue. The remaining
key-width finding is an accepted trusted-adapter limitation, not a technical
fix: one backend may implement several traits, and constructors do not verify
the actual device key width. Applications must validate and preserve the bound
key's properties. No new metadata-reporting API or hardware guarantee is added.

All nine registered provider checks passed after remediation, including Miri,
ASan/LSan, both 180-probe compiler endpoints, 408 archive lifecycle executions
and four Cortex-M compile checks. The 1,087 registry regressions passed. A fresh
target-directory retest also passed all 51 lifecycle tests, plus nine API-runner
and six package-runner regressions. See the permanent
[review disposition](../docs/assurance/aes-provider-pentest-remediation.md).

The usual clean-commit final gate and exact-commit GitHub/CodeQL handoff remain
required. Accepted retest is not tag or publication authorization.
