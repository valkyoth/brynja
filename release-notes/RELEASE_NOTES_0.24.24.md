# Brynja 0.24.24 Release Notes

Status: owner pentest PASS; awaiting green GitHub/CodeQL and explicit tag permission

## Scope

General SHA-512/t authority and public API **contract only**. No production
Rust algorithm, feature, protocol or CPU admission changes. The facade version
advances to 0.24.24; support versions and sanitization 2.1.0 stay unchanged.
This internal milestone selects zero crates; next publication remains v0.25.2.

- Authenticate the exact August 2015 FIPS 180-4 PDF against the existing local
  pin and official source; record sections, rights and revision/errata review.
- Freeze all 510 t values, exact decimal IV labels, arbitrary-bit digest
  identity, typed public/secret outputs, all ordinary/hardened byte/bit APIs,
  failure behavior, resource bounds and mandatory private-state clearing.
- Add the separate planned `algorithm.sha512-t` surface and normative
  `BRY-REQ-CRYPTO-0020`, with a machine-readable operation/evidence register.
- Test every u16 parameter, masks, labels, invalid types, authority/operation
  mutations, missing gates, reviewed bindings and bounded input handling.

The six existing named SHA-2 functions remain fully implemented. General
SHA-512/t is In progress, with actual implementations, independent IV/digest
oracles, cleanup and frozen public acceptance due in v0.24.25–v0.24.29.
No dormant API stubs or unsupported partial production implementation is added.

## Verification and limits

Local candidate checks passed: exhaustive contract/model and mutation tests,
all repository gate components (including a successful resumed standards tail
after metadata refresh), workspace tests/Clippy/docs/packages, twelve compiler
lanes, three bare-metal targets, current tooling/dependency admission, RustSec,
cargo-deny, SBOM and a fresh authority-lifecycle observation.

The owner assessment of `b73ea22173ef` passed with zero open findings. Final
local release checks passed: the complete repository gate, compiler/target and
QEMU checks, all ten full Miri groups, all 29 Kani harnesses, AddressSanitizer,
fresh dependency/tooling and authority checks, and publication-policy tests.
LeakSanitizer was disabled for the environment's ptrace restriction. Miri used
the existing group interface concurrently; the report identifies completed
groups and the intentionally stopped duplicate sequential work. These are
regressions over existing implementations, not execution evidence for the
unimplemented general SHA-512/t API. No new native admission is claimed.

See [the contract](../docs/sha512-t-contract.md) for precise scope and
[the current pentest report](../security/pentest/v0.24.24.md) for completed
local checks and the owner outcome. Contract-model tests do not prove a general
SHA-512/t implementation; no such implementation exists yet.

No arbitrary t gains FIPS, protocol, HMAC or signature approval. Short digests
have weak generic security bounds. All accelerated candidates remain
unadmitted; no independent cryptographic review or FIPS validation is claimed.
The contract requires mandatory sealed cleanup but retains all documented
register, compiler-copy, platform, abort and caller-copy residuals.

Commit the completed report and release metadata, then wait for green
GitHub/CodeQL and explicit owner tag permission. No crate is selected for
publication; the next scheduled public checkpoint remains v0.25.2.
