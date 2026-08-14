# Brynja 0.22.2 Release Notes

Status: implementation candidate; exceptional pentest, hosted verification,
and tag pending

Brynja 0.22.2 is an internal development milestone. It selects zero crates.io
packages. The signed v0.20.0 checkpoint remains the latest published release,
and every v0.22.2 change remains inside the cumulative v0.20.0-to-v0.25.0
assessment range.

## Added

- An isolated zero-dependency `no_std` RV64 SHA-256 candidate using the exact
  ratified RISC-V `Zknh` instruction bundle.
- First-party Rust inline assembly for exactly `sha256sig0`, `sha256sig1`,
  `sha256sum0`, and `sha256sum1`, with no external assembly, native object,
  C module, foreign ABI, build script, or delegated provider.
- Exact static `target_feature = "zknh"` selection while preserving the
  portable implementation's state, padding, checked length, digest, error,
  startup KAT, health-generation, and permanent-quarantine semantics.
- Rust 1.90.0 and 1.97.1 generated-code gates requiring all four Zknh
  instructions.
- Supplemental RISC-V QEMU execution of the complete accelerated SHA-256
  differential corpus, including official vectors, padding boundaries,
  multiple blocks, and irregular streaming partitions.
- A detached native-evidence route for an exact registered RISC-V cloud lane,
  requiring directly observed RV64 `zknh` rather than generic RISC-V, `Zkn`,
  RVV, or product-name inference.
- Checksum-pinned local copies and machine-readable authority records for the
  ratified RISC-V scalar-cryptography 1.0.1 and vector-cryptography 1.0
  specifications.

## Security Boundaries

The RV64 Zknh kernel is an implemented candidate, not an admitted backend.
Ordinary construction rejects it, and the optional std detector deliberately
does not auto-select RISC-V. Only the repository evidence configuration can
force the exact statically proven path; doing so grants no runtime admission
or support claim.

The unsafe boundary is confined to one source-hash-bound module containing
four exact inline-assembly statements and five documented low-level blocks.
The scalar path remains authoritative on every build that lacks exact Zknh
compiler proof or backend admission. The reserved vector route names exact
`Zvknha`; it has no implementation or low-level authority, and `Zvknhb` would
require a separate reviewed policy amendment.

## Deliberate Exclusions

There is no native RISC-V correctness, performance, code-size, side-channel,
CPU-migration, authenticated-provenance, independent-review, register-erasure,
or FIPS-validation evidence. QEMU and cross-compilation remain supplemental
only. A sanitized preflight found the registered native lane has Rust 1.97.1
and generic RV64 vector/bit-manipulation support but no scalar or vector SHA
extension, so it stopped before candidate execution. RV32, RISC-V vector
crypto, automatic RISC-V runtime detection, SHA-224,
SHA-384, SHA-512, HMAC, and final SHA-256 public-API chain acceptance remain
outside this milestone.

## Release Process

This milestone introduces a cryptographic inline-assembly module and therefore
meets the project's exceptional pentest trigger even though no crates.io
publication is selected. Tagging requires a passing assessment and retest of
the exact implementation candidate, a committed pentest report, the complete
local tag gate, and green GitHub and CodeQL on the final report commit.
