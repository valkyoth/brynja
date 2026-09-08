# Brynja v0.24.30

Status: exceptional owner pentest and remediation retest PASS. Final local release verification is recorded in the pentest report; green GitHub/CodeQL and explicit tagging permission remain required. Not tagged or published.

## Opt-in acceleration availability contract

This is a contract-only milestone. No production Rust, cryptographic algorithm,
unsafe code, backend admission, feature graph or external dependency changes.
The facade version advances to 0.24.30; support versions stay unchanged.

- Inventory eleven existing kernels across nine families and 29 identities,
  including workload width, exact symbols, compiler bundles, current features,
  ordinary/hardened disposition and the following activation versions.
- Separate project-qualified operational readiness from native measurements,
  independent cryptographic review and FIPS validation. Third-party approval
  is not a prerequisite for future ordinary tested use; none of these
  observations can act as a CPU execution permit.
- Freeze Portable/Prefer/Require semantics, explicit fallback, exact identity,
  startup quarantine, sticky midstream failure and no hidden fallback.
- Specify allocation-free static authority and separate opt-in hosted/legacy
  packages, with full platform/migration and mandatory hardened-owner boundaries.
- Add an unpublished dependency-free no_std executable model with exhaustive
  selection tests, consuming ownership examples and compiled negative controls.
  Its public constructor cannot enable any candidate, and it hashes no data.
- Pentest remediation adds dedicated strict all-target Clippy to the repository
  gate for this standalone fixture, with driver-removal and five compiled lint
  regressions. No production Rust or tagging/publication rules change.
- Register the isolated contract's own full Miri group. Internal milestones
  run that group when affected and smoke tests for unchanged families; public
  checkpoints still run every full group. Dependency or unknown-impact changes
  remain fail-closed. This fixes an unnecessary full-suite selection, not a
  cryptographic implementation or admission change.

See the [contract and commands](../docs/acceleration-availability.md) and
[implementation/review record](../security/pentest/v0.24.30.md).

Existing portable family completion remains unchanged. CPU candidates remain
unadmitted. Actual static/hosted/family activation starts in v0.24.31 and must
pass its own implementation and public-package tests. No new native collection,
cryptographic proof, independent review, FIPS validation or deployment approval
is claimed by this contract. Existing secret-erasure residuals remain unchanged.

All release entries remain `publish = false`; the next public checkpoint remains
v0.25.2. Obtain exceptional owner pentest, finalize release checks, commit the
report, wait for green GitHub/CodeQL, then request explicit tagging permission.
