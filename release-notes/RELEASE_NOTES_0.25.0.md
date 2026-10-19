# v0.25.0 — Complete Generic HMAC Construction

Status: in development; no tag, publication or qualification claim.

## Initial implementation

- Added the unpublished `brynja-mac-hmac` leaf with sealed adapters over the
  existing hardened SHA-224/256/384/512, SHA-512/224, SHA-512/256 and SHA3-224/256/384/512
  owners. No hash, backend or core cleanup implementation was changed.
- Implemented byte streaming, full-length one-shot tags, long-key normalization,
  exact protocol-selected byte truncation, consuming verification and typed
  secret/public outputs. Empty keys are mathematically supported, not secure.
- Added all seven RFC 4231 cases, lifecycle/output tests, negative ownership
  rustdoc cases, and an explicit 1,100-case Python/OpenSSL differential campaign.
  These are author tests, not an independent review or full qualification.
- Started source-only packaging with an explicit HMAC include list. Evidence,
  standalone tests and oracle tooling remain in GitHub, not the crate archive.

## Portable acceptance follow-up

- The real extracted archive now rejects 67 public API/ownership misuse probes
  with checked Rust diagnostics, including all ten algorithm owners, consumed
  streams, cross-algorithm/secret-public tag substitution and secret borrow escape.
- Seven compiled algorithm/comparison mutations are rejected by executing the
  relevant RFC or lifecycle test; compiler errors are not counted as successes.
- A private copied-source fixture injects 132 synthetic hash errors/unwinds and
  verifies owner release, transactional public output, clearing secret output and
  scratch destruction while storage is alive. Five debug/release tests and four
  compiled lifecycle/policy mutants cover this contract. This fixture never
  adds a public fault-injection feature or enters the published archive.
- Extracted `no_std` consumers instantiate all ten algorithms. HMAC-specific
  compiler erasure, real hash exhaustion, timing and verifier-family registration
  remain pending; synthetic adapter faults do not establish those properties.

## Remaining work before completion

1. Close modern profile coverage, general SHA-512/t and precise bit/key/tag
   policies, plus the error/fault and no_std consumer contracts.
2. Assess and implement applicable existing accelerated hash routes and
   protected/resident HMAC composition without weakening host-memory boundaries;
   finish facade integration and required API/profile/requirement inventories.
3. Register HMAC-specific evidence planning and bounded Miri/Kani/ASan/codegen
   campaigns. Reuse unchanged hash evidence; changes to shared implementations
   still require their affected consumer checks. No long sweep is launched here.
4. Finish package/downstream, mutant, timing and cleanup qualification, then
   exceptional independent pentest/retest and final release checks.

The completed v0.24.55 consolidation is the baseline, not deferred work.
Legacy HMAC-SHA-1/MD5 remains v0.25.1; cumulative public/package acceptance and
the publication checkpoint remain v0.25.2. Nothing is selected for publication
in this development milestone.

## Owner-directed package footprint

Before v0.25.2 publication, audit every selected package and its first-party
dependency closure. Ship runtime sources, required build inputs, licences,
README and Cargo metadata only; exclude evidence, native captures, assurance
fixtures, standalone tests/tools and generated audit reports. Retain every file
needed by build scripts or source includes, and prove the extracted packages
build as downstream consumers rather than relying only on a filename filter.
Record actual archive inventories and sizes in repository verification output,
without putting that evidence back into the published packages.
