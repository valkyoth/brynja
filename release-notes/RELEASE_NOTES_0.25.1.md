# v0.25.1 — Isolated legacy HMAC compatibility

Status: in progress; not release-ready or published.

## Implemented scope

- New allocation-free `no_std` `brynja-legacy-hmac` package, with sealed SHA-1 and
  MD5 identities separate from modern HMAC and all modern facades.
- Explicit legacy-use acknowledgement, long-key normalization, streaming,
  consuming finalization, typed public/clearing secret tags and verification.
- Preselected 10-byte through full-length legacy tags, including RFC 2202's
  96-bit examples; modern HMAC's minimum remains unchanged.
- Canonical high-bit-order message tails; byte-aligned keys and truncation.
- Source-only archive allowlist: runtime sources, Cargo metadata, README and
  licences. Tests and assurance artifacts remain in the repository.

## Verification and limits

The initial author tests exercise all fourteen RFC 2202 examples, all admitted
byte truncations, key/message boundaries, streaming partitions, malformed tag
lengths, public destination preservation and secret destination clearing.
Real extracted archives pass these checks in debug and release, plus 140 byte
comparisons against Python `hmac`/`hashlib` and 176 bit-message comparisons
against separate Python hash models per profile. Byte-aligned controls also
check the bit models against Python's standard-library HMAC. Fourteen acceptance
tests reject archive, graph, feature/default and oracle-population mutations.
Eleven compile-fail doctests enforce affine/local state and output constraints.
Strict Clippy, Rust 1.90 compilation, bare-metal `x86_64-unknown-none` and Apple
Silicon cross-compilation pass. Cross-compilation is not native execution.
These checks do not establish independent security or compiler cleanup qualification.

Existing legacy hash implementations are unchanged. Their qualification does
not qualify the new composition. The initial API is portable only, including
under dependency feature unification. No modern, FIPS, protocol negotiation,
protected-memory, register-erasure or fatal-path guarantee is inferred.

## Work remaining before completion

- Complete downstream type-substitution/forbidden-export and failure-injection checks.
- Implement and qualify applicable accelerated/SIMD composition; assess protected
  and resident owners without silently downgrading their guarantees.
- Complete composition error/unwind, cleanup-codegen and timing checks.
- Register API/capability owners and a separately scoped evidence family.
- Obtain independent retest and run the affected release checks and GitHub.

No crates.io publication or release tag is authorized by this work-in-progress.
