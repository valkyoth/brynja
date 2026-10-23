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
- Default-off `sha1-execution` with `execution::Sha1Hmac`: borrow one hardened
  executor, admit all empty streams before keys, reject portable authority and
  retain no fallback route. Fatal update or recoverable unwind destroys both
  inner and outer owners; atomic message-length rejection preserves them.

## Verification and limits

The initial author tests exercise all fourteen RFC 2202 examples, all admitted
byte truncations, key/message boundaries, streaming partitions, malformed tag
lengths, public destination preservation and secret destination clearing.
Real extracted archives pass these checks in debug and release, plus 140 byte
comparisons against Python `hmac`/`hashlib` and 176 bit-message comparisons
against separate Python hash models per profile. Byte-aligned controls also
check the bit models against Python's standard-library HMAC. Fourteen acceptance
tests reject archive, graph, feature/default and oracle-population mutations.
Fifteen all-feature compile-fail doctests enforce affine/local state and output
constraints. Fourteen additional extracted-consumer negatives reject lifetime,
authority, algorithm-substitution, private-rebind and forbidden-export mistakes.
Strict Clippy for the new crate, Rust 1.90 tests, bare-metal
`x86_64-unknown-none` and Apple Silicon cross-compilation pass. Cross-compilation
is not native execution. The all-feature Clippy command requires `--no-deps`
for this scoped result: the unchanged SHA-1 CPU implementation triggers four
Rust 1.99 `chunks_exact_to_as_chunks` style warnings under a dependency-wide
`-D warnings` invocation. No shared implementation was changed to silence them.
These checks do not establish independent security or compiler cleanup qualification.

Explicit SHA-NI development runs on the local AMD x86-64 host pass in debug and
release, both from the workspace and extracted archives: 70 byte cases with
every admitted truncation and mismatched byte position, 88 bit cases with
streaming splits, and malformed-output/revocation tests. The native driver
independently checks exact populations and byte/bit results, and rejects absent
host features rather than substituting portable execution. Four driver tests
cover malformed populations, forged results and incomplete host feature probes.
Three private liveness/drop tests also pass under pinned Miri
`nightly-2026-09-11`; no full sweep was started or claimed.

Existing legacy hash implementations are unchanged. Their qualification does
not qualify the new composition. Default constructors stay portable even under
dependency feature unification. The separate SHA-1 execution API is explicit.
No modern, FIPS, protocol negotiation,
protected-memory, register-erasure or fatal-path guarantee is inferred.

## Work remaining before completion

- Complete failure-injection and native Arm execution checks.
- Implement MD5 SIMD composition and qualify both accelerated paths; assess protected
  and resident owners without silently downgrading their guarantees.
- Complete composition error/unwind, cleanup-codegen and timing checks.
- Register API/capability owners and a separately scoped evidence family.
- Obtain independent retest and run the affected release checks and GitHub.

No crates.io publication or release tag is authorized by this work-in-progress.
