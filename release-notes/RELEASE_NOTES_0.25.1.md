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
- Default-off `md5-batch`: explicit eight-slot HMAC-MD5 with real AVX2/NEON
  ipad/opad work, aggregate constant-time verification, typed public/secret
  tags and one compression budget spanning all phases. Ineligible shapes reject;
  normalization chooses scalar or SIMD before processing, never after failure.

## Verification and limits

The initial author tests exercise all fourteen RFC 2202 examples, all admitted
byte truncations, key/message boundaries, streaming partitions, malformed tag
lengths, public destination preservation and secret destination clearing.
Real extracted archives pass these checks in debug and release, plus 140 byte
comparisons against Python `hmac`/`hashlib` and 176 bit-message comparisons
against separate Python hash models per profile. Byte-aligned controls also
check the bit models against Python's standard-library HMAC. Fourteen acceptance
tests reject archive, graph, feature/default and oracle-population mutations.
Twenty-one all-feature compile-fail doctests enforce affine/local state and output
constraints. Twenty-eight additional extracted-consumer negatives reject lifetime,
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

The MD5 secret kernels and ordinary hash paths are unchanged. The hardened batch
driver now supports a borrowed prefix block per lane, and accumulates its length
before existing vector-tail processing. Focused portable and AVX2 regressions
cover all 256 active masks, canonical bit tails, padding/block boundaries, exact
work accounting and every cancellation/revocation/unwind checkpoint. Existing
MD5 batch tests also pass. The source-binding inventories are development drift
checks, not independent approval or a refreshed native qualification.

Native AVX2 HMAC author tests cover all masks, every admitted truncation, 70 byte
cases and 88 bit cases checked against independent Python models, both scalar
and SIMD long-key normalization, all tag-byte mismatch positions, exact budgets
and each cancellation/revocation/unwind boundary. Separate explicit native tests
do not silently pass on generic builds. No new unsafe or kernel code was added.
The three native HMAC-MD5 tests also pass under AddressSanitizer with
`ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:exitcode=1` and
`LSAN_OPTIONS=exitcode=23` on pinned `nightly-2026-09-11`. This is a runtime
memory-safety check, not proof of cleanup of compiler-created copies.
A separate bounded portable-prefix Miri test passes on the same pinned nightly,
covering prefix/padding budget rejection, a partial-bit tail, output clearing
and subsequent reuse. It does not claim to interpret the SIMD assembly.

Existing hash qualification does not qualify the new composition. Default constructors stay portable even under
dependency feature unification. The separate SHA-1 execution API is explicit.
No modern, FIPS, protocol negotiation,
protected-memory, register-erasure or fatal-path guarantee is inferred.

### Apple Silicon author check

Commit `6c3f34b3` was exported into a fresh directory on the Apple M2 Pro builder
(macOS 27.0.1, Rust 1.99.1). The source archive's SHA-256 was
`6dfa89b45230ad6988bfe80b4947bdd8ddb009a3a525cc584a60c93d6d961c6e`,
reconciled locally and remotely before extraction. No GitHub push was required.

- `python3 scripts/legacy-hmac/legacy_hmac_native.py`: two explicit SHA-1
  native tests per profile, debug and release, with `+neon,+sha2`; exact marker
  populations and 70 byte / 88 bit outputs checked independently by Python.
- `python3 scripts/legacy-hmac/legacy_hmac_md5_native.py`: three explicit NEON
  HMAC tests per profile, debug and release, with `+neon`; all 256 slot masks,
  70 byte / 88 bit cases and lifecycle/failure tests passed. The four-lane route
  exercises partial eight-slot batches that cannot be eligible on AVX2.
- `cargo test -p brynja-legacy-md5 --features hardened-execution
  --test hardened_execution --test prefixed_execution`, debug and release,
  with `RUSTFLAGS='-C target-feature=+neon'` and
  `BRYNJA_REQUIRE_HARDENED_MD5=1`: all nine tests passed per profile, none ignored.

These are source-bound author-operated functional checks, not signed runner
attestations, independent review, complete cleanup qualification or release
native-admission records. Existing approvals were not replaced.

## Work remaining before completion

- Complete the remaining qualification-specific failure-injection checks;
  focused native x86/Arm functional execution now passes.
- Qualify both accelerated compositions, including MD5 prefix handling; assess protected
  and resident owners without silently downgrading their guarantees.
- Complete composition error/unwind, cleanup-codegen and timing checks.
- Register API/capability owners and a separately scoped evidence family.
- Obtain independent retest and run the affected release checks and GitHub.

No crates.io publication or release tag is authorized by this work-in-progress.
