# v0.25.2 — HMAC public API usability acceptance

Status: implementation in progress; not release-ready, tagged or published.

This is the planned public checkpoint after the modern and isolated legacy HMAC
development milestones. It does not authorize publication before cumulative
review, package selection and release verification have completed.

## Implemented first step

Modern HMAC exposes one key-independent `validate_tag_policy::<A>` rule shared
by public leaf constructors, accelerated prefix constructors and hosted portable,
Linux protected and Apple resident selection. Full tags retain their exact bit
width; byte prefixes retain the 128-bit minimum and cannot round a fractional
SHA-512/t digest up to another byte. Algorithm admission precedes width checking.
The consuming portable token retains its chosen policy; no selected-backend
failure acquires a portable fallback.

Author checks passed:

- Leaf and hosted Rust tests, doctests, formatting and affected-crate Clippy
  using the existing repository lint allowance.
- Algorithm/tag-boundary matrices, including invalid algorithms, fractional
  widths, minimum tags and arithmetic overflow.
- Extracted leaf package debug/release tests and a bare-metal `no_std` consumer.
  The archive contains 18 files and is approximately 23 KB compressed;
  test and assurance artifacts stay outside the archive.
- Six compiled leaf-policy mutations and seven compiled hosted selection and
  Linux/Apple metadata-policy mutations rejected. These metadata tests do not
  execute native protected/resident workers.
- Existing extracted-package API, composition, handoff and cleanup mutation
  suites, without claiming new compiler cleanup or native qualification.

Static source-review bindings are reconciled with this implementation. Historical
native captures, external owner approval and family development-review records
are not rewritten to claim that the new caller code was previously qualified.

## Authoritative verification results

The cumulative review also identified KMAC routes returning successful false
decisions. The remediation extends mismatch-as-error to portable, selectable,
scoped, protected/resident and Windows enclave KMAC, including borrowed tag
comparison. The public `KmacVerification` type is removed; use `Result<(), Error>`
and reject all errors. Portable `verify_exact`/`verify_bits_exact` bind a
protocol-selected width before output generation. Completed mismatches remain
reusable after existing cleanup; backend errors never authorize fallback. This
changes pre-publication APIs. The supplied independent retest of `4ab30977`
closes both KMAC findings; platform execution limits and informational API/example
follow-ups remain recorded in the pentest ledger. Release qualification is separate.

Modern portable, static/runtime and protected/resident HMAC verification now
returns `Result<(), Error>`. Only a matching authenticator is `Ok(())`; a
completed mismatch is `Error::Mismatch`. The old boolean `Verification` wrapper
and hosted `Ok(false)` contract are removed. This intentionally changes the
development API before the public checkpoint; remove `.expose_public()` calls
and propagate or explicitly handle verification errors.

Private hosted workers retain their internal result-shape protocol. They convert
only a completed leaf mismatch to a false decision; public sessions return a
mismatch error after cleanup, result-shape validation and reusable-health
restoration. Operational failures still cannot authorize fallback. Timing tools
likewise distinguish completed mismatches from failed operations.

Leaf/hosted/strict-facade tests, extracted leaf and ordinary facade packages,
Linux protected scalar and SHA-NI worker package/mutation checks, timing-fixture
controls, workspace all-feature/all-target compilation and scoped Clippy pass.
Existing synthetic fault suites retain their exact error/unwind populations.
The portable and static/runtime caller-cleanup checks also pass for Rust 1.99.1
on x86-64 Linux under both panic modes, within their existing bounded dispatch
scope. These are author checks, not whole-frame erasure or independent review.

The hosted compiler checker now validates the complete emitted
`Hmac<Sha512T<129>>::from_static_with_tag_length` wrapper before conservatively
modeling its constructor call. Its argument/owner transfer, overflow and prefix
admission, error representation, sole callee and every emitted instruction are
checked; an unfamiliar wrapper shape fails closed. Instruction-deletion,
argument-substitution and extra-access regressions are integrated into the hosted
test suite. This abstraction is not an instruction-equivalence or timing claim.

Rust 1.90.0 and 1.99.1 hosted checks pass for Linux x86-64, Linux AArch64 and
Apple AArch64 under `panic=unwind`, with 1,302 public-verification mutations
rejected for each compiler. The
bridge checks match-to-success, mismatch-to-error, absent-result rejection and
operational-error preservation, including meaningful nested error payloads.
Rust 1.90.0 x86-64 `panic=abort` also passes after reconciling its emitted result
discriminants. Twelve compiling source mutants (candidate substitution,
mismatch accepted as success, and absent worker decision accepted as success)
are rejected across scalar/compiled Linux and Apple session bridges; restored
baselines pass. These are emitted-code checks, not native Apple worker execution.
Remaining compiler-profile coverage and native Apple execution remain pending.
Previous compiler/native evidence is not represented as qualifying these API
changes.

Extracted `brynja` and `brynja-crypto` consumers also exercise ten named modern
HMAC algorithms and the `Sha512T<129>`/`Sha512T<511>` fixture identities with
long keys, streaming versus one-shot output, full and
128-bit-prefix mismatch rejection, wrong-width rejection, and secret-output
cleanup that preserves the unused caller-buffer suffix. Debug/release consumers,
118 ownership/API negatives per facade, `no_std` builds, explicit execution
feature isolation and six isolated protocol dependency closures pass. The
facade README's verification example is updated and its three executable
examples pass.

## Combined portable package acceptance

The extracted `brynja` and `brynja-crypto` consumers now separately depend on
`brynja-legacy-hmac`, never obtain it through the modern facade. Each runs eight
tests in debug and release: the modern matrix above, every one of the 383 admitted
general SHA-512/t parameters, legacy SHA-1/MD5 streaming and long-key cases,
RFC 2202 vectors, full/truncated mismatch and wrong-width rejection, and secret
output cleanup. The legacy 80-bit floor cannot relax the modern 128-bit policy.
General fractional parameters remain project-defined interoperability profiles,
not a new standardization claim.

Each facade also passes an extracted `no_std` consumer and rejects twelve
compile-time substitutions, including equal-width modern/legacy tags and secret
tags, ordinary digest/tag confusion, foreign algorithm identities and missing
legacy acknowledgement. The graph check first establishes a modern-only
baseline, then binds every combined package's identity, version, source path and
target to its extracted archive. Normal/build edges (including target-conditional
edges) and features of the modern closure must remain identical; the legacy
closure remains separately bounded. Sixty-four archive-binding mutations,
fourteen graph/feature/kind mutations and a contaminated baseline are rejected.
These portable acceptance checks do not refresh hosted/native qualification.
Incremental command ownership selects this bounded combined check for either
HMAC family, without selecting the other family's Kani campaign. The three
prefix-wrapper regressions are also enumerated exactly once in the resumable
hosted suite. Focused scope tests and 142 detached-verification regressions pass;
no release criterion or evidence-approval requirement was relaxed.

## Publication footprint — source/metadata archives with repository fixtures

A local `cargo package --list --offline` audit of all 43 workspace crates found
16 crates still packaging 109 standalone test/vector files, totaling 2,834,387
source bytes. This is uncompressed source size, not registry download size.
Examples include the SHA-2/SHA-3 vector files and core/hosted integration tests.
The modern HMAC leaf already has a source/metadata allowlist; this does not make
its whole dependency closure lean. Separate `src` test modules also need review.

The first five migrated crates (`brynja-core`, `brynja-crypto-cpu-std`,
`brynja-pki`, `brynja-protocol`, `brynja-sanitization`) now explicitly include
Cargo metadata, both licences, README and all Rust source modules. Their 29
standalone test files (249,973 uncompressed source bytes) remain in the repository
but no longer ship in the archives. Embedded `src` test modules are retained;
this is not yet a claim that all published source is runtime-only. The
repository-only `brynja-test-support` crate remains unpublished and unchanged.

The existing package-list check now tests and enforces the migrated allowlists,
rejects missing source and metadata, duplicate/noncanonical paths and accidental
fixtures/evidence, and does not silently exclude tests from unmigrated families.
Nine focused content regressions pass. `check-lean-package-builds.py` creates real
archives and builds pristine extracted dependencies in debug/release under Rust
1.90.0 and 1.99.1; the four non-hosted crates also build for
`x86_64-unknown-none`. No repository fixture overlay is used, and the extracted
dependency bytes are checked unchanged afterward. This is package usability,
not compiler cleanup or native qualification.

All 43 archive listings, the five crates' workspace tests/doctests, the extracted
modern/legacy HMAC facade suite and protected scalar HMAC package/mutation suite
pass after this change. Current source-review bindings are reconciled; immutable
historical captures, capture snapshots and external approvals are unchanged.

The second migration covers `brynja-hash-sha2`, `brynja-hash-sha3`,
`brynja-mac-kmac` and `brynja-hash-tuple`. Their acceptance harnesses now read
reviewed repository fixtures into separate consumer directories; implementations
still resolve from extracted archives. The strict scalar consumer likewise
loads SHA-2 vectors from the repository. No fixture is overlaid onto an extracted
runtime dependency. This removes another 46 standalone test/vector files
(2,248,473 uncompressed source bytes). In the Rust 1.99.1 local packaging run,
SHA-2 shrank from approximately 419 KB to 100 KB compressed and SHA-3 from
210 KB to 106 KB. These are local archive measurements, not registry uploads.

Fixture-isolation regressions exercise fourteen facade installations, the strict
consumer, and three leaf package installers without archive test inputs. The
KMAC installer-inventory test now constructs a distinct repository fixture tree;
its omission and unexpected-test checks remain active. Bare-metal packaging
profiles are explicitly split: portable code is built, while all-feature
accelerated code is type-checked because generic bare x86's soft-float ABI does
not support all SIMD code generation. All-feature host builds remain required.

Nine pristine extracted crates pass debug/release builds on Rust 1.90.0 and
1.99.1; eight non-hosted crates pass portable bare-metal builds and all-feature
bare-metal type checks. Fourteen affected facade consumers compile in debug and
release (28 profile builds), with extracted dependency bytes unchanged. These
fixture builds do not claim runtime or native execution. The real KMAC and
TupleHash package suites separately pass their unchanged runtime populations,
ownership negatives, algorithm/verification and cleanup mutations; hardened
Keccak's generic package suite passes too. The facade regression suite, all 43
archive listings, API-profile checks and current metadata-binding regressions
pass. Historical native evidence and external approvals remain unchanged.

The third migration covers ordinary/hosted SHA-1, MD5 and ParallelHash. Another
31 standalone test/vector files (325,359 uncompressed bytes) stay in the
repository instead of the archives. Legacy installers now take external test
inputs from the repository, with runtime implementations still bound to the
extracted packages. Their ordinary and hardened debug/release suites, oracle
populations, ownership negatives and compiled mutation checks pass. This is
generic package acceptance, not refreshed native accelerated qualification.

ParallelHash first builds both pristine extracted libraries with all features
in debug and release. Only afterward does the test harness declare its eleven
external integration targets, including the additional scoped fixture, using
repository paths. It does not copy tests into runtime source directories.
Extracted unit tests, protected lifecycle tests, doctests and source mutations
remain active. The scoped fixture gained a crate documentation header to satisfy
the package's lint; its behavior is unchanged. All 436 compiled ownership probes
and 132 compiled mutation runs pass. Regressions enforce build-before-fixtures,
exact target inventory, missing-input rejection and no fixture installation
after a failed runtime build. Both ParallelHash facade consumers also compile
in debug/release without changing the extracted dependencies.

All fifteen migrated crates pass pristine extracted debug/release builds under
Rust 1.90.0 and 1.99.1; the eleven non-hosted crates pass portable bare-metal
builds and all-feature bare-metal type checks. The six newly migrated crates'
workspace all-feature tests/doctests and current review-metadata checks pass.
The 43-crate listing audit now finds **no standalone test files in any of the 30
publishable crates**. Three test-support files remain packaged only in a
repository-only crate with `publish = false`. Across the three migrations,
106 files and 2,823,805 uncompressed bytes are excluded, not deleted. The content
check also rejects future standalone test payloads in publishable crates.

The embedded-source audit retains declared Rust unit modules: omitting a module
while shipping its parent's `#[cfg(test)] mod` declaration breaks an extracted
crate's own tests. The HMAC leaf had exactly that omission; its lifecycle harness
previously copied `execution/tests.rs` back from the checkout. The archive now
contains that 1,903-byte module and the harness no longer repairs it. Missing
unit source is rejected before fixture creation, and a byte-distinct regression
confirms that the test uses archive input rather than the repository copy.
The four retained-owner tests pass in debug/release with all features, including
four compiled cleanup/error-classification mutants. The full extracted HMAC
vectors, lifecycle, bit/general/tag-policy, ownership and composition suites
also pass. No external vectors or native evidence were added to the archive.

The current HMAC archive is 19 files, approximately 24 KB compressed. All sixteen
source-allowlisted packages pass pristine extracted debug/release builds with
Rust 1.90.0 and 1.99.1; twelve non-hosted packages pass portable bare-metal builds
and all-feature bare-metal type checks. Declared unit-test Rust source is retained
intentionally, not represented as runtime-only code. No production Rust behavior
changed during these packaging migrations. Immutable historical captures and
external approvals remain unchanged; no archive has been uploaded to crates.io.

## Compiler-profile reconciliation and publication preparation

The remaining hosted HMAC profiles pass on both Rust 1.90.0 and 1.99.1 for
`aarch64-unknown-linux-gnu` and `aarch64-apple-darwin`, under both panic modes.
Each of these eight emitted-code checks covers the existing 48 host consumers,
48 loan probes and 24 executors, including dependency cleanup checks. These are
compiler-model checks, not native Apple execution or whole-frame erasure.

The focused Apple Silicon run subsequently exposed one stale Apple-only unit
test: its startup-failure regression still expected a boolean from public HMAC
verification. It now requires `Ok(())`, matching the already updated Linux test.
The SHA-256 native harness explicitly executes this previously ignored test in
debug and release on both platforms. Its regression tests reject skipped or
zero-test results and check the exact platform-specific test name. Mutation
driver expectations now require all five compile-and-fail pairs, including the
new mismatch-as-success mutation, rather than the former four.

The corrected native refresh passed on the M2 Mac under Rust 1.99.1:

- Resident SHA-256, SHA-512 and Keccak: scalar/compiled package consumers,
  ownership negatives, behavioral mutations and debug/release native routes.
- Hosted SHA-256, SHA-512 and Keccak: Require/Prefer selection in debug/release
  and eight fallback/policy mutations for each kernel family.
- The explicit startup-failure regression also passed locally with SHA-NI;
  Linux protected SHA-256 and AVX2 Keccak package/native/mutation checks pass.

All six Mac command records and their logs were downloaded and their hashes
reconciled with source archive
`dd22d3fabb1e98d86af1dd0341dc6932dc733a45368111fae35a3d11350675e6`.
The local record is under
`release-reports/v0252-mac-hmac-Qd4XuV/retry1/`, outside Cargo's disposable
`target` directory and outside crate archives. The initial compile-failure log
is retained separately. This is author-operated execution of an uncommitted
working-tree snapshot, not independent native review, a tagged capture or an
external approval. No dedicated x86 SHA-512 silicon execution is claimed.

The publication inventory contains 30 publishable crates and 13 excluded
repository/research/foundation crates. The cumulative comparison uses v0.20.0,
not the previous development milestone. The former `brynja-core` metadata-only
classification is corrected to include its cumulative secret-region APIs.
The manifests, exact dependency declarations, current fixture locks and SBOM
now use these transitions under the existing independent-version policy:

| Packages | Candidate version | Cumulative reason |
| --- | --- | --- |
| `brynja` | 0.25.2 | Public facade checkpoint; publish last |
| `brynja-core` | 0.10.0 | New secret-region APIs and implementation |
| `brynja-crypto`, `brynja-crypto-cpu`, `brynja-crypto-cpu-std` | 0.2.0 | Implemented crypto facade, kernels and hosted owners |
| `brynja-pki` | 0.3.0 | ASN.1 primitives and containers |
| `brynja-protocol` | 0.1.1 | Exact core dependency and archive metadata |
| TLS, TLS12, TLS13, TLS13-handshake, DTLS, QUIC-TLS and platform crates | 0.1.9 | Exact transitive dependency updates; transport implementations remain pending |
| `brynja-sanitization` | 0.1.2 | Dependency and packaging update; no new adapter API |
| Fifteen previously unpublished hash/MAC/strict/legacy crates | 0.1.0 | Initial packages, subject to cumulative review and separate legacy admission |

The publication selection passes the existing release-policy validator, but
selection is not upload authorization. Repository-only and unimplemented legacy
protocol packages remain excluded. Legacy hash/MAC packages remain separate from
the modern facade. No crate has been published.

## Coordinated version and fixture reconciliation

All 90 current root/fixture workspaces resolve offline with their locked graphs.
Third-party lock entries, including versions, sources, checksums and dependency
edges, are unchanged. The original v0.24.20 portable legacy manifest and lock
remain byte-for-byte frozen. A separate `current/Cargo.toml` compiles its exact
original library and binary source paths against the current dependency graph;
CI, compiler, Miri and sanitizer commands use that manifest. Its structural
regressions reject redirected source targets and enabled defaults. The frozen
vectors and all three portable lifecycle tests pass. No historical capture or
external approval was changed.

The SHA-1/MD5 candidate lock refreshes are explicitly bound in their current
operational deltas, not substituted into the immutable native snapshot. Two
new mutations reject lock drift. The historical-evidence and source-closure
regressions pass, as do the CPU boundary, release-policy, package-content,
native-schema and metadata-only preflight suites. Current review bindings are
author-maintained inputs, not a new independent qualification.

With the new versions, all sixteen migrated packages again pass pristine
extracted debug/release builds on Rust 1.90.0 and 1.99.1; twelve non-hosted
packages pass portable bare-metal builds and all-feature bare-metal type checks.
No repository fixture is copied into those runtime dependencies.

The extracted HMAC facade check also passes with the new versions: both
`brynja` and `brynja-crypto` run the combined modern/isolated-legacy matrix,
including all 383 general SHA-512/t parameters, debug/release verification and
cleanup, twelve separation negatives and 118 modern ownership/API negatives.
Their portable `no_std` builds, explicit execution opt-ins and six isolated
protocol closures pass. All 43 package listings pass; no standalone tests or
evidence were restored to the thirty publishable archives.

The broader extracted-facade package run also passes on Rust 1.99.1: SHA-2
ordinary/hardened/scoped and batch consumers, Keccak batch and sponge consumers,
KMAC, TupleHash, ParallelHash scheduled/streaming/threaded consumers and the
separate ordinary/hardened SHA-1/MD5 consumers. Debug/release runtime populations,
ownership/classification negatives and compiled behavior/cleanup mutations are
retained. This run used generic/portable execution and explicit unavailable-route
checks; accelerated kernels compiled but not executed are not counted as native
qualification. All-feature/all-target workspace test compilation passes too.

## Crate README publication audit

All 43 crate READMEs retain the shared remotely hosted WebP image, with an
explicit display width and descriptive alternative text. Publishable packages
link to their own registry/documentation pages; permanently unpublished packages
link to their own source instead. Repository-relative crate README links are
replaced with absolute repository URLs, so they do not depend on crates.io
recreating the checkout layout. The remote image returned HTTP 200 with the
expected image content type during the author check; the image is not added to
crate archives.

Each crate retains its own capability table, platform/SIMD disposition and
examples. Protocol/research placeholders explicitly show repository boundary
checks rather than fictitious operational APIs. Registry installation examples
are conditional on publication of this source version; candidate checkout
instructions remain available. Added examples cover modern HMAC mismatch
rejection in the facade, preselected truncated tags, clearing secret tags and
the repository-only deterministic clock helper.

The main tables mark complete modern/legacy HMAC APIs as implemented, separating
functional completion from release/platform qualification. No independent
cryptographic verification, FIPS validation, unfinished protocol implementation
or Windows production qualification was promoted. The current checkpoint still
requires its cumulative review and final release checks. Status regressions
enforce those distinctions; image/navigation/link/example regressions reject
21 malformed documentation cases. All 77 crate README doctests pass on Rust
1.90.0 and 1.99.1. Platform-gated examples remain bounded compilation/use
examples, not a new native qualification campaign.

## Remaining checkpoint work

Two supplied focused reviews of `v0.25.1..6313481f` report no Critical, High or
Medium issue. Their non-blocking notes are handled without runtime changes:
protocol-owned attempt budgets remain explicit, every public HMAC verification
entry documents fail-closed error handling, and the unpublished HMAC identity
was checked against the official sparse registry index. Documentation mutations,
leaf/hosted/strict tests and MSRV/current doctests pass. These focused reviews
are not the cumulative public review; see the ledger for exact dispositions.

The subsequent CI correction isolates two internal-release planner fixtures from
the live public release stage. New public-mode assertions preserve the full
checkpoint selection; all 143 detached-verification regressions pass. Planner,
reuse and approval policy are unchanged, and the generated test binding is
refreshed. This test-only follow-up still needs GitHub validation when committed.

The [review handoff](../docs/hmac-public-checkpoint-review.md) now enumerates the
completed author work and the remaining release work. The cumulative
[pentest ledger](../security/pentest/v0.25.2.md) is explicitly pending, not PASS.
The current Linux workspace all-feature/all-target tests also pass with the
coordinated versions (`--locked --offline`); ignored target-specific tests are
not represented as executed. README, package and status regressions retain the
distinction between implemented APIs and release qualification.

1. Freeze the candidate and obtain independent review of v0.20.0 through this
   public checkpoint, not only the immediate v0.25.1 changes.
2. Reconcile current compiler/native/timing records using the existing exact
   reuse proofs; collect changed routes without relabelling older execution.
3. Complete public-checkpoint verification and the clean-tree publication
   package check. The unchanged planner selects repository, matrix, ASan, Miri
   and Kani, with extended public Miri coverage. No full sweep has been started
   during this preparation.
4. Obtain green GitHub/CodeQL on the reviewed candidate and explicit tag and
   publication authorization. The 30 selected packages have not been uploaded.
