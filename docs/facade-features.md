# Modern facade features

`brynja` and `brynja-crypto` forward the same algorithm features. The examples
below use `brynja::crypto`; users of `brynja-crypto` replace that prefix with
`brynja_crypto`. Existing flat portable functions and types are unchanged.
These APIs require the current unpublished checkout until the planned
publication checkpoint. No crate version is implied by these examples.

```sh
cargo add brynja --path /path/to/brynja/crates/brynja --no-default-features --features sha2-hardened-execution
```

## Feature selection

All features below are default-off. They expose existing implementations, not
new kernels. Every execution/batch feature also exposes the `cpu` namespace
for explicit no_std authority construction; `general-sha512-t` alone does not.

| Feature(s) on either facade | Namespace/API | Profile |
| --- | --- | --- |
| `cpu` | `cpu` | Low-level no_std authority and candidate inventory; not host detection |
| `general-sha512-t` | `sha2::Sha512T`, `sha2::sha512_t` | General-t extension, including existing hardened portable APIs |
| `sha2-static-execution`, `sha2-runtime-execution` | `sha2::execution` | Ordinary public-data single-stream execution |
| `sha2-hardened-execution` | `sha2::hardened_execution` | Explicit secret-bearing execution |
| `sha256-batch`, `sha512-batch` | `sha2::batch`, `sha2::batch512` | Ordinary public-data independent-message SIMD |
| `sha256-hardened-batch`, `sha512-hardened-batch` | `sha2::hardened_batch`, `sha2::hardened_batch512` | Distinct clearing batch owners |
| `sha3-static-execution`, `sha3-runtime-execution` | `sha3::execution` | Ordinary SHA-3/SHAKE/cSHAKE execution |
| `sha3-hardened-execution` | `sha3::hardened_execution` | Hardened SHA-3/SHAKE/cSHAKE owners |
| `keccak-batch`, `keccak-hardened-batch` | `sha3::batch`, `sha3::hardened_batch` | Distinct ordinary/clearing independent-state SIMD |
| `kmac-hardened-execution`, `kmac-runtime-execution` | `kmac::execution` | Hardened KMAC/KMACXOF |
| `tuplehash-hardened-execution`, `tuplehash-runtime-execution` | `tuplehash::execution` | Hardened TupleHash/TupleHashXOF |
| `parallelhash-hardened-execution`, `parallelhash-runtime-execution` | `parallelhash::execution` | Hardened serial/caller-scheduled ParallelHash/ParallelHashXOF |
| `parallelhash-hardened-batch` | `parallelhash::execution::batch` | Hardened grouped leaves; threading remains a hosted concern |

Byte/bit input, streaming, fixed/XOF output and general-t types retain the leaf
API contracts. A runtime feature permits importing a runtime authority; it
does not install a detector or select a backend automatically. The portable
flat functions remain portable even if another dependency enables execution.

## Explicit portable execution

With `sha2-hardened-execution`, select the ordinary or hardened type explicitly:

```rust
use brynja::crypto::sha2::{execution as ordinary, hardened_execution as hardened};
let result = ordinary::Sha256::hash(ordinary::Execution::portable(), b"abc").unwrap();
assert_eq!(result.digest, brynja::crypto::sha256(b"abc").unwrap());

let mut output = [0; 32];
{
    let secret = hardened::Sha256::hash_secret(
        hardened::Execution::portable(), b"private input", &mut output).unwrap();
    assert_eq!(secret.digest.expose().len(), 32);
}
assert_eq!(output, [0; 32]);
```

For leaf-only dependencies, select the leaf's corresponding feature and use
its crate name directly: for example `brynja-hash-sha2/hardened-execution` and
`brynja_hash_sha2::hardened_execution`. Reexports do not wrap or weaken owners.

```sh
cargo add brynja-hash-sha2 --path /path/to/brynja/crates/brynja-hash-sha2 --no-default-features --features hardened-execution
```

## Hosted and protected profiles stay separate

Use `brynja-crypto-cpu-std` for hosted CPU selection and operation-specific
preferred/required authorities, and `brynja-hash-parallel-std` for bounded
joined workers. Their features are independent opt-ins; the no_std facades
never activate them. See the [hosted adapter](../crates/brynja-crypto-cpu-std/README.md)
and [ParallelHash executor](../crates/brynja-hash-parallel-std/README.md) examples.
Required acceleration must reject when unavailable; a backend failure never
authorizes silent fallback. Static deployment must establish ISA support before
constructing authority. A Cargo feature alone is not that guarantee.

For example, enable `sha2-runtime-execution` on the facade and
`runtime-execution` on the separate hosted adapter. This ordinary public-data
example prefers Arm SHA-256 when available; only an explicit `None` session
selects portable execution. Construction/session errors are not fallback:

```sh
cargo add brynja --path /path/to/brynja/crates/brynja --no-default-features --features sha2-runtime-execution
cargo add brynja-crypto-cpu-std --path /path/to/brynja/crates/brynja-crypto-cpu-std --no-default-features --features runtime-execution
```

```rust
use brynja_crypto_cpu_std::execution::{Authority, Kernel, Mode};
use brynja::crypto::sha2::execution::{Execution, Sha256};
let authority = Authority::new(Kernel::ArmSha256, Mode::Prefer).unwrap();
let execution = match authority.session().unwrap() {
    Some(session) => Execution::from_runtime(session),
    None => Execution::portable(),
};
let result = Sha256::hash(execution, b"public input").unwrap();
assert_eq!(result.digest, brynja::crypto::sha256(b"public input").unwrap());
```

Use `Mode::Require` instead of `Mode::Prefer` when acceleration is mandatory;
treat a constructor/session error as operation failure, not permission to retry
portably. Use `Mode::Portable` (or `Execution::portable()` without the hosted
adapter) to force portable execution. These are per-operation selections, not
a global default. Production callers should propagate errors instead of the
examples' `unwrap()`.

Protected/resident profiles have different guarantees and platform limits;
they are not enabled by these execution features. For a protected-only API
surface use [brynja-strict](../crates/brynja-strict/README.md) and enforce your
application's dependency policy. Legacy SHA-1/MD5 must be selected from their
separate leaf/hosted packages, never through the modern facade.

For an explicit legacy-only dependency, for example:

```sh
cargo add brynja-legacy-sha1 --path /path/to/brynja/crates/brynja-legacy-sha1 --no-default-features --features hardened-execution
```

Use `brynja_legacy_sha1::hardened_execution` and its
[leaf examples](../crates/brynja-legacy-sha1/README.md); host selection remains
in [the separate legacy adapter](../crates/brynja-legacy-sha1-std/README.md).
Hardened storage does not repair SHA-1's broken collision resistance.

## Security and Cargo unification

Ordinary state/workspaces accept public data only and do not erase secret
remnants. Classification markers are caller assertions, not provenance checks.
Hardened APIs retain their bounded cleanup guarantees and documented residuals;
facade reachability is not independent verification, FIPS approval or a stronger
protection profile. Existing candidate backends retain their admission status.

Cargo features are additive across dependents, but these namespaces now use
explicit export lists and facade-owned feature gates. Enabling a leaf feature
elsewhere does not automatically add its module/free-function exports here.
Conformance-only free functions, standalone `hardened_in_place` modules and
setup-only types are not forwarded at facade namespace roots. Production
`in_place` APIs nested in opted-in execution modules remain available.
KMAC production types no longer acquire
conformance methods through feature unification: separate leaf-only types in
`brynja_mac_kmac::conformance` own those methods, including execution and scoped
workspaces/readers. Reexported types otherwise retain their inherent methods;
curation is not provenance
enforcement or a sandbox against direct leaf use.
Independent package tests exercise this deliberate unification and must not
rely on workspace-root feature activation.

The hidden `HardenedCshake*` in-place methods remain intentionally reachable:
cross-crate KMAC/TupleHash composition uses them to erase the exact embedded
source allocation. cSHAKE has no KMAC minimum-key/tag policy; these methods
neither construct a KMAC owner nor bypass its key/tag checks. They keep the
absorbing/squeezing/vacated lifecycle, typed secret output and explicit public
declassification. Finalization or wiping cannot reopen absorption. They are
not conformance-only methods and hiding module exports cannot hide inherent
methods. The packaged tests exercise both cSHAKE identities through each facade;
internal source-allocation clearing tests remain separate.

## Focused verification

`python3 scripts/repository/check-facade-package.py` packages and extracts the
modern closure, compiles isolated opt-ins for `x86_64-unknown-none`, checks
default isolation and rejects absent APIs. `--toolchain 1.90.0` checks the MSRV.
Every resolved package identity, version, manifest and source target is bound
to the extracted archives; checkout fallbacks, unknown local packages, native
link declarations, build scripts and proc macros are rejected.
Debug/release checks exercise portable output equivalence and clearing owners;
they do not stand in for native accelerated qualification or a full sweep.
Each facade runs ten combined family/batch tests, three hosted/documentation
tests, three portable Keccak oracle tests, four hosted/static Keccak tests and
four SHA-2 route/lifecycle tests per profile,
alongside the separate conformance-isolation checks. The harness rejects missing or ignored runtime tests and
compiles the Rust examples directly from this document.
The consumer and packaging phases run in private directories under the checkout's
`target`, rejecting inherited Cargo configuration before launching commands.
Separate extracted TLS/DTLS/QUIC consumers check their actual dependency closures
without removing CPU edges, including six real feature-activation mutants.

## Unpublished checkout identities

Internal tags retain support-crate development versions until the planned
publication checkpoint. They are not claims that modified checkout contents
match an already published crates.io archive of the same name/version. The
examples require explicit checkout paths; acceptance uses extracted local
archives and explicit patches. The repository SBOM describes that local graph,
not a checksum attestation for registry archives. Use the reviewed commit and
local archive provenance, not only name/version, to identify this candidate.
No publication is selected by this internal milestone.

## Batch consumer acceptance

The Keccak batch cases reuse the independent bit-level oracle for all eight
SHA-3/SHAKE/cSHAKE identities, including customized, partial-bit and zero-width
XOF cases. Ordinary output remains transactional; hardened secret destinations
clear on Drop and rejection; explicit public output and sparse layouts retain
their separate contracts. Compiled mutations must reach and fail the intended
runtime assertion, not merely fail to build. This original suite selects
portable execution. A separate hosted consumer now runs the same oracle and
lifecycle cases with preferred selection, plus the existing ordinary/hardened
CLI fixtures with portable, preferred and required selection. Required mode
must reject unavailable authority before output. On an available route all
256 mixed four-lane batches (1,024 independent outputs) execute through both
facades in debug and release. The hardened fixture checks secret, declassified
and public outputs, full staging clearing, output identity and canaries.

The opt-in SIMD campaign also checks a public static-session counter against
the ordinary executor report, then revokes the authority and confirms rejection
without output or counter changes. Six compiled Keccak mutations cover omitted
permutation, scalar replacement, incorrect vector reporting and omitted output
clearing. Correct digests alone cannot satisfy the scalar-replacement test.
These checks do not inspect private workspace/register erasure or establish
platform qualification; dedicated family checks retain that responsibility.

SHA-2 consumers reuse the existing ordinary/hardened batch fixtures with only
their imports redirected through each facade and a separate hosted adapter.
They compare 384 SHA-224/256 batches and 4,846 SHA-512-family batches against
independent expected outputs, including all valid general-t widths, sparse
slots and bit/padding boundaries. Portable and preferred modes use the full
corpus; required acceleration uses its eligible full-width subset or must
reject unavailable selection before producing any output. Twelve compiled
mutations check output, algorithm, work-accounting and clearing behavior.

For a local SIMD functional check, run
`python3 scripts/repository/check-facade-package.py --native-simd`.
After checking CPU support in a generic executable, it builds a separate
AVX2/NEON-specialized consumer, requires all four SHA-2 and both Keccak batch
routes to be available and checks positive vector counts. The six SHA-2
no-op/scalar-replacement mutations must fail the actual session-counter
invariant; Keccak mutations must fail their named runtime tests. Run this only where
the deployment preserves that ISA throughout execution; the initial CPU check
is not a live-migration guarantee. This option is not native release
qualification, independent review or a benchmark. The default command does
not request a specialized build; on supported Arm hosts the hosted APIs may
already select NEON in a generic build.

## TupleHash consumer acceptance

The same command now redirects the existing TupleHash execution fixture's
imports through each extracted facade and the separate hosted adapter. It
checks 268 independent cases: twelve official NIST examples and 256 generated
arbitrary-bit cases, with 67 cases for each fixed/XOF identity. Ordinary and
hardened outputs, fragmented items, mixed secret/public squeezing, scoped
accelerated workspaces, scratch clearing and authority revocation are checked.
Seven malformed inputs run both alone and after a valid request to ensure
rejection does not print partial results.

Portable and preferred-portable selection always run. Static required,
static preferred and hosted required selection must either execute with the
exact expected healthy route or fail with the probed unavailability reason.
Generic x86 hosted execution intentionally remains unavailable: an AVX2 build
does not supply a platform-wide migration guarantee. `--native-simd` also
requires the compiled TupleHash route, using AVX2 on x86 or the complete
NEON/SHA2/SHA3 bundle on Arm after a generic capability probe. More cores or
an available batch NEON route alone do not establish that Arm bundle.

Each profile runs six existing execution lifecycle tests and one compiled-
authority rejection test; a supported static build additionally runs six
scoped fixed/XOF tests. There are 128 compiled trait, ownership and
classification rejections per facade. Four framing/domain/update mutants,
one borrowed-scratch cleanup mutant and an opt-in scalar-fallback mutant
test the checks themselves. The scalar-fallback mutant must reject in both
required and preferred modes, despite retaining a working portable algorithm.

TupleHash exposes route/health reports, not a public permutation counter.
This consumer checks those reports and output/lifecycle behavior; it does not
claim a new instruction-count observation, private-frame cleanup inspection,
independent review or multi-platform native qualification.

## ParallelHash threaded batch consumer acceptance

The separate `brynja-hash-parallel-std` adapter is explicitly opted in by the
consumer, not pulled into either facade's defaults. Its own archive is bound
to the same isolated local-package graph. The consumer uses facade-exported
ParallelHash identities and bit inputs with the adapter's public owned and
scoped threaded batch executors; no workspace dependency or evidence cfg can
satisfy a missing facade export.

The existing threaded fixture runs 256 independent arbitrary-bit cases (64
per fixed/XOF identity) with one and three workers, in debug and release.
It checks public/secret equality, canaries, scratch and output Drop clearing,
leaf/group/thread accounting and reported vector work. Portable and preferred
selection use the complete corpus. Required selection uses 48 nonempty cases
aligned to both supported SIMD widths, and separately rejects an incomplete
group instead of silently using a scalar tail. Unavailable required authority
must reject before any output. The explicit local SIMD option enables AVX2 or
NEON only after a generic host probe. Root hashing stays portable here; this
is not accelerated-root or private worker-frame qualification.

Two additional lifecycle tests cover cancellation, zero work budget, leaf
limits, invalid block/bit sizes, undersized scratch and executor reuse after
failure across all four identities and both executor forms. Public errors
preserve the destination, secret errors clear it and scratch clears only its
supplied region. Twenty-five compiled trait negatives cover facade-exported
collectors, readers, streams and workspaces. Compiled mutants verify secret
error clearing, public copying and (with SIMD) worker vector accounting.

The fixture's separate local/scoped-root executable imports deliberately
hidden leaf-only APIs and is not redirected or silently claimed as covered.
Further family/route reconciliation and independent retest remain pending.

## ParallelHash execution and scoped-root consumer acceptance

A separate extracted consumer redirects the existing scheduled, streaming and
threaded execution drivers through both facades and explicitly opted-in hosted
adapters. It checks the same 256 independent arbitrary-bit cases across all
four fixed/XOF identities in debug and release. Thirteen requested modes cover
portable, preferred, required and static selection; unsupported required modes
must reject with the probed reason before output. Six malformed requests run
alone and after a valid request to check transactional campaign output.

Each profile runs nineteen execution/stream/threaded lifecycle tests. An
available static route additionally runs twelve scoped accelerated tests and
the fixture's scoped streaming/scheduled checks for every corpus case in each
of its three static modes. These include accelerated roots, unlike the separate
threaded batch campaign above. On generic x86 the hosted migration guarantee
remains unavailable, including in an AVX2-specialized build.

Two synthetic reference computations in the copied scoped tests use curated
ordinary public APIs instead of deliberately hidden portable in-place helpers.
The accelerated assertions are retained; this is not coverage of those hidden
APIs or a claim that ordinary reference storage clears confidential data.
Three framing/domain mutants, two cleanup mutants and an opt-in forced-scalar
mutant must be caught after successful compilation. The scalar substitution
must fail the root, stream and threaded route checks before output. Public
route reports are not new instruction-count or private-frame observations.
These remain local functional checks, not independent or native qualification.

## Ordinary SHA-3/SHAKE/cSHAKE consumer acceptance

The same command runs the existing single-state fixture through both extracted
facades and a separately opted-in hosted `sponge-execution` adapter. All source
modules and vector files used by the copied integration tests come from the
extracted SHA-3 archive, not a workspace dependency. SHA-3/SHAKE uses 76 NIST
vectors and 1,008 additional comparisons with the portable implementation;
cSHAKE uses four NIST examples and 624 independent bit-oracle cases. The latter
includes arbitrary-bit function names, customization and messages, empty N/S
SHAKE equivalence, partial output and rate boundaries.

Debug/release consumers check one-shot and fragmented streaming execution,
setup/work accounting, short-scratch rejection and output atomicity. Portable,
hosted preferred, hosted required and static required modes must match the
probed route or reject exact unavailability before printing a success result.
Six copied integration tests additionally exercise public byte entry points,
wrong-operation rejection and quarantine. Their static-only branches run in
the explicit native build; the generic build does not qualify those branches.

Each facade compiles 48 raw-input rejections with explicit-public-marker
controls, 70 trait rejections with positive type-existence controls and seven
marker/ownership/authority bypass rejections. This enforces explicit caller
classification, not data provenance. These ordinary owners do not promise
secret-memory erasure and must not receive confidential data.

Eleven compiled mutations cover permutation, domain separation, output/state
commit, reported work and final-bit masking. Native checks additionally reject
a skipped static permutation and a correct-output portable route downgrade.
The work reports count execution-layer operations; they are not an independent
CPU-instruction witness, nor proof against a scalar replacement that also
forges its route report. Family code-generation/native checks retain that
responsibility. This is local functional acceptance, not a hardened-owner
review, new native qualification or independent cryptographic verification.

## Single-state SHA-2 consumer acceptance

Both extracted facades also run the existing ordinary and hardened SHA-2
execution fixtures. The named corpus contains 240 NIST bit-vector cases; the
independent general-t corpus contains 4,590 cases across all 510 valid widths.
Vector files come from the extracted SHA-2 archive. The existing bounded
general-t corpus visitor is reused without changing its parsing logic.

Debug/release consumers exercise one-shot and fragmented updates, partial-bit
finalization, work accounting and hardened secret/public output behavior.
Portable, preferred, static and hosted requests include separate narrow-only
selection, so unavailable SHA-512 instructions do not hide usable SHA-224/256
execution. Exact availability errors are required before success output.
Five copied ordinary lifecycle tests and two corpus-parser tests run per
profile; hardened output clearing and quarantine checks remain in the
existing hardened fixture. Scoped/in-place owners are not covered by this slice.

Each facade rejects 50 ordinary and 52 hardened ownership/classification
probes. Six ordinary and eight hardened compiled mutations cover compression,
input, padding, IV, commit, accounting, output masking and error-path clearing.
The opt-in native campaign also rejects omitted compression and reported
portable substitution. It requires SHA-224/256 instructions and enables
dedicated SHA-512 only when the CPU probe reports the complete feature bundle.
On a host without that bundle, required SHA-512 rejects instead of being
counted as accelerated coverage. Route/work reports are not independent
instruction counters. These are functional acceptance tests, not new native,
register-cleanup or independent cryptographic qualification.

## Production KMAC/KMACXOF consumer acceptance

Both extracted facades run all four KMAC/KMACXOF identities against twelve
official examples and 256 cases generated with the existing independent
SP 800-185 oracle. The latter retain arbitrary-bit customization/messages and
rate-boundary inputs, but use full-strength production keys and fixed tags;
XOF outputs still include empty, short, partial-bit and rate-crossing cases.
This is a production corpus, not a claim that the facade accepts every
standards-valid weak-key conformance vector.

The existing fixture is adapted by exact source anchors to call production
constructors and finalizers. No conformance feature, test owner or direct leaf
dependency is enabled. Seventeen malformed/weak-key/short-tag requests must
reject with exact errors and no partial output, including after a valid case.
Portable, preferred, required static and hosted selection are checked in debug
and release. Hosted unavailability is not treated as accelerated coverage.

Seven production lifecycle tests cover transactionality, secret-output Drop,
terminal/forgotten readers, verification and recoverable unwinding. Available
static builds add four scoped lifecycle tests and per-case fixed/XOF scoped
checks, including caller scratch, mixed output and revocation. The separate
test-owner integration test is deliberately omitted from these consumers;
conformance isolation remains tested by the preceding facade checks. One
scoped weak-key probe is adapted from a test owner to production rejection
at scope entry. Hidden portable in-place helpers remain outside facade scope.

Each facade rejects 88 compiled ownership/classification probes. Four compiled
domain/update/suffix/comparison mutants and a borrowed-scratch cleanup mutant
exercise the generic checks. Native runs additionally reject a scoped-scratch
cleanup mutant with both fixed and XOF tests, and a portable substitution in
required/preferred modes. Source restoration and pristine reruns are required.
Route observations are not independent instruction or private-frame witnesses.
This adds functional acceptance, not native or independent qualification.

## Hardened SHA-3/SHAKE/cSHAKE consumer acceptance

Both extracted facades use `sha3-hardened-execution` and
`sha3-runtime-execution`, plus the separate hosted adapter, without a direct
hash-leaf dependency or conformance feature. Eight hardened identities run
76 recorded NIST cases and 628 cSHAKE official/independent bit-oracle cases.
Every case exercises owned and scoped APIs with secret and explicitly
declassified public output. Input is fragmented, N/S and message tails retain
arbitrary bits, and XOF reads cross rate boundaries with partial final output.
Secret-output Drop and caller scratch clearing are checked after comparison.

The copied leaf integration tests add fixed padding boundaries, mixed output,
cancel/revocation behavior and a seeded 64-case, four-identity operation
campaign. Those differential checks use the portable implementation as their
reference; they are not a second independent oracle. Additional scoped tests
exercise invalid widths, inadequate scratch, terminal output failures,
forgotten readers, recoverable unwinding, reuse and quarantine. They inspect
publicly observable output/reuse behavior, not private workspace bytes.

Required static and hosted sessions must expose the expected kernel and healthy
authority before processing. Each available route runs debug/release tests;
an unavailable route runs only its exact admission-rejection test after the
full suite compiles. It never counts an early-return kernel test as execution.
The explicit native option requires the locally supported AVX2 or Arm bundle.

Each facade rejects 158 compiled trait, ownership, scope-escape and output-
classification violations, with positive type checks and expected diagnostics.
Five native compiled mutants remove/change the permutation, fixed domain,
scoped public-output commit, borrowed scratch clearing or scoped partial-bit
mask. They must compile and then fail the named runtime test; compiler errors
and unrelated process failures are not accepted as mutation evidence.
Extracted sources restore on all exits and pristine tests repeat afterward.

This is functional consumer acceptance, not native release qualification,
independent instruction counting, private-frame cleanup proof or certification.
Production code, original fixtures and historical captures remain unchanged.

## Scoped SHA-2 consumer acceptance

The extracted facades also exercise `sha2::hardened_execution::in_place`:
all six named hashes and every valid general SHA-512/t parameter. The named
corpus retains 240 NIST bit-vector cases; the existing bounded general-t
visitor supplies 4,590 independent expected-output cases. No second oracle
or hash implementation is introduced. Portable, hosted preferred/required
and static required modes use the same selection probe as single-state SHA-2.
Narrow-only accelerated runs explicitly retain portable wide hashing; they
do not count missing dedicated SHA-512 support as native execution.

Debug/release runs compare secret and explicitly declassified public outputs,
byte and bit finalization, fragmented updates and workspace reuse. Checks
retain exact general-t parameter identity, final-bit masking, route, message
and padding counts, and portable IV-derivation accounting. Secret outputs
outlive the callback and clear their destinations on Drop.

Lifecycle checks cover the six named workspaces and five representative
general-t widths. Wrong secret-output sizes clear the supplied destination;
wrong named public-output sizes preserve it. Each cancellation, dropped or
forgotten handle and recoverable unwind is followed by a fresh known-result
computation. Available accelerated owners additionally exercise revocation
before update and finalization, terminal reuse, skipped callbacks after
revocation and wrong-family admission. Revocation populations are checked
against the actual narrow/wide routes. These observations do not expose or
prove private workspace/register clearing; existing low-level checks remain
separate obligations.

Each facade rejects 102 compiled trait, lifetime, scope, output-classification
and intermediate length/preflight-query probes. Six compiled mutants test
named/general IV initialization, general output masking, scoped public-copy
commit, per-scope work-counter reset and wrong-size secret-output clearing.
Native checks additionally reject omitted CPU compression and portable
substitution under required selection. Mutants must compile and produce the
fixture's exact mismatch error; unrelated failures are not accepted. Sources
restore on all exits and pristine corpus/lifecycle checks repeat afterward.

Hidden leaf-only portable in-place APIs are not exported by these facades and
are not claimed here. This adds public functional acceptance, not native
release collection, independent instruction counts or new qualification.

## Isolated ordinary legacy consumer acceptance

SHA-1 and MD5 stay outside both modern facades. The packaged acceptance command
also runs separate consumers of `brynja-legacy-sha1`/`brynja-legacy-sha1-std` and
`brynja-legacy-md5`/`brynja-legacy-md5-std`, each with ordinary execution enabled
explicitly. Their enabled graphs contain only the selected legacy pair, core
and hash-core; optional manifest edges are resolved using real archives but
must not activate modern cryptography, protected profiles or the other legacy
family. Resolved identities and source targets must match the extracted archives.

To run just this slice locally:

```sh
python3 scripts/repository/check-legacy-execution-package.py --toolchain 1.99.1
python3 scripts/repository/check-legacy-execution-package.py --toolchain 1.99.1 --native-simd
```

Both commands use a private config-free Cargo environment. The native opt-in
requires a detected SHA-NI/AVX2 or Arm SHA-1/NEON bundle before compiling for it;
missing support fails rather than passing a skipped native campaign. This is
ordinary public-data acceptance, not permission to use these collision-broken
algorithms for new security protocols or confidential data.

Debug/release checks reuse the archived public integration tests, the SHA-1
529-vector NIST population and 1,135-message independent bit oracle, and MD5's
2,048 mask/tail cases plus 384 independent eight-lane batches. The required MD5
oracle subset contains 128 eligible batches on the tested AVX2 lane. Portable,
preferred and required selection, hosted availability, streaming, revocation,
transactional output and exact SIMD/scalar work counts are checked. SHA-1's
x86 hosted route remains unavailable even in a SHA-NI-specialized binary;
MD5 can use its compiled AVX2 bundle through the hosted adapter.

Compile-fail probes reject 18 SHA-1 and 13 MD5 ownership, authority-entry and
public-classification misuses. Two SHA-1 revocation/finalization mutations and
four MD5 output/report mutations run in both profiles. Native runs additionally
reject SHA-1 portable substitution and MD5 vector omission/scalar substitution.
Each mutant must compile and fail a runtime assertion; sources restore on all
exits and pristine public tests repeat. These checks do not claim hardened,
strict or resident-owner coverage; those existing suites remain separate and
their v0.24.53 reconciliation is pending.
