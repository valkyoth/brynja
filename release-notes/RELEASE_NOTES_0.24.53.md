# v0.24.53 - Acceleration Public Consumer Acceptance

Status: development in progress; not release-qualified. No publication selected.

## ParallelHash threaded consumer acceptance

Both extracted facades now run the existing threaded ParallelHash batch fixture
with a separately opted-in, archive-bound `brynja-hash-parallel-std` adapter.
The 256 independent arbitrary-bit cases cover all four identities, public and
secret outputs, owned and scoped executors, canaries, output/scratch clearing,
leaf order and group/thread/vector accounting with one and three workers.
Required SIMD uses 48 lane-aligned cases and rejects incomplete groups; generic
unavailable authority fails before output. The local SIMD option is functional
acceptance, not new native qualification, and the root remains portable.

Additional downstream lifecycle tests cover cancellation, work/leaf limits,
invalid block/bit sizes, scratch bounds and reuse after rejection. Twenty-five
compiled ownership negatives per facade and compiled output-copy, cleanup and
vector-report mutations check enforcement. The threaded adapter remains absent
from default/no_std facade consumers; no production feature graph or release
gate changes. Serial/accelerated-root and deliberately hidden leaf-only scoped
route reconciliation, wider families and independent retest remain pending.

## KMAC conformance separation

The four KMAC/KMACXOF identities' production states no longer acquire inherent
conformance methods when another dependency enables `conformance-testing`.
Distinct concrete types under `brynja_mac_kmac::conformance` share the existing
core, parameter checks and cleanup; there is no conversion back to production
states. This covers portable, execution and scoped in-place owners, workspaces
and readers. Production constructors, algorithms and outputs are unchanged.

This deliberately changes the pre-1.0 test API: qualify weak-parameter
constructors with `conformance::`, rather than calling them on production
`Kmac128/256` or `KmacXof128/256`. Explicit leaf one-shot conformance helpers
remain available. Neither facade reexports the conformance module or helpers.
Package-external negative tests cover every removed inherent method through
the direct leaf, flat facade and namespaced facade under additive features.

Migrate execution tests to `conformance::execution`, portable scoped tests to
`conformance::hardened_in_place`, and accelerated scoped tests to
`conformance::execution::in_place`. Test execution types still require the
same execution authority; they do not implement the production-only
`execution::HardenedState` trait. The same private core and cleanup macros serve
both type families; no cryptographic implementation is duplicated.

Hidden cSHAKE composition methods remain available on reexported types because
cross-crate hardened compositions use their exact-source clearing transitions.
The separate review found no KMAC key/tag-policy bypass through those methods:
they cannot create or convert into a KMAC owner. Their lifecycle and public/
secret classification are checked through each packaged facade. This is not
an assertion that facade curation can hide inherent methods or prevent callers
from implementing their own protocol over lower-level cSHAKE.

## Packaged Keccak batch consumers

Both extracted facades now reuse the independent bit-level Keccak batch oracle:
256 mixed four-lane batches, 1,024 expected outputs across all eight
SHA-3/SHAKE/cSHAKE identities. Ordinary, hardened-secret and explicitly public
hardened outputs cover partial bits, customization, zero-width XOF outputs and
rate boundaries. Checks include sparse public layouts, exact identities and
bit lengths, work accounting, cancellation/budget rejection, subsequent reuse,
quarantine, explicit declassification, destination canaries and clearing of
secret outputs and staging.

Five compiled mutations verify detection of omitted/partial output commits,
incorrect work reports, omitted secret-output clearing and omitted final-bit
masking. Harness regressions reject missing populations and compiler failures
masquerading as successful mutation rejection. This extends the existing
acceptance command; it adds no release gate, dependency or production change.
These consumers force portable execution and do not establish native SIMD
execution or inspection of private workspace memory.

## Packaged SHA-2 batch consumers

Both facades now run the existing ordinary and hardened SHA-2 batch fixtures
against extracted archives, with a separately opted-in hosted adapter. The
independent corpora cover 384 SHA-224/256 batches and 4,846 SHA-512-family
batches, including every valid SHA-512/t width, sparse masks and bit/padding
boundaries. Secret identity/width, explicit declassification, public output,
Drop clearing, work accounting, cancellation, budget rejection and subsequent
reuse are checked without copying a cryptographic implementation.

Portable/preferred selection is exercised with the full corpus; required
selection receives eligible full-width groups or must reject unavailability
without output. Four additional lifecycle tests cover selection and quarantine.
Twelve compiled output/algorithm/report/cleanup mutations and six opt-in SIMD
no-op/scalar-substitution mutations prevent vacuous acceptance.

`check-facade-package.py --native-simd` additionally requests a host-capability-
checked AVX2/NEON build with positive vector counters. This is local functional
acceptance, not refreshed native release qualification. The usual command,
gate rules, historical evidence and full-sweep deferral remain unchanged.

## Packaged hosted/static Keccak consumers

The packaged Keccak coverage now also exercises the existing ordinary/hardened
CLI fixtures through both facades with portable, preferred and required hosted
selection. Each profile compares 256 four-lane batches against 1,024 independent
SHA-3/SHAKE/cSHAKE outputs; unavailability must reject before output. Preferred
lifecycle tests preserve cancellation, budget, reuse, staging and public/secret
failure checks, including sparse layouts. A public static-session witness
checks actual backend-call counts against the executor report and verifies
revocation. Six compiled SIMD/output/report/cleanup mutations include a scalar
replacement that retains correct digests but fails the counter witness.

`--native-simd` now requires both Keccak routes as well as all four SHA-2
routes. This adds local functional acceptance, not new native qualification,
production behavior or release-gate policy.

## Packaged TupleHash consumers

Both facade paths now reuse the existing TupleHash execution fixture and its
268-case independent oracle (twelve official examples plus 256 generated
arbitrary-bit cases). It exercises all four fixed/XOF identities through
ordinary/hardened owners, fragmented item writers, mixed secret/public output,
scoped accelerated workspaces and revocation. Static/preferred/hosted routes
must execute as selected or reject exact unavailability before output. Seven
malformed requests also follow a valid case to check atomic campaign output.

The separate existing execution and scoped integration tests run from the
extracted consumer. Both facades reject 128 compiled ownership/classification
probes, four algorithm mutants and one scratch-clearing mutant. The opt-in
accelerated campaign additionally rejects a forced portable substitution in
required and preferred modes. No production behavior or gate policy changes;
route reports do not become instruction-count or native-qualification claims.

## Packaged ParallelHash execution and scoped roots

Both facades now run scheduled, streaming and threaded single-state execution
against the 256-case independent arbitrary-bit corpus in debug and release.
Thirteen requested modes either execute their expected route or reject exact
unavailability before output. Nineteen lifecycle tests run per profile; an
available static route adds twelve scoped tests and per-case accelerated
streaming/scheduled-root checks. The separate threaded batch coverage retains
its portable root; this new slice covers accelerated roots explicitly.

Three framing/domain mutations, two cleanup mutations and an opt-in scalar
substitution test the acceptance checks. Two synthetic portable references in
the copied scoped tests are adapted to curated public APIs without exposing
hidden leaf helpers or changing the accelerated assertions. This is functional
acceptance only, not instruction-count, private-frame or native qualification.
No production implementation, dependency or release-gate policy changes.

## Packaged ordinary SHA-3/SHAKE/cSHAKE consumers

The existing single-state fixture now runs through both extracted facades and
an explicitly selected hosted sponge adapter. Its 1,084 SHA-3/SHAKE cases
comprise 76 NIST vectors and 1,008 portable-reference comparisons; its 628
cSHAKE cases comprise four NIST examples and 624 independent bit-oracle cases.
Debug/release profiles check byte/bit and streaming/XOF behavior, setup/work
accounting, output atomicity, six lifecycle tests and exact static/hosted
availability. Each facade rejects 125 classification/ownership misuse probes.

Eleven compiled algorithm/output/state/accounting mutants and two native
no-op/portable-downgrade mutants test the checks. Work/route observations are
not independent instruction counters. These are public-only non-erasing
owners, not hardened secret owners or new qualification. Production code,
dependencies, historical evidence and release-gate policy are unchanged.

## Packaged ordinary/hardened single-state SHA-2 consumers

Both facades now reuse the existing execution fixtures with 240 NIST named
bit-vector cases and 4,590 independent general-t cases across all valid widths.
Debug/release profiles cover one-shot/fragmented updates, partial bits, work
accounting and hardened public/secret output behavior. Six requested mode
combinations require the expected narrow/wide route or exact unavailability.
Five ordinary lifecycle tests and two parser tests also run per profile.

Each facade rejects 50 ordinary and 52 hardened ownership/classification
probes, six ordinary and eight hardened algorithm/output/accounting mutants,
plus opt-in native no-op and portable-downgrade mutants. Dedicated SHA-512 is
executed only on capable hosts; unavailable selection is not accelerated
coverage. This slice does not cover scoped/in-place SHA-2 owners or provide
independent instruction counts, cleanup qualification or native release
evidence. Production code, dependencies and gate rules are unchanged.

## Packaged production KMAC/KMACXOF consumers

Both facades now run twelve official examples and 256 independent oracle cases
through production execution APIs, with full-strength keys and fixed tags.
The corpus retains partial-bit and rate-boundary cases; XOF output includes
zero/short lengths. Exact source adaptations replace test-conformance calls
without enabling the conformance feature or exporting its owners.

Debug/release runs cover portable/preferred/required routes, seven lifecycle
tests and seventeen malformed or weak-input rejections with atomic output.
Native static builds add four scoped lifecycle tests and per-case scoped
fixed/XOF checks. Each facade rejects 88 ownership/classification probes,
four algorithm/comparison mutants and a borrowed-scratch cleanup mutant.
Native checks also reject scoped-scratch cleanup and portable substitution.
These functional checks do not qualify private-frame cleanup or native
platforms. Production implementations and release-gate rules are unchanged.

## Packaged hardened SHA-3/SHAKE/cSHAKE consumers

Both facades now run 76 recorded NIST bit vectors and 628 cSHAKE official/
independent-oracle cases through owned and scoped hardened APIs, exercising
all eight identities with secret and explicitly declassified public output.
Fragmented input, arbitrary-bit prefixes/tails, empty output and rate-crossing
reads retain exact expected results and observable destination/scratch cleanup.

Copied leaf lifecycle tests and a deterministic 64-case/four-identity property
campaign supplement the independent vectors. Scoped tests add invalid output,
forgotten-reader reuse, recoverable unwind and terminal authority revocation.
Each facade rejects 158 compiled ownership/classification/scope probes. Native
checks also reject five compiled domain, permutation, scoped-copy, scratch-
clearing and partial-output-mask mutations, then repeat pristine checks.

Static and hosted required routes either execute in debug/release or reject
the exact unavailable reason. Unavailable lanes compile the complete tests
but run only admission checks; they are not accelerated execution evidence.
These consumer checks do not inspect private storage/registers or establish
independent instruction counts, native qualification or certification.
No production implementation, dependency or release-gate policy is changed.

## Packaged scoped SHA-2 consumers

Both facades now exercise named and general-t scoped workspaces using the
existing 240 NIST and 4,590 independent general-t cases. Secret/public outputs,
parameter and route identity, work counts, arbitrary-bit tails, fragmented
updates and reuse are checked in debug/release across the selected modes.

Eleven lifecycle identities cover all six named workspaces and five general-t
widths: wrong-size output, cancellation, Drop, forgotten handles, recoverable
unwind and fresh known-result reuse. Available accelerated routes also test
terminal revocation, destination guarantees, callback rejection and wrong
kernel-family admission. Narrow-only runs explicitly use portable wide hashing.

Each facade rejects 102 compiled ownership/scope/classification/metadata probes
and six observable IV/masking/copy/accounting/output-clearing mutants. Native
checks also reject CPU no-ops and portable substitution. Private-memory and
register-cleanup qualification remain separate; no production implementation,
dependency, gate or historical evidence was changed.

## Isolated ordinary legacy consumers

Separate packaged SHA-1 and MD5 consumers retain legacy-only opt-in graphs;
neither family is exported from the modern facades. Their archive-bound graphs
reject unexpected feature activation, source paths and external dependencies.
Fresh private Cargo environments prevent ambient configuration from selecting
workspace sources instead of the extracted packages.

Debug/release acceptance reuses existing public tests and independent oracles:
529 SHA-1 NIST vectors, 1,135 SHA-1 bit messages, 2,048 MD5 mask/tail cases and
384 independent MD5 batches. Exact test populations, required-route admission,
hosted/compiled distinctions, revocation, transactional output and work counts
are enforced. The optional native campaign requires the actual CPU bundle.

The consumers reject 18 SHA-1 and 13 MD5 ownership/authority/classification
misuses. Compiled mutations cover revocation, finalization, missing/partial
output, incorrect work counts, native no-op and portable substitution. Existing
legacy package/native helpers remain unchanged. Hardened consumers are covered
below; protected-platform reconciliation is still pending. No production
implementation or gate changes.

## Isolated hardened legacy consumers

Separate SHA-1 and MD5 hardened package consumers now reuse their public
owned/scoped integration tests and independent corpora. Exact dependency and
feature graphs prevent ordinary/evidence/protected profile substitution.
Portable, compiled and hosted selection remain distinct, and native opt-in
requires detected SHA-NI/AVX2 or the corresponding Arm feature bundle.

Debug/release checks exercise secret/public outputs, bit/byte and streaming
behavior, exact work, output Drop, cancellation, forgotten handles, reuse,
recoverable unwind and quarantine. Scoped failure cases cover wrong-size SHA-1
output and every insufficient MD5 compression budget, checking complete secret
clearing, unchanged public output and healthy executor reuse after rejection.

The profiles reject 34 SHA-1 and 31 MD5 compiled ownership/scope/classification
misuses. Seven SHA-1 and eight MD5 generic mutations, plus one SHA-1 and two MD5
native mutations, verify observable output, guard, quarantine and route checks.
Private-memory/register erasure and protected-platform qualification remain
separate; no production, dependency, gate or historical-capture change.

## Linux protected legacy consumers

A separate opt-in package-external command now covers protected GNU/Linux
SHA-1/MD5 consumers without folding platform requirements into portable checks.
Exact archive/feature graphs retain the required protected-memory support chain
and reject unrelated ordinary, resident or evidence features.

The existing 169-message independent bit corpus covers scalar SHA-1/MD5 and
required SHA-1; MD5 SIMD checks 712 ordered lanes and exact work reports.
Debug/release checks include public declassification, request/resource failures,
forgotten output, caller-unwind reuse and explicit quarantine. Twenty-two SHA-1
and twenty-eight MD5 compiled negatives enforce public ownership/lifetime bounds.
Compiled absorption/output/width/quarantine mutations validate the test paths.

This is public functional acceptance, not private-memory erasure proof, a new
native qualification or Windows/macOS coverage. Original protected-profile
checks, production code, historical captures and release gates remain unchanged.

## Apple Silicon resident legacy consumers

A separate native Mac command now tests the public resident SHA-1/MD5 APIs
against the same independent bit corpus and lifetime/ownership cases. It requires
the resident-only graph and markers, mutates only extracted resident sources and
rejects cross-profile substitution. Linux strict dependencies and guarantees do
not transfer to this profile; core-dump exclusion is explicitly not claimed.

Compiled route expectations now use the selected compiler's effective features,
not an OS-name assumption. This fixes a harness mismatch exposed by Apple's
baseline SHA support without changing the library or treating skipped execution
as a pass. Both generic and explicitly accelerated builds remain checked.

## Strict modern scalar public consumer

A new opt-in extracted-package consumer imports the strict-only facade with
defaults disabled. Its exact feature graph prevents ordinary, resident,
conformance or hidden acceleration substitution. Debug/release tests cover
6,004 recorded/independent cases across named/general-t SHA-2, SHA-3, SHAKE,
cSHAKE, KMAC/KMACXOF and TupleHash/XOF, including every valid general-t width.

Public lifecycle checks exercise work/cancellation rejection, bit/weak-input
validation, borrowed and explicit public output, wrong-size preservation,
forgotten loans and caller-unwind reuse. Fifty-six compiled negatives and sixteen
budget/cancellation/output mutations (both profiles) validate observable tests.
No private-memory erasure, batch/accelerated execution or platform qualification
is inferred. Production code, dependency manifests and release gates are unchanged.

## Strict compiled public consumers

Separate strict-facade consumers partition the recorded/independent corpus by
narrow SHA-2, wide SHA-2 and Keccak-family routes. Exact dependency/features,
compiler target bundles and CPU/OS probes prevent hidden feature unification
or mistaken static admission. Unavailable routes are compiled and checked for
specific rejection, explicitly not counted as corpus execution.

Available routes check exact kernel identity, output/bit behavior, request
rejection, healthy reuse and irreversible quarantine. Fifty-two compiled
negatives cover ownership, lifetimes and explicit declassification. Worker
absorption/transfer and quarantine mutations must fail selected runtime tests.
Local SHA-NI/AVX2 execution passes; dedicated x86 SHA-512 and Arm execution by
this new consumer remain pending. No production or gate behavior changed.

## Work remaining before retest and acceptance freeze

- Obtain independent retest of the complete conformance separation before
  closing v0.24.52 F-1; author checks alone do not close it.
- Complete package-external route/operation coverage across all planned modern
  and isolated legacy families, including compiled behavioral mutants and
  ownership/output/error guarantees.
- Reconcile affected source policies, compiler checks and current acceptance
  records, then obtain the required independent pentest/retest.
- Run focused checks, ordinary CI and non-sweep release checks. The owner has
  deferred the additional full sweep to v0.24.55; this does not qualify changed
  implementations using historical native records. Native collection remains
  scheduled for v0.24.54 with the final reconciliation at v0.24.55.

No production kernel, unsafe block, dependency, release-gate rule or historical
capture is changed by the conformance separation. Independent verification
and FIPS validation remain separate, unclaimed qualifications.
