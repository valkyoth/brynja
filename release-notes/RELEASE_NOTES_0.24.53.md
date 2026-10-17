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
