# v0.24.53 - Acceleration Public Consumer Acceptance

Status: development in progress; not release-qualified. No publication selected.

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
