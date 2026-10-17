# v0.24.53 - Acceleration Public Consumer Acceptance

Status: development in progress; not release-qualified. No publication selected.

## Portable KMAC conformance separation

The four portable KMAC/KMACXOF production states no longer acquire inherent
conformance methods when another dependency enables `conformance-testing`.
Distinct concrete types under `brynja_mac_kmac::conformance` share the existing
core, parameter checks and cleanup; there is no conversion back to production
states. Production constructors, algorithms and outputs are unchanged.

This deliberately changes the pre-1.0 test API: qualify portable weak-parameter
constructors with `conformance::`, rather than calling them on production
`Kmac128/256` or `KmacXof128/256`. Explicit leaf one-shot conformance helpers
remain available. Neither facade reexports the conformance module or helpers.
Package-external negative tests cover every removed inherent method through
the direct leaf, flat facade and namespaced facade under additive features.

## Work remaining before retest and acceptance freeze

- Separate execution and scoped in-place conformance states/workspaces; review
  related hidden cSHAKE integration methods without removing required hardened
  integration. The portable change alone does not close v0.24.52 F-1.
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
capture is changed by the initial portable separation. Independent verification
and FIPS validation remain separate, unclaimed qualifications.
