# Brynja v0.24.47

Development in progress: ordinary Keccak multibuffer SIMD and local-first
standards observation. Not released; no crates selected for publication.

## Completed development work

- Added default-off ordinary independent-state Keccak SIMD: four AVX2 lanes
  and two NEON lanes, separate from single-state Keccak acceleration.
- Added bounded SHA-3/SHAKE/cSHAKE batch APIs with independent byte/bit framing,
  finite XOF outputs, arbitrary-bit cSHAKE N/S, mixed-domain groups, scalar tails,
  checked work controls and transactional caller-owned output staging.
- Added an optional hosted adapter, explicit portable/prefer/require selection,
  and owner-local quarantine with ordinary request-failure reuse.
- Development tests cover portable/native-AVX2 differential comparisons,
  emulated NEON, packaged consumers, negative ownership and compiled mutants.
- Added a 128-case end-to-end portable/vector benchmark, exact AVX2/NEON
  emitted-code inspection and native evidence collection with coverage checks.
- Integrated the new budget proof, focused Miri and enforced ASan/LeakSanitizer
  into the existing SHA-3 family. No release approval or publication rule changed.
- The optional local-first authority observer requires hash-verified local
  copies of all locked documents before checking upstream content.
- Transport outages may retain the reviewed document, but explicitly report
  remote freshness as unverified. Changed bytes, missing/corrupt local files,
  redirects, malformed responses and prior unresolved reviews remain blockers.
- Local files stay under the ignored `references/local/authority-cache` path.
  Existing committed RFC/IANA fixtures remain unchanged. No network response
  silently replaces a reviewed local file or its hash.
- The release observer opts into this behavior. The scheduled monitor remains
  strict, and offline results cannot renew successful-live-observation receipts.

## Pending milestone work

Native correctness/performance qualification, exceptional pentest and final
release verification are not complete yet.
Existing single-state acceleration is not a substitute. See the
[batch contract](../docs/keccak-batch-execution.md) for the new API boundaries.

No independent cryptographic review, FIPS validation, secret-bearing multibuffer
support or military-deployment approval is claimed. Hardened batching remains
the separate v0.24.48 milestone.
