# Brynja v0.24.47

Development in progress: ordinary Keccak multibuffer SIMD and local-first
standards observation. Not released; no crates selected for publication.

## Completed development work

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

Independent-state AVX2/NEON Keccak kernels, public SHA-3/SHAKE/cSHAKE batch APIs,
packaged oracle/mutation campaigns, native correctness/performance qualification,
pentest and final release verification are not complete yet. Existing single-state
acceleration is not a substitute. No new production cryptographic API is claimed
by the standards-tooling work.

No independent cryptographic review, FIPS validation, secret-bearing multibuffer
support or military-deployment approval is claimed. Hardened batching remains
the separate v0.24.48 milestone.
