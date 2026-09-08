# Brynja v0.24.28

Status: implementation candidate; awaiting owner pentest.

## Scope

General SHA-512/t portable public API acceptance over signed v0.24.27.
No production cryptographic behavior, runtime dependency, CPU admission or
facade API changes. Stale SHA-512/t parameter and digest documentation sentences are
corrected to acknowledge the existing hashing and secret-output APIs.

- Runnable no_std consumer exercises all 510 valid t and 4590 independent byte
  and arbitrary-bit expected results through ordinary/hardened one-shot and
  streaming routes, with distinct typed secret outputs and declassification.
- All u16 parameter inputs, wrong destination widths and red zones, borrowed
  preflight rejection, cancellation, malformed imports and bit descriptors.
- Cargo archive extraction with isolated, empty-cache offline package-external
  consumer resolution; exactly three first-party runtime dependency crates.
- Debug/release malformed-corpus rejection, external ownership/type compile
  failures, and six compiled package IV/cleanup mutations.
- CI toolchain and bare-metal scripts now explicitly include this consumer.

See [runnable commands and operation coverage](../docs/sha512-t-public-acceptance.md).
General SHA-512/t stays **In progress** pending v0.24.29 final evidence. The six
named SHA-2 functions retain their existing completed status. No hosted or
accelerated implementation is newly admitted.

## Verification and release policy

Actual completed checks and remaining work are recorded in the
[pentest report](../security/pentest/v0.24.28.md). Passing repository tests is not
independent cryptographic review or FIPS validation. Existing physical-erasure
and caller-copy limits remain unchanged; public importers do not accept a
typed secret owner implicitly.

The facade advances to internal 0.24.28; support versions stay unchanged and
every package remains `publish = false` in the release selection. The next
scheduled crates.io checkpoint is v0.25.2. After owner pentest/retest, complete
release checks, commit its PASS report, wait for green GitHub/CodeQL and obtain
explicit tag permission. Do not tag, push or publish this candidate early.
