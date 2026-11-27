# v0.30.6 — standalone cipher package publication acceptance (in preparation)

This checkpoint prepares the cumulative package split since the public v0.25.3
baseline. It adds no cipher or hardware backend. The root and facade READMEs
now list the owning crate, available import routes, and independent-review
status separately. Start with the [capability tables](../README.md#cryptography-verification-status)
when choosing between a raw primitive and authenticated encryption.

## Packaging progress

An offline Cargo packaging preview on Rust 1.100.0 assembled the 29 local
packages in the normal/build dependency closure (including optional edges) of
`brynja`, `brynja-crypto-cpu-std`, and `brynja-legacy-hkdf`. The five new
archives (ChaCha20, AES, GHASH, AES-GCM/GMAC and legacy HKDF) each contained
the README and both licenses, byte-identical to their source files. This used
the current development versions and Cargo's package staging area, not the
live registry. The staging closure is **not** the list of packages to upload.

## Frozen selection and registry rehearsal

The [public plan](../release-crates.toml) selects **35 packages**, in dependency
order, starting with `brynja-core 0.11.0` and ending with `brynja 0.30.6`.
Five are first publications; the other thirty get fresh versions. Dependency-
only patches are necessary because workspace packages use exact pins, including
for optional backends. No cryptographic Rust source was changed for this freeze.

Run `python3 scripts/release/check-registry-consumer.py` from a clean candidate.
It packages the selected crates locally, checks the README and both licenses
inside each archive, and tests consumers of Cargo's staged registry. There are
no workspace paths or patch overrides in the consumer manifest. Resolved
versions and archive checksums must agree with the selection. Both Rust 1.90.0
and 1.100.0 run the packaged examples via the direct and supported compatibility
routes, reject raw imports without opt-in, type-check the shared owners and
compile for Cortex-M. These are package checks, not new platform qualification.

The preparation-time registry lookup found the thirty existing names had the
same owner set as `brynja`, their baseline versions were available and their
selected new versions were unused. The five initial names were absent (not
reserved). The publisher rechecks each first-publication name before uploading
and confirms its active indexed version before publishing dependents. Only
immediately after a successful first upload may the sole owner be the trusted
individual uploader rather than the full project owner set. In that case,
add the remaining project owners explicitly and verify the full list before
closing the release. The publisher never changes owners. Resuming with
`--start-at` requires the full owner set on skipped first publications. A dry
run does not exercise those live post-upload conditions.
The [packaging-delta review](../security/pentest/v0.30.6-delta.md) is distinct
from the required cumulative review. That review, the final gate and the
exact-commit GitHub/CodeQL handoff are still pending; nothing has been uploaded.
