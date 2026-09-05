# Roadmap Ordering Review

Historical review: numerical results below describe the earlier ordering pass.
The current expansion and final gate positions are recorded in
[ROADMAP_EXPANSION_AUDIT.md](ROADMAP_EXPANSION_AUDIT.md).

Date: 2026-09-05. Baseline: `dbe6f4b`.
This is a planning review, not an implementation or cryptographic assessment.

## Result

The consolidated roadmap now contains 1202 stops, including the release
candidate, and 1201 non-RC closure rows. Fifteen dedicated portable acceptance
stops and one TLS 1.2 exporter stop were added to the previous 1186 stops.
The last pre-RC checkpoint is v0.355.0. There are 86 public checkpoints and
1116 tagged development milestones; the existing every-fifth-minor publication
cadence and exceptional pentest triggers are unchanged.

All v0.24.x identities are preserved. The next implementation remains v0.24.17.
Future plan numbering is not a package-version bump or an implementation claim.

## Smaller Family Releases

The old v0.46.0–v0.46.93 sequence mixed independent algorithms, compression
formats and acceptance gates. Those deserve separate minor versions, not one
94-stop patch chain. Examples of the resulting organization are:

| Work | New owner |
| --- | --- |
| Complete RSA key generation/import/validation | v0.43.0, before RSA consumers |
| Inventory and substrate schedule | v0.51.0–v0.51.1 |
| MD2; RIPEMD-160 | v0.52.0; v0.53.0 |
| FFDHE; DSA; ElGamal | v0.54.x; v0.55.x; v0.56.x |
| CCM; reusable block modes; DES family | v0.57.x; v0.58.x; v0.59.x |
| Camellia; SEED; ARIA | v0.67.x; v0.68.x; v0.69.x |
| GOST symmetric, hash/MAC, public-key families | v0.73.x–v0.75.x |
| Compression families | v0.80.x–v0.84.x |
| ML-DSA; SLH-DSA; substrate closure | v0.85.x; v0.86.x; v0.87.x |

DER, Edwards curves, PKIX issuance/PQ profiles, DRBG families, OpenPGP
prerequisites and legacy protocol families also get coherent minor groups.
Future groups from v0.25 onward are bounded to twelve stops by the schedule
validator. A small count does not itself make a scope reviewable: implementation
must still split newly discovered complexity before its consumer begins.

The complete old-to-new mapping is in
[roadmap-schedule.json](../requirements/roadmap-schedule.json): `id` preserves
the old identity, `version` gives the new position, and `requires` lists reviewed
prerequisites. Synthetic IDs identify genuinely new stops.

## Corrected Prerequisite Order

- Portable public acceptance precedes accelerated/backend evidence. Later
  evidence replays the frozen fixture; code fixes invalidate affected evidence.
- GOST 28147-89 at v0.73.0 precedes GOST R 34.11-94 at v0.74.0 because the hash
  uses that block cipher. See [RFC 5831](https://www.rfc-editor.org/rfc/rfc5831.html).
- Certificate selection at v0.113.0 precedes the authenticated TLS 1.3 server
  flight at v0.114.0.
- TLS 1.3 export is v0.123.0; TLS 1.2 export is v0.134.2 after its engine,
  before the v0.135.0 audit. The latter includes EMS and no-renegotiation
  requirements for its channel binding, not just raw exporter derivation.
  See [RFC 5705](https://www.rfc-editor.org/rfc/rfc5705.html) and
  [RFC 9266](https://www.rfc-editor.org/rfc/rfc9266.html#section-4.2).
- Irreversible module-wide FIPS failure at v0.175.0 precedes executable
  pre-operational self-test attestations at v0.175.1. This is architecture,
  not a FIPS validation claim.
- HPKE labeled KDF operations at v0.186.0 precede DHKEM profiles beginning
  v0.186.1, reflecting [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html).
- Standalone OCB/EAX acceptance at v0.222.0 precedes OpenPGP AEAD integration
  at v0.223.0; curve key wrapping at v0.224.0 precedes its profiles.
- OpenPGP cryptographic certificate validity at v0.228.0 follows required
  signing/binding implementations rather than promising executable validity
  while those algorithms are still absent.
- All catalogue family closures precede catalogue-wide and final product gates.

Forward references remain only as explicitly reviewed structural boundaries,
deferred capabilities or future acceptance obligations. They are not permission
to execute a missing primitive or conceal a private partial implementation.

## Reference And Evidence Integrity

Both normative plans, the catalogue, standards owner labels, requirements,
API-profile register and planning summaries use the new numbering. Stable
requirement IDs, normative obligations and lifecycle claims remain unchanged
(the HPKE statement's milestone references are renumbered);
changed requirement records receive explicit revisions validated against Git.
Historical release notes and pentest reports retain their original numbering.

Authority freshness is rebound only for local planning-reference changes.
External content, authority status and observation facts are unchanged; the
2026-09-04 receipt date is preserved, not presented as a new upstream check.
No Rust implementation, toolchain, dependency version, CPU admission, published
package version or implementation-status claim changes in this review.

## Verification

The release-plan gate checks matching titles/scopes, stable identities,
contiguous version groups, prerequisite order and reviewed forward references.
Mutation tests reject removed/reversed edges, missing identities, altered scopes
and out-of-order consumers. Catalogue coverage continues to preserve all 104
source rows and 93 family sequences. Standards generation and immutable
requirement-history checks must pass alongside the repository gate.

These checks protect the reviewed graph; they do not prove that every future
dependency is already known. Newly authenticated requirements must update the
graph and receive a preceding implementation stop before executable use.
