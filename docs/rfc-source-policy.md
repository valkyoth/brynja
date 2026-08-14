# Standards And RFC Source Policy

Status: policy

Brynja uses exact RFC Editor text as tracked normative references. Source URLs,
document roles, obsolescence, errata decisions, and IANA registry snapshots are
reviewed independently from implementation changes.

Requirements:

- only HTTPS RFC Editor URLs listed in rfc/SOURCES may be fetched;
- RFC bytes are immutable and checksum locked without line normalization;
- builds and tests never access the network;
- verified errata are recorded as decisions, never patched into RFC text;
- current IANA registries, not remembered assignments, govern numeric values;
- every base RFC's current updated-by and obsoleted-by closure is reviewed;
- the current RFC Index and referenced IANA registries are searched for
  standalone later specifications that allocate, freeze, profile, deprecate, or
  secure an admitted surface even when no formal updated-by edge exists;
- obsolete compatibility text is labeled and can never outrank its current
  replacement or update;
- every normative requirement must eventually map to code, a test, a documented
  non-goal, or an explicit future milestone;
- obsolete RFCs are retained only with an exact compatibility or legacy
  role and can never override a current specification;
- RFC text never enters crates.io packages or the project's software license;
- non-RFC PDFs/specifications default to local-only until redistribution rights
  are explicitly reviewed.

Use scripts/fetch-rfcs.sh to obtain missing allowlisted files, then inspect them
and use scripts/lock-rfcs.sh to create or refresh the reviewed checksum file.
Any source-list change and checksum change must be reviewed together.

Official NIST and ITU documents use the separate local-only allowlist and hash
manifest under references/. Release maintenance rechecks current RFC
replacements, errata, IANA registries, NIST planning notes, NIST errata, and
the in-force ITU edition before work on a dependent milestone.

The v0.3.0 evidence under `standards/` makes the source-level policy
executable. `source-policy.toml` owns lifecycle and milestone decisions plus
independently reviewed hashes for the canonical RFC-index projection, canonical
official errata fields, and exact IANA bytes;
`ERRATA.json`, the compact RFC-index projection, and exact IANA XML snapshots
preserve the reviewed upstream state; and `source-ledger.json` is reproduced
byte-for-byte by `scripts/check-standards-ledger.py`. Normal verification is
offline. The networked release gate runs
`scripts/update-standards-snapshots.py --check` and fails on upstream drift so
that no source, relationship, erratum, registry assignment, or date can change
silently.

Fetch and refresh operations cannot generate their own trust anchors. RFC and
local NIST/ITU lock scripts only validate pre-existing reviewed hash manifests;
the standards refresh refuses both `--check` and `--write` unless every result
matches the policy pin. A legitimate change requires manual pin entry from a
separate resolver, egress, or signed upstream channel before refresh. All URLs
must remain on the exact HTTPS host/path allowlist, including every redirect.
Network responses are size-bounded, and XML with DTD or entity declarations is
rejected before the dependency-free parser runs.

The v0.3.0 pins are anchored to the signed pre-pentest candidate and were
independently re-fetched over TLS using addresses returned by Google
DNS-over-HTTPS. The comparison covered every locked RFC and NIST source, all
IANA snapshots, the canonical RFC-index projection, and the canonical 285-entry
errata set.

The v0.3.1 `surface-policy.json` binds to the byte-exact generated source
ledger and classifies every semantic surface plus every nested registry and
individual record in all eight pinned IANA collections. The generated
`protocol-surfaces.json` carries normative sources, disposition, milestone,
planned code target, planned test target, and rationale for every row.
`check-protocol-surfaces.py` rejects a changed ledger, collection, registry,
record, classification, owner, target, or unmatched override and reproduces
both the JSON register and human-readable coverage byte for byte.

The v0.3.2 requirement-matrix foundation binds its reviewed pilot policy to the
exact generated source-ledger and protocol-surface hashes. It records stable
identifiers, exact source hash and section, source status and errata, normative
strength, applicability decision, owner, planned target or actual governance
symbol or documented boundary, tests, evidence lifecycle, and residual status.
Generated schema, matrix, coverage, and bidirectional source, decision, owner,
target, test, and evidence indexes are reproduced byte for byte. Fifty-one
positive and broken-fixture tests reject orphaned requirements, duplicate
identifiers, invalid sections or lifecycle transitions, a changed source
closure, premature evidence, missing targets, obsolete-as-current authority,
unexplained weakening of SHOULD or SHOULD NOT language, and symlink targets
that escape the repository root. Normal generation compares policy with the
immutable parent matrix: released identifiers cannot disappear, lifecycle
changes must use a declared transition, new records begin at revision one, and
changed records increment exactly once; released governance/protocol scope is
immutable. Exact-source mappings require the cited surface and consistent
normative authority, disposition, and owner. Broader reviewed-global mappings
are governance-only, RFC-backed, and require explicit reviewed rationale.
The v0.3.3 domain policy completes classical cryptography, encoding,
key-container, PKIX, OCSP, and CT coverage. It binds 34 new requirements to all
53 assigned exact authorities, records current, compatibility, evidence, and
exclusion roles, hashes every applicable normative RFC section, and assigns
all 3,324 current selected surfaces or explicitly defers the two ML-KEM surfaces to
v0.3.5. FIPS 202 and the in-force ITU-T X.690 (2021) plus Erratum 1 are
local-only checksum-pinned authorities. The following v0.3.4 transport pass
and v0.3.5 residual pass populate the remaining normative domains.

The v0.3.4 transport policy completes current and compatibility TLS, hardened
TLS 1.2, QUIC-TLS, DTLS 1.2, and DTLS 1.3 coverage. Seventy requirements bind
40 admitted authorities, 550 normative RFC sections, 63 exact implementation
owner milestones, and 485 selected surfaces. Current, compatibility, evidence,
exclusion, and caller-owned roles are distinct. RFC 9850 and optional TLS
facility groups remain explicit v0.3.5 deferrals; no deferred source can be
silently treated as admitted transport authority.

The v0.3.5 residual policy completes the pre-implementation closure. Final
FIPS 203, SP 800-227, SP 800-90B, and SP 800-90C join the local-only checksum
manifest. Fifty residual requirements bind 33 authorities and review
182 normative RFC sections through 165 exact requirement mappings and 17
explicit exclusions while assigning every one of the 763 surfaces left by the
earlier bundles. The generated closure proves that all 127 locked authorities,
all 273 roadmap rows, all 4,449 current surfaces, and all 167 requirements have
bidirectional ownership. The new OpenPGP rows are fenced from implementation
until v0.163.0 authenticates their RFC, errata, registry, algorithm, and
compression authority closure and generates the corresponding requirements
and surfaces. Local rights, mutable NIST and IANA refresh rules,
the resolved hybrid-source gate plus unavailable legacy and FIPS-validation
authorities remain machine-readable records rather than capability claims.

Section decisions are reconciled across the domain, transport, and residual
policies before matrix generation. A normative section cannot be mapped in one
bundle and excluded in another, duplicate exclusions must agree, and a
delegated section is accepted only when another bundle records an exact mapped
or excluded owner. RFC 9853 state, extension, ContentType 27, and message
registry surfaces remain inside the DTLS v0.111.1 boundary. RFC 6066 sections
are split among their exact TLS 1.2, TLS 1.3, SNI, certificate-status,
status-transport, alert, terminology, bounded wire-ignore, and
configuration-rejection decisions. RFC 7568 section 3 is authority
only for the SSLv3 prohibition.

FIPS planning also snapshots the dated FIPS 140-3 CMVP Management Manual,
Implementation Guidance, RFG and CMVP resolutions, SP 800-140 supplemental
lists, programmatic transitions, certificate caveats and status, ESV guidance,
and permitted validation wording. Mutable web guidance is recorded with
retrieval time and content hash; it never silently replaces the submission
baseline, and every later change receives an explicit applicability and
revalidation decision.
