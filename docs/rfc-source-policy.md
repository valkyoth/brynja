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

Official NIST documents use the separate local-only allowlist and hash manifest
under references/. Release maintenance rechecks current RFC replacements,
errata, IANA registries, NIST planning notes, and NIST errata before work on a
dependent milestone.

The v0.3.0 evidence under `standards/` makes the source-level policy
executable. `source-policy.toml` owns lifecycle and milestone decisions;
`ERRATA.json`, the compact RFC-index projection, and exact IANA XML snapshots
preserve the reviewed upstream state; and `source-ledger.json` is reproduced
byte-for-byte by `scripts/check-standards-ledger.py`. Normal verification is
offline. The networked release gate runs
`scripts/update-standards-snapshots.py --check` and fails on upstream drift so
that no source, relationship, erratum, registry assignment, or date can change
silently.

The v0.3.2 through v0.3.5 requirement-matrix passes record exact source hash and
section, normative strength, applicability decision, owner, planned target or
actual implementation symbol or documented boundary, positive and negative
tests, evidence lifecycle, and residual status. Automation must reject orphaned
requirements, duplicate identifiers, invalid lifecycle claims, a changed source
closure, and any unexplained weakening of SHOULD or SHOULD NOT language.

FIPS planning also snapshots the dated FIPS 140-3 CMVP Management Manual,
Implementation Guidance, RFG and CMVP resolutions, SP 800-140 supplemental
lists, programmatic transitions, certificate caveats and status, ESV guidance,
and permitted validation wording. Mutable web guidance is recorded with
retrieval time and content hash; it never silently replaces the submission
baseline, and every later change receives an explicit applicability and
revalidation decision.
