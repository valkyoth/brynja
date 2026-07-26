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
- every normative requirement must eventually map to code, a test, a documented
  non-goal, or an explicit future milestone;
- obsolete RFCs are retained only with an exact compatibility or historical
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

FIPS planning also snapshots the dated FIPS 140-3 CMVP Management Manual,
Implementation Guidance, RFG and CMVP resolutions, SP 800-140 supplemental
lists, programmatic transitions, certificate caveats and status, ESV guidance,
and permitted validation wording. Mutable web guidance is recorded with
retrieval time and content hash; it never silently replaces the submission
baseline, and every later change receives an explicit applicability and
revalidation decision.
