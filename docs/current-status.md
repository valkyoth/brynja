# Current Status

Status: v0.3.4 pentest and remediation retest passed; awaiting green CI

Brynja still has no TLS, cryptographic, PKI, QUIC, DTLS, platform, or legacy
protocol implementation. The Rust workspace remains package scaffolding and
must not be used to secure network traffic. Brynja is not FIPS 140-3 validated,
and no package, feature, build, profile, or configuration may imply otherwise.

Signed releases v0.1.0 through v0.3.2 established the workspace, hardened
release and isolation controls, made standards authority executable, and
classified protocol surfaces and the normative matrix foundation. The v0.3.4 candidate
advances only `brynja`; unchanged supporting crates remain at their
independently published `0.1.0` versions and are not selected again.

Version 0.3.0 provides the exact source foundation:

- 103 locked RFCs and eleven local NIST/ITU authorities map to lifecycle, domain,
  and roadmap ownership;
- RFC status and update/obsolescence relationships are closed or explicitly
  excluded;
- eight exact IANA XML snapshots preserve registry state;
- all 290 official errata have fail-closed reviewed dispositions; and
- ordinary checks reproduce the ledger offline while the release gate rejects
  live official-source drift.

Version 0.3.1 adds explicit protocol-surface decisions:

- 48 semantic decisions cover current and compatibility TLS, DTLS, QUIC-TLS,
  PKIX, OCSP, CT, HPKE, ECH, cryptographic algorithms, certificate and key
  formats, legacy protocols, and operational facilities;
- all 192 nested registries and all 4,106 individual records across the eight
  pinned IANA collections receive a deterministic disposition;
- every one of the 4,346 total surfaces records normative sources, owning
  milestone, planned code target, planned test target, and rationale;
- required exclusions explicitly cover Heartbeat, status_request_v2,
  production SSLKEYLOGFILE, TLS 1.3 post-handshake authentication,
  certificate-with-external-PSK, legacy PKCS1 client signatures, ML-KEM PKIX
  credentials, HPKE non-base modes, and unsigned X.509 certificates;
- QUIC version-specific cryptography and certificate compression remain
  explicit bounded future work, while unknown extensions are safely ignored
  only where protocol rules permit; and
- 25 positive and broken-fixture tests reject source-ledger drift, registry
  omissions, duplicate or unknown decisions, invalid owners or targets,
  overlapping rules, unmatched overrides, stale output, and premature
  implementation claims.

Version 0.3.2 added the normative-requirement foundation:

- 12 stable pilot requirements bind exact source-ledger and surface-register
  hashes, source sections and anchors, status, errata, strength, applicability,
  decisions, owners, residual risk, targets, tests, and evidence;
- all eight lifecycle states are represented: planned, implemented, tested,
  evidenced, rejected, caller-owned, legacy, and blocked;
- deterministic schema, matrix, coverage, and bidirectional source, decision,
  owner, target, test, and evidence indexes are reproduced byte for byte;
- implementation, test, and evidence claims require existing file anchors,
  while protocol requirements are forbidden from making premature
  implementation claims; and
- 51 positive and broken-fixture tests reject source or registry drift,
  malformed or duplicate identifiers, invalid sections, obsolete-as-current
  authority, illegal transitions, missing ownership and targets, premature
  evidence, weakened SHOULD decisions, symlink target escapes, released-ID
  removal, stale revisions, unrelated decision links, protocol use of global
  mappings, released-scope changes, lifecycle/disposition conflict, and stale
  generated output.

Version 0.3.3 completes the cryptography, encoding, and PKIX population pass:

- 34 new domain requirements bring the matrix to 46 stable records;
- all 53 exact authorities in the symmetric, public-key, key-container, PKIX,
  OCSP, and CT domains are cited with current, compatibility, evidence, or
  exclusion roles;
- all 3,322 cryptography, PKIX, PKI, OCSP, and CT surfaces map to a requirement
  or one of two explicit v0.3.5 ML-KEM deferrals;
- every uppercase normative RFC section is hash-bound with occurrence counts,
  and every domain rule records assurance invariants, a work bound, positive
  and negative target tests, an evidence gap, and residual risk;
- FIPS 202 and the in-force ITU-T X.690 (2021) plus Erratum 1 are pinned as
  local-only authorities, while SHA-3/SHAKE, GHASH, and ChaCha20 receive
  explicit semantic decisions; and
- fifteen domain fixtures fail on authority, binding, coverage, lifecycle,
  ownership, test-polarity, invariant, work-bound, or reproducibility defects.

Version 0.3.4 completes the TLS, DTLS, and QUIC-TLS population pass:

- 63 semantic surfaces give every planned transport implementation milestone
  one stable owner, code target, test target, source set, and rationale;
- 70 new requirements bring the matrix to 116 stable records and cover all 40
  admitted transport authorities, 550 normative RFC sections, and 480
  selected transport surfaces;
- all 914 domain and transport normative RFC sections now carry exact
  requirement IDs, unique extraction anchors, and section hashes, with zero
  implicit or unreviewed exclusions;
- source roles distinguish current, compatibility, evidence, exclusion, and
  caller-owned authority, including explicit Heartbeat, legacy signature,
  post-handshake-authentication, certificate-with-external-PSK, and QUIC
  transport boundaries;
- TLS, TLS 1.2, TLS 1.3, QUIC, and DTLS state and ownership mappings are
  version-separated and include work bounds, positive and negative tests,
  unresolved evidence, and residual risk;
- RFC 9850 key logging and four optional TLS facility groups remain explicit
  v0.3.5 deferrals, while status_request_v2 remains bound to the completed
  v0.3.3 OCSP review; and
- eight transport and seven section-binding fixtures reject missing owners,
  binding drift, role swaps, duplicate identities, omitted authorities,
  unmapped or non-normative sections, source/requirement mismatch, incomplete
  semantic revisions, unreviewed exclusions, and nondeterministic output.

This remains governance and planning evidence, not protocol implementation.
v0.3.5 populates optional, legacy, operational, and residual requirements
before protocol work begins. Concrete ECDHE-ML-KEM groups remain blocked until
both a final Standards Track RFC and final IANA values exist.

No `brynja-sanitization` package or dependency exists yet; its admission
decision remains gated at v0.11.1.

The v0.3.2 repository-owner pentest cycle reported no remaining vulnerability
and one optional defense-in-depth improvement. Target validation now resolves
paths and rejects symlinks that escape the repository root. The subsequent
retest found two medium release-assurance defects: lifecycle transitions and
revisions were not bound to immutable history, and decision links could be
structurally valid but semantically unrelated. Both are remediated locally with
immutable parent-matrix comparison, append-only identifiers, exact revision
rules, explicit mapping scopes, source/disposition/owner consistency, and 16
dedicated history and semantic-link tests. A later retest found one remaining
medium bypass: protocol rows could select reviewed-global and avoid
exact-source checks. Reviewed-global is now governance-only, released scope is
immutable, and the two affected RFC-wide protocol pilot rows now use exact
IANA sources at revision three. Ordinary CI now accepts only the exact current,
committed `RETEST REQUIRED`/`PENDING` remediation state so hosted checks can
run truthfully before retest, while all release and tag paths require
`PASS`/`PASS`. The final repository-owner retest passed with zero open
findings.

The repository owner pentested the signed v0.3.3 implementation candidate and
reported a green result with no findings. Its permanent report records `PASS`,
zero open findings, and `PASS` retest status.

The repository owner pentested signed v0.3.4 candidate
`42869b4b85087bac647c11a08064189878346112` and reported two Medium
governance-integrity findings. Both were remediated in signed commit
`091c6c29dbf4613646564f3d13b9e40ecc5d40ed`: every linked surface now has an
independent authority and owner check or an exact structured exception, and
every normative RFC section now has an exact requirement binding or reviewed
disposition. The repository-owner retest was green with zero open findings.
The permanent v0.3.4 report is `PASS`/`PASS`; the next step is green hosted
GitHub checks followed by explicit user authorization to tag.
