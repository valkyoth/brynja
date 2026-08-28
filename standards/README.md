# Standards Evidence

Status: reviewed source closure carried through v0.13.1

This directory is Brynja's machine-readable inventory of the authorities that
govern planned implementation work. It does not claim that any protocol or
primitive is implemented.

## Artifacts

- `source-policy.toml` is the reviewed human-authored mapping from each locked
  source to lifecycle, domain, milestone, registry, closure exception, and
  admission blocker. It also contains independently reviewed hashes for the
  canonical RFC-index projection, canonical official errata fields, and every
  exact IANA XML snapshot.
- `source-ledger.json` is generated deterministically from that policy, the
  locked RFC and local-source manifests, official metadata snapshots, and
  reviewed errata decisions.
- `ERRATA.json` records all errata returned for every locked RFC. Verified
  errata are implementation inputs, reported and held errata remain tracked
  without altering requirements, and rejected errata are non-applicable.
- `snapshots/rfc-index.json` is the minimal RFC Editor index projection for the
  104 locked RFCs. It preserves status and update/obsolescence relationships.
- `snapshots/iana/*.xml` are exact official IANA registry snapshots.
- `SHA256SUMS` locks every generated upstream evidence artifact. The ledger is
  excluded because it is reproduced and compared directly.
- `surface-policy.json` is the reviewed classification policy bound to the
  exact source-ledger hash. It records explicit semantic decisions, complete
  collection defaults, registry-specific rules, and exact entry overrides.
- `transport-surfaces/*.toml` adds one reviewed semantic surface for each of
  the 64 TLS, hardened TLS 1.2, QUIC-TLS, DTLS 1.2, and DTLS 1.3
  implementation milestones without changing registry classifications.
- `protocol-surfaces.json` deterministically classifies every semantic
  decision, nested registry, and individual record in all eight pinned IANA
  collections with its disposition, source, owner, code target, test target,
  and rationale. Transport rows additionally carry their stable requirement
  identifiers.
- `protocol-surface-coverage.md` is the generated human-readable count and
  domain summary. It is never edited independently of the JSON register.
- `../requirements/` binds stable requirements to this exact ledger and
  surface register and generates lifecycle, traceability, domain, and coverage
  evidence. v0.3.3 completes cryptography, encoding, PKIX, OCSP, and CT;
  v0.3.4 completes TLS, DTLS, and QUIC-TLS; v0.3.5 closes optional, legacy,
  operational, entropy, HPKE, ECH, ML-KEM, and residual population.

The RFC and local NIST/ITU checksum manifests are trust pins, not outputs of a
fetch. Their lock scripts validate existing pins and deliberately cannot
compute or replace them. The standards-policy pins are likewise established
before a refresh. The current standards pins are anchored to signed v0.3.2
commit `00b1180a9014b7e69986e8ddd29d46e85a20aa2f` and were independently
reverified over TLS using addresses obtained from Google DNS-over-HTTPS,
independently of every later `--write`.

NIST, ITU, and RISC-V PDFs remain local-only and are not required in a clean clone. The ledger
always validates their complete allowlist and hash manifest. When any expected
PDF is present, the entire cache must be present and every byte is checked.
Set `VERIFY_LOCAL_REFERENCE_FILES=1` to require the cache explicitly.

The lifecycle `current` is implicit. Explicit classes are:

- `compatibility`: obsolete text needed to implement a currently permitted
  compatibility profile, but unable to override current authority;
- `legacy`: insecure historical protocol authority confined to an independent
  legacy release line;
- `exclusion`: a source retained to make a deliberate rejection enforceable;
- `caller-owned`: a source defining behavior outside Brynja's ownership; and
- `evidence`: test vectors or supporting evidence rather than implementation
  authority.

## Offline Verification

Normal builds and tests never access the network:

```bash
python3 scripts/standards/check-standards-ledger.py
python3 scripts/standards/test-standards-ledger.py
python3 scripts/standards/check-protocol-surfaces.py
python3 scripts/standards/test-protocol-surfaces.py
python3 scripts/standards/check-requirements.py
python3 scripts/standards/test-requirements.py
python3 scripts/standards/test-requirement-domains.py
python3 scripts/standards/test-requirement-transports.py
python3 scripts/standards/test-requirement-lifecycles.py
```

The checker fails on non-HTTPS or unallowlisted URLs, redirects outside the
allowlist, missing or mismatched pins, missing or extra sources, hashes,
domains, milestones, registries, errata decisions, lifecycle conflicts,
obsolete-as-current authority, unclosed RFC relationships, relaxed hybrid
admission, or a stale generated ledger. XML and HTTP response limits plus
DTD/entity rejection bound compromised-upstream parsing. Broken fixtures prove
these failure paths.

The surface checker additionally fails on a changed source-ledger hash,
missing or duplicate collection, registry, record, decision, or identifier,
unknown disposition, source, milestone, or target, overlapping registry
rules, unmatched or duplicated overrides, any premature `implemented` claim,
or stale generated JSON or Markdown. All 4,126 individual IANA records, 195
nested registries, and 129 semantic decisions are represented; `future-work`
does not claim implementation. An `implemented` disposition is admitted only
when current code, tests, and requirement evidence support that exact surface.

The requirement checker additionally fails on changed ledger or surface hashes,
invalid RFC sections or anchors, obsolete-as-current sources, unknown or
duplicate stable identifiers, illegal lifecycle transitions, absent owners or
targets, premature test or evidence claims, weakened SHOULD decisions, broken
bidirectional mappings, repository-escaping targets, released-ID removal,
incorrect revisions, unrelated decision links, lifecycle/disposition or owner
conflicts, protocol use of global mappings, released-scope changes, or stale
generated artifacts. Its 12 foundation requirements exercise all eight
lifecycle states; 35 domain requirements cover all 56 assigned cryptography,
encoding, PKIX, OCSP, and CT authorities plus 3,325 current selected surfaces; 71
transport requirements cover 40 authorities, 550 normative sections, 64
implementation milestones, and 485 TLS, DTLS, and QUIC surfaces. Fifty-one
residual requirements cover 33 authorities, 182 reviewed normative sections,
and all 791 formerly uncovered surfaces. The residual section policy
contains 165 exact mappings and 17 explicit exclusions, producing complete
closure across all 130 sources and 4,455 surfaces.
Governance-tool evidence is not protocol implementation evidence.
Reviewed-global mappings are governance-only. The private-use extension pilot
is explicitly caller-owned rather than inherited future work.

## Reviewed Refresh

Refreshing evidence is an explicit networked maintenance operation:

```bash
scripts/standards/update-standards-snapshots.py --check
scripts/standards/update-standards-snapshots.py --write
python3 scripts/standards/check-standards-ledger.py --write
```

`--check` is part of the release gate and fails when an official RFC index,
errata result, or IANA registry differs. `--write` does not make upstream drift
acceptable and cannot replace a pin. For legitimate drift, first retrieve and
review the new digest through a separate resolver, network egress, or signed
upstream channel; manually update the policy pin and its provenance; then run
`--write`, review the semantic and byte diff, regenerate the ledger, pass all
tests, and commit the pin plus evidence together. The same pin-first process
applies to new RFC, NIST, and ITU source bytes.

The 2026-08-01 reviewed refresh accepted the official 2026-07-31 IANA DNS
Parameters snapshot. Its three new registries and seventeen new entries are
explicitly caller-owned by v0.140.0. Provisional Structured DNS Error draft
references in that registry are evidence of registry state, not admitted
implementation authority.

The 2026-08-09 reviewed refresh accepted one new provisional `snifq/1` ALPN
entry as caller-owned v0.130.0 registry state and three DNS reference-only
updates from drafts to RFC 10029 and RFC 10023. It adds no executable behavior,
does not admit the referenced drafts or RFCs into Brynja protocol scope, and
advances affected immutable requirement revisions.

The 2026-08-11 reviewed refresh locks final Standards Track RFC 10024 and the
matching final IANA assignments for X25519MLKEM768, SecP256r1MLKEM768, and
SecP384r1MLKEM1024. RFC 10024 has no reported errata, and the IANA delta adds
no new value. The former admission blocker remains recorded as `resolved`;
implementation stays planned only for milestone `0.120.0`, and drafts and
private code points remain forbidden.

The later 2026-08-11 reviewed TLS ExtensionType refresh records certificate
type value 4 as C509 Certificate and moves the unassigned range start to 5.
The registry's provisional `draft-ietf-cose-cbor-encoded-cert-20` reference is
not admitted as normative authority; the surface remains future work behind
the existing certificate-type decision boundary and admits no runtime code.

The 2026-08-17 reviewed RFC errata refresh adds verified editorial RFC 9954
erratum 9136. It corrects two references to the TLS 1.3 `KeyShare` section from
4.2.8 to 4.3.8, changes no normative hybrid-key-exchange behavior, remains an
explicit input for planned v0.117.0, and admits no runtime code at this
refresh.

The 2026-08-28 reviewed SMI Numbers refresh advances two existing MAC-address
object references from a draft to final RFC 10031 and adds
`id-rdna-c509Name` value 2 under the existing PKIX relative-distinguished-name
registry with a provisional `draft-ietf-cose-cbor-encoded-cert-20` reference.
The matching DNS Parameters refresh adds provisional UNECE and ISO RR types,
the RFC 8460 `_tls` underscored TXT name, a temporary provisional DELEG
parameter, and schema-only NOTIFY mnemonic normalization. Existing v0.48.0
PKIX/OCSP ownership and caller-owned v0.140.0 DNS disposition remain
unchanged. This evidence refresh admits neither new normative authority nor
runtime code.

The same 2026-08-28 refresh records reported technical RFC 3986 erratum 9147.
Because it is not verified, it remains `track-not-applied` and cannot change
requirements or implementation behavior unless its official status and
security impact are reviewed again at an owning milestone.

Final FIPS 203, SP 800-227, SP 800-90B, and SP 800-90C are checksum-pinned
local-only authorities. Their publication pages, planning notes, errata, and
CMVP applicability remain mutable and must be refreshed at their dependent
milestones without silently replacing the reviewed baseline.

Final SP 800-185 is likewise checksum-pinned locally for the complete pre-1.0
cSHAKE, KMAC, TupleHash, and ParallelHash chain. Its 2025 revision announcement
is recorded as mutable authority, not as normative replacement text. The
planned v0.24.5 lifecycle monitor extends the present RFC/errata/IANA drift
check to official publication landing pages and documents. It will report
upstream status independently from Brynja disposition: withdrawal or
supersession triggers human impact review and a corrective milestone, but can
never automatically move an implementation to legacy, keep it modern, or
authorize changed code.
