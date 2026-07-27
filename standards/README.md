# Standards Evidence

Status: v0.3.1 reviewed source ledger and protocol-surface decisions

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
  103 locked RFCs. It preserves status and update/obsolescence relationships.
- `snapshots/iana/*.xml` are exact official IANA registry snapshots.
- `SHA256SUMS` locks every generated upstream evidence artifact. The ledger is
  excluded because it is reproduced and compared directly.
- `surface-policy.json` is the reviewed classification policy bound to the
  exact source-ledger hash. It records explicit semantic decisions, complete
  collection defaults, registry-specific rules, and exact entry overrides.
- `protocol-surfaces.json` deterministically classifies every semantic
  decision, nested registry, and individual record in all eight pinned IANA
  collections with its disposition, source, owner, code target, test target,
  and rationale.
- `protocol-surface-coverage.md` is the generated human-readable count and
  domain summary. It is never edited independently of the JSON register.

The RFC and local NIST checksum manifests are trust pins, not outputs of a
fetch. Their lock scripts validate existing pins and deliberately cannot
compute or replace them. The standards-policy pins are likewise established
before a refresh. The current standards pins are anchored to signed candidate
commit `5131bf2e2a1126812e30ddcb98f5bbee7412d1e3` and were independently
reverified over TLS using addresses obtained from Google DNS-over-HTTPS,
independently of every later `--write`.

NIST PDFs remain local-only and are not required in a clean clone. The ledger
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
python3 scripts/check-standards-ledger.py
python3 scripts/test-standards-ledger.py
python3 scripts/check-protocol-surfaces.py
python3 scripts/test-protocol-surfaces.py
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
or stale generated JSON or Markdown. All 4,106 individual IANA records, 192
nested registries, and 45 semantic decisions are represented; `future-work`
does not claim implementation.

## Reviewed Refresh

Refreshing evidence is an explicit networked maintenance operation:

```bash
scripts/update-standards-snapshots.py --check
scripts/update-standards-snapshots.py --write
python3 scripts/check-standards-ledger.py --write
```

`--check` is part of the release gate and fails when an official RFC index,
errata result, or IANA registry differs. `--write` does not make upstream drift
acceptable and cannot replace a pin. For legitimate drift, first retrieve and
review the new digest through a separate resolver, network egress, or signed
upstream channel; manually update the policy pin and its provenance; then run
`--write`, review the semantic and byte diff, regenerate the ledger, pass all
tests, and commit the pin plus evidence together. The same pin-first process
applies to new RFC and NIST source bytes.

Concrete ECDHE-ML-KEM groups remain fail-closed at milestone `0.120.0`.
RFC 9954 supplies only the generic construction; a final Standards Track RFC
and final IANA code points are both required. Drafts and private code points
cannot satisfy the blocker.
