# Standards Evidence

Status: v0.3.0 reviewed source ledger

This directory is Brynja's machine-readable inventory of the authorities that
govern planned implementation work. It does not claim that any protocol or
primitive is implemented.

## Artifacts

- `source-policy.toml` is the reviewed human-authored mapping from each locked
  source to lifecycle, domain, milestone, registry, closure exception, and
  admission blocker.
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
```

The checker fails on missing or extra sources, hashes, domains, milestones,
registries, errata decisions, lifecycle conflicts, obsolete-as-current
authority, unclosed RFC relationships, relaxed hybrid admission, or a stale
generated ledger. Broken fixtures prove these failure paths.

## Reviewed Refresh

Refreshing evidence is an explicit networked maintenance operation:

```bash
scripts/update-standards-snapshots.py --check
scripts/update-standards-snapshots.py --write
python3 scripts/check-standards-ledger.py --write
```

`--check` is part of the release gate and fails when an official RFC index,
errata result, or IANA registry differs. `--write` does not make upstream drift
acceptable: the resulting diff must be reviewed, the policy adjusted when
needed, the ledger regenerated, tests passed, and all artifacts committed
together.

Concrete ECDHE-ML-KEM groups remain fail-closed at milestone `0.120.0`.
RFC 9954 supplies only the generic construction; a final Standards Track RFC
and final IANA code points are both required. Drafts and private code points
cannot satisfy the blocker.
