# Normative Requirement Evidence

Status: v0.3.4 TLS, DTLS, and QUIC-TLS domain coverage

This directory turns exact standards authority into stable, reviewable
requirements without claiming that planned protocol behavior exists. The
matrix contains 12 foundation requirements, 34 cryptography, encoding, PKIX,
OCSP, and CT requirements, and 70 TLS, DTLS, and QUIC-TLS requirements.
Version v0.3.5 populates optional, legacy, operational, and residual domains.

## Artifacts

- `policy.json` is the reviewed input. Each stable identifier records exact
  source and section, normative strength, applicability, decision, owner,
  lifecycle, revision, mapping scope and rationale, target or boundary, tests,
  evidence, and residual risk.
- `domain-scope.toml` binds the v0.3.3 source and surface domains, exact ledger
  and register hashes, grouped surface ownership, and explicit later
  deferrals.
- `domains/*.toml` are compact reviewed inputs for cryptography, encoding,
  PKIX, OCSP, and CT. Each record adds exact authority roles, assurance
  invariants, a work bound, positive and negative planned tests, an evidence
  gap, and reviewed mapping rationale.
- `domain-sections.toml` and `transport-sections.toml` explicitly bind every
  uppercase normative RFC section to one or more requirements or an exact
  reviewed disposition. They also carry the immutable requirement revisions
  introduced by those semantic bindings.
- `transport-scope.toml`, `transport-exceptions.toml`, and
  `../standards/transport-surfaces/*.toml` are the reviewed v0.3.4 inputs.
  They bind every transport authority, semantic implementation milestone,
  intentional rejection, caller-owned boundary, registry group, and explicit
  deferral.
- `schema.json` is the deterministic schema and legal lifecycle-transition
  contract.
- `matrix.json` resolves every source against the exact source-ledger and
  protocol-surface hashes, including RFC section hashes, status, errata, IANA
  snapshot identity, registry-record hashes, unique extraction anchors, and
  per-requirement normative-section bindings.
- `indexes.json` provides bidirectional source, decision, owner, target, test,
  and evidence mappings.
- `coverage.md` is the generated human-readable lifecycle and scope report.
- `domain-coverage.json` proves exact authority, normative-section, and
  protocol-surface coverage for the v0.3.3 scope, including requirement IDs
  for all 364 normative sections.
- `transport-coverage.json` proves exact coverage of 40 authorities, 550
  normative RFC sections, 63 owner milestones, and 480 transport surfaces,
  including requirement IDs or reviewed dispositions for every section.

The lifecycle values are `planned`, `implemented`, `tested`, `evidenced`,
`rejected`, `caller-owned`, `legacy`, and `blocked`. An implementation claim
requires an existing symbol; test and evidence claims require existing
anchors. This foundation permits implementation-state claims only for its
governance tooling. Protocol requirements remain planned or explicitly
bounded until their owning implementation milestones.

Normal generation compares the worktree with the immutable matrix in `HEAD`,
or a clean committed candidate with `HEAD^`. Existing identifiers cannot
disappear. New identifiers start at revision one; unchanged content retains its
revision; any content change increments exactly once; and lifecycle changes
must follow the declared transition graph. Governance versus protocol scope is
immutable after an identifier enters history; a genuine scope change requires
a new stable identifier. The signed linear release history anchors this chain.
v0.3.2 is the bootstrap matrix release; later release tags preserve the same
chain as permanent baselines.

An `exact-source` mapping requires direct source relation and consistent
surface disposition and owner. Every protocol requirement must use this scope.
An IANA-backed requirement must include its
exact source surface; any additional surface must share normative authority
and ownership. A `reviewed-global` mapping is limited to RFC-backed rules and
governance requirements and requires a substantive human-reviewed rationale.

A `reviewed-domain` mapping is restricted to the five v0.3.3 policy domains
and their allowlisted surface domains. All 53 in-scope authorities must be
cited with their exact current, compatibility, evidence, or exclusion role.
Every one of the 3,322 selected surfaces must map to an owning requirement or
an explicit later milestone. The only deferrals are the two ML-KEM surfaces
owned by v0.3.5.
Every linked surface must independently share both an admitted authority and
the requirement owner. A legitimate cross-authority or cross-owner relation
requires an exact structured exception naming the surface, authorities,
expected owner, and reviewed rationale; free-form prose cannot bypass this
check.

The v0.3.4 `tls-dtls-quic` profile cites 40 authorities with exact current,
compatibility, evidence, exclusion, or caller-owned roles. RFC 9850 and four
optional TLS facility groups are explicitly deferred to v0.3.5;
status_request_v2 remains mapped to its v0.3.3 OCSP review. Every one of the 63
planned transport implementation milestones has one stable semantic surface
and requirement.

## Verification

Normal checks are offline and reproduce every generated byte:

```bash
python3 scripts/check-requirements.py
python3 scripts/test-requirements.py
python3 scripts/test-requirement-domains.py
python3 scripts/test-requirement-transports.py
python3 scripts/test-requirement-sections.py
python3 scripts/test-requirement-lifecycles.py
```

The 82 broken-fixture and positive tests reject changed source hashes, invalid
sections, duplicate or malformed identifiers, obsolete-as-current authority,
illegal lifecycle transitions, missing owners or targets, premature evidence,
weakened SHOULD decisions, unknown surface decisions, stale generated output,
repository-escaping symlink targets, removed released identifiers, stale or
gratuitous revisions, released-scope changes, protocol use of global mappings,
unrelated semantic links, lifecycle/disposition or owner conflicts, and
unsupported protocol implementation claims.
Section fixtures additionally reject unmapped or non-normative sections,
requirement/source mismatches, duplicate bindings, incomplete semantic
revisions, and unreviewed exclusions while proving every extraction anchor and
section hash.
Domain fixtures additionally reject authority-role errors, missing surface
groups, absent positive or negative tests, weak work bounds, missing assurance
invariants, out-of-scope decisions, and nondeterministic domain evidence.
Transport fixtures additionally reject missing milestone ownership,
caller/protocol role swaps, authority or surface binding drift, duplicate
stable identities, and nondeterministic transport evidence.

After a reviewed policy change, regenerate and inspect all projections:

```bash
python3 scripts/check-requirements.py --write
```

Generated artifacts must never be edited independently of `policy.json`,
`domain-scope.toml`, `domains/*.toml`, `transport-scope.toml`,
`transport-exceptions.toml`, and `../standards/transport-surfaces/*.toml`.
The two `*-sections.toml` policies are reviewed inputs as well.
