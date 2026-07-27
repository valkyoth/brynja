# Brynja 0.3.2 Release Notes

Status: pentest passed; awaiting green GitHub checks and tag authorization

Brynja 0.3.2 establishes the normative-requirement matrix foundation. It does
not implement TLS, cryptography, PKI, QUIC, DTLS, platform services, or legacy
protocols and must not be used to secure network traffic.

## Stable Requirement Evidence

The reviewed `requirements/policy.json` is bound to the exact v0.3.0 standards
ledger and v0.3.1 protocol-surface register. The deterministic generator
produces:

- a versioned schema and legal lifecycle-transition contract;
- a resolved matrix with exact RFC section hashes, source status, errata, IANA
  snapshot and record evidence, normative strength, applicability, owner,
  residual risk, target, tests, and evidence;
- bidirectional source, decision, owner, target, test, and evidence indexes;
  and
- a human-readable lifecycle, strength, scope, and mapping report.

Stable identifiers survive rendering, ordering, and prose changes. Every
requirement has exactly one target: a planned or actual symbol, an explicit
boundary, a legacy boundary, or a blocker.

## Lifecycle Foundation

The 12-requirement authority pilot exercises all eight lifecycle states:
`planned`, `implemented`, `tested`, `evidenced`, `rejected`, `caller-owned`,
`legacy`, and `blocked`.

Actual-symbol, test, and evidence claims require existing file anchors.
Protocol requirements are prohibited from claiming implemented, tested, or
evidenced status in this planning milestone. The implementation-state examples
cover only the requirement-governance tooling itself.

## Fail-Closed Verification

Normal checks regenerate the schema, matrix, indexes, and coverage report and
compare them byte for byte. Fifty-one positive and broken-fixture tests
reject:

- changed source-ledger, surface-register, RFC, IANA snapshot, registry, or
  record hashes;
- malformed or duplicate stable identifiers, invalid sections and anchors,
  unknown decisions, absent owners, and missing targets;
- obsolete authority presented as current, illegal lifecycle transitions,
  premature test or evidence claims, and unsupported protocol implementation
  claims;
- weakened SHOULD decisions without an explicit bounded deviation rationale;
- repository-escaping symlink targets; and
- stale or nondeterministic generated artifacts.

The production builder also compares every candidate with its immutable parent
matrix. Released identifiers cannot disappear, lifecycle changes must follow
the declared transition graph, new records start at revision one, unchanged
records retain their revision, and changed records increment exactly once.
Exact-source mappings enforce cited-source, disposition, and owner consistency;
RFC-wide governance mappings require explicit reviewed rationale.
Reviewed-global mappings are governance-only, every protocol row requires
exact-source validation, and released governance/protocol scope is immutable.

These checks run in the ordinary repository gate and the dedicated v0.3.2
release gate.

Ordinary CI now distinguishes a valid remediation candidate from an authorized
release: it accepts only a current committed `RETEST REQUIRED`/`PENDING`
report while external retest is outstanding. The dedicated v0.3.2 release and
tag gates remain strict and require `PASS`/`PASS`, zero open findings, and all
other release controls.

## Publication

Only `brynja 0.3.2` is selected for crates.io publication. All unchanged
modern supporting crates retain version `0.1.0` and are not republished.
Legacy and repository-only packages remain unpublished.

Publication still requires the repository owner's committed PASS pentest
report, green hosted GitHub checks, explicit tag authorization, and the exact
signed tag at `HEAD`.

The initial pentest reported no exploitable vulnerability. Its one optional
defense-in-depth observation was adopted: actual requirement targets are now
resolved and rejected if a repository-internal symlink escapes the repository
root. A dedicated regression fixture covers the boundary. Repository-owner
retest then identified missing production history enforcement and unrelated
decision-link acceptance as two medium findings. Both are remediated with
immutable history, revision, transition, mapping-scope, source, disposition,
ownership, and private-use classification checks plus 16 dedicated fixtures.
The next retest found that protocol rows could still select reviewed-global;
that remaining medium bypass is closed with governance-only global mappings,
immutable released scope, exact IANA sources for the affected pilot rows, and
two additional fixtures. The final repository-owner retest passed all
remediations with zero open findings. The release now awaits green hosted
GitHub checks and explicit tag authorization.

## Limitations

The pilot proves the data model, transitions, mappings, and failure behavior;
it is not complete normative coverage. Versions v0.3.3 through v0.3.5 populate
cryptographic, encoding, PKIX, TLS, DTLS, QUIC, optional, legacy, and residual
requirements before implementation begins. No matrix row, surface decision,
compiled scaffold, or Cargo feature is a protocol, security, interoperability,
or FIPS validation claim.
