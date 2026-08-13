# Brynja v0.20.0 Scheduled Public Checkpoint

Status: cumulative pentest and remediation retest passed; awaiting green hosted checks

Brynja v0.20.0 adds bounded DER framing in `brynja-pki 0.2.0`. The
checkpoint selects 15 packages for eventual crates.io publication. Its
cumulative assessment, remediation, and retest passed with zero open findings,
but none may publish until the permanent report and release-check candidate are
committed and GitHub and CodeQL are green.

## Bounded DER Reader

- A safe-Rust, `no_std`, allocation-free reader borrows exact header, content,
  and encoded input slices without copying.
- Non-recursive primitive, constructed-start, and balanced constructed-end
  events use a caller-selected fixed compile-time frame stack.
- Named immutable limits bound input bytes, depth, nodes, children per parent,
  identifier octets, length octets, value bytes, and total parsing work.
- Canonical low/high tag rules, definite minimal lengths, universal
  end-of-contents rejection, checked offsets, and parent containment reject
  malformed or ambiguous framing.
- Every failed read preserves the observable reader position and returns a
  closed payload-free error.

This release does not implement type-specific ASN.1 canonicality, SET ordering,
X.509, path validation, revocation, cryptography, signature verification,
independent cryptographic verification, or FIPS validation.

## Verification

- Fourteen integration tests cover canonical forms, nesting, multiple roots,
  every truncation point, malformed tags and lengths, parent escape, every
  resource ceiling, stack mismatch, and failure atomicity.
- One exhaustive corpus parses all 65,536 two-octet inputs deterministically.
- Three compile-fail examples reject positional/default limits and formatting
  of reader state or borrowed elements.
- Six implementation files are SHA-256 locked and remain below 500 lines.
- Thirty-three broken policy fixtures reject allocation, recursion, unsafe/FFI,
  I/O, provider or cryptographic coupling, mutable/public internals, missing
  canonical checks, limit weakening, graph drift, and source drift.
- The exact X.690 edition and mandatory erratum are linked to implemented
  requirement `BRY-REQ-ENC-0001` revision 2 and the dedicated
  `format.der.framing` surface.

The scheduled cumulative assessment found no Critical, High, or Medium issue
and one Low semantic-boundary oracle. An incomplete nested identifier or length
could inspect one adjacent byte beyond its parent before rejection. Every
header byte access is now parent-boundary-aware, and regressions prove adjacent
bytes cannot influence the nested error. Repository-owner retest of exact
signed remediation candidate
`7fd31b4cc536cb2dce1a565fa3551365b086000f` passed with zero open findings.

## Candidate Publication Set

The dependency-ordered candidate set is:

1. `brynja-core 0.9.0`
2. `brynja-crypto 0.1.2`
3. `brynja-crypto-cpu 0.1.1`
4. `brynja-crypto-cpu-std 0.1.1`
5. `brynja-pki 0.2.0`
6. `brynja-protocol 0.1.0`
7. `brynja-platform 0.1.8`
8. `brynja-tls13-handshake 0.1.8`
9. `brynja-tls12 0.1.8`
10. `brynja-tls13 0.1.8`
11. `brynja-tls 0.1.8`
12. `brynja-dtls 0.1.8`
13. `brynja-quic-tls 0.1.8`
14. `brynja-sanitization 0.1.1`
15. `brynja 0.20.0`

This list is a pending release plan, not evidence that any candidate is already
published. The release script publishes only selected changed packages, in
dependency order, and never republishes unchanged or repository-only crates.

## Pentest And Release Process

The scheduled assessment is backwards-looking and cumulative: its baseline is
signed v0.15.0 and its endpoint is the exact signed v0.20.0 implementation
candidate. A PASS/PASS report with zero open findings must be committed before
the release-check commit waits for green GitHub and CodeQL. Only explicit user
authorization after those checks permits the signed tag and package
publication.
