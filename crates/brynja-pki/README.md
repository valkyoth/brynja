<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja">Crates.io</a>
  |
  <a href="https://docs.rs/brynja">Docs.rs</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md">Release Plan</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md">Threat Model</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/brynja">
    <img src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja security-first Rust cryptography and secure protocols overview">
  </a>
</p>

# brynja-pki

`brynja-pki 0.2.0` implements Brynja's first PKI substrate: a borrowed,
allocation-free, non-recursive DER framing reader. It accepts canonical
identifier and definite minimal length encodings, emits primitive and balanced
constructed traversal events, and exposes exact header, content, and encoded
input slices without copying.

Every reader is created with named immutable limits for input bytes, depth,
nodes, children per parent, identifier octets, length octets, value bytes, and
total parsing work. A caller-selected const stack capacity bounds traversal
storage. Truncation, overflow, indefinite or non-minimal lengths,
non-canonical high tags, universal end-of-contents, parent-boundary escape, and
resource exhaustion fail closed without advancing reader state.

## Cryptography Verification Status

No PKI code in this crate has been independently reviewed. This component only
moves from ❌ to ✅ when a named independent reviewer signs off and the
evidence is linked from its status entry. Project tests, CI, Kani, Miri,
fuzzing, and pentesting do not by themselves constitute independent
verification.

| Component | Cryptographic scope | Independently verified |
| --- | --- | --- |
| `brynja-pki` | ASN.1, DER, X.509, path validation, and revocation | ❌ Not verified |

Only DER tag-length-value framing is implemented. ASN.1 primitive semantics,
SET ordering, X.509, path validation, revocation, cryptography, signature
verification, and FIPS validation remain unimplemented. Passing project tests,
the scheduled pentest, CI, Kani, Miri, or fuzzing does not make this component
independently cryptographically verified.

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.15"
```

The last published package is `0.1.7`. This `0.2.0` candidate is selected for
the v0.20.0 checkpoint and remains unpublished until the committed release-
check candidate and hosted checks pass. The cumulative v0.15.0 to v0.20.0
assessment and remediation retest now record PASS/PASS with zero open
findings. The initial assessment found one Low semantic-boundary oracle and no
Critical, High, or Medium issue; parent-aware header access and focused
regressions remediate it. This crate is governed by the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).

The project-wide no-third-party-crates, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
