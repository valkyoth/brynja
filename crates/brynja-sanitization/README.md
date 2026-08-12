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

# brynja-sanitization

`brynja-sanitization 0.1.0` is a separately selected, `no_std`, downstream
secret-storage adapter. It wraps exact `sanitization 2.0.3` with default
features disabled and no activated transitive package. It is not enabled by
`brynja`, any TLS or DTLS engine, any default or all-features build, or the
future FIPS validated-module closure.

The adapter exposes one opaque, fixed-size, non-copyable owner with redacted
debugging, closure-scoped inspection, transactional replacement, explicit
clear, and named copies to and from `brynja-core` owned regions. Rich source
errors cannot cross its boundary. Modern and legacy callers use the same
protocol-neutral type; there is no legacy-specific adapter.

The package is implemented at Brynja v0.11.2 and selected for initial
publication at the v0.15.0 scheduled public checkpoint. The cumulative pentest
passed with zero findings, but it remains unpublished until every hosted
release gate passes.

```toml
[dependencies]
brynja-sanitization = { version = "0.1", default-features = false }
```

Until that checkpoint publication completes, downstream repository users must
use an exact reviewed Git revision or local path and accept the development
risk.

## Cryptography Verification Status

This package is pre-1.0 and has not been independently reviewed. A component
only moves from ❌ to ✅ when a named independent reviewer signs off and linked
review evidence is recorded. Project tests, CI, Kani, Miri, fuzzing,
code-generation inspection, pentesting, or upstream review are evidence, but
not independent verification or certification. It does not implement TLS,
cryptography, PKI, or a FIPS validated module.

| Component | Scope | Independently verified |
| --- | --- | --- |
| `brynja-sanitization` | Fixed-size secret ownership and explicit Brynja-region copies | ❌ Not verified |

The exact upstream package identity, unsafe inventory, verification evidence,
residual risks, and fail-closed re-review triggers are recorded in the
[admission review](https://github.com/valkyoth/brynja/blob/main/docs/sanitization-admission-review.md).
