<p align="center">
  <b>Security-first, dependency-free, no_std TLS in Rust.</b><br>
  Built in small audited releases with strict modern/legacy protocol isolation.
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
    <img src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja Rust TLS crate overview">
  </a>
</p>

# brynja-core

`brynja-core 0.2.0` provides Brynja's allocation-free v0.5 alert and failure
value domains. It classifies every TLS AlertDescription registry byte without
coercing reserved or unassigned values, admits assigned alerts by concrete TLS
or DTLS version, and keeps orderly close, cancellation, local failure,
provider failure, and resource exhaustion distinct.

Failure envelopes contain only closed enums. They intentionally implement
neither `Debug` nor `Display`, accept no arbitrary strings or byte payloads,
and expose no numeric resource limits. This is not a TLS state machine,
cryptographic implementation, PKI processor, provider implementation, or
production-ready transport.

## Protocol Verification Status

The alert and failure domains have not been independently reviewed. Project
tests, CI, Kani, Miri, fuzzing, and pentesting do not by themselves constitute
independent protocol verification.

| Component | Protocol scope | Independently verified |
| --- | --- | --- |
| `brynja-core` | Alert registry, close, cancellation, and failure value domains | ❌ Not verified |

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.5"
```

The `0.2.0` package is selected for publication with Brynja v0.5.0 after the
version-specific pentest, a committed PASS report, green GitHub checks, and
explicit tag authorization required by the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).

The project-wide no-third-party-crates, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
