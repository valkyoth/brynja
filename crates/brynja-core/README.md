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

`brynja-core 0.3.0` adds Brynja's allocation-free v0.6 checked numeric and
resource foundations to the v0.5 alert and failure value domains. It provides
compile-time bounded `u64`/`usize` values, semantically distinct counts and
lengths, non-wrapping sequence numbers and epochs, and immutable explicit
resource and work budgets.

Every arithmetic operation is checked independently of build profile.
Sequence and epoch exhaustion cannot wrap or reuse zero. Budget checks return
the existing typed, limit-value-free exhaustion result without mutating the
budget. Every resource limit is supplied exactly once through a named builder
method; duplicate and incomplete assignments fail with a typed domain-specific
error. Numeric values and budget types intentionally implement neither `Debug`
nor `Display`; the fixed, valueless `NumericError` enum implements `Debug` for
safe diagnostics. This is not a TLS state machine, cryptographic
implementation, PKI processor, provider implementation, or production-ready
transport.

## Protocol Verification Status

The alert, failure, numeric, and budget domains have not been independently
reviewed. Project tests, CI, Kani, Miri, fuzzing, and pentesting do not by
themselves constitute independent protocol verification.

| Component | Protocol scope | Independently verified |
| --- | --- | --- |
| `brynja-core` | Alert, failure, bounded numeric, sequence, epoch, and budget value domains | ❌ Not verified |

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.6"
```

The `0.3.0` package is selected for publication with Brynja v0.6.0. The
repository-owner pentest and retest passed; publication still requires green
hosted release checks under the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).

The project-wide no-third-party-crates, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
