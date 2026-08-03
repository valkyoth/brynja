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

`brynja-core 0.4.0` adds Brynja's allocation-free v0.7 borrowed read cursor to
the alert, failure, checked numeric, sequence, epoch, and immutable budget
value domains from earlier milestones.

Every arithmetic operation is checked independently of build profile.
Sequence and epoch exhaustion cannot wrap or reuse zero. Budget checks return
the existing typed, limit-value-free exhaustion result without mutating the
budget. Every resource limit is supplied exactly once through a named builder
method; duplicate and incomplete assignments fail with a typed domain-specific
error. Numeric values and budget types intentionally implement neither `Debug`
nor `Display`; the fixed, valueless `NumericError` enum implements `Debug` for
safe diagnostics. `ReadCursor` borrows caller input, advances only after an
exact checked range is available, returns borrowed slices and array references,
and consumes itself when `finish` checks for trailing data. It is not clonable
or formattable, and its value-free errors reveal no input, offset, requested
length, or available length. This is not TLS framing, a protocol parser, a TLS
state machine, cryptography, PKI, a provider, or a production-ready transport.

## Protocol Verification Status

The alert, failure, numeric, budget, and cursor domains have not been
independently reviewed. Project tests, CI, Kani, Miri, fuzzing, and pentesting
do not by themselves constitute independent protocol verification.

| Component | Protocol scope | Independently verified |
| --- | --- | --- |
| `brynja-core` | Alert, failure, bounded numeric, sequence, epoch, budget, and borrowed cursor domains | ❌ Not verified |

Most application users will eventually depend on the modern facade:

```toml
[dependencies]
brynja = "0.7"
```

The `0.4.0` package is selected for publication with Brynja v0.7.0. The
repository-owner pentest and retest passed; publication still requires green
hosted release checks under the
[release plan](https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md).

The project-wide no-third-party-crates, `no_std`, 500-line source-file,
platform-portability, and modern/legacy isolation policies apply here.
