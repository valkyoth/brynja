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

# brynja-crypto-cpu-std

`brynja-crypto-cpu-std` reserves the separate opt-in host CPU-detection and
dispatch-initialization boundary. It depends only on `brynja-crypto-cpu`, is
selected directly by host applications, and can never enter Brynja defaults,
protocol engines, bare-metal graphs, or a FIPS validated-module artifact.

The v0.1.1 placeholder deliberately remains `no_std`. It contains no runtime
detection, global initializer, detector dependency, platform service,
executable backend, cryptographic code, or low-level-code allowance. A later
implementation milestone must explicitly authorize standard-library use and
prove that detection evidence cannot activate a backend without its direct KAT
and migration-safe execution authority.
Version 0.13.3 registers native host lanes and a strict evidence-admission
schema without implementing detection here. An unavailable host stays
unadmitted, QEMU evidence cannot be promoted to a native claim, and recorded
runner metadata cannot authenticate evidence. Candidate/native claims remain
forbidden until a reviewed trusted-runner verifier is separately admitted.
Brynja v0.17.0 makes this exclusion structural: no std detector, ordinary
backend policy, opportunistic result, or adapter-owned global can enter or
alter its FIPS-aware module configuration or session.

## Cryptography Verification Status

No cryptographic or dispatch code in this crate has been independently
reviewed. A component only moves from ❌ to ✅ when a named independent reviewer
signs off and the evidence is linked. Project tests, CI, Kani, Miri, fuzzing,
and pentesting do not by themselves constitute independent verification.

| Component | Cryptographic scope | Independently verified |
| --- | --- | --- |
| `brynja-crypto-cpu-std` | Future host feature detection and dispatch initialization | ❌ Not implemented or verified |

Version `0.1.1`, with its exact CPU-boundary dependency update, was published
at v0.20.0 after the cumulative pentest, remediation retest, and hosted gates
recorded `PASS`/`PASS` with zero open findings. The project-wide
first-party Rust, dependency, source-size, platform, FIPS, and low-level-code
policies apply here.
