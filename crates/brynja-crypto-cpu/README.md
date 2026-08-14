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

# brynja-crypto-cpu

`brynja-crypto-cpu` is the optional, zero-dependency, `no_std` package for
separately reviewed first-party ISA kernels and static selection. Version
0.1.1 now contains isolated SHA-256 candidates for x86_64 SHA instructions and
AArch64 SHA2 instructions. Portable `brynja-hash-sha2` continues to own
streaming state, padding, length accounting, finalization, and scalar fallback.

Both candidates are deliberately unadmitted in v0.22.1 while commit-bound
native evidence is incomplete. Ordinary construction therefore cannot execute
either kernel: static selection returns `None`, runtime-attested construction
returns `NotAdmitted`, opportunistic host use falls back to scalar, and
required acceleration fails closed. Evidence builds can directly exercise a
candidate only through the repository-only `brynja_cpu_evidence` configuration.

Every backend session is caller-owned and thread-bound. Construction checks
the architecture, runs a direct `abc` known-answer test, reports its exact
backend and health generation, and permanently quarantines that session after
a bad answer. The safe compression surface accepts exactly one 64-byte block.
The package does not detect CPU features, allocate, perform I/O, use foreign
code or assembly, own a global registry, promise register erasure, or claim
FIPS validation. It cannot be an implicit dependency of a protocol engine or
default feature.

## Cryptography Verification Status

No cryptographic code in this crate has been independently reviewed. A
component only moves from ❌ to ✅ when a named independent reviewer signs off
and the evidence is linked. Project tests, CI, Kani, Miri, fuzzing, and
pentesting do not by themselves constitute independent verification.

| Component | Cryptographic scope | Independently verified |
| --- | --- | --- |
| x86_64 SHA-256 candidate | SHA-extension compression | ❌ Implemented but unadmitted and not independently verified |
| AArch64 SHA-256 candidate | NEON/SHA2 compression | ❌ Implemented but unadmitted and not independently verified |

Metadata version `0.1.1` was published at v0.20.0 after the committed
cumulative pentest, remediation retest, and hosted gates recorded
`PASS`/`PASS` with zero open findings. The project-wide
first-party Rust, `no_std`, source-size, platform, FIPS, and unsafe-code
policies apply here.
