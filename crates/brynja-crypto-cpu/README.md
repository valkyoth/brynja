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

`brynja-crypto-cpu` is the optional, zero-dependency, `no_std` package boundary
reserved for separately admitted first-party ISA kernels and static selection.
It is downstream from portable scalar ownership and cannot be an implicit
dependency of a protocol engine or default feature.

Version 0.1.1 contains no detector, intrinsic, assembly, executable backend,
cryptographic algorithm, dispatch implementation, low-level-code allowance,
performance claim, or FIPS validation. Every future backend symbol requires
its own source hash, feature and ABI preconditions, safe-wrapper invariants,
KAT and quarantine path, native evidence, and primitive-specific review.
Version 0.13.3 provides the repository-level evidence schema, native/QEMU lane
registry, fault and differential fixtures, and performance admission budgets;
it records no backend result and admits no implementation in this package.
Candidate/native claims are forbidden until an independently reviewed
trusted-runner verifier exists, and observed operating state must exactly match
the reviewed ABI prerequisites.
Brynja v0.17.0 additionally requires every future FIPS-selected backend to be
owned by one exact module environment and complete feature bundle; ordinary
dispatch identity and this package alone cannot authorize or validate it.

## Cryptography Verification Status

No cryptographic code in this crate has been independently reviewed. A
component only moves from ❌ to ✅ when a named independent reviewer signs off
and the evidence is linked. Project tests, CI, Kani, Miri, fuzzing, and
pentesting do not by themselves constitute independent verification.

| Component | Cryptographic scope | Independently verified |
| --- | --- | --- |
| `brynja-crypto-cpu` | Future first-party CPU cryptographic kernels and static selection | ❌ Not implemented or verified |

Version `0.1.0` was published at v0.15.0. Metadata candidate `0.1.1` is selected
for v0.20.0 and remains unpublished pending its cumulative pentest and hosted
gates. The project-wide
first-party Rust, `no_std`, source-size, platform, FIPS, and unsafe-code
policies apply here.
