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
0.1.1 now contains isolated SHA-256-family candidates for x86_64 SHA,
AArch64 SHA2, and RV64 Zknh instructions plus SHA-512-family candidates for
AArch64 SHA-512 and RV64 Zknh instructions. Internal v0.24.4 source also adds
x86_64 AVX2 and AArch64 SHA3 Keccak-f[1600] candidates for later SHA-3/SHAKE
dispatch. Portable hash crates continue to own public streaming state,
padding, length accounting, finalization, and scalar fallback.

All seven candidates are deliberately unadmitted while commit-bound native
evidence is incomplete. x86_64 SHA-512 is a reviewed scalar-only decision;
RISC-V Keccak is also scalar-only because the pinned ratified authorities have
no qualifying Keccak instruction route. AVX2, SHA3, or AVX-512 availability
alone does not authorize a backend. Ordinary construction therefore cannot execute
any kernel: static selection returns `None`, runtime-attested construction
returns `NotAdmitted`, opportunistic host use falls back to scalar, and
required acceleration fails closed. Evidence builds can directly exercise a
candidate only through the repository-only `brynja_cpu_evidence` configuration.

The registered RISC-V host lacks `Zknh`, `Zvknha`, and `Zvknhb`. The RV64
candidate is therefore QEMU/codegen-only until qualifying real hardware is
available; generic RV64, RVV, or bit-manipulation support cannot qualify it.
The host remains useful for native scalar and exact-feature tests it really
supports, and a post-v1.0.0 community campaign will seek broader hardware
coverage without treating submitted observations as backend admission.

Every backend session is caller-owned and thread-bound. Construction checks
the architecture, runs a direct `abc` known-answer test, reports its exact
backend and health generation, and permanently quarantines that session after
a bad answer. The safe compression surfaces accept exactly one 64-byte or
128-byte block.
The package does not detect CPU features, allocate, perform I/O, use foreign
code or external assembly, own a global registry, promise register erasure, or
claim FIPS validation. The RV64 candidates contain six separately approved
register-only first-party Rust inline-assembly statements across SHA-256 and
SHA-512 operations. They cannot be an implicit dependency of a protocol
engine or default feature.

## Cryptography Verification Status

No cryptographic code in this crate has been independently reviewed. A
component only moves from ❌ to ✅ when a named independent reviewer signs off
and the evidence is linked. Project tests, CI, Kani, Miri, fuzzing, and
pentesting do not by themselves constitute independent verification.

| Component | Cryptographic scope | Independently verified |
| --- | --- | --- |
| x86_64 SHA-256 candidate | SHA-extension compression | ❌ Implemented but unadmitted and not independently verified |
| AArch64 SHA-256 candidate | NEON/SHA2 compression | ❌ Implemented but unadmitted and not independently verified |
| RV64 SHA-256 candidate | Zknh scalar-crypto compression | ❌ Implemented but unadmitted and not independently verified |
| x86_64 SHA-512 family | Scalar-only decision; no admitted instruction kernel | ❌ No accelerated implementation claimed |
| AArch64 SHA-512 candidate | NEON/SHA-512 compression | ❌ Implemented but unadmitted and not independently verified |
| RV64 SHA-512 candidate | Zknh scalar-crypto compression | ❌ Implemented but unadmitted and not independently verified |
| x86_64 Keccak candidate | AVX2 Keccak-f[1600] permutation | ❌ Implemented but unadmitted and not independently verified |
| AArch64 Keccak candidate | NEON/SHA3 Keccak-f[1600] permutation | ❌ Implemented but unadmitted and not independently verified |
| RISC-V Keccak | Scalar-only decision; no qualifying ratified instruction route in pinned authorities | ❌ No accelerated implementation claimed |

Metadata version `0.1.1` was published at v0.20.0 after the committed
cumulative pentest, remediation retest, and hosted gates recorded
`PASS`/`PASS` with zero open findings. The project-wide
first-party Rust, `no_std`, source-size, platform, FIPS, and unsafe-code
policies apply here.
