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

`brynja-crypto-cpu-std` is the separate opt-in host detector and SHA-2
dispatch-reporting adapter. It uses the standard library's architecture feature macros,
depends only on `brynja-crypto-cpu` and `brynja-hash-sha2`, and is selected
directly by host applications. It never enters Brynja defaults, protocol
engines, bare-metal graphs, or a FIPS validated-module artifact.

`RuntimeSha256Backend::opportunistic()` detects an exact supported feature
bundle once, runs the backend's startup KAT, and otherwise retains portable
scalar SHA-256. `RuntimeSha256Backend::required()` never silently falls back.
Reports distinguish accelerated execution from unavailable hardware,
unadmitted candidate code, and quarantine. No global default or hidden
initialization is installed.

`RuntimeSha256Backend` also owns SHA-224 selection because both algorithms use
the same exact compression kernel. `RuntimeSha512Backend` reports AArch64
SHA-512 candidate availability and retains scalar SHA-384, SHA-512,
SHA-512/224, and SHA-512/256 until admission. x86_64 SHA-512 is intentionally
scalar, and required SHA-512-family acceleration fails closed.

The x86_64, AArch64, and RV64 Zknh kernels remain unadmitted in v0.22.2 pending complete
native evidence. This adapter detects only the stable x86_64 and AArch64
feature bundles; RISC-V automatic detection stays intentionally disabled, so ordinary runtime selection reports
`ScalarBackendUnadmitted` on qualifying machines. QEMU and cross-compilation
can supplement instruction and portability evidence but cannot establish a
native admission claim. The registered RISC-V host lacks the required SHA
extensions, so this candidate is explicitly QEMU/codegen-only there. Brynja
will seek additional exact-feature native observations through a reproducible
post-v1.0.0 community campaign, while retaining the normal authenticated
admission gates.

## Example

```rust
use brynja_crypto_cpu_std::{RuntimeSha256Backend, RuntimeSha256Selection};

let backend = RuntimeSha256Backend::opportunistic();
let digest = backend.hash(b"abc")?;
let report = backend.report();

assert_eq!(digest.as_bytes().len(), 32);
assert!(matches!(
    report.selection(),
    RuntimeSha256Selection::ScalarNoFeature
        | RuntimeSha256Selection::ScalarBackendUnadmitted
));
# Ok::<(), brynja_crypto_cpu_std::RuntimeSha256Error>(())
```

Applications that require acceleration use `RuntimeSha256Backend::required()`
and handle `RequiredAccelerationUnavailable` rather than receiving scalar
output.

## Cryptography Verification Status

No cryptographic or dispatch code in this crate has been independently
reviewed. A component only moves from ❌ to ✅ when a named independent reviewer
signs off and the evidence is linked. Project tests, CI, Kani, Miri, fuzzing,
and pentesting do not by themselves constitute independent verification.

| Component | Cryptographic scope | Independently verified |
| --- | --- | --- |
| SHA-256 host detection and dispatch | x86_64 SHA and AArch64 NEON/SHA2 selection, explicit scalar fallback, and no automatic RISC-V activation | ❌ Implemented; accelerated candidates remain unadmitted and not independently verified |
| SHA-512-family host reporting | AArch64 NEON/SHA-512 observation, explicit scalar fallback, x86 scalar-only decision, and no automatic RISC-V activation | ❌ Implemented; accelerated candidates remain unadmitted and not independently verified |

Version `0.1.1`, with its exact CPU-boundary dependency update, was published
at v0.20.0 after the cumulative pentest, remediation retest, and hosted gates
recorded `PASS`/`PASS` with zero open findings. The project-wide
first-party Rust, dependency, source-size, platform, FIPS, and low-level-code
policies apply here.
