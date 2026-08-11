# Brynja v0.13.2 Development Milestone

Status: implementation complete; awaiting pentest

Brynja v0.13.2 reserves the package, dependency, source, and future low-level
boundaries for CPU acceleration. It advances the `brynja` facade to 0.13.2 but
keeps both new packages outside that facade and selects no crate for crates.io
publication.

## Reserved Packages

- `brynja-crypto-cpu 0.1.0` is a zero-dependency `no_std` boundary reserved
  for separately admitted, first-party Rust ISA kernels and static selection.
- `brynja-crypto-cpu-std 0.1.0` is a directly selected host-adapter boundary
  depending only on `brynja-crypto-cpu`. Its placeholder deliberately remains
  `no_std` until a later milestone authorizes runtime detection.
- The ordinary facade, scalar cryptography, every protocol engine, default
  features, bare-metal graphs, and validated-module/FIPS graphs remain
  independent of both packages.

Both packages are inert. They expose only false implementation-status
constants used to prevent a placeholder from being mistaken for executable
cryptography or dispatch.

## Machine-Enforced Boundary

`security/cpu-acceleration-boundary.toml` records:

- zero active backends and zero additional low-level-code allowances;
- eight reserved x86_64, AArch64, and RISC-V backend identities;
- one exact future module, architecture, instruction bundle, and ABI
  precondition set for each identity;
- thirteen safe-wrapper invariants and fifteen mandatory amendment artifacts;
- exact source hashes and a 500-line maximum for every admitted source; and
- explicit facade, engine, default, bare-metal, detector, and FIPS exclusions.

The policy is intentionally preparatory. A reserved identity or path does not
authorize the module to exist, execute an instruction, claim performance, or
enter a validated artifact.

## Verification Evidence

- workspace metadata validates all 27 classified packages in no-default and
  all-feature graphs;
- the CPU-boundary validator checks package manifests, direct-dependency
  direction, source inventories, source hashes, reserved modules, claims,
  review size, FIPS separation, and the complete future admission checklist;
- eighteen broken fixtures reject premature activation, nonzero allowances,
  policy weakening, source drift, low-level tokens, oversized or unregistered
  files, false implementation claims, third-party detection, facade or engine
  smuggling, and build scripts; and
- 33 workspace-policy fixtures include independent rejection of either CPU
  package entering the ordinary facade and of the kernel package entering a
  protocol engine.

## Security And Verification Status

This milestone adds no cryptographic primitive, CPU detector, intrinsic,
assembly, executable backend, dispatch implementation, build script, new
low-level site, performance admission, or FIPS service. No cryptographic or
protocol component has gained independent verification. Future low-level
symbols remain subject to a primitive-specific source hash, safe-wrapper proof,
known-answer and scalar-differential tests, native-hardware and emitted-code
evidence, side-channel review, FIPS disposition, and independent assessment.

## Release Process

v0.13.2 is an internal development milestone in the cumulative range after
v0.10.0 through v0.15.0. It selects zero crates for crates.io publication. The
complete local gate, any required assessment and remediation, green GitHub and
CodeQL, and explicit repository-owner authorization remain mandatory before
the signed `v0.13.2` tag.
