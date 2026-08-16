# Platform Support

Status: policy

| Tier | Targets | Day-one evidence |
| --- | --- | --- |
| Host test | Linux, Windows, macOS | Workspace tests on native GitHub runners |
| Compile | FreeBSD | `x86_64-unknown-freebsd` no_std workspace check |
| Compile | Android | `aarch64-linux-android` no_std workspace check |
| Compile | iOS | `aarch64-apple-ios` no_std workspace check |
| Compile | Bare metal | `thumbv7em-none-eabi`, `riscv32imac-unknown-none-elf`, and `x86_64-unknown-none` all-feature workspace checks |
| Contract | Aesynx | Stable adapter contract plus executable target-ABI or emulator harness required for v1 |

## Registered Native CPU-Acceleration Evidence

| Architecture lane | Available native evidence | Admission rule |
| --- | --- | --- |
| AMD x86_64 | Local AMD system | Record exact CPUID, microcode, OS, compiler and feature bundle; admit only forced paths measured on that CPU |
| Intel x86_64 | AWS Intel instance selected by observed CPUID | Instance-family marketing is not evidence; absent SHA, AES, carry-less, AVX2, VAES or AVX-512 features leave the corresponding path unadmitted |
| Apple AArch64 | Apple M2 macOS system | Record exact Apple CPU, macOS, compiler and AArch64 crypto/vector features; do not generalize M2 evidence to every Arm system |
| Server AArch64 | AWS Arm system | Record exact Graviton or successor CPU and observed features independently from Apple evidence |
| RISC-V | Available slow cloud host | Generic RISC-V and base RVV do not imply crypto extensions; admit only an exact ratified scalar-crypto or vector-crypto bundle seen on matching native hardware |

Every lane runs scalar as the portable baseline. `brynja-crypto-cpu` is a
reserved `no_std` backend package; the separate, currently inert
`brynja-crypto-cpu-std` boundary may provide opt-in runtime detection on
supported host systems after a later explicit admission. OS-less targets
use compiler-proven target features or an explicitly reviewed capability token.
Cross-compilation and QEMU prove build and supplemental instruction behavior,
not native performance, microarchitecture-specific side channels, CPU feature
detection, or production support. An unavailable or non-qualifying machine
produces a visible candidate or scalar-only result rather than a support claim.
Version 0.13.3 binds these lanes, three supplemental QEMU routes, exact
provenance fields, raw-artifact hashes, 90-day freshness, noise and
benchmark-order limits, and code-size, cold-start, latency, throughput, and
side-channel gates in `assurance/cpu-evidence-policy.toml`. All lanes remain
non-authorizing or unavailable and all ten admission-register backends remain
unadmitted. Exact-commit v0.23.3 correctness observations passed on local AMD,
observed-feature AWS Intel, Apple M2, and AWS Arm; the RISC-V host remains a
non-qualifying negative-feature lane.

Compilation is not a complete support claim. Production support later requires
native interoperability, entropy/time integration, lifecycle tests, packaging,
and platform-specific security review. Protocol-facing traits live in upstream
`no_std` interface crates; `brynja-platform` is a downstream implementer and is
never required by a protocol engine. Core packages may not inspect the OS or
assume `std`. The reserved CPU-detection boundary is a separate downstream
package, not a facade, core, or protocol dependency, and provides no entropy, clock,
transport, storage or generic OS integration.

The v0.4.0 bare-metal matrix proves only that the complete crate graph remains
OS-less and `no_std` compatible. It supplies no allocator, startup, interrupts,
entropy, time, transport, storage, device access, linker image, emulator, or
hardware evidence.

For v1, applications and kernels provide entropy implementations. Brynja ships
no built-in Windows, macOS, BSD, mobile, or bare-metal entropy FFI. Safe clock,
transport, and storage examples may be provided, but every future OS-specific
unsafe adapter requires its own crate, versioned unsafe/FFI milestone, platform
tests, and external audit. Missing capabilities always fail closed.

Real Aesynx hardware qualification may follow `1.0.0` if hardware is not
available during the release line, but the ABI/emulator, entropy, time,
transport, storage, acceleration, boot-to-handshake, and lifecycle contract is
a hard v1 gate.
