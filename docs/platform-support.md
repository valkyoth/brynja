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

Compilation is not a complete support claim. Production support later requires
native interoperability, entropy/time integration, lifecycle tests, packaging,
and platform-specific security review. Protocol-facing traits live in upstream
`no_std` interface crates; `brynja-platform` is a downstream implementer and is
never required by a protocol engine. Core packages may not inspect the OS or
assume `std`.

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
