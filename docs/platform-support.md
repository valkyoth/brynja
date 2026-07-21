# Platform Support

Status: policy

| Tier | Targets | Day-one evidence |
| --- | --- | --- |
| Host test | Linux, Windows, macOS | Workspace tests on native GitHub runners |
| Compile | FreeBSD | `x86_64-unknown-freebsd` no_std workspace check |
| Compile | Android | `aarch64-linux-android` no_std workspace check |
| Compile | iOS | `aarch64-apple-ios` no_std workspace check |
| Planned | Aesynx | Architecture review against the local Aesynx target and APIs |

Compilation is not a complete support claim. Production support later requires
native interoperability, entropy/time integration, lifecycle tests, packaging,
and platform-specific security review. Core packages may not inspect the OS or
assume `std`; platform adapters must fail closed when a required capability is
unavailable.

