# Hosted CPU execution authority

v0.24.32 implementation candidate; exceptional owner pentest and fresh native
adapter evidence remain pending. Independent cryptographic verification: NO.
FIPS validation: NO. This is ordinary public-data raw kernel execution, not
hardened hashing or a complete hash API. High-level integration follows in
v0.24.33; the original admission-gated hash adapters are unchanged.

## Opt-in API

Add `brynja-crypto-cpu-std` with its default-off `runtime-execution` feature.
Support-package version numbers stay at 0.1.1 until the next public checkpoint;
the current implementation is available from this repository, not the existing
published 0.1.1 artifact. The `brynja` facade does not acquire this dependency.
The CPU leaf remains zero-dependency `no_std`. Runtime opt-in also exposes the
separate static-execution module; it does not enable compiler target features.

```rust
use brynja_crypto_cpu_std::execution::{Authority, Kernel, Mode};

let owner = Authority::new(Kernel::ArmSha256, Mode::Prefer)?;
let report = owner.report();
match owner.session()? {
    Some(session) => { /* use this ordinary raw compression session */ }
    None => { /* consumer performs its explicitly selected portable work */ }
}
# Ok::<(), brynja_crypto_cpu_std::execution::Error>(())
```

`Portable` never probes or constructs a kernel owner. `Prefer` reports an exact
portable fallback reason before any kernel execution. `Require` returns that
reason as an error. Reasons distinguish wrong architecture, unavailable complete
features/OS state and missing migration guarantees. An accelerated owner first
executes the real kernel KAT. A failed KAT retains a quarantined owner; session
requests fail in BOTH preferred and required modes, without fallback.
Session errors preserve every input state word. Reports contain no machine name,
network data, environment identifier or secret. Detection starts no thread and
changes no process affinity, signal handler or global crypto configuration.

## Platform audit and availability

The standard-library source shipped with Rust **1.90.0 and 1.98.1** was inspected
at `library/std_detect/src/detect/os/`. The adapter uses stable Rust detection
macros, not its own foreign imports, external library or copied detector.

| Host | Detection and disposition |
| --- | --- |
| AArch64 Linux | `linux/aarch64.rs` uses auxiliary-vector HWCAP; NEON/SHA2 or NEON/full SHA3 bundle authorizes the corresponding route. |
| AArch64 Android | Same system interface with Rust's Exynos 9810 heterogeneous-core mitigation; SHA3 is suppressed on the affected configuration. |
| AArch64 macOS/iOS | `darwin/aarch64.rs` uses system `sysctlbyname` feature queries. SHA2 requires SHA1+SHA256+AdvSIMD; SHA3 requires SHA512+SHA3+AdvSIMD. |
| AArch64 Windows | `windows/aarch64.rs` uses `IsProcessorFeaturePresent`. Rust 1.90 detects SHA2 but not SHA3/SHA512; Rust 1.98 adds the latter flags. Unknown flags fail closed. |
| x86_64 Linux/Windows/macOS/BSD | Standard CPUID detection includes AVX OSXSAVE/XGETBV XMM/YMM checks. It does NOT establish a common scheduler/VM baseline: generic hosted execution remains unavailable. |
| AArch64 BSD and all other targets | No reviewed hosted execution authority in this version. Prefer reports fallback, Require errors. |

Linux documents HWCAP as the userspace availability interface and exposes safe
system-wide feature values across heterogeneous CPUs. Sources:
[ARM64 HWCAP](https://docs.kernel.org/arch/arm64/elf_hwcaps.html) and
[CPU feature-register ABI](https://docs.kernel.org/arch/arm64/cpu-feature-registers.html).
Apple documents its system queries in
[Determining instruction set characteristics](https://developer.apple.com/documentation/kernel/1387446-sysctlbyname/determining_instruction_set_characteristics).
Microsoft documents the installed-system interface in
[IsProcessorFeaturePresent](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent).
The Linux/Android detector source also records the pre-Android-9 Exynos issue.
FreeBSD's aux-vector interface and Rust's separate AArch64 detector need an
additional platform-specific review before authorization; OS name alone is not
feature evidence.

The safety assumption is a conforming OS/hypervisor preserving its advertised
process instruction ABI across scheduling, hotplug and VM migration. A malicious
or defective kernel/hypervisor is outside the guarantee. Rust macros may use
compiler-enabled features directly: target-specialized builds additionally
retain their normal deployment requirement to run only on compatible machines.
A KAT and a thread-bound Rust type are NOT migration protection. A successful
affinity query alone would also be insufficient; this version makes no affinity
calls. Unsupported platforms retain [explicit static execution](static-cpu-execution.md).
A future safe x86 affinity/platform adapter needs its own reviewed lifetime and
failure contract, not an automatic switch based on CPUID.

## Ownership and failure boundary

The hosted owner contains an opaque core owner; no public detector injection,
boolean constructor, marker trait, clone, reset or report-to-owner conversion
exists. Core `runtime_execution::Authority::from_platform` is an explicitly
unsafe integration boundary requiring the full CPU/OS/scheduler guarantee for
the owner's entire lifetime. Ordinary callers should use the safe hosted API.
No raw pointers or memory ownership are transferred across that boundary.

Every session borrows one owner and generation. Testing, stale generations and
quarantine reject before instructions or mutation. Quarantine is irreversible
for that owner; fresh construction is independent and cannot repair old sessions.
This is NOT a process-wide failure latch or FIPS module session. Static, hosted,
historical evidence-admission and hardened capabilities remain distinct.
No register/spill/cache/stack erasure or secret-bearing execution is claimed.

## Reproducible checks and evidence

Run these single-line commands from the repository root:

```sh
cargo fetch --locked
python3 scripts/cpu/check-hosted-execution.py
python3 scripts/cpu/check-hosted-execution.py --qemu
cargo run --locked --offline --release --manifest-path assurance/hosted-cpu-execution/Cargo.toml
```

The normal gate checks ordinary packaged downstream imports, default-off
rejection, debug/release lifecycle and strict fixture Clippy. Compiled mutants
exercise missing architecture/features/migration checks, required/preferred
confusion, testing/quarantine and generation failures. QEMU uses a generic
AArch64 musl binary with NO target-feature flags or evidence cfg and requires
three operational routes. Emulation is not native evidence or timing assurance.
The focused Miri/ASan owner suites do not claim to emulate CPU intrinsics.

Native AMD verifies safe unsupported-host disposition. Fresh Intel, AWS Arm and
Apple M2 captures must record the exact source commit, Rust version, commands,
selected routes and test outcomes after the exceptional pentest. Earlier kernel
evidence does not certify this new hosted authorization layer. Windows, Android,
iOS and BSD cross-compilation is not native execution evidence. No current
evidence establishes independent cryptographic review or FIPS validation.
