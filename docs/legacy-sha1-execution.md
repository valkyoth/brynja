# Ordinary operational legacy SHA-1

Development implementation for v0.24.41; owner pentest and fresh native release
qualification are pending. SHA-1 is collision-broken. These APIs are not for
new signatures, certificates, authentication, passwords or confidential data.
No independent cryptographic verification or FIPS validation is claimed.

The portable `Sha1` and `HardenedSha1` APIs are unchanged. New execution is
default-off: enable `execution` on `brynja-legacy-sha1`, or `runtime-execution`
on the separate `brynja-legacy-sha1-std` adapter. The modern facade and modern
protocol dependency graphs do not acquire a SHA-1 dependency.

## APIs and authority

- `Executor::portable()` never probes or executes an instruction backend.
- `Executor::for_compiled_target(Mode)` selects an explicitly specialized binary.
- `Authority::for_compiled_target()` requires the complete compile-time bundle.
- The separate unsafe `Authority::from_platform` boundary requires an external
  process-wide, lifetime-long feature contract. It is not a safe CPUID shortcut.
  Its mandatory non-panicking revalidator runs before startup and operations;
  a reported loss permanently quarantines existing streams, without fallback.
- `brynja_legacy_sha1_std::execution::select(Mode)` uses only the allowlisted
  AArch64 system feature APIs already reviewed for the modern hosted adapter.
- `Mode::Prefer` falls back only for unavailability before startup. Failed KATs,
  revoked owners and operation failures never silently switch to portable.
- `start(PublicData::acknowledge())`, `hash` and `hash_bits` require explicit
  public-data classification. Streams expose checked byte/bit capacity,
  irregular byte updates, consuming byte/bit finalization and cancellation.
- `quarantine()` permanently revokes the owner and every borrowing stream.
  Owners and streams are non-cloneable and thread-bound; reports grant nothing.

| Platform/profile | Execution contract |
| --- | --- |
| x86/x86_64 static | Explicit `+sha,+sse2` binary; deployment must preserve the bundle on every executing CPU |
| Little-endian AArch64 static | Explicit `+neon,+sha2` binary (Rust's SHA2 bundle includes SHA1) |
| AArch64 hosted Linux/Android/macOS/iOS/Windows | OS-wide feature ABI, complete NEON/SHA2 bundle, startup KAT |
| Generic hosted x86, BSD, unknown targets | Required fails; Prefer returns portable; current-core feature flags alone are insufficient |
| Confidential/keyed/hardened acceleration | Not provided here; separate v0.24.42 work |

These are the existing kernels, not a new SHA-1 variant. The earlier `cpu` and
`cpu-evidence` candidate API retains its two-key evidence-only gate, even with
Cargo feature unification. Operational execution uses a separate owner; it does
not set `is_admitted()` to true or claim independent backend approval.

## Memory and lifecycle boundaries

Private source-owned byte buffers retain their existing compiler-resistant Drop
cleanup. Kernel-local temporaries, registers and spills are not cleanup-qualified;
the new APIs must not process secrets. PublicData is a caller acknowledgement,
not a mechanism for detecting confidential bytes. Borrowed sessions cannot
outlive their owner. Finalization consumes the operation on success and failure;
length preflight is atomic, while backend failure destroys retained state.

| Residual risk | Responsibility and boundary |
| --- | --- |
| CPU hotplug or VM migration violates advertised process-wide features | The OS/hypervisor must preserve its capability ABI throughout execution. Repeated, potentially cached feature queries do not pin a thread, close a check-to-use race, or prove migration safety. Native correctness tests cannot establish this deployment property. |
| Confidential bytes passed with `PublicData::acknowledge()` | The caller classifies every input, including later streaming chunks. This token neither inspects bytes nor declassifies a secret owner. Ordinary streams do not implement the sealed hardened capability; confidential input requires the separate hardened API. |
| Repeated health-check overhead | Checks remain at every defensive boundary. The hosted callback reuses standard-library OS capability detection; no syscall-heavy polling, throttling or interval-based authorization is introduced. |

## Platform-specific trust basis

Cached detection is not live revocation. The built-in hosted callback uses
Rust's process-wide feature cache: calling it again does not re-query the kernel
or detect a post-construction feature loss. The leaf's callback interface can
honour a platform provider's revocation signal, and `quarantine()` remains an
explicit revocation mechanism; neither means the built-in adapter monitors
migration. The tests inject revocation, not physical CPU-feature loss.

The following mapping was checked against the shipped Rust 1.90.0 and 1.98.1
sources under `library/std_detect/src/detect/os/`, plus `detect/cache.rs`.
The five OS names are not interchangeable evidence of a Linux HWCAP contract.
All rows concern little-endian AArch64 and still require both Rust `neon` and
`sha2` detection; compiler-enabled target features retain the static binary's
deployment requirements.

| OS | Detector and justification | Limit of the justification |
| --- | --- | --- |
| Linux | `linux/aarch64.rs`: auxiliary-vector HWCAP; Rust's SHA2 bundle requires SHA1, SHA2 and ASIMD. Linux documents system-safe feature exposure across available CPUs. [HWCAP][linux-hwcap], [feature ABI][linux-features]. | Trust in a conforming kernel/hypervisor, not detection of a later ABI violation. |
| Android | The same Linux detector, including its Exynos 9810 workaround for misreported heterogeneous-core features on older Android. The workaround retains SHA1/SHA2 only with the required ASIMD bundle. [Rust Android handling][rust-linux]. | Known workaround, not a claim that every vendor kernel is correct. Unknown misreporting and nonconforming migration remain deployment risks. |
| macOS | `darwin/aarch64.rs`: Apple's system `sysctlbyname` ISA queries; Rust combines `FEAT_SHA1`, `FEAT_SHA256` and `AdvSIMD`. [Apple ISA queries][apple-isa], [Rust Darwin mapping][rust-darwin]. | Reliance on Apple's advertised system ISA, not a citation establishing arbitrary VM live-migration safety. |
| iOS | The same Rust Darwin detector and Apple ISA-query interface as macOS. It does not use Linux HWCAP or a current-core CPU identifier. [Apple ISA queries][apple-isa], [Rust Darwin mapping][rust-darwin]. | Same conforming-system assumption; macOS native observations do not constitute iOS qualification. |
| Windows | `windows/aarch64.rs`: `IsProcessorFeaturePresent`, documented as a query about the current computer. NEON plus `PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE` supplies the SHA1/SHA2 bundle. [Microsoft feature API][windows-features], [Rust Windows mapping][rust-windows]. | System capability API, not an independently established hotplug/VM-migration guarantee. |

The engineering basis for hosted execution is these OS-supported ISA interfaces
and their Rust mappings, **conditional on the OS/hypervisor maintaining its
advertised execution ABI**. In particular, the Apple and Microsoft references
are not represented as containing Linux's explicit heterogeneous-CPU wording.
Native platform tests establish correctness on the recorded host only. Windows,
Android and iOS are not native-qualified by Linux or Apple M2 runs.

The remaining Low platform-trust risk is documented, not eliminated by the
callback. Owner risk acceptance/retest and fresh release evidence remain
pending; no military/classified deployment qualification is claimed. Deployments
that cannot rely on their platform's advertised ABI must select portable mode.

[linux-hwcap]: https://docs.kernel.org/arch/arm64/elf_hwcaps.html
[linux-features]: https://docs.kernel.org/arch/arm64/cpu-feature-registers.html
[rust-linux]: https://github.com/rust-lang/rust/blob/1.90.0/library/std_detect/src/detect/os/linux/aarch64.rs
[apple-isa]: https://developer.apple.com/documentation/kernel/1387446-sysctlbyname/determining_instruction_set_characteristics
[rust-darwin]: https://github.com/rust-lang/rust/blob/1.90.0/library/std_detect/src/detect/os/darwin/aarch64.rs
[windows-features]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent
[rust-windows]: https://github.com/rust-lang/rust/blob/1.90.0/library/std_detect/src/detect/os/windows/aarch64.rs

The broader [hosted CPU platform review](hosted-cpu-execution.md#platform-audit-and-availability)
uses the same detection foundation. This SHA-1 review does not confer new
qualification on that separate API or on its hardened consumers.

## Reproducible checks

`cargo test -p brynja-legacy-sha1 --features execution` runs the new public
acceptance, including all 529 NIST vectors, byte/bit partitions, million-byte
input, revocation and consuming ownership. Generic builds test portable control
and unavailable required routes; this alone is not instruction-execution proof.

On a qualified SHA-capable x86 machine, run with invocation-local
`RUSTFLAGS="-C target-feature=+sha,+sse2"`. The static route emits the
`SHA1_OPERATIONAL` marker only after successful real hashing. No evidence cfg is
used. `python3 scripts/sha1/check-sha1-package.py --execution` repeats acceptance
against extracted packages and 1,135 independent bit-message oracle cases.
Cross-target/QEMU correctness remains supplemental, never native qualification.

After a green owner pentest, fresh native collection uses
`python3 scripts/sha1/capture-sha1-execution-native.py LANE OUTPUT.json --attest-native`.
Registered lanes are `amd-x86_64`, `intel-x86_64`, `aws-aarch64` and
`apple-m2-aarch64`. Fetch the locked workspace dependencies first. The capture
requires a clean committed checkout, verifies each host feature bundle, runs
generic/hosted and explicit static paths without candidate-evidence flags,
and repeats the independent packaged consumer checks. The JSON binds the
commit, compiler, reviewed sources, exact routes and results. Collection is
operator-self-attested and must be reviewed before release; it is not a proof
of hypervisor migration policy, side-channel resistance or physical erasure.

Ownership checks reject 19 invalid packaged uses; compiled debug/release
mutations demonstrate that revocation and finalization guards cannot be removed
without failing the tests. Scoped Miri covers portable owner lifecycle; ASan
covers ordinary execution state. Instruction-specific native checks are separate
from that generic sanitizer run.
