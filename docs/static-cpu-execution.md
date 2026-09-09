# Static CPU execution

Raw sessions require explicit `PublicData::new(...)` classification of both
state and input blocks. This is a visible caller attestation, not proof that
bytes are non-secret and not an erasing owner. Never classify secret-derived
material this way. Operations are synchronous without caller callbacks; signal
handlers and async-reentrant entry into a running owner are unsupported.

Status: v0.24.31 is signed. v0.24.32 adds explicit PublicData classification to raw calls; high-level and hardened hash acceleration remain separate work.

`brynja-crypto-cpu` provides `static_execution::{Authority, Kernel, Session}`
behind its default-off `static-execution` feature. This is an ordinary
public-data, raw compression/permutation API, not the complete hash-family
integration scheduled next. Existing hash constructors, legacy APIs and
runtime-detection paths retain their previous admission behavior.

| Kernel | Compiler target bundle | Executable platform contract |
| --- | --- | --- |
| X86Sha256 | x86_64, sha, sse2 | SHA instructions and XMM state on every eligible CPU |
| X86Keccak | x86_64, avx, avx2 | AVX2 plus OSXSAVE/XCR0 XMM/YMM state on every eligible CPU |
| ArmSha256 | aarch64, neon, sha2 | Advanced SIMD state and SHA2 on every eligible CPU |
| ArmSha512 | aarch64, neon, sha3 | Advanced SIMD and the complete Rust SHA3/SHA512 bundle |
| ArmKeccak | aarch64, neon, sha3 | Advanced SIMD and the complete Rust SHA3/SHA512 bundle |

Static compilation is a deployment contract, not runtime detection. A binary
built with these target features must execute only on compatible CPUs with OS
register state enabled throughout its lifetime, including scheduler migration,
virtualization and hotplug. Do not distribute it as a generic binary. Rust may
emit enabled instructions elsewhere in the executable, before an API call.
The API cannot make an incompatible specialized executable safe to launch.
Neither a Cargo feature nor `!Send`/`!Sync` establishes hardware support.

Rust defines unsupported target-feature execution as undefined behavior;
the Arm `sha3` Rust bundle represents FEAT_SHA3 **and** FEAT_SHA512, not an
inference from one loosely named host flag.
[Rust target-feature rules](https://doc.rust-lang.org/reference/attributes/codegen.html#the-target_feature-attribute),
[Rust Arm feature definitions](https://doc.rust-lang.org/src/std_detect/detect/arch/aarch64.rs.html).

## Ownership and failures

`Authority::new(kernel)` checks the exact architecture and compiler bundle
before executing a direct known-answer test using the actual kernel. Feature
and architecture failures return typed errors. A KAT failure retains a
quarantined authority; `session()` rejects it. The owner cannot be reset or
cloned. Generations progress from testing (1) to tested (2), and once to
explicitly quarantined (3), without wraparound.

The internal `Testing` state rejects sessions and operations with `NotReady`,
distinct from permanent `Quarantined` failure. Both reject before generation,
feature checks or caller-buffer mutation. Construction remains synchronous:
public callers never receive an owner still in `Testing`. This distinction
does not introduce asynchronous startup, retries or a reset mechanism.

`StaleGeneration` is also an internal defensive distinction: the only public
generation-changing transition is quarantine, and `Quarantined` takes
precedence. Safe public callers cannot currently observe `NotReady` or
`StaleGeneration`; tests construct private lifecycle models to cover them.

Sessions borrow the exact owner and generation. Every operation checks health,
generation, full compiler bundle and operation identity before state mutation.
`quarantine()` invalidates all sibling sessions irreversibly; repeated calls
are idempotent. Reports are freely copyable diagnostics and cannot mint or
renew authority. Neither owners nor sessions transfer between threads.

Quarantine is caller-owner-local. Creating a distinct owner performs a fresh
KAT; this is not a global FIPS-module error latch or a continuing hardware fault
detector. There is no automatic recovery or silent fallback in an established
session. High-level Portable/Prefer/Require routing belongs to subsequent
family integration; these low-level calls require the exact requested kernel.

## Use

Select the leaf with `default-features = false, features = ["static-execution"]`.
For a target-specialized x86 SHA executable, compile with
`RUSTFLAGS="-C target-feature=+sha,+sse2"` only after verifying its deployment
platform meets the full contract. Equivalent Arm and AVX2 bundles are above.

```rust
use brynja_crypto_cpu::static_execution::{PublicData, Authority, Error, Kernel};

fn compress_public_block(state: &mut [u32; 8], block: &[u8; 64]) -> Result<(), Error> {
    let authority = Authority::new(Kernel::X86Sha256)?;
    let session = authority.session()?;
    session.compress_sha256(PublicData::new(state), PublicData::new(block))
}
```

Use the full hash crates for padding, streaming and digest identity. Raw state
and block APIs require the caller to implement those mathematical operations
correctly. These ordinary kernels do not clear secret-derived schedules,
temporaries or state: **do not use them for HMAC, keys, passwords or confidential
data**. Hardened accelerated owners remain a separate planned implementation.

## Evidence and limits

The downstream fixture `assurance/static-cpu-execution` uses only public APIs
without evidence cfgs. It checks complete known vectors, exact route counts,
sibling revocation and error atomicity. Package tests use extracted normal
Cargo artifacts. Source and compiled mutants exercise feature checks, startup
testing and health generations; Miri covers the non-instruction lifecycle.

Native AMD and supplemental AArch64 QEMU execution are distinct observations;
QEMU is not native Arm, side-channel or migration evidence. No fresh AWS or
Apple native capture is claimed here. RISC-V and legacy execution are not
enabled by this API. Independent cryptographic review and FIPS validation
remain absent, and no cryptographic kernel algorithm is changed in this step.

The architecture gate also accepts big-endian AArch64, but this release has
no big-endian execution evidence. That target is unverified, not known-broken
or natively qualified. Windows/macOS execution, heterogeneous migration,
feature withdrawal and machine-level side-channel evidence are likewise not
established by the current AMD-native and little-endian Arm-QEMU observations.
