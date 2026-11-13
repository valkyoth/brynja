# Using the AES block APIs

This guide describes the current checkout's development APIs. It is not a
crates.io publication announcement or deployment qualification. AES here is a
single-block primitive, not message encryption: no authentication, padding,
nonce management or TLS key schedule is supplied. Do not invent a protocol by
repeatedly calling these block operations. No HSM is required.

## Choose an explicit route

| Route | Dependency feature | Public key-owner namespace | Admission |
| --- | --- | --- | --- |
| Portable software | `hazmat-aes-block` | `brynja_crypto::aes` | No CPU authority; never silently switches to an accelerated owner |
| Static acceleration | `aes-static-execution` | `brynja_crypto::aes::execution` | Borrow a healthy `execution::Authority`; compile for the complete ISA bundle and deploy only on compatible CPUs |
| Hosted acceleration | `aes-runtime-execution`, also explicitly on `brynja-crypto-cpu-std` | `brynja_crypto::aes::execution` | Borrow the kernel authority from `brynja_crypto_cpu_std::aes::Authority`; reviewed little-endian AArch64 Linux/macOS routes only |

For the facade, enable the same feature on `brynja` and replace
`brynja_crypto` with `brynja::crypto`. The hosted adapter remains a separate
dependency; the facade does not install a global detector or own your selection.
Static acceleration remains usable without std. Enabling an acceleration feature
does not turn the ordinary portable constructors into dispatching constructors.

Static `Authority::new(Kernel::X86AesNi)` requires the x86 AES/SSE2 bundle;
`Kernel::ArmAes` requires the AArch64 AES/NEON bundle. Compilation success alone
does not authorize executing a target-specialized binary on another CPU.
Keep the authority alive for every key that borrows it. Check admission through
a session or key construction, not merely a copied diagnostic report: low-level
construction can retain a quarantined owner for diagnostics.

For hosted selection, choose `Mode::Require` when acceleration is mandatory.
`Mode::Prefer` can return a portable selection only for pre-execution
unavailability; the application must then explicitly construct a portable key.
`kernel_authority()` returns `None` for that portable selection, not for a failed
kernel. After startup or an operation fails, propagate the error; do not retry
the operation through portable AES. A selected authority's quarantine is terminal.
Generic hosted x86 selection is unavailable because current-core detection does
not establish the required lifetime migration contract.

The optional Arm `DitPolicy::Require` is available through `new_with_dit`.
It rejects missing DIT and disables portable fallback, including under
`Mode::Prefer`. It covers expansion and block kernels, not the entire owner or
application. See [DIT policy](assurance/aes-dit.md) and
[platform limits](assurance/aes-platform-side-channels.md). RISC-V remains an
[evidence-only candidate](assurance/aes-riscv-development.md), not an ordinary
static or hosted deployment route.

## Own the buffers and their lifetimes

| AES width | Input key / operation-local owner storage | Cached `ExpandedKey` storage | Block size |
| --- | --- | --- | --- |
| 128 | 16 bytes | 176 bytes | 16 bytes |
| 192 | 24 bytes | 208 bytes | 16 bytes |
| 256 | 32 bytes | 240 bytes | 16 bytes |

Choose `Aes128Key`, `Aes192Key` or `Aes256Key` for operation-local expansion.
The corresponding `ExpandedKey` keeps its schedule until clear/drop, reducing
repeated expansion at the cost of a longer-lived, larger secret buffer. These
storage choices apply to both portable and accelerated owners.

Declare storage before constructing the owner. For acceleration, declare the
authority before the key owners. Key owners cannot outlive their storage or
authority, and cannot be copied, cloned or sent to another thread. Input keys
are borrowed during construction; the caller remains responsible for their
original storage and any copies.

`encrypt_block` and `decrypt_block` return a clearing `SecretBlock` borrowing
the output buffer. Borrow its `expose()` result only while that owner is live;
use a checked slice-to-array reference conversion when passing it to another
block operation. That conversion need not copy the block. Explicit `clear()`
consumes the owner and clears its buffer; ordinary Drop also clears it. Clear
or drop output owners before inspecting or reusing their backing storage.

`encrypt_block_public` instead requires `PublicCiphertext::acknowledge()` and
leaves successful ciphertext in caller-owned public storage. This is an explicit
intent marker, not authentication or access control. There is no public decrypt.
Errors after secret destination admission clear that destination; failed public
encryption leaves the caller's public destination unchanged. Follow the API's
error contract rather than treating a buffer's contents as a success signal.

## Tested examples and how to run them

These source examples are already consumed by the existing verification runners;
the guide does not introduce a second, untested copy of their Rust code.

- [Portable README example](../crates/brynja-crypto/README.md#raw-aes-ownership-example-development-api): all three widths and both owner forms, public known answers, borrowed round trips and explicit clearing. The archive runner compiles and executes the README code for direct and facade consumers.
- [no_std accelerated example](../assurance/aes-accelerated-campaigns/no-std.rs): all six owners and all three output methods, caller-backed storage, borrowed authority and error propagation. This is compiled as a library from archives, not executed or claimed as native qualification.
- [Packaged authority adapter](../assurance/aes-accelerated-campaigns/lib.rs): shows static construction and hosted `Mode::Require`, checks live health, and keeps the owning authority alive behind the returned borrow. `ForcedAuthority` is a test helper, not an exported Brynja API.
- [Round-trip example](../assurance/aes-public-api/tests/roundtrip.rs): borrow the actual encrypted result, clear the encrypting key, decrypt through either owner form, then clear both result buffers and verify canaries. The accelerated runner changes only the import and authority arguments, preserving the assertions.
- [Hosted selection consumer](../assurance/aes-hosted/src/main.rs): handles unavailable required acceleration, exercises both owner forms against known answers, and demonstrates terminal quarantine without fallback. Its `expect`/assertions belong to a test executable; applications should propagate errors and supply their own key lifecycle.

From a checkout with the named Rust toolchains, targets and QEMU provisioned:

```sh
brynja-verify run aes packaged-portable
brynja-verify run aes --needed --category aes-roundtrip
brynja-verify run aes --needed --category aes-accelerated-no-std
brynja-verify run aes --needed --category aes-hosted
```

These commands execute explicit checks; plain `brynja-verify aes` only scans
recorded status. Read the [acceptance worklist](assurance/aes-usability-acceptance.md)
for exact configurations and the distinction between current consumer checks
and historical evidence. Native ARM/Apple observations are not refreshed by
QEMU. Accelerated timing qualification remains unresolved; this investigation
has not established a portable-AES defect. The recorded portable timing screens
retain their own finite host/build scope, not a universal constant-time guarantee.
Cleanup does not promise erasure of compiler spills, registers, dumps or caller
copies, and no physical-fault resistance is claimed.
