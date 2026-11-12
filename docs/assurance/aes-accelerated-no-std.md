# Packaged accelerated AES no_std and API isolation

This is compile-only coverage for the v0.27.3 development API, not native
hardware qualification. No production cryptography or publication gate changes.

```sh
brynja-verify run aes --needed --category aes-accelerated-no-std
```

The four registrations select Rust 1.90.0 and 1.99.1, each through the direct
`brynja-crypto` API and the `brynja` facade. Each consumer uses byte-checked
Cargo archives in an isolated workspace, offline, with exact dependency paths,
versions and active features checked from target-filtered Cargo metadata.
Neither route includes the hosted `brynja-crypto-cpu-std` adapter.

For each registration, twelve library builds cover both static and low-level
runtime features in debug/release on:

- `thumbv7em-none-eabi`: bare-metal Cortex-M, without an AES instruction backend;
- `x86_64-unknown-linux-gnu`: `+aes,+sse2`;
- `aarch64-unknown-linux-musl`: `+aes,+neon`.

The [no_std fixture](../../assurance/aes-accelerated-campaigns/no-std.rs)
forbids unsafe code and contains no allocator or std imports. It compiles every
key width, both raw and cached owners, secret encryption/decryption, explicit
public encryption and explicit clearing. Cargo must return a nonempty library
artifact in the isolated target directory; its SHA-256 is retained with the
command and both diagnostic streams. These are library builds, not final
executable links or runs. Linux target selection does not turn the fixture into
a std application, but it is not evidence for a bare-metal x86/ARM deployment.
On Cortex-M these APIs can compile while accelerated authority admission remains
unavailable. Low-level runtime construction retains its unsafe platform obligation;
enabling its feature does not supply a hosted detection mechanism.

Each registration also requires 53 positive/negative compiler pairs on Cortex-M:
49 existing ownership/admission probes and four feature-isolation probes. They
check default-off AES with dependency defaults both enabled and disabled,
portable AES without acceleration, and static admission without runtime
construction. Ownership probes cover all six owner types, authority lifetime,
borrow exclusivity, Send/Sync/Copy/Clone/Debug restrictions and the distinction
between reports and authority. Each positive twin must compile first; negatives
must return Cargo's compile-error status and exactly the expected diagnostic
codes/counts, with primary spans in the consumer source. Arbitrary compiler or
dependency failures cannot satisfy the negative check.

## Unsupported bare-metal x86 trial

An initial Rust 1.90.0 direct/static debug build for `x86_64-unknown-none`
with `+aes,+sse2` failed in LLVM: “Do not know how to split the result of this
operator!” The failed command and complete diagnostics remain in
`target/aes-accelerated-no-std/1.90.0-direct-8hp4uphx/` locally. This was not
recorded as a pass. The built-in target uses a soft-float ABI; diagnostic
configuration probes on both compiler endpoints warn that disabling soft-float
violates that ABI. No ABI override was adopted. This target is excluded from
the registered campaign and remains unsupported by this accelerated acceptance
scope; Linux x86 library success does not resolve its failure.

See the upstream [target description](https://doc.rust-lang.org/rustc/platform-support/x86_64-unknown-none.html)
and [target definition](https://github.com/rust-lang/rust/blob/main/compiler/rustc_target/src/spec/targets/x86_64_unknown_none.rs).

## Coverage limits

This checks API usability and feature isolation only at the two named compiler
endpoints and targets. It does not prove every compiler/target configuration,
hardware admission correctness, timing, native ARM behavior, fault resistance,
spill/register erasure or exception dispatch. Native campaigns and emitted-code
qualification remain separate. No timing measurements are taken or retried.

The runner has regression controls for archive escapes, feature/population
drift, malformed/wrong diagnostics, failed positive twins, missing/empty or
symlinked artifacts, ambient compiler overrides, target selection and exact
registry completion markers. Local records are observations, not authenticated
certification evidence.
