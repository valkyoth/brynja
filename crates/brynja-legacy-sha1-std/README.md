<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja-legacy-sha1-std">Crates.io</a>
  |
  <a href="https://docs.rs/brynja-legacy-sha1-std">Docs.rs</a>
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
    <img width="840" src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja security-first Rust cryptography and secure protocols overview">
  </a>
</p>

# brynja-legacy-sha1-std

Optional hosted CPU detection for the isolated, collision-broken SHA-1 leaf.
This crate is not a default or modern-facade dependency. The leaf stays `no_std`.

## Cryptography Verification Status

Default-off `strict-acceleration` adds `strict_execution::CompiledSession`.
Use the scalar session's `Limits`, `hash` and `hash_chunks` interfaces, with
build-wide SHA/SSE2 on x86-64 or NEON/SHA2 on little-endian GNU/Linux AArch64.
Deployment must preserve this bundle throughout execution. Startup KATs,
authority, state and staging stay on protected stacks. There is no fallback.
Cancellation permits reuse; backend failure or worker panic quarantines.
This does not repair SHA-1 or claim independent qualification.

No named independent reviewer has verified this component. Passing tests, CI,
Kani, Miri, fuzzing or a pentest is not independent cryptographic verification.

| Algorithm | Implemented | Independently verified |
| --- | --- | --- |
| Protected compiled SHA-1 sessions | 🚧 Implemented; qualification pending | ❌ Not independently verified |
| SHA-1 | ✅ Fully implemented | ❌ Not independently verified |
| Opt-in hosted ordinary acceleration | ✅ Opt-in, platform-limited | ❌ Not independently verified |
| Opt-in hosted hardened acceleration | ✅ Opt-in, platform-limited | ❌ Not independently verified |
| Protected scalar SHA-1 sessions (Linux GNU x86-64/little-endian AArch64) | 🚧 Implemented; qualification pending | ❌ Not independently verified |
| Apple Silicon resident scalar/Arm SHA-1 sessions (no dump exclusion) | 🚧 Implemented; qualification pending | ❌ Not independently verified |

## Hardware and SIMD

The default `RuntimeSha1Backend` remains observational: opportunistic calls use
portable SHA-1 and `required()` fails closed. The separate default-off
`runtime-execution` feature exposes `execution::select(Mode)` for ordinary
public data. Supported AArch64 system feature APIs can authorize the SHA1/NEON
route; generic x86 required mode fails, since current-core CPUID alone cannot
establish migration safety. Specialized x86 binaries use the leaf's explicit
static route. No feature report can be converted into an execution authority.
Operational native observations passed on Linux and macOS; other supported OS
lanes are not qualified by those observations. See the
[operational API](https://github.com/valkyoth/brynja/blob/main/docs/legacy-sha1-execution.md)
for selection, streaming, byte/bit hashing and ownership examples.

## Use

Default-off `macos-resident` adds a separate Apple Silicon macOS
`macos_resident::Session`. It acquires guarded, locked, fork-excluded output and
a private joined worker stack; owned payloads clear on error, reuse and release.
It does **not** exclude core dumps and is not a fallback for `strict-execution`.
Caller input/copies, OS storage, fatal abort and privileged snapshots are outside
this profile. SHA-1 remains collision-broken and unsuitable for authentication.

`macos-resident-acceleration` additionally exposes `CompiledSession`, requiring
build-wide `-C target-feature=+neon,+sha2` and lifetime-wide compatible deployment.
The Cargo feature alone does not enable instructions. It requires the Arm route,
never silently selecting scalar; authority and KAT stay on the resident worker.
Unsupported targets reject. Native development tests are not independent review.

```rust
# #[cfg(feature = "macos-resident")] {
# fn resident_example() -> Result<(), brynja_legacy_sha1_std::macos_resident::Error> {
use brynja_legacy_sha1_std::macos_resident::{Session, Limits};
let mut session = Session::new(Limits {
    stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
    max_output_mapping_bytes: 65536, max_message_bits: 8192, max_chunks: 16,
})?;
let digest = session.hash(b"legacy compatibility input")?;
assert_eq!(digest.expose().len(), 20);
drop(digest); // clears the borrowed output
# Ok(())
# }
# if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
#     resident_example()?;
# } else {
#     assert!(matches!(resident_example(), Err(brynja_legacy_sha1_std::macos_resident::Error::Resource(
#         brynja_legacy_sha1_std::macos_resident::ResourceError::Unsupported))));
# }
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

See the [resident scope](https://github.com/valkyoth/brynja/blob/main/docs/macos-resident-profile.md) and the
[byte/bit API](https://github.com/valkyoth/brynja/blob/main/crates/brynja-legacy-sha1-std/src/macos_resident/mod.rs). Neither feature imports legacy
algorithms into the modern facade or enables strict Mac admission.

The separate default-off `strict-execution` feature adds
`strict_execution::Session`. Construct it with explicit protected stack/output
mapping budgets, a message-bit limit and a chunk-count limit, then call
`session.hash(input)` or `hash_chunks(chunks, tail, valid_bits, cancellation)`.
Raw tails are MSB-first; content validation and scoped hashing execute on a
locked, guarded, dump/fork-excluded worker stack. Output stays in an affine
protected loan: Drop clears it, `expose` borrows secret bytes, and `declassify`
requires explicit public-output authority. Errors and recoverable unwind clear
output and the joined stack before reuse. Unsupported targets fail closed.
This `Session` wrapper is scalar-only; separate `CompiledSession` selects
SHA-NI/Arm. Qualification remains pending. Neither repairs collision resistance, protects caller copies,
or promise whole-process/register/interruption erasure. The modern facade gains
no legacy dependency. See the [compiled session example](https://github.com/valkyoth/brynja/blob/main/crates/brynja-legacy-sha1-std/src/strict_execution/mod.rs)
and [strict-profile limits](https://github.com/valkyoth/brynja/blob/main/docs/strict-hardening-profile.md).

Select this isolated legacy adapter explicitly.

After this source version is published, install from the registry:

```sh
cargo add brynja-legacy-sha1-std
cargo add brynja-legacy-sha1
```

For an unpublished candidate or matching local checkout instead:

```sh
cargo add brynja-legacy-sha1-std --path /path/to/brynja/crates/brynja-legacy-sha1-std
cargo add brynja-legacy-sha1 --path /path/to/brynja/crates/brynja-legacy-sha1
```

```rust
use brynja_legacy_sha1_std::RuntimeSha1Backend;
let selected = RuntimeSha1Backend::opportunistic();
let mut state = selected.start();
state.update(b"public legacy file bytes")?;
assert_eq!(selected.hash(b"public legacy file bytes")?, state.finalize());
assert!(RuntimeSha1Backend::required().is_err());
# Ok::<(), brynja_legacy_sha1::Sha1Error>(())
```

SHA-1 is unsuitable for new signatures, authentication or password hashing.
The observational and ordinary APIs handle public data only. Confidential legacy
data requires a hardened owner, never a public-data acknowledgement token.
No FIPS validation is claimed.

The distinct default-off `runtime-hardened-execution` feature adds
`hardened_execution::select(Mode)`. It returns a non-cloneable, thread-bound
executor with typed secret output, explicit public declassification and owned
scratch clearing. Hosted AArch64 and static leaf x86/Arm routes remain subject
to the documented lifetime-wide platform contract. Project-owned native correctness
evidence covers AWS Arm and Apple M2 Pro, not arbitrary hotplug or VM migration.

```rust
# #[cfg(feature = "runtime-hardened-execution")]
# fn example() -> Result<(), Box<dyn std::error::Error>> {
use brynja_legacy_sha1_std::hardened_execution::{select, Mode};
let owner = select(Mode::Prefer)?;
let mut bytes = [0u8; 20];
drop(owner.hash_secret(b"legacy confidential input", &mut bytes)?);
assert_eq!(bytes, [0; 20]);
# Ok(())
# }
# #[cfg(feature = "runtime-hardened-execution")]
# example()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

See the [hardened execution contract](https://github.com/valkyoth/brynja/blob/main/docs/legacy-sha1-hardened-execution.md).
MIT OR Apache-2.0; zero third-party dependencies.

See [SHA-1 acceleration](https://github.com/valkyoth/brynja/blob/main/docs/legacy-sha1-acceleration.md)
for evidence restrictions and the native capture procedure.
