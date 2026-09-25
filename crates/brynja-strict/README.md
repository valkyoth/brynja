<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja">Crates.io</a>
  |
  <a href="https://docs.rs/brynja">Docs.rs</a>
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
    <img src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja security-first Rust cryptography and secure protocols overview">
  </a>
</p>

# brynja-strict

Strict-only entry point for modern protected cryptography. Existing `brynja`
remains portable and unchanged; importing this crate is an explicit application
choice, not certification or proof that all application code uses this profile.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Strict-only modern protected sessions | 🚧 Implemented; qualification pending | ❌ No |
| Explicit compiled hardware/SIMD selection | 🚧 Implemented; qualification pending | ❌ No |

Exports: `sha2`, `sha3` (SHAKE/cSHAKE), `kmac`, `tuplehash`, `parallelhash`
and independent-message `batch`. No legacy hashes, ordinary digests, raw CPU
execution authorities, generic protected callbacks or protocol APIs are exported.
Even with default features disabled, dependencies enable the protected sessions.

## Hardware and SIMD

Scalar `Session` constructors stay scalar. Enable `acceleration` to expose
separate `CompiledSession` constructors; batches always require an explicit
portable or compiled kernel route. Full build-wide CPU feature bundles and
compatible deployment are required for compiled kernels. No CPU detection,
affinity or live-migration guarantee is implied. Missing required features reject.
There is no automatic switch to a weaker memory profile.

## Usage

The development facade requires the checkout until its scheduled publication:

```sh
cargo add brynja-strict --path /path/to/brynja/crates/brynja-strict --no-default-features
```

This example deliberately requests invalid resources and safely rejects on every
platform; it never silently creates an ordinary-memory session:

```rust
use brynja_strict::sha2::{Algorithm, Limits, Session};
let result = Session::new(Algorithm::Sha256, Limits {
    stack_bytes: 0, max_stack_mapping_bytes: 0,
    max_output_mapping_bytes: 0, max_message_bits: 8192, max_chunks: 16,
});
assert!(result.is_err());
```

See the [compiled session-pool example](src/lib.rs) for successful hashing on a
supported deployment. Construct a bounded pool at startup, use exclusive session
loans, drop each output before reuse and retire quarantined compiled sessions.
Do not allocate an unbounded new session per incoming request.

## Platform and memory limits

Constructors require native GNU/Linux x86-64 or little-endian AArch64, Linux 4.4
and glibc 2.27 or newer, plus successful eager page locking and dump/fork exclusion.
Other targets and verification models can compile for portability tests but
constructors return errors. They never return a weaker implementation.

On 4 KiB pages, a SHA-256 session with a 262144-byte stack locks 266240 bytes:
64 stack pages plus one digest page. Guard pages add virtual address space,
not locked payload. Other families have additional mappings and ParallelHash
has one stack per worker plus its root and CV/staging/output mappings. Budget
all live sessions together against RLIMIT_MEMLOCK; bounds are per resource,
not a process-wide quota. Lock exhaustion rejects construction before input.

Inputs and copies made by the application remain its responsibility. Lengths,
scheduling, privileged snapshots, hibernation, arbitrary register interruption,
external protection revocation, panic hooks and fatal abort remain outside the
bounded protection. Sanitizer builds are diagnostics only, not qualified
secret-processing deployments. Native Arm qualification and independent review
remain pending. See the [complete contract](../../docs/strict-hardening-profile.md).
