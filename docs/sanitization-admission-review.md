# Sanitization Adapter Admission Review

Status: admitted only for conditional implementation of the separately selected
`brynja-sanitization` package at v0.11.2; no Brynja production dependency graph
changes at v0.11.1.

Checked: 2026-08-09.

## Decision

Brynja admits the crates.io release `sanitization 2.0.3` as the sole candidate
for a protocol-neutral downstream adapter. The future adapter must exact-pin
that release, disable default features, select no features, and use
adapter-owned wrapper types. One adapter will serve modern and legacy callers;
`brynja-legacy-sanitization` is rejected because secret-memory destruction has
no irreducible legacy-only semantics.

This decision does not add `sanitization` to the current workspace, authorize
another unsafe block in Brynja, or replace the mandatory v0.11.0
`brynja-core` destruction primitive. It only permits v0.11.2 to implement an
explicitly selected storage/lifecycle adapter if every frozen condition below
can be enforced.

| Property | Reviewed value |
| --- | --- |
| Package | `sanitization 2.0.3` from crates.io |
| Latest stable check | `2.0.3` on 2026-08-09 |
| Release source commit | `ffcb211cd931c6966b2e767ce5edffa4b47c4f07` |
| Externally reviewed code commit | `d9578b20a5e0ad9c9226648773409466f662e3b6` |
| Package SHA-256 | `75e43f2762b31232062e8ba7bfbdfcbd33c80c43bf7a306a7e195c3c4f734e0f` |
| License | MIT OR Apache-2.0 |
| Rust / edition | Rust 1.90, edition 2021 |
| Runtime model | `no_std`, no allocator, no build script, no native link |
| Selected Cargo features | none; default features disabled |
| Activated runtime graph | only `sanitization 2.0.3`; no transitive package |
| Advisory result | no RustSec advisory found on 2026-08-09 |
| Upstream independent pentest | PASS, 2026-07-21, zero open findings |

The machine-readable authority for these values is
`security/dependency-admissions/sanitization-2.0.3.toml`. The package hash is
both the crates.io index checksum and the SHA-256 of the downloaded `.crate`
archive. Its `.cargo_vcs_info.json` binds the archive to the release source
commit above.

## Feature And Dependency Closure

The admitted manifest form is exactly:

```toml
sanitization = { version = "=2.0.3", default-features = false }
```

Cargo metadata and the isolated lockfile resolve one runtime package and no
runtime dependencies. In particular, `zeroize`, `sanitization-derive`, serde,
and subtle are optional upstream edges and remain absent. The upstream default
`asm-compare` feature is also disabled. Allocation, native memory locking,
guard pages, canaries, cache flushing, register scrubbing, multi-pass clearing,
hardware-secret traits, derive, interoperability, Serde, strict comparison,
and all named profiles are outside this admission.

Upstream test-only dependencies are evidence tooling, not members of the
selected runtime graph. Brynja does not re-export them, run them in production,
or count their guarantees as adapter guarantees.

The independent, unpublished fixture under
`assurance/sanitization-admission` instantiates the exact manifest and an
opaque, non-empty, adapter-owned fixed-size wrapper without joining the Brynja
workspace. Six behavior tests and three compile-fail tests cover explicit
complete clear, closed initialization failure, transactional replacement failure, panic
unwind, redaction, empty-storage rejection, non-clonability, and rejection of
rich error payloads at both fallible API boundaries. The tag gate
rebuilds this fixture across the full compiler and target matrix.

## Unsafe And Destruction Review

The selected package forbids unsafe code generally and opens named internal
exceptions. With no features, the inherited source trusted computing base
contains the volatile erasure backend and the always-available atomic
`ConsumeOnceSecret` implementation. Feature-gated platform assembly, native
mapping, memory-lock, guard-page, canary, cache-flush, and register-scrub code
is not selected. The v0.11.2 adapter is limited to fixed-size
`sanitization::SecretBytes<N>` storage and must not expose the consume-once or
optional platform surfaces without a new numbered review.

`SecretBytes<N>` owns exactly `N` inline bytes, is not `Copy` or `Clone`,
redacts `Debug`, supports closure-scoped access, clears through per-byte
volatile writes and fences, and clears on explicit request and Drop. Its
fallible constructor clears partially generated output; replacement builds a
clear-on-drop candidate before clearing and swapping the old value; panic
unwind drops the candidate. Complete fixed-size backing is cleared, so there is
no allocation-capacity tail in this admitted surface.

The comparison against v0.11.0 found compatible ordinary-RAM destruction
behavior for explicit clear, Drop, fallible initialization, replacement,
error, unwind, optimizer resistance, and complete fixed-size storage. It did
not find an equivalent for Brynja's protocol-specific typed initialization and
destruction-duty state machine. Therefore the adapter cannot become the engine
owner or authoritative protocol erasure mechanism: bytes crossing into a
Brynja engine remain governed by `brynja-core`'s v0.11.0 owner and destruction
contract.

Upstream evidence includes MIR/LLVM IR/assembly inspection, Miri, bounded Kani
harnesses, native tests, target-specific evidence, and the independent 2.0.3
pentest. Those are useful inputs, not proof of all compilers, runtimes, targets,
hardware behavior, or Brynja integration.

## Frozen Adapter Boundary

At v0.11.2, `brynja-sanitization` may define an opaque
`SanitizedSecret<N>` wrapper around `sanitization::SecretBytes<N>` and narrow
explicit methods that preserve redaction and ownership. It must satisfy all of
the following:

- applications select the package with a direct dependency; no facade feature,
  default feature, `all-features` shortcut, engine edge, or implicit activation
  exists;
- the adapter owns every public wrapper and trait implementation, uses no
  orphan-rule workaround, and provides no blanket or implicit conversion;
- conversion into or out of Brynja protocol storage is explicit and
  caller-auditable; storage ownership cannot be shared or ambiguous;
- fallible byte sources return only a Brynja-owned, zero-sized
  `SourceFailure`; callers clear source-specific sensitive error state before
  collapsing it, and no arbitrary error payload may cross or be discarded at
  the adapter boundary;
- modern and legacy applications use the same wrapper contract while their
  engines, credentials, state, caches, and tickets remain isolated;
- `brynja-core` stays mandatory and authoritative for every protocol-owned
  secret region and all destruction failure handling;
- the adapter remains outside `brynja-fips-module`, every validated-module
  dependency closure, and every FIPS claim; it cannot satisfy or imply FIPS
  SSP destruction or certificate coverage.

The adapter itself may depend on the exact `sanitization` release and the
narrow frozen `brynja-core` contracts needed for explicit transfer. No Brynja
facade, core, provider, modern engine, or legacy engine may depend back on the
adapter.

This closed error rule remediates the v0.11.1 review finding that the initial
candidate accepted generic errors and could normally drop a secret-bearing
error payload. The finding never reached the production graph; the candidate
and admission validator now make that API shape a compile-time and policy
failure.

## Compatibility And Target Evidence

An isolated no-default-features candidate compiled with Rust 1.90.0, 1.91.0,
1.92.0, 1.93.0, 1.94.0, 1.95.0, 1.96.0, 1.96.1, 1.97.0, and 1.97.1. Rust
1.97.1 cross-checks passed for Linux, Windows MSVC, FreeBSD, macOS, Android,
iOS, embedded ARM, embedded RISC-V, and `x86_64-unknown-none`; WASM also
compiled as an explicitly weaker compatibility target.

Only Linux was executed locally for this downstream candidate. The remaining
checks are compile-only and inherit no runtime or timing claim. Upstream
classifies x86_64 Linux as Tier A, AArch64 Linux/Windows/macOS as Tier B native,
BSD/Android/iOS/embedded as Tier B or B/C compile-only, and WASM as Tier C.
Brynja preserves those distinctions rather than promoting cross-compilation to
native evidence.

## Residual Risk And Re-review

The adapter cannot guarantee cleanup after abort, forced termination,
`mem::forget`, or equivalent destructor bypass. It cannot erase earlier Rust
moves, compiler spills, registers, caches, DMA copies, dumps, swap,
hibernation, privileged inspection, allocator metadata, or physical memory.
WASM does not provide native-equivalent volatile semantics. Miri does not prove
OS behavior, and Kani does not prove real concurrent execution. Neither the
upstream pentest nor this admission is FIPS validation or independent
verification of Brynja.

Every listed change forces a new admission review. This includes any new
upstream release, checksum, source, license, MSRV, feature, dependency, unsafe
boundary, target guarantee, advisory, or behavior, as well as any proposed
selected feature, conversion, allocation mode, engine/facade/FIPS edge, or
ownership change. A failed review withholds or removes the adapter; it never
weakens or removes Brynja's own destruction path.
