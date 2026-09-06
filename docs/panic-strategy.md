# Panic strategy belongs to the application

Brynja does **not** force downstream users to adopt `panic = "abort"`.
Cargo reads profiles from the consuming workspace root, not from dependency
manifests. Our root release setting selects abort for repository builds and
that particular emitted-code evidence; it is not a library API requirement.
Applications may use their target's default, explicit unwind, or explicit abort.
See the [Cargo profile rules](https://doc.rust-lang.org/cargo/reference/profiles.html#panic)
and the dependency-profile rule near the top of that page.

Where the target supports unwinding, the application's workspace can choose:

```toml
[profile.release]
panic = "unwind"
```

With unwinding, ordinary Rust destruction runs as the stack unwinds. Hardened
owners must clear their owned regions without panicking. With abort, destructors
do not run; a smaller binary or immediate termination is not a secret-erasure
guarantee. Some no_std targets cannot unwind, and their panic handler/runtime is
also the application's responsibility. No process-wide panic hook or handler is
installed by these hash crates. Neither profile guarantees erasure of compiler
copies, registers, dumps, swap, caches or caller-owned buffers.

Checked public input/length errors return typed errors. SHA-1 and MD5 additionally
assert their private buffer offsets before writing in **all** build modes. Safe
public calls cannot construct invalid offsets; these guards defend against a
future internal bug, not arbitrary process-memory corruption. If a guard trips,
the operation must not return a fabricated digest. Its panic follows the chosen
application strategy. Do not reuse an object involved in an invariant panic or
treat catch_unwind as recovery from undefined behavior or memory corruption.

Stable `cargo test --release` still uses the unwinding test harness: it verifies
optimized pre-write assertion behavior, but does **not** demonstrate abort
execution. `scripts/legacy-hash/check-panic-profiles.py` separately builds and
runs real downstream release binaries with default, unwind and abort profiles,
checks the SHA-1/MD5 compiler commands, and verifies secret-output destruction
during a recoverable application panic in unwind builds. The abort binary runs
valid acceptance cases; it does not deliberately crash or claim abort cleanup.

The repository-local abort profile is retained for continuity of its compiler
evidence. It must not be described as a mandatory deployment policy. Normal
downstream optimized fixtures already exercise the target's default strategy.
