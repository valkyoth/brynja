# Fixed Rust worker ABI experiment

Status: **fixed public Rust worker executed natively; no Windows strict activation**.
This public-marker experiment changes neither production crypto nor release gates.
The exact [observations and failure controls](windows-enclave-rust-worker-results.md)
are recorded separately; they are not cryptographic or full-worker qualification.

The [bounded depth results](windows-enclave-window-depth-results.md) establish a
particular assembly/C frame budget and caught exception, not Rust compatibility.
The next image calls one fixed `no_std` Rust function from the guarded, locked
OS-stack window. No caller-provided bytes, pointers, closures, vtables, secrets,
cryptographic operations or new Cargo dependencies are accepted.

## Deliberately narrow boundary

The C wrapper calls `PublicRustWork(mode, low, high)`, which returns four
pointer-width public diagnostics using `#[repr(C)]`: status, local-array address,
bytes filled and clearing result. C compile-time assertions and Rust unit tests
check size, alignment and all field offsets. The x64 ABI's aggregate-return
behavior must additionally work in the native linked image; layout assertions
alone do not prove calling-convention compatibility.
[Rust C representation](https://doc.rust-lang.org/reference/type-layout.html#the-c-representation).

Rust uses a fixed 1024-byte local marker and bounded loops with volatile writes
and readback. It reports distinct success, halfway cancellation, pre-work
rejection and post-write error states. A supplied integer window must enclose
the complete local array before marker writes. These integer bounds are trusted
public experiment configuration, not authority supplied by an untrusted host.
No operation allocates, spawns threads, accepts arbitrary callbacks or declares TLS.

The Rust object is compiled with `panic=abort`, `force-unwind-tables=yes` and
optimization level 2. Unwind-table presence is **not** Rust panic qualification.
The optional existing C exception completes before Rust entry. It must not
unwind through the Rust function, nor may a Rust panic cross into C. A panic or
unhandled native exception fails the process; no cleanup claim follows it.
[Rust FFI unwinding constraints](https://doc.rust-lang.org/nomicon/ffi.html#ffi-and-unwinding).

After return, the existing assembly leaves the work window, clears/readbacks
all 64 KiB while the sixteen pages remain locked, then finishes the host handshake
and restores boundaries. This is separate from Rust's local-array clearing.
A missing-local-clear Rust mutant must be detected even though the outer window
is cleared. A missing-outer-clear assembly mutant must also be rejected. Public
diagnostic globals deliberately persist; this probe does not claim full image,
TLS, runtime-copy or register clearing.

## Build and observation plan

Use the pinned local Rust 1.98.1 compiler to emit a Windows x64 COFF object,
assembly and LLVM IR. Link that object on the disposable Windows enclave host
with the existing MSVC C/assembly scaffold and enclave-only runtime libraries.
Enable `/std:c11` for the C aggregate-layout assertions and retain `/W4 /WX`.
Inspect unresolved object symbols, the final PE imports, stack frame and call
graph. Do not import the general Windows Rust standard-library runtime into an
enclave or infer enclave compatibility from the ordinary Windows target name.
Microsoft's [enclave tooling](https://github.com/microsoft/VbsEnclaveTooling)
lists Rust support, but that is not qualification of this independently built
object, our worker lifecycle or our cryptographic implementation.

The normal, missing-local-clear and wrong-result Rust objects are separate
artifacts. Native records bind the source commit/hashes, signed image, supplied
Rust object and compiler identity file. These hashes do not independently prove
how a binary was built: preserve/review exact compile/link commands and emitted
code. The compiler identity describes the Linux cross-compiler host, while native
execution occurs on Windows; do not conflate them.

Required controls are repeated execution of all four outcomes, C-exception-before
controls, compiled local/outer cleanup mutants, wrong-result and wrong-mode
rejections, exact complete report validation and teardown. Crashes, timeouts or
load/setup failures are not passing cleanup observations.

After this experiment, actual operation adapters still need a bounded call graph,
complete secret-region/register/runtime ownership and ABI review. Production
signing, complete worker-layout dump behavior, concurrency, supported baselines
and any recoverable Rust-panic design remain separate work. This is not a new
public facade and cannot replace the current `Unsupported` result.
