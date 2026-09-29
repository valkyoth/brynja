# Public-vector SHA-256 enclave experiment

This v0.24.50 research step runs the existing, unchanged portable
`brynja_hash_sha2::sha256` and `Sha256` APIs inside the guarded, locked 64 KiB
window described by [the Rust worker experiment](windows-enclave-rust-worker-design.md).
It does **not** enable Windows strict sessions or qualify secret processing.
The [native observations and failure controls](windows-enclave-sha256-results.md)
are now recorded separately.

## Scope and independent checks

Twenty fixed public messages cover empty input, `abc`, the standard 56- and
112-byte messages, padding boundaries and lengths through 1,024 bytes. Python
`hashlib.sha256` generates the checked-in expected digests. Each message runs
through one-shot hashing and streaming in seven-byte chunks, including an empty
update. Successful work requires exactly 40 matching digests.

The four synthetic modes are success (40 comparisons), cancellation after ten
messages (20), rejection before work (zero), and a reported post-work error
(40). These are experiment control paths, not cancellation/error injection
inside the hash implementation. The existing C exception control completes
**before** entry into Rust; it does not establish Rust panic unwinding.

Explicit input and output arrays are cleared and read back using volatile
accesses. Ordinary hash state, intermediate copies, registers and compiler
spills are not claimed to be individually erased. The outer scaffold separately
checks full-window clearing, boundary protection, callback teardown and page
locking on three repetitions. All data are public. This is neither a secret
provenance test nor proof against host compromise, snapshots or interruption.

Two compiled Rust mutants omit local clearing or corrupt the compared digest.
The runner must reject mismatched results. A separately identified missing-clear
control can record detected local residue, but cannot claim qualification.
The existing assembly mutant must still reject missing outer-window clearing.

## Build boundary

`scripts/cryptography/windows_enclave_sha256_build.py` directly compiles the
three first-party crates `brynja-core`, `brynja-hash-core` and `brynja-hash-sha2`
with Rust 1.98.1, without Cargo features or acceleration. It checks the explicit
dependency assumptions, binds their source files and manifests, and builds
separate normal and mutant archives with LLVM IR and assembly for inspection.
This experiment is not a Cargo packaging or supported-target qualification.

The final Rust `staticlib` includes its Rust dependencies, as specified by the
[Rust linkage reference](https://doc.rust-lang.org/reference/linkage.html).
Native MSVC links it to the unchanged window assembly and a small C adapter.
The no-std archive has a single fatal panic handler calling `__fastfail`; a panic
is a failed experiment, never a successful cleanup path. No foreign exception
is intentionally raised across the non-unwinding Rust ABI.

Build commands, source hashes, archive hashes, compiler identity, native image
hashes, failed controls and signing warnings must be retained alongside native
observations. No pass may be inferred from cross-compilation alone. The existing
development-signing limitations remain in force; production signing, protected
secret ownership, complete stack/caller coverage and supported deployment
qualification remain separate work. Release gates and production APIs are
unchanged.
