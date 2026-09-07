# MD5 multi-buffer SIMD contract

Status: v0.24.22 implementation candidate; supplied pentest clean, four native captures reviewed; final local release checks passed; awaiting green GitHub/CodeQL and owner tag permission.
MD5 remains **In progress** until the v0.24.23 final cross-backend disposition.
It is collision-broken, not independently cryptographically verified, and not
FIPS validated. Faster legacy compatibility does not repair MD5's security.

## API and ownership

`brynja-legacy-md5` remains first-party, allocation-free and `no_std`. Its default
single-message ordinary/hardened byte/bit APIs and compressor are unchanged.
The opt-in `batch` feature adds consuming `Md5Batch` and `HardenedMd5Batch`.
`cpu` includes `batch` and adds two isolated candidate instruction kernels:

| Backend | Exact bundle | Independent messages | Disposition |
| --- | --- | --- | --- |
| x86_64 AVX2 | AVX2 plus OS YMM context support | 8 | Unadmitted |
| Little-endian AArch64 NEON | NEON | 4 | Unadmitted |
| AVX-512 | No downclock/performance/feature qualification yet | — | Not implemented |
| RISC-V Vector | No qualifying native vector machine/compiler evidence | — | Not implemented; portable remains available |

This is parallel processing of independent messages, not dedicated MD5 hardware
or a single-stream speedup. Eight fixed slots retain caller order. `None` is an
inactive slot, distinct from an active empty `BitString`. Successful inactive
slots become zero. Each active slot independently supports canonical MSB-first
bit tails and the unchanged RFC 1321 low-64-bit little-endian length encoding.
Repeated slots intentionally repeat the hash; no concatenation or lane sorting.
AVX2 needs all eight slots active with a complete shared block prefix; NEON
processes each contiguous four-slot group. Single messages, incomplete groups,
uneven suffixes and all terminal padding use scalar compression.

`Md5BatchControl` bounds total message compression blocks, including padding,
not bytes or wall time. A callback may cancel before each charged operation and
before output commit. Previously consumed budget is not refunded. Public output
is transactional: failure/cancellation/recoverable unwind preserves all eight
slots. Control state may record work already consumed. No callback runs after
commit begins. Lengths, slot activity, report counts and cancellation are public
metadata, including in hardened mode; pad first if length confidentiality matters.

The separate `brynja-legacy-md5-std` adapter observes AVX2/NEON capability without
minting an execution session. Opportunistic single/batch calls remain portable;
required acceleration always fails. No modern, TLS, PKIX or FIPS dependency edge.
Cargo feature unification can expose CPU types but does not admit execution.

## Secret-bearing batches

The distinct `HardenedMd5Batch` has no SIMD/session method and cannot be cloned
or formatted. It composes eight existing registered `Md5Owner` instances instead
of introducing another sponge/schedule representation. Each owner clears its
chaining state, block/message words, length, buffered count and result staging
through the existing compiler-resistant core clearing primitive on success,
failure, cancellation, recoverable unwind and Drop. The optional sanitization
adapter is not needed to activate this mandatory cleanup.

`digest_public` requires explicit `PublicDeclassification`. `digest_secret`
establishes cleanup of the entire 128-byte destination before any callback, and
returns one affine `OwnedSecretRegion` spanning all eight slots. Errors and
unwind clear the whole destination, including inactive slots and partial staging;
successful ownership clears on Drop. Caller inputs and copied outputs remain
caller responsibilities. Public metadata masks/counts contain no secret bytes.

Plain byte slices cannot prove that input is public. Do not pass secret-derived
material to ordinary SIMD APIs. Their transposed words, vector states, compiler
temporaries, registers and spills are not secret-cleanup-qualified. Hardened
owners retain the existing limits for compiler-created copies, registers,
caches, dumps, swap, DMA, moves, `mem::forget`, abort/termination and physical
remnants. Memory locking/pinning is not forced by the portable leaf.

## Session and evidence boundary

Production builds reject every candidate before the actual multi-lane KAT.
Experimental execution requires both non-default `cpu-evidence` and the unique
`--cfg brynja_md5_cpu_evidence`. Neither shared CPU/SHA-1 cfg, feature unification
nor `cfg(test)` alone bypasses this. This guards accidental configuration, not
malicious compiler/source modifications. Do not persist evidence flags or deploy
evidence binaries. The safe compiled-target constructor relies on the binary's
complete target-feature deployment contract; externally supplied runtime
authority has an explicit migration-safe safety contract.

Sessions are non-cloneable and neither Send nor Sync. They KAT the actual kernel
using distinct messages per lane, revalidate before each block and final output,
and permanently quarantine on KAT/authority failure. Non-Send does not prevent
OS migration. A feature callback cannot itself prove safety between the check
and the last instruction. Native correctness, reviewed operating-state/migration
authority, performance and side-channel evidence are prerequisites to a separate
architectural admission review. A flipped admission flag is not sufficient.

## Reproduction

Run `python3 scripts/md5/check-md5-cpu.py`, `python3 scripts/md5/test-md5-cpu.py`
and `scripts/md5/check-md5-cpu-codegen.sh` for public/packaged, negative-build and
compiler-endpoint checks. `scripts/md5/check-md5-cpu-qemu.sh` exercises AArch64
NEON under QEMU only; emulation is not native timing or hardware evidence.
The unchanged v0.24.20 corpus, 936 batch comparisons, 16 lane permutations, arbitrary-state/block lane
differentials and per-operation counters prevent a requested-but-unused route
from being reported as vector work. Benchmarks include scalar single/incomplete
groups and actual full-width batches; results are observations, not speedup promises.

After a clean committed candidate and owner pentest, install Rust 1.98.1 and
run `cargo +1.98.1 fetch --locked` once online to prime the workspace cache.
Capture one registered lane, for example on Apple M2:

```sh
python3 scripts/md5/capture-md5-cpu-native.py apple-m2-aarch64 target/md5-m2-v0.24.22.json
```

Other lanes are `amd-x86_64`, `intel-x86_64`, `aws-aarch64`. The collector requires
unchanged committed sources, checks every enumerated Linux CPU's features,
rejects overwrites and emits no hostname. Return the JSON for reviewed disposition.
Native records remain operator-self-attested and do not admit a backend. No
new RISC-V vector or AVX-512 hardware claim is made by this milestone.

The [v0.24.22 native archive](../assurance/md5-observations/v0.24.22/README.md)
preserves passing AMD, Intel, Apple M2 Pro and AWS Arm captures at exact
commit `95d1d6b56282621e742b425aa08988d9568d3e84`. Its result disposition
does not qualify migration-safe authority, constant-time behavior or secret
SIMD cleanup. Both instruction candidates remain unadmitted.
