# Legacy SHA-1 and MD5 final acceptance — v0.24.23

This closes the implemented ordinary and hardened SHA-1/MD5 byte/bit APIs,
including one-shot and streaming use, typed secret output, explicit public
declassification, MD5 bounded batches and the opt-in host fallback adapters.
It does not make either hash collision-resistant, recommended for new designs,
an authentication mechanism, independently verified or FIPS validated.

## Run the real consumer

```sh
cargo run --locked --release --manifest-path assurance/legacy-hash-final/Cargo.toml
python3 scripts/legacy-hash/check-legacy-final-acceptance.py
python3 scripts/legacy-hash/test-legacy-final-acceptance.py
```

The new consumer calls the byte-identical v0.24.20 library fixture first. Its
entire source, manifests, lock and real-file/bit corpus remain frozen in
`scripts/legacy-hash/frozen-v02420.toml`. That old binary's historical
"In progress" line is deliberately unchanged; it is not the current status.
The final consumer adds 160 frozen-vector/mask MD5 batch comparisons, ordinary
and hardened outputs, complete secret-output destruction, cancellation, budget
failure, recoverable unwind and both optional host adapters. Required
acceleration fails closed. No source-level access to private kernels is used.

The library also compiles without default features on bare-metal targets;
only the optional `host` feature requires std. No production crate or public
cryptographic algorithm changes for this milestone, and no third-party runtime
dependency is introduced.

## Execution and evidence dispositions

| Route | Disposition |
| --- | --- |
| Portable SHA-1/MD5 ordinary/hardened byte/bit | Complete public acceptance |
| Portable MD5 eight-slot ordinary/hardened batch | Complete public acceptance, including inactive and partial lanes |
| SHA-1 x86 SHA and AArch64 SHA1 candidates | Implemented, unadmitted; no ordinary execution authority |
| MD5 AVX2 eight-lane and NEON four-lane candidates | Implemented, unadmitted; scalar tails retained |
| Required host acceleration | Typed rejection; opportunistic mode remains portable |
| Hardened accelerated hashing | Unavailable; not cleanup-qualified |
| MD5 AVX-512/RISC-V Vector and legacy RISC-V acceleration | Not implemented or admitted; portable fallback only |

The committed MD5 captures retain their original exact commit, compiler and
raw result hashes. The final checker compares capture-bound Rust/manifests with
the current unchanged implementation. This is reuse of previously reviewed
operator observations, **not execution on a new commit or a fresh native run**.

The SHA-1 captures were private files, and those raw files are unavailable in
this checkout. Only the signed v0.24.21 report, its recorded artifact hashes and
historical review are retained. They are not presented as newly authenticated
raw evidence. SHA-1 remains explicitly unadmitted, irrespective of its historical
passing observations. Recollect or recover and authenticate the raw files before
attempting an admission review. No new AWS/Mac run is required to close the
portable APIs while keeping these candidates unadmitted.

QEMU and forced evidence builds remain supplemental tests of the candidate
kernels, KATs, quarantine, feature rejection and width/scalar-tail behavior.
They never establish native timing, migration safety or secret-SIMD cleanup.
Production admission requires a separate reviewed architectural change and new
appropriate evidence, not flipping a status field. Every changed implementation
invalidates the affected evidence and requires the contract to run again.

## Security boundaries and ongoing checks

`claims.toml` keeps implementation completion separate from collision security,
modern/default admission, independent review and FIPS validation. The final
policy binds the full relevant Rust source closure, public fixtures and CI/local
coverage. Mutation tests reject altered frozen data, omitted checks, changed
claims, dependencies and capture evidence. Packaging and modern/TLS/PKIX/FIPS
isolation retain their existing mandatory repository gates.

Focused Miri covers the new downstream consumer, including cancellation/unwind
and full output clearing; unchanged owners receive their registered smoke tests.
All full owner campaigns passed before v0.24.22 and remain tied to that checked
source and verifier. Public checkpoints still renew all full groups. Compiler,
Kani, sanitizer, differential and source-policy checks remain required.

Ordinary hash state must not own secrets. Hardened owners clear their inaccessible
state, but caller copies, moves, compiler copies, registers/spills, caches,
swap/dumps, DMA, forget, abort and termination retain their documented limits.
Completion is not authorization for military/classified or modern protocol use.
