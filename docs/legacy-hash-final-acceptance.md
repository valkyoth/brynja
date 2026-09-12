# Legacy SHA-1 and MD5 final acceptance — v0.24.23

Historical closure note: the later default-off SHA-1 operational authority is
reviewed separately in `scripts/legacy-hash/sha1-operational-delta.toml`. The
original snapshot is immutable; the delta pins only the named new/changed
authority files and never changes the SHA-1 algorithm, shared foundations or
MD5 native bindings. It does not qualify the operational API using old captures.
Fresh native review is required for that API; see [ordinary SHA-1 execution](legacy-sha1-execution.md).

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

Before each ordinary, hardened-public and hardened-secret batch call, every
destination byte is initialized to the complement of its expected result,
including inactive lanes. Thus an earlier successful path cannot supply the
answer for a later no-op. Hardened-public execution also checks that no vector
blocks were reported. The mutation suite compiles disposable consumers in debug
and release: no-op, partial-write and false-route mutants must fail the actual
acceptance test, while the original stale-buffer weakness is reproduced as a
positive counter-control. Production crates and frozen vectors are never edited.

The fixture's inputs and expected hashes are public frozen test vectors, even
when exercised through a typed secret owner. Its fixed-width result comparison
uses Brynja's own `ConstantTimeEq`, without copying the borrowed output or adding
`subtle`. Regression tests cover all 128 mismatch positions and invalid widths;
they test functional behavior, not a new independent timing certification.

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

## Unwind and filesystem trust boundaries

Secret cleanup follows Rust destruction during normal scope exit and recoverable
unwinding; callers do not have to install `catch_unwind` to activate it. Tests
catch panics only so they can inspect the output afterwards. Both a cancellation
callback panic and a neighboring destructor initiating unwind are exercised.
The inspected MD5 owner and output-guard Drops call the existing first-party
clearing boundary without allocating or invoking user callbacks. MD5's fixed
regions are nonempty, so the clearing helper's empty-region error cannot arise
here; no result is unwrapped. Its isolated volatile primitive remains a reviewed unsafe
exception; this does not introduce unsafe code in MD5 owner destruction.

A second panic during unwinding can abort the process. This is **not** safe
from a memory-remanence perspective: remaining cleanup is not guaranteed.
Abort, forced termination and unrelated failing destructors remain deployment
limitations, not circumstances this portable crate can override.

The Python acceptance checker requires a trusted, quiescent checkout. Its
portable symlink/path checks are not a sandbox against another process racing
the filesystem. The actual read is bounded as well as the initial file-size
check, including growth-after-check tests and cross-platform newline tests.
Do not execute it over a checkout concurrently writable by untrusted users;
isolate such workers or use an immutable input snapshot. `O_NOFOLLOW` on the
final file alone would not protect changing parent directories or all supported
platforms, so no complete TOCTOU-containment claim is made.

Ordinary hash state must not own secrets. Hardened owners clear their inaccessible
state, but caller copies, moves, compiler copies, registers/spills, caches,
swap/dumps, DMA, forget, abort and termination retain their documented limits.
Completion is not authorization for military/classified or modern protocol use.
