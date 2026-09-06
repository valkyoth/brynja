# Legacy SHA-1/MD5 portable acceptance — v0.24.20

This freezes a usable **portable reference**, not a completed acceleration
family, independent cryptographic review or FIPS validation. Both algorithms
are collision-broken. Clearing their state does not repair collision resistance.
Neither is a password hash, signature scheme, certificate validator or MAC.
Modern/default, TLS, PKIX and FIPS graphs cannot select these legacy leaves.
Both verification rows remain **In progress** until v0.24.23 disposition.

Run the complete public consumer and package/isolation checks:

```sh
python3 scripts/legacy-hash/check-legacy-acceptance.py
python3 scripts/legacy-hash/test-legacy-acceptance.py
cargo run --locked --offline --manifest-path assurance/legacy-hash-public-api/Cargo.toml
```

The dependency-external library is `no_std`, with only exact first-party SHA-1
and MD5 dependencies. Its binary is a test-only hosted launcher, not a shipping
crate. The initial candidate changed no algorithm; its pentest follow-up makes
SHA-1's two private offset guards always-on, matching MD5. No valid-input digest
or public API changes. The reviewed source freeze includes this remediation. The corpus
includes real UTF-8 text and archive-index JSON files, empty/abc messages,
all final bit widths and representative 447/448/449/511/512/513/1023-bit
boundaries. `src/vectors.rs` freezes expectations from the separately composed
Python bit oracles, cross-checked for byte messages with the system hashlib
implementation. The existing SHA-1 NIST and MD5 RFC 1321 vector/provenance and
wide differential gates remain mandatory; Python/system crypto is test-only.

| Profile | Consumer operations exercised |
| --- | --- |
| Ordinary | new/default, one-shot bytes/bits, irregular streaming, length observation, capacity probes, consuming byte/bit finalization |
| Hardened | new/default, streaming, capacity probes, one-shot secret bytes/bits, consuming byte/bit public finalization with explicit declassification, typed secret destinations |
| Failure/lifecycle | Noncanonical bits, capacity exhaustion probes, unchanged public and cleared secret failure outputs, cancellation, secret-owner Drop, recoverable consumer unwind |

Real exhaustion and pre-mutation counter injection remain leaf-private tests;
the external fixture does not bypass privacy to forge near-limit state. The
existing exact owner/Drop/wipe MIR, LLVM and assembly checks bind the private
clearing regions. Consumer observations of cleared outputs alone do **not**
prove private-state clearing. Register/cache/spill/move/dump/DMA/swap, abort,
forced termination, forgotten owners and caller copies remain residual risks.
Callers still own input clearing, copied/public outputs and cumulative work
budgets; no allocator, pinned-memory or process-wide protection is implied.

Four real `.crate` archives (core, hash-core, SHA-1, MD5) are boundedly unpacked,
their Rust files compared with frozen sources, and the unchanged consumer
compiled and executed using only those archives. Nothing is uploaded. Hashes
of the fixture, corpus, primitive source and acceptance tooling are retained in
`scripts/legacy-hash/legacy-reviewed.toml`; changes require explicit review.

Positive-controlled compiler cases reject modern hash reexports, substituting
legacy owners for sealed SHA-2 capability, passing them as FIPS service
authority, absent certificate/signature/password/negotiation entry points,
and cloning secret owners. These prove the **current absent or incompatible
API boundaries**, not future protocol implementations or a global prohibition
on a caller deliberately writing its own misuse. Dependency graph traversal
also checks twelve modern roots with all/default-disabled features.

The interpreter campaign uses the bounded external lifecycle and unwind tests;
wide file partitions and vector repetition run natively and under ASan.
This fixture owns a separate `legacy` Miri group. Rust 1.90.0–1.98.1 and the
three declared bare-metal targets compile/test the external consumer. Later
acceleration must preserve this exact portable reference and document its
own execution/admission evidence; it cannot silently replace these paths.
