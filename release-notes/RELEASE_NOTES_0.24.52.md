# v0.24.52 — Facade features and package reachability

Status: development candidate; implementation and acceptance work in progress.
No release qualification, independent cryptographic verification or publication
is claimed. The next planned publication checkpoint remains v0.25.2.

The modern facades now forward explicit default-off features for existing
SHA-2, SHA-3/SHAKE/cSHAKE, KMAC, TupleHash and ParallelHash execution and batch
owners. General SHA-512/t has its own opt-in. Existing flat portable APIs remain
unchanged; leaf namespaces expose the corresponding operation-specific APIs.

The facades remain `no_std`. Hosted detection, protected/resident sessions and
thread workers remain separately selected companion packages. Legacy SHA-1/MD5
are not reexported. Cargo features expose APIs, not CPU support, instruction
authority, secret provenance, independent verification or FIPS approval.

The focused acceptance checks extract real crate archives, reject unavailable
APIs without their features, compile individual opt-ins on a bare-metal target,
inspect resolved dependency graphs and exercise portable result/cleanup behavior.
The isolated matrix has passed on Rust 1.90.0 and 1.99.1, including additive
leaf-feature unification and separately selected hosted portable/preferred/
required-mode checks. These checks do not execute accelerated instructions.
The metadata preflight and focused CPU/workspace regressions also pass. Each
compiler rejected 30 compiled Send/Sync/Copy/Clone/Debug probes across the two
facades' SHA-2, KMAC and TupleHash execution owners. All 64 existing crate README
examples, scoped Clippy, formatting, assurance metadata and release-policy tests
pass. The publication plan selects zero packages.
Expanded downstream coverage also passed on both compiler endpoints. Each
facade runs ten combined family/batch tests in debug and release: named SHA-2
bit inputs and general-t boundaries; SHA-3 bit inputs, SHAKE/cSHAKE streaming
and XOF tails; KMAC fixed/XOF output and key-length rejection; TupleHash item
framing; ParallelHash serial/grouped leaves; and ordinary/hardened SHA-2 and
Keccak batches. Public rejection preserves destinations, while secret output
owners clear on drop and rejected work clears their supplied destinations.
These are equivalence checks against existing portable implementations, not
an independent cryptographic oracle or accelerated execution qualification.

Both Rust examples are extracted from the facade guide and compiled/executed
alongside the separate hosted test: three tests per facade/profile. Runtime
test populations are checked explicitly; six focused negative cases reject
missing/ignored/failed tests and removed documentation examples.

Final candidate review and independent owner-supplied pentest remain pending.
No full verification sweep or native campaign was launched.

No cryptographic kernel, admission policy or release-gate policy changes in
this initial forwarding implementation.
