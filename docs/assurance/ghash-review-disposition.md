# v0.28.0 GHASH review disposition (pending scoped retest)

The first report reviewed the committed range v0.27.6..e6c5c05f and explicitly
excluded the uncommitted GHASH work. The second reviewed the candidate working
tree. Neither reported a Critical or High issue. They did not review exactly
the same tree, and neither is approval of the changes below.
Original combined input SHA-256: `602a9d9ac2ab5d7a13bb4e832bfdd5f8bda5492d7ba5d183d534b663156887a9`.

| Finding | Disposition and regression coverage |
| --- | --- |
| Compiler/evidence policy mismatch | Already repaired in the working tree. Rechecked both evidence validators, their rejection suites and the Rust freshness suite; current is 1.100.0, MSRV is 1.90.0. This does not relabel old compiler observations. |
| AES mutation fixture referenced archived research | Already repaired in code; corrected the development record. The production baseline is 17 library tests, none ignored. The runner tests and all 18 real mutation controls were exercised; no research fixture was restored. |
| Raw GHASH exposed by default | Fixed before release: `hazmat-ghash` is a separate, default-off feature on both crates. The isolated consumer probe checks defaults, defaults off, AES only and explicit GHASH on both compiler endpoints. Enabled functional and lifecycle suites remain selected explicitly. Future GCM should keep its internal arithmetic separate from raw-public API admission. Feature unification is not a security boundary between dependencies in one build. |
| Same supporting-crate versions on an internal train | Retain the existing no-publication policy, not a new versioning exception. Corrected `brynja-core` to `change = "code"`; the facade advances and both changed supporting crates are held. Use reviewed Git identity and scoped fingerprints, not the supporting crate version or SBOM alone, to identify this tree. Revisit versions at a public checkpoint before upload. |
| Copies/spills and x86-only code review | Added a separate three-target Rust 1.100.0 [cross-assembly screen](ghash-portable-screen.md). A fixed-address Cortex-M spill is not erased by clearing caller storage. No spill-erasure or cross-target timing claim; no new timing measurements. |
| Zero GHASH subkey | Keep the raw field operation defined for every field element. Zero is not evidence of a failed derivation; conversely a zero buffer is not evidence of a successful one. Documented this and tested a nonempty multi-block computation with zero H. A future GCM implementation must propagate key-derivation failure, not silently substitute a buffer. |
| Caller-controlled work | Existing bounded, failure-atomic update contract retained. The caller sets a finite application budget; GCM framing and protocol limits belong to the future construction. No blanket message size added to raw GHASH. |
| Sanitization record / GCM scope | Clarified original adapter boundary versus the 0.28.0 package refresh and retained source review. Admission and release-history tests check the new package identity. No IV handling, tag comparison, masking, or other GCM behavior is claimed here. |

Retest the committed candidate from **v0.27.6** (the last tag); v0.27.7 was
not a release. Focus on feature admission, retained test selection, and the
new build-specific evidence. This disposition is not a PASS or authorization
to tag or publish.
