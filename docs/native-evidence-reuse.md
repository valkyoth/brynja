# Reviewed native-evidence carry-forward

Native execution observations retain their actual capture commit, compiler,
platform, outputs and qualification limits. A later test refactor does not turn
them into new hardware observations, nor does Git history alone approve reuse.

The tag gate first runs each existing exact-source native validator. The existing
TupleHash/ParallelHash facade-version-only fallback is retained. If those checks
reject a source delta, the owner-approved test/tooling fallback can accept only
the exact delta in [the review record](../security/native-reuse/v0.24.49-review.json).
There is no general exemption for files named `tests.rs` or for changes labelled
documentation. The standalone exact validators intentionally still reject drift.

## The v0.24.49 review

The native capture is `7a9e9cc6d309d2b0e447498f340fd26a095e2866`. The reviewed
source is `b31075ee038714a6ef2a4bd304324a74e74d635c`. Twenty-four platform records
cover hardened SHA-1, ordinary/hardened MD5, hardened Keccak, KMAC, TupleHash and
ParallelHash. Hardened SHA-2 still uses its unchanged exact-source validator.

The review binds 33 changed paths: 27 Rust test/test-containing files and six
Python review/tooling files. The native matrices retain their full vectors,
widths, lengths and assertions. New selectors affect Miri only; native execution
ignores them. This is source-level equivalence review, not a claim that newly
compiled binaries have been compared byte for byte.

The SHA-1 and MD5 engine production prefixes are identical before their unique
test-module delimiters. ParallelHash's core production prefix is identical before
its test-only assurance module; the extracted buffering helper remains below
that guard. All other production code, parent module guards, manifests, lockfiles,
build scripts and compiler configuration remain unchanged. A new or changed
implementation file outside an individual family's inventory also rejects reuse.

The six tooling changes are explicitly reviewed, not ignored: three hash maps
bind the refactored tests; TupleHash's mutation positive control expects sixteen
instead of fifteen scoped tests; ParallelHash's policy and regressions bind the
new helper and its test-only parents. No native command or kernel is replaced.

## Acceptance checks

The fallback requires all of the following:

- A clean committed checkout and full ancestral capture/review commit identities.
- Exact old/new hashes for every reviewed difference; no unreviewed native input
  additions, removals or modifications, including test/tooling changes.
- Unchanged implementation/build trees through the current commit. The original
  capture-to-review production delta must also be confined to the approved tests.
- Original index and artifact bytes equal to the reviewed commit, including
  original owner review, lanes, CPU identities and checksums. Each source hash is
  recomputed from the capture commit and each existing family result validator
  checks its original records, compiler and execution markers.
- A committed, source-bound [focused-check receipt](../security/native-reuse/v0.24.49-checks.json)
  and matching logs. Seven affected crates run their native all-feature library
  and integration tests with an invalid Miri case selector and the routine Miri
  profile in the environment. Native counters still require full traversal.
  ParallelHash policy/mutations, TupleHash packaged negatives/mutations and the
  carry-forward regressions also run. This is current Linux x86-64 test evidence,
  not a new Mac/Arm hardware capture or an independent security assessment.

`python3 scripts/release/native_review_checks.py` produces the focused receipt
only after every fixed command succeeds and the bound inputs remain unchanged.
No arbitrary imported command list, failure-as-success mode or fallback-to-Miri
substitute exists. Logs live outside Cargo output and survive `cargo clean`.

The fallback is `python3 scripts/release/native_review_carry_forward.py --family FAMILY`.
Its PASS output identifies the original capture and explicitly labels reuse.
Future source deltas need another explicit reviewed record and corresponding
focused verification; this approval does not automatically authorize new test
changes or production changes. A production change requires new native evidence.

This mechanism does not change publication scope, waive Kani/ASan/Miri, approve a
full sweep, import the cancelled schema-1 receipt, grant certification, or alter
the existing release requirements outside this approved native reuse path.
