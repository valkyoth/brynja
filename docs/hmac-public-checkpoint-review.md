# v0.25.2 public checkpoint review handoff

Status: focused reviews received; independent cumulative review and release
qualification pending. This document is not a PASS report or permission to
publish. The implementation was prepared from
`697b5ec2adedda6c92eeb914c7f5baee92e6e655`. Use the full candidate commit ID
(`git rev-parse HEAD` in the clean review checkout) in the tester's report;
do not use that preparation baseline as the reviewed identity.

The owner-supplied Codex Daybreak and Claude reviews cover
`v0.25.1..6313481f6ada011ad2b22f117a8230be3a4c9982` and report no Critical,
High or Medium finding. The [ledger](../security/pentest/v0.25.2.md) records
their exact scope, three non-blocking notes and the later author-tested
documentation follow-up. They do not replace the full public-checkpoint review.

## Two different review ranges

- The immediate implementation delta is `v0.25.1` through this candidate.
  It changes modern HMAC policy/verification, package construction and examples.
- The scheduled public review is **`v0.20.0` through v0.25.2**, as selected by
  [release-crates.toml](../release-crates.toml). Intermediate development tags
  and their reports are supporting history, not a substitute for this range.

The selected publication closure contains 30 packages; 13 workspace packages
remain excluded. Selection does not authorize an upload. Versions and exact
first-party dependencies are coordinated for the cumulative implementations;
third-party lock entries are unchanged from v0.25.1. The modern facade must
remain isolated from the separately selected legacy crates and unfinished
protocol implementations must remain labelled as such.

## Immediate changes to review

1. **One modern tag policy.** `brynja-mac-hmac::validate_tag_policy` admits the
   algorithm before checking a key-independent tag width. Leaf, accelerated
   and hosted selection share it. Complete fractional SHA-512/t tags retain
   their exact bits; byte truncation cannot round up and retains the 128-bit
   floor. Policy is selected before the key or untrusted candidate tag.
2. **Authoritative verification.** Modern public verification returns
   `Result<(), Error>`: only a match is `Ok(())`; a completed mismatch is
   `Error::Mismatch`. The private hosted decision protocol is converted after
   cleanup and result validation. A valid mismatch permits documented reuse;
   backend/protocol failure must not gain a weaker fallback. Legacy verification
   keeps its separately admitted error/report semantics and tag floor.
3. **Usable extracted artifacts.** Combined modern/legacy consumers exercise
   every admitted general SHA-512/t parameter, named algorithms, long keys,
   streaming, prefix/full tags, mismatch and output ownership. Negative consumers
   reject digest/tag, algorithm and modern/legacy substitutions. Runtime
   dependencies resolve from extracted packages, not patched checkout sources.
4. **Lean, self-contained packages.** Sixteen package allowlists exclude
   standalone fixtures and evidence. Required Rust modules, including declared
   unit-test modules, remain packaged. Repository fixtures are inputs to
   separate consumers; they must not repair missing runtime source in archives.
5. **Current and historical identity.** Current manifests, locks, SBOM and
   author review bindings follow the coordinated versions. The frozen v0.24.20
   legacy fixture remains immutable; its new `current` manifest compiles the
   original sources with the current graph. Old captures and external native
   approvals must not be rewritten as current execution.
6. **Publication documentation.** All 43 crate READMEs have their own links,
   scope and examples, with the shared remote image. Implemented HMAC APIs are
   distinguished from independent review, platform qualification and unfinished
   protocols. Neither a green implementation row nor a package build is a
   certification or release approval.

## Completed author checks and what they establish

Detailed incremental results are in the
[candidate notes](../release-notes/RELEASE_NOTES_0.25.2.md). In particular:

- Combined extracted facade debug/release consumers cover all 383 admitted
  general HMAC SHA-512/t parameters, separate legacy profiles, misuse rejection
  and portable `no_std` use. Broader SHA-2/SHA-3/KMAC/TupleHash/ParallelHash and
  SHA-1/MD5 extracted consumers also pass their existing populations and mutants.
- Sixteen pristine extracted package closures build on Rust 1.90.0 and 1.99.1
  in debug/release. Twelve non-hosted packages build portable bare-metal code
  and type-check all-feature bare-metal code. Type-checking is not SIMD execution.
- All 43 package listings and 77 crate README doctests pass; the latter pass on
  both compilers. All 90 current root/fixture workspaces resolve locked/offline.
- The current Linux workspace passes `cargo test --workspace --all-features
  --all-targets --locked --offline` with the coordinated versions. Explicitly
  ignored feature/target-specific tests are not counted as executed coverage.
- Bounded HMAC caller/hosted compiler checks cover Linux x86-64, Linux AArch64
  and Apple AArch64 and the documented panic profiles. These checks do not
  establish arbitrary caller-frame, OS or fatal-path erasure.
- Linux protected SHA-256/Keccak and six Apple resident/hosted campaigns passed
  during development. The Apple archive digest is
  `dd22d3fabb1e98d86af1dd0341dc6932dc733a45368111fae35a3d11350675e6`;
  records and logs are retained under
  `release-reports/v0252-mac-hmac-Qd4XuV/retry1/` outside `target`.
  This is an author-operated, pre-version-reconciliation snapshot, not an
  independently approved capture of the final candidate.

Focused repeatable entry points (not the full release campaign):

```sh
python3 scripts/repository/check-crate-readmes.py
python3 scripts/repository/test-crate-readmes.py
python3 scripts/repository/check-verification-status.py
python3 scripts/repository/test-verification-status.py
python3 scripts/repository/test-package-contents.py
python3 scripts/repository/test-package-fixtures.py
python3 scripts/hmac/check-hmac-inventory.py
python3 scripts/release/release_crates.py --check
cargo test --workspace --all-features --all-targets --locked --offline
```

Tests requiring an explicit native target, feature authority or external tool
remain separate. An ignored test is not a pass and cross-compilation is not
native execution. Historical family-development records retain their original
version/snapshot; this handoff does not silently renew their evidence hashes.

## Existing scope limits

Carry forward the exact dispositions in the
[modern HMAC report](../security/pentest/v0.25.0.md),
[legacy HMAC report](../security/pentest/v0.25.1.md) and referenced platform
contracts. Examples include project-defined fractional SHA-512/t interoperability,
explicit legacy algorithms/short tags, caller-owned buffers outside protected
storage, macOS residency without dump exclusion, and fatal/privileged capture
limits. Dedicated x86 SHA-512 SDE results are emulation, not native silicon.
Do not reopen an accepted limit merely by assuming a stronger unstated promise;
new boundary violations, regressions and misleading claims remain actionable.

## Remaining release work

1. Freeze a candidate commit and obtain the cumulative independent review.
   Record actual findings and retests in the
   [pending ledger](../security/pentest/v0.25.2.md); do not inherit an earlier PASS.
2. Reconcile current compiler/native/timing receipts with their exact inputs.
   Reuse only where the existing proof permits it; collect genuinely changed
   routes before claiming final qualification. Development logs alone do not
   provide an external native approval.
3. Complete the public checkpoint's verification and clean-tree package check.
   The current planner selects repository, compiler matrix, ASan, Miri and Kani
   with the extended public Miri profile. No new full sweep was launched during
   this handoff preparation. This public-checkpoint requirement is distinct from
   incremental verification at ordinary implementation milestones.
4. Obtain green GitHub/CodeQL on the reviewed candidate, then explicit tag and
   publication authorization. Publish selected dependencies before the facade;
   the new exact versions are not assumed already available in the registry.
