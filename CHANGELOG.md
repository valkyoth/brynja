# Changelog

All notable changes to Brynja will be documented here. The format follows
Keep a Changelog and Semantic Versioning.

## [Unreleased]

### Fixed

- Record the complete v0.24.14 exceptional assessment and final retest as
  `PASS`/`PASS` with zero open findings. The permanent report binds the signed
  v0.24.13 baseline, all three exact remediation candidates, and the unchanged
  scheduled v0.20.0-to-v0.25.0 cumulative assessment boundary.
- Record the complete v0.24.13 exceptional assessment and exact final-candidate
  retest as `PASS`/`PASS` with zero open findings. The permanent report binds
  both remediation commits, all five findings or observations, and the
  unchanged scheduled v0.20.0-to-v0.25.0 cumulative assessment boundary.
- Make the public-but-hidden hardened cSHAKE composition bridge irreversible.
  Reader extraction and explicit wiping now enter a terminal lifecycle state
  first; later preflight, update, and finalization calls return
  `StateConsumed`. Internal and package-external regressions prevent reuse of
  cleared replacement storage as a fresh SHAKE state, and Rust 1.90/1.98 MIR
  evidence binds terminal transition ordering before finalization or wiping.
- Eliminate the v0.24.13 inline KMAC state-remanence path: KMAC no longer
  stores hardened cSHAKE in `Option<S>` or extracts it with `take()`. Fixed and
  XOF finalization now operate on the exact embedded source through `&mut`,
  replace it with a cleared owner, and volatile-clear the vacated allocation.
  Rust 1.90.0/1.98.1 development and optimized compiler evidence plus a
  negative source-move fixture enforce the transition.
- Hide weak-key and short-tag KMAC conformance entry points from default builds
  behind `conformance-testing`, reject impossible encoded-key widths instead of
  silently producing an empty prefix, and document the caller's required
  protocol-level verification-length bound.
- Move hardened cSHAKE customization and setup-length metadata into two new
  registered byte-backed owner regions, clear both at finalization and Drop,
  and enforce the complete thirteen-region boundary through unit, mutation,
  MIR, LLVM IR, assembly, Rust 1.90.0, and Rust 1.98.0 evidence. The exact
  remediation candidate passed repository-owner retest with zero open findings.

### Added

- Implement complete TupleHash128, TupleHash256, TupleHashXOF128, and
  TupleHashXOF256 in the new allocation-free `no_std` `brynja-hash-tuple`
  leaf. Whole and affine exact-length streamed tuple items preserve order,
  empty values, structural boundaries, and canonical arbitrary-bit inputs;
  fixed and incremental XOF output support ordinary public and hardened typed-
  secret ownership without exposing cSHAKE or Keccak internals.
- Bind all twelve official NIST TupleHash/TupleHashXOF examples, a separately
  composed 256-case arbitrary-bit oracle, tuple partition/collision negatives,
  abandoned-item failure, package-external bare-metal use, twenty-four
  cumulative Kani bounds, Miri, AddressSanitizer, source-policy mutations, and
  Rust 1.90.0/1.98.1 cleanup evidence to v0.24.14. TupleHash is fully
  implemented but not independently verified or FIPS 140-3 validated; the
  complete SP 800-185 family remains in progress through ParallelHash and
  combined final acceptance.

- Implement complete KMAC128, KMAC256, KMACXOF128, and KMACXOF256 in the new
  allocation-free `no_std` `brynja-mac-kmac` leaf. The public surface separates
  exact standards conformance from strength-enforcing production policy,
  exposes opaque fixed tags with constant-time verification, treats XOF output
  as typed secret unless explicitly declassified, and supports canonical
  arbitrary-bit inputs and output.
- Bind all twelve official NIST KMAC/KMACXOF examples, a separately composed
  256-case arbitrary-bit oracle, malformed assurance input, package-external
  bare-metal use, source-policy mutations, twenty-two cumulative Kani bounds,
  Miri, AddressSanitizer, timing checks, and Rust 1.90.0/1.98.1 cleanup
  evidence to the exact keyed construction. KMAC is fully implemented but not
  independently verified or FIPS 140-3 validated; the complete SP 800-185
  family remains in progress.
- Implement the complete v0.24.12 SP 800-185 encoding foundation and
  cSHAKE128/cSHAKE256 ordinary and hardened APIs. Byte and canonical
  arbitrary-bit N, S, message and output domains, exact empty-N/S SHAKE
  equivalence, one-shot, streaming, fixed-output and incremental squeeze paths
  are exposed through the SHA-3 leaf, crypto composition, and main facade.
- Add all four official NIST cSHAKE examples, a 480-result independently coded
  arbitrary-bit oracle, exact encoding/integer/bytepad boundaries, hardened
  secret-output clearing, a package-external `no_std` three-layer consumer,
  twenty cumulative Kani bounds, dynamic-analysis bindings, and adversarial
  source-policy mutations. The wider SP 800-185 family remains in progress
  through v0.24.17; no independent verification or FIPS validation is claimed.
- Add five pre-1.0 roadmap milestones for an optional high-assurance
  protected-memory layer: a portable `no_std` contract, first-party hosted
  providers for Linux/Android, Windows, Apple/BSD, and a cross-platform
  deployment-profile acceptance gate. The layer must fail closed without
  changing portable defaults or claiming control of registers, caches,
  caller-owned copies, forced termination, DMA, dumps, swap, hibernation, or
  physical security that it cannot actually enforce.
- Add the v0.24.11 combined downstream `no_std` acceptance fixture and
  fail-closed closure policy for every SHA-2 and SHA-3/SHAKE ordinary,
  arbitrary-bit, hardened public/secret, fixed-output, streaming, and XOF
  profile. The same gate inventories all seven optional CPU candidates as
  unadmitted and runs across the supported Rust and target matrices.

### Changed

- Re-admit and exact-pin first-party `sanitization 2.0.4` after the live release
  gate detected the upstream patch. Default features and every optional feature
  remain disabled, the selected `owned.rs` and `wipe_backend.rs` TCB files are
  byte-identical to 2.0.3, the package still resolves no transitive dependency,
  and the adapter remains outside every facade, engine, default, and FIPS
  boundary. The focused Brynja dependency-delta retest passed with no Critical,
  High, or Medium finding, restoring the report to `PASS`/`PASS`.
- Refresh the Miri and Rust sanitizer pin to the latest available
  `nightly-2026-09-04` at exact Rust revision
  `a69a63265cfd9e006d43137f98301b8d274ad4c9` after the v0.24.14 live pre-tag
  freshness gate detected the upstream nightly advance. This changes only
  assurance tooling and generated evidence, not production Rust or
  cryptographic behavior.
- Make pre-tag Miri proportional and fail closed: internal tags run smoke
  coverage for every registered group plus full coverage of changed groups and
  their downstream closure, while every crates.io checkpoint and every shared
  toolchain, manifest, lockfile, or Miri-policy change requires the complete
  suite. The grouped runner also exposes a future headless shard boundary;
  distributed results cannot replace local evidence until an exact-commit,
  exact-toolchain, complete-inventory aggregator is implemented.
- Refresh the default release compiler from Rust 1.98.0 to 1.98.1 after the
  fail-closed live freshness check detected the stable patch release. Rust
  1.98.0 remains an explicitly tested compatibility lane; the full gate,
  promised-target evidence, and cleanup/code-generation endpoints now use
  1.98.1 without changing the Rust 1.90.0 MSRV.
- Mark the exact SHA-2 and SHA-3/SHAKE families **Fully implemented** only
  after combined package-external acceptance. Independent verification and
  FIPS 140-3 validation remain explicitly absent, and no accelerated backend
  is admitted.

### Fixed

- Review and pin newly reported RFC 9846 technical erratum 9161 after the
  v0.24.11 live release gate detected it. The unverified report remains
  `track-not-applied`: it clarifies presentation syntax versus the existing
  conforming `signature_algorithms` sender requirement and admits no TLS code,
  requirement change, or wire-behavior change.
- Reconcile the v0.24.11 component inventory with the completed SHA-2 and
  SHA-3/SHAKE status, permanently reject both stale pending formulations, and
  record the voluntary assessment and clean retest as `PASS`/`PASS` with zero
  open findings.
- Move full Miri and AddressSanitizer execution from an inevitably timing-out
  20-minute GitHub job to the required local pre-tag gate. CI retains
  fail-closed validation of tool pins, script and coverage bindings, mutation
  tests, and emitted-code evidence; no cryptographic source or API changes.
- Record the completed exceptional v0.24.10 assessment and green retest of
  exact remediation candidate `b3232116a66f908524d859aa40d1b1ab8e31f913`.
  The permanent report closes its one High finding with `PASS`/`PASS` and zero
  open findings while retaining the scheduled cumulative v0.25.0 assessment.
- Close the High v0.24.10 hardened-state remanence finding by replacing
  source-created SHA-3 lane/counter conversion arrays with scalar fixed-count
  byte operations and staging partial secret SHAKE output only inside the
  registered owner buffer before clearing it. All seven partial output widths
  now have direct secret-output differential and clearing coverage; source
  mutations plus development and release MIR/LLVM checks reject reintroduced
  one-byte or eight-byte secret temporaries.
- Remediate both Medium v0.24.6 assurance-control findings: secret-owner
  registration is explicit rather than inferred, exact canonical owner types,
  fields, sanitizers and cleanup call paths are checked against Rust
  declarations, and all mixed-direction profiles now bind output secrecy,
  failure handling and authentication timing per operation. Twenty-three
  structural mutations and twenty-two exhaustive secret-output downgrade
  mutations pass locally; the first retest confirmed the information-flow fix
  and identified the two residual owner-evidence findings below.
- Close both Medium residual findings from the first v0.24.6 retest: six
  adjacent compiler contracts bind all eight current owner shapes and
  sanitizer signatures, cleanup calls use fully qualified Rust paths, and nine
  exact optimized-MIR call targets are enforced under Rust 1.90.0 and 1.98.0.
  Raw and raw-byte strings, disabled `cfg`, macro nesting, same-named methods,
  missing/duplicate MIR callers, and wrong MIR targets fail closed;
  the second retest confirmed those fixes and found one residual circular
  future-registration path.
- Close the Medium second-retest finding by rejecting registration-provided
  cleanup expressions, requiring every future registered owner to exactly
  match an independently maintained compiler contract, and deriving its exact
  adjacent test and complete optimized-MIR caller-to-sanitizer inventory from
  that contract. The reported read-only `OwnedSecretRegion::expose` record and
  incomplete registered MIR coverage now fail closed; independent third
  retest found the residual empty-target gap below.
- Close the Medium third-retest finding by deriving registered owner tests,
  caller headers, and sanitizer MIR targets from three separate exact-coverage
  maps; requiring every value and header component to be nonempty; and binding
  package, unique owner-specific test, caller method/type, and declared
  sanitizer function/type identities. Six low-level and seven registration
  regressions cover the reported bypass; the fourth retest found the residual
  owner-prefix gap below.
- Close the Medium fourth-retest finding by parsing MIR callees into exact
  function and owner identifier tokens rather than using substring membership.
  Positive turbofish and trait-qualified paths remain supported, while all four
  reported owner-name prefix/suffix collisions fail closed; eleven registered-
  identity regressions now pass; the fifth retest found the residual namespace
  gap below.
- Close the Medium fifth-retest finding by requiring registered Rust symbols
  to carry complete crate-rooted module paths and comparing sanitizer type or
  trait identities without suffix matching. Registered caller evidence now
  binds the exact crate, module, implementation source, method, and receiver
  type from the MIR header. The reported same-named cross-module, cross-crate,
  trait-module, and nested-module substitutions fail closed; twenty-two
  registered-identity regressions pass; the sixth retest found the residual
  MIR data-flow gap below.
- Close the Medium sixth-retest finding with a dedicated optimized-MIR control-
  flow and data-flow verifier for every future registered algorithm owner.
  Exactly one resolved sanitizer call must consume `_1` or an explicit
  reborrow/projection rooted in `_1`, and its call block must dominate every
  reachable normal and unwind exit. Decoy receivers, duplicate call sites,
  skipped normal cleanup, and skipped unwind cleanup fail closed; ten focused
  MIR regressions pass; the seventh retest found the two residual call-identity
  and reaching-definition gaps below.
- Close both Medium seventh-retest findings by anchoring the complete sanitizer
  identity at the MIR assignment right-hand side and replacing global stale
  provenance with control-flow-aware definite provenance. Call-result,
  branch-specific, loop, and `_1` redefinitions invalidate prior derivations;
  outer-module, crate-prefix, identifier-prefix, and trait-prefix callable
  substitutions and arrow-bearing non-call redefinitions fail closed.
  Nineteen focused MIR regressions pass; the eighth retest found the projected-
  place gap below.
- Close the Medium eighth-retest projected-place finding with a place-sensitive
  must/may provenance analysis over plain and call-result definitions. Writes,
  deinitialization, and call results rooted in `_1` or any possible alias fail
  closed, including branch-only aliases and typed/nested projections. A wider
  adjacent audit additionally rejects owner alias escape through casts,
  aggregates, other calls, inline assembly, unmodeled statements, and post-
  sanitizer mutation; requires the sanitizer to be compiler-proven non-
  unwinding; and conservatively tracks its result as possibly aliased. Three
  positive paths and twenty-two focused negative paths pass. The ninth retest
  confirmed that remediation and found the sanitizer-result escape below.
- Close the Medium ninth-retest sanitizer-result escape by retaining possible
  owner provenance when the exact sanitizer writes through a projected place
  and rejecting owner-derived `_0` at every reachable normal exit. Direct
  return, joined return, projected return, field, nested field, typed
  projection, and projected mutation paths now fail closed; four positive and
  twenty-nine negative strict-flow paths
  pass. The independent tenth retest confirmed all thirteen remediations and
  reported zero open findings; the permanent report records `PASS`/`PASS`.
- Enforce the standalone v0.24.3 SHA-3/SHAKE public fixture's declared Clippy
  policy with warnings denied in both the complete local gate and hosted CI,
  correct the reported comparison warning, and add negative policy fixtures
  that reject removal of either lint binding; independent retest of exact
  candidate `c7bd354e5bcf9a816c366cf24d0d88347771afc5` passed with zero open
  findings.
- Refresh the official DNS Parameters evidence after the local v0.24.2 tag
  gate detected IANA's 2026-08-28 update; classify the new
  `_nnu-verification` TXT entry as caller-owned v0.140.0 state, regenerate the
  complete standards, surface, and requirement closure, and admit no new
  authority, production code, API, dependency, or runtime behavior.
- Record both v0.24.2 Medium repository-assurance resource-bound findings,
  their production-code-neutral remediations, and the green independent
  second retest of exact candidate
  `c7af70e19def950f3a9004c18e5c869ef844c644` with `PASS`/`PASS` and zero open
  findings.
- Refresh the release-gate Miri and Rust sanitizer pin to the latest available
  `nightly-2026-08-30` at exact Rust revision
  `fd7ed57dfd3bdebb745a1d8158638727b0e7047a`, update CI and the dynamic-
  analysis evidence contract together, and rerun both workloads successfully.
- Move the default and complete release gate to official stable Rust 1.98.0,
  retain the uninterrupted Rust 1.90.0-through-1.98.0 compatibility matrix,
  and confirm every admitted crate and GitHub/assurance tool remains current.
- Remove 241 accidentally tracked SHA-3 differential Cargo artifacts,
  including two executable binaries; ignore Cargo targets at every workspace
  depth, reject tracked `target/` components in the complete repository gate,
  and run the differential fixture from a fresh locked non-incremental target.
- Record the v0.24.0 pentest's High build-artifact trust-bypass finding, its
  completed remediation, and the green independent retest of exact candidate
  `208cde2b24e9aef314e2a59e530a5fd0f659151d` with `PASS`/`PASS` and zero open
  findings.

### Added

- Implement the v0.24.10 complete hardened SHA-3/SHAKE state boundary. Four
  fixed-output states and two absorb/reader typestate pairs cover byte and
  arbitrary-bit input, incremental and arbitrary-bit XOF output, explicit
  public declassification, and affine typed-secret destinations.
- Register and compiler-check eleven byte-backed sponge, input/output,
  lifecycle, staging and permutation-scratch regions. All terminal paths use
  mandatory core clearing; exact Rust 1.90/1.98 MIR call resolution plus
  release MIR, LLVM IR and assembly checks reject destruction drift.
- Add all-identity ordinary/hardened differential, rate, bit-tail,
  multi-squeeze, failure, cancellation, early-Drop and unwind tests; a
  standalone bare-metal `no_std` consumer; two hardened-output Kani properties
  for eighteen cumulative harnesses; Miri, AddressSanitizer, and eight
  adversarial source-policy mutations. Final v0.24.11 combined acceptance,
  hardened acceleration, independent review, FIPS validation and publication
  remain pending.
- Implement the v0.24.9 complete ordinary FIPS 202 arbitrary-bit domain for
  SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128 and SHAKE256. A distinct
  low-bit-first canonical message type prevents confusion with SHA-2, and a
  typed consuming destination supports every SHAKE output bit length.
- Bind 76 reproducibly selected official NIST CAVP records, six official
  five-bit examples, 440 independent bounded oracle cases, sixteen cumulative
  Kani harnesses, Miri, AddressSanitizer, malformed-input rejection and
  package-external `no_std` leaf/facade acceptance into CI. Hardened FIPS 202
  state, final combined acceptance, independent review, FIPS validation and
  crates.io publication remain pending.
- Record the clean exceptional security assessment of exact v0.24.9
  implementation candidate `3f6669f670472cea4f2a162e545db456ee368530`;
  the permanent report records `PASS`/`PASS`, zero open findings, no Critical,
  High, or Medium finding, and no remediation.
- Implement the v0.24.8 complete hardened SHA-2 state APIs for all six FIPS
  180-4 identities. Distinct sealed portable states accept byte and canonical
  arbitrary-bit input, require explicit public declassification or typed
  secret output, and compiler-resistantly clear eight registered owner regions
  on terminal, error, `Drop`, and recoverable-unwind paths.
- Add package-external and bare-metal `no_std` hardened consumers, ordinary-
  versus-hardened differential and lifecycle tests, compile-fail capability
  and API tests, two Kani failure-output bounds, Miri, AddressSanitizer, and
  exact Rust 1.90.0/1.98.0 MIR/LLVM/assembly destruction evidence. Hardened
  acceleration remains prohibited; SHA-2 remains In progress until v0.24.11,
  and zero crates are selected for publication.
- Record two clean security assessments of exact v0.24.8 implementation
  candidate `9bb19a27d5ce957a2cf4474e88e445dce7950da3`; neither reported a
  Critical, High, or Medium finding, and the permanent exceptional report
  records `PASS`/`PASS`, zero open findings, and no required remediation.
- Refresh the exact AFL++ assurance-tool pin from 5.02c to latest 5.03c at
  upstream tag revision `dbaf11913c1b2702dee5b4d3dcfffd52f1defe50` after
  the pre-tag network freshness gate detected the release. This changes no
  production code, dependency, public API, or publication selection.
- Implement the v0.24.7 complete SHA-2 arbitrary-bit input domain for all six
  FIPS 180-4 identities. One canonical borrowed `BitString` rejects ambiguous
  unused tail bits; portable and forced-backend one-shot functions plus
  consuming incremental final-tail methods use exact checked 64-bit or 128-bit
  length accounting while preserving every byte API.
- Bind 240 exact selected NIST CAVP bit records, every final-bit residue and
  critical padding/block boundary, 1,008 results from a bounded independent
  Python oracle, accelerated-candidate parity, eleven total SHA-2/SHA-3 Kani
  bounds, Miri, AddressSanitizer, and an 18-result downstream `no_std` fixture
  into CI and hash-locked source policy. All CPU candidates remain unadmitted,
  SHA-2 remains In progress pending hardened profiles and final acceptance,
  and zero crates are selected for publication.
- Record two clean security assessments of exact v0.24.7 implementation
  candidate `68d0e88450c25355f3a3aa0a8b1947d484fe6b90`; neither reported a
  Critical, High, or Medium finding, and the permanent exceptional report
  records `PASS`/`PASS`, zero open findings, and no required remediation.
- Refresh Miri and Rust sanitizer evidence during the v0.24.11 release gate to
  latest available
  `nightly-2026-09-03` at exact Rust revision
  `2e2b193f8ada105f27608b7be81c293e0d7292cb` after the pre-tag freshness gate
  detected the upstream nightly advance.
- Implement the v0.24.6 cryptographic API-profile and secret-state closure
  register across all 129 semantic capabilities, with 22 exact API dimensions,
  milestone ownership, eight current, zero registered capability, and 75
  planned secret owners, mandatory
  core-versus-optional-adapter cleanup classification, typed public/secret
  outputs, reviewed source hashes, and deterministic JSON/document projections.
- Add twenty-five fail-closed structural mutation classes, twenty-two
  per-operation secret-output downgrade mutations, and a standalone
  zero-dependency `no_std` contract proving downstream code cannot forge the
  sealed hardened capability, ordinary states cannot satisfy hardened bounds,
  public failure destinations stay unchanged, and partial or panic-unwound
  secret destinations are cleared through the real core lifecycle.
- Advance the internal facade to `brynja 0.24.6` with zero crates.io packages
  selected and no production cryptography, dependency, unsafe boundary,
  backend admission, independent-review, erasure-completion, or FIPS claim.
- Refresh Miri and Rust sanitizer evidence to latest available
  `nightly-2026-09-01` at exact Rust revision
  `0dfb098f3aeecbe38c2566ca090193280e7349e7`.
- Implement the v0.24.5 cross-authority lifecycle monitor over all 130 locked
  RFC, NIST, ITU-T, RISC-V, and IANA authorities, with distinct upstream and
  Brynja states, exact content and stable publication-page identities,
  planning/replacement metadata, reviewed impact, and exact requirement,
  symbol, evidence, and milestone ownership.
- Add bounded exact-URL live observation, unresolved-drift retention,
  fail-closed human disposition rules, a weekly/manual read-only workflow,
  committed release-freshness evidence, and pre-tag live enforcement. Its
  first strict run detected RFC 9846 editorial erratum 9157; human review kept
  it unverified and track-not-applied, refreshed the exact evidence and 31
  affected requirement revisions, and the final complete observation passed
  with zero new or unresolved drift. No network result can modify policy,
  code, classification, publication, or a security claim.
- Advance the internal facade to `brynja 0.24.5` with zero crates.io packages
  selected and no production Rust, cryptographic behavior, dependency, unsafe
  boundary, backend admission, independent-review, erasure, or FIPS claim.
- Remediate three Medium v0.24.5 lifecycle-assurance findings: reject malformed
  HTTP-200 errata pages without exactly one authoritative outcome; archive and
  identity-bind observations before any review can close, with real roadmap,
  affected-object, evidence, and committed `PASS`/`PASS` exceptional-pentest
  validation for security changes; and replace the predictable tag artifact
  with exclusive no-follow creation inside a private `mktemp` directory.
- Close the first retest's residual Medium history-integrity bypass by requiring
  a non-shallow repository, comparing against every reachable schema-2 review
  archive, fetching complete history in the scheduled observer, and testing a
  shallow clone plus an add/delete/unrelated-commit sequence with real Git
  repositories.
- Fail closed when a historical review path exists but its blob cannot be read,
  distinguishing that partial-clone/corruption case from a genuine absent path
  through commit-tree inspection and regression fixtures.
- Record the final independent v0.24.5 retest of exact signed remediation
  candidate `116afe2390b61561c0d4414aa2a2dafbc3658a80` as green, closing all four
  lifecycle-assurance findings with `PASS`/`PASS` and zero open findings.
- Refresh Miri and Rust sanitizer evidence to latest available
  `nightly-2026-08-31` at exact Rust revision
  `90850177249efe0321573c569aec5d12b257f8d6` after the final release audit
  detected the prior daily pin was stale.

- Add isolated zero-dependency `no_std` Keccak-f[1600] candidates for x86_64
  AVX2 and AArch64 SHA3 instructions, with thread-bound direct-KAT sessions,
  permanent quarantine, zero ordinary admissions, and an explicit RISC-V
  scalar-only disposition because the pinned ratified ISA has no qualifying
  Keccak acceleration route.
- Bind v0.24.4 acceleration evidence to a 1,024-state direct permutation
  differential, 80 fixed-output and 28 XOF comparisons across all six frozen
  byte-oriented identities, Rust 1.90.0/1.98.0 emitted instructions, and
  supplemental AArch64 QEMU execution. Native Intel, Apple, and AWS Arm,
  performance, migration, side-channel, independent-review, secret-erasure,
  FIPS-validation, and public-dispatch claims remain absent.
- Advance the internal facade to `brynja 0.24.4`, select zero crates.io
  packages, and require an exceptional pentest before its signed tag because
  this milestone adds new intrinsic and evidence-only unsafe boundaries.
- Record the green exceptional v0.24.4 assessment of exact implementation
  candidate `2f755e821e31da9a5524320986c3eb9400f3cfad` as `PASS`/`PASS` with
  zero open findings while retaining zero backend admissions and every native,
  migration, performance, side-channel, independent-review, erasure, and FIPS
  restriction.
- Audit the entire pre-1.0 roadmap for complete reusable API shapes and private
  secret cleanup. Add a machine-readable API-profile and secret-state register,
  canonical arbitrary-bit plus distinct hardened SHA-2/SHA-3/SHAKE milestones,
  compiler-resistant sanitization of every Brynja-owned secret copy on every
  terminal path, package-external combined acceptance, and later separately
  locked RustCrypto, synchronous-I/O, and Tokio adapter gates. Both expanded
  hash families now remain **In progress** through v0.24.11 instead of claiming
  completeness from byte-oriented mathematical APIs alone.
- Harden that roadmap closure with recoverable panic-unwind and adjacent-
  cleanup-failure tests, non-panicking all-region destruction, explicit
  `mem::forget`/abort/termination/power-loss residuals, sealed downstream-
  unforgeable hardened capabilities, and typed public-declassification versus
  secret-output destinations with failure-atomic or cleared partial writes.
- Add a frozen standalone `no_std` consumer for all four SHA-3 digests and
  both SHAKE XOFs through leaf and facade APIs, covering 24 fixed-output, ten
  XOF, and twenty incremental-squeeze results over official, independent real-
  data, exact-rate, multi-rate, zero-output, checked-failure, and domain-
  separation cases.
- Package the exact sixteen-crate FIPS 202 closure with an empty Cargo home,
  safely extract and validate every archive, and rerun the consumer offline
  with version-only dependencies; negative fixtures reject corrupt outputs,
  missing semantics, hidden features, invalid phase/private access, and
  incomplete package contents.
- Advance the internal facade to `brynja 0.24.3` without changing production
  cryptography, dependencies, backend admission, independent-review, secret-
  erasure, FIPS-validation, or publication status. The SHA-3/SHAKE family
  remains **In progress** through final v0.24.11 complete API acceptance.
- Add complete allocation-free `no_std` SHAKE128 and SHAKE256 one-shot,
  streaming-input, consuming-finalization, and incremental multi-squeeze APIs
  with separate absorb/output types, exact FIPS 202 rates and suffix, checked
  `u128` input/output domains, zero-length output, and caller-owned buffers.
- Verify both XOFs with official zero-bit and 1,600-bit examples, exact
  rate-minus-one/rate/rate-plus-one inputs, every bounded input and output
  partition across multiple permutations, fixed-output domain negatives,
  Miri, AddressSanitizer, a ninth Kani bound, and independent-library
  differential results for all six FIPS 202 functions over 328 messages.
- Expand the reviewed SHA-3/SHAKE boundary to 43 mutation fixtures and exact
  hashes, reexport both XOFs through `brynja-crypto` and `brynja 0.24.2`, and
  retain the family as **In progress** pending portable and accelerated final
  acceptance; no package, backend, independent-review, secret-erasure, or FIPS
  claim is added.
- Remediate the v0.24.1 Medium incorrect-assurance-claim finding by executing
  SHA3-384/SHA3-512 under the CI-invoked Miri and AddressSanitizer scripts and
  adding four SHA-3 policy regressions that reject removal or narrowing;
  independent retest of exact remediation candidate
  `31ce5c95fdf4ea5eb6f1bb942de9f06c3f11f6d2` passed, and the permanent report
  records `PASS`/`PASS` with zero open findings.
- Refresh the reviewed standards evidence for verified editorial RFC 9954
  erratum 9136, which corrects two TLS 1.3 section references and changes no
  normative hybrid-key-exchange behavior or current runtime code.
- Add complete allocation-free `no_std` SHA3-384 and SHA3-512 one-shot,
  streaming, exact-digest, checked-length, consuming-finalization, common-
  trait, and facade APIs over the unchanged private Keccak-f[1600] sponge.
- Verify the two new algorithms with official FIPS 202 zero-bit and 1,600-bit
  examples, standard text and million-byte inputs, exact padding boundaries,
  irregular streaming partitions, raw-Keccak domain-separation negatives,
  public identity checks, and the existing shared Kani bounds.
- Expand the isolated independent-library differential corpus to all four
  fixed-output SHA-3 algorithms over 328 deterministic messages (1,312
  results), and expand reviewed-source enforcement to 29 mutation fixtures.
- Advance the internal facade to `brynja 0.24.1` without publishing a package,
  exposing SHAKE, admitting acceleration, or making secret-erasure,
  independent-review, or FIPS-validation claims; the family remains
  **In progress** until its later acceptance gates.
- Move the complete NIST SP 800-185 family into the pre-1.0 roadmap: cSHAKE128
  and cSHAKE256; KMAC128/256 and KMACXOF128/256; TupleHash128/256 and their XOF
  forms; and ParallelHash128/256 and their XOF forms. Separate milestones now
  own arbitrary-bit encoding, secret cleanup, tuple identity, bounded parallel
  execution, package-external portable acceptance, and final cross-backend
  acceptance before the family can be marked fully implemented.
- Pin the exact current final SP 800-185 PDF as local-only authority, add its
  requirement and surface ownership, record the announced revision as mutable,
  and plan a cross-authority lifecycle monitor that detects official updates,
  replacements and withdrawals while requiring human security disposition
  instead of automatically changing modern or legacy status.
- Add unpublished allocation-free `no_std` `brynja-hash-sha3 0.1.0` with one
  private safe-Rust Keccak-f[1600] owner and complete portable SHA3-224 and
  SHA3-256 one-shot, streaming, digest, checked-length, and consuming-finalize
  APIs, reexported through `brynja-crypto` and the `brynja 0.24.0` facade.
- Verify the two algorithms with official FIPS 202 zero-bit and 1,600-bit
  examples, text and million-byte values, exact sponge padding boundaries,
  every bounded two-part partition, a raw-Keccak domain-separation negative,
  and an isolated 328-message differential corpus against Python `hashlib`.
- Bind the v0.24.0 scope with 17 source-policy mutation fixtures, exact
  reviewed hashes, two Kani bounds, first-party-Rust/no-unsafe/no-allocation
  enforcement, normative requirement evidence, and explicit rejection of
  premature SHA3-384, SHA3-512, SHAKE, or raw-permutation exposure.
- Keep the SHA-3/SHAKE family visibly **In progress** until the later complete-
  family public and accelerated acceptance gates. v0.24.0 selects zero crates
  for publication and requires an exceptional new-primitive pentest before
  its internal signed tag; no independent-review, secret-erasure, CPU-
  admission, or FIPS-validation claim is made.
- Record the voluntary v0.23.4 assessment of exact signed implementation
  candidate `7864a8f3a8766d16fc9bb2ea89893351f29aa842` as `PASS`/`PASS`
  with zero open findings and no remediation. Preserve all CPU-admission,
  secret-state-erasure, independent-review, FIPS-validation, zero-publication,
  and scheduled v0.25.0 cumulative-review restrictions.
- Close the complete SHA-2 implementation chain at v0.23.4 with a standalone
  `no_std` downstream consumer that exercises all six algorithms through both
  leaf and facade public APIs over one-shot, irregular streaming, empty, text,
  binary, multi-block, million-byte, and file-like inputs.
- Repeat the public acceptance from a safely extracted 15-package offline
  Cargo archive closure with version-only dependencies and an empty Cargo
  home; reject corrupted digests, missing APIs or documentation, wrong output
  widths, incomplete backend accounting, evidence-only features, and altered
  package contents.
- Run the complete-family fixture on Rust 1.90.0 through 1.97.1 and check its
  `no_std` library across every promised OS-less target. Preserve zero admitted
  CPU backends and every independent-review, FIPS-validation, and ordinary-
  state-remanence restriction; select zero crates.io packages for internal
  v0.23.4.
- Record the exceptional v0.23.3 assessment as `PASS`/`PASS` with zero open
  findings and bind the final unadmitted disposition to exact-commit native
  AMD, Intel, Apple M2 and AWS Arm observations; retain RISC-V as a
  non-qualifying QEMU/codegen-only lane and preserve every authenticated-
  provenance, migration, performance, side-channel, independent-review,
  erasure and FIPS restriction.
- Extend the opt-in CPU surface across all six SHA-2 identities: SHA-224
  reuses the exact SHA-256-family kernels, while new static direct-KAT
  AArch64 SHA-512 and RV64 Zknh SHA-512 candidates serve SHA-384, SHA-512,
  SHA-512/224, and SHA-512/256 without merging public identities.
- Add forced scalar-equivalence tests across critical padding boundaries and
  irregular chunks under AArch64 and RISC-V QEMU, compiler-endpoint SHA-512
  instruction checks, permanent session quarantine tests, and complete-family
  std reporting with fail-closed required mode.
- Record x86_64 SHA-512 as scalar-only instead of inferring acceleration from
  AVX2 or AVX-512, retain all five candidates as unadmitted pending qualifying
  native performance, migration, and side-channel evidence, and select zero
  crates.io packages for exceptional internal v0.23.3.
- Split oversized future implementation families into review-sized tagged
  milestones with separate portable implementation, acceleration, and
  package-external acceptance gates. The revised roadmap now decomposes SHA-3,
  AES, GCM, ChaCha20/Poly1305, integer and field arithmetic, EdDSA/Curve448,
  P-521, the complete v0.46 cryptographic substrate, private-key containers,
  PKIX generation and legacy/PQ profiles, ML-KEM acceptance, SP 800-90A DRBGs,
  HPKE foundations, and Argon2/OCB/EAX; registry-driven OpenPGP and named
  legacy-protocol phases must insert further child rows before implementation
  if authenticated source closure reveals another oversized unit.
- Record the exceptional v0.23.2 repository-owner SHA-512/224 and SHA-512/256
  assessment of exact signed implementation candidate
  `0129013eaae7ee3f1cd2ca5cf9671b8ea5834165` as `PASS`/`PASS` with zero open
  findings and no remediation; retain ordinary-state erasure, complete-family
  acceleration, packaged acceptance, independent-review, FIPS, zero-
  publication, and scheduled v0.25.0 cumulative-review restrictions.
- Add complete allocation-free `no_std` SHA-512/224 and SHA-512/256 as
  separately typed one-shot, streaming, digest, error, and facade APIs over the
  reviewed SHA-512-family state.
- Implement the exact FIPS 180-4 SHA-512/t IV-generation procedure for the two
  approved identities and verify that its results equal the normative IVs used
  by public constructors; explicitly reject ordinary SHA-512 truncation.
- Cover both algorithms with NIST CAVP short, long, and Monte Carlo vectors,
  million-byte cases, every critical padding boundary, every two-part split,
  every fixed chunk width, exhaustion and common-trait use, reviewed source
  hashes, and adversarial negative fixtures.
- Mark all six named FIPS 180-4 SHA-2 algorithms implemented but not
  independently verified or FIPS 140-3 validated; retain ordinary-state
  remanence and absent complete-family acceleration restrictions and select
  zero crates.io packages for internal v0.23.2.
- Record the exceptional v0.23.1 repository-owner SHA-384/SHA-512 assessment
  of exact signed implementation candidate
  `22c1dcdc7594a34bc14b53b42d1d56f7aa66047b` as `PASS`/`PASS` with zero open
  findings and no remediation; retain ordinary-state erasure, acceleration,
  independent-review, FIPS, zero-publication, and scheduled v0.25.0
  cumulative-review restrictions.
- Add complete allocation-free `no_std` SHA-384 and SHA-512 over one private
  80-round `u64` compression owner and one private 128-byte buffered state,
  with exact distinct FIPS 180-4 IVs, 48-byte/64-byte digests, checked `u128`
  message domains, transactional streaming, consuming finalization, one-shot
  functions, common traits, and facade reexports.
- Verify SHA-384 and SHA-512 with NIST CAVP short and Monte Carlo vectors,
  FIPS long and million-byte examples, independently generated critical
  padding boundaries, every two-part split, every fixed chunk width, exact
  exhaustion and padding proofs, Miri, AddressSanitizer, and adversarial
  reviewed-source policy; explicitly reject the false truncated-SHA-512 model
  for SHA-384.
- Record both algorithms as implemented but not independently reviewed or FIPS
  140-3 validated; preserve ordinary-state remanence and absent-acceleration
  restrictions and select zero crates.io packages for internal v0.23.1.
- Record the exceptional v0.23.0 repository-owner SHA-224 assessment and
  retest of exact signed implementation candidate
  `8877bda1e697db98e77637d82bdc0d0d6ecad237` as `PASS`/`PASS` with zero open
  findings and no remediation; retain ordinary-state erasure, acceleration,
  independent-review, FIPS, zero-publication, and scheduled v0.25.0
  cumulative-review restrictions.
- Split the oversized complete-SHA-2 milestone into five reviewable tagged
  stops: complete SHA-224, complete SHA-384/SHA-512, complete SHA-512/224 and
  SHA-512/256, whole-family acceleration, and package-external acceptance.
- Add complete allocation-free `no_std` SHA-224 with a distinct FIPS 180-4 IV,
  exact 28-byte digest, checked message-length preflight, transactional
  streaming updates, consuming finalization, one-shot use, and the common
  fixed-output hash traits; reexport it through `brynja-crypto` and `brynja`.
- Verify SHA-224 with NIST CAVP short and Monte Carlo vectors, FIPS long and
  million-byte examples, every critical padding boundary, every two-part split,
  all fixed chunk widths, exact exhaustion proofs, and an explicit regression
  showing SHA-224 is not truncated SHA-256.
- Record SHA-224 as implemented but neither independently reviewed nor FIPS
  140-3 validated; retain the ordinary unkeyed-state erasure limitation and
  require a later hardened owner before HMAC or any secret-bearing use.
- Refresh the Miri and Rust sanitizer evidence toolchain to the latest
  available `nightly-2026-08-16` at exact Rust revision
  `67854e511de21d881bb16426996cd4259d44aa2e`, regenerate deterministic
  assurance evidence, and rerun both dynamic-analysis gates before v0.22.3.
- Record the voluntary v0.22.3 repository-owner assessment and retest through
  exact signed implementation and CI-correction candidate
  `399c9e7c5092d755dfbc22a3adf5500f85a8877e` as `PASS`/`PASS` with zero open
  findings and no cryptographic source remediation; retain zero publication,
  ordinary-state erasure, accelerated-admission, independent-review, FIPS, and
  scheduled v0.25.0 cumulative-review restrictions.
- Isolate SHA-256 package acceptance to its exact four-crate closure and an
  empty Cargo home so clean CI proves offline packaging without resolving the
  unrelated optional sanitization dependency or relying on a warm registry
  index.
- Clarify that ordinary `Sha256` does not guarantee erasure of secret-input
  remnants and that callers cannot clear its private internal state; retain
  hardened secret ownership as a mandatory gate before keyed admission.
- Complete the v0.22.3 SHA-256 implementation-chain acceptance with a
  standalone public-only `no_std` downstream consumer covering six
  authoritative real inputs, one-shot and irregular streaming, both public
  crate entry points, scalar execution, and explicit skips for every
  unadmitted accelerated backend.
- Add a public non-mutating SHA-256 message-length preflight so downstream
  consumers can deterministically test the exact maximum and exhaustion edge
  without private hooks or impossible allocations.
- Install and execute the same consumer against safely extracted package
  artifacts with version-only dependencies, and enforce it across Rust
  1.90.0 through 1.97.1, hosted systems, and the promised bare-metal matrix.
- Add executable negative fixtures for digest corruption, missing exports,
  backend misreporting, exhaustion bypass, unadmitted features, and altered
  package contents. Mark portable SHA-256 implemented while retaining explicit
  no-independent-review, no-FIPS-validation, zero-accelerated-admission, and
  no-v0.22.3-publication statements.
- Add an isolated first-party RV64 `Zknh` SHA-256 candidate using exactly
  `sha256sig0`, `sha256sig1`, `sha256sum0`, and `sha256sum1` in one
  source-hash-bound Rust inline-assembly module, with static exact-feature
  selection, direct startup KAT, health, quarantine, and scalar ownership.
- Verify all four Zknh mnemonics under Rust 1.90.0 and 1.97.1 and run the full
  accelerated SHA-256 differential corpus under explicit RISC-V QEMU, while
  treating cross-build and emulation evidence as supplemental only.
- Extend detached native evidence capture and its adversarial validator for the
  registered RISC-V cloud lane, requiring an exact observed `zknh` ISA string
  and rejecting generic RV64, RVV, lane, transcript, or instruction
  substitution.
- Keep the RV64 candidate unadmitted and absent from automatic std detection
  because qualifying native correctness, migration, performance, side-channel,
  authenticated-provenance, independent-review, and FIPS evidence is absent;
  retain the `Zvknha`/`Zvknhb` vector route as an unimplemented reservation.
- Record a sanitized inventory of the registered eight-hart SpacemiT X60 lane:
  user-local Rust 1.97.1 is available, but every hart lacks `Zknh`, `Zvknha`,
  and `Zvknhb`, so the preflight stops before candidate execution and the lane
  remains useful only for focused scalar, portability, generic-vector, and
  bit-manipulation work.
- Define the RISC-V evidence split explicitly: use that host natively only for
  exact features in its all-hart intersection, label absent cryptographic
  extensions QEMU/codegen-only, and keep both routes separate from admission.
- Add a post-v1.0.0 community RISC-V qualification plan with reproducible,
  privacy-conscious capture instructions, exact-feature hardware requests,
  local bundle validation, and an explicit rule that community observations
  alone cannot admit a backend.
- Record the exceptional v0.22.2 assessment as `PASS`/`PASS` with zero open
  Critical, High, or Medium findings and no source remediation; retain the
  QEMU/codegen-only, native-evidence, erasure, independent-review, admission,
  and FIPS restrictions.
- Advance the facade to internal v0.22.2 with no crates.io publication and
  require an exceptional pentest before tagging because inline cryptographic
  assembly creates a new unsafe ISA boundary.
- Add isolated first-party x86_64 SHA and AArch64 SHA2 compression candidates,
  static `no_std` selection, direct startup KAT, caller-owned health and
  permanent quarantine in `brynja-crypto-cpu`.
- Add an optional SHA-256 CPU-session edge that retains scalar ownership of
  streaming state, padding, checked length and finalization, plus a separate
  opt-in `std` detector with actual-backend reporting, scalar fallback and
  fail-closed required mode.
- Keep both v0.22.1 accelerated candidates unadmitted until complete
  commit-bound native evidence exists, and require generated x86 SHA and
  AArch64 SHA2 instructions without making register-erasure, independent-
  review or FIPS-validation claims.
- Add a clean-commit-bound detached native candidate runner that can execute
  locally or over SSH, survive operator disconnects, persist job state, fetch
  completed bundles, and reject source, lane, transcript, checksum, symlink,
  or admission-authority substitution before formal evidence review.
- Collect and locally validate private non-authorizing candidate observations
  for local AMD, observed-feature AWS Intel, Apple M2, and AWS Arm at exact
  signed commit `7d6dc573d8aaf049085d4bc4007642ee3b9ed82f`, while retaining
  zero admitted backends pending authenticated, performance, side-channel, and
  CPU-migration evidence.
- Accept both ELF `sha256h` and Apple Mach-O `sha256h.4s` emitted-instruction
  spellings through a narrow regression-tested matcher that rejects
  `sha256h2` prefix substitution.
- Record the exceptional v0.22.1 assessment and retest of exact signed commit
  `7d6dc573d8aaf049085d4bc4007642ee3b9ed82f` as `PASS`/`PASS`
  with zero open findings and no cryptographic implementation, admission,
  dependency, or public-API change after the final evidence-tool correction.
- Give the published `brynja` package a compact crates.io-specific README with
  current capability examples, design boundaries, verification tables, a
  reduced workspace guide, and links to the detailed repository documentation;
  keep the full project narrative in the GitHub README.
- Replace the root crate-level verification matrix with smaller concrete
  capability tables that distinguish public usability from independent review,
  retain the architectural component inventory in `docs/VERIFICATION_STATUS.md`,
  and require SHA-256 to wait for v0.22.3 acceptance before appearing as
  implemented.
- Require every named implementation milestone to expose a complete usable
  public API with consumer-style end-to-end evidence, block or immediately
  patch completeness gaps, and close every multi-version implementation chain
  with a separately tagged public-API usability-acceptance milestone.
- Add v0.22.3 as the SHA-256 chain acceptance stop with one runnable downstream
  fixture covering real one-shot and streaming inputs, authoritative digests,
  package contents, portability, and every admitted backend.
- Add allocation-free canonical ASN.1 BOOLEAN, INTEGER, BIT STRING, OCTET
  STRING, OBJECT IDENTIFIER, admitted character-string, UTCTime, and
  GeneralizedTime value types to `brynja-pki`.
- Add validated SEQUENCE, SET, and SET OF wrappers with caller-supplied DER
  limits, direct-component tag ordering, and X.690 padded-octet ordering.
- Add nine behavior groups, exhaustive 256-value BOOLEAN, 65,536-value bit
  padding, and 65,536-value two-octet OID corpora, six compile-fail examples,
  ten reviewed source hashes, and forty adversarial policy fixtures.
- Promote `BRY-REQ-ENC-0002` to implemented revision 3 and add the dedicated
  `format.asn1.values` surface without claiming schema decoding, DEFAULT
  omission, AlgorithmIdentifier, X.509, cryptography, independent review, or
  FIPS validation.
- Advance the facade to internal v0.21.0 with zero crates.io publication and
  require an exceptional pentest because canonical semantic decoding extends
  a hostile parser boundary.
- Record the exceptional assessment of exact signed v0.21.0 implementation
  candidate `6e3ca63305fd3923ca723c9d7f559a9b12843002` as `PASS`/`PASS`
  with zero findings and no source remediation, while retaining explicit
  schema-validation and independent-review cautions.
- Record the repository owner's green v0.21.0 retest and the complete local
  tag-gate pass on signed pentest-report candidate
  `5c6a819a1fc6f12129ca75ce93201de2549d1563` before hosted verification.
- Record that signed v0.20.0 passed hosted checks and published all 15 selected
  packages, including `brynja 0.20.0`, `brynja-pki 0.2.0`, and initial
  `brynja-protocol 0.1.0`.
- Refresh Miri and sanitizer evidence to `nightly-2026-08-14` at exact Rust
  revision `ba28ff76f353a722f31c4f3dd2ac4e437d36411b` after the online
  freshness gate.
- Add `brynja-pki 0.2.0` bounded DER framing with borrowed exact slices,
  non-recursive event traversal, canonical identifier and definite minimal
  length checks, checked parent containment, and failure-atomic reader state.
- Add immutable input, depth, node, child, identifier-octet, length-octet,
  value-size, work, and fixed-stack ceilings, fourteen integration tests,
  three compile-fail examples, an exhaustive 65,536-input corpus, six locked
  source hashes, and thirty-three broken policy fixtures.
- Remediate the v0.20.0 Low DER semantic-boundary finding by preventing nested
  identifier and length parsing from reading an adjacent byte beyond its
  parent, with focused tag/length regression coverage and policy enforcement.
- Record the repository-owner retest of exact signed v0.20.0 remediation
  candidate `7fd31b4cc536cb2dce1a565fa3551365b086000f` as `PASS`/`PASS`
  with zero open findings.
- Promote `BRY-REQ-ENC-0001` to implemented revision 2 and add the dedicated
  X.690-bound `format.der.framing` surface without claiming ASN.1 semantics,
  X.509, cryptography, independent verification, or FIPS validation.
- Complete the scheduled v0.20.0 cumulative checkpoint with 15 selected
  packages after the v0.15.0-to-v0.20.0 pentest and remediation retest passed,
  hosted checks became green, the signed tag was created, and publication
  completed.
- Add unpublished `brynja-protocol 0.1.0` with typed external wire policies,
  borrowed TLS 1.2/TLS 1.3 and DTLS 1.2/DTLS 1.3 record-envelope parsing, and
  transactional caller-buffer encoding.
- Enforce profile-specific record constants and length bounds, preserve
  permitted legacy-version and unknown content-type bytes, and reject RFC 6520
  Heartbeat content and negotiation in every modern profile.
- Add eighteen behavior tests, three compile-fail examples, seven reviewed
  source hashes, thirty negative policy fixtures, and generated protocol-
  surface and requirement evidence for the first hostile parser boundary.
- Remediate the initial v0.19.0 High cleartext-exposure finding by separating
  TLS 1.2 and TLS 1.3 plaintext admission, categorically rejecting TLS 1.3
  application data during parsing and construction, and adding a dedicated
  closed error plus regression coverage.
- Record the repository-owner retest of exact signed v0.19.0 remediation
  candidate `238d4bac75eecce9dde63700c53f13e6f7a9aaed` as `PASS`/`PASS`
  with zero open findings while retaining the milestone in the cumulative
  v0.15.0-to-v0.20.0 checkpoint assessment.
- Advance the development facade to `brynja 0.19.0`, expose the shared framing
  crate, wire it into the modern TLS/DTLS engine packages, select zero crates
  for publication, and require an exceptional pentest before the signed tag.
- Add a final pre-1.0 RFC 9580 OpenPGP phase with 44 small standards,
  resource, packet, key, cryptography, message, lifecycle, interoperability,
  audit, remediation, and publication milestones, followed by whole-project
  integration and final-audit gates.
- Add a v0.47.1 admission milestone for exact-pinned first-party `base64-ng`
  reuse in bounded PEM and OpenPGP armor so Brynja does not duplicate Base64;
  the planned edge must remain allocation-free, `no_std`, non-cryptographic,
  and outside the FIPS module.
- Plan complete streaming and fixed-message SHA-1 once in future
  `brynja-legacy-sha1`, then separately admit `brynja-openpgp-legacy` as its
  first consumer for v4 fingerprints; later legacy protocol and hash-facade
  consumers require their own review and may not reimplement SHA-1.
- Add seventeen sealed mandatory security-decision domains, a caller-owned
  one-pending authoritative state machine, checked generations, permanent
  terminal latching, and exhaustive accepted, approved, non-approved,
  rejected, pending, canceled, failed, and terminal typed outcomes.
- Add affine token-gated external-key destruction whose success requires the
  exact consumed external-store token and whose duplicate, substituted,
  provider-failed, abandoned, or dropped transitions fail closed.
- Add fourteen authority behavior tests, seven compile-fail boundary examples, a
  SHA-256-bound six-file source policy, and twenty-nine decision, reason-binding,
  approval, terminal, token, low-level, size, and drift fixtures.
- Add broad FIPS-aware service-category sets with approved classification
  fail-closed until exact algorithm identities exist, transactional complete
  non-approved provider classification, module-owned scalar or
  accelerated environment assumptions, deterministic-build digest
  expectations, explicit SSP flow, and provider-derived destruction policy.
- Add an explicit trusted self-test runner boundary, private interruption-safe
  guard, permanent failure latch, and generation-bound non-cloneable
  informational service indicators that cannot authorize execution and become stale
  after catastrophic failure.
- Add six FIPS architecture behavior groups, four compile-fail boundary
  examples, a SHA-256-bound four-file source policy, and twenty-four isolation,
  classification, lifecycle, indicator, source-size, unsafe, and drift
  fixtures, including broad provider-handle escape.
- Add exact affine pending certificate, external-signature, and accelerator
  requests with mandatory poll/cancel capability admission, applicable
  destruction duties, checked effect-attempt and backpressure limits, and no
  implicit provider fallback.
- Add state-owning begin, resume, retry, backpressure, completion,
  cancellation, failure, exhaustion, and `Drop` transitions whose authoritative
  completion consumes one non-cloneable destruction token covering all frozen
  external-store, accelerator, cache, DMA, and other provider duties.
- Bind every pending effect to the exact authorizing provider; retain state
  through activation and later unwinding callbacks; recheck identity after
  guarded preparation immediately before activation; and charge
  provider-derived nonzero work before issuing a non-forgeable permit for each
  effectful transition.
- Add sixteen deterministic and adversarial lifecycle tests, four compile-fail
  ownership/forgery tests, a SHA-256-bound six-file policy, and twenty-one
  admission, identity, work, begin/unwind, cleanup, low-level, source-size, and drift
  fixtures.
- Add canonical checked durations, signed Unix wall time, inclusive validity
  ranges, opaque generation-bound monotonic instants, purpose-bound deadlines,
  explicit unavailable-time behavior, and permanent rollback failure.
- Add permanently unpublished deterministic wall and monotonic sources, ten
  behavioral tests, two compile-fail type/forgery examples, a SHA-256-bound
  five-file clock policy, and nine broken assurance fixtures.
- Add affine exact-purpose raw-entropy requests and non-cloneable initialized
  secure-random state with bounded requests, runtime-generation binding,
  mandatory fork/reseed transitions, transactional output, terminal
  quarantine, and synchronous destruction duties.
- Add a permanently unpublished deterministic/fault secure-random provider,
  thirteen behavioral tests, affine compile-fail examples, a hash-bound source
  policy, and nine isolation, trait, teardown, low-level, and drift fixtures.
- Add a hash-bound v0.13.3 CPU evidence schema, five native and three QEMU
  supplemental lanes, thirteen admission harnesses, exact raw-artifact
  provenance, bounded freshness/noise/order/performance rules, and a
  deterministic register retaining zero admitted backends.
- Add 55 adversarial evidence fixtures and a dependency-free non-cryptographic
  `no_std`/no-atomics scalar/mock fixture covering forced, required,
  unsupported, KAT, quarantine, differential, fallback, and independent-
  session behavior across host and OS-less target checks.
- Reserve unpublished `brynja-crypto-cpu 0.1.0` and
  `brynja-crypto-cpu-std 0.1.0` package boundaries without implementing a
  primitive, ISA kernel, runtime detector, or executable dispatch path.
- Add a SHA-256-bound CPU-acceleration policy covering eight reserved backend
  identities, exact future modules, instruction bundles, ABI preconditions,
  graph and FIPS exclusions, zero active kernels, zero new low-level
  allowances, and twenty-six broken fixtures.
- Add sealed CPU-backend identities, exact feature bundles, scalar,
  opportunistic, required-accelerated, and validated-module policies, and inert
  candidate profiles that cannot authorize an instruction.
- Add caller-owned no-atomics health sessions, direct-KAT guards, opaque
  feature and KAT evidence, monotonic health/runtime generations, permanent
  quarantine, thread-bound active/dispatch tokens, exact-operation selection,
  and explicit opportunistic scalar-fallback reports.
- Bind backend evidence to one opaque measured artifact and operational
  environment and bind KAT pass/failure evidence to the exact session and
  instance. Add opaque exact-session CPU leases plus sealed CPU-context,
  migration-excluding guard, and kernel traits; acquire and retain the guard
  across direct execution and revalidate logical authority after every
  platform callback.
- Add thirteen CPU-backend behavior test groups, eleven compile-fail authority
  and token examples, a SHA-256-locked eight-file source policy, and
  twenty-three broken fixtures.
- Implement nineteen independent provider operations spanning cryptographic,
  signature, KEM, AEAD, entropy, clock, certificate-chain, storage, and pending
  boundaries without implementing any provider effect or algorithm; MAC
  generation and verification are separate capabilities.
- Add immutable capability snapshots, transactional named installation, frozen
  resource/work limits and destruction duties, opaque borrowed handles,
  exact-operation authorization, and bounded version-neutral request metadata.
- Add nine provider-contract test groups, six compile-fail token/result-forgery
  examples, a SHA-256-locked four-file provider source policy, and thirteen
  broken fixtures.
- Implement private normalized `Choice` and `CtMask` values plus constant-time
  equality, conditional selection, conditional swap, and a compiler barrier for
  every unsigned word width and compile-time-sized byte arrays.
- Add exhaustive byte-pair, word-boundary, array mismatch-position, and
  compile-fail tests; a hash-locked source policy with fourteen negative fixtures;
  and optimized LLVM/assembly witnesses across ten stable compilers and nine
  promised targets with five evidence-policy fixtures.
- Add target-aware assembly function-body inspection and six negative fixtures
  for RV32 secret branches and secret-indexed loads, non-public fixed-array
  branches including a backward direct-`Choice` classifier bypass, and
  x86_64/AArch64 conditional branches.
- Canonicalize RISC-V numeric argument-register aliases, classify all eighteen
  base, pseudo, and compressed conditional forms, and retain ten focused
  negative branch/address fixtures.
- Add the versionless post-1.0 hash-ecosystem plan and the updated Brynja
  project image.
- Implement separately selected `brynja-sanitization 0.1.0` with opaque
  fixed-size ownership, closed source failures, transactional replacement,
  redacted diagnostics, explicit clear, and named exact-length copies to and
  from Brynja owned regions.
- Add behavior, every-failure-position, capacity, unwind, differential, and
  compile-fail tests plus Miri and adapter-level MIR/LLVM/assembly evidence.
- Admit exactly one external resolved package in machine policy: first-party
  `sanitization 2.0.3`, owned only by the adapter, with no enabled feature or
  transitive dependency.

### Changed

- Give every top-level verification-status row an explicit owning crate, split
  modern and legacy hash families, and list the planned SP 800-185, SHA-1, and
  MD5 closure milestones without prematurely claiming implementation. The
  regression policy now accepts and validates the four-column ownership form,
  including rejection of forged crate or independent-review checkmarks.
- Expand the pre-1.0 legacy-hash chain with a frozen portable SHA-1/MD5
  acceptance boundary, dedicated x86/AArch64 SHA-1 acceleration, explicit
  multi-buffer MD5 SIMD across qualifying x86_64, AArch64 and RISC-V targets,
  and an unchanged-fixture cross-backend closure before either family becomes
  Fully implemented. Strengthen v0.24.11 so SHA-2 and SHA-3/SHAKE status can
  leave In progress only after exact-final-code cross-backend evidence and
  synchronized human- and machine-readable status updates.
- Add the v0.18.1 bounded observational security-event schema with opaque
  authority-derived events, explicit one-way caller timestamp enrichment,
  deterministic fixed-capacity FIFO buffering, and visible saturating loss
  accounting; keep observation structurally unable to authorize, commit,
  complete, latch, alert, execute effects, or alter security state.
- Advance the development facade to `brynja 0.18.1`, retain every supporting-
  crate publication version, include v0.18.1 in the cumulative v0.20.0 range,
  and select zero crates for crates.io publication.
- Record the exceptional repository-owner v0.18.1 assessment as PASS/PASS with
  zero open findings and no remediation, while retaining the complete delta in
  the scheduled v0.20.0 cumulative assessment.
- Make public accepted and approved resolutions permanently fail closed until
  a sealed exact-subject proof path exists; retain exact token-bound acceptance
  only inside external-key completion.
- Hold every resolved non-terminal outcome in `AwaitingCommit` behind an affine
  completion, terminalize dropped pending decisions and dropped completions,
  and map mandatory self-test failure directly to permanent integrity failure.
- Bind each accepted, approved, non-approved, rejected, canceled, and failed
  disposition to its own opaque non-interchangeable outcome type; keep validated
  rejection/failure reasons private and require commit to match the exact
  disposition retained by authority state.
- Advance the development facade to `brynja 0.18.0`, retain every supporting-
  crate publication version, include v0.18.0 in the cumulative v0.20.0 range,
  and select zero crates for crates.io publication.
- Advance the development facade to `brynja 0.17.0`, retain every supporting-
  crate publication version, include v0.16.0 and v0.17.0 in the next cumulative
  checkpoint range, and select zero crates for crates.io publication.
- Advance the development facade to `brynja 0.16.0`, retain every supporting-
  crate publication version from v0.15.0, and select zero crates for crates.io
  publication.
- Advance the cumulative public checkpoint to `brynja 0.15.0`,
  `brynja-core 0.8.0`, dependency-only modern support releases, and the initial
  `brynja-crypto-cpu`, `brynja-crypto-cpu-std`, and
  `brynja-sanitization` packages; the scheduled cumulative pentest and hosted
  release gates passed and the complete selected set was published.
- Require the secure-random destruction-failure handler after failed explicit
  teardown as well as `Drop`, quarantine, and rejected initialization; rename
  the engine hook to reflect its complete scope and cover explicit and `Drop`
  failure exactly once in regression tests.
- Advance the `brynja` facade to `0.14.0`, retain supporting-crate versions,
  implement requirement `BRY-REQ-ENTROPY-0014`, and select zero crates for
  crates.io publication.
- Advance the `brynja` facade to `0.13.3` while retaining every supporting-
  crate version and selecting zero crates for crates.io publication.
- Advance the `brynja` facade to `0.13.2`, keep both CPU boundaries outside
  every facade and protocol engine, and select zero crates for crates.io
  publication.
- Advance the `brynja` facade to `0.13.1` while retaining `brynja-core 0.7.0`
  and every other supporting-crate version; select zero crates for crates.io
  publication at this internal development milestone.
- Admit final Standards Track RFC 10024 as the authority for
  X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024 planning; refresh
  the exact IANA TLS Parameters snapshot, resolve the former hybrid-source
  blocker, and retain implementation exclusively at v0.120.0.
- Advance every requirement whose immutable evidence includes the refreshed
  TLS Parameters snapshot, while preserving all registry classifications and
  recording that RFC 10024 adds no errata and changes no existing errata
  decision.
- Freeze the CPU backend contract before any ISA implementation exists; defer
  isolated kernels, std detection, unsafe admission, and native performance
  evidence to v0.13.2 and v0.13.3.
- Freeze provider authority in upstream `brynja-core`; keep
  `brynja-platform` as a downstream future implementation boundary and do not
  introduce a registry, fallback provider, platform dependency, or effect.
- Refresh the Miri and Rust sanitizer evidence toolchain to
  `nightly-2026-08-13` at exact Rust revision
  `c98d0cb27cc63afdd62602a52eb4feb8a1c682dd` after the online freshness gate.
- Complete the v0.12.0 constant-time foundation without selecting any crate for
  publication; require its exceptional assessment before the signed tag.
- Clarify in the shared package header and main README that Brynja is a
  TLS-first cryptography and secure-protocol ecosystem, with reusable leaf
  hash/MAC families below the still-essential `brynja-crypto` provider and
  composition layer.
- Advance the development facade to `0.11.2` without crates.io publication or
  any facade, engine, default-feature, legacy-specific, or FIPS activation.
- Add the adapter to the package, release, archive, version-matrix, SBOM, and
  documentation inventories while deferring its first publication to a public
  checkpoint.
- Expand the future roadmap with scalar-first, per-primitive CPU acceleration
  milestones; separate no_std ISA kernels from opt-in std detection; and name
  native AMD, AWS Intel, Apple M2, AWS Arm, and qualifying RISC-V evidence lanes.
- Establish the permanent first-party Rust cryptography golden rule and plan
  separately locked downstream `brynja-rustls` and `brynja-tokio` companion
  adapters without admitting either dependency to the core workspace.

### Security

- Record the exceptional v0.18.0 mandatory security-outcome assessment and
  clean second repository-owner retest of exact signed remediation candidate
  `635b229296be45b195d37d8111fd8ad8f8b1e571`, closing four High and one
  Medium finding across the initial review and first retest with `PASS`/`PASS`
  and zero open findings.
- Record the exceptional v0.17.0 FIPS-aware architecture assessment and green
  repository-owner retest of exact signed remediation candidate
  `bc83f44a9c8fdb710d03429b1669ee6c4449b054`, closing two High operation-only
  approval and SSP-destruction-source findings with zero open findings. Retain
  caller-session-scoped failure as a non-exploitable future constraint and
  require a module-wide sibling-proof irreversible latch at v0.127.1 before
  any executable or approved FIPS service exists.
- Record the final full-delta review through exact signed candidate
  `3f889a2c07ae513235fd8cb9056faa983f2135e9` with no open Critical, High, or
  Medium vulnerability; require an opaque unforgeable module-owned self-test
  attestation at v0.125.0/v0.127.0 before provider execution or approved status
  can become reachable.
- Record the exceptional v0.16.0 pending-lifecycle assessment and final
  repository-owner PASS retest of exact signed third remediation candidate
  `f0557b8419b77129d1763e9469ae4e7deeffc2e7`, closing three High and two
  Medium findings with zero open findings.
- Record the scheduled cumulative v0.15.0 assessment of all changes after
  signed public tag v0.10.0 through exact signed implementation candidate
  `1aa4ad938438f0f2dc996b74b6364f1026c05e0f` as PASS/PASS with zero open
  findings.
- Record repository-owner PASS retest of exact signed v0.14.0 remediation
  candidate `854c301de56ba432bd0544e2acc525b34a7b28c8`, closing the Medium
  explicit-teardown terminal-handler omission with zero open findings.
- Refresh the locked IANA TLS ExtensionType snapshot after the release gate
  detected the 2026-08-11 C509 Certificate type allocation; retain its
  provisional draft as non-authoritative future work and regenerate complete
  4,447-surface requirement closure without admitting code.
- Force LF checkout for repository text and reject removal of that rule from
  the CPU-evidence policy, keeping reviewed byte hashes identical on Windows,
  Linux, and macOS.
- Install all three OS-less Rust targets before GitHub's ordinary repository
  gate and enforce the setup with a broken-workflow fixture, preventing the CPU
  admission fixture from failing because `core` is unavailable.
- Refresh the locked IANA DNS Parameters snapshot after the release gate
  detected the 2026-08-11 `_x402` TXT underscored service-name addition;
  classify it as caller-owned at v0.140.0, retain its provisional draft as
  non-authoritative, and regenerate complete 4,446-surface requirement closure.
- Remediate two High v0.13.3 evidence-admission findings by rejecting all
  candidate and native claims until a reviewed trusted-runner verifier exists,
  requiring exact machine-readable artifact semantics bound to the source,
  binary, run context, and declared measurements, and matching every observed
  operating-state value to the backend's exact reviewed ABI prerequisites.
- Remediate the follow-up assessment's Low JSON parser denial of service by
  bounding artifact integers to signed 64-bit values, rejecting floats and
  non-finite constants, and normalizing oversized inputs into controlled
  evidence errors without a traceback.
- Record repository-owner PASS retest of exact signed second v0.13.3
  remediation candidate `1f08ca0fd9be6bf1995a22a9ca806addc17641e0`
  with zero open findings.
- Reject stale, future, mixed-CPU, incomplete-feature, fabricated-native,
  unowned-runner, non-finite, noisy, order-biased, under-sampled, slow,
  oversized, unhashed, path-escaping, QEMU-promoted, or false-eligibility CPU
  evidence while leaving unavailable hosts explicitly unadmitted and scalar
  builds independent.
- Remediate one High fail-open inert-source admission flaw by anchoring both
  source hashes independently in the validator, requiring real line-anchored
  `no_std` and false-status declarations, and rejecting source-plus-policy
  hash replacement, commented attributes, and executable placeholder drift.
- Remediate one Medium policy-integrity flaw by independently pinning the
  complete reviewed policy and comparing every amendment, forbidden mechanism,
  safe-wrapper invariant, FIPS field, and backend ABI precondition exactly.
- Record repository-owner PASS retest of exact signed v0.13.2 remediation
  candidate `2fa60d05d8c4472426cdb979243f53e2e959c231` with zero open findings.
- Keep scalar, protocol-engine, default, bare-metal and FIPS graphs isolated
  from host CPU detection; require a later primitive-specific policy amendment,
  source hash, native evidence, exceptional review and explicit allowance
  before any low-level CPU implementation can be admitted.
- Require one explicitly chosen provider and one exact declared operation;
  reject unsupported direction without registry search, implicit fallback, or
  authorization reuse.
- Check aggregate immutable input, output capacity, provider-operation count,
  and work limits before effects, and reject installation without an explicit
  nonempty local/external/accelerator/cache/DMA destruction-duty set.
- Keep handles, authorization, and request tokens non-cloneable and
  non-formattable; forbid provider-native IDs, mutable request output, protocol
  versions, allocation, platform coupling, unsafe code, and request-side result
  claims from the v0.13 boundary.
- Remediate the voluntary v0.13 assessment's three High findings by removing
  request-side result constructors, retaining exact installed-provider
  identity, and separating MAC generation from verification while forbidding
  verification byte output. Remediate its Medium finding by replacing
  caller-supplied work claims with a monotonic meter initialized from the
  installed provider's frozen budget.
- Record the repository-owner retest of exact signed v0.13.0 remediation
  candidate `b45185e5aefdd48b9dc1859fee7a9000be9b6168` as PASS/PASS with
  zero open findings; signed tag v0.13.0 contains the remediated contract.
- Prevent safe candidate observations, profiles, reports, or public approval
  values from becoming backend authority; require opaque exact evidence and a
  direct KAT result before activation.
- Quarantine recursive, interrupted, failed, mismatched, or approval-invalid
  initialization permanently; reject stale health/runtime generations and
  unsupported operations immediately before future direct kernel entry.
- Remediate the exceptional v0.13.1 assessment's first two High findings: exact
  session and measured-instance references prevent KAT/approval replay between
  equal profiles, while an opaque platform CPU lease binds the admitted CPU
  context. Close the first retest's third High TOCTOU finding by sealing the
  context, migration guard, and kernel; holding migration exclusion across the
  direct call; validating logical authority after every platform callback; and
  removing arbitrary application closures from guarded entry. Record the
  repository-owner retest of exact signed final remediation candidate
  `738d21227d9681299d7464d9df360cf49cac8cca` as PASS/PASS with zero open
  findings; keep the tag blocked until GitHub and CodeQL are green.
- Remediate the pentest's High RV32 timing finding by passing every expanded
  word and array mask through the non-inlined optimization barrier before
  XOR/AND selection, then close two Medium assurance-scanner bypasses through
  register canonicalization and complete RISC-V conditional classification.
- Record the repository-owner retest of exact signed candidate
  `7ce43fffdf81a349c7c44aae33b229d077d4512d` as PASS/PASS with zero open
  findings; keep the tag blocked until GitHub and CodeQL are green.
- Keep decision and mask construction private, expose one explicitly named
  public declassification, forbid ordinary equality/formatting, dynamic slices,
  secret-dependent lengths, and fallible surfaces in the v0.12 boundary, and
  document that emitted code is evidence rather than proof or a
  microarchitectural guarantee.
- Record the exceptional v0.11.2 repository-owner assessment as PASS/PASS with
  no findings and zero open findings; retain the adapter in the later
  v0.10.0-through-v0.15.0 cumulative assessment scope.
- Keep `brynja-core` authoritative for protocol-region destruction and require
  explicit copies whose two owners clear their storage independently.
- Require an exceptional v0.11.2 assessment because the first production
  wrapper around external unsafe secret-storage code is a material boundary.
- Preserve fail-closed re-review on upstream version, source, checksum,
  feature, dependency, unsafe, advisory, target, ownership, or FIPS drift.
- Require exact CPU feature bundles, forced backend differentials, KAT health
  and quarantine, native performance and side-channel evidence, honest
  candidate status, scalar fallback, isolated unsafe review, and exact FIPS
  implementation-symbol and operational-environment ownership.
- Reject C and other foreign/native cryptographic implementations, wrappers,
  vendor libraries, source and binary artifacts, package build scripts, Cargo
  native-link metadata, foreign ABIs, and external-module FIPS substitutions
  through policy, CI, and nine permanent broken fixtures.

## [0.11.1] - 2026-08-09

### Added

- Commit an exact, machine-readable admission record and reviewer-facing audit
  for first-party `sanitization 2.0.3`, including source/package hashes,
  features, graph, unsafe inventory, target evidence, advisories, upstream
  pentest, residual risks, and re-review conditions.
- Add an independent candidate wrapper with six behavior tests and three
  compile-fail tests, eleven broken policy fixtures, and release-gate online
  crates.io freshness, package-archive, compiler, and target verification.

### Changed

- Advance the development facade to `0.11.1` without publishing a crate or
  adding `sanitization` to any Brynja production manifest or lockfile.
- Conditionally admit one future protocol-neutral `brynja-sanitization`
  adapter at v0.11.2 with an exact pin, default features disabled,
  adapter-owned wrappers, explicit selection, and no legacy split.

### Security

- Keep Brynja's v0.11.0 owned-region destruction primitive mandatory and
  authoritative; the optional adapter cannot become an engine dependency or
  weaken protocol destruction duties.
- Exclude the adapter from all facades, engines, defaults, implicit
  conversions, and the FIPS validated-module closure. Upstream independent
  review remains evidence, not Brynja verification or FIPS validation.
- Remediate the candidate fixture's secret-bearing error-remanence finding by
  replacing arbitrary generic source errors with a payload-free Brynja-owned
  `SourceFailure`, rejecting rich errors at compile time, and making policy
  validation fail on generic error acceptance. The fixture was never in the
  production graph.
- Record the repository-owner PASS retest of signed remediation commit
  `cd1c881d2eb6c9aa925f1527a326330c1cf3b80a` with zero open findings; v0.11.1
  remains an internal tag with no crates.io publication selection.

## [0.11.0] - 2026-08-09

### Changed

- Advance the development facade to `0.11.0` and adopt signed tags for every
  automated-tested milestone while reserving routine cumulative pentests and
  crates.io publication for each fifth-minor public checkpoint.
- Bind every future checkpoint report to the backwards-looking change range
  after its prior public tag through the new candidate, beginning with
  v0.10.0 through v0.15.0 and then v0.15.0 through v0.20.0.
- Refresh the reviewed IANA TLS ExtensionType and DNS Parameters pins for one
  caller-owned provisional ALPN entry and three reference-only changes, without
  admitting draft/RFC implementation authority or executable behavior.

### Added

- Affine write-only initialization and readable ownership for one complete
  exclusively borrowed caller secret region.
- Complete-region volatile clearing on admission, incomplete finish, both Drop
  paths, and explicit owner clear, with failure-atomic sequential writes.
- Machine-enforced single-unsafe-block policy and MIR, LLVM IR, assembly, Miri,
  AddressSanitizer, ten-compiler, and nine-target verification.

### Security

- The zeroization claim is limited to the exclusively borrowed Rust allocation
  and excludes registers, copies, caches, DMA-visible copies, dumps, suspend
  images, physical memory, concurrent access, forgotten owners, and termination.
- v0.11.0 requires an exceptional committed PASS pentest before its signed
  development tag because it introduces the first unsafe secret-destruction
  boundary; it still selects no package for crates.io publication.
- Closed the initial pentest's unsafe-policy bypass by SHA-256 pinning the exact
  approved module and, after retest exposed comment-separated and nested-
  attribute variants, replacing syntax-shaped matching with broad fail-closed
  low-level/code-inclusion identifier rejection, fixed library targets, and
  non-symlink source confinement; the repository-owner retest of signed commit
  `88a6c73d3b2ad055702aede3858b1e7ecc8d24aa` passed with zero open findings.

## [0.10.0] - 2026-08-03

### Added

- Abstract affine secret initialization and live-state contracts with exact
  complete-write transition and no byte-backed production owner.
- Explicit local-memory, external-store, accelerator, cache, and DMA
  destruction duties for every early exit, replacement, obsolescence, and
  drop.
- Repository-only RFC 9850 key-log encoding with complete-line transactional
  writes and mechanically enforced production-graph isolation.
- Tested requirement and protocol-surface evidence for secret lifetime,
  test-only key logging, and the production key-log prohibition.

### Changed

- Advance `brynja-core` to `0.7.0`, the eight changed exact-pinned modern
  support packages to `0.1.6`, and the facade to `0.10.0`.
- Mechanically classify post-v0.10 roadmap tags as development milestones or
  each-fifth-minor cumulative public checkpoints.

### Security

- Secret states remain non-clonable, non-formattable, secret-free in
  diagnostics, and impossible to construct before complete initialization.
- No local-memory erasure claim is made before the separately gated v0.11.0
  primitive and emitted-code evidence.
- Destruction failure reached through `Drop` is delivered to a mandatory
  platform-specific durable/fail-stop handler instead of being discarded.
- The repository-owner retest passed with the Medium Drop-failure finding
  closed, the informational v0.11 evidence blocker retained, and zero open
  findings.

## [0.9.0] - 2026-08-03

### Added

- Exact caller-owned workspace partitioning across named secret, plaintext,
  transcript, certificate, and output arenas.
- Monotonic complete-range arena allocation with capacity, used, remaining,
  high-water, and successful non-empty allocation-count telemetry.
- Exhaustive small-layout, every-domain duplicate/omission,
  every-position/request, overflow, exhaustion, zero-length, sentinel,
  pointer-identity, domain-isolation, diagnostic, and compile-fail tests.

### Security

- One exact backing slice is safe-split once in fixed named order, eliminating
  caller-selected independent-buffer overlap and provenance decisions.
- Sealed zero-sized domain markers make simultaneous arena handles distinct
  Rust types and reject accidental secret/output or other domain swaps.
- Both backing-length mismatch directions and every rejected allocation leave
  caller bytes and accounting unchanged.
- Workspace and arena state is private, non-clonable, non-formattable, and
  lifetime-bound to the exclusive caller buffer; errors carry no capacity,
  offset, request, count, byte, string, or provider-native values.
- Allocated bytes retain caller contents and require initialization. No
  release, reuse, zeroization, destruction, protocol, independent-review,
  production, or FIPS-validation claim is advanced.
- Pentesting confirmed the documented drop-remanence and retained-allocation
  boundaries. `SecretDomain` now states that it is not a secret owner,
  `CertificateDomain` rejects private-key semantics, and v0.10 explicitly
  requires typed complete initialization while v0.11 retains the unsafe-policy
  and emitted-code gate for optimization-resistant destruction.
- The repository-owner retest passed with both observations closed and zero
  open findings.

## [0.8.0] - 2026-08-03

### Added

- Allocation-free `WriteCursor<'output>` exclusively borrowing caller-owned
  mutable output.
- Transactional single-slice, multi-part, and repeated-byte writes with exact
  consuming completion and immutable written-prefix inspection.
- Exhaustive every-position/request, whole-buffer no-mutation, aggregate-part,
  overflow, zero-length, empty-output, identity, representation, and
  compile-fail tests.

### Security

- Every operation checks its complete destination before changing any byte;
  capacity or arithmetic failure preserves the full output and cursor position.
- Debug builds assert that each mutable destination lookup remains reachable
  after successful preflight, while release builds retain the fail-closed
  optional-range fallback.
- Multi-part writes preflight the overflow-safe aggregate length before copying
  their first part, so one call is one mutation transaction.
- Cursor state is private, non-clonable, non-copyable, non-formattable, and
  holds an exclusive borrow that prevents safe outside output mutation.
- Write errors are closed and value-free. No integer encoding, framing, arena,
  secret-destruction, protocol, production, independent-review, or FIPS claim
  is advanced.
- The repository-owner pentest and retest passed with the post-preflight
  invariant observation closed and zero open findings.

### Changed

- Beginning after signed `v0.10.0`, group ordinary pentesting and crates.io
  publication into five-minor release trains while retaining a signed tag for
  every roadmap version. Scheduled cumulative checkpoints occur at `v0.15.0`,
  `v0.20.0`, and every fifth minor through `v0.160.0`; exceptional security and
  early-release triggers remain fail-closed.
- Development milestones and patch rows require their complete tests,
  evidence, documentation, signed commit, full automated tag gate, and green
  GitHub and CodeQL before tagging, but create no scheduled release report or
  crate publication. Plan validation mechanically distinguishes all 47 public
  checkpoints from 151 tagged development milestones.

## [0.7.0] - 2026-08-03

### Added

- Allocation-free `ReadCursor<'input>` borrowing caller-owned immutable bytes.
- Exact dynamic, typed `Length<MAX>`, and fixed-array reads with checked end
  offsets and explicit consuming trailing-data validation.
- Exhaustive every-position/request, every-truncation-byte, trailing-suffix,
  overflow, zero-length, borrow-identity, representation, and compile-fail
  tests.

### Security

- Failed reads never advance the cursor or change its remaining input.
- Cursor state is private, non-clonable, non-copyable, non-formattable, and
  bound to the caller input lifetime; no read path uses unchecked indexing.
- Remaining-input accessors assert the internal position invariant in debug
  builds while retaining fail-safe, panic-free release behavior.
- Read errors are closed and value-free: they contain no bytes, offsets,
  requested lengths, available lengths, strings, or allocation.
- No framing, integer decoding, protocol parsing, secret ownership,
  independent review, production, or FIPS-validation claim is advanced.
- The repository-owner pentest and retest passed with the defense-in-depth
  cursor observation closed and zero open findings.

### Fixed

- Replaced the hosted-macOS-sensitive detached-descendant timeout fixture with
  an ordered handshake that proves survival only after process-group cleanup.
- Release publication now accepts the properly capitalized signed tag subject
  `Brynja vX.Y.Z` while retaining compatibility with historical lowercase
  `brynja vX.Y.Z` tags; strict tag checks remain confined to the publisher's
  explicit publish context.

## [0.6.0] - 2026-08-01

### Added

- Private-field bounded `u64` and `usize` values with fallible construction
  and checked addition, subtraction, and multiplication.
- Semantically distinct bounded counts and byte lengths with fail-closed
  `u64`-to-`usize` conversion.
- Protocol-neutral sequence-number and 16-bit epoch values that return typed
  exhaustion instead of wrapping.
- Explicit immutable resource and work budgets with no defaults or setters.
- Exhaustive small-domain arithmetic/advance matrices plus boundary,
  representation, no-mutation, zero-budget, and compile-fail tests.
- Reviewed the 2026-07-31 IANA DNS Parameters refresh and classified its three
  new registries and seventeen entries as caller-owned v0.140.0 surfaces.

### Security

- Primitive overflow, configured-bound violations, underflow, pointer-width
  truncation, and monotonic-value exhaustion all fail closed in every profile.
- Count/length confusion is rejected by the type system, and numeric values
  and budgets implement neither `Debug` nor `Display`.
- Budget failures preserve resource class and operation phase without carrying
  configured numeric limits.
- Replaced the seven-argument resource-budget constructor with a named builder
  that fails closed until every domain is supplied, and deny future overlong
  positional APIs through workspace Clippy policy.
- Added safe `Debug` diagnostics for the closed, valueless `NumericError` enum
  while bounded values and budget types remain non-formattable.
- Made every named resource-budget setter single-assignment and return a typed
  `Duplicate(domain)` error instead of silently replacing an earlier limit;
  incomplete builds now return typed `Incomplete(domain)` errors.
- No TLS/DTLS record, sequence, epoch, parser, mutable accounting, protocol,
  independent-review, production, or FIPS-validation claim is advanced.
- Provisional draft references carried by IANA registry records are not
  admitted as implementation authority.
- The repository-owner pentest and follow-up retest passed with all three
  reported API-design findings closed and zero open findings.

## [0.5.0] - 2026-07-31

### Added

- Exhaustive TLS AlertDescription classification across all 256 registry
  bytes, preserving assigned, reserved, and unassigned identities.
- Protocol-version-aware assigned alerts with derived semantic class and
  hardened severity.
- Distinct orderly-close, cancellation, alert-failure, local-failure,
  provider-failure, and resource-exhaustion domains in `brynja-core 0.2.0`.
- Positive, negative, exhaustive, representation-bound, and compile-fail tests
  linked to the tested `BRY-REQ-TLS-0005` requirement.

### Security

- Failure envelopes accept no arbitrary text, bytes, provider-native codes,
  cryptographic material, or numeric limits and implement neither `Debug` nor
  `Display`.
- Close and cancellation cannot be ambiguously collapsed into `TlsFailure`;
  only error-class alerts can become alert failures.
- The alert registry is the only protocol surface marked implemented. TLS,
  DTLS, cryptography, PKI, providers, independent verification, production
  readiness, and FIPS validation remain explicitly unclaimed.
- The repository-owner pentest of the signed implementation candidate passed
  with no findings; the permanent report records `PASS`/`PASS` and zero open
  findings.

## [0.4.0] - 2026-07-31

### Added

- A first-party deterministic mutation runner covering empty, original,
  truncation, deletion, bit-flip, and zero/`0xff` insertion cases with exact
  replay indexes and SHA-256 failure identities.
- A canonical raw-stdin differential protocol requiring at least two distinct
  process adapters and rejecting crash, timeout, output exhaustion, malformed
  JSON, noncanonical hex, unsupported classes, and semantic mismatch.
- OS-less all-feature workspace checks for ARMv7E-M, RV32IMAC, and x86_64.
- Deterministic assurance evidence binding policy, runners, CI, and every Cargo
  manifest, with 24 positive and broken fixtures.

### Security

- Child processes run without a shell and both output streams are capped while
  produced. Inputs are explicitly public test data, and campaign launchers
  must provide OS network, filesystem, process, and device isolation.
- Kani 0.67.0, AFL++ 5.02c, honggfuzz 2.6, Miri, and Rust sanitizers have exact
  upstream source revisions and cannot enter repository Cargo manifests.
- Stable Rust 1.97.1 remains the release compiler; Kani 0.67.0 uses a separate
  compatible Rust 1.90.0 verifier pairing. No proof harness is admitted, and
  policy-only status cannot be claimed as formal verification.
- Bare-metal compilation does not claim startup, allocation, interrupts,
  entropy, time, transport, storage, emulator, hardware, or Aesynx support.

## [0.3.5] - 2026-07-31

### Added

- Fifty optional, HPKE, ECH, ML-KEM, entropy, operational, legacy, and
  residual requirements, bringing the deterministic matrix to 167 records.
- Local-only checksum pins for final FIPS 203, SP 800-227, SP 800-90B, and
  SP 800-90C.
- Exact residual coverage of 33 authorities, 182 normative RFC sections, and
  all 743 surfaces left by the foundation, domain, and transport bundles.
- A generated closure report mapping all 126 locked authorities, 206 roadmap
  rows, 4,424 protocol surfaces, and 167 requirements in both directions.
- Twenty-two residual broken fixtures, bringing the requirement suite to 110
  positive and negative tests.

### Security

- Concrete ECDHE-ML-KEM groups remain blocked because the current IANA values
  are provisional and the group specification is not yet a final RFC; drafts
  and private code points cannot satisfy the gate.
- Non-RFC legacy implementations remain blocked on authenticated source bytes,
  hashes, errata, redistribution rights, cipher decisions, isolation review,
  and a separate pentest.
- FIPS validation milestones remain blocked on a dated, rights-reviewed FIPS,
  ISO, CMVP, laboratory, certificate, caveat, and operational-environment
  baseline; no current package or profile claims FIPS validation.
- Every local NIST/ITU authority has an explicit local-only distribution
  record, while all eight IANA registries and five mutable NIST publication
  pages have dependent-milestone refresh owners.
- Raw Public Keys, Delegated Credentials, certificate-compression receive,
  artifact, and send phases, HPKE context/base/export phases, ECH phases, and
  entropy phases now match their exact roadmap owners.
- Two Medium pentest findings are remediated: all 741 residual surfaces are
  explicit, reciprocal, independently validated, and homogeneous by code/test
  boundary; all 182 residual normative sections have one or more of 165 exact
  mappings or one of 17 reviewed exclusions instead of RFC-wide inheritance.
- Three additional Medium retest findings are remediated: section decisions
  reconcile globally across bundles, RFC 9853 RRC extension and registry
  ownership is confined to the v0.111.1 DTLS boundary, and SSL 2, WTLS, PCT,
  SNP, and SSL 1 requirements remain mechanically source-blocked.
- Two further Medium retest findings are remediated: RFC 9853 ContentType 27
  is confined to a dedicated DTLS-only admission boundary, and RFC 6066
  sections are split among exact SNI, status, alert, exclusion, and
  cross-bundle delegation decisions instead of being attributed wholesale to
  OCSP.
- Three final Medium retest findings are remediated: unsupported RFC 6066 peer
  ClientHello extensions use a bounded opaque ignore path distinct from
  rejected local configuration and unsolicited responses; RFC 6066 has an
  independent TLS 1.2 owner at v0.90.1; and generated `delegated` section
  evidence is declared and contract-tested against the schema.
- The repository-owner retest of the complete ten-finding remediation passed
  with zero open findings; the permanent v0.3.5 report is `PASS`/`PASS`.

## [0.3.4] - 2026-07-30

### Added

- Sixty-three stable TLS, hardened TLS 1.2, QUIC-TLS, DTLS 1.2, and
  DTLS 1.3 semantic surfaces, one for every owning implementation milestone
  from the shared secret contract through the DTLS audit gate.
- Seventy transport requirements, bringing the deterministic matrix to 116
  stable records and explicitly covering 40 authorities, 550 normative RFC
  sections, and 480 transport surfaces.
- Exact current, compatibility, evidence, exclusion, and caller-owned source
  roles plus explicit requirements for Heartbeat, legacy TLS 1.3 PKCS1 client
  signatures, post-handshake authentication, certificate-with-external-PSK,
  and the QUIC transport boundary.
- A generated transport-coverage artifact and eight positive and
  broken-fixture tests for milestone, authority, role, binding, identity,
  surface, and reproducibility failures.
- Reviewed domain and transport section policies that bind all 914 normative
  RFC sections to exact requirements, extraction anchors, and section hashes,
  plus seven dedicated positive and broken section-binding fixtures.

### Security

- Every planned transport state transition has one stable owner, target
  symbol, positive and negative test target, work bound, evidence gap, and
  residual-risk statement without claiming protocol code exists.
- QUIC packet, frame, recovery, congestion, Retry, migration, and transport
  semantics remain mechanically caller-owned; TLS, TLS 1.2, TLS 1.3, DTLS,
  and QUIC requirements cannot hide behind a generic cross-version mapping.
- RFC 9850 key logging and four optional TLS facility groups remain explicit
  v0.3.5 deferrals; the status_request_v2 exclusion remains bound to its
  already reviewed v0.3.3 OCSP requirement.
- Protocol-surface and requirement artifacts now bind the separate transport
  policies and reject missing owner milestones, authority drift, role swaps,
  duplicate identities, and stale projections.
- The pentest's two Medium governance-integrity findings are remediated:
  every linked surface must independently match authority and owner or use an
  exact structured exception, and every normative section must have an
  explicit requirement binding or reviewed disposition. External retest of
  the remediated candidate passed with zero open findings; the permanent
  v0.3.4 report is `PASS`/`PASS`.

## [0.3.3] - 2026-07-30

### Added

- Thirty-four cryptography, encoding, PKIX, OCSP, and Certificate
  Transparency requirements, bringing the deterministic matrix to 46 stable
  records.
- Exact authority-role coverage for all 53 assigned sources, section-hash
  coverage for 364 normative RFC sections, and requirement or explicit
  deferral coverage for all 3,322 selected protocol surfaces.
- Local-only checksum pins for FIPS 202 and the in-force ITU-T X.690 (2021)
  plus Erratum 1.
- Explicit SHA-3/SHAKE, GHASH, and ChaCha20 semantic decisions and corrected
  SHA-2, HMAC, HKDF, and AES milestone ownership.
- A generated domain-coverage artifact and 15 positive and broken-fixture
  tests for authority, scope, role, ownership, work-bound, invariant,
  test-polarity, surface-group, and reproducibility failures.

### Security

- Every new requirement records explicit resource or work assurance,
  positive and negative target tests, unresolved evidence, and residual risk
  without claiming planned code exists.
- Current, compatibility, evidence, and exclusion authorities cannot be
  silently interchanged; every in-scope source must be cited and every
  selected surface must be assigned.
- ML-KEM algorithm and PKIX credential surfaces remain explicitly deferred to
  the complete hybrid review at v0.3.5.
- Five newly reported RFC Editor errata were reviewed as
  `track-not-applied`; no reported erratum was silently incorporated.
- The repository-owner pentest passed the signed v0.3.3 implementation
  candidate with zero findings and required no remediation.

## [0.3.2] - 2026-07-27

### Added

- A stable normative-requirement policy and deterministic schema, resolved
  matrix, bidirectional indexes, and human-readable coverage report.
- A 12-requirement authority pilot spanning all eight lifecycle states and
  binding exact RFC, errata, IANA, source-ledger, and protocol-surface
  evidence.
- Fifty-one positive and broken-fixture tests for identity, source, section,
  lifecycle, transition, ownership, target, evidence, SHOULD-deviation, drift,
  symlink-escape, immutable history, revision, semantic-link, and stale-output
  failures.

### Security

- Protocol requirements cannot claim implemented, tested, or evidenced status
  before their owning implementation milestone and existing anchors.
- Ordinary and release checks now fail closed on requirement-policy or
  generated-evidence drift.
- Actual target validation resolves symlinks and rejects paths that leave the
  repository root.
- Requirement changes are compared with the immutable parent matrix; IDs
  cannot disappear, lifecycle transitions must be legal, and content changes
  require exactly one revision increment.
- Exact-source decision mappings now enforce source, disposition, and owner
  consistency, while broader governance mappings require explicit reviewed
  rationale.
- Reviewed-global mappings are restricted to governance requirements, and a
  released requirement cannot change between governance and protocol scope.
- Ordinary CI accepts only a well-formed, current, committed
  `RETEST REQUIRED`/`PENDING` pentest report while remediation awaits external
  retest; release and tag gates continue to require `PASS`/`PASS`.
- The repository-owner retest passed after all v0.3.2 remediations, leaving
  zero open findings and the permanent report in `PASS`/`PASS` state.

## [0.3.1] - 2026-07-27

### Added

- A deterministic protocol-surface register containing 45 explicit semantic
  decisions, 192 nested IANA registries, and all 4,106 individual records from
  the eight pinned registry collections.
- Required disposition, normative-source, milestone-owner, planned-code-target,
  planned-test-target, and rationale fields for all 4,343 classified surfaces.
- Explicit decisions for Heartbeat, status_request_v2, production and
  test-only SSLKEYLOGFILE handling, TLS 1.3 post-handshake authentication,
  certificate-with-external-PSK, legacy PKCS1 client signatures, ML-KEM PKIX
  credentials, HPKE non-base modes, unsigned X.509 certificates, QUIC
  version-specific cryptography, and certificate compression.
- Human-readable generated disposition, kind, and domain coverage.
- Twenty-five positive and broken-fixture tests for completeness, ownership,
  source binding, classification, override, parser, and reproducibility
  failures.

### Security

- Bound the surface policy to the byte-exact v0.3.0 source ledger so RFC
  status, errata, registry, source, and classification drift cannot remain
  silent.
- Rejected missing or duplicate collections, registries, semantic IDs, JSON
  keys, and overrides; unknown sources, milestones, dispositions, and targets;
  overlapping rules; unmatched selectors; unsafe XML declarations; and any
  premature `implemented` claim.

## [0.3.0] - 2026-07-27

### Added

- A deterministic standards ledger covering all 103 locked RFCs, eight
  local-only NIST authorities, eight exact IANA registry snapshots, and every
  owning roadmap milestone.
- A complete reviewed inventory of 285 official errata with fail-closed
  dispositions based on RFC Editor status.
- Offline source, checksum, lifecycle, relationship, ownership, blocker, and
  reproducibility validation with 28 positive and broken-fixture tests.
- A networked release check that rejects RFC index, errata, or IANA drift.
- A permanent evidence index and explicit final-RFC plus final-IANA admission
  blocker for concrete ECDHE-ML-KEM groups.

### Fixed

- Replaced refresh-time trust-on-first-use hashes with independently reviewed,
  non-self-replacing RFC, NIST, RFC-index, errata, and IANA pins.
- Enforced the exact HTTPS source and redirect allowlist in the Python
  standards pipeline.
- Bounded all upstream responses and rejected XML DTD and entity declarations
  before parsing to prevent compromised-source expansion and memory denial of
  service.
- Kept local-only, redistribution-restricted NIST bytes optional in clean CI
  while still validating their complete manifest and automatically checking
  every byte whenever a local cache exists.

## [0.2.0] - 2026-07-27

### Added

- Machine-readable classification and exact dependency/feature/publication
  policy for all 24 workspace packages.
- Separate no-default and all-feature graph validation with modern, legacy,
  QUIC, repository, target, pin, and feature-smuggling negative fixtures.
- Machine-checked GitHub main-branch release controls matching the protected
  `eth` ruleset model.

### Changed

- Required pentest reports to be regular committed files synchronized against
  every prior report-bearing parent.
- Required release tags to be directly targeted, signed and annotated with the
  exact `brynja vX.Y.Z` subject.
- Extended Clippy enforcement to both all-feature and no-default-feature
  workspace configurations.
- Supplied step-scoped GitHub workflow authentication to the live protected
  release-control validator and enforced that wiring in release metadata.
- Documented the intentional fail-closed release panic posture and its
  availability tradeoff.

## [0.1.0] - 2026-07-26

### Added

- Security-first, dependency-free, `no_std` workspace foundation.
- Modern and legacy protocol package boundaries.
- Standards provenance, toolchain, platform, and release planning policies.
- Guarded independent-version crates.io planning and dependency-order
  publication with mandatory facade releases.
- Committed per-version pentest reports that must stay synchronized with every
  later release-candidate fix before green CI and explicit tagging.
- Versioned admission and conditional implementation stops for one optional
  protocol-neutral `brynja-sanitization` downstream adapter, with no
  `zeroize`, third-party activated dependency, facade, engine, or FIPS-module
  path.
- Independently pinned and verified CI security-tool archive checksums.

### Changed

- Made truncating-cast and sign-loss Clippy lints non-overridable.
- Enforced publication of `brynja` for every official tag, selected the full
  initial modern dependency closure, and added non-uploading package-archive
  validation to the guarded publisher.
