# Current Status

Status: v0.7.0 pentest and retest passed; awaiting GitHub

Brynja has implemented only shared alert/failure and bounded numeric/resource
value domains plus a protocol-neutral borrowed read cursor. It still has no
TLS framing or parser, TLS state machine, cryptography, PKI, QUIC-TLS, DTLS
engine, platform provider, or legacy protocol implementation and must not be
used to secure network traffic. Brynja is not FIPS 140-3 validated, and no
package, feature, build, profile, or configuration may imply otherwise.

Signed releases v0.1.0 through v0.6.0 established the workspace, hardened
release and isolation controls, made standards authority executable, and
classified protocol surfaces and the normative matrix foundation, and added
the assurance harness and first value domains. The v0.7.0 candidate selects
`brynja-core 0.4.0`, eight dependency-only modern support patches at `0.1.3`,
and `brynja 0.7.0`.

Version 0.3.0 provides the exact source foundation:

- 103 locked RFCs and fifteen local NIST/ITU authorities map to lifecycle, domain,
  and roadmap ownership;
- RFC status and update/obsolescence relationships are closed or explicitly
  excluded;
- eight exact IANA XML snapshots preserve registry state;
- all 290 official errata have fail-closed reviewed dispositions; and
- ordinary checks reproduce the ledger offline while the release gate rejects
  live official-source drift.

Version 0.3.1 adds explicit protocol-surface decisions:

- 126 semantic decisions cover current and compatibility TLS, DTLS, QUIC-TLS,
  PKIX, OCSP, CT, HPKE, ECH, cryptographic algorithms, certificate and key
  formats, legacy protocols, and operational facilities;
- all 192 nested registries and all 4,106 individual records across the eight
  pinned IANA collections receive a deterministic disposition;
- every one of the 4,424 total surfaces records normative sources, owning
  milestone, planned code target, planned test target, and rationale;
- required exclusions explicitly cover Heartbeat, status_request_v2,
  production SSLKEYLOGFILE, TLS 1.3 post-handshake authentication,
  certificate-with-external-PSK, legacy PKCS1 client signatures, ML-KEM PKIX
  credentials, HPKE non-base modes, and unsigned X.509 certificates;
- QUIC version-specific cryptography and certificate compression remain
  explicit bounded future work, while unknown extensions are safely ignored
  only where protocol rules permit; and
- 25 positive and broken-fixture tests reject source-ledger drift, registry
  omissions, duplicate or unknown decisions, invalid owners or targets,
  overlapping rules, unmatched overrides, stale output, and premature
  implementation claims.

Version 0.3.2 added the normative-requirement foundation:

- 12 stable pilot requirements bind exact source-ledger and surface-register
  hashes, source sections and anchors, status, errata, strength, applicability,
  decisions, owners, residual risk, targets, tests, and evidence;
- all eight lifecycle states are represented: planned, implemented, tested,
  evidenced, rejected, caller-owned, legacy, and blocked;
- deterministic schema, matrix, coverage, and bidirectional source, decision,
  owner, target, test, and evidence indexes are reproduced byte for byte;
- implementation, test, and evidence claims require existing file anchors,
  while protocol requirements are forbidden from making premature
  implementation claims; and
- 51 positive and broken-fixture tests reject source or registry drift,
  malformed or duplicate identifiers, invalid sections, obsolete-as-current
  authority, illegal transitions, missing ownership and targets, premature
  evidence, weakened SHOULD decisions, symlink target escapes, released-ID
  removal, stale revisions, unrelated decision links, protocol use of global
  mappings, released-scope changes, lifecycle/disposition conflict, and stale
  generated output.

Version 0.3.3 completes the cryptography, encoding, and PKIX population pass:

- 34 new domain requirements bring the matrix to 46 stable records;
- all 53 exact authorities in the symmetric, public-key, key-container, PKIX,
  OCSP, and CT domains are cited with current, compatibility, evidence, or
  exclusion roles;
- all 3,322 cryptography, PKIX, PKI, OCSP, and CT surfaces map to a requirement
  or one of two explicit v0.3.5 ML-KEM deferrals;
- every uppercase normative RFC section is hash-bound with occurrence counts,
  and every domain rule records assurance invariants, a work bound, positive
  and negative target tests, an evidence gap, and residual risk;
- FIPS 202 and the in-force ITU-T X.690 (2021) plus Erratum 1 are pinned as
  local-only authorities, while SHA-3/SHAKE, GHASH, and ChaCha20 receive
  explicit semantic decisions; and
- fifteen domain fixtures fail on authority, binding, coverage, lifecycle,
  ownership, test-polarity, invariant, work-bound, or reproducibility defects.

Version 0.3.4 completes the TLS, DTLS, and QUIC-TLS population pass:

- 64 semantic surfaces give every planned transport implementation milestone
  one stable owner, code target, test target, source set, and rationale;
- 71 new requirements bring the matrix to 117 stable records and cover all 40
  admitted transport authorities, 550 normative RFC sections, and 485
  selected transport surfaces;
- all 914 domain and transport normative RFC sections carry reviewed
  decisions: 909 exact mappings and five explicit dispositions with unique
  extraction anchors and section hashes;
- source roles distinguish current, compatibility, evidence, exclusion, and
  caller-owned authority, including explicit Heartbeat, legacy signature,
  post-handshake-authentication, certificate-with-external-PSK, and QUIC
  transport boundaries;
- TLS, TLS 1.2, TLS 1.3, QUIC, and DTLS state and ownership mappings are
  version-separated and include work bounds, positive and negative tests,
  unresolved evidence, and residual risk;
- RFC 9850 key logging and four optional TLS facility groups remain explicit
  v0.3.5 deferrals, while status_request_v2 remains bound to the completed
  v0.3.3 OCSP review; and
- eight transport and nine section-binding fixtures reject missing owners,
  binding drift, role swaps, duplicate identities, omitted authorities,
  unmapped or non-normative sections, source/requirement mismatch, incomplete
  semantic revisions, unreviewed exclusions, and nondeterministic output.

Version 0.3.5 completes the optional, legacy, operational, and residual pass:

- 50 new requirements bring the matrix to 167 stable records;
- final FIPS 203, SP 800-227, SP 800-90B, and SP 800-90C are added as
  local-only checksum-pinned authorities;
- 33 residual authorities and 182 normative RFC sections are reviewed through
  165 exact mappings and 17 explicit dispositions;
- all 743 surfaces left by the foundation, domain, and transport bundles are
  assigned, producing complete coverage of all 4,424 surfaces;
- the generated closure maps all 126 locked sources, all 206 roadmap rows, all
  4,424 surfaces, and all 167 requirements in both directions;
- local redistribution boundaries, all eight mutable registries, five mutable
  NIST publication pages, source-free plan rows, and dependent refresh owners
  are explicit; and
- twenty-two residual fixtures reject draft claims, missing or duplicate
  groups, unlinked or boundary-mixed surfaces, non-representative source,
  target, owner or disposition drift, blanket section coverage, orphaned
  sources or plans, stale mutable guidance, source-rights gaps, missing
  exclusions, actionable source-blocked legacy requirements, and weakened
  hybrid, legacy, or FIPS blockers;
- domain, transport, and residual section decisions are globally reconciled,
  with delegated sections accepted only when another bundle records an exact
  owner;
- the DTLS RRC state, extension, ContentType 27, and message registry are fixed
  at v0.111.1, while stream TLS must reject RRC admission;
- RFC 6066 is split among exact TLS 1.2, TLS 1.3, SNI, status, alert,
  terminology, bounded peer ClientHello ignore, and configuration-rejection
  decisions instead of being mapped wholesale to OCSP; and
- RFC 7568 section 3 is authority only for the SSLv3 prohibition boundary.

Version 0.4.0 establishes assurance infrastructure without protocol code:

- bounded first-party mutation covers empty, original, truncation, deletion,
  bit-flip, and zero/`0xff` insertion cases in deterministic replay order;
- differential adapters consume bounded public test bytes over raw standard
  input and return canonical JSON, with fail-closed crash, timeout, output,
  class, encoding, and mismatch handling;
- seed and corpus files use descriptor-bound, no-follow, limit-plus-one reads,
  corpus enumeration is case-bounded, and differential and generated mutation
  execution hold only one case at a time;
- process execution never invokes a shell; Windows uses suspended-start
  kill-on-close Job Objects, while POSIX process-group cleanup is explicitly
  cooperative and hostile execution fails closed without a declared external
  cgroup, PID-namespace, container/VM, or fork-and-setsid-denial boundary;
  campaign launchers retain an explicit duty to supply and evidence OS network,
  filesystem, process, and device isolation;
- CI and the local release gate compile the complete all-feature workspace for
  `thumbv7em-none-eabi`, `riscv32imac-unknown-none-elf`, and
  `x86_64-unknown-none`;
- exact source pins cover Kani 0.67.0, AFL++ 5.02c, honggfuzz 2.6, and the
  separately pinned Miri/sanitizer nightly without adding a Cargo dependency;
- stable Rust 1.97.1 remains the release compiler while Kani 0.67.0 uses the
  documented compatible Rust 1.90.0 verifier pairing; no Kani proof harness is
  admitted or claimed at this milestone; and
- deterministic assurance evidence binds policy, runners, CI, and every Cargo
  manifest, with 43 positive and broken fixtures, including detached-descendant
  limitation, native-host CI, Windows startup constant, bounded input,
  streaming corpus, and exact local/remote probe timeout checks.

Version 0.5.0 implements the first shared protocol value domains:

- all 256 TLS AlertDescription bytes classify as assigned, reserved, or
  unassigned without lossy coercion;
- assigned alerts carry a concrete TLS 1.2, TLS 1.3, DTLS 1.2, or DTLS 1.3
  identity and fail closed on version-specific misuse;
- orderly close and explicit cancellation are distinct from alert failures;
- local, provider, and resource-exhaustion failures carry only closed enums,
  with no strings, byte payloads, provider-native codes, or numeric limits;
- failure envelopes implement neither `Debug` nor `Display`, and compile-fail
  tests prevent accidental formatting or secret-payload constructors; and
- `BRY-REQ-TLS-0005` and the alert registry surface now point to actual code
  and tests through immutable `implemented` and `tested` revisions.

Version 0.6.0 adds bounded numeric and resource foundations:

- `BoundedU64<MAX>` and `BoundedUsize<MAX>` use private fields, fallible
  construction, and checked addition, subtraction, and multiplication;
- `Count<MAX>` and `Length<MAX>` remain different Rust types, while `u64` to
  `usize` conversion fails closed when the target pointer width is too small;
- protocol-neutral `SequenceNumber<MAX>` and `Epoch<MAX>` advance without
  wraparound and return typed exhaustion at their inclusive maxima;
- `ResourceBudget` names seven resource dimensions through a fail-closed
  builder that requires exactly one assignment per limit and returns typed
  duplicate or incomplete-domain errors, while `WorkBudget` carries an
  explicit `u64` work-unit limit;
- budget checks do not mutate either operand and return the existing typed
  `ResourceExhaustion` without embedding numeric limits;
- small-domain arithmetic and advance matrices are exhaustively checked, with
  additional boundary, representation, zero-budget, and compile-fail tests;
- the reviewed 2026-07-31 IANA DNS snapshot adds three registries and
  seventeen entries, all explicitly caller-owned by v0.140.0, bringing the
  current register to 4,444 surfaces without admitting provisional draft text
  or advancing a protocol implementation claim; and
- no protocol surface or normative protocol requirement advances because
  these types are source-free shared foundations; later wire widths,
  direction-specific state, parsers, and engines remain future work.

Version 0.7.0 adds borrowed input consumption:

- `ReadCursor<'input>` stores only a caller-owned immutable byte-slice borrow
  and a private position, performs no allocation, and exposes no mutable input;
- dynamic, typed `Length<MAX>`, and fixed-array reads compute their end offset
  with checked arithmetic and use bounds-checked slice access without indexing;
- success advances by exactly the requested length, while overflow,
  truncation, and fixed-array conversion failure leave position and remaining
  input unchanged;
- explicit consuming `finish()` rejects every trailing suffix, while an
  exhaustive composite fixture rejects truncation at every byte boundary;
- the cursor is non-`Clone`, non-`Copy`, non-formattable, and `must_use`, and
  compile-fail tests bind those API constraints and the caller-input lifetime;
- `ReadError` carries only `Truncated`, `LengthOverflow`, or `TrailingData`,
  with no bytes, offsets, requested/available lengths, strings, or allocation;
  and
- no protocol surface or normative protocol requirement advances because this
  is a source-free cursor foundation; integer decoding, framing, parsers,
  writes, arenas, secret ownership, and state machines remain future work.

Everything beyond those foundation domains remains governance and planning
evidence, not protocol implementation.
Concrete ECDHE-ML-KEM groups remain blocked until both a final Standards Track
RFC and final IANA values exist. Non-RFC legacy requirements carry
machine-checked blocked lifecycles and exact blocker targets until source
provenance and rights are authenticated. FIPS validation
milestones remain blocked on a dated rights-reviewed mutable guidance baseline.

No `brynja-sanitization` package or dependency exists yet; its admission
decision remains gated at v0.11.1.

The v0.3.2 repository-owner pentest cycle reported no remaining vulnerability
and one optional defense-in-depth improvement. Target validation now resolves
paths and rejects symlinks that escape the repository root. The subsequent
retest found two medium release-assurance defects: lifecycle transitions and
revisions were not bound to immutable history, and decision links could be
structurally valid but semantically unrelated. Both are remediated locally with
immutable parent-matrix comparison, append-only identifiers, exact revision
rules, explicit mapping scopes, source/disposition/owner consistency, and 16
dedicated history and semantic-link tests. A later retest found one remaining
medium bypass: protocol rows could select reviewed-global and avoid
exact-source checks. Reviewed-global is now governance-only, released scope is
immutable, and the two affected RFC-wide protocol pilot rows now use exact
IANA sources at revision three. Ordinary CI now accepts only the exact current,
committed `RETEST REQUIRED`/`PENDING` remediation state so hosted checks can
run truthfully before retest, while all release and tag paths require
`PASS`/`PASS`. The final repository-owner retest passed with zero open
findings.

The repository owner pentested the signed v0.3.3 implementation candidate and
reported a green result with no findings. Its permanent report records `PASS`,
zero open findings, and `PASS` retest status.

The repository owner pentested signed v0.3.4 candidate
`42869b4b85087bac647c11a08064189878346112` and reported two Medium
governance-integrity findings. Both were remediated in signed commit
`091c6c29dbf4613646564f3d13b9e40ecc5d40ed`: every linked surface now has an
independent authority and owner check or an exact structured exception, and
every normative RFC section now has an exact requirement binding or reviewed
disposition. The repository-owner retest was green with zero open findings.
The permanent v0.3.4 report is `PASS`/`PASS`, and signed tag `v0.3.4` is
published. Four v0.3.5 assessment rounds reported ten Medium
governance-integrity findings, all of which were remediated. The repository
owner retested signed commit
`0d1203bd1c2640e40edb31d7ff18bf20833140a2` and reported it green with no
remaining finding. The permanent v0.3.5 report records `PASS`/`PASS` with zero
open findings, and signed tag `v0.3.5` is published.

The v0.4.0 assessment cycle reported one Medium governance-integrity finding,
one accepted Low architectural risk, one Low tooling-availability finding,
and four Medium resource, containment, and Windows-availability findings.
Bounded subprocess probes, descriptor-bound input allocation, streaming
corpora, cooperative POSIX limitation disclosure, fail-closed hostile POSIX
containment contracts, Windows Job Object startup, native-host CI, and
independent-review/FIPS disclosures address the complete assessment. The
repository owner retested signed commit
`62ad878cf2e536fec43cab99d42c6943cab905d5` and reported it green with no
remaining finding. The permanent v0.4.0 report records `PASS`/`PASS` with zero
open findings, and signed tag `v0.4.0` is published. The repository owner
pentested signed v0.5.0 implementation candidate
`20305afe423d8a6142abe15bd0357546b3f8d41c` and reported it green with no
findings. Its permanent report records `PASS`/`PASS` with zero open findings.
The hosted checks passed after one documented assurance-test timing correction,
and signed tag `v0.5.0` is published. The v0.6.0 assessment found one Medium
positional-budget-construction footgun and one Low diagnostic-ergonomics gap.
Named fail-closed budget construction, a workspace-wide overlong-argument
lint, safe `NumericError` debugging, and regression tests remediate both
findings. A follow-up assessment found that repeated named setters still used
last-write-wins behavior. Every setter is now single-assignment and returns a
typed `Duplicate(domain)` error; `build()` returns typed `Incomplete(domain)`
errors. Exhaustive tests cover duplicate and missing assignment for all seven
domains. The repository owner retested signed candidate
`89d4d7a930c89e2b6788554941389ca0d83cf999` and reported it green with no
remaining finding. The permanent report records `PASS`/`PASS` and zero open
findings. Signed tag `v0.6.0` and the intended ten-crate publication are
complete. The v0.7.0 assessment of signed implementation candidate
`784bfce7ae3c68f6ad9fee0e69058bee3c2a678a` found no exploitable cursor
defect and one Low defense-in-depth observation about an implicit internal
position invariant. Debug-build assertions now make that invariant explicit.
The assessment also retained the fail-closed fixed-array conversion branch and
required parser-level adversarial fuzzing when the first concrete framed
parser is implemented. Hosted macOS CI exposed and the remediation corrected
a timing-racy detached-descendant assurance fixture. The repository owner
retested signed remediation candidate
`13adb4b4d5d5eca97b40381fc41533ba5723e69b` and reported it green with no
remaining finding. The permanent report records `PASS`/`PASS` and zero open
findings; release now awaits the final committed candidate and green GitHub
checks.
