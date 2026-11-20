# v0.27.7 fault-model reviews: dispositions

Status: unfinished research archived under
[`research/aes-fault-integrity`](../../research/aes-fault-integrity/README.md).
The bounded scope was accepted by the owner on 2026-11-13; it was not qualified.
No usable fault-integrity API or configuration is qualified. Earlier statements
about pending owner acceptance below describe their respective review revisions.
This records owner-supplied design feedback, not a completed implementation pentest.
See the [revised model](aes-fault-profile-design.md). No existing AES API, release
gate, dependency or recorded verification result changes in these revisions.
The sections through "First-revision design validation" preserve the first
review's disposition; subsequent reviews and follow-up tests are recorded below.

## High findings

1. **Safe-error/SIFA: accepted design defect, residual now explicit.** The first
   draft confused correct-output integrity with confidentiality under faults.
   Alarm/success is a potential oracle. Global key retirement and trusted rotation
   after a fault are application obligations; owner recreation is not recovery.
   Ineffective injections are a separately reported leakage category. They may
   allow repeated queries before any retirement, so even "one query per owner"
   is too strong. No universal key-recovery query count, generic masking cure or
   infective-computation cure is claimed. This remains unresolved confidentiality
   risk, not a technical fix or automatically accepted deployment policy.
2. **D3 emitted capture: accepted.** Require independent opaque reads into separate
   borrows, with independent encoding and final-linked checks. Existing core copy
   assembly is available on x86_64/little-endian AArch64, but those configurations
   are not thereby qualified. Other fallback architectures/models cannot satisfy
   the profile admission claim without new reviewed primitives and evidence.
3. **Release-decision encoding/compiler merging: accepted with correction.**
   Neither a one-bit Choice nor duplicate inline ct_eq calls establish fault
   resistance. Require independently accumulated full comparisons, opaque core
   boundaries, wide encoded authorization, emitted checks and instruction-level
   tests. Do NOT use XOR-folded differences: cancellation can hide mismatches.
   Expanding a corrupted bool to 128 bits also preserves the single failure point.
   Exact codewords, construction and consumption remain review obligations.
4. **Source tests versus shipped artifact: accepted.** Use a non-Cargo evidence
   cfg for data-injection models, not a selectable production feature. A custom
   cfg is still under downstream builder control and is not an access-control
   mechanism. Require validated instruction-level simulation of the unchanged,
   hashed release-profile artifact for C1/DC1/L1 and S1. Instrumented or patched
   copies cannot replace this evidence. Simulator availability is a real open
   prerequisite, not grounds to mark a Rust-hook test as binary qualification.

## Medium findings

5. **Output readback: adopted with explicit assumptions.** Both paths need opaque
   destination reloads and independent validations before return. Secret output
   stays guarded; public writes require rollback on error/unwind. The old public
   destination may actually contain a secret, so its snapshot must be cleared,
   not classified public merely by the new ciphertext API. Safe exclusive borrows
   establish API-level visibility, not physical/DMA invisibility. Post-readback
   faults and failed rollback/cleanup remain explicit exclusions.
6. **Local skips: included as S1 with a narrower argument.** A skip confined to
   one domain must detect incorrect output or report an ineffective injection.
   A skipped bijection can have a fixed point; not every skip changes the output.
   Arbitrary cross-domain/address/control-flow skips remain excluded unless
   explicitly enumerated in C1/DC1.
7. **Analytic basis: adopted without overgeneralization.** A changed state followed
   by an unchanged bijective suffix cannot converge to the correct state. This
   covers isolated state/round-key-application sites, not every raw-key, expansion,
   persistent/repeated operand or skip fault. Such faults can change multiple
   future transformations; they require separate reasoning and integrity checks.
   All post-use schedule checks are explicitly before destination writes.
8. **Storage separation/encoding: adopted, not physical isolation.** Separate
   borrows and complemented/bit-plane replicas are required design elements.
   Complement coding detects common-zero controls, but a common XOR mask can
   preserve the encoded relation while corrupting both logical values. Adjacent
   buffers, bus faults, Rowhammer and simultaneous clearing remain common-mode
   concerns; the design does not claim universal burst-fault protection.
9. **Encoded lifecycle: adopted.** Require wide valid codewords, invalid-state
   rejection and &mut operations in new owners. Test every modeled bit/byte
   corruption, not just ordinary error transitions. Codeword distance does not
   protect against a whole valid-state overwrite or a skipped validation branch.

## Accuracy points

- Name `hazmat-aes-block`; enabling the proposed profile also exposes unchecked
  owners. Feature opt-in does not enforce exclusive checked use by an application.
- Bind emitted-code admission to exact target-cpu/target-feature settings as well
  as compiler, target, optimization, panic and LTO settings.
- DC1 is mandatory for completion and currently unimplemented/unqualified.
- Inverse checking with the same AES key independently captured/expanded in the
  other domain is a legitimate alternative but is not the selected same-direction
  design; its different input properties need review.
- Secondary expansion must use its own substitution implementation. Shared
  Scratch, secret owners, clearing, opaque copy/comparison/readback primitives,
  compiler and physical execution environment are explicitly inventoried.
- Payload numbers remain lower bounds, not final public storage sizes. Add
  codewords, integrity representation, readback and rollback scratch before
  publishing the final API's memory and performance costs.

## First-revision design validation, not implementation evidence

The first revision of `scripts/aes/test-aes-fault-model.py` exercised eleven public-data toy
examples: the conditional permutation lemma, ineffective skips, correlated
round-key cancellation, alarm equality leakage, repeated ineffective queries,
shared-load replication, XOR-fold cancellation, one-bit-to-wide propagation,
complement/common-mode limits, single-byte codeword separation and whole-codeword
substitution. They test the reasoning and counterexamples, NOT AES execution,
SIFA mitigation, machine-code behavior or physical resistance. They are not
registered as a passing fault-profile campaign.

The revised model still needs owner/reviewer acceptance of its confidentiality
limits and exact core/binary boundary design before production implementation.
No claim from the original review is silently reclassified as a completed fix.

## Second review: precise protection boundary

The reviewer accepts the first-round corrections and reports no integrity-design
regressions. The following are design refinements, not production fixes or
qualification evidence:

1. **Faulty-output versus outcome channels: adopted.** Within the bounded model,
   withholding incorrect blocks removes the faulty-output channel needed by DFA
   and modeled round-reduction output attacks. That specific confidentiality
   benefit does not eliminate safe-error/SIFA, failure-stage timing, filtered
   correct-output leakage, passive attacks or out-of-model faults. No universal
   "two faulty ciphertexts" recovery bound is needed or claimed.
2. **Mutation families: adopted with a necessary qualification.** Name nonzero
   XOR, constant replacement, AND/OR/stuck-at, arbitrary byte functions and skips.
   XOR changes the targeted byte for every value, but only the unchanged
   bijective-suffix premise guarantees that it changes the final output. Internal
   circuit faults can be suppressed in a value-dependent way: even bit flips can
   participate in SIFA. The distinction is site-specific, not "XOR is safe".
3. **Global retirement: clarified, not dismissed.** Enforcing retirement across
   all uses at the first alarm stops later observations under that key. The
   ineffective prefix, selected correct outputs, timing and first alarm can
   still leak. There is no universal prefix length or geometric expectation
   under chosen faults. The suggested "128 rotations recover a byte" does not
   follow for independent new keys; same-key reimport is the dangerous case,
   and is not genuine rotation. Prior observations cannot be undone.
4. **Stage timing: explicitly retained as a residual.** A uniform error code and
   fixed-work byte comparisons do not hide different failure/cleanup/rollback
   paths. This draft does not promise fixed-duration failure processing or keep
   using compromised state merely to equalize runtime. Safe dummy work and
   single-exit processing would need their own design and binary evidence.
   Owner/reviewer scope acceptance must include this observation channel.
5. **Additional passive exposure: adopted.** Duplicated keys/schedules, scratch,
   longer residence and two correlated computation traces may worsen passive
   memory/power/EM exposure compared with ordinary AES. Complement encoding is
   recoverable key material, not masking. Rollback snapshots may retain old
   plaintext/secrets; they are not necessarily key-equivalent bytes.
6. **Plaintext echo: explicit negative control.** Correlated skips can leave both
   results equal to input and release plaintext despite agreement. This remains
   outside the budget and must be demonstrated as such, without reintroducing
   mathematically invalid rejection of legitimate AES fixed points.
7. **Persistent constants: original second-round disposition, superseded below.** Enumerate domain-local
   affine/round/field/circuit and encoding constants, including emitted operands,
   with independent pre/post-use validation and injected cases. Shared masks or
   expected values are explicit common-mode dependencies. A faulty constant need
   not change every result, so output agreement alone cannot retire every
   persistent mismatch. If independent validation cannot be established, the
   configuration remains unqualified; this is not a completed PFA defense.
8. **Readback pairing: strengthened.** Each independent readback path checks BOTH
   replicas using independent loads/decoding/accumulation, rather than assigning
   one replica to each path. Otherwise a corrupted primary copied to destination
   plus bypass of the secondary-only check could pass (D1+C1). A separate D4
   plus separate primary data corruption is two data faults, not DC1; retain it
   as an additional control, not an unnoticed model expansion.

The tentative name is now **AES fault-integrity profile**, feature
`aes-fault-integrity`; no published API has been renamed. The version plan,
expanded roadmap and schedule record agree on the name and bounded scope.
Milestone identity, prerequisites and order are unchanged. Explicit pre-code
owner/reviewer acceptance of the confidentiality boundary is an exit obligation,
not a new general release gate. Opening rustdoc for every proposed owner must
state the boundary. The vague reference to an earlier timing deferral is removed;
earlier acceptance is not approval of this profile's residuals.

## Second-revision design validation

The second revision had 19 tests, adding eight cases: nonzero XOR under the intact
suffix premise; value-dependent suppression of internal XOR faults; biased
AND/OR survivors; retirement transcript truncation and changed-key relations;
same-error/different-stage work; persistent constant faults with correct-output
subsets; correlated plaintext echo; and readback pairings with every single-byte
nonzero XOR corruption and either check bypassed. These remain reasoning checks,
NOT independent compiled checks, AES correctness or physical/SIFA qualification.

The roadmap regression checker also rejects removal of the explicit acceptance,
outcome-leakage, global-retirement, readback-pairing and constant-site obligations.
No cryptographic source, existing verification evidence or publication workflow
was changed. Production implementation still awaits the scope acceptance and
concrete core/binary-boundary design identified in the review questions.

Validation of this revision: all 19 toy tests, the complete release-plan
regression suite (including 70 AES acceptance cases), 14 normative-requirement
core tests, reproducibility of all 175 requirements, repository Markdown link
checks and diff whitespace checks passed. These counts describe tooling/design
validation only; no new production AES campaign was run or claimed.

## Third review: constants and operational guidance

The reviewer identifies a real defect in the second revision's design obligation,
not a repeat of an already accepted residual. The mandatory runtime attestation
of every constant, including emitted immediates, is withdrawn for v0.27.7 in favor
of option (b), bounded output integrity:

- A domain-local constant fault must not cause an incorrect block to escape the
  intact independent validation path, including DC1 with one check bypassed.
  It may persist through calls whose results are correct. Those filtered outputs
  and the duration until detection belong to the unresolved outcome-leakage
  residual. Per-use constant attestation is no longer required or claimed.
- Independently checking literals in source does not attest the instruction
  operand actually used. Runtime code inspection or encoded data constants with
  opaque loads would require a separate design; they are not secretly added as
  implementation prerequisites. The prior draft mixed an additional early-
  retirement goal into output integrity without a viable mechanism.
- Persistent retained-key/schedule checks, retirement on every detected mismatch,
  domain independence, mapped constant-site evidence and shared-constant negative
  controls remain required. A constant used by validation or both domains must
  not be smuggled into the single-computation-domain argument.
- Application/rustdoc guidance now covers remote observers: uniform peer-visible
  failure responses, protected logs, no alarm retry, and the information exposed
  by later terminal failures. Uniform responses do not hide availability, timing
  or selected successes. Global retirement requires application enforcement;
  the crate's terminal state alone stops only one owner.
- Failure-stage timing is qualified: the known site of a chosen transient fault
  may already predict the detecting stage, but effectiveness and detection stage
  for latent/persistent faults can depend on input/key. No universal additional
  leakage amount or fixed-time failure claim is made.
- The XOR row is reworded without an ambiguous "only"; status text uses the
  fault-integrity name. Negative controls now include correlated decryption
  skips returning unchanged ciphertext as purported secret plaintext, as well
  as encryption skips releasing plaintext. Neither justifies echo rejection.

The roadmap and its regression checker preserve the corrected constant policy
and remote-error guidance. The scope still requires owner acceptance; this
review and its disposition do not grant that acceptance or qualify an artifact.

The toy suite adds three cases: a persistent constant fault surviving correct-
output calls until a mismatching call retires the owner with no later dispatch;
uniform error mapping that still exposes terminal availability; and the decrypt
echo control. The prior constant test now checks all byte inputs with either
domain faulty and either validation path bypassed, allowing only correct values
while explicitly retaining the biased survivor set. These are logical models,
not AES fault-injection or independent machine-code validation.

Third-revision validation passed: all 22 toy tests; the complete release-plan
regression suite, including 73 AES acceptance cases; 14 normative-requirement
core tests; reproducibility of all 175 requirements; Markdown link checks; and
tracked/new-file whitespace checks. No production cryptographic code was changed.

## Owner acceptance and first implementation slice

After the third review disposition the owner explicitly instructed:
"Please do so lets accept it and move into implementation."
This accepts the bounded integrity scope, domain-local constant option (b),
outcome/stage-timing and passive-exposure residuals, and application-enforced
global retirement. It is not artifact qualification or approval to omit the
remaining codeword, capture, DC1 and exact-binary requirements.

Implementation originally began with a private `cfg(test)` workbench. That
workbench is now archived under `research/aes-fault-integrity/crypto/fault_integrity/`
and requires an explicit research-only cfg. It has no public feature,
constructor, fallback or production routing. Its initial bit-plane substitution
uses algebraic-normal-form Boolean polynomials instead of the primary AES
field-exponentiation implementation. It calls no primary AES arithmetic helpers.
The coefficient arrays are generated from the frozen FIPS 197 Table 4 and its
inverse by a subset transform; a separate direct-subset-parity test reconstructs
them. Runtime evaluation visits every monomial in public order, never indexes
the substitution table using secret data, and uses clearing Scratch arrays.
Shared core clearing, compiler behavior and scalar spill/register residuals
remain in the common-mode inventory.

Four initial Rust tests cover coefficient provenance, exact lane representation,
all byte values in all 16 lanes with distinct neighbors in both directions, and
replicated-byte answers plus round trips. They do not qualify faults, timing,
independent captures or release control. No full secondary block cipher, key
expansion, user-facing fault owner or `brynja-verify` fault-profile pass is claimed.

First-slice validation passed:

- Four substitution tests on Rust 1.90.0 and pinned 1.99.1, plus optimized 1.99.1.
- Strict Clippy (`--lib --tests --features hazmat-aes-block --no-deps -- -D warnings`)
  on both toolchains.
- `cargo test -p brynja-crypto --features hazmat-aes-block,external-key-provider`:
  135 unit/integration/doctests passed; three existing opt-in OpenSSL differential
  tests were ignored as configured, not rerun or claimed by this slice.
- Twelve default-feature library tests, 22 toy fault-model tests, roadmap and
  requirements reproducibility checks, formatting, links and whitespace checks.

Next: implement and independently test secondary key expansion and block rounds
for all three widths and both directions, retaining this private workbench until
the independent capture/lifecycle/release machinery is ready. This partial
implementation adds no claim of constant-time, SIFA or physical-fault protection.

## Second implementation slice: independent complete block engine

The private workbench now implements key expansion and encryption/decryption
for AES-128/192/256. Expansion keeps an Nk-word cyclic history, substitutes using
the secondary Boolean polynomials and retains round keys in bit-plane form.
The linear layers operate on planes using lane permutations and XOR networks;
inverse column mixing uses an opposite-row correction before forward mixing.
No primary substitution, field multiplication, state-layout or key-expansion
helpers are called. Shared Scratch/Error/core clearing remain explicit.

This temporary workbench uses maximum-sized storage for 15 round keys; it is
not a finalized caller-storage ABI or a fault-checking owner. Re-expansion clears
old round-key storage and leaves unused rounds zero. Invalid widths and use of
an unexpanded schedule are rejected. No public feature or production route
enables the engine, and no new dependency is introduced.

Validation passed on Rust 1.90.0 and pinned 1.99.1, plus optimized 1.99.1:

- Ten workbench tests, including all 2,078 frozen NIST AESAVS KAT records
  (568/700/810 by width, both directions), each transformed twice with its
  retained schedule. These are KATs, not the full MMT/MCT campaigns.
- Complete frozen FIPS Appendix A schedules for all widths, independent
  polynomial-oracle checks for every single-byte value/position through both
  linear directions, and exact shift permutations for every single-byte input.
- Strict corpus parsing with explicit populations, key/block widths and
  sections, with missing/extra/malformed-record regression tests.
- Width rejection, unexpanded-schedule output preservation, and reuse from a
  larger key size to AES-128 with zero unused round-key storage.
- Strict Clippy on both toolchains. The ordinary portable/provider/HKDF
  unit/integration/doctest run passes 141 tests; three existing opt-in OpenSSL
  differential tests remain ignored as configured, not claimed as rerun evidence.

Next work is the bounded corruption harness and reviewed capture/lifecycle/
release machinery. These functional tests do not establish domain independence
in machine code, DC1, timing, fault resistance or safe public output release.

## Third implementation slice: source-data corruption campaign

The corruption harness requires BOTH `cfg(test)` and the explicit non-Cargo
`brynja_fault_evidence` cfg. No production hook or Cargo feature enables it.
It directly mutates the private test schedules, running the existing primary
and secondary engine methods unchanged. All keys, inputs and observed outputs
are public fixtures; the reference equality classifier is not a protected
release decision or quarantine owner.

The full experiment replaces every retained round-key storage byte with every
possible byte, independently for each engine, key width and direction. Primary
sites are contiguous round-key bytes; secondary sites are physical bit-plane
bytes spanning eight logical bytes, not mislabeled logical-byte substitutions.
One FIPS key/block pair is used for each width/direction. Baseline answers are
checked against frozen expected values, not just agreement between engines.

Exact population per compiler:

| Width | Trials | Changed-value mismatches | Unchanged-value correct agreements |
| --- | ---: | ---: | ---: |
| AES-128 | 180,224 | 179,520 | 704 |
| AES-192 | 212,992 | 212,160 | 832 |
| AES-256 | 245,760 | 244,800 | 960 |
| Total | 638,976 | 636,480 | 2,496 |

No wrong agreement occurred in this enumerated single-domain schedule campaign.
Unchanged replacements are ineffective controls, not successful detections.
Each trial's restoration starts an independent experiment; it is NOT proposed
application recovery by repairing a failed key. The separate persistence test
confirms first/middle/last-byte faults in both engines remain through two calls,
without silently healing. It does not implement or prove terminal retirement.

Small tests additionally exercise mutation families and invalid-site rejection,
single-input-replica divergence, and excluded common-mode wrong-input/wrong-key
controls. Those common-mode controls deliberately produce wrong agreements.
Logical input-copy tests do not qualify independent opaque D3 capture. Transient
internal computation, retained raw keys, persistent constants, skip/control-flow,
L1/C1/DC1, output-copy/rollback and exact-binary fault evidence remain unfinished.

Run the explicit experiment (not a release gate):

```sh
python3 scripts/aes/test-aes-fault-data.py
python3 scripts/aes/check-aes-fault-data.py --toolchain 1.99.1
python3 scripts/aes/check-aes-fault-data.py --toolchain 1.90.0
```

The runner uses a separate target directory per listed compiler, explicit evidence
cfg and optimized builds. It checks exact successful test names, populations and
the source-data summary, rejecting zero selected tests, missing/changed markers,
failures, timeouts and overriding flag/wrapper environment. The large Rust test
is ignored by default and refuses debug execution. A preliminary manual command
omitted the leading `aes::` from an exact selector and selected zero tests; it
is not evidence. The checked runner prevents that mistake from reporting success.

The checked optimized campaign passes on both Rust 1.90.0 and pinned 1.99.1,
with the exact population above on each compiler. Evidence-cfg strict Clippy
also passes on both toolchains. Eleven runner regressions and the existing
22 toy-model tests pass. These results
are local source-level observations, not an authenticated execution receipt,
current `brynja-verify` fault-profile pass, physical evidence or a timing claim.

## Fourth implementation slice: private lifecycle and rollback prototype

`aes/fault_integrity/transaction.rs` remains beneath the parent's `cfg(test)`.
It introduces no public owner, production route, Cargo feature, dependency or
core primitive. Computation callbacks are private test scaffolding, NOT a proposed
adapter or trusted production API. They stand in for computation AND the still
unfinished retained-key/schedule pre/post checks. Integration tests feed both
existing engines into this scaffold for all three widths and both directions.

Candidate lifecycle encodings are sixteen repeated bytes: Healthy `a5`,
InProgress `3c`, Terminal `c3`. Pairwise Hamming distances are 64, 64 and 128
bits, and every pair differs at every byte. Zero is invalid. Admission stores
InProgress before computation; unsuccessful completion, error and unwind leave
Terminal. Later calls do not invoke computation. Invalid encodings are rejected
and latched terminal. A final state re-check precedes restoring Healthy.
These source-level properties are not a proof against corrupted predicates,
condition flags, whole-codeword writes or instruction skips. In particular, the
ordinary completion boolean is NOT an implementation of qualified release
authorization. This candidate encoding does not settle the release-token design.

Public output uses a `Scratch`-owned snapshot, tentative write and readback;
error/unwind restores old bytes. Old bytes may be secret, so the snapshot clears
on either success or rollback through the existing `Scratch` Drop observer.
Secret output is admitted before fallible work, even before lifecycle rejection.
The existing finished clearing region is retained privately for readback and
only then wrapped in `SecretBlock`. No unverified region is returned to the
caller, and no new core readback accessor was necessary for this functional
prototype. Public release consumes `PublicCiphertext`; there is no public
decryption method. The clearing output can outlive the lifecycle object.

Each of two full source readback loops compares every byte against BOTH result
replicas. OR accumulation avoids cancellation; the second loop uses reverse
order and complemented operands. This does NOT prevent compiler CSE, load
forwarding, conversion to a shared comparator or conditional-branch bypass.
Both results are evaluated on a mismatch, but there is no whole-operation
constant failure-stage timing claim. Results are plain byte fixtures here;
independent secondary decoding paths are also still required. Lifecycle becomes
Healthy immediately before the infallible source-level final commit/return;
the instruction-level transition and final-return window remain unqualified.

Seven ordinary tests cover reusable success, error/disagreement, terminal
no-reentry, compute unwind, rollback/clearing after tentative writes, independent
output lifetime, malformed readback lengths and non-cancelling differences.
They also exercise real primary/secondary AES computation, without claiming
complete retained-schedule integrity checks. Six extra tests require the explicit
non-Cargo `brynja_fault_evidence` cfg:

- All 16,384 single-byte replacements across the three lifecycle codewords and
  zero state; none admits a non-Healthy encoding.
- All 4,096 replacements at the completion boundary; changed InProgress bytes
  cannot complete or revive the owner.
- 24,480 changed-byte checks across both readback loops and all three operands.
- 4,080 tentative-public-destination corruptions with rollback and retirement.
- 4,080 corrupt secret-copy cases that issue no output owner and clear storage.
- Explicit correlated echo controls for encryption AND decryption: equal bad
  replicas are accepted, demonstrating the common-mode exclusion, not hiding it
  through an invalid AES output-value heuristic.

These are direct source mutations/guard tests. They do not inject into the
shipping binary, core copy assembly, final return, rollback or release predicate;
they do not qualify D4, L1, C1 or DC1. No public API is admitted on this evidence.
Opaque independent capture/comparison, wide release authorization, full retained
storage checks, integrated fault sites and exact-binary qualification remain
unfinished. Global application-level key retirement and all accepted
confidentiality residuals remain unchanged.

Reproduce the 13-test private transaction suite with:

```sh
RUSTFLAGS='--cfg brynja_fault_evidence' cargo +1.90.0 test --locked -p brynja-crypto --lib --features hazmat-aes-block aes::fault_integrity::transaction
RUSTFLAGS='--cfg brynja_fault_evidence' cargo +1.99.1 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block aes::fault_integrity::transaction
```

Both commands pass all 13 tests. Strict evidence-cfg Clippy passes on both
compilers. The normal portable/provider/HKDF suite passes 148 tests, with the
three optional OpenSSL comparisons still ignored, and the no-default-feature
suite passes 31 tests including doctests. The 11 runner regressions, 22 toy-model
tests, formatting, roadmap, documentation-link and diff-integrity checks pass.
No production source path or dependency changed in this slice.

## Fifth implementation slice: retained-storage integration

The private `retained.rs` cached prototype now drives the transaction scaffold
with real primary and secondary AES computation, with these source-level checks:

- Two disjoint caller key borrows, one plain and one complemented; both clear on
  import error/unwind or Drop. Each engine expands from its own capture. The
  copies/decoding are ordinary Rust, NOT qualified independent opaque capture.
- Complete key comparison and binding of the retained key to the initial Nk
  schedule words. Complete primary-vs-decoded-secondary schedule comparison,
  including zero unused secondary rounds and the expected round-count metadata.
- Validation at import, before computation and after both computations but
  BEFORE returning to the transaction's first destination write. No repair or
  replacement of a mismatching replica. Cached computation does not re-expand.
- Terminal rejection before re-entering computation after an error or unwind;
  secret destination clearing and public destination preservation use the prior
  transaction guards. Key storage remains owned until Drop, with no reset API.
- A local marker keeps the private cached owner non-Send/non-Sync. This is not
  the final typed public API, caller-backed schedule ABI or operation-local owner.

The pre/post storage checks currently use a single full OR accumulator and a
shared normalization path. This is a functional integration, NOT the independent
encoded checks required for C1/DC1. Do not count two calls to this checker as
independent release authorization. Schedule metadata, capture, decoding, ordinary
predicates, linked-code boundaries and the final release window remain pending
qualification. Domain-local constant faults keep the accepted output-integrity/
outcome-leakage disposition; this does not claim to attest instruction immediates.

Three normal tests cover frozen FIPS answers for all widths and directions,
repeated cached operations, output outliving the key, clearing/canaries, invalid
input/storage widths, complement representation and unchanged schedules on use.
Five tests additionally require `brynja_fault_evidence`:

- 1,491 retained-storage sites across all widths: one changed byte at every key
  and schedule position, including unused secondary storage, plus round-count
  changes. Repeated validation rejects without repairing. Trial resets are only
  independent test setup, not permitted application recovery.
- 21 import scenarios covering selected corruption sites, explicit errors and
  unwind; both admitted key borrows clear.
- 189 operation scenarios across widths, public encryption/secret encryption/
  secret decryption and three checkpoints (pre-check, after primary, after both
  results). Every injected scenario is hit exactly once; faults detected after
  both results still retire before output release. All three entry paths reject
  subsequent calls without entering a checkpoint.
- Correlated replacement of both keys AND both schedules is a negative control:
  validation can accept the wrong key. This is outside the single-domain budget.
- Common-zero controls: wiping both plain/complemented key stores breaks their
  relation, but wiping BOTH schedules for a zero key can agree and release wrong
  output. Bit-plane layout alone does not protect against common-mode zeroing.
  This explicit excluded control must not become a claim of universal detection.

Only the mutation/error checkpoints require the non-Cargo evidence cfg, and the
entire integration remains behind `cfg(test)`. These hooks change the compiled
artifact and provide no instruction-level or physical evidence. No current-pass
record, public feature or release gate is added.

Reproduce the eight-test integration suite:

```sh
RUSTFLAGS='--cfg brynja_fault_evidence' cargo +1.90.0 test --locked -p brynja-crypto --lib --features hazmat-aes-block aes::fault_integrity::retained
RUSTFLAGS='--cfg brynja_fault_evidence' cargo +1.99.1 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block aes::fault_integrity::retained
```

The primary schedule adapter was factored out of the earlier source-corruption
harness without changing its engine calls. The checked 638,976-trial campaign
was rerun on both compilers with unchanged populations/results. The ordinary
portable/provider/HKDF suite passes 151 tests, with three optional OpenSSL
comparisons still ignored. No production crypto dependency or route changed.

## Sixth implementation slice: capture and readback boundaries

No new unsafe core primitive was needed for the capture step. Private
`capture::pair` now calls the existing `brynja_core::copy_secret_region` twice,
with the ORIGINAL caller source both times and distinct exclusive destination
borrows. It checks all three lengths before either write. Key import complements
the second destination only after that second capture; it no longer synthesizes
that replica from ordinary caller-byte loads. Input capture uses the same two
calls. Cleanup remains the caller guard's responsibility across partial capture
error/unwind. There is no promise of physically independent storage or resistance
to a fault in the shared caller source/pointer metadata.

Each invocation of the transaction readback checker now makes a fresh core copy
of the actual destination into its own clearing `Scratch<16>`. The subsequent
comparison still uses unqualified ordinary Rust. No previous source/register
copy is intentionally supplied as the second readback. Core uses opaque assembly
on x86-64 and little-endian AArch64 outside Miri/Kani; the portable fallback on
other targets and under those tools remains functional modeling, not D3 evidence.
Availability of the core assembly does NOT admit an AES fault-profile target.

Added tests cover:

- Capture lengths 0/1/7/8/9/15/16/17/24/31/32/33/48, sixteen offsets, exact bytes
  and neighboring canaries; inconsistent lengths reject before either write.
- Disjoint source and destinations in one allocation, using safe borrows.
- Every position in 16/24/32-byte captures: changing the first destination after
  its copy does not change the second, which still receives the caller's bytes.
- Partial capture error/unwind with clearing guards; nine failed key-import
  cases clear both admitted key borrows, and 27 input-capture failure cases
  retire the cached owner and preserve/clear destinations as appropriate.
- Later calls to a retired owner never enter the capture hook. A changed
  destination between two direct readback invocations is freshly observed.

All corruption/error seams require `brynja_fault_evidence`, while the entire
prototype remains `cfg(test)`. These are source checkpoints, not injections into
the core assembly or the final binary.

### Local linked-code observation, not qualification

An optimized, non-injection x86-64 Linux unit-test executable was inspected using
GNU `nm -C` and `objdump -Cd --no-show-raw-insn` after:

```sh
cargo +1.99.1 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block aes::fault_integrity::capture
```

Compiler: rustc 1.99.1 (`58cf8f9c35b355199727627d07ae34a4e2846d67`), LLVM 23.1.1,
host `x86_64-unknown-linux-gnu`, no custom RUSTFLAGS/evidence cfg. This is the
Cargo TEST artifact (including test-only Drop observers/unwind), NOT a shipping
release-profile artifact or clean tagged source receipt. The local executable
was `target/release/deps/brynja_crypto-9c929ddf55c3d466`, SHA-256
`3582a086c8aa8824577507fd44f0eb32c64822361758a8a36dc6c4c20793c6b8`.
It is a temporary build output, not an archived certification artifact.

Observed in that executable:

- `capture::pair` at `0xa8c00` retains two calls to `copy_secret_region` at
  `0xa8c27` and `0xa8c3c`. Both pass the original source pointer retained in
  `r14` as the source; the destinations are the separate caller arguments.
  The first result is checked before the second call.
- `transaction::validate` at `0xa82d0` calls `transaction::check` twice, at
  `0xa82e7` and `0xa8300`, preserving the destination argument across calls.
  `check` at `0xa8190` calls the core copy at `0xa81cb` into fresh local storage
  before reading/contrasting either replica.
- IMPORTANT NEGATIVE OBSERVATION: the reverse/complement flag no longer changes
  the check body. LLVM canonicalized both structures to the same vector XOR/OR
  reduction. The two calls return ordinary one-bit results combined with OR.
  Fresh reads survived, but the required distinct protected comparisons and
  wide independent authorization are NOT implemented. Do not present this as
  C1/DC1 success or rely on source loop order to prevent canonicalization.

For a new build, obtain the executable path printed by Cargo and inspect those
demangled functions with `nm -C PATH` and `objdump -Cd --no-show-raw-insn PATH`.
Re-record the digest, compiler, flags, pointer dataflow and checks; do not assume
these addresses or conclusions transfer. No AArch64 linked inspection was done
in this slice. Core's unchanged `secret_memory_transfer.rs` SHA-256 was
`85f0cef7c2a8508c4d594ad7462bccb92fd8e5bea7897164d7df3ee655dcf3e0`.

Functional validation passes on Rust 1.90.0 and optimized 1.99.1: five capture,
nine retained-integration and fourteen transaction tests with the evidence cfg.
Strict Clippy passes on both compilers. The normal portable/provider/HKDF suite
passes 154 tests, with three optional OpenSSL comparisons still ignored.
No public feature, production path, dependency, release gate or new unsafe code
was added. Next work remains independent opaque comparisons, encoded release
authorization and their exact-artifact fault qualification.

## Seventh implementation slice: opaque comparison workbench

The new `brynja_fault_primitives` cfg is explicitly separate from
`brynja_fault_evidence`. It exposes a hidden, UNSUPPORTED development module in
core, not a Cargo feature or released fault-integrity API. With this cfg, the
private AES transaction uses the candidate comparisons. Without it, the core
module is absent and the private transaction retains its ordinary Rust reference
comparison. Injection checkpoints remain separately controlled by the evidence
cfg, so non-injection candidate binaries can be inspected.

Core's `fault_comparison_workbench` contains two safe fixed-size entry points:

- `forward_16`: independently reads all sixteen bytes of the observation and
  both replicas in ascending order, accumulating two OR-of-XOR differences.
  Each result byte is zero exactly when its full comparison agrees.
- `reverse_16`: independently reloads all three inputs in descending order,
  accumulating two AND-of-XNOR masks. Each result byte is 0xff exactly when
  its full comparison agrees. It does not consume the forward result.

Both overwrite exactly two caller-owned bytes and return no Boolean. Results
stay in the transaction's clearing scratch, never an application report. These
two-byte accumulators are NOT wide release tokens; comparing them to their
expected values still yields an ordinary one-bit decision. No claim is made that
a fault in an accumulator, predicate, flags, latch or final branch is protected.
The exact wide authorization design remains a review obligation. This slice does
not silently implement a token by stretching one Choice into a larger integer.

### New unsafe inventory and boundary

Two private unsafe extern-C leaves, each with x86-64 and little-endian AArch64
assembly, live only in the core workbench. AES retains `forbid(unsafe_code)`.
Safe array borrows prove two writable output bytes, sixteen readable bytes for
each input and output/input disjointness; shared inputs may alias each other.
All loops are fixed public bounds; accesses are bytes at offsets 0..15 and
output offsets 0/1. Neither leaf calls another function or branches on content.
Early clobbers exclude every pointer register. Working secret registers and
condition flags are explicitly cleared on ordinary return. No guarantee covers
caller spills/registers, interruption, speculative/physical observation or
corrupted control flow. The x86 function prologue saves a callee-saved register;
the assembly region itself has no stack access. Do not turn that into a claim
that the complete caller or ABI uses no stack.

Other targets and Miri/Kani select safe portable models. The
`uses_opaque_candidate()` configuration indicator is NOT qualification. No target
admission or external/hardware-provider policy changes.

### Functional and code-generation observations

Four core tests cover all 65,536 byte pairs, every nonzero XOR pattern at every
position in all three operands, independent model agreement, mixed lanes,
aliasing immutable inputs, non-cancellation, unaligned slices, exact output
overwrites and neighboring canaries. They pass natively on x86-64 Rust 1.90.0
and 1.99.1, including optimized builds, and under AArch64 musl QEMU cortex-a53
on both compilers. The Cortex-M `thumbv7em-none-eabi` release build succeeds
through the portable model; this is compile-only. Two focused tests (unaligned
canaries and mixed/aliased inputs) pass Miri on nightly-2026-09-11 using the safe
model. Miri does NOT execute or validate these assembly leaves.

With BOTH cfgs enabled, the fourteen transaction tests pass on 1.90.0 and 1.99.1,
and the nine retained-integration tests pass on 1.99.1. The seven non-injection
transaction tests also pass in an optimized 1.99.1 primitive-enabled artifact.
Strict Clippy passes for the workbench and its AES integration on both compilers.
The ordinary core suite and 154-test portable/provider/HKDF suite still pass;
three opt-in OpenSSL comparisons remain ignored in the latter.

The optional checker `scripts/aes/check-aes-fault-comparison-codegen.py` observes
the two named leaves in a linked ELF. It checks architecture and distinct
symbols, the complete reviewed instruction sequences, operand dataflow, public
loop backedges, both output stores and working-register/flag clearing. It fails
on missing/duplicate leaves, changed operands/bounds, missing instructions or
unexpected calls. Nine checker regressions include deletion of EVERY selected
instruction, changed load sources/loop bounds/erase instructions, altered
backedges, alias/missing-symbol cases, legacy Rust symbol hashes and tool
failures/timeouts. The older ARM toolchain retains a 16-hex symbol hash; only
that exact suffix is normalized, with duplicate-leaf rejection preserved. These tests
mutate parser fixtures, NOT executable instructions: they are checker regression
tests, not C1/DC1 instruction-level fault simulation.

Observed normalized leaf sizes are 26/27 instructions for x86-64 forward/reverse
and 22/22 for AArch64. Unlike the prior source loops, these leaves remain
different implementations. Observations matched both compilers' core test
artifacts, and the x86-64 1.99.1 primitive-enabled crypto test artifact. The
checker does NOT validate caller control flow, independent decoding, release
tokens, final return, physical faults or timing. All artifacts are local tests,
not shipping binaries, qualified configurations or authenticated receipts.

Selected 1.99.1 local test-artifact SHA-256 values:

- x86-64 core: `55efaa577bf0612d1d53dc7e665dddbb2e030f9016e883e9c0c324e812fb92f4`.
- AArch64 core: `881a79b1a99a788bfaf6464a0c6b37ff372c3a499746b83fde66b99cfe832e80`.
- x86-64 crypto: `ae5b47dd2e9e31333248ee6de0e1dc4b39134bfe1d29d67d886618cae908cdef`.

Reproduce without injection hooks (substitute `+1.90.0` for the MSRV):

```sh
RUSTFLAGS='--cfg brynja_fault_primitives' cargo +1.99.1 test --locked --release -p brynja-core --lib fault_comparison_workbench
RUSTFLAGS='--cfg brynja_fault_primitives' cargo +1.99.1 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block aes::fault_integrity::transaction
python3 scripts/aes/test-aes-fault-comparison-codegen.py
```

Use the ELF path printed by Cargo with the optional checker:

```sh
python3 scripts/aes/check-aes-fault-comparison-codegen.py --arch x86_64 --binary PATH_TO_TEST_ELF
```

For emulated ARM functional execution:

```sh
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER='qemu-aarch64 -cpu cortex-a53' RUSTFLAGS='--cfg brynja_fault_primitives' cargo +1.99.1 test --locked --release -p brynja-core --lib --target aarch64-unknown-linux-musl fault_comparison_workbench
```

Inspect that ELF with `--arch aarch64 --objdump PATH_TO_LLVM_OBJDUMP`.
Add `--cfg brynja_fault_evidence` to RUSTFLAGS only for source-injection tests;
that changes the artifact and is not evidence about an uninstrumented caller.
No verification pass, release gate or dependency was added. The next required
work is reviewed wide authorization and integration, followed by exact-artifact
instruction-level fault evidence; v0.27.7 remains unfinished.

## Eighth implementation slice: reviewable receipt model

Added the private `authorization_model` under the existing test parent and
`brynja_fault_primitives` cfg. It uses the previous opaque comparison candidates
but does NOT replace transaction validation or expose a public release token.
The proposed representation and qualification obligations are in
[the candidate design](aes-fault-profile-design.md#candidate-receipt-model-not-an-approved-release-encoding).
This is a reference model for reviewing an encoding, not approval of an encoding.

Each path holds sixteen fresh, independently computed two-byte comparison lanes.
Forward and reverse success words are distinct and nonzero. No Boolean is expanded
into a word, and no lane is filled by copying a previous lane's result. For intact
generation with stable divergent operands, each path differs from success in at
least sixteen bytes/bits. The model retains ordinary Rust final predicates and
control flow, so it does not yet enforce that separation at machine level.

Nine tests cover:

- All 256 replicated equal-byte fixtures and exact path-specific receipts;
  exchanged paths, zero initialization and every incomplete byte prefix reject.
- Every operand (destination/primary/secondary), every position, every nonzero
  XOR mask: 12,240 divergent fixtures, with exact residual encodings and distance
  assertions for both paths. Mixed-lane equal differences cannot cancel.
- 24,480 divergent-fixture / single-whole-check-replacement combinations reject.
  The injection replaces a complete selected receipt with success, not merely
  an equality bit. This is a source-level model, NOT instruction-skip evidence.
- All 16,384 single-byte replacements of correct receipt storage: only unchanged
  bytes pass. All 393,216 byte-replacement attempts against the smallest-distance
  single-bit divergent fixtures leave both individual validators rejecting.
- Explicit negative controls: correlated bad data can agree; two whole-check
  replacements can succeed; changing destination AFTER capture leaves the old
  receipt valid. The latter is why receipts cannot be reusable authorizations.

The mutation tests additionally require the non-Cargo `brynja_fault_evidence`
cfg. Normal builds gain no API, feature, dependency or release gate. No unsafe
code was added in this slice. No timing experiment was rerun.

Reproduce the candidate's functional/mutation tests:

```sh
RUSTFLAGS='--cfg brynja_fault_primitives --cfg brynja_fault_evidence' cargo +1.99.1 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block aes::fault_integrity::authorization_model
RUSTFLAGS='--cfg brynja_fault_primitives --cfg brynja_fault_evidence' cargo +1.90.0 test --locked -p brynja-crypto --lib --features hazmat-aes-block aes::fault_integrity::authorization_model
```

These tests do not model arbitrary faults in receipt generation or final
predicates, nor establish fault-resilient memory allocation, physical separation,
constant integrity, operation binding or protected commit. C1/DC1/L1 instruction
simulation and the confidentiality residual remain unchanged. v0.27.7 is still
unfinished; this slice is not a reason to release the profile.

Validation for this slice:

- Nine candidate tests pass on x86-64: optimized Rust 1.99.1 and debug MSRV
  1.90.0; the same nine pass on AArch64 musl under QEMU cortex-a53 / 1.99.1.
  QEMU is functional evidence only, not native platform/fault qualification.
- The full normally enabled workbench selection passes 51 tests on optimized
  1.99.1. Its separately invoked exhaustive retained-schedule campaign remains
  explicitly ignored in this command, not counted as rerun coverage.
- Targeted Miri on nightly-2026-09-11 passes the incomplete-receipt and
  exchanged-receipt tests. Miri executes safe primitive models, not the assembly.
- Strict crypto Clippy with both development cfgs passes on 1.99.1 and 1.90.0.
- Ordinary AES/provider/HKDF tests and doctests pass (154); the three opt-in
  OpenSSL comparisons remain ignored, and no dependency on OpenSSL was added.
- Python model (22), data-runner (11) and leaf-checker (9) tests pass, as do
  the release-plan check, repository documentation-link check, formatting and
  diff-integrity checks.

## Ninth implementation slice: two-guard tentative copy experiment

Inspection of the previous optimized 1.99.1 reference `Candidate::consume`
confirmed that its two Rust check results end in one combined condition
(`not %bpl; or %bpl,%r15b; setne %bl`). That is consistent with the documented
limitation: source-level independent checks do not protect a final release branch.

The hidden, non-Cargo `brynja_fault_primitives` workbench now includes
`tentative_copy_16`. Its x86-64 leaf completes both full 32-byte receipt scans
before using two separate conditional branches to guard the actual sixteen-byte
copy. Forward uses OR of word differences; reverse uses AND of word agreements
with distinct expected constants and a reversed traversal. No external libc
comparator, shared decoded Boolean or call appears in that leaf. On ordinary
rejection the destination is untouched and its diagnostic report is zero.
Normal completion clears the working integer/vector registers and flags.

This adds a narrowly scoped unsafe x86-64 boundary in core, with a safe fixed-array
wrapper proving readable lengths and exclusive mutable output/report regions.
Unaligned accesses are supported; all loops have public fixed bounds and use
only baseline x86-64/SSE2 instructions. It does not provide fault-resilient memory
safety if pointers or loop bounds are themselves corrupted. The normal safe-call
contract must not be confused with a physical fault guarantee.

The report is NOT permission to return an AES result. The function accepts stale
or forged success receipts and can then copy arbitrary proposed data. It has no
lifecycle admission, independent secondary decoding, fresh data binding, readback,
rollback or final-return protection. It remains separate from the transaction and
cached owner. Non-x86 targets and Miri/Kani execute only a functional copy model;
there is no ARM guarded-copy assembly or native ARM claim in this slice.

### Finite native debugger observations

`scripts/aes/check-aes-fault-guard.py` checks an exact 31-instruction leaf, including
operands, backedges, rejection targets, stores and clearing. It then runs GDB
against a single-call public-fixture test in the same unmodified executable.
Breakpoints are explicitly hardware-assisted; mutations change the stopped
thread's PC, accumulator or condition flag, NOT code bytes. Both fixture receipts
are wrong by one bit before entry. All seven cases matched expectations on
optimized x86-64 core test artifacts built with Rust 1.99.1 and 1.90.0:

- Baseline: destination unchanged, zero report.
- Skip the first rejection branch: second guard still rejects.
- Flip ZF at the first rejection branch: second guard still rejects.
- Set the forward accumulator to zero before its test: second guard rejects.
- Skip the first accumulator test: the preceding public loop leaves ZF set;
  despite that bypass, the second guard rejects.
- Repair the reverse accumulator before the first guard: first guard rejects.
- Negative control, skip BOTH rejection branches: the proposed bytes are written
  and the fixture deliberately fails its unchanged-output assertion. The runner
  requires that exact forbidden output and exit status, not any crash/failure.

Because the first rejection prevents reaching the second branch, this is not an
independent single-second-branch experiment with both bad receipts. The two-skip
negative control confirms reachability of both only under two events. These are
seven finite leaf experiments, NOT exhaustive instruction/register fault coverage,
AES data-fault simulation, simulator qualification or completed C1/DC1 evidence.
Debug exceptions, scheduling and debugger semantics differ from physical faults.
Test artifacts also differ from the still-unimplemented final public profile.

Observed ELF SHA-256 identities:

- 1.99.1: `5d2319bf3bbfa95efec231e079669bb1dcb0bed8bb84e73c0fdf8e6c134cea34`.
- 1.90.0: `81e0e0314777d789bcf308b163ef99c2bc6ccf6d3f7b5049fb3bf46e6822bc05`.

The runner demands exact test populations, hardware-stop counts, known accumulator
pre-states, confirmation that each mutation took effect, expected fixture outcome
and unchanged executable bytes afterward. Unsupported debugger behavior, missing
symbols, changed instructions or timeout fails rather than becoming evidence.
It prints artifact/site/case metadata and transient transcript hashes; it is not
an authenticated receipt store and does not persist the raw debugger transcripts.

Reproduce on a trusted x86-64 checkout with GDB/ptrace access:

```sh
RUSTFLAGS='--cfg brynja_fault_primitives' cargo +1.99.1 test --locked --release -p brynja-core --lib fault_comparison_workbench::guarded_copy
python3 scripts/aes/check-aes-fault-guard.py --binary PATH_TO_CORE_TEST_ELF
python3 scripts/aes/test-aes-fault-guard.py
```

Use the actual executable path printed by Cargo, and repeat with `+1.90.0`.
These binaries have NO `brynja_fault_evidence` source-injection cfg. They DO have
`cfg(test)` and the primitive development cfg; do not call them shipping artifacts.
No release gate, timing rerun, dependency or production owner was added.

Functional/regression validation for this slice:

- Four new core tests pass on both x86-64 compiler builds, including all 16,384
  single-receipt-byte replacements against a safe reference, all 256 replicated
  data values, invalid/swapped receipts and sixteen unaligned positions/canaries.
- The AES receipt model now also feeds its tentative copy: 24,480 divergent-data
  plus one-whole-receipt-bypass combinations leave output unchanged. Its nine
  tests pass on both optimized compiler builds. The complete normal workbench
  selection passes 51 tests; the opt-in exhaustive schedule campaign was not
  rerun in that command.
- All eight core comparison/copy workbench tests pass on AArch64 musl/QEMU with
  1.99.1. The copy path there is the safe model, not the new x86 assembly.
  A no_std Cortex-M build passes. Targeted Miri passes the unaligned-copy test
  using the safe model, not assembly or debugger injection.
- Strict core and crypto Clippy pass on 1.99.1 and 1.90.0. Ordinary core tests
  and the 154 AES/provider/HKDF tests/doctests pass; the three OpenSSL opt-in
  comparisons remain ignored. The normal production configuration is unchanged.
- Five new runner regressions cover exact/legacy-hash symbol parsing, deletion
  of every leaf instruction, guard-operand changes, hardware-stop commands,
  missed/ineffective events, malformed outcomes and failed/timed-out tools.
  The existing Python model/data/comparison suites (22/11/9), release-plan and
  documentation-link checks, formatting and diff-integrity also pass.

## Tenth implementation slice: private guarded transaction integration

With `brynja_fault_primitives` selected, the private transaction now uses fresh
receipt construction and the experimental guarded tentative copy. This also
exercises the path through the cached workbench's existing lifecycle. The old
reference path remains selected when the development cfg is absent; the public
production API, feature set and dependencies are unchanged.

`authorization_model::copy_fresh` accepts only the destination and the two current
computed results. It constructs receipts, invokes the guard and drops the receipt
storage inside that call: callers cannot supply a previous receipt or select a
different proposed-data parameter. The diagnostic report may reject an operation,
but is never the only success check. Both fresh readbacks still compare the actual
tentative bytes with BOTH computed results. This is not physical anti-replay or
protection from faults after the last readback.

For public output, all work runs within the preexisting snapshot/rollback guard.
The owner must remain InProgress before and after the tentative-write/readback
helper and at completion. For secret output, the guarded copy targets a private
clearing staging block because existing initialization owners deliberately expose
no mutable destination accessor. The ordinary initialization write follows; the
finished owner remains private through two additional ACTUAL-destination checks.
Only then can a SecretBlock be constructed. A failure/unwind drops the private
owner and clears the admitted destination. This slice adds no unsafe code and
does not describe that ordinary initialization write as an opaque guarded commit.

The new non-Cargo `brynja_fault_evidence` checkpoints exercise the real private
transaction path, not an independently copied test implementation. They cover
before-copy, after-copy, between-readbacks, secret-only pre-initialization-write,
and lifecycle completion boundaries. Thread-local one-plan selection, exact hit
counts and RAII cleanup prevent silent missed sites or cross-test contamination.

Three new tests establish these bounded source-model outcomes:

- **114,240 mutation cases:** twelve shared stage/site combinations per path,
  four additional secret-only combinations, sixteen byte positions, all 255
  nonzero XOR masks. Sites are primary/secondary results, actual public output
  or private secret staging, and encoded lifecycle state. Every effective case
  rejects, restores the original public bytes or clears secret bytes, retires,
  and refuses later computation on both entry paths. The completion checkpoint
  mutates lifecycle state only, not data after the final readback.
- **18 error/unwind cases:** every applicable checkpoint on both paths, including
  after tentative writes and immediately before completion. Public rollback,
  secret clearing, terminal state and no reentry are verified after each.
- **32 ineffective overwrite controls:** changing the old public destination or
  secret staging before it is overwritten with correct output succeeds. These
  are explicitly ineffective events, not detections or confidentiality evidence.

The source test's first population assertion incorrectly counted the secret-only
checkpoint for both paths (130,560 rather than 114,240). Every mutation outcome
had passed; the count assertion failed on both compilers and QEMU. The assertion
now states the actual formula `(12*2 + 4) * 16 * 255`; no sites or checks were
removed to make it pass. The existing live Scratch-drop observer also checks that
cleared receipt/staging/snapshot storage contains zeros on ordinary cleanup.

The secret-only pre-write checkpoint corrupts a source payload that is subsequently
copied into the private destination and caught by actual-destination readback. It
does NOT inject an instruction or memory fault inside the core initialization
write. These tests likewise do not prove register clearing, instruction-skip
resistance, independent normalization, final-return integrity or C1/DC1/L1.
The guarded-copy leaf's earlier debugger observations do not automatically
qualify this new caller. That complete emitted-caller and fault-site work remains
unfinished, including ordinary Boolean completion/commit/readback decisions.

Reproduce the integrated source campaign on either compiler:

```sh
RUSTFLAGS='--cfg brynja_fault_primitives --cfg brynja_fault_evidence' cargo +1.99.1 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block aes::fault_integrity
RUSTFLAGS='--cfg brynja_fault_primitives --cfg brynja_fault_evidence' cargo +1.90.0 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block aes::fault_integrity
```

Both complete normally enabled workbench selections pass 54 tests; one separately
invoked exhaustive schedule test remains ignored, not counted as rerun coverage.
Targeted Miri on nightly-2026-09-11 passes all 18 boundary error/unwind cases using
the safe primitive models. No new timing experiment or release gate was added.

The 17 integrated transaction tests also pass under AArch64 musl/QEMU on 1.99.1
(opaque comparison leaves, functional guarded-copy model). The seven normal
transaction tests pass in a primitive-enabled build without source-injection
hooks. Strict crypto Clippy passes with both cfgs on 1.99.1/1.90.0, and with only
the primitive cfg on 1.99.1. The ordinary AES/provider/HKDF suite remains at 154
passing tests/doctests, with three opt-in OpenSSL comparisons ignored. Python
guard/comparison/model/data tests (5/9/22/11), release-plan/documentation-link
checks, formatting and diff integrity pass.

## Eleventh implementation slice: native transaction observations

This slice tests the optimized integrated public transaction without the
`brynja_fault_evidence` source hooks. It found a real gap in the private prototype:
LLVM could eliminate the later InProgress comparisons because normal Rust code
could not modify that state between checks. In the original 1.99.1 test ELF,
changing one state byte from `0x3c` to `0x3d` immediately after the tentative
output store still returned success and restored Healthy. The source-hook
campaign had passed, but its possible state writes changed the optimization
problem. It was not evidence that the uninstrumented checks survived.

The primitive-enabled path now snapshots state through the existing
`brynja_core::copy_secret_region` boundary into clearing Scratch at entry, before
and after guarded write/readback, and at completion. The ordinary reference path
remains unchanged without that cfg. Inspected optimized x86-64 callers retain
fresh opaque transfer calls and comparisons. Repeating the native state mutation
now rejects, restores the original public output, retires the owner and refuses
subsequent computation. This is a private workbench correction, not a released
production-AES defect or a new protected predicate. No unsafe code, dependency,
public feature or production fault owner was added.

`scripts/aes/check-aes-fault-transaction.py` runs a trusted local test ELF under
GDB. The `probe_tests::public_call` fixture invokes the existing transaction with
two public `0x42` result blocks; it does not replace the transaction implementation
or run AES rounds. Only the fixture wrapper is marked non-inline. The runner
requires source-injection cfg to be absent, validates the existing guarded-copy
leaf's exact instruction sequence, identifies unique caller/check symbols and
return sites, records their instruction hashes, and checks the live ABI/state
before mutations. This caller parsing is NOT an exhaustive instruction allowlist
or a complete emitted-code qualification of all callees.

Hardware breakpoints do not patch code bytes. Each run checks all sixteen bytes
of expected entry/copy state, exact breakpoint and event counts, the mutation's
actual effect, and a specific fixture outcome. The artifact bytes must remain
unchanged. The baseline MUST accept; injections expected to reject MUST verify
rollback, Terminal state and refusal of another call. Unexpected tool failure,
timeout, missed injection or a merely crashing negative control fails the runner.

The following nine finite cases give the expected outcomes on optimized x86-64
Rust 1.99.1 and 1.90.0:

| Native event | Required observation |
| --- | --- |
| No mutation | Accept correct output |
| One invalid entry-state byte | Reject, restore, retire |
| One state-byte flip after tentative store | Reject, restore, retire |
| One output-byte flip after tentative store | Reject, restore, retire |
| One primary-result-byte flip after tentative store | Reject, restore, retire |
| Output corruption plus first readback's error result forced to success | Second readback rejects, restores, retires |
| Output corruption plus second readback's error result forced to success | First readback rejects, restores, retires |
| Output corruption plus BOTH readback results forced to success | Wrong output escapes: required negative control |
| Output corruption at the fixture return, after final checks | Wrong output escapes: required negative control |

For bypass cases, GDB checks the failing `Result` ABI value at the actual `check`
return and flips its low result bit. This models those selected result-register
events, not every branch skip, flag corruption, comparison instruction, schedule
site, lifecycle transition or physical propagation mechanism. The two escaping
controls must produce the exact wrong-output assertion and test-failure exit;
they are not counted as detections. The ordinary Boolean combination of readback
results, rollback/commit flags and final return remain unqualified.

Artifact SHA-256 observations (local records, not authenticated receipts):

- Before state-reload correction, 1.99.1:
  `9e110d955b10ceaf530c99244a73824130b474a501a90cb03be2f8badcc6095c`.
- After correction, 1.99.1:
  `86eeb7a2c4ae5b8c9e7bf415efb2057a2cf0c515b0b9cb3f0dac7157c4d33b4d`.
- After correction, 1.90.0:
  `3a497ab766db9663f6273c6fff1a4ea79e91bb32a94af7ada9e2219b950b9553`.

The runner prints artifact/site metadata and per-case transcript hashes. It does
not retain full transcripts or establish a signed evidence chain. The old ELF is
not a shipped fixture; the enduring regression is the required rejection case
against the current build. Rebuild and select the executable printed by Cargo:

```sh
RUSTFLAGS='--cfg brynja_fault_primitives' cargo +1.99.1 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block native_public_transaction_probe
python3 scripts/aes/check-aes-fault-transaction.py --binary target/release/deps/brynja_crypto-0e319f9c26ea36b6
RUSTFLAGS='--cfg brynja_fault_primitives' cargo +1.90.0 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block native_public_transaction_probe
python3 scripts/aes/check-aes-fault-transaction.py --binary target/release/deps/brynja_crypto-9fa6fd47f68fcc2f
```

Executable names and bytes can change with source/build configuration. Do not
substitute the dual-cfg source-instrumented executable. These are release-profile
test ELFs, NOT a final shipping fault-integrity library/API. Complete C1/DC1/L1,
the actual secret-destination write, all owner call sites, and the full linked
release path remain unfinished; no physical-fault or confidentiality claim follows.

Regression checks for this slice:

- The full private selection passes 55 tests on each optimized compiler, with
  the separately invoked exhaustive schedule campaign still ignored. This
  includes the 114,240 source mutations and 18 error/unwind cases from the prior
  slice; the new native fixture adds one normally accepting test.
- All 18 transaction tests pass on AArch64 musl/QEMU with 1.99.1. This exercises
  opaque ARM comparisons/transfers but the guarded-copy functional model, not
  native ARM debugger injection or an opaque ARM final commit.
- Targeted Miri on nightly-2026-09-11 passes the boundary error/unwind test using
  safe primitive models. It does not execute inline assembly.
- Five new runner tests cover symbol/return ambiguity, exact checkpoint values,
  outcome/negative-control validation, hardware-only commands, source-cfg
  rejection and failing/timed-out tools. Existing guard/comparison/model/data
  suites pass 5/9/22/11 tests respectively.
- Strict crypto Clippy passes with both development cfgs on 1.99.1/1.90.0.
  The primitive-only 1.99.1 configuration also passes. The separate ordinary
  AES/provider/HKDF suite passes 154 tests/doctests; its three opt-in OpenSSL
  comparisons remain ignored. Release-plan/documentation-link checks,
  formatting and diff integrity pass.

No timing rerun or new mandatory release gate was introduced. The next work is
native coverage of the secret transaction and remaining caller decisions, not
promotion of these finite public-fixture results to completed qualification.

## Twelfth implementation slice: native secret transaction observations

The private native fixture now also returns the actual `SecretBlock` from
`Lifecycle::secret`. On ordinary success it verifies the borrowed output before
dropping the owner and checks clearing afterwards. On rejection it checks cleared
destination, Terminal state, and that a fresh admitted destination is cleared
without invoking another computation. No production implementation, public API,
core primitive or dependency changed in this slice.

The existing debugger runner accepts `--path secret` (public remains the default).
It distinguishes the first two readbacks of private staging from the subsequent
two checks of the ACTUAL admitted destination. At the latter boundary it verifies
destination identity/length, both independent result addresses/contents and
InProgress state before injecting. Thus the new data fault occurs after
`SecretRegionInitialization::write` has actually written caller storage, not in a
surrogate or a source checkpoint. This does not simulate the copy instruction's
own faults or cover every instruction in the secret path.

Eleven finite cases have matching observations on Rust 1.99.1 and 1.90.0 x86-64
optimized test ELFs without `brynja_fault_evidence`:

- Baseline accepts the correct secret block and clears it on drop.
- Invalid entry state, one state/primary/output byte mutation at actual readback,
  and a separate private-staging byte mutation reject, clear and retire.
- Corrupt actual output with either one individual readback's error forced to
  success: the other readback rejects, clears and retires.
- Corrupt output with both readback errors bypassed, or corrupt it after the last
  check at the fixture return: expected escaping negative controls, NOT detections.
- **Corrupt output and flip ZF at the shared combined-result branch: wrong output
  escapes. This is an in-model DC1 counterexample, NOT an accepted exclusion.**

In both inspected secret callers, the compiler combines readback failure bytes
with `or %al,%bpl`, then uses one `jne` to reject. GDB checks both failure bytes
and clear ZF before flipping only ZF. The compiler-specific site parser requires
the unique observed OR/MOV/JNE sequence and rejects changed/ambiguous layouts.
The original failure bytes are not altered. This is one result/decision fault
plus one data fault, unlike the earlier two-result-bypass negative control. It
demonstrates why the still-private ordinary Rust final decision cannot satisfy
the accepted model merely by having two separate full readbacks.

The runner's zero exit status means the declared experiment observations were
reproduced, not that DC1 passed. Secret reports explicitly emit
`known_in_model_escape: true` and
`KNOWN_IN_MODEL_ESCAPE: combined decision bypass; DC1 remains unimplemented`.
No verification-registry pass or release approval is generated. Replacing and
qualifying this combined decision is required implementation work before exposing
a fault-integrity owner. Generalizing the current success result, silently
dropping this case, or relabeling it as out of budget is not an acceptable fix.

The initial runner attempt used a nonexistent GDB `$r8b` register spelling and
therefore failed checkpoint validation. It now reads the low byte of `$r8` via
a mask. No event or expected outcome was relaxed. Hardware breakpoints still
leave executable bytes unchanged; public fixture values only are used. Fixture
ABI and disassembly assumptions are checked, not portable guarantees.

Observed ELF SHA-256 values after adding the secret fixture:

- Rust 1.99.1: `d3fc6663e5c782f49b64dd5295171049c66778a8b74bda5c8f8e200facaf8fef`.
- Rust 1.90.0: `30d863cbe0a21fe5524947539ebcc3cc63c6a0e52a2c669d80cb528d580b6672`.

Build with the primitive-only command from the preceding slice (select
`native_secret_transaction_probe`), then use the executable printed by Cargo:

```sh
python3 scripts/aes/check-aes-fault-transaction.py --path secret --binary target/release/deps/brynja_crypto-0e319f9c26ea36b6
python3 scripts/aes/check-aes-fault-transaction.py --path secret --binary target/release/deps/brynja_crypto-9fa6fd47f68fcc2f
```

The nine public experiments were rerun against both new artifacts and retain
their prior outcomes. The full dual-cfg workbench passes 56 tests on both
compilers (one separately invoked exhaustive schedule campaign remains ignored).
All 19 transaction tests pass on AArch64 musl/QEMU; these are functional tests,
not ARM debugger fault qualification. Miri passes the new ordinary secret fixture
with safe models, not native injections. Strict dual-cfg crypto Clippy passes on
both compilers. The unchanged ordinary AES/provider/HKDF suite passes 154
tests/doctests, with three opt-in OpenSSL comparisons ignored.

Ten runner regressions now exercise both paths, actual/staging-site selection,
cross-path/outcome substitution, the explicit combined-branch parser, exact
counterexample observation and the mandatory unresolved-gap report. Existing
guard/comparison/model/data suites pass 5/9/22/11 tests. These are harness and
functional regression results, not closure of the newly demonstrated DC1 gap.

## Thirteenth implementation slice: fresh secret release permit

The private primitive-enabled secret transaction now adds `permit_fresh` after
the two actual-destination readbacks. It first checks that lifecycle state is
still InProgress. The permit helper then invalidates that state to Terminal,
constructs fresh forward/reverse receipts from the ACTUAL admitted destination
and both independent results, and invokes the existing two-guard opaque copy to
restore InProgress only on matching receipts. No caller-supplied receipt or
previous success Boolean authorizes that restoration. The diagnostic report
must accept, and completion separately reloads/checks InProgress before releasing
the owner. No new unsafe code, primitive or public API was introduced.

This is deliberately not a claim that the old combined branch disappeared. It
still exists, but bypassing it no longer suffices. The unchanged native ZF-flip
injection following destination corruption now reaches the fresh permit, rejects,
clears output and retires. Bypassing both earlier readback results also rejects.
The runner names these cases `combined-decision-bypass` and
`two-readbacks-bypass` and REQUIRES rejection; the previous escaping outcomes fail
the experiment. Only the post-final-check secret-output corruption remains an
expected escaping negative control in this finite set. Historical findings and
artifact observations above describe the earlier implementation, not this fix.

All eleven secret experiments reproduced their declared outcomes on optimized
x86-64 Rust 1.99.1 and 1.90.0 test executables without source-injection hooks.
An initial sandboxed GDB invocation failed, so native execution was explicitly
approved outside that restriction. An initial MSRV run lacked a required outcome
marker; the diagnostic rerun reported successful rejection/clearing/retirement,
and the complete rerun succeeded. The missing-marker cause was not established;
it was not counted as a pass or used to relax validation. This is not timing
evidence or an alarm-threshold experiment.

The runner now defaults to short status output. Artifact/site metadata requires
explicit `--details`; debugger command arrays, raw transcripts, registers and
memory values are not echoed on tool failure. Tests use public synthetic data.
Run the same primitive-only build and `--path secret` commands from the previous
slice. Use the executable printed by Cargo; older binaries must not be substituted.

The new functional permit regression covers 256 matching blocks and 12,288
single-bit mismatches across destination/primary/secondary byte positions, plus
an invalid-length rejection. Matching data restores the permitted codeword;
every mismatch or invalid length leaves the denied codeword. Both optimized
dual-cfg workbenches pass 57 tests, with the separate exhaustive schedule campaign
still ignored. All 19 transaction tests pass on ARM musl/QEMU using the copy
model; targeted Miri passes the secret fixture with safe models. Strict Clippy
passes on both compilers after replacing a test-only unchecked indexing expression
with checked access. The runner regressions require the new rejection outcomes.

Remaining work includes native faults inside permit construction, its report,
state restoration and final completion; equivalent public-path hardening; and
complete linked-owner/C1/DC1/L1 qualification. The final observation-to-return
window remains explicit. This fix addresses the demonstrated secret-path escape;
it does not establish general fault resistance or authorize production exposure.

## Fourteenth implementation slice: public permit and native permit observations

The private primitive-enabled public transaction now uses the same fresh
`permit_fresh` as the secret path, after destination readbacks and before
completion/commit. A failed permit still leaves the rollback owner active and
retires the lifecycle. The earlier public two-readback-result escape is now a
required rejection in the transaction runner, not an accepted exclusion. The
secret path and the historical observations above retain their original scope.

The new `check-aes-fault-permit.py` runs three finite cases for each output path:

- mutate actual output at permit entry, then forge the denied copy's diagnostic
  report: the independent lifecycle check still rejects;
- mutate actual output at permit entry, then forge the helper's returned success:
  the independent lifecycle check still rejects;
- change one byte of the lifecycle immediately after the guarded restoration:
  completion rejects the changed codeword.

All six cases reject, retire, and restore public output or clear secret output
on optimized x86-64 Rust 1.90.0 and 1.99.1 test artifacts. These are finite
development observations, not a complete mutation campaign, production-linked
owner qualification, physical evidence, or a C1/DC1/L1 claim. The last case
addresses one changed state byte, not arbitrary complete-state replacement.

The runner initially injected before an earlier destination readback. That
readback correctly rejected, so the intended permit event was never reached;
the run failed validation and was not counted as evidence. The harness now
stops at the permit entry and checks the fixture's actual argument bindings
before injection. It uses hardware stops without changing executable bytes,
requires every declared checkpoint exactly once, rejects mixed/duplicate
outcomes, checks that source-injection hooks are disabled, and checks artifact
bytes are unchanged. Its five regression tests also cover malformed/missing
checkpoints, wrong paths/outcomes, bad artifacts, and quiet handling of tool
failures. Debugger commands and transcripts are not printed on failure.

The tested primitive-only artifact SHA-256 identities (working-tree builds,
not clean release artifacts) were:

```text
64edf21a34aaea7bd76c019f349ac8c1026650e6659f1f70f0c598e12f78764f  target/release/deps/brynja_crypto-0e319f9c26ea36b6
36c3734b1e1209deb114a97ea2c60eaf34b0e8368ccb65365a878c5792caf4c8  target/release/deps/brynja_crypto-9fa6fd47f68fcc2f
```

Reproduce using a fresh build and the executable path printed by Cargo, not a
possibly stale executable left in `target`:

```sh
RUSTFLAGS='--cfg brynja_fault_primitives' cargo +1.90.0 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block native_public_transaction_probe
python3 scripts/aes/check-aes-fault-permit.py --binary PATH_FROM_CARGO --path public
python3 scripts/aes/check-aes-fault-permit.py --binary PATH_FROM_CARGO --path secret
```

Repeat for 1.99.1. Do not set `brynja_fault_evidence` for native observations.
Run the corresponding transaction runner on both paths as well: all 9 public
and 11 secret cases reproduced on each compiler. The post-final-check escaping
negative controls remain expected and explicitly outside the checked window.

The dual-cfg functional workbench passes 57 tests on each compiler, with one
separate exhaustive campaign intentionally ignored. All 19 transaction tests
pass under AArch64 musl/QEMU using its copy model; this is not an ARM native
guard claim. Strict no-deps Clippy passes on both compilers. The directly invoked
model/data/comparison/guard/transaction/permit runner suites pass 22/11/9/5/10/5
tests. Python unittest discovery selected no files because of these scripts'
hyphenated names; that invocation was not counted as a test pass.

Remaining work is the full receipt/capture/decision/commit fault surface,
complete linked AES-owner artifacts and supported-target admission, followed by
the optional public API and its external ownership/package tests. The final
observation-to-return window and accepted outcome-leakage residual remain.

## Fifteenth implementation slice: native cached AES owner observations

Nine new private fixtures exercise `Cached` end to end: AES-128/192/256, each
through public encryption, secret-output encryption and decryption. They use
the public FIPS Appendix C key/block answers, separate borrowed key storage,
independent schedule generation, both real AES engines, retained-storage checks,
the transaction, and the final fresh permit. The test inputs enter through
`black_box` to avoid fixture constant propagation; no fault-injection hook is
enabled. These are optimized TEST executables, not shipping artifacts. Their
presence does not establish that a future public owner's generated code is
identical, or qualify compiler/backend combinations.

The fixture asserts the actual known answer before clearing a secret block.
Success must leave the owner reusable. Rejection must restore the old public
destination or clear the secret destination and retire the same owner for BOTH
public and secret routes. Dropping the owner must clear both admitted key
borrows without touching their unused suffixes. This checks explicit borrowed
storage, not register/spill erasure or every internal schedule's emitted cleanup.

`check-aes-fault-cached.py` declares seven experiments per width and route:
baseline; one-bit corruption of the actual destination, primary result, or
secondary result at final-permit entry; destination corruption plus a forged
permit report; destination corruption plus a forged helper result; and a
changed lifecycle byte after restoration. The baseline must accept and all six
mutation cases must reject/retire with the appropriate output behavior. The
runner checks complete expected blocks and distinct pointer bindings before
the events, requires exact fixture identity and ordered markers, validates the
guard leaf, and rejects changed artifacts. It prints short status, not debugger
commands, transcripts or memory values. Its six regression tests cover all
declared identities, wrong/missing/mixed outcomes, site selection, incomplete
execution, artifact changes, and quiet tool failures.

All 63 experiments reproduced on each optimized x86-64 Rust 1.90.0 and 1.99.1
primitive-only artifact (126 observations total, including 18 baselines). The
sample sites and values are finite: this is NOT exhaustive bit, instruction,
schedule, capture, constant or round coverage. In particular, altering a domain
RESULT at permit entry is not evidence of a native fault during that domain's
computation. Earlier source-injection evidence retains its separate status.

Tested working-tree artifact SHA-256 identities:

```text
6c0cbe0abaa1516fe128061eac65d3a35590aa2a603bc9c1f3dfa61611bcb6b2  target/release/deps/brynja_crypto-0e319f9c26ea36b6
2c48c8ec9ba1d7aaa29d8eb706bc594913482bb6222ee2e81ebba67bac288fc8  target/release/deps/brynja_crypto-9fa6fd47f68fcc2f
```

To reproduce, build with just the primitive cfg and use the path Cargo prints:

```sh
RUSTFLAGS='--cfg brynja_fault_primitives' cargo +1.90.0 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block native_cached_
python3 scripts/aes/check-aes-fault-cached.py --binary PATH_FROM_CARGO --path public
python3 scripts/aes/check-aes-fault-cached.py --binary PATH_FROM_CARGO --path encrypt
python3 scripts/aes/check-aes-fault-cached.py --binary PATH_FROM_CARGO --path decrypt
```

Repeat on 1.99.1. `brynja_fault_evidence` must remain unset for native runs.
Each script invocation covers all three widths and seven declared cases.

The dual-cfg functional workbench passes 66 tests on each compiler (one separate
exhaustive campaign remains ignored), and all nine cached-owner baseline tests
pass under AArch64 musl/QEMU using the functional copy model. Strict no-deps
Clippy passes on both compilers. Ordinary crypto AES/provider/HKDF tests and
doctests pass 163 checks, with three optional OpenSSL tests left ignored; no
OpenSSL dependency was added. The runner/model suites pass 6 cached, 5 permit,
10 transaction, 5 guard, 9 comparison, 22 model and 11 data tests.

Remaining work includes native data/control faults before the permit, receipt
construction and final decisions/commit, operation-local owner integration,
supported-target admission and the external public API/package contract. The
native observation runner adds no release gate and no qualification claim.

## Sixteenth implementation slice: operation-local schedule owner

The private `Ephemeral` owner now supports AES-128/192/256 public encryption,
secret-output encryption and decryption. It retains only the two borrowed key
replicas, the encoded lifecycle and the thread-local marker between operations.
Key admission/capture/complement checking is factored into `Keys::new`; cached
keys use the same path. Both borrowed destinations are admitted for clearing
before validation, so import errors clear both, not the caller's source key.
There is no new public feature, dependency, unsafe code or reset/retry API.

Each operation validates the stored key pair, separately copies each domain's
own key representation through the core transfer boundary into local clearing
storage, then expands each domain from its own copy. The secondary is never
seeded from the primary. The existing retained-state computation checks all
schedules before and after use. The operation additionally rechecks the stored
key pair and its agreement with the local captures. All local keys, decoded
scratch and schedules drop before the computation callback returns to the
guarded output transaction. Only the independently computed result scratch
survives to the final release checks. This is a source/functional construction,
not qualification of compiler preservation or the complete D3/C1/DC1 budget.

New ordinary tests cover all FIPS widths/directions, repeated use, a returned
secret block outliving the key owner, invalid imports and short destinations,
clear-on-drop with untouched unadmitted suffixes, and each retained key byte
corrupted individually. Repairing those test bytes does not revive a retired
owner. The existing explicit-clearing observer now has a test-only reset/read
helper; it verifies that a temporary primary schedule has cleared on every
operation while the persistent owner (and, on success, the secret block) is
still alive. This says nothing about registers or compiler-created copies.

Separate source-evidence tests exercise 252 combinations across widths, routes
and four boundaries (after schedule setup, before computation, between domains,
and after computation): 180 mutate key/schedule/round metadata and 72 inject
errors or unwinds. There are also 27 input-capture trials (nine mutations and
18 errors/unwinds), plus nine import-capture trials (three mutations and six
errors/unwinds). Every declared event must be hit; public output is restored,
admitted secret output clears, and subsequent calls on every route are rejected
before fresh expansion/computation checkpoints. Error/unwind trials are cleanup
and lifecycle evidence, NOT computational fault-detection coverage. These hooks
remain behind the non-Cargo evidence cfg inside the test-only workbench.

The nine real-AES native fixtures are now generated for both owner lifetimes.
`check-aes-fault-cached.py` retains its historical filename and default, and adds
`--owner ephemeral`. Exact owner identity is part of validation: cached results
cannot satisfy an operation-local run. All seven finite permit events per width
and route reproduced for both owners on Rust 1.90.0 and 1.99.1: 252 observations
including 36 healthy baselines. These still inject at the final permit boundary,
not inside expansion, recapture, rounds or retained-state predicates. The earlier
11 secret-transaction regression events also reproduce on both new artifacts.

Tested primitive-only working-tree artifact SHA-256 identities:

```text
c1ac3534de131c6af2ecf8e2def02e0824c7d3adee0501fff28c61183bd31d7e  target/release/deps/brynja_crypto-0e319f9c26ea36b6
e583ea6192c3712429d9de2a391bb29753f605000d24f3fe7f972389884a43d7  target/release/deps/brynja_crypto-9fa6fd47f68fcc2f
```

Reproduction adds only the owner selector to the preceding slice's runner:

```sh
RUSTFLAGS='--cfg brynja_fault_primitives' cargo +1.90.0 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block retained::probe_tests
python3 scripts/aes/check-aes-fault-cached.py --binary PATH_FROM_CARGO --owner ephemeral --path public
python3 scripts/aes/check-aes-fault-cached.py --binary PATH_FROM_CARGO --owner ephemeral --path encrypt
python3 scripts/aes/check-aes-fault-cached.py --binary PATH_FROM_CARGO --owner ephemeral --path decrypt
```

Repeat on 1.99.1 and with `--owner cached`. Do not enable source-evidence hooks
for native observations, and use the current Cargo-reported executable.

The complete dual-cfg workbench passes 81 tests on each compiler; the separately
declared exhaustive schedule campaign remains ignored. AArch64 musl/QEMU passes
33 retained-owner tests with that exhaustive test ignored, using its safe copy
model rather than a native guarded-copy admission. Targeted Miri passes invalid
imports and every retained-key-byte corruption/retirement test under safe core
models. Strict no-deps Clippy passes on both compilers. Ordinary AES/provider/HKDF
and doctest checks pass 175 tests, with three optional OpenSSL tests ignored.
The owner runner has seven passing regression tests, including CLI owner
selection, rejection of substituted owner results and artifact mutation.

The operation-local integration gap is now addressed in the private prototype.
Full native capture/expansion/round/retained-state/check/commit coverage,
supported-build admission, public opt-in APIs and package-external contracts
remain unfinished. Neither these source tests nor the finite native observations
authorize a public fault-integrity claim or remove the accepted residuals.

## Seventeenth implementation slice: native retained state and input capture

This slice changes no Rust implementation. `check-aes-fault-retained.py` uses
hardware stops at existing capture, secondary computation and core-copy helper
boundaries in the preceding slice's optimized primitive-only test artifacts.
It does not add a source-injection hook, patch executable bytes, or qualify a
production artifact. Only the same public FIPS fixtures are used.

Seven cases run for each width, route and owner lifetime:

1. Healthy baseline, requiring successful output and owner reuse.
2. Change one byte of the stored primary key at secondary-computation entry.
3. Change one byte of the stored complemented key at that entry.
4. Change a secondary schedule plane byte before secondary computation.
5. Change that schedule byte after secondary computation returns successfully.
6. Change the secondary round-count metadata after that successful computation.
7. Change the first input replica after its opaque copy completes; observe the
   second copy independently completing from the unchanged caller source.

Cases 2–6 observe the key-capture destinations and verify their fixture values
and helper arguments before the event. The schedule cases admit only two
explicit private-layout hypotheses (round-count word first or last), require a
unique match with the expected round count and encoded initial round key, and
reject unrecognized layouts. This is test-artifact-specific inspection, not a
stable Rust ABI. Cases 5–6 also require a successful helper result and the exact
known-answer output BEFORE mutation. The subsequent rejection therefore tests
retained-state validation even though the secondary had computed correct bytes.
It does not merely demonstrate disagreement between two faulty/correct outputs.

Case 7 stops at input capture rather than key import. It observes both opaque
copy completions without source instrumentation: first replica equals the caller
input before mutation; second replica and caller source still equal the original
input after the second copy; first replica retains only the declared changed
byte. The owner must then reject and retire. This directly observes the separate
copy boundary at one declared input site; it is not an exhaustive capture,
encoding or shared-source fault campaign.

Every mutation case requires the existing real-owner fixture to restore public
output or clear secret output, reject subsequent calls through BOTH routes, and
clear its borrowed key storage on destruction. The seven cases reproduce for
AES-128/192/256, public encryption, secret encryption and decryption, cached and
operation-local owners, and both Rust 1.90.0 and 1.99.1: 252 observations, of which
36 are healthy baselines. No counterexample or Rust fix was needed at these
selected sites. All observations are on the local x86-64 host; they provide no
new ARM/RISC-V native or physical-fault qualification.

The runner requires exact fixture identity, ordered event/outcome markers,
hardware-stop counts, an unchanged executable, and disabled source-evidence
hooks. Six regression tests exercise both demangling forms, missing/ambiguous
symbols, event ordering, wrong/duplicate outcomes, site selection, matrix
completeness, artifact changes and quiet failure reporting. Only short status
is printed; command arrays, debugger transcripts and memory values are not.

Tested working-tree artifact SHA-256 identities (unchanged from slice 16):

```text
c1ac3534de131c6af2ecf8e2def02e0824c7d3adee0501fff28c61183bd31d7e  target/release/deps/brynja_crypto-0e319f9c26ea36b6
e583ea6192c3712429d9de2a391bb29753f605000d24f3fe7f972389884a43d7  target/release/deps/brynja_crypto-9fa6fd47f68fcc2f
```

Reproduce using the existing primitive-only build, taking the current executable
path from Cargo. This experiment needs no rebuild with data-injection hooks:

```sh
RUSTFLAGS='--cfg brynja_fault_primitives' cargo +1.90.0 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block retained::probe_tests
python3 scripts/aes/check-aes-fault-retained.py --binary PATH_FROM_CARGO --owner cached --path public
python3 scripts/aes/check-aes-fault-retained.py --binary PATH_FROM_CARGO --owner cached --path encrypt
python3 scripts/aes/check-aes-fault-retained.py --binary PATH_FROM_CARGO --owner cached --path decrypt
```

Repeat with `--owner ephemeral` and on 1.99.1. The exact symbol, return-site,
argument and layout checks must match; unfamiliar builds fail rather than
silently receiving an observation pass. These are development scripts, not an
additional release gate. Earlier unchanged functional/Miri/QEMU results retain
their recorded scope and are not represented as newly rerun by this slice.

Coverage remains finite: this does not exhaust primary schedule bytes, all
intermediates/round skips, constants, capture/normalization sites, or combined
data-plus-check-bypass events. Full C1/DC1/L1 coverage, emitted independence and
cleanup of complete shipping owners, supported-build admission and the external
public API remain unfinished. Correct-output filtering, outcome leakage and the
final check-to-use window retain the accepted limitations.

## Eighteenth implementation slice: independent computation completion

A combined native probe found a real gap in the private prototype. Changing the
first input replica after its opaque copy made `Retained::compute` reject before
either AES engine ran. Forcing only that function's returned error to success
then let the transaction accept two equal, initially zero result buffers. The
real cached AES-128 public fixture failed its known-answer assertion. This was
a development counterexample, not a released AES API or a qualifying pass.

The transaction now owns a fresh invalid 16-byte completion record and checks
it independently of the computation's returned `Result`, before either public
or secret destination is written. The retained engine marks it only after both
transforms and post-use retained/input checks. The operation-local owner checks
the retained engine's separate inner record before marking its own outer
record. A forged early success therefore leaves the relevant record invalid,
so the operation retires and restores public output or clears secret output.
All 128 single-bit changes to the marked record are rejected in source tests.
These records do not prove protection against an arbitrary instruction skip,
whole-codeword overwrite or a bypass of every independent decision.

The new `check-aes-fault-completion.py` reruns baseline, input-only,
input-plus-forged-success and marked-completion-bit cases against each actual
optimized test artifact. The last case changes one bit in the completed record
after both engines have produced the correct known answer, then requires
rejection and retirement before release.
It requires separate input-copy completions, exact expected fixture outcome,
terminal retirement on rejection, cleared borrowed storage, unchanged ELF and
disabled source-injection hooks. On local x86-64, all 72 declared cases passed
for each of Rust 1.90.0 and 1.99.1: AES-128/192/256, cached and operation-local,
public encryption, secret encryption and secret decryption. The previous
counterexample now rejects even when the returned error is forged to success.
The completed-record bit is also rejected through both owner lifetimes. This
tests one emitted-code L1 site, not every record location or a bypass of the
record check.
Three Python runner contract tests and two new Rust transaction tests pass;
the full private workbench passes 83 tests with one deliberately ignored
exhaustive campaign on both compilers. Ordinary AES/provider/HKDF tests and
strict no-deps Clippy on both compilers also pass. Targeted Miri passes both
new transaction tests, and AArch64 musl/QEMU passes the retained-owner suite
(33 tests, one exhaustive campaign ignored). The existing cached and retained
native probe runners still pass a cached public-path smoke check on 1.99.1.
These are development observations, not a full C1/DC1 campaign or
public-profile qualification.

Tested primitive-only working-tree artifact SHA-256 identities:

```text
b73842d1dd3f91090c28a1da737989f58ecf2543b06761e1ca594ba759823a80  target/release/deps/brynja_crypto-0e319f9c26ea36b6
b64b3f4e58d9eb6a1dc9910c9aa2b9d57c2ed8e5433bd581cfa2ae222955a656  target/release/deps/brynja_crypto-9fa6fd47f68fcc2f
```

Reproduce with the primitive-only optimized test binary reported by Cargo,
then run `python3 scripts/aes/check-aes-fault-completion.py --binary PATH
--owner cached --path public`; repeat for `--owner ephemeral` and paths
`encrypt`/`decrypt` on each compiler. Debugger output remains captured and
unprinted. The old pre-fix artifact identities are recorded in slice 17; they
are not represented as current, passing evidence. Full fault-budget and
supported-build admission, public opt-in APIs, package-external contracts and
independent implementation review remain unfinished.

## Nineteenth implementation slice: late operation-local completion boundary

The operation-local owner checks an inner completion record immediately after
the temporary retained engine returns, but still has persistent/local key
checks to perform before it marks the transaction's outer record. A new
`brynja_fault_evidence`-only checkpoint changes one local captured key byte
after both AES engines and the inner check have completed. The later
local-versus-persistent key comparison must reject it. The source fixture then
forges only the outer computation's returned error into success; the outer
completion record remains invalid and the transaction must still reject.

The source test covers all three key widths, public encryption, secret
encryption and secret decryption. It requires unchanged public output or cleared
secret output, terminal owner state, rejection of both later routes and clearing
of both borrowed persistent key buffers on destruction. It passes on Rust
1.90.0 and 1.99.1. The complete private workbench now passes 84 tests on each
compiler, with the declared exhaustive schedule campaign still ignored.
Strict no-deps Clippy passes on 1.99.1. This checkpoint is absent from the
primitive-only native artifacts and from production code; it demonstrates the
source-level inner/outer record ordering, NOT emitted-code DC1 qualification.
The ordinary AES/provider/HKDF suite, formatting, document links and release
plan checker also pass. No public opt-in API or supported fault-integrity build
is admitted yet.

## Twentieth implementation slice: native late operation-local completion

This slice changes no production or private AES implementation. The new
`check-aes-fault-outer-completion.py` observes the existing optimized
primitive-only test artifacts with source-injection hooks disabled. It first
checks the real operation-local key import and outer completion record. It
then stops after the nested retained computation returns successfully with the
exact FIPS known answer in both output buffers. Only then does it flip one
byte of the retained persistent key. The outer operation-local post-check
must reject this late fault. In a separate combined case, the probe also
forges that outer error return to success; the still-invalid outer completion
record must prevent any output release and permanently retire the owner.

Baseline, late-key-only and late-key-plus-result-bypass cases reproduce for
AES-128/192/256, public encryption, secret encryption and secret decryption
on Rust 1.90.0 and 1.99.1: 54 native development observations. Each run
requires ordered checkpoint markers, exact fixture identity, an unchanged
ELF, cleared borrowed key storage, and expected acceptance or terminal
rejection. Four Python runner tests reject missing checkpoints, false
successes, wrong outcomes, an altered event order and an altered artifact.
Raw debugger output is captured, never printed. The tested binary identities
are the unchanged primitive-only artifacts recorded in slice 18.

This is one D2 plus C1/DC1-like site in a local x86-64 test artifact, not a
complete combined-fault or physical-fault claim. Other key and schedule
locations, data/skip sites, final permit and return branches, supported-build
admission, public APIs and independent implementation review remain unfinished.

A subsequent broad regression scan of the existing retained-state native
runner was not clean on its first pass: three operation-local cases reported
only `native execution unconfirmed` while other cases passed. Each affected
path passed on rerun, including repeated complete-path attempts, but the
original raw debugger transcripts were not retained, so the cause is not
established. This is NOT counted as a clean refreshed retained-state campaign
or as a demonstrated AES result failure. The runner still rejects the same
conditions; its failure message now reports only checkpoint counts so a
future recurrence can be diagnosed without exposing debugger output. The
new outer-completion observations above were separate, complete runs.

## Twenty-first implementation slice: secondary round-skip source evidence

The secondary engine now has a `brynja_fault_evidence`-only hook that skips one
declared substitution call at a selected round. This flag is not a Cargo
feature and is absent from primitive-only native artifacts and ordinary
builds. The source campaign exercises every round for AES-128/192/256,
public encryption, secret encryption and secret decryption, and both cached
and operation-local owners: 216 declared one-skip executions. Every case
rejects before releasing output, preserves or clears the destination as
appropriate, retires the owner, and rejects subsequent use. The complete
private workbench passes 85 tests with one separately ignored exhaustive
schedule campaign on both Rust 1.90.0 and 1.99.1; strict no-deps Clippy and
the ordinary AES/provider/HKDF suite pass on 1.99.1.

The Rust 1.99.1 primitive-only optimized test artifact changed after this
source edit, even though its evidence-only branch is disabled. Its new SHA-256
identity is `c58133b30ece121a49beee855d72b0719b41ed17f3816456f77f3b675633fa4d`.
The Rust 1.90.0 artifact remains at the slice-18 identity. All six
completion-probe groups and all three outer-completion groups were rerun and
passed on the new 1.99.1 artifact. Earlier cached/retained probe observations
are bound to their recorded older artifact; they are not silently promoted to
the new hash. The intermittent retained-runner transcript issue from slice 20
is still unclassified. This S1 campaign is source-only: it does not test
native instruction skips, all arithmetic operations, combined skip-plus-check
bypass, or physical-fault propagation. Public admission remains unfinished.

## Twenty-second implementation slice: native secondary call skip

The fixed, predeclared cached/retained native regression matrix was rerun on
the new Rust 1.99.1 artifact from slice 21: all 12 owner/path groups passed
without retry in that campaign. The earlier intermittent transcript mismatch
remains unexplained; one later clean matrix does not erase it.

`check-aes-fault-round-skip.py` uses hardware stops in the same uninstrumented
optimized artifacts. After the secondary schedule transform begins, it stops
at a selected `Planes::substitute` entry, verifies that the return address lies
in that actual transform invocation, and skips the call by resuming at its
return address with a successful call result. This is one controlled
secondary-domain *call* skip, not a patch to the ELF or an arbitrary
instruction skip inside the substitution circuit. The real cached or
operation-local owner must reject and retire before public or secret output
is released. Each width also has a healthy no-skip baseline.

All 468 native development observations passed in one fixed matrix: three
key widths, 10/12/14 selected rounds, public encryption, secret encryption
and secret decryption, both key lifetimes, and Rust 1.90.0 and 1.99.1.
This comprises 432 selected call skips and 36 healthy baselines. The runner
requires exact fixture identity, ordered checkpoints, the selected call's
return into the active transform, terminal outcome, cleared borrowed key
storage and unchanged ELF. Three runner contract tests reject wrong markers,
outcomes and step selection. An initial harness-only failure compared the
link-time address to a PIE-relocated runtime address; the runner now captures
the transform's runtime start address before validating the return range.
No AES implementation was changed to resolve that harness failure.

This covers one native S1-style call boundary in local x86-64 test artifacts.
It does not establish arbitrary instruction-skip coverage, other arithmetic
sites, combined skip-plus-check bypass, supported-build admission or physical
fault resistance. The default-off public API remains unfinished.

## Twenty-third implementation slice: private non-test build shape

The fault-integrity workbench can now be compiled outside `cfg(test)` by the
non-public `brynja_fault_profile_build` compiler cfg. Its tests and
source-injection hooks remain `cfg(test)`-only; the ordinary Cargo feature
graph still offers no fault-integrity owner or public API. The non-test module
is intentionally unused, so `dead_code` is allowed only for this private
development build. This checks that the implementation is not accidentally
dependent on the Rust test harness or `std`; it does not admit any backend.

On Rust 1.99.1, both the primitive and fallback configurations type-check in
`no_std` on the host. The primitive configuration also type-checks for
`thumbv7em-none-eabihf` on Rust 1.90.0 and 1.99.1. Strict no-deps Clippy
passes for the non-test primitive build. The private evidence suite still
passes on both compilers: 85 passed and one separately ignored exhaustive
schedule campaign. No new native fault observation or supported-build
qualification follows from these compile checks. A public opt-in surface,
target-specific admission, complete fault budget and independent review remain
unfinished. Earlier native observations remain bound to their recorded
artifact hashes; this source edit does not silently rebind them to a new build.

## Twenty-fourth implementation slice: empty admission set

No target/compiler/profile combination has completed the reviewed fault
budget. The private cached and operation-local owners therefore share an
explicit admission check at key import: outside `cfg(test)` it rejects before
reading the key or touching either caller-owned storage buffer. Only private
unit fixtures can opt into the unqualified workbench. This is deliberately an
**empty release admission set**, not a claim that the current x86-64 candidate
or any other build is qualified. A builder controlling rustc can set `cfg(test)`;
the switch is not an adversarial security boundary, and the module remains
private with no Cargo feature or public owner.

Tests check that the release admission path rejects and that denied imports
leave the input key and both storage buffers unchanged for AES-128/192/256.
The existing evidence suite still passes (88 passed, one separately ignored
exhaustive schedule campaign), strict non-test no-deps Clippy passes, and the
private `no_std` build still type-checks with and without opaque primitives;
the Rust 1.90.0 Cortex-M build also type-checks. The temporary internal error
mapping is generic `SecretMemory`; a public implementation must expose a
distinct unsupported-build error and define exact artifact-bound admission
before any configuration is allowed. The earlier native observations were not
rerun for this source revision and remain tied to their previously recorded
binary hashes.

## Twenty-fifth implementation slice: persistent transform-constant source model

A new `cfg(test)` plus `brynja_fault_evidence` hook changes one coefficient of
the secondary substitution's highest-degree monomial, only during block
transforms. The mutation persists across calls to the same private owner.
It is effective only when a substituted byte reaches `0xff`; the test selects
one public input with no effective mutation and another with a divergent
result. This is a domain-local *callsite* model, not a physical mutation of
an emitted immediate or a shared expansion/transform constant. The hook is
absent from non-test builds and the earlier native evidence binaries.

For AES-128/192/256, public encryption, secret encryption and secret
decryption, and both cached and operation-local owners (18 scenarios), the
first call returns the correct block under the still-active but ineffective
mutation. The next call detects a differing result, restores public output or
clears secret output, and retires the owner. Both later routes reject without
running the secondary transform; borrowed key storage clears on owner drop.
The test separately counts reached and effective substitution sites, so a
correct-output call is not mislabeled as a detected fault. This demonstrates
the accepted filtered-correct-output/SIFA residual in the source model, not
confidentiality protection or a distribution bound.

The private evidence suite passes on Rust 1.90.0 and 1.99.1 (89 passed, one
separately ignored exhaustive schedule campaign); ordinary all-feature
crypto tests and strict non-test no-deps Clippy also pass. No native constant
fault, full C1/DC1 campaign, exact-artifact admission or public API is claimed.
Prior native observations remain bound to their recorded older artifacts.

## Twenty-sixth implementation slice: persistent expansion-constant source model

The test-only coefficient hook now distinguishes secondary key expansion from
block transformation. A persistent one-bit change to the expansion S-box's
affine constant (the always-active ANF monomial zero) is installed without
altering primary AES or the caller key. This models a domain-local expansion
callsite; it does not mutate or attest a compiler-emitted immediate. The hook
remains absent from non-test builds, including when the evidence cfg is set.

For each AES width, cached import rejects the altered secondary schedule
before returning an owner and clears both admitted caller storage buffers.
For each width and public-encrypt, secret-encrypt and secret-decrypt path,
an already imported operation-local owner rejects its next call, preserves
public output or clears secret output, then stays terminal on both routes.
The test verifies that the expansion site was reached and effective, that
later terminal calls do not re-enter it, and that guard bytes outside the
borrowed key regions remain unchanged. Cached and operation-local behavior
are intentionally different: the former has no returned owner to retire when
import itself fails.

The persistent-transform test from slice 25 still checks its separate
filtered-correct-output case. This is finite functional source evidence, not
an exhaustive PFA/SIFA study, native fault simulation, physical qualification
or a release admission. Earlier native observations remain bound to their
recorded binaries.

## Twenty-seventh implementation slice: correlated-echo negative control

The private transaction tests now model a correlated skip of BOTH AES domains
plus a forged computation-completion record. With the public FIPS AES-128
example, equal input replicas pass the transaction's agreement and readback
checks: public encryption can return the original plaintext as purported
ciphertext, and secret decryption can return unchanged ciphertext as purported
plaintext. The test also verifies the returned secret block clears on Drop.
Both the opaque-candidate and functional-fallback transaction paths reproduce
the control.

This is deliberately outside the single-domain/limited-bypass fault budget.
The fixture supplies skipped computation through a callback; it does not
inject an instruction skip into the integrated AES owner or a release binary.
It documents the worst correlated confidentiality outcome, not a newly found
in-model escape and not an argument for an invalid ciphertext-equals-plaintext
heuristic. The accepted common-mode exclusion and SIFA residual remain open.

## Twenty-eighth implementation slice: private failure classification

The private transaction now distinguishes destination admission failure,
the first rejected operation (which retires the owner), and a later call to
an already retired owner. The cached and operation-local private owners carry
that classification through their internal operation methods. Their existing
generic fixture methods still map failures to the original value-free AES
`SecretMemory` error, so no ordinary/public AES API changed. A computation
error is classified as *rejected and retired*, not as proof that a physical
fault was detected. A malformed lifecycle word is rejected and made terminal;
subsequent calls do not invoke the computation callback.

Regression tests cover the first-versus-later distinction on both public and
secret transactions, and on the persistent transform and expansion source
models across all three key widths and both key lifetimes. Public failure
restores the old output, secret failure clears it, and a retired owner does
not run the secondary transform. This error label is diagnostic only: its
ordinary Rust state check is not a protected release decision. Applications
must not expose the distinction to remote peers; doing so would add an alarm
oracle to the already accepted SIFA/failure-stage residual.

The private evidence suite passes on Rust 1.90.0 and 1.99.1 (94 passed, one
separately ignored exhaustive schedule campaign). Ordinary all-feature
crypto tests, strict no-deps Clippy and the `no_std` Cortex-M build check
also pass. No public error type, exact build admission, native retest on this
source revision or C1/DC1 qualification is claimed. Earlier native records
remain tied to their recorded artifact hashes.

## Twenty-ninth implementation slice: private import-failure classification

The private failure labels now also distinguish an unqualified build from a
rejected key import. Both cached and operation-local constructors pass through
the same empty build-admission check before reading key bytes or changing
caller storage. A malformed key width or storage extent after test-fixture
admission is instead `ImportRejected`, and the borrowed storage is cleared.
A persistent secondary expansion-constant mismatch likewise rejects cached
import with that label. Ordinary AES and the existing generic private fixture
methods still return their previous value-free error; no public error type or
usable fault-integrity constructor has been introduced.

Tests cover unqualified rejection with untouched key/storage for all three
widths, a malformed 17-byte key, a too-short second storage borrow, and the
cached expansion-fault case. Both private owner constructors preserve the
import-rejection label and clear admitted storage for all three key widths.
The label distinction is not a protected diagnostic channel and must not be
exposed to protocol peers. The release
admission set remains empty; exact compiler/profile/linked-artifact policy,
native retesting and full C1/DC1 qualification are still unfinished. Earlier
native observations remain bound to their recorded binaries.

Every private diagnostic still maps to the same value-free ordinary AES error.
The import-rejection/cleanup, import-error/unwind and error-mapping tests also
passed individually under Miri. These targeted interpreter checks are not a
full-profile Miri campaign and do not qualify fault or side-channel behavior.

## Thirtieth implementation slice: primary constant source model

The evidence-only portable-field fixture can replace the primary affine
constant during primary expansion, forward transform or inverse transform.
It requires both `cfg(test)` and `brynja_fault_evidence`, and an explicit
phase/site-matched thread-local guard. Ordinary builds contain no fixture
module or hook call. A separate test checks that the wrong phase/site and
operations outside a guard retain the ordinary field answer.

For AES-128/192/256, source-level tests now exercise the primary constant
fault on cached imports and operation-local first use, plus encrypt-public,
encrypt-secret and decrypt-secret calls in both owner lifetimes. An affected
cached import rejects and clears both key borrows; an affected operation
retires, leaves public output unchanged or clears secret output, and blocks
later calls without another transform. This complements the secondary
constant model, but does not establish every value-dependent persistent-fault
case or a universal detection theorem.

The evidence-enabled library suite passed on Rust 1.90.0 and 1.99.1 and under
ASan/LSan: 129 passes with one separately ignored exhaustive schedule campaign
in each run. The targeted primary expansion-fault case also passed under Miri;
ordinary all-feature AES tests, strict Clippy and the Cortex-M `no_std` build
passed. These are development checks, not an admitted release-profile campaign.
The source hook changes evidence codegen, so earlier native observations cannot
be transferred to this build.

## Thirty-first implementation slice: primary filtered-output source model

The primary-only test fixture now alters the `0x1b` reduction constant at the
first source-level `xtime` invocation of each primary block transform. That
invocation's high input bit decides whether the changed constant affects the
field result. The test enumerates public input bytes to find one unaffected
block and one block whose primary result differs from the independent
secondary result, separately for each key width and direction. The chosen
source occurrence is not asserted to be one stable emitted instruction after
optimization; the fixture is absent outside `cfg(test)` plus
`brynja_fault_evidence`.

Both cached and operation-local owners may release the first *correct* result
while the persistent fault remains present. The later differing result is
withheld: public output is restored, secret output is cleared, and the owner
enters terminal state with no further primary transform. This deliberately
models correct-output filtering as a possible SIFA/safe-error oracle, not as
confidentiality protection. Applications still need global key retirement
and peer-visible failure uniformity after any alarm.

The direct fixture test checks ineffective and effective first calls. The
owner regression covers all three key widths, both block directions and both
schedule lifetimes. The full evidence-enabled library suite passed on Rust
1.90.0 and 1.99.1 and under ASan/LSan: 131 passes, one separately ignored
exhaustive schedule campaign. The direct fixture test passed under Miri; the
ordinary all-feature suite, strict Clippy and `no_std` Cortex-M compile check
passed. No exact binary was requalified, no build is admitted, and C1/DC1
and physical-fault claims remain unfinished.

## Thirty-second implementation slice: correlated constant negative control

The test-only primary fixture changes the forward S-box affine constant by one
bit; the separate secondary ANF fixture changes its monomial-zero coefficient
by the same bit. With both fixtures installed during encryption, the two
independent implementations agree on a *wrong* answer. The private owner
therefore returns success for public ciphertext and for a clearing secret
block, then still works normally after both fixtures are removed. This is an
expected, escaping **two-domain/common-mode negative control**, not a profile
pass. It is covered for AES-128/192/256 and cached and operation-local owners.

The paired single-domain control applies only the secondary change: it rejects
before public output changes, retires the owner, and performs no later
substitution. The earlier primary-only regressions supply the other half of
that control. Together the tests make the exclusion observable instead of
inferring protection from redundant computation. Shared constants, correlated
instruction faults and physical common-mode mechanisms remain outside the
bounded claim; no echo/output-value heuristic was added.

The evidence-enabled library suite passes on Rust 1.90.0 and 1.99.1 and under
ASan/LSan (133 passed, one separately ignored exhaustive campaign). The
ordinary all-feature suite, strict Clippy, `no_std` Cortex-M compile check,
formatting and release-plan checker also pass. This is source-only negative
control evidence; it does not admit a release build or qualify C1/DC1.

## Thirty-third implementation slice: current native transaction branch

The private x86-64 transaction checker initially failed closed on the current
secret-call artifact: its former exact `or` branch pattern no longer matched
the compiler output. The checker now accepts only that historical pattern or
the observed `transaction::validate` call followed by a one-byte success
assignment, `test %al,%al`, and `jne`. It recognizes the two observed success
registers separately and rejects missing, duplicated or changed patterns.
The combined-decision injection still targets the actual branch, and a fresh
permit check must reject the tampered destination. Parser regressions cover
both new register shapes and pattern substitution; unknown metadata fails
closed. No production Rust or public API changed in this slice.

On each of the then-current Rust 1.90.0 and 1.99.1 optimized x86-64 test ELFs,
the native transaction runner reproduced 9 public and 11 secret declared
outcomes; the native permit runner reproduced 3 public and 3 secret outcomes.
The transaction and permit runner unit suites passed 10 and 5 tests. These
are working-tree, `brynja_fault_primitives`-only test artifacts, with no
`brynja_fault_evidence` source hooks. Their SHA-256 identities are:

```text
643279f738c9b73441f0ad6075ffcab1c2b1a29157847be81cafee01ec19e191  Rust 1.99.1  target/release/deps/brynja_crypto-0e319f9c26ea36b6
fb069c86c9836571601b1af786a9f815dc80b88f4f42d55a1895c9935b292342  Rust 1.90.0  target/release/deps/brynja_crypto-9fa6fd47f68fcc2f
```

Rebuild from the intended source and use the executable path Cargo reports;
the paths above are local identifiers, not stable release artifact names.
These finite debugger observations are neither a complete C1/DC1/L1 campaign
nor exact-build admission, physical-fault qualification or a release pass.

## Thirty-fourth implementation slice: secondary AESAVS multi-block answers

The private independent secondary engine now checks the frozen AESAVS ECB MMT
response files for AES-128/192/256. The test parses every declared field and
record, checks both directions, and applies each schedule to all consecutive
independent blocks in its record twice. All 60 records and 330 blocks match the
published expected bytes; this is not an ECB mode or protocol API. Parser
regressions for each width reject missing, extra, malformed and wrong-width
records. The fixtures are the existing pinned files in
`assurance/aes-avs/fixtures/`, not new downloads or generated expectations.

The two focused tests passed on Rust 1.90.0 and on optimized Rust 1.99.1;
the ordinary 86-test library suites passed on both compilers, and the
evidence-enabled Rust 1.99.1 suite passed 135 tests with one separately
ignored exhaustive campaign. Strict Clippy and formatting checks passed.
This is functional coverage of the secondary engine only. The separately
executed Monte Carlo/key-update chain follows; a supported composite release
artifact, native fault qualification, timing and the public opt-in profile
remain unfinished.

## Thirty-fifth implementation slice: secondary AESAVS Monte Carlo chains

An explicit optimized test now parses the frozen ECB MCT response files for
AES-128/192/256 and performs all 100 records per direction and width. It
checks every record's chained key and input, runs exactly 1,000 secondary
block transforms with one expanded schedule per record, checks the final
output, and derives the next key from the penultimate and final outputs as
specified for each width. This is 600 records and 600,000 transforms per
compiler run. The test is ignored by routine test invocations because a
debug-profile run would be disproportionately slow; it is run explicitly in
release mode. Parser and key-update regressions remain routine tests.

The complete optimized campaign passed on Rust 1.90.0 and 1.99.1. Both use
the existing pinned `assurance/aes-avs/fixtures/` bytes; the test neither
downloads vectors nor creates expected outputs from the primary engine.
Reproduce explicitly on either pinned toolchain (shown for 1.99.1):

```sh
cargo +1.99.1 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block fault_integrity::cipher_avs_tests::all_frozen_monte_carlo_chains_both_directions -- --ignored
```

The ordinary Rust 1.99.1 library run passed 87 tests with this one campaign
ignored; strict no-deps Clippy, formatting and the release-plan checker pass.
These are secondary-engine functional answers, not composite owner or
fault-injection qualification. C1/DC1/L1, exact-build admission, public API,
timing and independent implementation review remain unfinished.
Adding this test module changes the test executable; the earlier native
observations remain tied to their recorded hashes and must be repeated on any
new candidate artifact before they can support that artifact.

## Thirty-sixth implementation slice: composite-owner multi-block answers

The same frozen MMT corpus now runs through both private owner lifetimes,
not just the secondary engine. All 60 records are checked once with a cached
owner and once with an operation-local owner, covering AES-128/192/256 and
both directions. Exact counters require 120 imports, 660 secret-output calls
and 330 explicitly acknowledged public-encryption calls. Each result is
checked against the frozen answer, not against another owner.

Secret blocks alternate explicit clearing and ordinary Drop; both leave the
admitted destination zeroed. The same owner processes successive blocks and
public/secret calls. Separate caller key borrows clear on owner Drop, while
prefix/suffix guard bytes around key storage and output stay unchanged. These
are observable caller-buffer lifecycle assertions, not a claim to observe all
internal schedules, compiler copies, registers or physical erasure.

Ordinary library suites passed on Rust 1.90.0 and 1.99.1 (88 passed, one
explicit Monte Carlo campaign ignored). The evidence-enabled Rust 1.99.1
suite passed 137 tests with two explicitly separate campaigns ignored;
strict no-deps Clippy and formatting also pass. No production code or public
API changed. Composite-owner Monte Carlo chains follow in the next slice;
exact-build/fault-model qualification remains unfinished and old native
receipts remain artifact-bound.

## Thirty-seventh implementation slice: composite-owner Monte Carlo chains

The frozen MCT corpus now runs through both private owner lifetimes for all
three widths and both directions. Each lifetime independently follows all
100 chained records per direction and width, without reseeding from later
published keys or inputs. Each record uses 1,000 secret-output calls and
checks its final result against the frozen answer. Per compiler this is
1,200 imports and 1,200,000 owner calls, exercising both AES engines together.
Every call checks explicit clearing or Drop of the secret destination and its
guard bytes; every import checks clearing and guards of both caller key borrows
on owner destruction. Internal spills/registers are not observed by this test.

The explicit optimized campaign passed on Rust 1.90.0 and 1.99.1 with
`brynja_fault_primitives` enabled and source-injection hooks disabled:

```sh
RUSTFLAGS='--cfg brynja_fault_primitives' cargo +1.99.1 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block retained::avs_tests::monte_carlo::frozen_monte_carlo_chains_through_both_owners -- --ignored
```

Repeat with `+1.90.0`. The campaign is intentionally ignored in routine runs
to avoid debug-profile cost. Ordinary suites passed 88 tests on each compiler
with two explicit campaigns ignored; the evidence-enabled 1.99.1 suite passed
137 tests with three explicit campaigns ignored. Strict no-deps Clippy and
formatting pass. Public-output behavior remains separately covered by MMT;
this MCT campaign exercises secret output in both directions.

The finite native transaction and permit observations were refreshed on these
same primitive-only x86-64 test ELFs: 9 public and 11 secret transaction outcomes
and 3 permit outcomes per path reproduced on each. Artifact SHA-256 identities:

```text
991a743625cad0395d4384a19d4bf6521091566eaf4b3029fba719ac3e630434  Rust 1.99.1  target/release/deps/brynja_crypto-0e319f9c26ea36b6
b73c4ac98959f0e5bcc5b67e21bfc80e30766d891d93d7850876af036d887d4b  Rust 1.90.0  target/release/deps/brynja_crypto-9fa6fd47f68fcc2f
```

Only those finite native observations were repeated, not every earlier fault
campaign. These working-tree test artifacts are not admitted release builds.
Full C1/DC1/L1, exact-build admission, timing, public API and independent
implementation review remain unfinished; no physical-fault claim is added.

## Thirty-eighth implementation slice: substitution skip plus forged write status

The native round-skip runner now accepts `--bypass-write`. After skipping one
secondary substitution call, it stops at the integrated `guarded_write` entry
and confirms that the primary result equals the public FIPS answer while the
secondary result differs. It then confirms a failing return with unchanged
destination bytes and forges the return status to success. A later intact
validation must still reject, retire and preserve/clear the appropriate output;
the fixture also checks subsequent no-success behavior and key-buffer cleanup.
This is one selected call-skip plus one return-register event, not arbitrary
instruction-level S1/DC1 coverage. In particular, the primary result remains
correct here; this does not establish coverage of faulty primary output.

On the two primitive-only artifacts hashed in the preceding slice, all 36
substitution positions across AES-128/192/256 reproduced for each of the two
owner lifetimes and three output paths: 432 selected combined outcomes across
both compilers. The ELF bytes remained unchanged. The original no-bypass
baseline also reproduced for all widths on each compiler. The runner's five
unit tests check exact event sequences, genuine skip requirements, failed
write status, forged status, rejection, missing/duplicate markers and path
separation. Raw debugger transcripts remain suppressed.

Not every attempted run was confirmed. The first helper target (`copy_fresh`)
was inlined, so setup rejected it; the experiment explicitly targets the
separately identifiable `guarded_write` stage instead. Three concurrent full
invocations subsequently failed native transcript confirmation (1.99.1 cached
decrypt at AES-128 step 1; 1.99.1 ephemeral public at AES-192 step 9; 1.90.0
cached public at AES-256 step 6). Those invocations are not counted as passes.
The same complete combinations later reproduced serially without weakening
validation; the concurrent confirmation failure's cause is not established.
Status-only count diagnostics were added for future investigation. These
development observations are not a release gate or complete qualification.

Reproduce serially using each recorded artifact, owner and path:

```sh
python3 scripts/aes/check-aes-fault-round-skip.py --binary PATH_FROM_CARGO --owner cached --path public --bypass-write
```

Repeat for `ephemeral`, `encrypt`, `decrypt` and the other compiler. This slice
changes tooling/documentation only; no cryptographic implementation or public
API changes, no supported-build admission and no physical claim are made.

## Thirty-ninth implementation slice: primary-result mutation plus bypass

The new `check-aes-fault-primary-output.py` runner stops at the integrated
guarded-write stage and confirms that both result replicas match the frozen
FIPS answer. It changes one selected primary-result byte with XOR 1, confirms
that only that replica changed, and observes the stage reject without changing
the destination. In the combined case it then forges that stage's return
status to success; an intact later validation must still reject and retire.
The owner fixture checks public rollback or secret clearing, rejection of later
calls, and key-storage cleanup. Unlike the preceding secondary-skip experiment,
the primary result proposed for release is demonstrably wrong in these cases.

The final runner configuration reproduced all 1,188 selected outcomes on the
two primitive-only x86-64 artifacts hashed in slice 37: 36 healthy baselines,
576 primary-only mutations and 576 mutations combined with a forged status.
This covers all 16 final-result byte positions, three widths, three output
paths, two owner lifetimes and both compilers. Each mutation is only XOR 1;
this does not cover every replacement value, other intermediate sites, all
bypass locations or the complete D1/DC1 model. The executable bytes were not
patched and their recorded hashes remain unchanged.

One initial serial invocation (1.99.1 cached encrypt, AES-192 combined byte 9)
was unconfirmed: all required fault/owner markers, two breakpoint stops and
normal exit were present, but the exact test-summary line was not matched.
It is not counted as a pass. Forty focused diagnostic repetitions and a full
current-compiler matrix did not reproduce the reporting failure. The final
runner disables optional GDB thread notices to reduce output interleaving;
it does not relax summary or outcome validation. The precise original cause
is not established. Both full final matrices completed serially without that
failure; no automatic retry was added.

Five runner regression tests check selected-byte mutation, primary-only writes,
mandatory failed return before bypass, exact event sequences, retirement,
wrong-path/outcome rejection and quiet rejection of invalid artifacts. These
mock transcripts are harness tests, not additional native fault evidence.

```sh
python3 scripts/aes/check-aes-fault-primary-output.py --binary PATH_FROM_CARGO --owner cached --path public
```

Repeat for `ephemeral`, `encrypt`, `decrypt` and each compiler artifact. Omitting
`--byte` selects all 16 positions; an explicit byte runs only that position and
the baseline. This tooling-only slice neither admits a release build nor changes
the production AES implementation. Complete fault qualification, timing, public
API admission and independent implementation review remain unfinished.

## Fortieth implementation slice: release-obligation reconciliation

The design and release plan now link one current closure checklist. It separates
the demonstrated functional vector/lifecycle results from unfinished full-model
qualification, exact-build admission, the public API, scoped operational tests,
new-profile timing and independent implementation review. The immediate next
qualification deliverable is a candidate fault-site inventory with explicit
mutation/bypass pairings and per-artifact mappings. Existing selected native
experiments are inputs to that inventory, not proof that its coverage is complete.
Missing required sites remain open; no accepted guarantee or exclusion changed.

The stale statement that the workbench is test-only was corrected: private
non-test development builds type-check it, but their admission set remains empty.
No production code, API or release-gate behavior changed in this documentation
slice, and no new experiment was counted as evidence.

## Forty-first implementation slice: checked source candidate inventory

`assurance/aes-fault-sites.json` identifies 22 open source regions covering the
candidate D1/D2/D3/D4/S1/L1/C1 paths, with a separate open DC1 pairing obligation.
It records mutation families, integrity outcomes, owner lifetimes, source anchors,
runner references and the work required to expand each region into concrete
cases. Nine regions include designated-bypass candidates. These are region
counts, **not** enumerated fault-site counts or qualification results.

The map follows both import and use, independent primary/secondary computations,
operation-local recapture, inner/outer completion and final handoff. The actual
secret destination remains distinct from its private staging write. Domain-local
constant integrity relies on output comparison; ineffective persistent faults
may continue producing correct filtered outputs under the accepted residual.
Nothing reinstates a runtime-immediate validation or echo-rejection requirement.

The optional checker rejects inconsistent bookkeeping while explicitly reporting
zero qualified configurations. Twelve regression tests cover duplicate IDs/JSON
keys, missing classes/scopes, malformed DC1 references, stale/ambiguous anchors,
unknown mutation/outcome references, unsafe file paths, symlinks, attempted
qualification promotion and bounded non-sensitive CLI output. It validates all
checked-in source and runner references. It does not establish that the candidate
list is complete, that an anchor's surrounding code is unchanged, or that a
listed runner has executed successfully. The current-format checker deliberately
rejects nonempty artifact mappings rather than treating an arbitrary hash as
qualification.

Next, expand the regions into the exact operation/byte/instruction and bypass
pairings required by the reviewed model, then map them to an exact candidate
configuration. Emitted mappings, complete coverage and admission remain open.
No Rust source or executable changed in this slice; no fault experiments were
rerun or added to the evidence totals. The existing review records retain their
artifact-specific limitations and unconfirmed attempts. No new publication gate,
dependency or public API was added.

Validation: all 105 tests across the 13 `test-aes-fault-*.py` scripts passed
when each script was executed directly, including the 12 new inventory tests.
The source-inventory checker and release-plan checker passed, and
`git diff --check` was clean. Python's default discovery skipped these
hyphenated script names (zero tests), so that discovery invocation is not counted
as validation. No Rust or native qualification rerun was needed for these
tooling/documentation-only changes.

## Forty-second implementation slice: two-replica capture case expansion

The first concrete source-case expansion now covers both returns from
`capture::pair`'s independent core copies. Previously the capture source hook
ran only after the first copy; a second checkpoint now runs after the second
copy. Both hooks require **both** `cfg(test)` and `brynja_fault_evidence` and
are absent from ordinary and private non-test builds. No Cargo feature enables
them. Existing first-copy fixtures retain their original selection behavior.

Three populations are defined in the inventory, with deterministic case labels
and matching Rust tests:

| Source population | Exact selection | Observations per compiler |
| --- | --- | --- |
| Copy boundaries | Widths 16/24/32 bytes, both replicas, every byte; XOR 1–255, replacement/AND/OR 0–255; uniform source byte `0x42` | 147,312 trials: 137,376 changed replicas, 9,936 unchanged; source, other replica and destination guards preserved |
| Shared import validation | Same selection through `Keys::new_profile`, before either schedule is expanded | 147,312 trials: 137,376 rejected imports, 9,936 unchanged accepted imports; both admitted regions clear on rejection or drop, guards preserved |
| Owner/output propagation | All three widths, both replicas, all 16 input positions, both owner lifetimes and all three output paths; XOR 1 or unchanged replacement `0x24` | 1,152 trials: 576 retire with public rollback/secret clearing and no later computation; 576 unchanged captures retain ordinary successful use |

The copy helper itself does not detect or retire faults: that row observes
isolation and mutation semantics, not fault rejection. The import test exercises
the common raw-key admission routine, not every cached constructor/expansion
handoff. The owner row uses a distinct uniform `0x24` block and uniform `0x42`
key. A healthy baseline is collected before each selected mutation; secret
outputs are cleared by the existing test helper. These are finite public
fixtures, not exhaustive key/input coverage. Effective and ineffective counts
are retained separately; unchanged captures are not counted as detected faults
or as confidentiality evidence. AND/OR populations include all single-bit
stuck-at cases, which also have explicit truth-table tests over every original
byte. Second-copy error, unwind and out-of-range mutation selection are tested.

The inventory's 295,776 labels describe these three source populations, not
independent physical experiments. The checker validates ranges, dimensions,
mutation-family identity, references and counts. Four additional Python tests
check stable/unique enumeration and reject malformed ranges, duplicate families,
unmapped sites, accidental scope reduction and attempted qualification promotion.
The case definitions are not execution receipts. They intentionally retain the
`source-only-emitted-open` status.

This changes evidence-build code generation. It does not refresh the linked
artifact observations in earlier slices, which remain specific to their recorded
hashes. No instruction-level experiments were run or inferred here. The new
checkpoint is after a source-level copy, not an injection into that copy's
emitted loads/stores. The local-key recapture and complement windows, actual
destination-write faults, all remaining mutation sites and DC1 combinations
remain open, as do qualification and production admission.

Reproduction (repeat with `+1.90.0` for the minimum supported compiler):

```sh
RUSTFLAGS='--cfg brynja_fault_primitives --cfg brynja_fault_evidence' cargo +1.99.1 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block capture -- --quiet
python3 scripts/aes/check-aes-fault-sites.py
python3 scripts/aes/test-aes-fault-sites.py
```

The capture-filtered run contains 15 tests, including all five new Rust tests;
zero tests would not reproduce this slice. No secret/debugger dumps are needed.

Validation completed on Rust 1.90.0 and 1.99.1: all 15 capture-filtered tests
and the full instrumented unit suite (142 passed, three existing explicit
campaigns ignored) passed on each compiler. Strict no-dependency Clippy for the
library/tests with both evidence cfgs passed on both compilers. On 1.99.1, the
ordinary no-cfg suite passed 88 tests with two existing campaigns ignored; the
primitive-only suite passed 96 with two ignored. The private non-test release
build also type-checked with all three development cfgs, retaining the double
test/evidence guard and empty production admission. All 109 Python fault-tooling
and model tests passed, including 16 inventory tests. Formatting, release-plan
consistency, source-inventory validation and diff-integrity checks passed.

## Forty-third implementation slice: exact capture-chain mapping

The optional `check-aes-fault-capture-map.py` now maps the actual x86-64 chain
from `capture::pair` through `copy_secret_region` to the opaque `copy_bytes`
leaf. It first requires a complete, exact instruction shape for all three
functions, including local branch targets, direct call targets, length admission,
argument movements, return encoding and the copy loop. It records offsets for
both calls and their continuations, the leaf loads/stores and returns, bound to
the whole ELF hash. It does not infer a convenient instruction from a nearby
symbol or accept wildcard register/branch patterns.

Two paired shapes were observed: the current-compiler artifact holds the common
source in `r14` and the second destination in `r15`, with wrapper success encoded
as `0xff`; the rebuilt minimum-compiler artifact holds those pointers in `r15`
and `r14`, with success encoded as `0x04`. These are private Rust ABI observations,
not stable ABI promises. Each pair of calls passes the original common source
and a separate destination to the core wrapper, which forwards them to the
opaque copy leaf. The leaf performs fresh source loads on each invocation.
Mixed caller/wrapper encodings, changed operations and unknown shapes reject.

Runtime observations use four hardware breakpoints, without software breakpoint
patches or data/register mutation. They check full source/replica ranges and
contents, independent destinations, equal lengths, the exact saved return
addresses at both wrapper entries and leaf returns, and successful capture
completion. Only public FIPS fixtures run. The existing owner fixture then checks
the expected AES result, healthy reuse and storage cleanup. The observer requires
the source-injection flag to be false and one successful fixture execution; missing
or duplicate checkpoint/outcome lines do not pass. Raw debugger output is captured,
not printed. The ELF bytes must remain unchanged across the run.

The final runs reproduced **36 baseline cases on each compiler**: three key
widths, two owner lifetimes, three output paths and key/input capture selection.
All six checkpoints were confirmed in each case. No fault was injected. The
16/24/32-byte lengths exercise the word-copy loop; the byte-tail loop is mapped
statically but not exercised by this population. A return-boundary observation
is not evidence for every byte fault during the emitted store.

The exact hashes, symbols/offsets, shape digests, baseline case labels and selected
working-tree source snapshots are retained in
[`aes-fault-capture-map-observations.json`](../../assurance/aes-fault-capture-map-observations.json).
Those snapshots are not a complete build identity or reproducible-build
attestation. The artifacts are release-profile **test** ELFs, not downstream
production artifacts. The empty production admission set is unchanged.

Failed setup attempts are retained rather than counted as observations. The first
current-compiler invocation stopped on its first case because four debugger
return-address comparisons could not evaluate a function-value cast. Two
diagnostic repetitions confirmed the same expression error. Explicit function
address casts fixed it, with a regression check; no outcome predicate was relaxed.
The rebuilt minimum-compiler artifact initially failed static shape recognition.
Inspection established its different register/return encoding, so a second exact
paired pattern was added. Neither setup failure counts toward the 72 final cases,
and no automatic retries were added.

Thirteen new Python regression tests cover both shapes, hashed symbols, exact
event offsets, missing/duplicate/aliased symbols, changed or missing instructions,
wrong source/destination flow, branch/call target changes, mismatched return
encodings, every required runtime marker, source-hook rejection, fixture/population
validation, observation-only command construction, malformed artifacts and quiet
subprocess failures. Mock transcripts test the tooling, not the native model.

```sh
RUSTFLAGS='--cfg brynja_fault_primitives' cargo +1.99.1 test --locked --release -p brynja-crypto --lib --features hazmat-aes-block --no-run
python3 scripts/aes/check-aes-fault-capture-map.py --binary PATH_FROM_CARGO --json
python3 scripts/aes/test-aes-fault-capture-map.py
```

Repeat with `+1.90.0` and its Cargo-emitted ELF path. This is optional development
mapping, not a verification pass or new release gate. Complete D3/DC1 pairings,
import/complement/local-recapture windows, remaining emitted sites, timing and
independent implementation review remain open. No Rust source or API changed in
this slice, and earlier native records remain bound to their own artifact hashes.

Validation: all 122 tests across the 14 Python fault-tooling/model scripts
passed, including the 13 new mapping regressions. The source-inventory and
release-plan checkers passed and `git diff --check` was clean. Both recorded
ELF hashes and every selected source snapshot were checked against the local
files after recording. No new Rust test build or native observation is labeled
production qualification.

## Forty-fourth implementation slice: native input-store faults and completion bypass

`check-aes-fault-copy-store.py` extends the exact capture-chain mapping to a
finite mutation at the actual word-store instruction. It selects either input
replica, one of its two word-store visits and one byte lane in the loaded word.
Immediately before the store it checks the instruction location, source and
destination pointers, copy offset/remaining length, loaded fixture word, and
partially copied destination. It changes only the selected byte's low bit in
the register, single-steps the mapped store and checks the actual destination
and next instruction location. The original source and other replica must remain
unchanged. It then observes the completed capture pair to confirm that exactly
the selected byte differs and all subsequent copy writes completed normally.

The runner uses hardware breakpoints and one-instruction stepping, with one
breakpoint slot recycled so no more than four are live. No command patches
executable bytes or directly edits the destination to impersonate the store.
All values are public FIPS fixtures; raw debugger output stays captured. The
artifact bytes on disk are checked unchanged after the full campaign.

The selected combined case then stops at the real `Retained::compute` return.
The input mismatch must have produced an error **before either AES result was
computed**, with both result buffers and the completion codeword still zero.
Only then is that return status forged to success. The real enclosing owner must
still reject, restore the public destination or clear the secret destination,
retire permanently and refuse subsequent operations; the existing owner fixture
checks those outcomes and key-storage cleanup. This tests a selected status
bypass with an unmarked completion record, not a bypass of every release check
or a case where a faulted AES result has already been computed.

The exact selection was fixed before running: three AES widths, both owner
lifetimes, public encryption/secret encryption/secret decryption, both input
replicas, and all 16 byte positions. Each group has one unchanged baseline at
byte zero, 16 XOR-1 store faults and those same 16 faults combined with the
failed-return bypass. Both compiler artifacts completed their full populations:

| Compiler command | Healthy baselines | Store fault only | Store fault plus selected bypass |
| --- | ---: | ---: | ---: |
| Rust 1.99.1 | 36 | 576 | 576 |
| Rust 1.90.0 | 36 | 576 | 576 |

All healthy cases produced the expected result and remained reusable. All
faulted cases rejected and retired. There were no failed/unconfirmed native
invocations in these two final runs and no automatic retries. These are 2,376
finite development cases, not a complete fault-model result. Only XOR 1 is
covered, only on these public keys/blocks and input-copy stores; no key-import
store, arbitrary mutation family or other C1 site is covered by this campaign.

[`aes-fault-copy-store-observations.json`](../../assurance/aes-fault-copy-store-observations.json)
records the exact ELF hashes, capture instruction mappings, computation symbol/
return offset and instruction digest, selection, per-group counts and selected
source snapshots. Capture helpers require the exact paired code shapes from the
preceding slice. The computation helper additionally requires a unique symbol/
return and runtime argument/result/completion checks; it is **not** a complete
static verification of that helper. These are release-profile test ELFs with
source fault hooks disabled, not qualified production binaries. Local snapshots
and observation files are not signed receipts or complete build attestations.

Nine new Python regression tests check store-successor mapping, every replica/
word/lane selection, untouched baselines, required failed returns before forging,
register-only writes, all transcript markers and retirement outcomes, exact case
populations, invalid selections/artifacts, immutable artifacts, no retry, and
quiet failure reporting. Mock transcripts do not add native fault evidence.

```sh
python3 scripts/aes/check-aes-fault-copy-store.py --binary PATH_FROM_CARGO --json
python3 scripts/aes/test-aes-fault-copy-store.py
```

Use the primitive-only test artifacts and build command recorded in the previous
slice, separately for both compilers. All 131 tests across the 15 Python
fault-tooling/model scripts passed. The source-inventory and release-plan checks
passed, and `git diff --check` was clean. No Rust source, public API, dependency,
admission rule or release gate changed. Full emitted-site coverage and DC1
pairings, timing and independent implementation review remain open.

## Forty-fifth implementation slice: native key-import store faults

Added dedicated native-import fixtures for the cached and operation-local
owners at all three AES widths. Unlike the existing operation fixtures, they
inspect a constructor rejection directly: no owner is returned, both admitted
key buffers clear, the original caller key and surrounding storage guards
remain unchanged, and the output sentinel is untouched. Healthy imports exercise
public encryption, secret encryption and secret decryption against public FIPS
answers, including secret-output clearing and eventual key-buffer clearing.
Import rejection is not retirement of an already-created owner.

`scripts/aes/check-aes-fault-import-store.py` uses the preceding exact capture
mapping and hardware breakpoints to select each key-copy word store. It observes
the original source, both destinations, disjointness, lengths and guards before
the copy. At the selected store it checks the partial copy, changes only the
chosen register byte with XOR 1, steps the store once and verifies the actual
destination write. At capture-pair return it verifies the full copied regions,
unchanged caller source and exactly one changed replica byte. This happens
before complement encoding; no source hook, executable-byte patch or direct
destination mutation supplies the injected fault.

The fixed selection covers both replicas, every key byte, AES-128/192/256 and
both owner lifetimes, with one unchanged baseline per width/owner/replica group:

| Compiler command | Healthy imports | Rejected imports with cleanup |
| --- | ---: | ---: |
| Rust 1.99.1 | 12 | 288 |
| Rust 1.90.0 | 12 | 288 |

Both complete native populations passed, with no failed/unconfirmed invocations
in these campaigns and no automatic retries. These 600 cases cover selected
single data faults only. They do **not** cover import-validation bypasses or
DC1 combinations, arbitrary mutation values, other caller keys, later
complement/recapture windows, other architectures or physical fault behavior.

[`aes-fault-import-store-observations.json`](../../assurance/aes-fault-import-store-observations.json)
records exact artifact hashes, capture mappings, group counts, reproduction
commands and selected source snapshots. Both rebuilt artifacts match the known
paired capture-code shapes without relaxing the matcher. Source fault hooks are
disabled in these optimized test ELFs. The new fixtures change the ELF hashes;
earlier observation records remain bound to their own binaries and must not be
presented as new-build passes. Local snapshots are neither complete build
attestations nor authenticated execution receipts.

Nine runner regression tests cover key-width/word/lane selection, untouched
baselines, checkpoint and cleanup requirements, correct constructor outcomes,
source-hook rejection, complete populations, invalid or changed artifacts,
unknown code shapes, no retry and quiet failure reporting. A separate source-hook
test exercises 12 selected constructor-rejection cleanup paths; it does not add
native binary evidence. The native fixtures intentionally allow either outcome
internally, while the observer requires acceptance for baselines and rejection
for every selected mutation. A passing fixture alone is not a fault result.

```sh
python3 scripts/aes/check-aes-fault-import-store.py --binary PATH_FROM_CARGO --json
python3 scripts/aes/test-aes-fault-import-store.py
```

Use the primitive-only build command recorded with the observations, separately
for both compilers. Validation passed: 102 primitive-only Rust tests per compiler,
149 instrumented Rust tests per compiler, 94 ordinary Rust tests on 1.99.1, strict
scoped Clippy with both cfgs on both compilers, and all 140 tests across 16 Python
fault-tooling/model scripts. Ignored development fixtures remain ignored; these
counts are not a claim that every fault campaign ran. Formatting, source-inventory,
release-plan and diff-integrity checks also passed.

This slice changes test fixtures, tooling, observation records and documentation,
not production AES arithmetic, dependencies, public APIs or release gates. The
inventory remains open and production admission remains empty. The next import
obligation is mapping and testing validation/status bypasses with corrupted key
data; full site coverage, DC1, final-linked qualification, timing and independent
implementation review are still unfinished.

## Forty-sixth implementation slice: cached-import decision bypass

The preceding key-store campaign is now extended with one explicit inlined
import-decision bypass for the cached owner. The source checks captured keys
inside `Keys::new_with_fixture_profile`, then checks them again when constructing
the cached schedules in `Retained::from_captured`. The operation-local constructor
has a different continuation and is intentionally not counted in this experiment.

An initial attempt to stop at the standalone `Keys::validate` function did not
reach the intended import check: the compiler had inlined it into the constructor.
Two baseline campaign attempts per compiler aborted unconfirmed; four diagnostic
baseline invocations on 1.99.1 investigated the missing stops and address mapping.
A separate diagnostic Python import-path error never started the debugger. None
is counted as a successful observation. The correction targets the actual
inlined decision; no production function was forced out of line to manufacture
a convenient test site, and no Rust source or fixture changed.

`scripts/aes/check-aes-fault-import-bypass.py` retains the exact capture-chain
mapping and key-copy observations. It additionally requires a unique constructor
symbol/return and one specific local decision sequence: comparison-accumulator
scratch storage, its clearing call and readback, and the accumulator test followed
by the constructor's rejection/success branch. Unknown or ambiguous shapes abort.
The full constructor is not statically qualified by this local pattern.

After the selected store mutation and completed capture, the runner stops just
before the actual accumulator test. It checks both encoded replicas, the intact
caller key and guards, cleared comparison scratch and the original decision.
For a corrupted key the accumulator must still be exactly 1. Only then does the
combined case force that decision register to zero. It neither repairs either
key replica nor changes executable bytes. The cached constructor must still
return `ImportRejected`, clear both admitted key buffers and leave the output
sentinel and source/guards unchanged. No owner is returned, so this is rejection
and cleanup rather than retirement of a usable owner.

The fixed population includes all key bytes in both replicas and AES-128/192/256:

| Compiler command | Baselines | Healthy forced-success controls | Store faults | Store faults plus decision bypass |
| --- | ---: | ---: | ---: | ---: |
| Rust 1.99.1 | 6 | 6 | 144 | 144 |
| Rust 1.90.0 | 6 | 6 | 144 | 144 |

All 600 cases in the corrected campaigns completed. Healthy controls return
usable owners and exercise all three block paths; every selected corrupted
import rejects with cleanup, including the 288 combined cases. The healthy
forced-success control writes zero to an already-zero accumulator; it is not
separate instruction-skip coverage. There are no automatic retries. Completed
campaigns and earlier unconfirmed setup attempts are recorded separately in
[`aes-fault-import-bypass-observations.json`](../../assurance/aes-fault-import-bypass-observations.json).

The record binds the same two primitive-only optimized test ELFs used by the
preceding import-store experiment, with exact binary hashes, instruction/site
metadata and selected source snapshots. Source hooks remain disabled. This is
one finite cached-import DC1-like pairing on public fixture keys, not full C1/DC1
coverage, a production build attestation or physical-fault qualification. Other
comparison sites, constructor propagation, mutation families, complement windows
and operation-local behavior remain open. The initial missed-stop attempts also
demonstrate why a source-level check name alone cannot identify emitted coverage.

```sh
python3 scripts/aes/check-aes-fault-import-bypass.py --binary PATH_FROM_CARGO --json
python3 scripts/aes/test-aes-fault-import-bypass.py
```

Eight new Python regression tests cover both emitted symbol spellings, the
inlined-decision shape, every byte/replica selection and register mutation,
required original decisions, checkpoint/cleanup/outcome markers, source-hook and
bad-execution rejection, exact populations, changed/unknown artifacts, no retry
and quiet failure reporting. All 148 tests across 17 fault-tooling/model scripts
passed, along with source-inventory, release-plan and diff-integrity checks.
Mock transcripts are runner tests, not additional native observations.

No production Rust, cryptographic arithmetic, public API, dependency, admission
rule or release gate changed. Production admission and whole-artifact qualified
mappings remain empty. The next distinct obligation is the operation-local
constructor/use boundary after a bypassed import check; the wider site inventory,
DC1 pairings and implementation qualification remain unfinished.

## Forty-seventh implementation slice: operation-local import/use boundary

The operation-local owner differs from the cached owner after key import. Its
constructor retains two key replicas but defers schedule creation and further
key checks until use. A private native fixture now distinguishes three outcomes:
rejected at import with no owner, accepted and reusable, or returned from import
but rejected and permanently retired on first use. It checks public encryption,
secret encryption and secret decryption separately, including unchanged public
output on rejection, cleared secret output, later `AlreadyRetired` results,
caller-key/guard integrity and clearing of both owned key buffers on drop.
The fixture's outcome alone is not evidence: the external runner fixes the
expected outcome for every selected case.

`scripts/aes/check-aes-fault-import-use.py` reuses the exact native key-copy
store and inlined import-decision mapping. For both key replicas, every byte of
AES-128/192/256 and all three operation paths, it selects one XOR-1 register
mutation immediately before the key-copy store. The combined case additionally
forces the import comparison's accumulator to zero after checking its original
failed value. It does not patch executable bytes, directly edit a key buffer,
skip first-use validation or enable source fault hooks.

| Compiler command | Baselines | Healthy bypass controls | Store faults | Store faults plus import bypass |
| --- | ---: | ---: | ---: | ---: |
| Rust 1.99.1 | 18 | 18 | 432 | 432 |
| Rust 1.90.0 | 18 | 18 | 432 | 432 |

Both complete native populations passed on the first attempt: 1,800 finite
cases, with no unconfirmed invocations counted and no automatic retries.
Corruption without the bypass rejected at import. Corruption with the selected
bypass returned an owner, but its first operation rejected without releasing a
faulted block and retired it. Later public and secret calls were refused. The
healthy bypass controls write zero to an already-zero decision register; they
are not independent instruction-skip evidence. These results do **not** mean
that a bypassed corrupted import always rejects during construction, nor that
key buffers erase immediately when the owner retires. The fixture verifies
their clearing when the owner is dropped.

[`aes-fault-import-use-observations.json`](../../assurance/aes-fault-import-use-observations.json)
records exact optimized test-ELF hashes, selected source snapshots, capture
and constructor-decision mappings, group counts and limits. The new fixtures
changed both ELF hashes, so older native observations remain bound to their
earlier artifacts. These are local working-tree observations, not complete
reproducible-build attestations, signed receipts or production qualification.

Eight new Python tests exercise path/byte/replica selection, import-versus-use
outcome distinctions, required event and cleanup markers, failure reporting,
complete populations, changed/unknown artifacts and no retries. A test-only
source-hook test separately exercises selected rejected-import cleanup paths;
source hooks were disabled in the observed native ELFs. The two primitive-only
Rust suites passed 111 tests each, and both instrumented suites passed 159
tests each. All 156 tests across 18 Python fault-tooling/model scripts and
strict scoped Clippy on both compilers passed. The ordinary Rust suite,
formatting, source-inventory, release-plan and diff-integrity checks passed.

```sh
python3 scripts/aes/check-aes-fault-import-use.py --binary PATH_FROM_CARGO --json
python3 scripts/aes/test-aes-fault-import-use.py
```

No production AES arithmetic, public API, dependency, admission rule or release
gate changed. The private workbench remains unqualified, with whole-artifact
admission mappings empty. Other import and first-use decision sites, mutation
families, full DC1 pairings and final-linked implementation review remain open.

## Forty-eighth implementation slice: post-encoding source matrix

Added one test-only checkpoint after the secondary key replica is complement-
encoded and before the first import validation. The source matrix covers all
bytes of both replicas at AES-128/192/256 widths with XOR masks, replacement,
AND and OR mutations. These are 147,312 selected source cases: 137,376 effective
mutations reject import; 9,936 ineffective mutations admit only the unchanged,
correct key. Every case checks the caller key, buffer guards and clearing of
both admitted key buffers after rejection or owner drop.

This checkpoint requires both `cfg(test)` and `brynja_fault_evidence`, changes
the instrumented binary and is absent from the primitive-only optimized ELFs
used for the preceding native observations. It is not evidence that emitted
complement-writing instructions have been located or faulted. The earlier native
records remain bound to their original artifact hashes and source snapshots.
No production profile is admitted from this source test.

An additional 1,728 source-only owner-path cases now propagate a selected
effective XOR-1 or ineffective same-byte replacement through both cached and
operation-local constructors, all key bytes in both encoded replicas, and public
encryption, secret encryption and secret decryption. Effective mutations reject
construction without touching the output. Ineffective mutations return owners
that produce the expected FIPS blocks; secret output clears on owner release.
Every case checks caller-key integrity, both admitted key-buffer clears on
rejection/drop and surrounding guards. These cases verify source behavior, not
native instruction faults or bypass pairings.

## Forty-ninth implementation slice: operation-local recapture source mutations

The operation-local owner now has a test-only checkpoint after its two per-call
copies of the retained primary and complemented key replicas, before creating
the temporary schedules. It is compiled only with `cfg(test)` and
`brynja_fault_evidence`; ordinary and earlier native observation binaries do
not contain it. The checkpoint changes test codegen and is not an emitted-site
fault experiment.

One bounded source test covers all 16/24/32 key bytes, both replicas, and
public encryption, secret encryption and secret decryption. At each position it
tries XOR-1, a same-byte replacement, an AND mask and an OR mask: 1,728 cases.
The 864 effective mutations reject without releasing output and permanently
retire the owner. The 864 ineffective mutations return the expected FIPS block
and leave the owner usable. Every case checks a single checkpoint hit,
unchanged persistent key replicas, public-output rollback or secret-output
clearing, caller-buffer guards and clearing of both retained key buffers on
owner drop. The test does not directly observe the temporary scratch after its
Drop; existing scratch-owner tests remain separate.

This source-only expansion does not establish emitted separation, cover a
within-copy fault or a bypassed recapture check, and is not counted as native
D3/DC1 evidence. The 22 candidate source families and nine bypass families
remain OPEN; whole-artifact qualification mappings and production admission
remain empty.

The instrumented release suites passed on Rust 1.90.0 and 1.100.0 (162 passed,
three ignored on each); the ordinary Rust 1.100.0 suite passed (103 passed,
two ignored). Strict scoped Clippy passed on both compilers. Formatting, the
source-inventory checker and its 16 regressions, release-plan validation and
diff-integrity checks also passed. The inventory's 295,776 formal source-case
labels are unchanged: this bounded recapture test is not yet an emitted-site
mapping or an additional inventory population.

## Fiftieth implementation slice: linked operation-local recapture baseline

The private [mapping runner](../../scripts/aes/check-aes-fault-local-recapture-map.py)
now accepts only two exact primitive-only x86-64 test ELF hashes. It checks the
reviewed `Ephemeral::compute` instruction shapes around both local key-copy
calls. Hardware breakpoints on each binary observed nine public-FIPS-fixture
baselines: AES-128/192/256 across public encryption, secret encryption and
secret decryption. The reviewed core wrapper and opaque copy leaf were also
mapped. Hardware breakpoints confirmed both leaf entries received the exact
source, destination and length passed by the operation-local caller, and both
leaf returns left the expected bytes in scratch. The first copy read the
retained primary key into one scratch range; the second read the separately
retained complemented key into another. The source/destination ranges did not
overlap, both copied values matched the fixtures, and each test completed
with the expected output and key-buffer cleanup. [The observation record](../../assurance/aes-fault-local-recapture-map-observations.json)
pins both linked binary hashes, call offsets and selected working-tree source
snapshots; it does not pretend those snapshots form a complete build identity.

For the same 18 baselines, hardware breakpoints and single-stepping also
checked every eight-byte word load, the register value at the following store,
and the destination word after that store. The 16/24/32-byte copies use two,
three or four word iterations per replica respectively. The copy leaf's
byte-tail branch is only statically mapped; these fixture lengths do not take it.

The runner never prints debugger registers or key bytes, and its five
regression tests cover changed call shape, missing leaf checkpoints, wrong
fixture outcome and unknown-artifact rejection. Both linked artifacts passed
all nine cases. This maps baseline call boundaries, leaf entry/return and
word-copy steps only:
no fault was injected at any observed word site or statically mapped byte site,
no C1/DC1 bypass was paired, and no production artifact, other target, or
compiler configuration is qualified. The 22 source families and nine bypass
families remain OPEN, with
no whole-artifact mappings or public fault-profile admission.

## Fifty-first implementation slice: partial emitted-site candidate map

The [candidate map](../../assurance/aes-fault-emitted-site-candidates.json)
now records the `local-key-copy` D3 family on the same two pinned development
ELFs. It binds each compiler's caller symbol and copy-call offsets to the
observed opaque-copy word load/store offsets. A strict
[validator](../../scripts/aes/check-aes-fault-emitted-sites.py) derives 252
stable width/path/replica/word context labels and checks them against the
recorded nine baseline cases per artifact. Its eight regressions reject
changed offsets, missing cases, reduced width/path coverage, duplicate
artifacts, qualification labels and invented fault results. The source
inventory links this partial record while retaining `artifact_mappings: []`.

The labels do not represent unique instruction addresses or injected faults.
They are a pilot for the complete candidate-site inventory, not a closure
claim: this one family remains OPEN, 21 other source families are wholly
unmapped, all nine bypass families remain OPEN, and no DC1 pairings or
production builds are qualified.

## Fifty-second implementation slice: current-toolchain capture boundaries

The existing exact-shape capture runner was repeated on the same primitive-only
Rust 1.90.0 and 1.100.0 test ELFs used for local recapture. It passed 36
read-only public-fixture cases per binary: all three key widths, both owner
lifetimes, three block paths, and separate key-import versus block-input
capture scopes. The [new current-artifact record](../../assurance/aes-fault-capture-current-observations.json)
pins both linked ELF hashes and selected working-tree source snapshots rather
than extending the older Rust 1.90.0/1.99.1 record's source context.

The [partial candidate map](../../assurance/aes-fault-emitted-site-candidates.json)
now binds `key-capture` and `block-capture` separately to those observed
capture-call and copy-return offsets, alongside the operation-local key-copy
word map. Its validator derives 540 deterministic context labels and nine
regressions reject changed family scope, artifact identity, offsets, result
claims and missing cases. All three families remain OPEN: this is baseline
call/return mapping, not within-copy fault injection, DC1 pairing, or
whole-artifact qualification. The other 19 source families and all nine
bypass families remain unmapped or OPEN, and public admission remains empty.

## Fifty-third implementation slice: retained pre/post validation calls

The private [read-only runner](../../scripts/aes/check-aes-fault-retained-validation-map.py)
now pins the two `Retained::validate` call sites in each exact x86-64 test ELF:
one before the primary/secondary transforms and one after them, before the
transaction can hand off output. Public-fixture hardware breakpoints and
single-stepping passed all three key widths, both owner lifetimes and all
three block paths on Rust 1.90.0 and 1.100.0: 36 baseline cases in all.
The [record](../../assurance/aes-fault-retained-validation-observations.json)
pins both linked hashes and selected working-tree source snapshots. Five
runner regressions reject missing/changed call shapes, incomplete markers,
unknown artifacts and unreviewed fixture identities.

The [partial candidate map](../../assurance/aes-fault-emitted-site-candidates.json)
now labels 612 baseline contexts across four still-OPEN source families; its
ten regressions reject forged retained-family status, missing call boundaries
and shrunken fixture scope. This observes healthy validation call order only.
It does not map the internal retained-key or schedule comparisons, inject a
persistent fault, establish D2 detection, cover DC1, or qualify a production
build. Eighteen other source families remain wholly unmapped, and all nine
bypass families remain OPEN.

## Fifty-fourth implementation slice: primary and secondary result boundaries

The private [read-only result runner](../../scripts/aes/check-aes-fault-result-map.py)
pins the primary transform's three width-specific calls and the separate
secondary transform call in each exact x86-64 test ELF. It checks the two
successful return boundaries against public AES answers, without printing
block data or altering the inferior. All three widths, both owner lifetimes
and all three paths passed on Rust 1.90.0 and 1.100.0: 36 baseline cases.
The [record](../../assurance/aes-fault-result-map-observations.json) pins both
binary hashes and selected source snapshots. Four runner regressions reject
changed call shapes, missing result/fixture markers and unknown artifacts.

The partial map now has 684 context labels over six still-OPEN source
families. Its 11 regressions reject forged result-family status, missing
return boundaries, shrunken baseline scope and a changed observation hash.
This is a healthy-result boundary observation, not a D1 fault outcome:
there was no result mutation, comparison bypass, output-withholding test or
physical injection. Sixteen source families remain wholly unmapped; all
nine bypass families are OPEN and no build is admitted.

## Fifty-fifth implementation slice: inner completion-codeword store

The private [read-only completion runner](../../scripts/aes/check-aes-fault-completion-map.py)
pins the emitted `Retained::compute` path in the same two exact x86-64 test
ELFs. It checks the post-use validation call, input-agreement branch and
store of the 16-byte inner completion codeword. Public-fixture breakpoints
confirm that the healthy record changes from zero to the expected codeword
in all three widths, both owner lifetimes and all three paths on Rust 1.90.0
and 1.100.0: 36 baseline cases. The [record](../../assurance/aes-fault-completion-map-observations.json)
pins binary hashes and selected source snapshots. Four runner regressions
reject changed store/guard shapes, missing markers and unknown artifacts.

The partial map now has 720 context labels across seven still-OPEN source
families. Its 12 regressions reject promotion of the completion family from
one observed inner store to a full lifecycle claim. This was not a fault
injection: outer completion, final permit, skipped branches, DC1 pairings
and physical faults remain unqualified. Fifteen source families remain
wholly unmapped, all nine bypass families are OPEN, and no build is admitted.

## Fifty-sixth implementation slice: operation-local outer completion handoff

The private [read-only outer completion mapper](../../scripts/aes/check-aes-fault-outer-completion-map.py)
pins the `Ephemeral::compute` call into `Retained::compute` and the later
outer codeword store in the same two exact x86-64 test ELFs. Public-fixture
breakpoints confirm that the inner marker changes first while the outer
marker remains zero, then the outer marker changes, across three widths and
three paths on Rust 1.90.0 and 1.100.0: 18 baseline cases. The
[record](../../assurance/aes-fault-outer-completion-map-observations.json)
pins the binary hashes and selected source snapshots. Four runner
regressions reject changed call/store shapes, missing markers and unknown
artifacts.

The partial map now has 738 context labels across the same seven still-OPEN
source families. Its 13 regressions reject promoting this healthy handoff to
a fault pass or silently shrinking its observation scope. No outer-check
bypass, final permit, DC1 pairing or physical fault was tested here. Fifteen
source families remain wholly unmapped, all nine bypass families are OPEN,
and no build is admitted.

## Fifty-seventh implementation slice: deny-first final-permit boundaries

The private [read-only permit mapper](../../scripts/aes/check-aes-fault-permit-map.py)
pins the fresh-receipt call and guarded state rewrite in both exact x86-64
test ELFs. Public-fixture breakpoints observe the actual destination and
lifecycle at entry, the denied state before guarded rewriting, and the
healthy return state. All three widths, both owner lifetimes and all three
paths passed on Rust 1.90.0 and 1.100.0: 36 baseline cases. The
[record](../../assurance/aes-fault-permit-map-observations.json) pins both
binary hashes and selected source snapshots. Four mapper regressions reject
changed denial/call/return shapes, missing markers and unknown artifacts.

The partial map now has 846 context labels across eight still-OPEN source
families. Its 14 regressions reject forged permit status, missing boundaries,
shrunken fixture scope and a changed record hash. These observations do not
map receipt internals, failed permits, bypass pairings, final handoff or
physical faults. Fourteen source families remain wholly unmapped, all nine
bypass families remain OPEN, and no build is admitted.

## Fifty-eighth implementation slice: paired guarded-write checks

The private [read-only readback mapper](../../scripts/aes/check-aes-fault-readbacks-map.py)
pins two distinct `guarded_write` calls into the same `transaction::check`
helper in both exact x86-64 test ELFs. Public-fixture breakpoints confirm
forward then reverse selectors, full 16-byte agreement with both computed
results, and healthy returns across three widths, both owner lifetimes and
three paths on Rust 1.90.0 and 1.100.0: 36 baseline cases. The
[record](../../assurance/aes-fault-readbacks-map-observations.json) pins the
binary hashes and selected source snapshots. Four mapper regressions reject
changed calls/selectors, incomplete markers and unknown artifacts.

On public routes the checked bytes are the actual caller destination. On
secret routes they are private staging; the later actual-destination check
remains a separate obligation. The two sites share an implementation and do
not establish independent fault detection. The partial map now has 918
context labels across nine still-OPEN source families; its 15 regressions
reject promotion to a bypass pass. Thirteen source families remain wholly
unmapped, all nine bypass families are OPEN, and no build is admitted.

## Fifty-ninth implementation slice: actual secret-destination validation

The private [read-only secret-destination mapper](../../scripts/aes/check-aes-fault-secret-destination-map.py)
pins the secret owners' staged write, later validation call and final permit
call in both exact x86-64 test ELFs. Public-fixture breakpoints distinguish
the private staging bytes from the caller's admitted destination. Admission
clears that destination first; at the later validation call, it holds the
computed 16-byte result and is the buffer passed to `transaction::validate`.
The same helper makes separate forward and reverse `transaction::check`
calls before permit. Three widths, both owner lifetimes and encrypt/decrypt
passed on Rust 1.90.0 and 1.100.0: 24 baseline cases. The
[record](../../assurance/aes-fault-secret-destination-map-observations.json)
pins binary hashes and selected source snapshots. The mapper and bookkeeping
regressions reject changed call shapes, missing observations, forged fault
status and a changed record hash.

This is a healthy-path emitted boundary map, not a destination-fault test.
The two checks share an implementation; failed validations, bypasses, final
handoff and physical faults remain untested. The partial map now has 1038
context labels across ten still-OPEN source families. Twelve source families
remain wholly unmapped, all nine bypass families are OPEN, and no build is
admitted.

## Sixtieth implementation slice: healthy secret-result construction

The private [read-only secret-result mapper](../../scripts/aes/check-aes-fault-secret-result-map.py)
pins the call to `Operation::complete` and the later result pointer/length
stores in both exact x86-64 test ELFs. Public-fixture breakpoints confirm
that the caller's secret destination still holds the computed result at the
completion call, that completion returns successfully, and that the returned
descriptor is populated with that destination and a 16-byte length. The
cached and operation-local owners have different cleanup/store ordering; the
mapper pins each rather than assuming a shared layout. Three widths, both
owner lifetimes and encrypt/decrypt passed on Rust 1.90.0 and 1.100.0: 24
baseline cases. The
[record](../../assurance/aes-fault-secret-result-map-observations.json) pins
the binary hashes and selected source snapshots. Four mapper regressions
reject changed completion calls or stores, missing markers and unknown
artifacts. The emitted-site validator also rejects forged fault status and
changed record hashes.

These are healthy-path construction observations only. They do not test the
failed completion branch, alteration after the last destination check, the
return into the external caller, a bypass, DC1 pairing or physical fault.
The partial map has 1110 context labels across ten still-OPEN source families;
12 source families are wholly unmapped, all nine bypass families are OPEN,
and no build is admitted.

## Sixty-first implementation slice: secret result returned to the fixture caller

The private [read-only fixture-caller mapper](../../scripts/aes/check-aes-fault-secret-caller-map.py)
pins each `run_cached` and `run_ephemeral` call into its secret owner and the
caller's following status test in both exact x86-64 test ELFs. At the return
boundary, public-fixture breakpoints confirm a success discriminant, a
descriptor pointing at the same caller destination with length 16, and the
expected bytes in that destination. The fixture then confirms its own
accepted path and storage clearing. Three widths, both owner lifetimes and
encrypt/decrypt passed on Rust 1.90.0 and 1.100.0: 24 baseline cases. The
[record](../../assurance/aes-fault-secret-caller-map-observations.json) pins
binary hashes and selected source snapshots. Four mapper regressions reject
changed calls or status tests, incomplete markers and unknown artifacts; the
map validator rejects forged fault status and a changed record hash.

This observes return into one exact test fixture, not every public API caller
or an injected fault at the final handoff. Post-validation corruption, failed
branches, bypasses, DC1 pairings and physical faults remain untested. The
partial map has 1158 context labels across ten still-OPEN source families;
12 source families are wholly unmapped, all nine bypass families are OPEN,
and no build is admitted.

## Sixty-second implementation slice: lifecycle completion rejection

The private [finite completion probe](../../scripts/aes/check-aes-fault-lifecycle-complete.py)
changes the first byte of the in-progress lifecycle word from `0x3c` to
`0x3d` immediately before `Operation::complete` in the two pinned x86-64 test
ELFs. It confirms the complete call returns an error; at the fixture-caller
boundary the admitted secret destination is zero and the owner is terminal.
The fixture also checks that a subsequent use is rejected. Three widths,
both owner lifetimes and encrypt/decrypt passed on Rust 1.90.0 and 1.100.0:
24 mutation cases. The
[record](../../assurance/aes-fault-lifecycle-complete-observations.json) matches
fresh runs and pins binary hashes and selected source snapshots. Four runner
regressions require the mutation point, rejection markers and fixture outcome.

This is one debugger-induced byte mutation, not a physical-fault model or a
complete lifecycle-handoff campaign. It does not test another byte/site,
metadata corruption, skipped completion branches, correlated faults or DC1
bypasses. The partial emitted map's 1158 baseline labels, 12 wholly unmapped
source families and nine OPEN bypass families are unchanged. Its global
`fault_results` and `dc1_pairings` remain empty; no build is admitted.

## Sixty-third implementation slice: stage expansion and bounded native replay

The [source-stage ledger](../../assurance/aes-fault-stage-expansion.json) now
names 112 candidate work stages across every one of the 22 source families,
including 39 candidate decision stages across all nine C1 bypass families.
Its validator requires every source
family to be represented and keeps exact instruction sites and DC1 temporal
pairings explicitly empty. These are stage labels for future emitted-site
enumeration, not proof that the source or machine-level inventory is complete.

A [bounded native replay](../../scripts/aes/run-aes-fault-native-sweep.py)
checked eight existing computation, completion, transaction and permit
probe invocations on each of the two pinned x86-64 test ELFs (Rust 1.90.0
and 1.100.0). The first and third sweeps passed 16/16. The intervening
repeat passed 15/16: the Rust 1.100.0 cached/encrypt completion probe exited
unconfirmed. Three isolated repeats of that probe then passed all 12 of its
width/case outcomes. A complementary six-job roster per ELF passed 12/12.
Its first attempt included an inapplicable guard probe: that probe's declared
`brynja-core` test is not present in either `brynja-crypto` ELF, despite its
leaf symbol being linked. One operation-local/public probe also exited
unconfirmed on that attempt and passed when run in isolation. Both
intermittent outcomes remain open observations, not retried passes.
The [record](../../assurance/aes-fault-native-sweep-observations.json) identifies
the artifacts and exact rosters; ten new bookkeeping tests cover
the ledger and replay wrapper. Subprocess output is suppressed and only
bounded status is printed.

This replay is a regression check over selected already-defined fault cases,
not a new all-site campaign. The test ELFs are not release-linked artifacts.
Ten families remain only partly mapped, twelve remain unmapped, all 22 are
OPEN, and all nine bypass families still lack complete emitted decision and
DC1 pairing coverage. No whole-model or release qualification is claimed.

## Sixty-fourth implementation slice: named-body boundaries for seven open regions

The [symbol-boundary mapper](../../scripts/aes/check-aes-fault-symbol-boundaries.py)
now locates named executable bodies for secondary expansion and rounds,
import and use checks, receipt observations, tentative writes and lifecycle
completion in both pinned x86-64 test ELFs. The
[record](../../assurance/aes-fault-symbol-boundaries.json) stores exact binary
hashes and the address/size of each named body. A fresh `--check-record`
observation matched it. Four new fail-closed tests reject missing, duplicate
or non-text symbols, unknown binaries and a changed recorded boundary.

These seven regions previously had no entry in the partial emitted-context
map. A symbol span is an entry point for instruction review, not an
enumeration of the faultable instructions inside it; inlining or duplicated
code can put source operations elsewhere. Therefore the stricter emitted-site
metric remains ten partly mapped and twelve unmapped, with all 22 source
families and nine bypass families OPEN. No fault, DC1 or release admission
result is inferred from symbol presence.

## Sixty-fifth implementation slice: core guard fixture on its actual artifacts

The `brynja-crypto` test ELFs link the guard leaf but do not include its
`brynja-core` fixture test. That explains why the guard probe failed in the
first complementary sweep; it was run against the wrong test population.
The [pinned wrapper](../../scripts/aes/check-aes-fault-guard-artifacts.py)
now requires two exact `brynja-core` test ELFs, checks that the declared
fixture exists, and invokes the existing native guard experiment. All seven
declared leaf cases passed on each artifact (14/14). The
[record](../../assurance/aes-fault-guard-artifacts.json) pins both hashes,
the test identity and the leaf-only limit. Four wrapper regressions reject
unknown artifacts, missing population, duplicate or missing cases and record
drift.

This resolves the fixture-selection error, not AES C1/DC1 qualification.
The guard leaf is only one component of receipt authorization. Its AES
callers, status propagation, final handoff and fault/data-bypass pairings
remain OPEN, as do all nine bypass families in the full model.

## Sixty-sixth implementation slice: exact decoded candidates in named bodies

The [instruction enumerator](../../scripts/aes/check-aes-fault-instruction-candidates.py)
now decodes every instruction boundary inside the seven named-body families
on both pinned x86-64 test ELFs. The
[record](../../assurance/aes-fault-instruction-candidates.json) contains 3,435
exact instruction offsets, with a normalized disassembly hash for each body.
It separately tags 559 syntactic control-transfer or flag-setting instances
as review candidates. A fresh `--check-record` run reproduced every offset,
count, hash and tag. Three new tests reject missing, duplicate, unordered or
out-of-span boundaries and recorded drift.

These are decoder candidates, not 3,435 model sites. Inlining can place
operations outside the named bodies; some decoded instructions are setup or
cleanup rather than secret computation. The 559 syntactic control candidates
are not automatically C1 bypasses. Source-stage correspondence, exact fault
location/byte, persistence, expected outcome, skipped-instruction effects and
DC1 temporal compatibility must still be reviewed. No source family is
closed by this inventory.

## Sixty-seventh implementation slice: wider owner/path native matrix

The bounded native runner now covers five existing probe families across
both owners and all three paths, for every AES width each probe supports.
The primary-result probe uses the two endpoint byte positions, 0 and 15.
This is 36 script invocations per pinned test ELF. The
[record](../../assurance/aes-fault-owner-path-matrix-observations.json) keeps
the first sweep's 71/72 result: all 36 passed on Rust 1.90.0, and 35/36 on
Rust 1.100.0. The latter's cached/decrypt AES-256 completion-bit case was
unconfirmed. A later single-case diagnostic observed all expected markers
in 20/20 launches, but does not erase the failed attempt. One new test pins
the matrix roster and retains that result as incomplete. A further 30 full
probe repeats confirmed 29 and failed native confirmation once. With a new
bounded, boolean-only diagnostic mode, 39 of 40 more repeats confirmed; the
failure retained all breakpoint and normal-exit indicators but lacked the
exact fixture-pass summary marker. A regression test covers the diagnostic's
bounded fields. The missing summary is an unconfirmed run, not an AES pass.

The matrix broadens existing local fault observations; it does not test all
byte positions, all decoded instructions or all applicable C1/DC1 pairings.
The cause of the intermittent completion probe remains unknown. No
release-linked artifact or public profile is admitted.

## Sixty-eighth implementation slice: completion-state instruction candidates

The [completion decision mapper](../../scripts/aes/check-aes-fault-completion-decision-map.py)
ties the `lifecycle-handoff/completion-state-check` source stage to seven
selected emitted instructions in each pinned test ELF: opaque copy call,
copy status, expected codeword load, both half-word comparisons, mismatch
combination and mismatch flag. It separately locates the shared state-select
branch, state store and result return. The
[record](../../assurance/aes-fault-completion-decision-map.json) pins offsets
and the decoded-body hash; fresh disassembly matched. Three fail-closed tests
check record drift, body membership and unknown artifacts.

This is a candidate stage map, not a proof that no other instruction
participates in completion or that a skipped branch cannot release output.
The state-selection instructions serve both healthy and terminal outcomes;
their C1 semantics and downstream propagation remain unqualified.

## Sixty-ninth implementation slice: complete single-bit completion codeword grid

The [bounded matrix runner](../../scripts/aes/check-aes-fault-lifecycle-codeword-matrix.py)
mutated every one of the 16 in-progress codeword bytes by each of its eight
single-bit flips immediately before `Operation::complete`. Across three AES
widths, two owner lifetimes, encrypt/decrypt secret paths and both pinned
x86-64 test ELFs, all 3,072 cases confirmed rejection, clearing of the
admitted destination, terminal owner state and rejected reuse. The bit-0
preflight subset was 384/384. The
[record](../../assurance/aes-fault-lifecycle-codeword-matrix-observations.json)
pins the dimensions and artifact hashes. The original one-byte probe still
passes unchanged; new tests cover all generated byte/bit mutations, invalid
dimensions, unknown artifacts and case-count bookkeeping.

This closes only the single-bit grid at one L1 completion boundary in local
test ELFs. Other lifecycle codewords and stages, byte replacements or
stuck-at faults, instruction skips, C1/DC1 pairings and final-linked release
artifacts remain OPEN. The full 22-family site inventory is still not closed.

## Seventieth implementation slice: guarded-write readback byte grid

The [readback matrix runner](../../scripts/aes/check-aes-fault-readback-byte-matrix.py)
mutated each of the 16 bytes of the checked destination by XOR 1 immediately
before each of the forward and reverse guarded-write readbacks. Across three
AES widths, cached and operation-local owners, public encryption and both
secret directions, and both pinned x86-64 test ELFs, 1,152/1,152 cases
confirmed the intact primary and
secondary replicas at the boundary, changed the destination only, then
observed rejection, fixture-confirmed public rollback or secret cleanup,
terminal retirement and rejected reuse. The byte-0 preflight was 36/36
for each readback.
The [record](../../assurance/aes-fault-readback-byte-matrix-observations.json)
pins the artifact hashes and full case population; the runner has an optional
fail-closed record check. Five unit tests cover mutation commands, unknown
artifacts, invalid dimensions, result parsing and incomplete/duplicate records.

This is D4 evidence at the tentative guarded-write boundary, not at the later
actual secret destination. It covers only XOR 1 before each check. Other fault
mutations, C1/DC1 pairings, instruction skips and final-linked release
qualification remain OPEN; neither the 22-family site inventory nor the nine
bypass families is closed by this matrix.

## Seventy-first implementation slice: actual secret-destination readback grid

The [actual-destination runner](../../scripts/aes/check-aes-fault-actual-secret-byte-matrix.py)
mutated each of the 16 bytes of the caller's admitted secret destination by
XOR 1 immediately before each of the forward and reverse validator readbacks.
Its debugger checkpoints confirm that the pointer is the fixture caller's
destination, not the earlier guarded staging buffer, and that both result
replicas are intact at the mutation boundary. Across three AES widths, cached
and operation-local owners, secret encryption and decryption, and both pinned
x86-64 test ELFs, 768/768 cases confirmed rejection, destination clearing,
terminal retirement and rejected reuse. The byte-0 preflight was 48/48.
The [record](../../assurance/aes-fault-actual-secret-byte-matrix-observations.json)
pins the artifact hashes and case population; the runner has an optional
fail-closed record check. Five unit tests cover commands, artifact and
dimension guards, result parsing, and incomplete/duplicate record rejection.

This is selected D4 evidence at the actual destination. It covers only XOR 1
at the two validator call sites, not the initialization write, finish,
permit, final SecretBlock handoff, other fault mutations or C1/DC1 pairings.
The 22 source families and nine bypass families remain OPEN; no final-linked
release qualification follows from these test ELFs.
