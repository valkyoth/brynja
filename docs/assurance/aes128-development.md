# AES-128 development contract — v0.27.0

Status: initial implementation; milestone and qualification incomplete.

## Scope and authority

`brynja_crypto::aes` (also through `brynja::crypto::aes`) implements the
AES-128 key expansion, CIPHER and INVCIPHER from
[FIPS 197-upd1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf),
sections 4–5. Initial fixed-answer regressions use its Appendix A.1 schedule,
Appendix B and original Appendix C.1 block examples, and the four individual
AES-128 block pairs in
[SP 800-38A, Appendix F.1](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf).
Those mode-document examples test the block primitive, not an implemented ECB
mode. AES-192/256, authenticated encryption, padding, modes, nonces, acceleration
and TLS are excluded. No new third-party dependency is introduced.

## API and owned storage

- `Aes128Key::new` copies an exact 16-byte key into exact 16-byte caller storage.
  Array types reject other key sizes at compile time. Input copies remain the
  caller's responsibility; no key export, implicit hash or backend selection.
- `encrypt_block` and `decrypt_block` take one exact 16-byte input and a disjoint
  output buffer. Both return `SecretBlock`; ciphertext is not automatically
  declassified. `expose` explicitly borrows its bytes.
- `encrypt_block_public` consumes `PublicCiphertext::acknowledge()` and commits
  one public ciphertext block only after successful computation. Errors/unwinds
  preserve the entire destination. There is no public-decryption operation.
  This follows the symmetric-cipher profile's explicit public declassification
  boundary; it does not add a mode or authentication.
- The key and output owners have no Copy, Clone, Debug, Send or Sync. Explicit
  consuming `clear` and ordinary Drop clear their caller storage. Output may
  outlive the key; safe borrowing prevents overlapping inputs and live outputs.
- Each secret-output operation admits output with `SecretRegionInitialization`, then
  expands a 176-byte schedule into a clearing guard. State, expansion word and
  row-permutation scratch also have guards. No populated scratch is returned
  by value. The schedule dies before the output owner returns.
- Internal checked-index failures return a value-free error and the admitted
  output clears. Test-only hooks inject failure or unwind after each of the
  eleven round-key additions, in both directions. The tests observe guards'
  storage after wiping but before destruction, and caller buffers afterwards.
  These hooks are absent from ordinary builds.
- The public ciphertext path has equivalent error/unwind injection at all eleven
  round-key boundaries, checking unchanged output, live scratch cleanup and
  subsequent successful key reuse.

## Constant-work design versus qualification

GF(256) multiplication uses eight fixed steps and masks; inversion uses a
fixed exponentiation chain. The S-box and inverse S-box have no lookup tables.
Round counts and memory positions depend only on public fixed dimensions and
operation direction. This readable scalar implementation is not a performance
claim and is not compiler/target constant-time qualification. Optimizers may
change machine-level behavior. Scalar temporaries, moves, registers and spills
remain outside guard-storage clearing guarantees; so do forgotten owners,
abort, paging, process termination and dumps.

The `dataflow-review` registration inspects six actual optimized portable helper
bodies (`expand`, `transform`, `add_key`, `substitute`, `mix`, and field `inverse`)
on Rust 1.90.0 and 1.99.1, x86_64, abort/unwind. It builds the production library
at opt-level 3 with fat-LTO enabled, one codegen unit and overflow checks. These
are library compiler artifacts, not a final linked application's LTO output.
The existing `operation-cleanup` check separately binds the public operation
wrappers to the real expansion and transform helpers.

Within a deliberately restricted scalar LLVM model, all loaded values and the
field inverse argument are secret. Pointer addresses, lengths, operation
direction and round numbers are public; pointer contents are not declassified.
Fixed-point propagation through arithmetic, selects and loop-carried phi nodes
rejects secret-dependent branches, addresses, shift counts, helper control
arguments and status returns. Only the six reviewed helper call summaries and
named memory/lifetime/rotate/core-clear operations are admitted. Unknown
instructions or call shapes fail rather than being assumed safe. Every helper
is analyzed, including the public-status return assumptions used at call sites.

The scalar inverse's emitted x86_64 assembly is checked separately: only the
reviewed arithmetic/register operations and fixed stack-relative accesses are
accepted, with no branches, calls, indexed memory loads or variable shifts.
Arithmetic LEA instructions do not access memory. Fixed stack spills are allowed
and are **not** claimed to be wiped. Nineteen checker regressions cover secret
branches, addresses, loop propagation, statuses, calls, shift counts, stack
pointer writes, unsupported instructions and suppressed false completion.
Artifact hashes and all four configuration results are retained in the runner.

All six helper assembly streams additionally have an explicit control/address
review, recorded below, with pinned normalized fingerprints. Seven replay
regressions reject changed instructions, missing helpers, altered scope and
symbol-normalization ambiguity (26 dataflow/replay tests total). A fingerprint
mismatch requires review, never automatic approval of a new compiler output.

This is bounded emitted-code evidence, not whole-program constant-time proof:
the assembly review is not a formal noninterference proof; wrapper/core machine code, final-link
optimization, other targets, instruction latency and physical/speculative
channels remain outside this check. Public lengths/addresses/direction are an
explicit model assumption. Passing this model cannot qualify an uninspected
deployment compiler, target or profile.

The `timing-screen` registration adds a coarse synthetic observation, not a
constant-time claim. `assurance/aes-timing` calls the actual public API with
fixed 16-byte inputs, comparing all-zero/all-FF keys (fixed block) and
all-zero/all-FF blocks (fixed key), for encrypt, decrypt and explicitly public
encryption. Each timed call includes key import, schedule creation/destruction
and owner Drop; repeated operations are observed through `black_box`. Public
mode selection is fixed within a campaign. Printing and record allocation
occur outside measured operations.

The pinned build is Rust 1.99.1, release opt-level 3, fat LTO, one codegen unit,
overflow checks enabled and abort panics on Linux x86_64. The runner records
compiler, host, logical CPU, oracle version and executable hash, then pins its
measurement child to one logical CPU. Independent OpenSSL block preflight
checks all twelve contrast outputs, with a published known-answer oracle
control in both directions. There are 32 discarded warmup pairs, followed by
512 pairs per campaign (256 AB, 256 BA), with four operations per timed sample.

All raw measurements and paired-difference summaries are retained in the runner
log. The shared HMAC diagnostic's absolute paired-t threshold is 10; constant
nonzero differences are alarms, not divide-by-zero passes. Any alarm or missing,
reordered, invalid or duplicate sample fails the registration; there is no
automatic retry or threshold adjustment. Ten synthetic runner regressions cover
these failure paths, oracle checks and false-success suppression.

This small, fixed-contrast screen does not explore arbitrary secrets, alignment,
cold caches, adversarial scheduling, speculative execution, power/EM leakage,
other compilers/CPUs or target binaries. Operating-system and background load
can affect measurements; binary hashing does not pin external shared libraries.
Zero alarms mean only that this diagnostic did not flag those retained samples.

## Initial reproducible checks

`brynja-verify aes` scans status only. Run the registered initial checks with:

```sh
brynja-verify run aes --needed
```

The twenty-two registrations distinguish public vectors, internal finite/fault tests,
MSRV vectors, compile-fail examples, release-profile vectors, Cortex-M compile,
ASan/LSan vectors and round faults, two exact Miri ownership/public-output tests,
an opt-in independent OpenSSL comparison, three bounded Kani harnesses, and
paired diagnostic-specific checks on two compilers, compiling source mutations,
bounded emitted public-owner Drop dispatch, and operation-scratch/explicit-clear
dispatch, development-owner inventory regressions, isolated downstream consumers,
a 14-compiler consumer matrix, bounded emitted-dataflow review and a bounded host timing screen. Each execution registration
requires its exact population; a zero-test execution is not accepted. These
compile against the composition crate's full default dependency closure but do
not rerun earlier hash campaigns. Rustdoc negative examples do not establish
specific error diagnostics. Cortex-M is compile-only; no target runtime claim.

## Isolated downstream consumers

`assurance/aes-public-api` is a standalone `no_std` workspace with exactly one
selected public route: `direct` (`brynja_crypto::aes`) or `facade`
(`brynja::crypto::aes`). It includes no production source modules or internal
test hooks. Its wrapper exercises key import, public-output acknowledgement and
explicit key clearing. Six host tests exercise both fixed-answer directions,
Drop and consuming clear, guard canaries, storage reuse, an output outliving its
key, persistent explicitly public ciphertext and a caller panic after a successful
encryption. The unwind test verifies that the intentional caller-panic point was
reached; an earlier assertion failure cannot masquerade as the expected unwind.

`scripts/aes/check-aes-consumer.py` copies the fixture into a private directory,
relocates only its two checkout dependency paths, and runs locked/offline builds.
It rejects changed fixture policy, missing/symlinked fixture files, unexpected
active package/source/feature graphs, missing/ignored/duplicate tests and failed
commands. The existing portable composition graph includes hash dependencies;
their earlier campaigns are not rerun. No legacy, CPU execution or hosted-memory
feature is admitted by these exact graph checks.

The `downstream` registration runs six exact tests in each of eight configurations:
both routes, debug/release, Rust 1.90.0/1.99.1. Each compiler/route also compiles
the consumer library for `thumbv7em-none-eabi` (four compile checks, no target
execution). The separate `downstream-matrix` registration uses `--matrix` to run
both routes in debug/release on the repository's fourteen pinned compiler
versions (1.90.0 through 1.99.1): 56 host configurations, 336 test executions.
Cortex-M remains endpoint-only. Eleven runner regressions exercise policy,
graph, population, relocation, file admission, matrix selection and failure
handling. These observations use checkout sources, not unpacked crate archives;
they do not establish compiler timing behavior. Packaged full-family acceptance remains
the separate v0.27.2 milestone; this step grants no publication approval.

## Development owner and requirements inventory

The source-bound API register now includes a separate
`development.algorithm.aes128` record, not `registered.algorithm.aes`. Its
operation and lifecycle lists are specific to this block API rather than
copied from the wider symmetric-cipher profile. The canonical contract checks
real owner fields/local markers, mandatory guards, explicit clears, widths,
round bounds and the compiler-check bindings. Nineteen synthetic regressions
reject inventory/qualification drift and broken source declarations. The
global API-profile tests additionally ensure this record does not remove the
planned family owner or promote the family disposition. These are inventory
checks, not cryptographic tests or independent review.

Normative requirements, implementation controls and residual attack assumptions
are mapped in the [AES control contract](../security-controls.md#aes-128-development-contract-v0270)
and [threat model](../threat-model.md#aes-128-block-boundary-v0270-development).
The overall family requirement remains planned until its separately scoped
variants and remaining obligations are addressed.

## Production arithmetic and index proofs

The dependency-free `assurance/aes-policy` fixture compiles the actual
`aes/portable/field.rs` and `layout.rs` modules using source-path inclusion.
The production block implementation calls those same helpers. There is no
proof-only cipher, clearing-owner stub or alternate field implementation under
the production names. Kani 0.68.0 / CBMC 6.11.0 runs three exact harnesses:

- For arbitrary byte pairs, production multiplication equals an independent
  16-bit carryless product followed by polynomial long division by `0x11b`.
  The eight-step loops use unwind bound 9, with unwinding assertions enabled.
- For arbitrary admitted state indices (0–15) and either direction, ShiftRows
  source indices stay in bounds, preserve rows, are injective and compose with
  the inverse direction to return the original index.
- For arbitrary admitted rounds (0–10) and byte positions (0–15), production
  round-key indices equal the mathematical offset and remain below 176.

These are field-operation and admitted-index proofs only. They do not prove
the S-box as a whole, full key expansion, CIPHER/INVCIPHER correctness, secret
destruction or machine-code constant time. Existing finite/vector/fault tests
remain separate. Kani's compile-time unsupported-construct warnings describe
unreachable constructs in the compiled crate; each selected harness must still
complete successfully, including its reachability and safety checks.

## Diagnostic-specific misuse acceptance

`scripts/aes/check-aes-api.py` builds the composition library in a private target
directory and compiles external consumers with Rust 1.90.0 or 1.99.1. Each of
29 negative probes has a neighboring positive control compiled against that
same artifact. A negative passes only with compiler exit status 1, the one
expected diagnostic code, and a primary span in the probe source. Missing
libraries, unrelated errors, successful invalid programs and compiler failures
are not accepted as misuse evidence. Probe scope includes:

- key/output Copy, Clone, Debug, Send and Sync rejection;
- consumed owners, storage lifetime and live-borrow protections;
- exact AES-128 key, storage, block and destination widths;
- overlap rejection for secret encryption, decryption and public encryption;
- no key export or public decryption, and explicit consumed public-output authority.

This is checkout-built external API acceptance, not packaged-source acceptance
or a runtime secret-clearing proof. Thirteen runner regressions test the exact
population and fail-closed handling of malformed diagnostics, wrong errors,
missing artifacts, failed positive controls, wrong verifier identities and
missing/duplicate proof summaries. The normal registry suite includes them.

## Compiling source-mutation controls

`scripts/aes/check-aes-mutations.py` copies the production AES module, internal
tests and public vector harness into a private temporary fixture with the real
core dependency. The repository's production files are never edited. Both the
unaltered and restored copies must pass all six public and five internal tests.
Each of twelve deliberate defects must compile successfully, then fail its
specific regression by assertion with exactly one failing test. Build errors,
zero-test runs, a different failed test, process aborts and surviving defects
are rejected as evidence.

The defects cover the field modulus, both affine constants, initial round
constant, previous key-word offset, ShiftRows direction, skipped round, inverse
MixColumns coefficient, final round key, omitted schedule clearing, forgotten
explicit key clear, and a premature public-output write. This demonstrates
sensitivity of those selected tests; it is not exhaustive mutation coverage or
a proof that all implementation defects are detectable. Runner regressions
also check anchor uniqueness, source restoration, surviving mutants and compile
failures. Only public test keys and blocks enter the fixture.

## Bounded public-owner emitted-code dispatch

`assurance/aes-owner-cleanup` consumes the actual `Aes128Key` and `SecretBlock`
types through ordinary Drop after borrowing each with an observer. The checker
builds library artifacts for x86_64 Linux with Rust 1.90.0 and 1.99.1, each under
abort and unwind profiles (opt-level 3, one codegen unit, overflow checks,
configured fat LTO). These are emitted library MIR/LLVM/assembly artifacts,
not a final application binary or a final-link LTO qualification.

The checker reuses the bounded two-word `OwnedSecretRegion` descriptor executor
from the HKDF owner checks; it uses no HKDF algorithm or outer output-option
assumption. It tracks the symbolic secret pointer and length through the
observer and verifies one dispatch to core's destructor before each modeled
return or observer-unwind exit. It evaluates populated and empty descriptors;
unknown instructions, wrong extents, wrong pointers and missing dispatch fail.
MIR owner types and assembly symbols are identity checks only, not substitutes
for the LLVM descriptor-flow check. Core's non-panicking clearing destructor
remains a delegated premise.

Twelve IR-text negative controls per compiler/profile are rejected, including
removed/wrong destruction, early return, wrong pointer/length, missing or
repeated observer, uninitialized descriptor length, post-destruction writes,
wrong target, missing probe and unknown instructions. These checker mutations
are distinct from the twelve compiling algorithm/cleanup mutations above.

This evidence covers public-owner ordinary Drop dispatch only. Explicit-clear
method bodies and operation-local schedule/state/word/row scratch have a separate
bounded check below. Neither establishes physical erasure, register
or spill cleanup, cleanup after abort/forget, constant time or independent review.

## Bounded operation-scratch and explicit-clear dispatch

`scripts/aes/check-aes-operation-cleanup.py` emits the actual composition library
on Rust 1.90.0 and 1.99.1, x86_64 Linux, with abort/unwind, opt-level 3, one
codegen unit, overflow checks and configured fat LTO. It selects exact production
methods, requires the public encrypt/decrypt consumers to call the shared secret
operation, and requires both output paths to call the production expansion and
round helpers. MIR/assembly presence checks establish artifact identities only.
The flow checks operate on emitted LLVM, not a source-only clearing marker.

Four bodies contain nine checked allocations: schedule/state in each secret and
public operation, the expansion word, and four inlined ShiftRows copies in the
round helper. The bounded graph walker follows all modeled branch, loop, error,
return and unwind edges. Each allocation has inactive, live-needing-clear and
live-cleared states. Its complete extent must be dispatched to the core clearing
function before its lifetime ends or the function exits. Other calls/stores
conservatively dirty live scratch. The distinct caller-output initialization
guard is not mistaken for local scratch. Clear dispatch and the core callee's
non-panicking clearing behavior remain separate obligations; the latter is an
existing delegated premise. Unreachable double-panic termination is not a
recoverable-unwind or erasure guarantee.

Both public consuming `clear` methods must have the observed direct two-word
descriptor-forwarding body, with unchanged pointer and length sent to
`OwnedSecretRegion::clear`. New control flow, inlining, instructions or calls in
these bodies require checker review. This verifies delegation, not the core
callee again. The scratch checker models lifetime/clearing effects rather than
interpreting AES arithmetic or proving the public ciphertext commit.

Each compiler/profile must reject 55 IR-text mutations: five for each of the nine
scratch allocations (short extent, wrong pointer/callee, early return, write
after clear), plus five for each explicit-clear method. Ten synthetic runner
regressions cover those controls, bypassed error/unwind cleanup, repeated
lifetimes, population/call-edge/profile mismatches and driver failure. Synthetic
graphs and IR-text mutations are parser checks, not compiled mutant executions.

These are pre-link library artifacts, not final-application LTO qualification.
They do not cover compiler-created scalar copies, register/spill cleanup,
physical erasure, panic-abort cleanup, forgotten owners or side-channel timing.

## Independent block-vector and differential coverage

The public vector harness now includes all 568 ENCRYPT/DECRYPT records from the
four NIST AES-128 ECB KAT response files (GFSbox, KeySbox, VarKey, VarTxt).
[Fixture provenance and hashes](../../crates/brynja-crypto/tests/fixtures/aes128/README.md)
identify the source archive and normalization. Strict parser negative controls
reject partial populations and malformed records. Encryption records exercise
both secret and explicit-public output paths. Fixtures are included in the
composition crate's package so packaged integration tests can compile.

The separate `aes128_differential` harness compares 4096 block operations across
64 deterministic public keys with the installed OpenSSL executable. Inverse
inputs are independently generated ciphertext, not only forward-roundtrip
results. The harness is ignored in ordinary Cargo runs because it requires an
external executable; the verifier explicitly runs it with `--ignored --exact`,
requires one passing test and the exact completion marker. Missing/failed
OpenSSL or wrong output length fails the test. Its binary is fingerprinted and
runtime version logged, but external shared libraries are not pinned. This is
an implementation comparison, not compiler, side-channel or deployment
qualification. All command-line keys are public test material, never secrets.

## Required before milestone closure

- The AES-128 transformation/vector mapping was reviewed against the pinned
  FIPS authority (see the dated review below). The four KAT sets, OpenSSL
  differential coverage and selected compiling mutations still do not
  constitute a complete AESAVS/CAVP validation campaign.
- The development-owner inventory, normative requirement mapping, threat model
  and controls now describe this exact subset. Review their scope with the
  remaining milestone evidence; do not promote the planned AES family when
  only AES-128 is present.
- Review remaining proof obligations and side-channel limits; the synthetic
  timing screen and bounded LLVM/scalar-inverse review are present, but do not
  qualify whole-program constant-time behavior. Extend bounded
  emitted-code observations where the supported deployment scope requires it;
  inspect every claimed compiler/target/profile. No broad qualification is
  inferred from table-free source or passing vectors.
- Review the isolated public downstream evidence alongside expanded dynamic
  failure coverage and supported target checks. Checkout consumers now run
  through both public routes across fourteen compilers; packaged AES-family
  acceptance remains v0.27.2.
- Obtain the owner's scoped pentest/retest, prepare candidate metadata, run the
  finite final gate, then await exact-candidate CI and explicit tag approval.

Release metadata now identifies the internal 0.27.0 candidate. Its finite
checklist retains HKDF compatibility and adds bounded AES consumer endpoints;
it does not implicitly rerun deep verification. The owner's scoped pentest
and final gate are pending. No 0.27.0 tag or publication is authorized by these tests.

## Initial local validation — 2026-11-03

All eight scoped AES registrations passed on the working tree based on
`9698e07b`, including ASan/LSan and the single Miri ownership test. Their exact
commands, timestamps and input fingerprints are recorded in the local verifier.
The 170 verification-registry tests, strict all-target composition Clippy,
formatting, facade compilation, modern/legacy HKDF crate suites and doctests
also passed. The source/claim-register consistency checker passed without
promoting AES to a qualified registered owner; that integration remains open.

Initial validation caught and corrected new-code Clippy issues and updated the
historical sanitizer-binding test to leave new AES registrations to their own
explicit command/environment/population assertions. No historical sanitizer
binding or success requirement was relaxed. These results are development
observations, not a final gate, pentest or independent cryptographic review.

## Expanded local validation — 2026-11-03

All eleven scoped AES registrations passed on the updated working tree based on
`9698e07b`. This includes the 568 NIST records in debug, optimized, MSRV and
ASan/LSan harnesses; 4096 OpenSSL 3.5.3 differential comparisons; ASan/LSan round
faults; and two separate exact Miri owner/public-output cases. Each registration
records its own current input fingerprint. Miri does not run the whole KAT set
or all injected faults, and Cortex-M remains compile-only.

All 171 verification-registry tests, modern/legacy HKDF crate suites and
doctests, AES all-features integration tests, strict composition all-target
Clippy, formatting and diff-integrity checks passed. `cargo package --list
--allow-dirty --locked --offline -p brynja-crypto` includes all four fixture
files and their provenance README. This package listing is not the outstanding
packaged downstream acceptance or publication authorization.

## Proof and misuse validation — 2026-11-03

All fourteen scoped AES registrations passed after extracting production
field/layout helpers, including all three Kani harnesses and all 29 paired
diagnostic probes on each of Rust 1.90.0 and 1.99.1. Vector, differential,
ASan/LSan, Miri, optimized, MSRV and Cortex-M compile checks were rerun against
the changed source. The 185 registry/runner tests, modern/legacy HKDF suites,
AES all-features integration tests, strict composition Clippy, formatting and
diff-integrity checks passed. No final-gate or side-channel claim is implied.

Runner development caught an incorrect dependency-artifact search path in the
first positive-control compile, and the verifier rejected dotted check IDs.
Both were corrected before recording passes; identifier syntax is now asserted
in the AES registration regression. Missing-crate errors are explicitly rejected
by the diagnostic matcher tests, never counted as successful API rejection.

## Mutation and public-owner dispatch validation — 2026-11-03

All sixteen AES registrations passed on the working tree based on `9698e07b`.
The twelve source mutants compiled and failed their designated tests; both
baseline runs passed. Both real public-owner Drop probes passed in each of the
four compiler/panic configurations, with all twelve IR-text negative controls
rejected per configuration. These are separate, explicitly bounded observations.
The existing AES vector, differential, proof, misuse, ASan/LSan, Miri, optimized,
MSRV and Cortex-M registrations remain current on this tree.

All 194 registry/runner regressions passed, including the eight new mutation and
owner-checker regressions (21 AES runner tests total). Strict composition and
owner-fixture Clippy, formatting and diff-integrity checks passed. This step did
not change production AES arithmetic or its public API. Operation-scratch and
explicit-clear emitted-code checks remain open, as do the broader milestone
and qualification items above. No release, commit or tag is implied.

## Operation cleanup validation — 2026-11-03

All seventeen AES registrations passed on the working tree based on `9698e07b`.
The new operation-cleanup registration checks all four compiler/panic
configurations, nine local scratch allocations in four production bodies and
both explicit-clear methods, rejecting all 55 IR-text mutations per configuration.
The remaining sixteen registrations were refreshed, including ASan/LSan, Miri,
vectors, differential comparisons, bounded proofs and compiling source mutations.

All 205 registry/runner regressions (31 AES runner tests), workspace formatting
and diff-integrity checks passed. No production cipher or public API changed in
this step. The previous host operation-scratch/explicit-clear evidence gap is
now covered by the bounded dispatch checks above, not by a physical-erasure or
constant-time claim. Owner/requirements integration, broader qualification,
downstream acceptance and the remaining milestone review remain open.

## Ownership and requirements integration validation — 2026-11-03

All eighteen AES registrations passed on the working tree based on `9698e07b`,
including the new nineteen-case development-owner contract. The vector,
independent differential, MSRV, optimized, no_std compile, Miri, ASan/LSan,
bounded Kani, paired misuse, compiling mutation and emitted cleanup checks
were refreshed. No production cipher code or public API changed in this step.

All 225 registry/runner regressions passed. The API-profile, AES/HKDF/legacy-HMAC
owner, protocol-surface, requirement core/history/lifecycle/domain/transport/
section/residual regressions and generated-artifact checks passed, as did
workspace formatting and diff integrity. The broader inventory runs exposed
three stale pre-HKDF assertions (registered-owner count, implemented-surface
population and roadmap count); these now explicitly retain HKDF while keeping
AES-family completion separate from its development-only AES-128 record.

Ownership, normative controls and threat-model integration are now present.
Remaining milestone work includes broader emitted-code/side-channel evidence,
downstream acceptance, final requirement/vector review and a scoped pentest.
The partial family record does not authorize modes, acceleration or AES-192/256,
and no release approval, independent review or physical-erasure claim is made.

## Isolated downstream validation — 2026-11-04

All nineteen AES registrations passed on the working tree based on `9698e07b`.
The new consumer registration completed 48 host test executions (six named tests
in eight compiler/route/profile configurations) and four no_std Cortex-M compile
checks. Existing vector, Miri, ASan/LSan, bounded proof, mutation and emitted
cleanup registrations were refreshed without rerunning historical hash campaigns.

All 235 registry/runner regressions passed, including nine new consumer-runner
tests and its registration/input-closure regression. Strict current-toolchain
Clippy passed for both consumer routes; workspace/fixture formatting, generated
API/requirements/extra-registration checks and diff integrity passed. The first
registration attempt was rejected for a missing required `contains` field; it
was corrected and pinned by regression before any registered pass was recorded.

No production AES operation changed. The façade documentation now names its
development-only AES-128 export. These are checkout-external consumer observations,
not crate-archive acceptance or full compiler/side-channel qualification. Wider
compiler coverage, remaining requirement/vector review and the scoped pentest
still precede milestone closure. No commit, tag or publication was performed.

## Compiler matrix and timing observation — 2026-11-04

All twenty-one AES registrations are current on the working tree based on
`9698e07b`. The new fourteen-compiler matrix passed all 56 host configurations
(336 executions of the six consumer tests) and four endpoint Cortex-M compile
checks. The endpoint-only registration remains separately scoped and overlaps
the matrix; these are not different algorithms or additional unique test cases.

The first registered timing observation passed its twelve-output independent
preflight and retained all 3072 measured pairs across six campaigns. It reported
zero alarms; absolute paired-t values ranged from approximately 0.076 to 1.095
against the fixed diagnostic threshold of 10. The binary, compiler, logical CPU,
oracle version and raw samples are retained in the `aes/timing-screen` attempt.

## Transformation and emitted-dataflow review — 2026-11-04

The production field, layout, expansion and round functions were compared with
the repository's pinned `references/local/NIST.FIPS.197-upd1.pdf` (SHA-256
`62c86eb567f13edb8f71826e985da870b04ef6381634f303cdb16e84d47becd1`).
The review checked the column-major state (§3.4), reduction polynomial/xtime
(§4), inverse-plus-affine substitution (§5.1.1), row directions and forward/
inverse matrix coefficients (§5.1.2–3 and §5.3.1–3), and Algorithms 1–3.
AES-128 uses Nk=4, Nb=4, Nr=10, a 44-word schedule, all ten round constants,
and no MixColumns in either final round. The inverse uses the ordinary reversed
schedule, not the distinct equivalent-inverse key transformation. No algorithm
change was needed from this review.

The existing full Appendix A.1 schedule answer, published block pairs and four
568-record KAT populations exercise that mapping. The fixture hashes, strict
section/count/field parser and independent forward/inverse differential inputs
remain separate controls; round trips alone are not the correctness oracle.
The full AES-family requirement stays planned because AES-192/256 are absent.
This is an implementation review, not independent review or CAVP validation.

The new emitted-dataflow runner passed all four compiler/panic configurations.
Its scalar inverse bodies contain 740 machine instructions on Rust 1.90.0 and
749 on Rust 1.99.1, including fixed stack spills; no physical erasure claim
follows from these observations. The exact scope and remaining machine-level
and deployment limitations are described above. Production cipher code was not
changed by this review or by the new checker.

After registration, all twenty-two AES checks passed and were current on the
working tree based on `9698e07b`, including the refreshed timing observation
(zero alarms), Miri, ASan/LSan, bounded Kani, compiling mutations and fourteen-
compiler matrix. All 269 verification-registry/checker regressions passed.
Requirement and owner-register consistency, generated extra-registration
consistency, workspace formatting and diff-integrity checks also passed.
These observations do not authorize a commit, tag, publication or deployment.
No retry-to-pass or threshold change was performed. This record is not a
constant-time proof or approval for a deployed target.

All 249 registry/runner regressions passed, including ten new timing-runner
tests and the compiler-matrix controls. Strict Clippy for the new timing fixture,
workspace/fixture formatting, generated API/requirements/extra-registration
checks and diff integrity passed. Production cipher code and its public API were
unchanged. Remaining work is final vector/requirement and emitted-code/side-channel
scope review, followed by the owner's scoped pentest and finite release process;
full deployment qualification is not inferred from these local observations.

## Six-helper machine review — 2026-11-04

The six production helper assembly bodies were inspected on Rust 1.90.0 and
1.99.1 for x86_64-unknown-linux-gnu using the release settings described above.
Both abort and unwind builds reproduce the reviewed instruction streams after
normalization. This is a local implementation review, not independent approval.

| Helper | Control and address argument in the inspected assembly |
| --- | --- |
| `substitute` | The only conditional branch selects the public direction. State loads/stores use fixed offsets 0–15 from the saved state pointer; each direction makes sixteen direct calls to `inverse`. Affine rotates/XORs have constant counts; there are no tables. |
| `mix` | The forward path is unrolled at fixed state offsets. The inverse path advances a public column index by four from 0 through 12, stopping at 16. Saved state pointers and loop indices occupy distinct stack slots from secret-byte spills. Field arithmetic uses masks, XORs and constant shifts. |
| `expand` | Branches test the public key length, fixed schedule counter, SubWord periodicity and public bounds. Rust 1.99.1 advances its index from 19 by four until 179; Rust 1.90.0 advances from -160 to zero with derived public offsets. The schedule base and derived offsets survive inverse calls in separate saved locations. SubWord uses four direct inverse calls; Rcon starts at one and follows fixed arithmetic. Scratch clearing has fixed length four; status is public success/failure. |
| `add_key` | The public round is shifted by four and checked against 176. Schedule accesses use that public offset plus fixed byte offsets; state accesses use offsets 0–15. A fresh comparison of the public offset produces the returned status, not the secret XOR result. |
| `transform` | Direction and fixed round counters control the paths. Both compiler versions execute middle rounds 1–9 forward and 9–1 inverse. First/last schedule accesses use fixed offsets 0–15 and 160–175; row permutations use fixed offsets in 16-byte stack scratch. Branches on helper status use the reviewed public `add_key` result. Clear-call pointers come only from the exact core-clear GOT symbol, never secret memory, with fixed scratch extent 16. |
| `inverse` | The existing restricted assembly checker accepts 740 instructions on Rust 1.90.0 and 749 on Rust 1.99.1: arithmetic and fixed stack spills, with no branches, calls, indexed memory or variable shifts. Spills are not claimed wiped. |

The reviewed substitution and add-key streams are identical between the two
compilers. Differences in the remaining helpers include register allocation,
public bounds checks and public loop-counter conventions. Arithmetic LEA is
not a memory access; a one-operand byte rotate has an implicit count of one.

`scripts/aes/machine-review.json` pins all six SHA-256 fingerprints per compiler.
The replay helper ignores whitespace, comments and CFI unwind metadata and
renames only exact selected helper symbols, the delegated core-clear symbol,
and local labels in definition order. It preserves instructions, registers,
constants, displacements, alignment directives and control-flow references.
Missing/duplicate bodies, unknown symbols and changed fingerprints fail closed.
There is no automatic policy-refresh mode. The review document itself is an
input of the registered check.

This mechanism detects changes relative to a reviewed compiler stream; it is
not an assembly taint analysis or a proof of final linked bytes. Core clearing,
ABI/GOT integrity, wrappers, unwind metadata, final application optimization,
other targets and compiler versions, instruction timing, speculative execution
and physical leakage remain outside this review. Separate cleanup and timing
registrations retain their own narrower claims. No production cipher changes
were made for this review, and no deployment or release approval is implied.

## Candidate preparation — 2026-11-04

The facade, dependent fixture pins/locks, release inventory and SBOM now identify
0.27.0. Supporting component versions remain unchanged and no crate is selected
for publication. The finite final checklist has 24 entries; routine component
CI selects 18, with separate bounded AES and packaged HKDF consumer jobs. Deep
verification remains explicit and separate. The owner's scoped pentest is
required, not recorded as passed.

Preparation caught two integration issues: old exact facade fixture pins and
the packaged HKDF runner's rejection of the composition crate's new AES vector
include form. Pins now match the local facade; the runner admits only the
reviewed five-file AES fixture set for `brynja-crypto`, with missing/extra/symlink
and archived-byte regressions. Neither fix changes cryptographic operations.

Local preparation checks passed: 276 registry regressions, 25 scoped-release
tests, 28 packaged-runner tests, release inventory/roadmap/workspace policy,
composition and legacy-HKDF suites, strict Clippy, formatting, requirement and
owner consistency, and SBOM comparison. Both AES public consumer routes passed
at Rust 1.90.0/1.99.1 in debug/release plus Cortex-M compilation. Modern and
legacy packaged HKDF consumers passed at both endpoints, including their
diagnostic negatives and Cortex-M checks.

These working-tree checks are not the clean-commit final release gate. Earlier
AES campaign executions retain their original input fingerprints and dates;
version/lock/document changes can make those records outdated. No historical
result is promoted or relabeled as a new execution. Candidate commit, scoped
pentest/retest, final gate and exact-commit GitHub/CodeQL are still pending.
