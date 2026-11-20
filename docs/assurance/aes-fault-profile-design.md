# Archived AES fault-integrity research: design for review

Status: unfinished research archived under
[`research/aes-fault-integrity`](../../research/aes-fault-integrity/README.md).
No v0.27.7 release or public API is planned; this is not a gate for GHASH.
The bounded scope was accepted by the owner on 2026-11-13 before the prototype
was built, but the model was never qualified.
Baseline: signed v0.27.6 (`c5b7f181`). No fault-integrity API is implemented or
qualified by this document. Existing portable, accelerated and provider APIs
are unchanged. The historical proposal is retained in the
[deferred roadmap slot](../RELEASE_PLAN.md#v0277---aes-fault-integrity-research-archive),
not as a release approval or current exit criteria.

Owner decision: "Please do so lets accept it and move into implementation."
This accepts the bounded integrity scope and documented confidentiality residuals,
including option (b) for domain-local constants, remote outcomes, stage timing,
passive exposure and application-enforced retirement. It does not qualify an
implementation, waive DC1 or approve unreviewed core/assembly primitives. Concrete
capture, codeword, release and binary-evidence obligations remain to be met.

## Purpose and non-goals

Provide optional detection of explicitly bounded computational corruption for
AES-128, AES-192 and AES-256, encryption and decryption, with operation-local
and cached schedules. Require neither an HSM nor an external adapter. Keep
ordinary users on the existing APIs unless they deliberately select this profile.

The algorithm remains AES as specified in
[FIPS 197-upd1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf),
including all valid block values and fixed points. This proposal is an engineering
fault model, not a NIST-prescribed countermeasure, validation or certification.
No ciphertext/input equality heuristic or encrypt-then-decrypt check using the
same corrupted schedule substitutes for independent computation.
The initial design uses same-direction redundant computations only. Inverting
the primary result using the same AES key, independently captured and expanded
by the other implementation,
is a possible alternative, not inherently invalid, but has different input and
fault-propagation obligations and is not silently substituted into this model.

Not promised: arbitrary voltage/clock/laser/EM resistance, power/EM protection,
universal constant time, complete compiler spill/register erasure, authenticated
message encryption, protection against a hostile OS/DMA engine, or validation of
an arbitrary external provider. Software fault injection is not physical evidence.

## Protection boundary: faulty blocks versus observable outcomes

The proposed guarantee is bounded output integrity, not general protection
against fault attacks. If established for D1-D4/S1/DC1, withholding incorrect
blocks removes the released-faulty-output channel used by differential fault
analysis (DFA), including modeled round-reduction outputs. This is a specific
confidentiality benefit, conditional on the model and intact trust boundary;
it does not establish key confidentiality under chosen faults. See the original
[AES DFA analysis](https://arxiv.org/abs/cs/0301020). No universal number of
faulted blocks needed for key recovery is asserted.

Not mitigated: recovery from success/alarm outcomes, failure-stage timing,
termination behavior or the selection of correct outputs that survive the
checks (safe-error/SIFA); passive side channels and memory disclosure; and
out-of-model faults. A correct ciphertext is not a neutral observation when
whether it is released depends on a secret-dependent fault's effectiveness.

Safe-error and statistical ineffective fault attacks (SIFA) are explicit,
unresolved confidentiality risks. For a selected intermediate byte `x`, replacing
it with `v` can yield success when `x == v` and failure otherwise. The externally
observable success/alarm, termination, retry or response distribution can therefore
leak secret-dependent information even when no incorrect block is released.
See the researchers' [SIFA explanation](https://sifa.isec.tugraz.at/) and
[analysis of masked redundant circuits](https://arxiv.org/abs/2107.01917).
Neither generic masking nor infective computation is assumed to solve this
automatically; a confidentiality claim would need its own design and analysis.

Terminal retirement is not a one-probe guarantee: ineffective injections may
allow repeated successful calls.
Owner recreation, process restart and reimport can multiply observations of the
same key. No universal "256 probes recover the key" bound is asserted; actual
recovery depends on the reachable site, intermediate/key relation and fault model.

Application guidance: treat a detected computational fault as potential key
compromise, retire that key across owners/processes/devices, and investigate and
rotate it through a trusted recovery path. Do not merely recreate the owner or
reimport the same key, including from backups. This crate cannot enforce global
retirement or rotation. Rotation does not undo a leaked observation or detect an
ineffective injection, and is not a proof of SIFA resistance. Deployments requiring
confidentiality under active physical faults cannot rely on this profile alone.

Applications must not expose distinct alarm responses, error codes or logs to
untrusted peers: map them to the same external failure response as other failures.
Keep detailed diagnostics access-controlled. An alarm must trigger retirement,
not automatic retry, including retries by protocol middleware. Later terminal
errors can also reveal that an earlier fault was effective. Uniform responses
reduce explicit remote oracles; they do not hide timing, connection termination,
lost availability or filtered successes and do not establish SIFA resistance.

Global retirement nevertheless matters: if the APPLICATION enforces it across
all uses at the first alarm, it stops further cryptographic queries under that
key; the crate alone stops only that owner. The observable transcript includes the
ineffective outcomes before that alarm, their correct outputs and timing, and the
first alarm itself. There is no universal bound on this prefix: repeated
ineffective faults can continue without retirement. Estimates such as one or two
observations require additional probability/independence assumptions, not this
chosen-fault model. Nor does "about 128 rotations recover a byte" follow: genuinely
independent replacement keys do not supply guesses about one unchanged secret
byte. Reimporting the SAME key defeats this protection; rotation must mean new
key material, not a new owner identifier.

Tests must distinguish detected effective corruption, undetected incorrect output
(failure), ineffective injection with correct output (integrity-only result),
unreached hooks and out-of-model controls. Record ineffective cases and observable
outcome distributions separately; never count them as "faults detected" or as
confidentiality assurance. The third review and owner decision above establish
scope acceptance, including stage timing and additional passive exposure below.
Earlier acceptance of other AES limitations was not used as this approval.

## Proposed initial configuration

- Portable software only, `no_std`, no allocation and no new dependencies.
- Tentative default-off feature: `aes-fault-integrity`, explicitly forwarded by
  the facade. It would depend on `hazmat-aes-block`; this deliberately also
  compiles/exposes the existing unchecked owners. A Cargo feature is not an
  enforcement boundary: applications requiring checked execution must select the
  distinct profile types, not assume unchecked APIs have disappeared. Neither
  provider nor accelerated features would enable it implicitly.
- Distinct key owners for each width and schedule lifetime, with exclusive
  mutable operations and terminal local state. No Copy, Clone, Debug, export,
  Send or Sync. Clear/Drop consume or retire all owned key-equivalent storage.
  Every new owner's opening rustdoc must state bounded output integrity and the
  unresolved safe-error/SIFA outcome channel, with the global-retirement rule;
  require indistinguishable peer-visible failure responses, protected diagnostics
  and no alarm retry, and warn that terminal errors can expose a prior alarm.
  The feature/type name must not imply general fault-attack resistance.
- No accelerated/provider selection parameter in the initial API. Enabling
  unrelated Cargo CPU features must not select a different profile backend. LLVM
  can still change code for `-C target-cpu`/`target-feature`, so qualification must
  bind the exact compiler, target, feature set, optimization, panic and LTO settings. Any
  later backend selection must reject unsupported combinations before key use,
  never silently route to ordinary unchecked AES.
- Separate profile errors for detected inconsistency and a terminal owner;
  existing ordinary AES error/API contracts are not changed.

These names and storage details are proposals, not a source-compatibility promise.
Width, direction and lifetime must all be included from initial acceptance;
an AES-128-only result does not close this milestone.

Initial architecture candidates are x86_64 and little-endian AArch64, not yet
admitted configurations. Existing opaque core copy boundaries on those targets
are starting points, not automatic profile qualification. Other architectures,
Miri/Kani safe models and ordinary Cortex-M compile checks do not establish D3
or C1/DC1. A profile constructor must reject unadmitted configurations; test-only
models may run there but must not be presented as deployable profile support.

## Trust boundary and observation interval

The proposed claim begins after independent key/input replicas have been
captured and validated, and ends at the final validated output handoff. Correct
caller input before capture is an assumption: two copies of the same already
wrong caller key cannot reveal what the caller intended. A fault during copying
into one replica is in scope when it is represented by a listed injection site;
corruption of the common source before both copies is not.

Capture requires two separate opaque copy operations, each loading caller memory
independently, into separately borrowed primary and secondary storage. Do not
derive both replicas from one compiler-held value. The secondary is complemented
or independently encoded, with capture/encoding sites included in D3. Inspect
final-linked code for independent loads and retained boundaries for every admitted
configuration. `copy_from_slice`, `inline(never)` or a Rust compiler fence alone
does not establish this. The existing non-x86_64/non-little-endian-AArch64 copy
loop is not D3 evidence. A common bus/memory corruption affecting both source
reads remains excluded; two calls cannot make the physical source independent.

Addressing, memory isolation, instruction decoding and the integrity of the
observation mechanism are trusted except at enumerated sites below. Output-copy
corruption before readback is now modeled as D4. Corruption after the final
readback, arbitrary return/commit jumps, and faults preventing successful cleanup
or rollback remain excluded. The reduced but nonzero check-to-use window must
remain visible in public documentation.

Rust's aliasing rules help organize independent storage; they do not establish
physical isolation of memory, buses, registers, cores or power domains. Source
diversity also does not prove compiler-emitted independence.

## Fault budget for review

An injection site must name its domain, stored object/intermediate, bit or byte,
and operation stage. "Any corruption anywhere" is not an acceptable shorthand.

| Class | Proposed model | Required result |
| --- | --- | --- |
| D1: local transient data | One byte mutated at one declared intermediate in one computation or expansion domain, using a named family below | Detect and retire, or demonstrate that the result remains the correct AES result |
| D2: local persistent storage/constant | One byte changed in one retained key replica, schedule or enumerated domain-local constant, including a preexisting change; it persists across uses | Retained key/schedule mismatch must retire before release; domain-local constant faults must be detected if they would alter the result, or release only the correct result; every detected mismatch retires, but constant-fault detection on every use is NOT promised |
| D3: replicated capture | One byte corrupted while writing one key/input replica after reading the common source | Reject inconsistent capture or detect divergent computation before release |
| D4: output-copy corruption | One byte corrupted during the destination write, before readback | Detect before returning a secret owner/public success; clear secret output or restore public output and retire |
| S1: local computation skip | One declared round/arithmetic-instruction skip confined to one domain, without altering addressing, domain boundaries or release flow | Detect if the resulting output differs, otherwise record an ineffective injection, not a detection |
| L1: encoded-state corruption | One byte replacement or one bit flip in a valid lifecycle/release codeword at a declared storage/register site | Cannot produce a different valid authorized codeword; reject invalid states before use/release |
| C1: check bypass | One enumerated comparison-result/flag/register fault or branch skip forcing one designated validation stage to pass, with otherwise correct computation | Correct output only; no false claim that this alone tests computational fault detection |
| DC1: data/skip plus one bypass | One D1/D2/D3/D4/S1 event plus one C1 event bypassing one designated independent validation stage | Mandatory acceptance obligation: a separate intact validation path must prevent incorrect release; currently unimplemented/unqualified |

The budget spans import and the entire key lifetime: a retained persistent fault
is not reset to "zero faults" on the next call. A second independent data fault,
even in a later call, is outside this initial budget. Correct-output ineffective
injections are a separate confidentiality-risk category, not detected faults;
persistent key/schedule mismatch and every detected constant-induced mismatch
must retire the key rather than be silently repaired or normalized away. A
latent constant fault may persist through correct-output calls as described below.

### Mutation families and effectiveness

Record the mutation function and the injection site, not just "replacement".
The byte budget permits the following families; their leakage classifications
describe local mutation, not an unconditional claim about the final alarm:

| Family | Local value change | Outcome qualification |
| --- | --- | --- |
| Fixed nonzero XOR delta, including a bit flip | Always changes that byte, independently of its value | Changes the final result when injected at a state boundary with an unchanged bijective suffix; elsewhere later value-dependent logic may suppress it. Under that suffix premise the alarm bit is value-independent, not necessarily its timing |
| Set to attacker-chosen constant `v` | Ineffective exactly when `x == v` | Value-dependent effectiveness; possible safe-error oracle |
| AND/OR masks, stuck-at bits | Depends on the targeted bits; identity masks change nothing | Value-dependent effectiveness; filtered correct outputs may be biased |
| Declared byte function `f(x)` | Depends on its fixed points; identity is always ineffective | Analyze each function and reachable site; arbitrary replacement does not imply random or value-independent faults |
| S1 instruction/round skip | Depends on the state and skipped computation | Fixed points or unused results can make it ineffective; not automatically a detection |

Even nonzero XOR faults inside an arithmetic circuit can be suppressed by later
value-dependent computation. For example, flipping an operand before AND with
a secret-dependent zero bit may leave the result unchanged. Do not extrapolate
the intact-permutation-suffix argument to key expansion, internal circuit wires,
overwritten temporaries or repeated persistent operands. The
[SIFA researchers' examples](https://sifa.isec.tugraz.at/) explicitly include
bit-flip propagation and filtering. These are distinct from an isolated byte
change at the state boundary used in the analytic argument below.

### Persistent constant sites

Before implementation approval, enumerate each domain's constants and their
physical representations: S-box affine constants (including AES `0x63` and inverse `0x05`), round
constant seeds/values and update rules, field-reduction (`0x1b`) and mixing constants,
secondary-circuit constants, and domain-local complement/encode/decode masks.
An evolving expansion intermediate is D1; persistent corruption of its seed or
constant operand is D2. Include emitted immediates as well as stored constants
where a value-only byte fault preserves instruction decoding/addressing.

For v0.27.7, domain-local constant faults use the bounded output-integrity rule,
NOT a promise to attest every constant or detect every persistent alteration on
the next use. With an intact independent computation and validation path, a
constant fault that changes the result must be detected before release and retire
the owner; when both results remain correct, that call may succeed while the
constant fault persists. DC1 still requires an intact validation path when one
check is bypassed. Each enumerated constant site needs mapped injection/binary
evidence for these obligations, including faults that leave some outputs correct.
Only computation-domain constants belong to this argument: a constant affecting
shared validation, authorization or both domains cannot be classified as harmless
domain-local D2 merely because it is an immediate. Map such dependencies to the
check/control budget or the explicit common-mode exclusions.

The duration and selection of correct outputs released under a persistent
constant fault are part of the unresolved PFA/SIFA-style outcome-leakage residual.
Output agreement proves neither absence of that fault nor confidentiality.
There is no alarm-triggered retirement until a mismatch is actually detected.
Retained key/schedule integrity checks before and after use remain required;
this change does not waive them or permit reuse after any detected mismatch.

The previous draft's pre/post-use validation of every emitted immediate was an
unjustified obligation, not an implemented protection. A source comparison of
literals may be folded away, and comparing another literal does not establish
integrity of the actual operand used by AES. Runtime code inspection or changing
constants into redundantly encoded data with opaque loads would be separate
designs with new dependencies, fault sites and costs. Neither is required or
claimed here. Stronger constant attestation can be considered later if a narrower
outcome-leakage residual is requested; it would not by itself solve SIFA.

Any constant or decode mask shared by BOTH domains is common-mode infrastructure,
not two independent D2 sites. Inventory and test its corruption as an excluded
negative control; physical separation of equal literals must be checked in the
linked artifact, not inferred from duplicate source declarations.

Attacker choices include the site, replacement byte, operation and public input.
There is no assumption that an attacker selects a random byte or does not know
the comparison schedule. The implementation must not rely on fault rarity.

Out of scope initially: correlated corruption of both domains; common input/key
replacement before capture; multiple independently corrupted storage locations;
code/constant/pointer/length corruption outside enumerated sites; skips crossing
domain boundaries or arbitrary jumps; skipping both release guards; coordinated
valid-codeword substitution or bypass of the latch checks beyond L1/C1;
corruption after the final readback or during rollback/cleanup;
and an attacker who can alter the injector, oracle or test record.

Common-mode faults and multi-fault/control-flow attacks must still receive
negative-control experiments showing the boundary. They must not be silently
counted as successful coverage. If review requires broader protection, revise
the design and budget before implementation; do not relabel exclusions as fixes.

Required negative control: correlated skips leave both domains equal to the
unmodified input. Agreement and readback can then release plaintext through the
public-ciphertext path; for decryption they can return unchanged ciphertext as
purported plaintext in a `SecretBlock`. Exercise both directions: clearing
ownership does not make an incorrect decrypted value correct. Two domain skips
or a common-mode skip are outside this
budget, but this severe confidentiality consequence must be demonstrated and
documented. Do NOT "fix" it with echo rejection: legitimate AES fixed points
remain valid outputs, and equality is not a backend-correctness test.

## Analytic argument and its limits

For a fixed correct key schedule, the suffix of an AES state transformation is
bijective. If exactly one state value changes at a defined boundary and the
remaining suffix is unchanged, the output changes. Likewise a changed byte in
one round-key XOR application changes that state; an intact independent domain
and intact comparison then detect different outputs. Tests must establish that
each implementation/injection site satisfies these premises, not replace them.

This is NOT a theorem for every D1/D2/S1 site. A fault in a raw key or key-expansion
intermediate can alter multiple future round keys; a persistent operand may be
read several times. The faulty and reference paths then do not share one intact
suffix. Nor must skipping a bijection change its input: bijections can have fixed
points. Site-specific arguments and retained input/key/full-schedule comparisons
are therefore required. A wrong output must never pass, but correct output alone
does not establish absence of corrupted storage or confidentiality leakage.
In particular, the set of correct outputs selected for release by the alarm
filter is itself a SIFA observation, not evidence of confidentiality.

Full retained-key/schedule integrity checks cover these additional cases and
support DC1; they are not justified solely as redundancy for an output compare.
Post-use checks occur BEFORE any destination write, and cannot be deferred until
after output release. Readback adds a later check; it does not replace them.

## Proposed computation and storage architecture

Two domains compute the same direction from separate validated replicas:

1. Primary: existing portable AES arithmetic, expanded from its own key replica.
2. Secondary: a separately structured implementation, with independent key
   expansion and different state representation/substitution structure. Proposed
   direction: bit-plane Boolean operations instead of the primary byte-oriented
   field-exponentiation implementation. Its key expansion must use its own
   reviewed substitution circuit, never `portable::field::sbox`. No
   third-party circuit or implementation is reused. The initial private workbench
   evaluates algebraic-normal-form Boolean polynomials derived from the FIPS
   substitution table; its coefficient tables are read only in public monomial
   order. It is intentionally not a minimized gate-count circuit.
   No secret-indexed lookup tables.

The secondary must not call the primary's substitution, field arithmetic,
round, expansion or state-layout helpers. A second call to the existing primary,
even with fresh buffers, is insufficient.
Review and test the secondary independently against frozen answers before
using agreement between implementations as a detector.

Operation-local owners retain independent key replicas and construct separate
schedules for each operation. Cached owners independently construct and retain
two schedules. Compare the complete schedules under a defined normalization at
import, before computation and after computation but BEFORE destination writes,
not only a short checksum that can collide. Never
overwrite a bad replica with its peer and continue. Comparisons must not mutate
the schedules into agreement or use a normalized copy as both operands.

Dataflow must retain separate input/state/output replicas until release. The
normalization/conversion path itself needs named injection sites: a shared
bad converter must not become an unacknowledged trusted AES implementation.
Cached integrity checks and computation checks are complementary; neither
alone proves the original key was admitted correctly.

Owners take separate disjoint caller borrows for both replicas, not one exposed
array sliced internally. This makes logical ownership explicit, not DRAM-row
separation: adjacent separate allocations may still share a fault domain.
Complement/bit-plane encoding must make the modeled common-zero/stuck-at controls
diverge, but cannot establish general burst/Rowhammer protection. For example,
applying the same XOR mask to both plain/complemented representations can preserve
their relation while changing the decoded key. Simultaneous clearing or corruption
of both stores is tested as a boundary/control, not a universally detected class.

Shared/common-mode inventory (must stay explicit during implementation):

- `Scratch`, `OwnedSecretRegion`, `SecretRegionInitialization` and their Drop paths;
- `clear_owned_region`/volatile clearing and `secret_memory_transfer::copy_bytes`;
- comparison accumulation/predicate boundaries, normalization and planned readback;
- any shared constants, complement/decode masks and expected integrity values;
- compiler/linker, instruction set, process/address space, caller source and CPU;
- proposed narrow opaque core capture/comparison/encoding primitives.

`aes.rs` forbids unsafe code. Required volatile/assembly boundaries must therefore
live in narrowly scoped, separately reviewed `brynja-core` primitives, with safe
interfaces and fallback/admission rules. Existing core constant-time primitives
are not fault-qualified by reuse. In particular, `ct_eq` is inline source code
and `Choice`/`secret_difference_is_zero` expose a normalized one-bit decision;
neither supplies an independent wide release authorization.

## Failure and release state machine

An operation moves `Healthy -> InProgress` before accessing a key schedule.
Only successful validation may move it back to Healthy. Every detected mismatch,
internal error or unwind leaves it terminal. Subsequent calls return a terminal
error without expanding or transforming; only destruction/clearing remains.
No implicit retry, reset, fallback or replacement binding. New owners require
`&mut self`; they cannot be thin wrappers retaining the existing `&self` lifecycle.

Use distinct multi-byte lifecycle codewords with a specified minimum Hamming
distance greater than the modeled bit/byte corruption budget, and reject every
invalid encoding. Include zeroed/uninitialized storage as invalid. Verify exact
codeword checks and stores in emitted code; widening a bool after a faulty check
does not harden its origin. This mitigates L1, not an arbitrary instruction that
writes a complete valid Healthy word or bypasses validation. Terminal/in-progress
states must not become authorized through any modeled single-byte replacement.

Secret destinations are admitted into clearing guards before fallible work.
Public encryption stages output privately and changes caller output only at the
tentative commit followed by validation. Decryption returns a clearing secret owner, never a
public plaintext path. Public ciphertext still needs the existing explicit
acknowledgement. All intermediate states/schedules and comparison accumulators
use clearing owners; exclusions for compiler copies, abort and forgotten owners
remain explicit.

Adopt readback before return for both destinations. The two validation stages
must independently reload actual destination bytes, not reuse the source/register
value the compiler already knows. D4 plus C1 must not bypass both readback checks.

For BOTH secret and public paths, readback R1 fully compares freshly loaded
destination bytes against BOTH the primary result and independently decoded
secondary result. R2 independently reloads the destination and repeats BOTH full
comparisons with separately accumulated results and a different structure/order
and encoding. Success requires both paths; neither reuses the other's decoded
buffer, accumulator, equality bit or authorization. Fault sites include those
independent decoding/check paths. Do not assign R1 only to primary and R2 only
to secondary: a primary fault copied to the destination plus a bypass of R2
would otherwise pass (D1+C1). With either one path bypassed, the intact path
must still check both replicas. Earlier schedule/result checks are not a reason
to weaken this pairing.

D4 plus a separate primary-data fault is TWO data faults, not DC1's one data
event plus one bypass. Include it as an additional control with an intact
secondary, without silently broadening the promised budget. A single fault
propagating from primary into the copied destination remains one D1 event.

- Secret path: write while retaining clearing ownership, perform independent
  readback checks against intact redundant results, and only then issue a
  `SecretBlock`. On mismatch/error/unwind, clear and retire. Today's
  `SecretRegionInitialization` has no readback accessor before `finish`; design
  a narrow guarded verification primitive, or retain the finished clearing owner
  internally until verification. Neither may expose the unverified owner/bytes.
- Public path: guard a snapshot of the original destination, tentatively write,
  read back and validate, then finalize success. On error/unwind, restore the
  snapshot and retire. Treat that snapshot as secret-bearing clearing storage:
  the API does not prove that the OLD destination bytes are public. Rollback
  must precede return/unwind and the snapshot must be cleared on both paths.

Under safe exclusive borrowing the caller cannot read through that borrow during
the call, so rollback preserves API-level failure atomicity. It does not erase
transient exposure to DMA, a hostile process observer or physical observation.
The snapshot, rollback, final return and after-last-readback interval require
explicit assumptions; this is not physically atomic publication.

DC1 requires two independently evaluated release checks over intact domain data,
not the same previously computed boolean tested twice. Failures must latch before
any release authority is issued. A bypass hook may skip exactly one designated
validation stage, not arbitrarily jump over the entire commit protocol. The
implementation and emitted-code review must demonstrate the claimed separation.
DC1 is mandatory for this milestone, not an optional later claim. Until it passes
the milestone remains unfinished; no configuration is currently admitted.

Use separately accumulated full comparisons with different structure/encoding
(direct and independently decoded/complemented) and opaque boundaries preventing
CSE, load forwarding and replacement by a shared early-exit `bcmp`/`memcmp`.
Two Rust loops, `black_box`, or compiler barriers alone are not evidence of this.
Review their final-linked call sites and each retained check/latch/commit path.

Release authorization must retain independently produced wide encoded results,
with specified codeword distances, validation and single-use consumption. Do not
XOR-fold differences into a checksum: two mismatches can cancel. A 128-bit token
made by expanding one `Choice` is still a one-bit failure point. Full comparisons,
independent origins and protected control flow are required; large token width
alone is not a proof. Token construction/validation and condition flags are
explicit C1/L1 targets, including DC1 combinations. Exact encoding remains a
review obligation before implementation, not a newly invented cryptographic MAC.

### Candidate receipt model (not an approved release encoding)

The private `authorization_model` workbench now makes one candidate concrete for
review. It is absent unless BOTH its enclosing test build and the non-Cargo
`brynja_fault_primitives` cfg are selected. The private transaction and cached
workbench now exercise fresh receipt construction and guarded tentative writes.
This is experimental integration, not approval of a public encoding or owner.

Each path retains sixteen two-byte lanes (32 bytes per path, 64 bytes total).
Each forward lane separately reloads the destination and invokes the opaque full
comparison against BOTH replicas. It encodes the two raw OR-of-XOR accumulators
by XOR with `[0xa5, 0x3c]`. The reverse path independently reloads and compares in
reverse order; it XORs the complement of each AND-of-XNOR accumulator with
`[0x5a, 0xc3]`. It visits its lanes in reverse order. No normalized equality bit
is widened, no difference checksum is folded, and a prior lane's accumulator is
not reused. All scratch and receipt storage uses clearing owners.

With stable operands and intact computation, success is the repeated path-specific
pair. A mismatch with either replica changes at least sixteen bytes and sixteen
bits of EACH fully computed receipt. Therefore a single stored-byte replacement
cannot repair that stable mismatch into success. The two success codewords are
bitwise complements (256-bit distance); zero is invalid for both. These are
representation properties, NOT a bound on faulty token construction, transient
observations, partially written receipts, expected-constant corruption or faulty
validation. Codewords are not MACs, secret authenticators or physical anti-replay.

The model uses ordinary Rust validators, evaluates both, then consumes the
non-Copy/non-Clone candidate by value. This only models type-level consumption;
it has no operation identity and does not bind later destination contents.
Tests deliberately demonstrate stale-receipt acceptance, two-check bypass and
common-mode agreement. A single-check replacement plus divergent data is rejected
in the source model, but is NOT C1/DC1 evidence for a released binary.

Before using any such encoding, review and qualify the capture/loop bounds,
independent secondary decoding, each accumulator-to-lane store, full receipt
validators, expected constants, separate final guards, lifecycle completion and
commit/return ordering in the exact artifact. The current Rust `Result` combine
is specifically NOT a protected final guard. Keep fresh destination checks tied
to guarded publication; no public API may accept an old receipt. A generation
counter alone would not protect an after-check destination mutation.

This intentionally expensive reference requires 32 full comparison invocations
and 32 fresh sixteen-byte destination copies per observation, before receipt
validation and any AES work. It is not a final performance/API decision. The
64-byte receipt payload excludes loop/ABI spills, snapshots and other scratch;
there is no stack-size claim. Encoding review, emitted-caller review and exact
instruction-level simulation remain required before production integration or admission.

An additional private workbench experiment now tests an opaque **tentative**
copy on x86-64. It validates all 32 forward receipt bytes and all 32 reverse
receipt bytes, then uses separate rejection branches inside one assembly block
before the sixteen-byte copy. It does not combine the two check results into a
single returned Boolean controlling that write. Its one-byte report is only a
diagnostic, never release authority. Other targets/Miri/Kani use an ordinary
functional model for this new copy experiment; the existing opaque ARM comparison
leaves do not imply an opaque ARM copy/commit implementation.

The primitive alone does not solve receipt freshness, independent decoding,
lifecycle checks, readback, rollback or the final return window. Correctly formed
but stale/forged receipts can copy any proposed value. The private transaction
therefore constructs and consumes receipts inside a helper that accepts no receipt
or alternate proposed-data argument, then independently reloads/checks the actual
tentative destination against both results. This narrows ordinary misuse, not
physical fault possibilities between capture and use. It is not safe to expose
this as a protected AES operation.

The public workbench path writes only within its existing rollback guard and
commits after both readbacks and lifecycle completion. The secret workbench path
uses a clearing staging block for the guarded copy, then the existing
`SecretRegionInitialization::write` and private finished owner; two fresh checks
of the ACTUAL secret destination precede `SecretBlock` construction. This does
not make the secret initialization write an opaque guarded commit. No mutable
secret accessor or new production core secret-ownership API was added. Lifecycle
predicates, readback decision combination, rollback/commit flags and final return
remain unqualified Rust control flow. Source-checkpoint tests of those paths do
not qualify their compiled machine instructions.

An optimized private public-transaction experiment exposed eliminated lifecycle
checks: a state-byte mutation after the tentative write was accepted because the
compiler could prove there were no ordinary Rust state writes. With the primitive
cfg selected, each lifecycle check now snapshots the actual state through
`copy_secret_region` into clearing scratch before comparing. The supported opaque
transfer boundary preserves these observations in the tested builds, not the
integrity of their predicates, branches or completion/commit flags. The same
native mutation now rejects, restores output and retires the owner on both tested
x86-64 compilers. Source-only controls had not established this property.

The finite debugger experiments exercise the leaf and a private integrated
public transaction in test executables, not a shipping AES owner: hardware
breakpoints allow PC/register/flag/memory mutations without
patching executable bytes. They do not qualify the complete C1/DC1 budget or
simulate physical fault propagation. See the implementation record for exact
artifact identities, tested events and negative-control scope, including the
[integrated transaction observations](aes-fault-profile-review.md#eleventh-implementation-slice-native-transaction-observations).
In the original fixture, output corruption with either one readback result
bypassed rejected; bypassing BOTH results or corrupting output after the last
check escaped. The later permit experiment below changes the two-readback
outcome, while preserving the final-check window as a negative control. Neither
complete AES owners nor the full fault budget have acquired native qualification
from these observations.

The subsequent secret-transaction fixture checks the actual admitted destination
after its initialization write, not just private staging. It exposed an in-model
DC1 gap: one destination-byte corruption plus a ZF flip at the combined readback
decision released the wrong SecretBlock. This was not accepted as an exclusion.
The primitive-enabled secret path added a fresh permit after those
readbacks: invalidate lifecycle state, freshly compare the actual destination
against both results, and conditionally restore InProgress through the two opaque
receipt guards. Completion separately reloads and checks that state. The original
combined-branch injection and the two-readback-result bypass now reject, clear
and retire on both observed x86-64 compilers. The historical counterexample is
retained in the [secret transaction record](aes-fault-profile-review.md#twelfth-implementation-slice-native-secret-transaction-observations);
the [permit correction](aes-fault-profile-review.md#thirteenth-implementation-slice-fresh-secret-release-permit)
records its changed outcome. The public path now uses the same fresh permit
after its destination readbacks and before completion. Both paths reject the
two-readback-result bypass on the two observed x86-64 compilers. Three further
native cases per path exercise a forged permit report, a forged permit result,
and a changed restored lifecycle codeword. Each rejects and retires, restoring
public output or clearing secret output. See the
[public permit and runner record](aes-fault-profile-review.md#fourteenth-implementation-slice-public-permit-and-native-permit-observations).
These finite corrections do not qualify receipt construction, the permit's
entire instruction surface, final return, complete AES owners or the full DC1 model.

The next native fixtures call the private cached owner with real FIPS keys and
blocks, both independently expanded schedules and both AES engines. All three
widths exercise public encryption, secret encryption and secret decryption;
the previous transaction-only fixture supplied constant result bytes instead.
The new finite events are still located at the final permit boundary, not inside
key expansion or AES rounds. They reproduce expected acceptance or retirement,
output restoration/clearing, and borrowed-key clearing on both observed x86-64
compilers. See the [cached-owner observation record](aes-fault-profile-review.md#fifteenth-implementation-slice-native-cached-aes-owner-observations).
This closes a fixture-integration gap, not the complete linked-owner fault model.

There is now also a private operation-local schedule owner. It keeps separately
borrowed raw-key replicas between calls, expands each domain from its own
temporary capture, checks retained storage before/after computation, and drops
both temporary schedules before the transaction can release output. It shares
the encoded-key import and final transaction with the cached owner. Functional
tests cover clearing, repeated use, errors and unwinds; finite native permit
observations now exercise both lifetimes. See the
[operation-local implementation record](aes-fault-profile-review.md#sixteenth-implementation-slice-operation-local-schedule-owner).
The new post-use key checks, local recapture, expansion and cleanup still require
complete emitted-code/fault-budget qualification; the profile remains private.

Finite native observations now go earlier than the permit: selected key changes
at secondary-computation entry, secondary schedule/round-count changes around
that computation, and input-capture corruption between the two opaque copy
completions. They exercise both owner lifetimes and all widths/routes on the two
observed x86-64 compilers. The post-computation events verify the correct known
answer before corrupting retained storage, then require rejection, so their
outcome does not rest on a faulty-output mismatch. The input-copy event verifies
that the second copy still reads the unchanged caller source. See the
[retained-state/capture record](aes-fault-profile-review.md#seventeenth-implementation-slice-native-retained-state-and-input-capture).
These are selected native D2/D3 observations, not complete D1/S1/C1/DC1 coverage,
universal compiler/target qualification or physical independence evidence.

A later combined native probe found that an early input-capture error could be
forged into a successful return while both result buffers still held matching
initial zeros. The private transaction now independently checks a per-operation
completion record marked only after computation and retained checks. The
operation-local owner also checks an inner record before marking its outer one.
The finite retest rejects this case for all widths/routes and both lifetimes on
the two observed x86-64 compilers. A separate native probe flips one bit in a
completed record after correct AES output and requires retirement before
release. Neither observation establishes general C1/DC1/L1 qualification. See the
[completion-bypass record](aes-fault-profile-review.md#eighteenth-implementation-slice-independent-computation-completion).
Selected native observations also change a persistent key byte after the
operation-local retained computation has returned correct output, and then
forge the outer computation's error into success. The still-invalid outer
record prevents release. See the
[late-boundary record](aes-fault-profile-review.md#twentieth-implementation-slice-native-late-operation-local-completion).
A separate source-evidence S1 campaign now skips each secondary substitution
call site in turn across all widths, paths and owner lifetimes. It changes
test codegen and therefore cannot stand in for an instruction-level probe of
the primitive-only or release binary. See the
[round-skip record](aes-fault-profile-review.md#twenty-first-implementation-slice-secondary-round-skip-source-evidence).
The same selected secondary substitution *call* now has a finite native skip
campaign in both optimized local x86-64 test artifacts. It is stronger than a
source hook because no source instrumentation is compiled in, but it does not
qualify arbitrary in-function instruction skips or physical propagation. See
the [native call-skip record](aes-fault-profile-review.md#twenty-second-implementation-slice-native-secondary-call-skip).

Comparisons process all bytes without early exit on secret-dependent position.
Expose only the final success/failure decision, not the mismatch location,
intermediate values or partial output. That final decision itself may leak as
described above; constant-work comparisons do not remove the safe-error oracle.
Fixed-work source is a requirement, not
a claim of machine-code or timing qualification.

Failure-stage timing remains an explicit residual: pre-use integrity, post-use
integrity, result checks and readbacks can fail at different times; cleanup,
rollback and unwinding also have different paths. No stage number or intermediate
is returned, but a single error code does NOT hide the stage. This draft does
not promise a fixed-duration failure sequence or continue real key operations
after detecting compromised state. A future padded/single-exit design would need
separate safe dummy-work, fault-budget and emitted-code analysis; it is not
established by adding delays or by constant-work equality loops. Include these
timing observations in the accepted outcome-leakage boundary and test records.
For a chosen transient injection, its known site may already predict the stage
that detects it; not every stage distinction adds secret information. Whether
the fault is effective can still depend on secrets, and a persistent or latent
fault's detection stage can depend on the input/key. Do not assume the stage is
always public or quantify extra leakage without a site-specific analysis.

## Costs that must be published

At minimum, duplicated raw-key payloads are 32/48/64 bytes, and duplicated
schedule payloads are 352/416/480 bytes for AES-128/192/256. These are lower
bounds before any secondary representation expansion, owner state, additional
integrity material or scratch; they are not yet the public storage ABI.
Include encoded latch/release state, independently encoded replicas and guarded
public rollback storage in the final accounting.

Expect two computations plus integrity/release checks, and two expansions per
call for operation-local owners. No two-times-cost promise: the secondary may
cost substantially more. Measure stack high-water marks, exact caller storage,
latency and cached tradeoffs before publishing final sizes or performance claims.
Applications still need request/work limits.

This profile can INCREASE passive leakage and memory exposure relative to the
ordinary API: duplicated keys/schedules and checking scratch increase the
footprint and potentially residence time; a complemented key is trivially
recoverable key material, not masking or encryption. Two implementations process
the same key and can supply different, correlated power/EM leakage traces.
Dumps, cold boot and schedule scanning remain concerns. The rollback snapshot
also prolongs the lifetime of the caller's old bytes, which may contain plaintext
or other secrets (not necessarily a key). Integrity redundancy is a tradeoff,
not a monotonic confidentiality improvement or passive-side-channel defense.

## Verification worklist and evidence boundaries

- Freeze the reviewed model and enumerate every injection site. Record width,
  direction, schedule lifetime, site, mutation, detection outcome, ineffective
  cases, observable outcome distribution and whether correct output was released.
  Verify hook reachability and exact populations;
  missing/ignored cases or errors before the intended fault are not coverage.
- Exercise every byte position and replacement at declared storage sites. Use
  bounded exhaustive checks for primitive-level sites where feasible, with an
  explicit rationale for larger-domain coverage. A few plaintexts and byte flips
  cannot justify a universal claim over arbitrary arithmetic/input faults.
- Include preexisting and during-use persistent faults, and demonstrate terminal
  no-dispatch behavior on later calls. Exercise both domains symmetrically.
  Enumerate domain-local constants and shared-constant controls separately;
  record effective and ineffective inputs for persistent faults, not just one
  divergent example. For a domain-local constant fault, check that correct-output
  calls may succeed without claiming constant attestation, while the first
  detected mismatch retires before release and prevents further owner use.
- Inject actual corruption, not just returned errors/panics. Keep unwind/clearing
  regressions as separate lifecycle evidence. Verify secret zeroing, untouched
  public output on rejection, guard bytes and no internal value leakage.
- Test each comparison bypass alone and with modeled data corruption. Include
  common-mode/multiple-bypass controls explicitly marked outside the claim.
- Test encoded state/token bit/byte changes and common-zero/complement controls;
  final-copy corruption, both readbacks, snapshot restoration and unwind ordering;
  and every admitted local round/arithmetic skip. Ineffective skips are not detections.
- Independently test both implementations and the composition using known
  answers, differentials and AESAVS KAT/MMT/MCT for all widths/directions. Preserve
  valid equal-input/output semantics; do not reintroduce echo rejection.
- Add default-off and paired compiler ownership probes through direct/facade
  packages, no_std builds, archive-only consumers, Miri and ASan/LSan. Keep
  data-injection hooks behind a non-Cargo evidence cfg (tentatively
  `brynja_fault_evidence`), following the existing `brynja_cpu_evidence` separation.
  No public feature enables them. Custom cfg is not a security boundary against
  a downstream builder who controls compilation; evidence artifacts must carry
  distinct identity and cannot count as release artifacts. Normal builds must
  be checked for absence of injector exports, hooks and cfg activation.
- Source-level D1-D4 hooks are functional models, not release-binary evidence.
  C1/DC1/L1 and S1 require instruction-level fault simulation at declared sites
  of the exact uninstrumented release-profile artifact, including compares,
  flags/registers, latches, stores/readbacks and commit/rollback/return paths.
  Record artifact hash, compiler/target flags, instruction/address mapping,
  event and simulator semantics; the baseline binary bytes must remain unchanged.
  Patched copies or instrumented twins are supplementary, not that exact artifact.
  The simulator must be validated and its limits recorded. If unavailable, leave
  C1/DC1 unqualified rather than substituting a Rust hook returning true.
- Review final-linked code for domain separation, check retention, clearing and
  secret-dependent behavior under supported compilers/profiles. Define timing
  experiments for this new profile before collecting data; preserve alarms and
  do not retry to pass. Existing inconclusive ARM acceleration work is not
  reopened or promoted to a pass, and cannot qualify this new profile.
- Register scoped `brynja-verify` work as real runners become available. No
  placeholder passing evidence, broadened release gate or mandatory hardware
  service is added by this design step.

Independent review must address the model and implementation. Physical claims
would additionally require named-device fault experiments and environmental
assumptions; software injection alone cannot establish them.

## Current closure checklist

This checklist consolidates the existing v0.27.7 obligations; it does not add a
publication gate or narrow the owner-accepted model. Functional answers and
selected fault observations are not interchangeable with qualification.

| Obligation | Current evidence | Remaining closure deliverable |
| --- | --- | --- |
| Independent AES and composition | Frozen KATs and schedules; secondary and composite-owner MMT/MCT for all widths/directions; caller-buffer lifecycle checks | Preserve these regressions; complete independent differentials and package-external coverage of the eventual public profile |
| D1/D2/D3/D4/S1 site coverage | Source-data campaigns and selected native capture, retained-storage, result, destination and call-skip experiments | Freeze a complete candidate site inventory with mutation families, lifetime/stage, expected outcome and analytic justification; map every required site to each candidate artifact; missing sites remain open, not silently excluded |
| C1/DC1/L1 release authorization | Separate opaque primitives, candidate encoded receipts and lifecycle, finite native bypass/combination observations | Cover each designated validation/authorization stage and the supported data/skip combinations, including propagation into output, import and subsequent use; review emitted separation and final handoff, not only leaf helpers |
| Supported-build admission | Non-test constructors reject; private fixtures can run | Define and review the compiler/target/features/optimization/panic/LTO and final-linked artifact contract; admit only qualified configurations and reject the rest before key capture |
| Public opt-in API | Private cached and operation-local owners only | Implement width-specific owners, feature/facade forwarding, consuming clearing, errors, ownership restrictions and boundary documentation; no usable public profile before qualified admission |
| Scoped operational verification | Private tests and explicit development scripts | Register real profile runners, package-only consumers, compile-fail/no_std checks and affected Miri/sanitizer runs; do not convert development observation markers into current qualification passes |
| Timing and independent review | Earlier ordinary/accelerated AES evidence is separate; design reviews accepted the bounded confidentiality tradeoff | Predeclare and run the new profile's timing experiment, retain alarms, and independently review the implementation and qualification record; the earlier ARM timing deferral is neither reopened nor inherited as this profile's pass |

The next qualification task is the **candidate site inventory**, not another
unbounded sequence of sample injections. For each entry record a stable site
identifier, domain/object, operation phase, applicable widths/directions/key
lifetimes, mutation values or classes, persistence, expected outcome, source
location, exact emitted location and the check/bypass pairings it must survive.
State which cases are proved by a bounded argument and which are demonstrated
only on fixtures. Describe trusted/excluded behavior separately; an untested
required site cannot become an exclusion through omission from the inventory.
The inventory must also account for the simulator's own correctness and limits,
failed/unconfirmed attempts and explicit out-of-model controls.

The initial [source candidate inventory](../../assurance/aes-fault-sites.json)
now locates 22 regions in the private implementation. It is **not yet a frozen
or exhaustive fault-site inventory**: each region must be expanded into its
individual byte/stage/instruction cases. The stable IDs distinguish input/key
capture, the two computation domains, retained storage/constants, results,
import/use checks, completion, receipts, destination writes/readbacks, final
permission and lifecycle handoff. All entries remain **open**. Widths and paths
inherit the global scope where applicable; each entry lists its owner lifetimes
(local key recapture applies only to operation-local owners). Import regions
apply before all subsequent paths. Secret-destination staging/finish/readback
does not describe the public-output path.

The [stage expansion](../../assurance/aes-fault-stage-expansion.json) gives those
22 regions 112 named source-stage work units, including 39 candidate decision
stages across the nine bypass families. The selected
[native replay](../../assurance/aes-fault-native-sweep-observations.json)
passed 16 existing probe invocations across two pinned test ELFs in the first
and third sweeps; an intervening repeat passed 15/16, with one unconfirmed
completion probe. A complementary roster passed 12/12 after excluding an
inapplicable guard test absent from these executables; its first attempt also
had an intermittent operation-local/public probe. Neither
fills the required per-instruction site IDs or DC1 temporal pairings, and the
test ELFs are not release-linked qualification artifacts.

A separate [named-body map](../../assurance/aes-fault-symbol-boundaries.json)
locates executable symbol spans for seven of the previously wholly unmapped
regions on both test ELFs. A symbol span does not cover inlined copies or
enumerate faultable instructions; the stricter emitted-site count remains
ten partly mapped and twelve unmapped.

The native guard-leaf fixture is present in separate pinned `brynja-core`
test ELFs, not the `brynja-crypto` test ELFs. Its
[14 leaf-case replay observations](../../assurance/aes-fault-guard-artifacts.json)
are development evidence only; they do not establish AES caller C1/DC1
coverage or final-handoff authorization.

The [decoded-candidate record](../../assurance/aes-fault-instruction-candidates.json)
now gives 3,435 exact instruction offsets inside the seven named-body
families on the two test ELFs; 559 are syntactic control candidates. None
has yet been assigned a reviewed source-stage/fault-model identity. The
[wider native matrix](../../assurance/aes-fault-owner-path-matrix-observations.json)
ran 72 selected script invocations across owners, paths and widths, with one
unconfirmed completion probe (71/72). Later bounded repeats also intermittently
missed the exact fixture-pass summary despite confirmed breakpoints and normal
exit, so those attempts remain unconfirmed. These are development observations,
not whole-model or final-linked release-artifact qualification.

One `lifecycle-handoff/completion-state-check`
[instruction candidate map](../../assurance/aes-fault-completion-decision-map.json)
now pins seven selected codeword-check instructions per ELF, with shared
state-select/write and return candidates kept separate. The
[single-bit codeword matrix](../../assurance/aes-fault-lifecycle-codeword-matrix-observations.json)
confirmed 3,072/3,072 selected local cases across every codeword byte and
bit, all widths, both owner lifetimes and both secret directions. This is
evidence for that one L1 boundary only; other lifecycle stages, C1/DC1
pairings, compound faults and final-linked admission remain open.

The [guarded readback byte matrix](../../assurance/aes-fault-readback-byte-matrix-observations.json)
confirmed 1,152/1,152 local XOR-1 mutations immediately before each of the
two guarded-write destination checks across all widths, owners and public/secret
paths on those same two test ELFs. Fixture outcomes confirmed rejection,
public rollback or secret cleanup, retirement and rejected reuse. This is
only the tentative-write boundary: the later actual secret destination,
C1/DC1 bypasses and release-linked artifacts remain open.

The [actual secret-destination byte matrix](../../assurance/aes-fault-actual-secret-byte-matrix-observations.json)
separately confirmed 768/768 local XOR-1 mutations before the forward and
reverse validator readbacks of the caller's secret destination. It covered
both secret directions, all widths and owners on the two pinned test ELFs;
fixture outcomes confirmed destination clearing, retirement and rejected
reuse. This narrows the D4 mapping gap at the actual destination, but does
not cover other mutation families, C1/DC1 bypasses, permit/handoff faults or
release-linked artifacts.

Each region names its mutation family, expected integrity outcome, unique source
anchor, remaining expansion work and relevant development runners. A runner
reference is **not a pass or execution receipt**. Existing fixture observations,
including failed/unconfirmed attempts, remain in the chronological review record;
they cannot populate a complete emitted-site mapping automatically. In particular,
the primary-result experiment exercises XOR 1 only, and the secondary skip
experiment covers selected substitution calls, not every local instruction.

The inventory separately lists nine candidate C1 regions and keeps DC1 pairing
enumeration open. Pairings need temporal/compatibility reasoning, including import
and subsequent uses; neither arbitrary sampling nor an unexamined Cartesian
product establishes coverage. Domain-local constant faults retain the accepted
filtered-correct-output residual. Shared constants, correlated echo in either
direction and final-handoff/trusted-cleanup failures stay visible as negative
controls/exclusions, not passed cases.

`python3 scripts/aes/check-aes-fault-sites.py` checks this source bookkeeping only.
It rejects duplicate IDs, missing/ambiguous source anchors, dangling runner or
bypass references, missing model classes and attempts to label the inventory or
an artifact qualified. It does **not** prove source completeness, detect arbitrary
code changes under an unchanged anchor, run faults, or certify a binary. Exact
artifact mappings are empty and need a separately reviewed representation.
This optional development check is not a new release gate or verifier pass.

The separate [partial emitted-site candidate map](../../assurance/aes-fault-emitted-site-candidates.json)
now labels operation-local key-copy word steps, key-import and block-input
capture call/return contexts, retained pre/post validation calls,
primary/secondary transform return boundaries, inner/operation-local outer
completion-codeword stores, deny-first permit boundaries, paired
guarded-write destination/staging checks, later validation of the actual
admitted secret destination, healthy secret-result construction and return
into the pinned fixture caller, on two x86-64 test artifacts. Its
[bookkeeping validator](../../scripts/aes/check-aes-fault-emitted-sites.py)
cross-checks 1158 deterministic context labels against the distinct
[local recapture](../../assurance/aes-fault-local-recapture-map-observations.json)
and [current capture](../../assurance/aes-fault-capture-current-observations.json)
records, plus the [retained-validation call record](../../assurance/aes-fault-retained-validation-observations.json)
and [result-boundary record](../../assurance/aes-fault-result-map-observations.json),
plus the [inner completion record](../../assurance/aes-fault-completion-map-observations.json)
and [outer completion record](../../assurance/aes-fault-outer-completion-map-observations.json),
plus the [permit-boundary record](../../assurance/aes-fault-permit-map-observations.json)
and [guarded-write check record](../../assurance/aes-fault-readbacks-map-observations.json),
plus the [actual secret-destination record](../../assurance/aes-fault-secret-destination-map-observations.json)
and the [secret-result construction record](../../assurance/aes-fault-secret-result-map-observations.json),
and the [fixture-caller return record](../../assurance/aes-fault-secret-caller-map-observations.json).
These are not 1158 unique instruction addresses or fault-injection results.
All ten partially mapped source families remain OPEN; the other 12 source
families are wholly unmapped, nine bypass families remain OPEN, and the source
inventory's whole-artifact `artifact_mappings` is still empty. No build is admitted.
For secret routes, these mapped `guarded_write` calls inspect private staging;
the later validation call reads the actual admitted destination before permit.
In the healthy paths, lifecycle completion precedes the returned secret-region
descriptor stores, and the pinned fixture caller receives that descriptor.
Fault behavior, bypass resistance and general final-handoff integrity remain
open.
Separately, a [finite lifecycle-completion mutation record](../../assurance/aes-fault-lifecycle-complete-observations.json)
observes rejection after one debugger-induced in-progress codeword byte
change in the same test ELFs. This is not promoted to the partial map's
`fault_results`, a complete source-family pass, or release qualification.

The first concrete expansion is the inventory's `byte_case_sets`: three finite
source-case populations with deterministic labels including key width, owner,
path, replica, byte position, mutation family and operand. They describe copy
boundaries, shared key-import validation and propagation through both owners.
The checker validates their dimensions, unique test anchors and trial totals;
enumerating a label does not execute it. Their source-test results and exact
limits are recorded in the [capture expansion](aes-fault-profile-review.md#forty-second-implementation-slice-two-replica-capture-case-expansion).
These sets do not complete either capture family: arbitrary source values,
within-copy instruction events, local key recapture, complement-encoding windows
and DC1 bypass combinations are still open. They add no D4 actual-destination
injection coverage; the owner tests check output behavior after a D3-like source
capture mutation. No emitted mapping or admission is inferred from these counts.

A separate [post-encoding source matrix](aes-fault-profile-review.md#forty-eighth-implementation-slice-post-encoding-source-matrix)
checks both key replicas after complement encoding and before import validation.
It is test-only source instrumentation, not native fault evidence; emitted
complement-write sites and their bypass pairings remain open.

The [operation-local recapture source test](aes-fault-profile-review.md#forty-ninth-implementation-slice-operation-local-recapture-source-mutations)
mutates one per-call scratch key replica after both retained-key copies and
before schedule construction. It covers selected effective and ineffective
byte mutations across every key width, replica byte, and block path. This
test-only checkpoint does not map or fault emitted local-copy instructions;
the native site and DC1 obligations remain open.

A [bounded local-recapture observation](../../assurance/aes-fault-local-recapture-map-observations.json)
now maps the two operation-local copy-call boundaries and the reviewed core
wrapper/opaque-copy shape in two exact x86-64, primitive-only test ELFs.
Public-fixture hardware breakpoints confirm distinct persistent key-replica
sources, distinct scratch destinations, both copy-leaf entries and returns,
primary and complemented byte copies, and ordinary cleanup for each width
and block path. The same pinned artifacts also passed read-only hardware
breakpoints and single-stepping at every eight-byte word load/store pair for
the 16/24/32-byte recaptures.
The [runner](../../scripts/aes/check-aes-fault-local-recapture-map.py) rejects
unknown ELF hashes or changed instruction shapes. The byte-tail offsets are
static mapping only; no fault was injected into any word or byte site. This
is not a within-copy corruption or bypass experiment. Source and DC1 families
remain OPEN, and no production build or other target is admitted.

There is now a separate [partial capture-chain observation](../../assurance/aes-fault-capture-map-observations.json)
for two exact x86-64 test artifacts. It maps the two capture call/return boundaries,
the core wrapper and its opaque copy leaf, including word/byte load/store offsets.
An exact-shape checker and public-fixture hardware-breakpoint observations verify
the caller/source/destination flow. The two observed register allocations and
Rust result encodings are accepted only as complete paired patterns, not as a
compiler-version rule. See the [mapping record](aes-fault-profile-review.md#forty-third-implementation-slice-exact-capture-chain-mapping).
This is **not** a complete emitted-site inventory: within-copy faults, data/bypass
pairings and the rest of the implementation remain open. Accordingly the source
inventory's whole-artifact qualification mappings remain empty. Unknown code
shapes fail closed, and no production or downstream build is admitted.

A [finite input-store experiment](aes-fault-profile-review.md#forty-fourth-implementation-slice-native-input-store-faults-and-completion-bypass)
now uses that exact copy mapping to select one byte lane in the loaded word
immediately before a store. It changes only that lane with XOR 1, executes the
mapped instruction once and checks the actual destination, original source and
other replica. Both input replicas and all 16 positions are covered on the
named public fixtures, including one selected combined bypass at the failed
`Retained::compute` return. This is still not full D3/DC1 coverage: the computation
rejects before producing either AES result and leaves its completion record
unmarked. Other bypasses, import stores, mutation values, source values and
instruction sites remain open; this observation cannot qualify the public API.

A separate [key-import store experiment](aes-fault-profile-review.md#forty-fifth-implementation-slice-native-key-import-store-faults)
covers XOR-1 writes at every key byte in both capture replicas, for all three
key widths and both owner lifetimes. Each selected fault rejects construction,
returns no owner and clears both admitted key buffers; the caller's key and
storage guards remain unchanged. It covers data faults before complement
encoding, not import-check bypasses, later capture windows or full D3/DC1.
The new fixtures change the test ELF hashes: earlier observations retain their
original artifact bindings and are not results for these new binaries.

A [cached-import decision experiment](aes-fault-profile-review.md#forty-sixth-implementation-slice-cached-import-decision-bypass)
now combines those key-store faults with forcing the first inlined import
comparison decision to success. On the same two test artifacts, every selected
corrupted import still rejects and clears both key buffers. The runner locates
the actual inlined decision rather than assuming the standalone validator is
called. This is one finite cached-owner pairing, not coverage of operation-local
imports, every comparison/return site or the complete DC1 requirement.

The [operation-local import/use experiment](aes-fault-profile-review.md#forty-seventh-implementation-slice-operation-local-importuse-boundary)
tests the same selected decision bypass across public encryption, secret
encryption and secret decryption. With a corrupted imported key and that bypass,
construction may return an owner. Its first operation must nevertheless reject,
withhold or clear output, and retire that owner; later calls report retirement.
The observed key buffers clear on owner drop, not necessarily at the instant of
retirement. This is a bounded first-use result, not complete import or C1/DC1
qualification.

Only after that inventory and emitted-code review determine a satisfiable
initial configuration can build admission be designed as an approval mechanism.
A compiler-version check, target cfg, source hash or green sample runner alone
does not establish the final-linked contract. No configuration is admitted now.
After implementation/qualification and the scoped review, use the existing
finite final-check, GitHub and tag workflow; no new mandatory HSM, remote service
or repeated whole-repository crypto campaign is introduced here.

## Review questions and implementation order

Scope question 1 is accepted above. Resolve the remaining construction and
qualification questions during implementation before exposing a usable profile:

1. Is bounded output integrity with unresolved safe-error/SIFA leakage a useful
   accepted scope, including failure-stage timing and potentially increased
   passive exposure? Distinguish the removed faulty-block DFA channel from
   outcome leakage. Do callers understand global key retirement/rotation and its
   limits, including ineffective injections and same-key reimport?
2. Do independent opaque captures, storage encodings and all shared core
   dependencies establish the proposed D3 boundary on each exact configuration?
3. What exact lifecycle/release codewords and independently accumulated checks
   meet L1/C1/DC1 without fold collisions, single-bit expansion or compiler merging?
4. Can instruction-level simulation exercise the exact uninstrumented artifact
   and validate the claimed bounded skips/register/flag faults?
5. Do guarded secret readback and public rollback cover D4/DC1 while retaining
   honest assumptions about transient visibility and the final return window?
6. Which sites have a valid unchanged-bijective-suffix argument, and what separate
   reasoning covers expansion, persistent constants/operands, normalization and
   local skips? Does every mutation family retain its site-specific classification?

Approval of this draft is not evidence that those obligations are already met.

The [review dispositions](aes-fault-profile-review.md) record the changes
and corrections. The executable design sanity checks in
`scripts/aes/test-aes-fault-model.py` are counterexamples/toy-model tests only,
not AES implementation, physical evidence, or SIFA resistance proofs.

Then proceed in small tested slices: independent secondary primitives and
vectors; independently generated schedules; fault-model injection harness;
terminal owner and guarded output integration; external API/package checks;
dynamic/emitted-code/timing evidence; independent implementation pentest/retest.
The private workbench now includes independent bit-plane linear layers, rolling-
word key expansion and block rounds for AES-128/192/256 in both directions.
It passes the 2,078 frozen AESAVS KAT records and complete FIPS Appendix A schedules,
and is also type-checked in private non-test development builds whose admission
set is empty. These are functional answers, not fault qualification:
no qualified independent capture, qualified release authority or public
fault-integrity owner is implemented yet. A private transaction prototype now
exercises candidate lifecycle codewords, ordinary Rust error/unwind retirement,
guarded secret readback and public rollback. Its ordinary predicates and
completion flags are NOT fault-qualified release authorization; independent
opaque checks, final-linked inspection and DC1 remain pending. See the
[transaction implementation record](aes-fault-profile-review.md#fourth-implementation-slice-private-lifecycle-and-rollback-prototype).
The next private integration adds separate clearing key borrows, cached schedules
and complete retained-storage checks at import and before/after computation,
before destination writes. Its source comparisons and normalization remain
unqualified; see the [retained-storage record](aes-fault-profile-review.md#fifth-implementation-slice-retained-storage-integration).
Key/input capture and each destination readback now call the existing core
transfer boundary separately. A local optimized x86-64 test-artifact inspection
retains the two copies but also confirms that LLVM canonicalizes both comparison
orders into the same implementation. See the
[capture/readback record](aes-fault-profile-review.md#sixth-implementation-slice-capture-and-readback-boundaries);
independent opaque comparison and encoded authorization remain unfinished.
An optional non-Cargo primitive workbench now preserves separate forward and
reverse comparison leaves in observed x86-64 and AArch64 test artifacts. This
addresses the observed comparison canonicalization locally, not release authority:
the raw two-byte accumulators and outer predicates are not wide authorization,
and C1/DC1 remain unqualified. See the
[opaque comparison record](aes-fault-profile-review.md#seventh-implementation-slice-opaque-comparison-workbench).
An explicit source-data campaign now
exercises retained schedule-byte replacements in both engines, separately from
the normal tests. This covers selected D2 storage sites with public fixtures,
not the complete fault model or protected output release. The
[implementation record](aes-fault-profile-review.md#third-implementation-slice-source-data-corruption-campaign)
gives exact populations, commands, controls and limitations. Remaining slices are pending.
The later [primary filtered-output source model](aes-fault-profile-review.md#thirty-first-implementation-slice-primary-filtered-output-source-model)
records an ineffective reduction-constant occurrence that permits a correct
output before a later effective occurrence retires the same owner. This is a
development illustration of the accepted SIFA outcome-leakage residual, not
release-artifact or physical-fault evidence.
The [correlated constant negative control](aes-fault-profile-review.md#thirty-second-implementation-slice-correlated-constant-negative-control)
now demonstrates that matched wrong S-box behavior in both domains can release
a wrong block; a single-domain counterpart rejects. This deliberately remains
outside the one-domain fault budget.
If a required guarantee cannot be established, leave v0.27.7
unfinished and report the specific gap rather than silently narrow the claim.
