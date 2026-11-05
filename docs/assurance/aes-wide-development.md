# AES-192/256 development slice (v0.27.1)

Status: development candidate, not release or deployment qualification.

The [2026-11-05 pentest dispositions](aes-wide-pentest-remediation.md) preserve
all findings, the test-oracle hardening, qualification milestones and pending
clean-commit release provenance. This is not an exact-commit release approval.

The default-off `hazmat-aes-block` feature now exposes `Aes192Key` and
`Aes256Key`, plus optional `Aes192ExpandedKey` and `Aes256ExpandedKey`.
The façade's existing explicit feature forwarding exposes these same types.
Key storage is exactly 24/32 bytes; cached schedule storage is 208/240 bytes.
Blocks remain exactly 16 bytes. There is no generic user-defined AES variant,
automatic key-size selection, allocation, key export, mode or authentication.
The external-provider contract remains AES-128 only; no HSM is required.

Ordinary keys expand into clearing operation-local scratch. Cached keys retain
key-equivalent schedule material until explicit clear or Drop. All four owners
are non-Copy/non-Clone/non-Debug/non-Send/non-Sync. Input key copies remain the
caller's responsibility. Secret output owns its destination independently of the
key lifetime. Admitted secret destinations clear on error/unwind; explicit
public ciphertext is staged and only copied after success. Public decryption
is not provided. Aborts, forgotten owners, compiler copies, spills, registers,
paging, dumps and physical attacks remain outside those storage guarantees.

## Current checks

- FIPS 197-upd1 Algorithms 1–3: exact 12/14-round expansion and inverse/forward
  operations, including AES-256's additional SubWord step. Complete Appendix
  A.2/A.3 schedule comparisons use the pinned reference PDF.
- SP 800-38A F.1.3–F.1.6: four published block pairs per key width, both
  directions through both owner forms and explicit public encryption. Using
  these examples does not introduce an ECB mode API or CAVP claim.
- All eight AES-192/256 single-block AESAVS KAT response files: 700/810 records,
  respectively, in both directions with ephemeral/cached owners. Fixture hashes,
  strict parser negative controls and package inclusion are checked. This is
  not CAVP validation, MCT/MMT or validation of any mode API.
- Independent OpenSSL forward/inverse comparisons for 64 reproducible public
  keys and 32 blocks per direction per width: 4096 cases per width, each checked
  through both owner forms. Inverse inputs are independent synthetic ciphertext,
  not output of the implementation under test. Secret and public encryption are
  both checked; OpenSSL is a test oracle, not a production dependency.
  The differential runner records one absolute executable path, version and
  SHA-256, preflights published examples, passes that path to every invocation
  and requires an unchanged executable after the tests. Host/shared-library
  authenticity is not established by those identity checks.
- Eighteen compiling mutation controls across all widths, including missing
  AES-256 SubWord, wrong AES-192 schedule dependency, shortened rounds, wrong
  inverse round key and omitted clearing of either new schedule width. A
  compile failure is not accepted as a detected arithmetic/cleanup defect.
- Caller-storage canaries, explicit clearing, Drop, output outliving keys and
  reuse after clearing; injected errors/unwinds at every expansion and round
  checkpoint, including cached import and public-output preservation.
- Paired compiler diagnostics for each owner: exact widths, aliasing,
  lifetimes, move-after-clear, trait restrictions and public-output authority.
- Eighteen isolated downstream tests across all three widths, through direct
  and façade imports, debug/release, on fourteen pinned Rust compilers from
  1.90.0 through 1.99.1 (56 host configurations). Both compiler endpoints also
  check default-off feature gates and compile the public consumer for
  `thumbv7em-none-eabi` (four builds). The wide consumer exercises encryption
  and decryption, both owner forms, explicit clearing, Drop, canaries,
  independent output lifetimes and caller unwinds. These use checkout sources,
  not package archives; target compilation is not target execution.
- Five bounded Kani harnesses over the production field/layout helpers: field
  multiplication, shift permutation/inversion, round-key bounds for all three
  widths, exact wide-parameter admission and schedule indices referencing
  initialized words. The schedule proof assumes the loop's aligned admitted
  offset; it does not prove the loop or full AES cipher correct.
- Emitted Drop dispatch for all seven public AES owners on x86_64 Rust
  1.90.0/1.99.1, release abort/unwind. Each configuration checks descriptor flow
  to the delegated core destructor and rejects twelve broken-IR controls.
  This does not establish operation-scratch, register or compiler-spill erasure.
- Separate emitted operation-scratch checks on the same four configurations:
  fourteen bodies across both widths, including the exact generic helpers
  called by ephemeral and cached owners, plus four explicit-clear methods.
  Every modeled normal/error/recoverable-unwind exit dispatches each live local
  scratch allocation's full extent to core clearing; 130 broken-IR controls
  are rejected per configuration. Outlined output guards have a checked
  distinct/noalias descriptor ABI; this check does not prove their lifecycle
  or reprove the core destructor. Runtime/API checks cover those separate
  boundaries. Fatal cleanup, aborts, spills and whole-frame erasure are excluded.
- Bounded secret-dataflow analysis of all eleven portable LLVM helpers and
  fingerprint-bound assembly review on the same four configurations. See the
  review below for the public-control argument and strict limits; this is not
  whole-program constant-time or physical side-channel qualification.
- A separate 26-campaign zero/FF host timing screen covers both widths,
  ephemeral/cached encrypt/decrypt/public-output key and block contrasts, plus
  cached import/Drop. OpenSSL validates both classes before measurement. Each
  campaign fixes 512 pairs, four repetitions, 32 warmup pairs and alarm score
  10 in advance; no samples are discarded and no retry-to-pass is allowed.
  This is not a fixed-versus-random campaign or constant-time qualification.
- Scoped native/MSRV, optimized, ASan and selected Miri registrations in
  `brynja-verify aes`; registration is not an execution receipt. Read the runner
  for the current result and fingerprint of each check.

## Still required before closing v0.27.1

The retained HKDF package checker recognizes the composition crate's exact
five-file fixture set for each AES width. It rejects missing/extra/symlinked
inputs, broader include patterns and altered archive bytes; thirty runner
regression tests cover the selection and packaging boundary. This compatibility
work does not exercise AES through package archives or close v0.27.2 acceptance.

The development checks and [normative/control mapping](../security-controls.md#aes-192256-development-contract-v0271)
are in place. The [candidate notes](../../release-notes/RELEASE_NOTES_0.27.1.md),
facade version, consumer pins, SBOM and finite checklist are prepared. The
candidate refresh passed the registered AES checks, retaining the already-current
wide timing result. Owner pentest/retest and the clean-candidate finite release
gate remain pending. Broader compiler and target qualification remains
separate; the AES-family claim
register is not promoted from future-work to qualified implementation.

The already scheduled v0.27.2 work remains there: packaged portable acceptance,
AESAVS MCT/MMT, broader AArch64/final-linked/LTO qualification and stronger
fixed-versus-random timing. Hardware backends and optional hardware adapters
retain their own later milestones; they are not prerequisites to using the
portable Rust API for an appropriately scoped development application.

## Bounded host timing observation — 2026-11-05

The first registered `aes/wide-timing-screen` run passed its independent
preflight and recorded zero alarms across 26 campaigns on Linux x86_64,
logical CPU 0, Rust 1.99.1, release opt-level 3, fat LTO, one codegen unit,
overflow checks enabled and panic abort. OpenSSL 3.5.3 was the independent
oracle, not a production dependency. The largest absolute paired score was
2.778891688653562 (AES-192 cached decryption, block contrast), below the fixed
threshold 10. No alarm was discarded or measurement retried for this result.

Ephemeral campaigns time key construction, operation and key/output Drop.
Cached-operation campaigns construct the schedule before the timer and reuse
it for all four repetitions; schedule Drop is outside that timer, while secret
output Drop is inside. Cached-import campaigns time construction and Drop only;
their preflight additionally encrypts a block to validate the imported schedule.
Fixed-width keys or blocks are all-zero versus all-FF with the other input
filled with 0x37. Each campaign alternates 256 AB and 256 BA measured pairs after
32 warmup pairs. Allocation, formatting and stdout are outside timed operations.

The runner retains raw measurements and metadata locally at
`verification/.runner/logs/2-1793879473104997538.log`, SHA-256
`b6a510a73c6872fc85178ae6e686335953c9190e02ff017b4614811b37fd6bf1`.
The measured binary SHA-256 is
`af75816069310c29a14350a24632951844651ef65c92dc2e503b4e07e4c9547d`;
the scoped input fingerprint is
`974aca87dcc20f90407c4260b81da6ec869463113b2463514ff632436ecdd55b`.
These are unauthenticated local observations, not signed certification evidence;
the raw log is local runner storage, not a bundled published artifact.

This small deterministic contrast cannot rule out rare inputs, timing leakage,
cache effects, microarchitectural differences, final-linked transformations or
physical observation. It does not inherit AES-128 timing conclusions or imply
cross-compiler/target qualification. The stronger fixed-versus-random work
remains v0.27.2. Missing/duplicate/reordered samples, wrong policy metadata,
invalid times, oracle failures and alarms fail closed. Regression tests ensure
failed preflight prevents measurement and failed measurement does not retry.

## Eleven-helper machine review — 2026-11-05

The registered dataflow check now covers the original six helpers and five
additional AES-192/256 helpers. All six original assembly fingerprints are
unchanged on both compiler endpoints. Their existing
[public-control argument](aes128-development.md#six-helper-machine-review--2026-11-04)
continues to apply. The five new instruction streams were inspected on Rust
1.90.0 and 1.99.1, x86_64-unknown-linux-gnu, release opt-level 3, fat LTO,
one codegen unit, overflow checks enabled; abort and unwind builds reproduce
the same normalized streams per compiler. This is local implementation review,
not independent approval or target timing qualification.

| Additional helper | Control and address argument in the inspected assembly |
| --- | --- |
| `expand192` | Key length must be 24. Forty-six schedule-word iterations advance only public indices. Rust 1.99.1 computes periodicity using a multiply/shift sequence on the public offset; 1.90.0 narrows the bounded offset to a byte and uses constant multiplication and shifts. Neither divides secret data. Bounds, loop exit and RotWord/SubWord selection depend only on public counters. The four inverse calls consume secret bytes, whose results feed only fixed rotates/XORs, scratch and schedule values, not addresses or branches. Four-byte scratch clearing is delegated to core. |
| `expand256` | Key length must be 32. Fifty-two schedule-word iterations use a public index starting at 35 and ending at 243 (1.99.1), or -208 through zero with fixed displacements (1.90.0). Masking the public offset selects ordinary words, RotWord/SubWord/Rcon at position zero, or the additional SubWord at position 16. The emitted switch becomes comparisons/branches, not a secret-indexed table. Inverse calls and affine arithmetic use fixed operations; bounds/status and addresses remain public. Scratch clearing has fixed extent four. |
| `wide_add_key` | Round and schedule length are public arguments. The round is shifted by four; fixed byte offsets 0–15 are checked against the public length before schedule loads. Rust 1.90.0 combines these offsets using OR, 1.99.1 primarily uses LEA. Secret bytes only enter the XORs into fixed state offsets. Failure/success status is set from bounds/control, not cipher values. |
| `transform192` | Public direction selects forward/inverse paths; middle rounds are 1–11 or 11–1. First/last schedule accesses use offsets 0–15 and 192–207. Row permutations use fixed offsets in 16-byte stack scratch. Branches on add-key results use its public status. Shared substitution and mix helpers retain their existing reviews. |
| `transform256` | The same control/address structure uses middle rounds 1–13 or 13–1 and final schedule offsets 224–239. Saved state/schedule pointers, public loop counters and core-clear call pointers do not derive from secret bytes. |

The transform helpers' indirect clear calls come from the exact core-clear GOT
symbol, with a fixed local pointer and extent 16. ABI and GOT integrity are
assumptions, not proven properties. Secret spills remain visible in the emitted
code and are not claimed erased. Neither this review nor the cleanup checker
establishes register/spill/whole-frame erasure.

The LLVM model treats every load as secret and propagates taint through scalar
operations, truncation, selects and loop-carried phi values. It rejects secret
branch/switch selectors, addresses, shift counts, remainder operands and public
helper arguments/status. Remainder is admitted only for the observed i8/i64
constant-24 form. Wide helpers are resolved from the concrete public encryption
consumers and exact 208/240-byte schedule ABIs; all eleven portable definitions
and their call edges are required. Unknown helpers, aliases, instructions or
calls fail closed. Regression controls cover the additional operations, each
new helper's taint propagation, wrong/missing widths and removed call edges.

`scripts/aes/machine-review.json` pins eleven instruction-stream fingerprints
per compiler; it has no automatic refresh mode. Normalization preserves the
instructions, operands, offsets, constants, local control flow and call identity.
Changes require re-review. This is change detection relative to inspected
streams, not an assembly taint proof or final-linked application analysis.
Wrappers, core implementation, other compilers/targets, speculative effects,
power/EM observation and instruction timing remain outside its scope. No
production Rust changes were needed for this checker expansion.
