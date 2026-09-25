# KMAC sustained review — v0.24.49

Updated 2026-09-25. This consolidates the KMAC verifier work; it is **not a
release gate, release receipt, independent retest, or whole-API erasure proof**.
The detailed historical record remains in [kmac-verify/README.md](kmac-verify/README.md).

## Result and scope

The retained KMAC verifier composition work item is complete: actual debug
caller control flow, suffix framing and bit packing, state/reader ownership
transfers, comparison handoffs, destructor requests, and exact links to the
previously inspected debug/optimized reader implementations have been checked.
No production defect or production-code change resulted from this pass.

This closes the *KMAC-specific verifier composition* item, not all of F1.
Absorption/finalization payload computation, kernel erasure, and shared SHA-3
caller boundaries retain their separate contracts and review obligations.
KMAC key setup and tag/XOF APIs were source-reviewed against their existing
functional/lifecycle tests; they were not silently added to the verifier's
emitted-code coverage. Complete register/spill erasure for an arbitrary KMAC
call is not established. The [qualification checklist](qualification-status.md)
continues to track wider caller/worker review and independent retest.

## Exact provenance

These diagnostics replay retained LLVM/assembly; they do not compile or execute
Rust, and their entry points reject an attempted subprocess invocation.

- Record: ignored `dist/kmac-verify-nft_nl5x/observations.json`.
- Record SHA-256:
  `d1b6515193cabfb68c4223b60dd9850d85c42525c2096927363ef32372d4b16f`.
- Protected original archive SHA-256:
  `6a85f5de89c4e0e0f7c3dc725bfb7ab09c93b35525bcdb09645c361d75d26e52`.
- Source-matching checkout: ignored `dist/register-cleanup-review-source`,
  based on `cc5b9add`, with diagnostic-only additions. Exact recorded source
  and artifact validation stays enabled.
- Endpoint compilers: Rust 1.90.0 and 1.98.1; retained Linux x86-64/AArch64,
  portable and accelerated feature builds. Arm runtime observations in this
  record are QEMU, not native Apple/Windows/Arm qualification.
- Production sources in `brynja-mac-kmac`, `brynja-hash-sha3`, `brynja-core`
  and `brynja-crypto-cpu` are unchanged between `cc5b9add` and main `036f1e4e`.
  A later Arm fixture test correction still prevents presenting this old
  record as a capture of current main. No source hash was relaxed.

## Completed diagnostic matrix

Counts below are bounded modeled cases, not independent cryptographic vectors
or executions on each physical platform. Debug instances comprise sixteen
portable and eight accelerated verifier instantiations.

| Area | Completed check | Regression check |
| --- | --- | --- |
| Whole debug verifier | 24 instances; 7,872 cases; 579,264 byte-pair handoffs; 528 selected modeled unwinds | 264 caller/helper mutations rejected |
| Actual suffix and state consumption | 24 instances; 5,720 cases; 15,600 comparison handoffs; 336 selected modeled unwinds | 96 suffix/helper mutations rejected |
| Actual bit-packer below whole verifier | 24 instances; 4,064 cases; 12,464 absorb handoffs; 18,528 borrowed-byte fragment handoffs; 48 selected modeled unwinds | 120 helper mutations rejected; all 65,536 public-byte arithmetic operand pairs checked |
| Reader reconciliation | 48 exact debug caller-to-reader links; 16 portable and eight accelerated optimized pairs | 240 wrong/missing/altered-link regressions rejected; 96 controls |
| Input-byte borrowing | 88 emitted shared packer instances; same-row xor primitive assembly checked | 440 borrow regressions rejected; 88 controls |

Whole/suffix checks additionally pass 24 block-label controls and seven direct
payload/copy boundary rejections. Packer mutations pass 24 harmless-comment
controls. No-op mutations preserve the helper's return type; they are interpreted
LLVM mutations, not compiled production mutants. The 88 shared packer bodies
include old movable-API instantiations: checking their byte-borrow route does
not extend the scoped ownership guarantee to those old APIs.

The whole-verifier model executes the original root and helper CFGs. It checks
exact expected-length rejection, consumed state, key/tag strength, aligned and
partial output, multi-chunk comparison, first/last mismatch, producer failure,
and selected boundary unwind. Candidate, engine, staging, metadata difference
and pending-byte payloads cannot be loaded as model scalar values. Only the
declared comparison boundary exposes the authentication decision.

The suffix model includes actual `append_suffix`, `Option::take`, frame/packer
construction and destruction. The packing model adds actual `push_bit_string`,
`push_bytes`, `push_bits`, flush and counter helpers. Its independent handoff
oracle checks absent/empty, 1-, 33-, 168- and 4,097-byte messages, every valid
partial-byte width, and early/late absorb failures. Pending input remains a
borrow; successful flushes request its clearing. Every modeled exit traverses
the actual caller cleanup, including both frame and packer destruction.

The reader-link check binds the original artifact row, full function body and
ABI, not just a matching symbol name. It composes review contracts by exact
identity; it does not execute all caller and reader payload effects in a single
machine model. Optimized reader inspectors are reused rather than replaced.

## Source review outside the verifier probe

- Key setup: `Core::new` owns its cleanup guard before absorption. `absorb_key`
  borrows the key; its encoded length and partial-byte frame have their own
  clearing destructors. Key length/classification and public framing counters
  are not promised to be erased from every compiler temporary.
- Updates: the actual operation guard destroys state and metadata after a
  returned failure or recoverable unwind. Successful update retains the borrow.
- Fixed tags: public output is deliberate declassification. Secret finalization
  clears the complete destination before shape/strength/finalization checks.
- XOF: finalization frames `right_encode(0)` and transfers only borrowed state;
  output length is not substituted into that suffix. Reader errors terminate
  the owner; secret reads clear destinations even after prior termination.
- Scope: outer workspace/metadata/scratch guards cover forgotten inner handles
  and recoverable unwind, not abort or arbitrary platform interruption.
- Portable and accelerated adapters forward borrowed state into their matching
  cSHAKE APIs; they are not new cryptographic implementations.

Existing tests cover these paths in `hardened_in_place/tests.rs`,
`core_state/tests.rs`, `reader/tests.rs`, `xof/tests.rs`, accelerated tests and
`packer/framing_tests.rs`, plus official/API tests. This pass inspected that
coverage; it did not rerun an unchanged Rust/Miri/native campaign or turn
historical return-observer results into a physical-erasure proof.

## Remaining contracts and exclusions

The diagnostic's leaf contracts include SHA-3 absorption/finalization payload
work, public integer encoding, selected slice/iterator operations, comparison
primitives and volatile clearing. The shared helpers have separately recorded
evidence where stated; an injected return/unwind is not a real platform fault.
Clear requests are not measurements of overwritten RAM/registers. Unknown IR
instructions and wrong source/artifact identities fail rather than being skipped.

The multiply-by-one lowering preserves only the exact identity (including
nonoverflow flags); other multiplications remain unchanged. Local byte
arithmetic handlers are exhaustively tested without modifying the shared
interpreter. Mutation tests also caught and corrected an early diagnostic bug
where the supplied root mutant was not replacing the original definition.

No blanket claim covers caller-saved copies, arbitrary spills, preserved caller
registers, signals, abort, snapshots, old movable APIs, or unobserved compiler/
target/ABI combinations. Windows/macOS qualification still needs its appropriate
native evidence after retest. F1 and root `PENTEST.md` remain open for the wider
work; no release-gate rule or backend availability decision changed.

## Reproduce this pass

From the source-matching checkout, use the absolute retained record path:

```sh
record=/home/eldryoth/Work/codex-projects/brynja/dist/kmac-verify-nft_nl5x/observations.json
python3 assurance/register-cleanup/check_debug_kmac_whole.py "$record"
python3 assurance/register-cleanup/check_debug_kmac_suffix.py "$record"
python3 assurance/register-cleanup/test_debug_kmac_whole.py "$record"
python3 assurance/register-cleanup/check_debug_kmac_packing.py "$record"
python3 assurance/register-cleanup/test_debug_kmac_packing.py "$record"
python3 assurance/register-cleanup/check_kmac_review_links.py "$record"
python3 assurance/register-cleanup/test_kmac_review_links.py "$record"
python3 assurance/register-cleanup/check_kmac_packer_borrow.py "$record"
python3 assurance/register-cleanup/test_kmac_packer_borrow.py "$record"
```

Logs are retained outside Cargo's `target/` under ignored `dist/`; the diagnostic
record links their hashes. These are local development artifacts, not a new
release-receipt format.
