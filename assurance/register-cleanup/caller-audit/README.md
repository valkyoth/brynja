# Caller residue audit

Development diagnostics, **not release evidence or an erasure acceptance gate**.
No production API, backend selection, or release workflow is changed by this
fixture. F1 remains open. The sixteen opaque accelerated kernels do not cover
the portable implementations or all code surrounding an accelerated call.

## What executes

Five `inline(never)` C-ABI wrappers invoke the real default-feature-disabled
public `HardenedSha256`, `HardenedSha512`, `HardenedSha3_256`, `HardenedSha1` and
`HardenedMd5` streaming APIs. Each finalizes into a borrowed secret destination,
drops the output owner, and returns only a status. They do not expose the digest.
Separate known-answer tests check the five `abc` digests before output drop.

The optional fixture-only `scoped` feature selects five corresponding borrowed
workspace wrappers. Each constructs secret-free local storage before `with`,
updates/finalizes through the borrowed handle, drops the output, and lets the
scope clear before returning. The input/output/status ABI and observer are
unchanged. Construction is inside the observed wrapper; this is not a probe of
an arbitrary external caller's existing workspace or registers. Known-answer
tests use the selected API profile, not always the old movable implementation.

The fixture-only `higher` profile observes twelve portable scoped constructions:
KMAC, TupleHash and ParallelHash at both strengths, fixed output and XOF. Every
output is 32 bytes. KMAC borrows input bytes 0..32 as its synthetic key even for
an empty message; TupleHash adds one item (including an empty item);
ParallelHash borrows an eight-byte block buffer. Customization is empty.
XOF readers are created and consumed within the scope. This is not accelerated,
threaded, arbitrary-bit, verification-only, cancellation or failure-path coverage.

The fixture-only `accelerated` profile uses the same twelve probes and golden
outputs through the existing scoped execution APIs. It requires a static
AVX2 or Arm Keccak authority and creates distinct root/leaf sessions for
ParallelHash. There is no portable fallback. Construction and its public KATs
are inside the observed wrapper, before any synthetic key/message is supplied.
The worker checks exact route and health; a separate control revokes authority
after workspace construction and requires every identity to reject before input
is accepted. This does not exercise threaded workers or mid-message revocation.

The fixture-only `threaded` profile invokes the public scoped ParallelHash
coordinator with two workers, an eight-byte block and 32-byte secret output.
All four fixed/XOF identities run through portable, required static single-kernel
and required static multibuffer routes (twelve probes). Empty input and complete
four-leaf groups use lengths 0, 32, 64, ..., 256; two markers give 18 observations
per probe. Partial required-mode groups are tested separately for rejection,
not silently replaced by portable work. Checks bind leaf counts, accelerated
counts, worker width, root identity/health and multibuffer counters. Independent
vectors check results before output Drop; pre-cancelled calls must clear output.
The observer runs on the **coordinator after join**, not on the worker threads.
Neither worker-register residue nor OS thread-stack cleanup is measured here.

Linux observers seed caller-clobbered registers before the call and snapshot
them immediately on return, before Rust can overwrite them. Arguments are only
live buffer addresses and public lengths. The snapshot includes nine integer
registers and XMM0–15 on x86-64; X0–17 and V0–7/V16–31 on AArch64. It does not
read uninitialized/dead stack memory, touch Arm's reserved X18, or alter
callee-preserved registers. Deliberately retaining and clearing controls test
the observer, and a classifier test checks the eight-byte marker threshold.
Prefix/suffix canaries check snapshot bounds. The two safe public-call tests
also pass focused Miri; that run does not exercise the assembly observer.

Only repeated **synthetic public test bytes** are used. Fourteen public lengths
from 0 through 256 exercise padding and block boundaries, with two markers:
28 cases per algorithm per configuration. Input and unowned output suffixes
must remain unchanged; every owned destination must clear. Logs contain counts,
not raw register bytes, pointers, inputs, or digests.

An input-marker match demonstrates residue across **this wrapper plus the public
API**. It does not isolate a specific private kernel or instruction. No match
does **not** establish erasure: this narrow recognizer cannot identify arbitrary
digest/schedule values, transformed input, partial bytes, upper vector lanes,
stack spills, or residue on other paths. All records say
`qualifies_register_cleanup: false`, even when every test passes.

## Reproduce

From the repository root, with both endpoint compilers and QEMU installed:

```sh
python3 assurance/register-cleanup/test_callers.py
python3 assurance/register-cleanup/check_callers.py --arm --emit
python3 assurance/register-cleanup/check_callers.py --scoped --arm --emit
python3 assurance/register-cleanup/check_higher_callers.py
python3 assurance/register-cleanup/check_callers.py --higher --arm --emit
python3 assurance/register-cleanup/check_higher_callers.py --accelerated
python3 assurance/register-cleanup/check_callers.py --accelerated --arm --emit
python3 assurance/register-cleanup/check_threaded_callers.py
python3 assurance/register-cleanup/check_callers.py --threaded --arm --emit
cargo +1.98.1 clippy --locked --offline --manifest-path assurance/register-cleanup/caller-audit/Cargo.toml --all-targets -- -D warnings -A clippy::chunks_exact_to_as_chunks
```

The driver uses fresh build directories under ignored `target/caller-residue-*`,
records source hashes and compiler identities, and retains observations plus
MIR/LLVM/assembly for manual inspection. It rejects missing/duplicate records,
skipped controls, invalid counts and source changes during collection. It does
not automatically certify emitted-code cleanup. Arm execution is QEMU, not
native; no native Windows or Apple observation is made here.

Each run records `api_profile` and requires exactly one matching runtime marker.
Missing, duplicated or substituted profile markers fail; a movable run cannot
be presented as a scoped observation. The fixture feature is passed only to
the fixture, not to separately compiled dependencies. Nine collector regressions
cover this selection, observation bounds, missing controls and build overrides.
The higher profile extends the collector to ten regression tests and requires
exactly its twelve identities. `--higher` and `--scoped` cannot be combined.
`--accelerated` is likewise mutually exclusive and requires six tests, an exact
target-specific route marker and all twelve identities. Thirteen collector tests
cover profile/route substitution, lost revocation controls, every exposed x86
CPU's AVX/AVX2/XSAVE flags, and dependency-feature emission under Rust 1.90.
The driver explicitly supplies `+avx2` or QEMU's `+neon,+sha2,+sha3` bundle.
Linux feature enumeration is not a live migration monitor. Do not directly run
the specialized fixture on a deployment without that complete feature contract.

For accelerated emitted-code collection, the fixture is selected through its
isolated manifest; affected dependency libraries are emitted through the root
workspace with `hardened-execution`. Cargo 1.90 rejects selecting a dependency's
features through the isolated consumer manifest. These are development artifact
builds; they do not change production feature defaults or release commands.

The threaded profile instead emits every dependency in one isolated consumer
build using `--emit=mir,llvm-ir,asm,link`, preserving that consumer's unified
feature graph on both endpoint compilers. Fourteen collector tests now include
threaded profile, route, scope, count and emission-command substitution checks.
The threaded profile cannot be combined with another collector profile.

## Initial observations

On the sources following `0d356c11`, these numbers count cases with at least one
eight-byte repeated-input match, out of 28 per column. They are diagnostic
observations, not stable expected test results or security scores.

| Compiler / execution / profile | SHA-256 | SHA-512 | SHA3-256 | SHA-1 | MD5 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1.90.0 / native Linux x86-64 / debug | 0 | 0 | 0 | 0 | 14 |
| 1.90.0 / native Linux x86-64 / release | 6 | 0 | 10 | 6 | 0 |
| 1.98.1 / native Linux x86-64 / debug | 0 | 0 | 0 | 0 | 14 |
| 1.98.1 / native Linux x86-64 / release | 6 | 0 | 0 | 6 | 0 |
| 1.90.0 / QEMU Linux Arm / debug | 0 | 0 | 12 | 0 | 0 |
| 1.90.0 / QEMU Linux Arm / release | 0 | 0 | 0 | 8 | 0 |
| 1.98.1 / QEMU Linux Arm / debug | 0 | 0 | 12 | 0 | 0 |
| 1.98.1 / QEMU Linux Arm / release | 0 | 0 | 10 | 6 | 0 |

All functional/owned-destination checks pass in these configurations. The
positive residue observations prevent interpreting that result as complete
normal-return cleanup. The zeros, including SHA-512, leave their audit work open.

## Recheck after the private kernel and secret-copy ports

The same unmodified diagnostic was rerun at
`f76c57af564fcbcba89fa3e63bd8de30d4cb0432`. All eight compiler/target/profile
configurations pass their five functional/observer tests. They still do **not**
qualify whole-API erasure. Observed repeated-input matches out of 28 cases:

| Compiler / execution / profile | SHA-256 | SHA-512 | SHA3-256 | SHA-1 | MD5 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1.90.0 / native Linux x86-64 / debug | 0 | 0 | 0 | 0 | 14 |
| 1.90.0 / native Linux x86-64 / release | 24 | 0 | 10 | 0 | 0 |
| 1.90.0 / QEMU Linux Arm / debug | 0 | 8 | 12 | 0 | 0 |
| 1.90.0 / QEMU Linux Arm / release | 14 | 16 | 22 | 0 | 14 |
| 1.98.1 / native Linux x86-64 / debug | 0 | 0 | 0 | 0 | 14 |
| 1.98.1 / native Linux x86-64 / release | 24 | 0 | 10 | 0 | 14 |
| 1.98.1 / QEMU Linux Arm / debug | 0 | 8 | 12 | 0 | 0 |
| 1.98.1 / QEMU Linux Arm / release | 14 | 16 | 22 | 0 | 14 |

These are compiler-sensitive diagnostics, not a score or a quantitative
comparison of security. Changes in register allocation and wrapper code can
change the marker count without changing the private kernel's cleanup contract.
No match can establish absence of transformed secrets or stack copies.

The current Rust 1.98.1 x86-64 release SHA3 wrapper still performs a 1,040-byte
`memcpy` from `rsp + 1080` to `rsp + 32` after `update` succeeds, then passes
the latter address to consuming `finalize_secret`. Its successful return path
does not wipe the former region before reclaiming the stack frame. This is an
inspection of emitted code, not a read of dead stack memory. The separately
qualified permutation and destination-copy boundaries do not cover this move.

Local source-bound observations are retained under
`target/caller-residue-ql5q_sap/observations.json` with SHA-256
`0ee7f16b727500fb07d8fd5770266fab933e2d96bbf1261e739961e66ef7260b`.
The inspected `brynja_caller_residue_audit` 1.98.1 x86-64 release assembly has
SHA-256 `09909ab5878e36cd69038dca0aebb84dcb94a0cc6ede1b6a4c79b8edb0071483`.
These ignored development artifacts are not a release receipt or native approval.

### Historical ownership-design decision before expanding the public API

Keeping secret state inline in a freely movable Rust value prevents promising
that all previous locations are erased: a semantic move may copy bytes without
notifying that value. A private finalizer cannot recover an arbitrary prior
caller address. This matches Rust's documented
[move and pinning model](https://doc.rust-lang.org/std/pin/index.html#what-is-moving).

The proposed next design is an additive, caller-owned in-place hardened API:
initialize secret state only in its final storage, retain exclusive access for
its active lifetime, finalize there, and clear before releasing storage. The
existing by-value API would remain available with its existing owned-memory
guarantee, not silently acquire a stronger guarantee. This needs owner approval
because it expands the public API beyond private backend remediation.

An in-place lifetime alone is not register or spill erasure. Absorb/padding/
squeeze and higher-construction transfers still need qualified opaque paths,
error/unwind and ownership tests, emitted-code review and platform coverage.
Pinning alone does not suppress compiler temporaries; no such claim is made.
Do not close F1 or collect final native qualification on this diagnostic result.

The owner subsequently approved the additive scoped APIs. They are implemented;
the following recheck observes five of them. The historical proposal above is
not a new approval request or a claim that those five APIs remain unimplemented.

## Scoped versus movable recheck, 2026-09-20

Production sources are those at `daa8e33b`; this checkpoint changes the
development fixture/collector, not production Rust. Each profile runs 28 cases
per algorithm on both compiler endpoints, both Linux architectures and both
debug/release profiles (1,120 observations per API profile).

All five scoped algorithms have **zero repeated-input marker matches** in all
eight configurations. All functional checks, owned-output clearing and observer
controls pass. This narrow result does not prove removal of transformed secrets,
partial bytes, stack spills, upper vector lanes or interruption snapshots.

The movable recheck has zero matches for SHA-256, SHA-512, SHA3-256 and SHA-1.
MD5 still has 14/28 matches in x86 debug under both compilers, x86 release under
1.98.1, and Arm release under both compilers; its other configurations have zero.
These observations are not comparative security scores. The old movable API
retains its owned-memory guarantee, not a whole-register claim.

Inspection of the 1.98.1 x86 release scoped SHA3 wrapper finds its 1,032-byte
`memcpy` during secret-free initialization, **before** `update`. Unlike the
earlier movable wrapper, no bulk populated-owner copy occurs between `update`
and `finalize_secret` in this wrapper. This specific observation is not a proof
covering callees, all error paths, other compilers or other algorithms.

Ignored, source-bound records:

- `target/caller-residue-heo5fer6/observations.json` (scoped), SHA-256
  `01b618abca82e5da85d870876a19b7a3551fa8b09aeed74fab9d41aa0cdb5141`.
- `target/caller-residue-83c83esq/observations.json` (movable), SHA-256
  `7e7e7164e77bd94476372346aa5b0cd4f3dfd3d2ea96e21e979f4d31e5ddf454`.
- Scoped 1.98.1 x86 release fixture assembly, SHA-256
  `4bfedc0cc1f909f64fd880f415d52658c4ceef6f43217b7f99a4c97cd50e673f`.

The scoped fixture also passes strict Clippy and ASan/LSan with leak detection
and fatal error exits forced. These are development checks, not release receipts
or native approvals. No release-gate commands or behavior changed.

## Higher-construction recheck, 2026-09-20

All twelve higher-profile identities report zero repeated-input matches over
2,688 observations: 28 cases per identity, two compiler endpoints, debug/release,
native Linux x86 and QEMU Linux Arm. This is the same limited marker diagnostic,
not whole-API erasure qualification. Production sources are still `daa8e33b`;
only development fixtures, their first-party dependency graph and docs changed.

Known-answer controls call the same probe workers with an expected synthetic
output, inspect it before Drop, and require rejection of a corrupted expected
value. The observations pass no expected value and never expose/log the digest.
Twelve committed outputs are independently regenerated by the existing Python
SP 800-185 oracles. Ten compiled debug/release mutants reject omitted message
absorption, omitted tuple content, forgotten output cleanup, disabled comparison,
and incorrect output width. Positive controls execute all five fixture tests.
Strict fixture Clippy and ASan/forced LSan also pass. Existing movable/scoped
profiles still pass their Rust 1.90 controls.

The final source-bound record is
`target/caller-residue-skkao3s7/observations.json`, SHA-256
`ba5bd682d781f4e9922bb1681436ca66c83f85517b4468ca5e376aadabb84fba`.
It binds the three additional first-party crates, golden vectors, oracle scripts,
collector and mutation driver. MIR/LLVM/assembly is retained for all eight
configurations. The three added dependencies belong only to this unpublished
development fixture; no production manifest or external dependency changed.

These observations do not cover transformed values, arbitrary compiler spills,
all error paths, live migration, native Apple/Windows/Arm behavior or callers'
pre-existing register contents. They do not close F1 or alter release gates.

## Static accelerated higher-call observations

The twelve scoped KMAC/TupleHash/ParallelHash identities pass on both compiler
endpoints in debug/release on native Linux x86 AVX2 and QEMU Linux Arm Keccak.
All 2,688 observations have zero repeated-input matches. This does not prove
absence of transformed secrets, spills, upper-vector residue or worker-thread
residue. No native Arm, Apple or Windows execution is claimed by this campaign.

Six tests run in each configuration: independent vectors (and corrupt-vector
rejection), input/output bounds and clearing, two observer controls, observations,
and exact-route/health plus revoked-authority rejection. Sixteen compiled
debug/release mutations reject missing absorption, item content, output Drop,
comparison, width, revocation, kernel identity and health checks. Strict Clippy,
ASan/forced LSan and the existing movable/scoped/portable higher controls pass.
Production crate sources remain unchanged from `daa8e33b`.

The final source-bound record is
`target/caller-residue-q7339336/observations.json`, SHA-256
`50bdbaa301c7bc4e66d7dd821906f06699a921d5ab739e23741f399314939a13`.
It retains compiler identities, flags, Linux CPU enumeration, observations and
MIR/LLVM/assembly for all eight configurations. Current source and retained
artifact hashes were rechecked. CPU enumeration is not live-migration assurance.

The inspected Rust 1.90 x86 release KMAC256 wrapper's large `memcpy` calls move
the session/workspace before accepting the key or message; after update its
handle transfer is separate from the borrowed sponge. This is a specific emitted
wrapper observation, not a complete call-tree or spill/metadata qualification.
The report remains diagnostic and is not a release receipt or F1 closure.

## Threaded coordinator observations

The twelve threaded probes pass on Rust 1.90/1.98, debug/release, native Linux
x86 AVX2 and QEMU Linux Arm. All 1,728 observations have zero repeated-input
register markers. This observes the coordinating thread after every worker has
joined; it is **not worker-register or thread-stack erasure qualification**.

Six tests pass per configuration. Independent Python vectors cover all four
identities through all three routes. Sixteen compiled debug/release mutants
reject missing output Drop, disabled vector comparison, altered leaf/route/width
accounting, changed block framing, missing cancellation and portable substitution.
Fourteen collector tests, strict fixture Clippy and ASan with forced LeakSanitizer
pass. The existing threaded library's 53 tests also pass with required native
multibuffer coverage, including launch failure, cancellation, panic, ordering,
join and output-slot cleanup cases. Prior movable/scoped/higher/accelerated
fixture controls still pass under Rust 1.90.

Source inspection traces worker output into disjoint parent-owned slots that
are allocated empty and not resized while populated. Workers return typed
result borrows, not digest arrays or live authority leases. Rust 1.98.1 x86
release MIR likewise retains `leaf128`/`leaf256` results as `(LeafResult, bool)`;
that observation alone cannot rule out compiler-created temporaries elsewhere.
The parent slot guard survives worker errors and coordinator unwinding. Existing
fault tests exercise that lifecycle; this diagnostic adds no production changes.

The source-bound record is `target/caller-residue-tcj2wmrb/observations.json`,
SHA-256 `35b448f6a2995a25a2d42ca97646081efbcc709d14b2b0652f0f1bac4706d501`.
All recorded source hashes and 312 MIR/LLVM/assembly hashes were checked. These
are retained development artifacts, not automatic emitted-code qualification,
native Apple/Windows/Arm evidence or a release receipt. Full worker/caller spill
inspection, additional failure/verification paths and final native qualification
remain separate obligations. F1 stays open.

### Single-kernel worker handoff MIR check

`check_worker_handoffs.py` reuses the retained threaded record without rebuilding.
It checks current source hashes and retained artifact hashes, requires the exact
eight compiler/target/profile identities, and selects the two actual hosted
single-leaf helpers, `leaf128` and `leaf256`. Starting at their direct borrowed
workspace `execute` call, it follows both return and cleanup CFG edges. The
active workspace and its borrowed alias cannot be copied, moved, escaped or
reused; normal returns and recoverable unwinds must invoke that workspace's
Drop. The compiler's bare `unreachable` terminator for invalid enum states is
not a normal-return path and is not counted as cleanup. Construction-time copies
precede secret processing and are outside this narrow post-call check.

```sh
python3 assurance/register-cleanup/check_worker_handoffs.py target/caller-residue-tcj2wmrb/observations.json
python3 assurance/register-cleanup/test_worker_handoffs.py target/caller-residue-tcj2wmrb/observations.json
```

All sixteen helpers pass. The self-test rejects 256 mutations of their actual
MIR, including each individual success/error/unwind Drop removal, owner copies,
moves, escaped aliases, premature storage death, bypassed exits, cycles, missing
unwind edges and wrong signatures. Six record regressions reject stale sources,
wrong profiles/claims, missing/duplicate matrix rows and changed artifacts.
These are **MIR mutations**, not newly compiled crypto mutants.

This establishes the selected MIR handoff shape, not the destructor's machine
code, callee internals, metadata erasure, compiler spills or register cleanup.
It does not cover multibuffer worker closures or post-return operating-system
thread teardown. No release command calls this development checker; the existing
release gate and its evidence-reuse policy remain unchanged.

### Multibuffer worker handoff MIR check

The same retained record also supports `--batch`, selecting the actual
`wave128`/`wave256` worker closures rather than their coordinator. All sixteen
compiler/target/profile instances borrow their workspace into `execute_into`;
the checker traces that borrow across the out-of-line debug `Control::new`
call as well as the inlined release setup. It rejects owner/alias copies,
redefinitions and escapes before execution, then requires workspace Drop on
normal/error returns and recoverable unwinds after execution. Result-loan Drop
is distinct from workspace Drop and cannot substitute for it.

```sh
python3 assurance/register-cleanup/check_worker_handoffs.py --batch target/caller-residue-tcj2wmrb/observations.json
python3 assurance/register-cleanup/test_worker_handoffs.py --batch target/caller-residue-tcj2wmrb/observations.json
```

All sixteen closures pass; 368 mutations of their actual MIR and six record
regressions are rejected. The shared traversal still rejects all 256 existing
single-leaf mutants. Double-panic termination is explicitly outside recoverable
cleanup; a mutant changing that termination to an escaping recoverable unwind
must fail. This distinction does not add an abort-time erasure guarantee.

The parent `GroupSlots` destructor also passes an exact receiver-forwarding
check in all eight artifacts: it calls `GroupSlots::clear` on its own receiver.
Twenty-four additional MIR mutants reject changed callees, receivers and bypass
paths. This is only a forwarding check: its MIR retains `unwind continue`, so
it does **not** establish that the clear routine is compiler-proven non-unwinding
or qualify its machine code. The stricter production cleanup verifier is not
changed or bypassed. Sixteen existing scoped multibuffer runtime tests pass with
native static execution required, including parent clearing after forgotten
result loans, worker/coordinator panic, cancellation, ordering and launch failure.

These checks reuse the record/hash above; production inputs are unchanged.
They do not snapshot worker registers, inspect OS-reclaimed stacks or prove
whole-callee cleanup. F1 remains open for those separate qualification limits
and the final retest. No release-gate command or acceptance criterion changes.

### Retained production assembly boundary recheck

The threaded record contains actual dependency-crate assembly, emitted with
the consumer's unified features. It can therefore recheck selected private
normal-return boundaries without compiling them again. The new development
driver first validates the record's current source closure, full matrix and
artifact hashes through the worker-handoff checker, then uses the **existing**
assembly validators rather than inventing weaker copies.

```sh
python3 assurance/register-cleanup/check_recorded_boundaries.py target/caller-residue-tcj2wmrb/observations.json
python3 assurance/register-cleanup/test_recorded_boundaries.py target/caller-residue-tcj2wmrb/observations.json
```

All 88 inspections pass: core secret copy, mask, XOR, predicate and difference;
the hash-core predicate; and scalar SHA-256, SHA-512, Keccak, SHA-1 and MD5,
each across both compilers, architectures and debug/release profiles. The
validators check their defined opaque assembly boundary, working-register
cleanup and compiler instructions outside that boundary. They do not qualify
arbitrary calling functions or expand the supported architecture contract.

The tests reject 440 assembly-text mutants: missing erasure markers, removed
wipe instructions, loads during cleanup, loads after cleanup and stack spills.
Missing/duplicate inventory checks also fail, and the test forbids subprocess
execution to ensure inspection does not quietly rerun compilers or runtime tests.
These are artifact-text regressions, not newly compiled algorithm mutants.

The log `target/development-v02449/recorded-boundaries.log` has SHA-256
`de60064a66f67a79f26662a64d1a2cd1d7d255efb4da8ba8186ade970a2c89bf`.
It records the observation-record digest and the exact loaded inspector source
hashes separately from the retained Rust inputs. No new native execution,
Windows/Apple qualification or release receipt is inferred. High-level caller
copies, error/verification paths and final platform qualification remain
separate; F1 and the unchanged release workflow retain their current status.

### Retained accelerated Keccak boundaries

The same source-bound record also supplies the actual single-state and
multibuffer CPU kernels, rather than only their standalone fixtures:

```sh
python3 assurance/register-cleanup/check_recorded_keccak.py target/caller-residue-tcj2wmrb/observations.json
python3 assurance/register-cleanup/test_recorded_keccak.py target/caller-residue-tcj2wmrb/observations.json
```

All sixteen inspections pass (two kernels across the eight configurations).
Release LLVM embeds the public round-table address in the prologue. A narrow
adapter verifies its unique read-only 192-byte definition against the existing
independent oracle before allowing that address formation. It never allows a
load in its place; Arm literal-address loads are explicitly rejected as well
as the ordinary memory accesses checked by the existing boundary validators.
The original validators are unchanged and their temporary configuration is
restored after every inspection.

The tests reject 128 missing-boundary/wipe, load and spill assembly mutations,
plus 56 writable/altered/ambiguous table and address-formation mutations.
Subprocess execution is forbidden during those tests. These are assembly-text
negative controls, not newly compiled mutants or runtime checks. The log
`target/development-v02449/recorded-keccak.log` has SHA-256
`cf3b9bda6d562365e34f04efaca61b582a4466c8812ff1a456247f3d32fbcb46`.
It binds the retained record and loaded inspectors. This corroborates these
private normal-return boundaries, not caller verification/error paths, worker
spills, native platform execution or whole-call cleanup. F1 remains open.

## Remaining source boundaries

These are inspected source boundaries, not all dynamically tested by this
fixture. Paths below are relative to the repository root. Earlier observations
above remain historical; success-return probes do not close the obligations.

| Boundary | Representative sources | Remaining obligation |
| --- | --- | --- |
| Portable SHA-2 | `crates/brynja-hash-sha2/src/hardened/compress32.rs`, `compress64.rs` | Both hardened SHA-224/256 and the SHA-512 family now have baseline x86-64/Arm scalar-boundary development checks. Other-target models still expose scalar round temporaries; higher-level owner copies remain separate. |
| Portable Keccak | `crates/brynja-hash-sha3/src/hardened/permutation.rs` | Baseline x86-64/Arm scalar permutation now has source-bound development checks. Other-target models, caller absorb/squeeze and moved-owner copies remain open. |
| Portable legacy | `crates/brynja-legacy-sha1/src/compress.rs`, `crates/brynja-legacy-md5/src/compress.rs` | SHA-1 and MD5 now have baseline x86-64/Arm scalar-boundary development checks; their other-target models remain open. Tail framing/ownership is separate from compression. |
| Single accelerated Keccak | `crates/brynja-crypto-cpu/src/hardened_execution/keccak.rs`, `crates/brynja-hash-sha3/src/hardened/accelerated/engine.rs` | Session import/commit now stays inside the opaque kernel. Higher-level absorption, padding and squeeze remain to be addressed. |
| Batch staging | SHA-2 `src/hardened_batch/engine.rs`, `src/hardened_batch512/engine.rs`; SHA-3 `src/hardened_batch/engine.rs`; MD5 `src/batch/hardened_execution/vector.rs` | Packing, feed-forward/output transfer, portable tails and partial lanes require their own review. |
| Ownership and finalization | Primitive hardened owners, consuming finalizers, core secret-region output initialization | Moving a by-value Rust owner may create compiler copies; clearing its final owned region is not proof that earlier copies or registers clear. |
| Higher constructions | KMAC, TupleHash, ParallelHash framing/readers and threaded output transfer | Portable and static scoped success-return probes cover twelve identities; threaded coordinator probes cover four identities over three routes. Worker-register/spill qualification, verification/error paths and complete emitted-code qualification remain separate. |

The remediation must keep secret loads/transformations within qualified
boundaries and address caller staging explicitly. A late `vzeroall`, an ordinary
slice fill, or a wrapper around only compression cannot establish that property:
the compiler can spill or copy values before it, or load them again afterward.
Preserved caller registers and caller-owned buffers must remain valid. Any
portable replacement must retain targets without crypto/SIMD instructions,
existing feature defaults, quarantine/error behavior and public APIs. Kernel
normal-return cleanup still cannot erase asynchronous snapshots or platform
storage. Do not start final native qualification or close F1 on these diagnostics.

Emitted release code also makes the ownership-copy issue concrete: the 1.98.1
x86 SHA3 wrapper copies its 1,040-byte state to a separate stack region for the
consuming finalizer. Clearing that finalizer's owner is not erasure of the old
location. This was observed in emitted code, not by reading dead stack storage;
the runtime observer does not measure stack residue. Moving secret-bearing Rust
values and preserving existing by-value APIs therefore need separate treatment
from the private compression/permutation kernel ports.
