# Windows secret-execution isolation: package 08 follow-up

Status: **08A plaintext-transport feasibility blocked; design decision required** (2026-10-12). The owner chose
to keep package 08 blocked and design stronger isolation, rather than accept a
conditional cleanup claim. No release gate, production API or algorithm changes
are made by this document or its executable design criterion. The separate canary
below does not replace any of the nineteen existing family images.

## 08A canary checkpoint

The separate `isolated_sha256` C/Rust fixture now stages a bounded, single-copy
request before entering the guarded compute window. Its hardened in-place
SHA-256 worker neither calls transport nor accepts a host pointer. It retires
the entire input staging array, returns through the clear/readback/register
wrapper, and only then publishes an explicitly public test digest. It retains
strict containing-process access and refuses reentry. This is a **public-vector
development experiment**, not a newly available secret API.

On the local Windows x64 guest, 29 native cases pass: twenty independent hashlib
digest comparisons plus malformed descriptor/length/control, input/output-copy
failure, loaded-code expectation drift, denied admission, reentry and reuse.
A separately compiled omitted-window-clear mutant terminates with `0xc0000409`
and no success output. This is fatal rejection, **not successful cleanup**.
The canary's dirty-readback branch cannot continue into SDK guard restoration.

The actual signed PE and COFF objects bind seven Rust functions plus the thin C
entry. With two byte-rebound in-image memory runtime summaries, its compute
graph has ten nodes, 56 direct call/tail sites and no indirect calls or SDK
entry. Normal compute depth is 2,544 bytes below the C/Rust entry, for both
Win64 residues. This is not a bound on transport, OS or diagnostic paths.
The [canary observation](../assurance/windows-protection-observations/isolated-canary-20261012.json)
records twelve focused tests passing on Linux and Windows; Windows replays the same
LLVM 23.1.2 disassembly, not an independent second decoding.

Identity checks run inside this canary, compare the pinned loaded SDK text,
and inspect its actual copy IAT slots. The first canary rejected correctly:
the kit's copy declarations yield local linker-thunk addresses, so ordinary
function-address comparison was insufficient. The corrected implementation
checks the import slots instead. This is local identity checking, not remote
attestation or production-signing qualification.

The original canary's static staging was not residency-qualified. The separate
resident-staging experiment below addresses that implementation gap without
replacing or rewriting the original evidence. **08A remains open:** bind the
complete loaded transport/helper payload path and finish outer-wrapper/phase,
incoming-register and storage-lifetime composition before family migration. Raw artifacts,
failed first attempt and successful/mutant images are retained outside `target/`
under `release-reports/windows-isolation-08a-20261012/`.

### Resident-staging checkpoint

`isolated_resident.c` allocates a fresh three-page enclave mapping before accepting
payload: two no-access guard pages surround one 4,096-byte staging page. The
trusted host locks that page before input copy, observes its working-set Locked
bit again after staging, and retains the lock through computation and retirement.
No host callback dereferences enclave payload. The input occupies at most 1,024
bytes; the explicitly public test digest occupies the next 32. Request metadata
remains separate. The compute body receives only these in-enclave ranges.

After the compute window has retired, a separate assembly leaf clears and reads
back **all 4,096 bytes**, including unused capacity. Only zero readback permits
unlock notification and mapping release. The leaf has no explicit stack access,
vector operation or SDK call, and clears every GPR it modifies before normal
return. Dirty readback terminates before any unlock/free notification; fatal
termination is still not successful cleanup. Failed host acknowledgement or
mapping release is also fatal rather than silently reusable.

The [resident observation](../assurance/windows-protection-observations/resident-canary-20261012.json)
records **33 native cases**, including twenty hashlib comparisons, denial before
locking, rejection after locking, rejection after staging, reentry at three
phase boundaries, and an input spanning a readable prefix and inaccessible host
page. No atomic-copy assumption is made on failure. An omitted-staging-clear
image fast-fails with `0xc0000409`. Temporary development signing keys were removed.

Twelve focused tests pass on each host with identical parsed review reports.
The checker binds the actual C-to-Rust connection, the 70-byte retirement leaf,
and actual storage imports. It checks control-flow dominance of staging admission,
post-copy observation, compute, retirement and release in the pinned C root.
Every retirement byte, root instruction bytes outside relocation operands, one
actual retirement-target change, and all 198 native result fields have rejection
tests. The ten-node compute graph remains SDK-free, with 56 direct sites, no
indirect sites, and the same 2,544-byte normal bound. Windows replays the same
byte-bound LLVM decoding; it is not a second independent decoder.

This completes the **resident-staging experiment**, not a supported secret API or
whole-platform guarantee. Residency observations require the trusted host; they
are not attestation against a dishonest callback. SDK effects, incoming register
context and final composition with the outer wrapper remain unqualified.

### Loaded transport status-data checkpoint

A separate transport-data variant now extends loaded `.text` and actual-IAT
identity with the diagnostic formats and both status-conversion tables: 11,440
bytes across three read-only ranges. It checks every covering page is committed
and exactly read-only, checks range bounds, and compares every byte before
descriptor/payload admission. The pinned SDK ranges contain no loader fixups.
The original resident image and all nineteen family images are unchanged.

The [transport observation](../assurance/windows-protection-observations/transport-data-canary-20261012.json)
binds the new signed development image, actual COFF call edges, embedded expected
data and complete loaded-identity instruction bodies. The root instructions are
identical to the preceding resident canary; only its two identity-call references
change. Its compute graph is freshly rebound and recomposed: ten SDK-free nodes,
56 direct sites, no indirect sites and the same 2,544-byte normal compute bound.

On Windows, 21 identity observations accept the genuine expectation, reject text
drift and each data-range drift, reject an unknown control, and permit reuse.
Negative controls change expectations, never the live signed SDK. The same image
passes the 33 native resident cases, including twenty hashlib comparisons.
Thirteen new tests pass on each host, alongside all twelve predecessor tests;
parsed reports match. Regressions reject 11,440 changed data bytes, 726 identity
instruction bytes, 661 root instruction bytes, 80 descriptor/expected-data boundary
changes and a retargeted actual identity call. Development signing keys are removed.

The status-table model checks all 344 disjoint ranges and their 4,256 output words,
all range members/boundaries and 8,192 seeded random inputs. Binary and linear
lookup agree; this is **not exhaustive native SDK status-function execution**.
The fixed diagnostic strings contain only one numeric status conversion and no
payload-pointer format. This narrows data provenance, not the entire formatter,
exception or captured-register context. Whole-image qualification remains false.

### Normal window and control-storage composition

The [boundary observation](../assurance/windows-protection-observations/isolated-boundary-20261012.json)
now composes the actual transport-data image's C entry, six boundary helpers and
modified 399-byte wrapper. `PublicRustBody` enters at `H-40`, residue 24 modulo 32;
its complete 2,544-byte normal chain therefore reaches `H-2584`. This fits inside
the 65,536-byte clear/readback window for all 256 aligned RBP page residues.
The entry return slot and full caller home space are included. This is a bound
for the SDK-free **normal compute chain**, not for the whole thread or bootstrap
SDK calls. The 81,952-byte probe is not used as an invented SDK stack-depth bound.

The actual dirty-readback branch reaches terminal `int29` before either finish
notification or SDK guard restoration. Normal return requires both complete
8,192-word loops, volatile GPR/XMM clearing and the final clearing after restore.
Denied admission still reclaims without calling compute. XMM6–XMM15 low halves
are preserved for the Win64 ABI; YMM upper clearing uses the cached CPU/OS AVX
check. This does not qualify AVX-512/extended state, arbitrary exceptions, or the
provenance of preserved incoming registers.

All 24 named controls and the full descriptor occupy distinct, writable,
non-executable image ranges. Real call edges and shared addresses connect these
objects across the root, wrapper and boundary helpers. Fresh staging allocation
disjointness still relies on the trusted allocation API; staging lock/retirement
uses the earlier pinned root and trusted-host phase checks, not a new native run.

Nine new tests pass on Linux and Windows, without skips, and parsed reports match.
They reject 399 normalized wrapper-byte mutations, 351 linked wrapper-instruction
mutations, 1,045 helper-instruction mutations, four cleanup bypasses and 72 missing,
out-of-range or overlapping storage mutations. Existing images and earlier native
receipts remain unchanged. **This completes the normal wrapper/control geometry
check, not incoming-register or SDK payload qualification.**

### Outstanding transport prerequisite

Inspection of the pinned SDK confirms that its copy exports call the OS copy
stub without explicit software payload loads, then tail-transfer to status
conversion. That observation alone does not close the transport premise.
The status lookup at RVA `0xb604` can call the diagnostic entry at `0x168a4`,
which homes argument registers and enters deeper formatting/context paths.
Those paths use SDK data as well as code. The separate transport variant now
binds the status tables and fixed formats, but does not pin every deeper formatter,
exception or mutable thread-context input. Nor does an API success/failure result
establish the contents of all registers after an OS transition. These are
remaining proof obligations, not an observed disclosure.
Do not infer SDK erasure or a complete payload-path proof from the passing
resident canary. The next review must resolve these obligations under the stated
OS trust boundary, or report a concrete design blocker before migrating families.

The Microsoft contracts checked on 2026-10-12 describe copy success/failure and
continued availability under strict containing-process access, but do not specify
payload erasure from return registers. The x64 ABI allows volatile registers to
change across a call. Those facts do not establish that an OS transition actually
returns payload residue; they also cannot prove it never does. A successful native
copy, code hash or caller-side wipe after the SDK returns cannot substitute for
that missing internal-path evidence. No undocumented syscall or SDK patch is
introduced to work around this question.
[Copy-in contract](https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclavecopyintoenclave),
[copy-out contract](https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclavecopyoutofenclave),
[x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170).

### Finite success-path result and decision point

The [success-continuation observation](../assurance/windows-protection-observations/copy-success-gap-20261012.json)
closes the narrow question of whether this saved SDK clears vector registers on
successful copy return: **it does not**. The exact-encoding model starts immediately
after the opaque OS copy transition, assumes returned status zero, and follows
actual call/return and branch targets until the export returns. Both copy
directions and both thread-pointer alternatives are covered: 28 or 30 scalar
instructions, balanced returns, zero vector writes. The thread/home stores on
these paths contain only the zero status. The complete selected instruction
bodies are rebound to the pinned SDK file, not inferred from function names.

Eight focused tests and fourteen predecessor tests pass on each host with equal
parsed reports. Regressions reject missing instructions, vector/unmodeled
operations, changed call/branch targets, unbalanced returns, an infinite loop,
nonzero status assumptions, SDK drift and mismatched decoding. This is saved-code
inspection and a restricted model, not execution of the syscall or a general
x86 emulator. Windows replays the same decoding, not a second decoder.

An arbitrary hypothetical vector value at syscall return survives this normal
SDK continuation. **That is not evidence that Windows actually returns secret
residue.** It establishes why the API result and ABI alone cannot prove the
stronger erasure claim. Nor does it prove error-path residue: error/exception
contexts remain separately unqualified. Clearing in Brynja after SDK return
cannot retrospectively establish what the SDK saved before returning.

This is now a concrete **08A feasibility blocker**, not a request to keep pinning
more unrelated helper bodies. Do not begin 08B/08C migration until one of these
premises is justified:

1. **Retain plaintext transport with additional platform evidence.** Obtain a
   suitable contract or reviewed implementation evidence for payload provenance
   across OS return and all reachable SDK diagnostic/context storage. More
   successful copy samples, another SDK hash, or a larger window are insufficient.
   The contracts reviewed above do not currently supply that evidence. This is
   an external assurance dependency, not an identified Microsoft vulnerability.
2. **Separately design a transport that does not expose plaintext to the SDK.**
   Authenticated ciphertext-only transfer is a candidate, not an implemented or
   proven solution. It would require trusted endpoint/image binding, key and
   entropy bootstrap, authentication, replay/order protection, bounded framing,
   key retirement and complete failure-path ownership. The bootstrap must not
   import its secret through the same unresolved plaintext path. Existing kernel
   correctness tests would remain reusable, but this introduces a protocol/API
   and cryptographic implementation scope beyond the approved phase split.

The recommended next action is a **separately approved design-only feasibility
pass for option 2**, with an explicit stop if secure bootstrap or suitable
first-party primitives are unavailable. Do not implement ad-hoc encryption,
weaken strict memory access, patch the SDK, or introduce raw syscalls. This
document does not authorize that expansion. Conditional closure was already
declined by the owner and is not silently substituted. Package 08 remains blocked;
the completed compute/storage work is preserved without promotion to a supported
secret boundary. No claim of impossibility is made.

## What the completed reconciliation establishes

All nineteen original images now have their actual outer-wrapper/C/worker entry
connections checked. The sequential worker enters at `H-104`, with RSP residue
24 modulo 32; concurrent root/leaf entries are at `H-216`, residue 8. The deepest
known composed prefix reaches `H-25152`. Both wrapper layouts clear and read back
8,192 words across the full 65,536-byte window, including denied admission and
normal error returns, before returning through the reviewed register boundary.

The [reconciled observation](../assurance/windows-protection-observations/outer-window-20261012.json)
records **249 passing tests on Linux and Windows**, no skips, identical parsed
review reports and current checker/test hashes. These are saved-image inspections,
models and mutations, not fresh native enclave execution. The same byte-bound
LLVM 23.1.2 disassembly is replayed on both hosts, not independently decoded twice.

This is **not** a complete transitive stack bound. The already-bound SDK status
conversion can enter diagnostic, dynamic-context and metadata-selected exception
paths. In the saved `vertdll.dll`, the handler at RVA `0x1d570` calls a target
loaded from its dispatcher record; the status raiser at `0xbeb0` has a recursive
call at `0xbf15`. These observations do not prove those paths are exploitable,
normally reachable for every input, or that a leak occurred. They show why the
current evidence cannot supply an unconditional finite bound or erasure proof.

The main signed-image hash binds import requirements, not the exact loaded SDK
bytes. The installed SDK file still matches the reviewed saved file, but that
is not per-image loaded-IAT attestation. The actual import contract is Windows
author identity plus security-version floors, as documented in
[image admission](windows-enclave-image-admission.md#imported-library-contract).

## Chosen architecture to investigate and implement

Separate **transport and scheduling** from **secret computation** on each enclave
thread. An SDK operation must never suspend a live secret computation frame.
Returning to the outer wrapper and wiping later is not sufficient if that frame
was already exposed to an SDK diagnostic or exception walk.

The proposed sequence is:

```text
admit image/platform -> stage bounded request -> enter private compute window
 -> return typed result -> clear/read back window and scratch registers
 -> publish authorized output / schedule next step / retire resources
```

Retained secret state can remain in explicitly owned enclave pages between
commands. This is not a promise to erase intentionally retained keys after every
command. No SDK function may receive a pointer to that state for inspection;
transport sees only dedicated staging ranges. Host caller-owned input copies and
already-authorized public outputs retain their existing documented boundaries.

### Transport and resource phase

- Reserve, validate and protect window/staging/retained pages before computation.
  Keep containing-process access restricted. Do not replace enclave copy APIs
  with raw host-pointer loads, undocumented syscalls or temporary relaxed access.
  Microsoft documents that strict access rejects direct containing-process
  accesses while the copy APIs remain available.
  [Strict-memory contract](https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclaverestrictcontainingprocessaccess).
- Copy each bounded request into owned enclave staging, then freeze ownership
  before decoding. Do not reread a mutable host descriptor during computation.
  Use explicit slot capacity and checked ranges; transport lengths must follow
  the existing public-length contract, not newly expose private counters.
- The SDK copy boundary is a separate **feasibility prerequisite**, not solved
  merely by moving it. Plaintext can still be in the copy buffer. Bind the actual
  loaded copy-entry code and its reachable user-mode helper paths; establish that
  payload bytes are transferred through the trusted OS copy primitive, not loaded
  into SDK software scratch/formatters. If this cannot be established, this
  design cannot close 08 as written. Do not claim staged plaintext is public.
- Before the first secret command, perform identity checks inside the actual
  admitted image for the loaded transport/runtime code used by that image.
  A separate public diagnostic enclave is insufficient. Keep exact reviewed
  fingerprints separate from Windows author/version admission. Servicing drift
  must reject this stricter qualification until reviewed, never accept by name.
- Enter SDK code only with public control registers and no secret-bearing caller
  frames in that thread. Keep transport stack separate from compute storage.
  Canonicalize error/status outputs; never report raw readback accumulators.

Windows API documentation recommends enclave copy accessors for crossing the
boundary; it does not supply a compiler-scratch erasure guarantee. The proposed
byte/loaded-identity checks are additional Brynja obligations, not a Microsoft
guarantee inferred from API success.
[Development guide](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide).

### Compute phase

- Refactor workers to consume a validated enclave-owned request instead of
  calling `Public*Input`/`Public*Output` transports themselves. Produce either
  retained secret output or an explicitly authorized output staging record.
- The complete emitted compute call graph must contain no SDK import, host
  callback, allocator, OS query, lazy runtime initializer or unassigned indirect
  target. In-image memory/arithmetic/probe helpers are permitted only with
  their existing byte, bound and register contracts. A source regex is not proof.
  The canary rebinds the already-reviewed linked MSVC memcpy/memset bodies; it
  does not treat their names or mere presence in the image as a qualification.
- Ordinary invalid requests, cancellation and work limits use explicit errors
  through the cleanup wrapper. Existing fatal-abort exclusions do not authorize
  using exception dispatch as a routine compute error path.
- Clear/read back the entire compute window and required scratch registers before
  resuming transport. Preserve the Win64 ABI using public entry save values;
  do not erase the caller's nonvolatile state with an unconditional `vzeroall`.
- Recompute the finite stack bound from **new emitted bodies**, including home
  space, alignment, indirect dispatch and runtime helpers. Retain both entry
  residues until the new wrapper establishes the exact one. A source-level
  refactor or the old 25,152-byte prefix is not a bound for the new images.

The executable prototype
[`windows_enclave_isolation_design.py`](../scripts/cryptography/windows_enclave_isolation_design.py)
tests the SDK-free graph criterion only. It is not a new gate. All nineteen
current root populations fail that criterion; the already-pure concurrent leaf
passes it. A graph pass alone proves neither memory provenance nor stack bounds,
and the prototype reports neither as qualified.

### Family and concurrency preservation

The new phase split must preserve SHA-2/SHA-3/SHAKE/cSHAKE framing and bit handling,
KMAC key/suffix/verify semantics, TupleHash item completion, all batch lane shapes,
and ParallelHash root/leaf ordering. Streaming becomes bounded staged commands,
not an unbounded whole-message buffer. Preserve transactional outputs and the
documented failure/quarantine classifications; partial transport failure must not
silently complete an update or expose partially authorized output.

For concurrent ParallelHash, return from private root computation before host
scheduling. Keep CVs and root state in owned enclave slots, not public scheduler
frames. Bind each job/result to plan, generation, lane and command; join all workers
before slot retirement. Each worker uses its own compute/transport phases. Other
threads may run concurrently: the condition is no secret-bearing frame on the
SDK caller's thread, not a false claim that all enclave threads are idle. Reject
re-entry and stale results; SDK code is still trusted platform code, not a
malicious in-enclave adversary isolated by page permissions.

## Four bounded implementation packages

1. **08A — prove the shared boundary on one SHA-256 image.** Implement staged
   request/compute/result transitions, exact loaded transport identity, and
   preallocated storage. Show the compute graph is SDK-free, bounds fit, and
   normal rejection paths clear before any SDK call. Run native success plus
   copy failure, identity drift, re-entry and cleanup-failure controls. Stop for
   a concrete design decision if SDK payload handling cannot satisfy the premise.
2. **08B — migrate sequential families and SIMD adapters.** Apply the shared
   boundary across the eighteen sequential routes without changing primitives.
   Run differential, ownership, transactional-output and emitted-graph checks
   for every distinct route. Do not repeat unchanged kernel proofs gratuitously.
3. **08C — migrate concurrent ParallelHash.** Make scheduling a public phase with
   generation-bound retained state/CV slots. Test cancellation, reordered/stale
   results, partial launches, join failures and every worker's window retirement.
   Preserve real parallel execution, not a silent scalar/sequential fallback.
4. **08D — reconcile the replacement nineteen-image set.** Rebuild/sign the
   affected development images, bind their real compiler/linker/SDK identities,
   replay finite compute stack and cleanup checks, and run native fault controls.
   Close 08 only if all required properties are established. Then package 09
   prepares the independent-pentest candidate; do not mark the retest passed.

These are completion units, not guaranteed one-turn timings. No new AEAD,
ad-hoc cryptography, API downgrade or release-gate redesign is assumed. A need
for a different secret-transport protocol would be a separate design decision.

## Non-negotiable claim limits

This architecture does not promise to erase privileged OS/hypervisor snapshots,
arbitrary interruption contexts, application-created copies or fatal-abort state.
Those existing exclusions remain; no library refactor establishes that guarantee.
It instead aims to eliminate **synchronous SDK entry with a live Brynja secret
compute context**, and establish complete cleanup of the resulting bounded
Brynja-controlled compute/storage regions on normal completion and rejection.
The SDK plaintext-transfer prerequisite remains blocking until demonstrated.
Production signing, Windows ARM64, newer compiler output and independent review
are not qualified by the current x64 development-image evidence.
