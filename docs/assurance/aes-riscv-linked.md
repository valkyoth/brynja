# RV64 scalar AES: bounded final-linked review

Scope: v0.27.4 evidence-only candidate; no native admission or timing approval.
This supplements the [functional development record](aes-riscv-development.md).

## Reproduction and artifact boundary

```sh
python3 scripts/aes/test-aes-riscv-linked.py
python3 scripts/aes/check-aes-riscv-linked.py --toolchain 1.90.0
python3 scripts/aes/check-aes-riscv-linked.py --toolchain 1.99.1
# Execute and retain source-scoped observations:
brynja-verify run aes --needed --category aes-riscv-linked
```

The runner requires the existing RV64 GNU target, cross linker/sysroot,
`qemu-riscv64`, `llvm-nm` and `llvm-objdump`; it installs nothing. It rejects
ambient compiler/runner overrides. It builds byte-checked Cargo archives with
the exact direct/facade dependency graphs, opt-level 3, fat LTO, one codegen
unit, overflow checks and both abort/unwind profiles on each compiler endpoint.
Only the explicit evidence cfg and Zkne/Zknd bundle enable the candidate.
QEMU runs with Zknh disabled. No hosted RV64 admission is introduced.

Eight final-linked consumers exercise all widths, both owner forms, both block
directions, public output, clearing/drop, quarantine and rejected construction.
Execution must name the RISC-V authority and emit the exact three-width
population. Artifacts under `target/aes-riscv-linked/` retain each executable,
its SHA-256, compiler/QEMU identity, commands, flags, metadata, execution log,
symbols, disassembly and JSON analysis. Inspection-tool and binary hashes are
rechecked after analysis. These are local observations, not signed receipts.

## What the checker establishes

`aes_riscv_machine.py` reads six complete leaf bodies directly from uniquely
mapped read/execute ELF segments: three expansions and three transforms.
It checks ELF class, endianness, RISC-V machine, load extents, nonoverlap and
symbol extents. Only the intended six symbol names are admitted. Rust 1.90.0's
legacy symbols omit const generics; their width must match exactly one complete
access/operation contract. The resulting population must still contain every
width exactly once for each operation. Neither symbol order nor an old hash
is used to guess the width.

The checker decodes the needed RV64 integer, compressed and scalar-AES
instruction encodings. Unknown instructions, calls, privileged accesses, stack
loads/stores and general indirect jumps are rejected. Only the exact return
through the unchanged return-address register is allowed. All bytes in each
symbol are decoded, including code after the first return. Every branch target
must be an instruction boundary inside that body. The retained disassembler
text is for human inspection; it cannot override the byte decoder.

Instruction semantics follow the RISC-V specification's
[compressed instructions](https://docs.riscv.org/reference/isa/v20260120/unpriv/c-st-ext.html)
and [scalar cryptography](https://docs.riscv.org/reference/isa/v20260120/unpriv/scalar-crypto.html).
The checker is deliberately not a general ISA emulator. AES results remain
opaque secret values rather than duplicating AES arithmetic in the reviewer.
Functional correctness is covered separately by KAT, AVS and external-oracle
campaigns, not inferred from this model.

Each incoming key, schedule and block byte is abstracted as secret. Public
integers and object-relative pointers remain distinct. Arithmetic propagates
secrecy conservatively; public integer operations use RV64 wrapping semantics.
Pointer arithmetic preserves object identity and signed relative offsets.
Every branch operand must be a known public integer; every memory address
must be a public object-relative pointer within the exact typed array extent.
Uninitialized registers and reads of an unwritten expanded-schedule byte fail.
Writes to read-only key/schedule input fail. There is no guessed memory region
or sampled secret value in this analysis.

Expansion has one public path per width, and transform has encryption and
decryption paths per width: nine paths per executable. All loops are fully
traversed, with a 20,000-instruction fail-closed bound. Unknown control flow
does not receive a pass. This is a bounded checker implemented in Python,
not a formally verified proof system or an independent security review.

## Reviewed memory and control flow

Expansion copies the input key in four-byte steps using byte loads/stores.
The public offset then runs from `K` through `S - 4`. Each new word reads the
previous four-byte word and the word `K` bytes earlier, both already written.
The public position modulo `K` selects SubWord/RotWord/Rcon, with the extra
AES-256 SubWord at position 16. Rcon starts at a public constant and its
conditional reduction therefore does not depend on the key. The model checks
exact key-read and destination-write populations, schedule initialization and
the expected SubWord instruction count.

| Width | Key bytes K | Schedule bytes S | Expansion byte reads | Expansion byte writes | SubWord instructions |
| --- | ---: | ---: | ---: | ---: | ---: |
| AES-128 | 16 | 176 | 336 | 176 | 10 |
| AES-192 | 24 | 208 | 392 | 208 | 8 |
| AES-256 | 32 | 240 | 448 | 240 | 13 |

Transform selects direction using the public boolean. It reads all 16 state
bytes, reads each complete round key exactly once, and writes each state byte
exactly once. Encryption advances by 16 bytes from round key zero; decryption
decrements by 16 from the final round key. Both stop within the admitted
schedule. Intermediate decryption keys pass through AES64IM. The round count
and two-half instruction population are checked for each direction.

| Width | Total state/schedule byte reads | State byte writes | Middle-round half operations | Final-round half operations | Decrypt AES64IM operations |
| --- | ---: | ---: | ---: | ---: | ---: |
| AES-128 | 192 | 16 | 18 | 2 | 18 |
| AES-192 | 224 | 16 | 22 | 2 | 22 |
| AES-256 | 256 | 16 | 26 | 2 | 26 |

Input pointers are not modified. Expansion must clear `t0`–`t6` before return;
both transform returns must clear `t0`–`t5` and `a2`. Writes outside the declared
scratch-register set are rejected, and no modified register may retain an
abstract secret at return. This covers only those explicit leaf registers.

## Retained owned-buffer clearing bodies

`aes_riscv_cleanup.py` additionally checks three complete bodies in each linked
consumer: core's `zeroize_region_volatile`, the retained `destroy_block`, and
`lifecycle::aes128::destroy_key`. LTO merges the fixture's equivalent key and
cached-key destruction functions; the admitted symbol population is exactly
these two destruction bodies. Missing, additional, overlapping or unexpected
bodies fail. This is not a proof that every owner callsite reaches them.

The byte templates were reviewed against the GNU RV64 disassembly of both
compiler endpoints and both panic profiles. Rust 1.90.0 returns immediately
for zero length, then decrements the public length while writing one zero byte
and advancing the pointer. Rust 1.99.1 returns for zero length, computes the
public end pointer, then writes one zero byte and advances until that end.
Both have one byte store, no secret loads, no calls, no stack accesses and no
data-dependent decisions. Their memory safety depends on the original Rust
mutable slice being valid, exclusive and non-wrapping. They do not flush caches
or clear previous copies, registers or unrelated stack slots.

The abort profiles and MSRV unwind profile merge explicit clearing and Drop:
a null owner returns, otherwise its unchanged slice pointer and length are
tail-transferred to the checked core clear function. The current unwind profile
branches on the public explicit-clear boolean; both branches perform the same
null-owner check and tail transfer. No secret bytes are inspected or copied.

Every byte, including both branch instructions and return instructions, must
match the selected compiler/profile template. AUIPC/JALR pairs are constructed
from the actual source address and the independently checked clear-symbol
address; their opcodes/registers and all signed displacement bits are bound.
No relocation bits are ignored and no arbitrary indirect destination is allowed.
Each linked report includes three body hashes and a separate cleanup success
marker. This exact-build check deliberately fails when compiler output changes;
new output requires a new review, not automatic template regeneration.

Five regression tests cover both mangling styles and all compiler/panic
combinations, independently known positive/negative displacement encodings,
every single-bit mutation in every checked body, redirected transfers on either
current-unwind branch, wrong profiles and malformed symbol populations/extents.
This supplements the functional clearing/drop/canary tests under QEMU.

## Block-session authority boundaries

`aes_riscv_sessions.py` checks the complete linked `Session::encrypt128/192/256`
and `Session::decrypt128/192/256` bodies. These are exact compiler/profile
templates reviewed against the RV64 disassembly, including instructions after
the ordinary returns. There must be exactly one symbol per width/direction and
no overlap with another session, any of the six reviewed kernels, or the
retained unwind stub. Legacy and current mangling are recognized explicitly.
The checker revalidates the actual leaf bytes and their full bounded width
contracts before binding each session to its correct transform entry point.
No call displacement bits are ignored. Unknown compiler/profile output fails
and requires explicit review rather than automatic template regeneration.

The observed entry paths read public owner health, permit generation and the
kernel selection. Testing returns `NotReady`, quarantine returns `Quarantined`,
a generation mismatch returns `StaleGeneration`, and a non-RISC-V selection
returns `WrongArchitecture`, before the leaf is called. These checks do not
modify caller state or owner state. Under Rust's valid-enum precondition,
MSRV's unsigned comparison against kernel value 2 and the current compiler's
equality comparison admit the same RISC-V choice. This is a compile-specialized,
evidence-only static build, not a new platform availability probe.

On admission, state and schedule pointers are forwarded unchanged and the
direction argument is exactly zero for encryption or one for decryption.
The wrapper saves owner/generation and the return address, not key or block
bytes. After the kernel returns it rereads health, generation and kernel.
Success uses the compiler's observed `Result` representation (8 on MSRV,
255 on the current endpoint). This is not a public ABI promise. A failed
postcheck returns the corresponding error and permanently sets health to
Quarantined and generation to 3, unless already quarantined. The fixed terminal
generation matches `Authority::quarantine`; it is not a wrapping counter.

MSRV's unwind profile also retains a landing pad. It checks whether the owner
is already quarantined, otherwise sets that same terminal state, preserves the
exception pointer and calls the unwind-resume import. Current builds do not
retain this session landing pad. The checked leaf has no calls or unwind path;
the session review does not claim to prove exception-table dispatch or faults
in the unwinder. Raw `Session` buffers remain caller-owned even on a postcheck
error: this review is not the higher-level clearing/output-staging contract.

For the retained resume edge, the checker reads the real ELF bytes of the RV64
AUIPC/load/JALR stub and binds its GOT slot to a unique `_Unwind_Resume`
undefined global-function relocation in the live `PT_DYNAMIC` tables. Those
tables must map to file-backed loads with the expected permissions; tag,
relocation, name, alignment, bounds and duplicate checks are fail-closed.
Section names or disassembler labels cannot substitute for the live import.
The jump-slot relocation and default PLT form follow the
[RISC-V ELF psABI](https://riscv-non-isa.github.io/riscv-elf-psabi-doc/).
The OS loader, resolved runtime function and exception tables remain trusted.

Seven additional regression tests cover every bit of the compiler/direction
templates (including the landing pad and both call displacements), wrong-width
calls, actual corrupted leaf bytes, unexpected symbols/extents/profiles and
malformed import stubs, live tags, symbol identities and relocation populations.
These are checker regressions, not physical-fault resistance tests. Every fresh
linked executable must also pass its QEMU functional checks and emit a separate
six-session success marker before the registered configuration passes.

## Key-owner constructors and expansion callers

`aes_riscv_constructors.py` checks the retained package-external `new_key` and
`new_cached` entry points for AES-128/192/256. These wrappers retain the normal
production constructor's inlined code without changing production inlining.
The 15 complete compiler/profile/width templates in
`riscv-constructors-review.json` were reviewed against GNU RV64 disassembly;
the file records the four original executable hashes for traceability, not as
whole-binary acceptance hashes. Every later build must match the reviewed
body and validated call targets. There is no runtime policy-generation option.
Current compiler panic profiles share bodies; MSRV cached unwind constructors
have additional landing-pad code. The policy binds every instruction byte.
Call placeholders are replaced with exact AUIPC/JALR encodings, never masked.

All six constructors first clear the entire caller storage, then check owner
health and the compiled RISC-V selection. An unready, quarantined or wrong-target
owner returns an error representation and clears the destination again, without
publishing a usable key or changing that owner's state. A successful ordinary
key constructor copies exactly 16, 24 or 32 input bytes and returns the clearing
region plus its authority and captured generation. No expansion is performed
by this form until a later block operation; its input remains caller-owned.

Cached constructors allocate 176, 208 or 240 scratch bytes below the saved
register area. The complete frame sizes are 224, 256 and 288 bytes. They
initialize scratch, call the separately checked matching-width expansion leaf,
then recheck health, captured generation and kernel before copying the schedule
to caller storage. Success clears the full temporary schedule before returning
the owner. Failure after expansion publishes an error rather than an owner,
clears scratch, quarantines the authority unless already terminal, and clears
caller storage. MSRV's retained unwind paths also clear scratch and destination,
quarantine and resume the original exception. Exception-table dispatch and the
external unwinder remain trusted, not proved by these path templates.

For AES-192 and AES-256, the review compared the complete instruction streams
against AES-128. Differences are the exact public key/schedule lengths, stack
frame and saved-register offsets, and AES-256 ordinary-key branch offsets caused
by full-width immediate instructions. All those differences are bound in their
own templates. The expansion call is checked against the leaf's actual byte
analysis, not guessed from legacy symbol order. Every core clear target is
independently template-checked. Calls to `memcpy`, `memset` and unwind resume
must bind to the corresponding live ELF import, including repeated calls and
both retained resume exits. Imported libc semantics remain a trust boundary;
this is not emitted-code qualification of libc or all possible downstream libc
implementations. `memset` initializes scratch; secure destruction uses the
checked volatile byte-clear body, not an assumed erasing libc call.

Seven new constructor regressions cover the complete width/profile population,
both manglings, every instruction bit (including all call relocations), wrong
expansion/copy/fill/clear targets, both resume exits, corrupted helpers, missing
or overlapping symbols and invalid policy/call-target populations. The fixture
policies are trusted review material, not an adversarial-input security boundary.
They do not establish immunity to physical faults, spills, paging or secret
copies outside the explicitly owned buffers. A separate six-constructor marker
is required for each fresh executable's registered observation.

## Evidence-only authority startup

The separate `aes-riscv-startup` category builds the package-external
`startup-riscv.rs` consumer from the same archive-only dependency graph. Both
compiler endpoints, direct/facade routes and abort/unwind profiles use fat LTO,
one codegen unit and the evidence-only RV64 scalar-AES configuration. Run it with:

```sh
brynja-verify run aes --needed --category aes-riscv-startup
```

The retained `startup` boundary takes an opaque valid `Kernel` value. It rejects
both non-RISC-V variants, admits the evidence-only RISC-V variant, and checks
generation 2 and healthy/quarantined state. A healthy consumer also exercises
real caller-key expansion, encryption/decryption, clearing and explicit
quarantine for all widths. This keeps the round kernels shared with caller-key
operations rather than allowing LTO to specialize them to startup constants.
Ordinary builds remain unadmitted; this is not a new public admission path.

`riscv-startup-review.json` pins two manually inspected complete body templates:
980 bytes on Rust 1.90.0 and 946 bytes on Rust 1.99.1, each with a 400-byte stack
frame. Route and panic-profile variations have the same normalized body for
each compiler. Every instruction operand remains bound; normalization is
limited to independently checked external-call and read-only-reference
addresses. There is no capture/auto-learning acceptance option.

The review binds the backend rejection branch, initialization of sequential
public keys, three full-schedule comparisons (176/208/240 bytes), and all six
round calls with their exact direction, width, buffers and expected endpoints.
All result differences are combined before storing healthy versus quarantined
state. The MSRV copies five public decrypted bytes into result padding; these
stores are retained in its template, not interpreted as secret erasure or
discarded as irrelevant instructions. The six leaf bodies are independently
checked using the bounded reviewer before their targets are accepted.

The public schedules and four block answers reuse the independent FIPS
reference bytes already recorded in `startup-arm-reference.json`. They are
bound to the actual addresses used by AUIPC/ADDI or AUIPC/LD instructions,
including interleaved address materializations and both 64-bit halves of each
block. Their live mappings must be read-only, and referenced objects, code
bodies and imports must not overlap. The three fill and comparison calls bind
to named `memset` and `bcmp` imports through the actual ELF dynamic relocation
metadata, not disassembler labels. The loader and libc implementations remain
trusted. All startup data is public; `bcmp` is not claimed to be constant-time.

For every consumer, the runner separately flips one bit in each of the 688
referenced bytes: 624 schedule bytes and all 64 plaintext/ciphertext bytes.
Every altered executable must return a quarantined owner at generation 2 and
refuse a session. Rejection before admission, a healthy owner, a crash, extra
output or missing completion cannot count as quarantine success. The original
executable is retained unchanged; temporary corrupted copies are not released.
This is startup self-test coverage, **not** detection of faults injected into
later AES operations, physical-fault resistance or protection against arbitrary
common-mode corruption.

Seven added regression tests cover both compiler/panic profiles and symbol
manglings, every startup code byte, every reference byte, wrong-width/direction
calls, reference substitution, corrupt kernels/import identities, malformed
symbols and mappings, corruption populations, exact runner markers and registry
input/consumer coverage. Prior leaf, clearing, session and constructor tests
remain in the same suite.

## Public-encryption staging and publication

`aes_riscv_public.py` checks six complete callers in each linked executable:
the package-external `public128/192/256` boundaries containing the ephemeral
owner's inlined operation, and the retained
`Aes128/192/256ExpandedKey::encrypt_block_public` bodies. The 24 reviewed
templates in `riscv-public-review.json` cover both compilers, panic profiles,
owner forms and all widths. Direct and facade imports share each corresponding
body policy. Templates were inspected against GNU RV64 disassembly; the checker
does not capture or accept new templates from the executable under examination.

The bodies enforce the following sequence:

1. Check authority health, generation and selected kernel. A quarantined or
   mismatched authority cannot reach the transform or publish output.
2. Validate the owned region's pointer and exact key/schedule length. Ephemeral
   owners initialize 176/208/240 bytes of schedule scratch, call the matched
   expansion and recheck authority before continuing. Cached owners retain
   their caller-owned schedule; this operation does not destroy the key.
3. Load the 16 input bytes into separate stack scratch. Call the matched-width
   transform with the encryption selector, then recheck authority health,
   generation and kernel before publication.
4. Only the successful path calls the named `memcpy` import with the caller's
   destination, staged result and length 16. Clear the 16-byte staging buffer
   and any ephemeral schedule through the separately checked volatile clear.
   Selected-operation failure paths quarantine the authority and clear their
   initialized scratch. Rejected public operations leave the caller's output
   unchanged; this differs from the secret-output admission/clearing contract.

Cached frames contain 16 staging bytes and saved registers in a 48-byte frame.
Ephemeral frames have 176/208/240 schedule bytes, then 16 staging bytes and
saved registers, totaling 240/272/304 bytes. Width-specific offsets, lengths,
guard branches, quarantine stores, encryption selector and copy/clear arguments
are bound by the complete body bytes. This is **not** a claim that saved
registers or arbitrary compiler spills are erased.

Only eight-byte AUIPC/JALR call displacements are relocated. Expansion and
transform targets must match independently checked leaf bodies of the same
width; clearing must reach the checked volatile zeroizer. Copy, fill and the
MSRV unwind-resume edges must resolve through the actual ELF PLT/GOT/dynamic
symbol records to `memcpy`, `memset` and `_Unwind_Resume`, respectively. Caller,
kernel, cleanup and import extents cannot overlap. Libc implementations,
loader behavior, exception tables and unwinder dispatch remain trusted and
unreviewed. Retained MSRV landing pads bind their scratch clears, quarantine
stores and both resume transfers; abort termination does not promise cleanup.

Seven new regression tests cover all profiles and both Rust manglings, every
single-bit change in every caller body (including guard/count/call bytes),
wrong-width or wrong-kind kernels, every relevant clearing edge, copy/fill
substitution, all twelve retained resume edges, corrupt dependency bodies and
import names, symbol/extent failures, malformed policy offsets and unexpected
target populations. Each linked consumer must emit its own
`AES_RISCV_LINKED_PUBLIC_PASS` marker. Secret-output caller staging and cleanup
are not included in this slice.

## Secret-output admission, staging and cleanup

`aes_riscv_secret.py` checks all six retained `Aes128/192/256Key::secret` and
`Aes128/192/256ExpandedKey::secret` bodies. Each handles both encryption and
decryption through its public direction argument. The 24 complete templates in
`riscv-secret-review.json` cover both compiler endpoints, panic profiles and
owner forms. Direct/facade bodies share the corresponding policy. They were
reviewed against GNU RV64 disassembly, including the width-specific frame,
key/schedule length, staging offset and branch-distance differences. There is
no policy-learning or byte-mask option in the checker.

The first call clears all 16 destination bytes, before inspecting authority
health. Entry rejection returns an error and clears the destination again.
The admitted path checks health, generation, kernel, non-null key/schedule
storage and its exact size. Ephemeral owners initialize schedule scratch, call
the matching expansion and recheck authority. Both forms copy exactly 16 input
bytes into stack staging before selecting encryption or decryption; input
values do not select the direction.

Cached bodies inline the session checks and have two calls to the same
matched-width round leaf, passing selector 1 for decryption and 0 for encryption.
Each direction checks health, generation and kernel after the transform before
reaching the copy. Ephemeral bodies call the corresponding checked
`Session::encrypt128/192/256` or `decrypt128/192/256` body. Those six session
bodies and their leaf targets are independently rechecked, not trusted merely
because their symbols exist. The ephemeral caller must accept only the exact
compiled success discriminant (8 on MSRV, 255 on the current compiler);
otherwise it follows the error/clearing path. These are compiler-specific
internal representations, not a public ABI guarantee.

On success, the named `memcpy` import copies 16 staged bytes into the admitted
destination. The staging region and any ephemeral schedule are explicitly
cleared before returning a success record containing the destination pointer
and length 16. The caller receives a clearing `SecretBlock`; successful output
is deliberately retained until that owner is cleared or dropped. On selected
operation failure, initialized staging, ephemeral schedule and destination
are cleared and authority is terminally quarantined. Cached key storage remains
owned and is not destroyed by an individual successful operation.

Cached frames are 80 bytes, with 16 staging bytes below saved registers.
Ephemeral abort frames are 256/288/320 bytes; unwind frames are 272/304/336
bytes. Their 176/208/240-byte schedule starts at stack offset zero, followed by
16 staging bytes and then saved registers. The policies bind the exact stack
offsets, direction branches, result discriminants, error/quarantine stores,
destination/length arguments, clears and owner transfer. They do not establish
erasure of arbitrary spills or saved registers.

Only the reviewed eight-byte call or tail-transfer relocations vary. An early
cached rejection tail-calls the volatile zeroizer on MSRV abort and both
current profiles; replacing that tail transfer with a returning call is rejected.
MSRV unwind bodies retain one resume edge per cached owner and two per ephemeral
owner, with the relevant staging/destination/schedule clears and quarantine
stores bound. The live `_Unwind_Resume` identity must agree with the checked
session bodies' resume import. The current bodies retain no such resume edges.
Exception-table dispatch and runtime unwinding remain outside this review;
abort termination does not promise cleanup. All kernel, session, caller,
zeroizer/destruction and runtime-import extents must be disjoint, and the copy,
fill and resume identities bind actual ELF dynamic symbols and relocations.

Seven new regression tests cover all profiles and both manglings, every bit in
each full caller body, both direction/width bindings, all clearing calls,
call-versus-tail substitution, all nine MSRV resume edges, corrupted leaf,
session and cleanup bodies, wrong imports, malformed symbols/extents and
invalid policy/target populations. Each linked consumer must emit
`AES_RISCV_LINKED_SECRET_PASS` separately. Existing QEMU consumer tests exercise
both directions and both owner forms, normal/explicit clearing, rejected
quarantined operations and the distinct public-output-preservation contract.

## Regression controls and limits

The six-leaf JSON byte fixtures are regression inputs only, not acceptance templates
or authority for new binaries. Tests mutate actual instruction bytes to check
rejection of secret branches/addresses, out-of-range reads/writes, writes into
read-only input, schedule reads before initialization, changed round counts,
missing clears on either return, bad branch destinations, unknown instructions,
calls and privileged/stack instructions. Additional tests cover nontermination,
ELF corruption, symbol/width populations, legacy mangling, wrong execution
markers and ambient build overrides.

Beyond the explicitly named leaf, clearing, block-session, key-constructor,
public-encryption, secret-output and separate startup bodies, this stage does
**not** review arbitrary downstream caller code or exception tables. Running their functional checks is not equivalent
to reviewing their emitted code. It does not establish compiler-spill erasure,
register erasure outside the leaves, microarchitectural constant time, power/EM
resistance, physical-fault detection or behavior of arbitrary downstream builds.
An arithmetic change may preserve this checker's structural properties while
producing wrong AES results; it must still pass the separate functional and
oracle checks. Native performance and timing remain unavailable on the offered
host because it lacks the required AES extensions.
