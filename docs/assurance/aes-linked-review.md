# Packaged AES final-linked x86_64 review

This v0.27.2 slice adds observations of **final executables**, not merely
pre-link library assembly. Its machine-code claim is deliberately restricted
to the eleven portable AES helper bodies, six surviving secret-output wrappers,
six explicit public-consumer boundaries, six constructors and core
copy/volatile-zeroizer routines in the known-answer executable, plus six
consumer cleanup boundaries and their zeroizer in a separate lifecycle
executable. It does not close whole-application qualification.

## Configurations and functional evidence

Run `brynja-verify run aes packaged-linked-msrv` and
`brynja-verify run aes packaged-linked-current`. Each covers direct and facade
imports, panic abort and unwind, on native Linux x86_64. Both use optimization
level 3, fat LTO, one codegen unit, overflow checks and unstripped executables.
All first-party inputs come from byte-checked Cargo archives in an isolated
workspace/Cargo home; no checkout dependency substitution, downloads, hardware
provider or publishing is involved.

The additional fixture performs 18 frozen FIPS 197 known-answer operations:
AES-128/192/256, ephemeral/cached owners, secret encryption/decryption and public
encryption. It checks secret output and caller-owned key/schedule clearing and
public ciphertext persistence. Consumer-only `inline(never)` boundaries call
the frozen public fixture's ordinary/cached import-encrypt-clear functions for
each width. Production methods may inline inside those boundaries; no production
inlining annotation or frozen API fixture was changed. The secret operations
still use their ordinary/cached owners directly. Both panic profiles execute normal success
paths here; **building with unwind does not mean this fixture injects a panic**.
Existing unwind/fault registrations remain separate. The older frozen public
consumer fixtures are unchanged.

### Separate final-linked caller lifecycle executions

`brynja-verify run aes --category package-lifecycle` builds a separate final
executable from `assurance/aes-linked/lifecycle.rs` using the same archive-only
graphs, compiler endpoints, direct/facade imports and optimized fat-LTO profile.
It does not alter the known-answer executable or its reviewed helper policies.
The runner records each lifecycle binary's hash and verifies it did not change
during inspection and execution. It also reviews six explicit consumer cleanup
boundaries and their zeroizer, as described below; this is not an instruction
review of every wrapper or a static review of exception tables.

All six ordinary/cached key types receive twelve normal cases per configuration:
secret encryption and decryption with normal Drop, explicit clear, output
outliving the cleared key, and a caller-side early `Result` return; plus public
encryption followed by normal Drop or caller early return; and both secret
directions transferring key and output ownership into a separately inspectable
cleanup boundary whose opaque callback returns normally. Known answers are
checked before secret outputs are destroyed. Caller-owned key/schedule and
output buffers have whole-buffer canaries on both sides, and input keys/blocks
are checked unchanged. Secret storage must clear; successful public ciphertext
must persist. This is 72 normal cases per executable, 576 across eight builds.

The four unwind builds also execute eight actual caller-unwind cases per key type:
live encrypted/decrypted secret output, an imported key before any operation,
successful public encryption, and encrypted/decrypted secret output with the
key outside the unwind scope. That surviving key must encrypt and decrypt the
known answers again. Two additional cases transfer the key and encrypted or
decrypted secret output into the inspectable cleanup boundary, whose opaque
callback starts a real unwind. These total 192 caller unwinds across both compilers and
routes. A private typed panic payload distinguishes the deliberate unwind from
an assertion failure. Two failing child-process controls per unwind executable
confirm that an unrelated panic and a missing panic cannot count as success;
signals and unrelated exit codes are rejected rather than treated as controls.
The process panic hook is not replaced.

The public portable signatures admit only fixed-size key/block storage, so
these caller-side errors/unwinds **do not simulate internal AES invariant
failures or panic during expansion/round computation**. Separate instrumented
fault tests retain that scope. No unwind is attempted in panic-abort builds,
and no destructor-on-abort, internal scratch observation, spill erasure or
whole-application machine qualification follows from these cases.

## Inspection and review policy

The runner resolves and records the actual `llvm-nm` and `llvm-objdump`
executables, their versions and SHA-256 hashes. It records the compiler identity
and final binary hash, and checks tools/binary are unchanged after inspection
and execution. These tools and the local compiler remain trusted inputs, not
independently attested software.

The unstripped symbol table must have exactly eleven recognized portable helper
symbols with nonzero, nonoverlapping extents. Their addresses and sizes are
logged. The inverse is decoded from that executable using explicit symbol
start/stop bounds. Every instruction's bytes must form a contiguous stream
covering exactly the symbol extent. Missing rows, architecture mismatches,
overlapping instructions, extra symbols, and truncation fail closed. Alignment
bytes outside the symbol are excluded by the symbol extent, not by searching
for the first return or discarding unknown instructions.

Both compiler streams were inspected. Only the existing conservative inverse
grammar is admitted: scalar arithmetic/Boolean operations, immediate shifts,
register conditional moves and fixed-offset stack accesses. There are no calls,
branches, secret-indexed loads or variable shift counts in these reviewed
inverse streams. This is neither an equivalence proof nor proof of instruction
latency on every processor.

| Compiler | Instructions | Symbol bytes | Local frame allocation |
| --- | ---: | ---: | ---: |
| 1.90.0 | 740 | 2385 | 56 bytes, plus callee saves and red-zone accesses |
| 1.99.1 | 749 | 2533 | 32 bytes, plus callee saves and red-zone accesses |

For each compiler, all four route/panic configurations have identical inverse
instruction text **and encoding**. `scripts/aes/linked-inverse-review.json`
pins both digests, counts, target and configuration scope. A change requires
explicit review; there is no automatic update path. Ten mutations per binary
test rejection of branches, calls, indexed accesses, variable shifts, stack
pointer replacement, extra returns/directives, an otherwise permitted arithmetic
insertion and changed instruction bytes.

## Round-key addition and volatile zeroizer

`scripts/aes/aes_linked_helpers.py` additionally pins exact operand-preserving
instruction templates and encoding hashes for three functions in each binary.
Only local branch addresses are normalized, after checking that the numeric
target and its symbol/offset annotation agree. All branch offsets remain in the
templates. Unknown instructions, extra/missing operations, changed registers,
bounds, strides, conditions or encodings require explicit re-review.

| Function | Rust 1.90.0 | Rust 1.99.1 | Inspected data/control boundary |
| --- | ---: | ---: | --- |
| AES-128 round-key addition | 10 instructions / 37 bytes | Same | Round offset and schedule bound control the branch and returned status; state/key loads flow through vector XOR to state storage |
| AES-192/256 shared round-key addition | 97 instructions / 372 bytes | 83 instructions / 326 bytes | Sixteen byte accesses are guarded by public schedule-length/round-offset comparisons; temporary key-byte registers are overwritten from public offsets before reuse as addresses |
| Core volatile zeroizer | 28 instructions / 105 bytes | Same | Public length selects a remainder loop and eight-byte zero-store loop; no reads of the region being cleared |

The MSRV wide helper forms offsets using OR after the round number is shifted
by four bits; current Rust uses LEA for offsets 1–14. The final offset uses OR
with 15 in both. The raw key bytes never feed these offset constructions or
the bounds comparisons. This is review of the pinned sequences, not a general
x86 taint engine or an independent proof of all arithmetic preconditions.

The zeroizer returns immediately for zero length, then writes a length-modulo-8
prefix and complete eight-byte groups. Its addresses/loop tests depend on the
supplied pointer and length, not the prior contents. Its inert alignment NOPs
remain pinned. This verifies the body, **not every caller's pointer/length or
cleanup dispatch**, and does not extend its owned region to compiler spills.

Three further mutations per function test an indexed-access substitution,
misbound branch target and changed encoded byte. Combined with the inverse's
ten mutations, those functions reject nineteen changes per configuration. The decoder
also has a regression for ten-byte instructions that completely fill objdump's
byte column without a trailing space; missing byte separators still fail.

## Mixing and linked constants

`scripts/aes/aes_linked_mix.py` binds the inspected mix helper, including its
actual constant-pool bytes in the final ELF image. Both encryption and decryption
paths were inspected. Rust 1.90.0 emits 303 instructions / 1381 bytes with thirteen
constant loads; Rust 1.99.1 emits 275 instructions / 1271 bytes with six. Each
compiler's normalized stream is identical across the four route/panic builds.

The only conditional branch is the initial `testl %esi, %esi` / `je` selecting
the public forward/inverse operation. State loads never overwrite that direction
argument or the `%rdi` state pointer. Subsequent operations use fixed-offset state
accesses, fixed RIP-relative constants, register arithmetic/Boolean operations,
immediate vector shifts and shuffles. Secret-dependent vector comparisons form
arithmetic masks; they do not select branches or memory addresses. Both paths
store the resulting state and return, with no calls or variable shift counts.
The current compiler spills intermediate vectors to fixed red-zone slots at
offsets -72, -56, -40 and -24 from `%rsp`; those spills are not erased here.

The constants include byte-insertion/selection masks and the `0x1b` field
reduction value. The checker validates ELF64 little-endian x86_64 headers and
nonoverlapping load mappings, binds decoded code to its file-backed read/execute
segment, and requires each constant's complete access width in a file-backed
read-only, non-executable segment. A four-byte `movd` load is distinguished from
sixteen-byte `movdqa` and `pand` loads. Unsupported encodings fail closed.

Only a verified RIP displacement is masked in the encoding hash: its SSE opcode,
register, encoded signed displacement, decoded displacement and numeric target
must agree. The referenced bytes replace that operand in the instruction-text
hash. Local branch offsets remain pinned, and the branch encoding, numeric
target and symbol annotation must agree. Vector lane annotations are retained;
only the cosmetic constant-symbol annotation is discarded after address binding.
There is no automatic digest update. This is review/replay of two exact streams,
not a general machine-code proof, runtime loader attestation or processor timing
guarantee.

Seven mix mutations per executable reject an indexed-access substitution,
misbound constant and branch targets, changed constant bytes, disagreement
between executable and decoded bytes in either direction, and an encoding change
present in both copies. Together those checks reject 26 mutations per binary.
Synthetic ELF tests additionally cover relocation without changing content,
permissions, truncation, overlaps, overflow, BSS tails, operand/encoding mismatch
and constant-access widths. Synthetic test policies cannot satisfy the real AES
policy.

## Substitution and exact inverse calls

`scripts/aes/aes_linked_substitute.py` pins both complete substitution streams:
456 instructions / 1308 bytes on Rust 1.90.0, and 577 instructions / 2059 bytes
on Rust 1.99.1. Each contains 32 direct calls: sixteen on the forward path and
sixteen on the inverse path. Every call's `E8 rel32` encoding, numeric target and
symbol annotation must agree with the **entry address of the exact inverse
symbol** that the runner independently decodes and checks. An interior address,
other symbol, indirect call or altered encoded destination is not accepted.
The inverse's body policy must pass before a successful configuration marker
can be issued. Mapping a callee address by itself does not qualify that body.

Both versions select direction with a single initial `testl %esi, %esi` / `je`.
The inverse path performs immediate rotations/XORs before each inverse call;
the forward path applies the forward affine mapping afterwards. All sixteen
state offsets are fixed. The one-operand `rolb %cl` notation rotates the value
in `%cl` by **one**; it is not a `%cl`-controlled rotation count. No secret value
selects a call target, branch, memory index or rotation count in these streams.

The MSRV forward path processes one byte at a time. Current Rust instead saves
inverse results in fixed stack slots/callee-saved registers and combines the
forward affine results with vector operations and a single read-only sixteen-
byte `0x63` constant, bound using the ELF checks described above. Its original
state pointer is saved at `48(%rsp)` before `%rbx` is reused for arithmetic,
then reloaded into `%rax` for the final state store. Secret bytes are not used
as that pointer. The fixed 56-byte frame and callee saves are restored, but
intermediate stack contents are **not erased**.

Only validated direct-call displacements are masked in addition to RIP
displacements; normalized call identities remain in the text digest. The
conditional branch and current compiler's unconditional epilogue jump retain
their encoded local offsets. Numeric/annotated/encoded destinations must match
an instruction boundary inside the symbol. Both normalized policies match all
four route/panic builds of their compiler. This remains exact review/replay,
not a general interprocedural proof or a promise about all emitted profiles.

Six additional mutations per binary reject an indexed-memory substitution,
wrong numeric callee, wrong callee name, misbound local branch, altered call
displacement in both executable/decoded bytes, and changed non-relocated
instruction bytes. This contributes six of the runner's mutations per binary.
Synthetic tests also cover valid relocation, calls into the middle of a callee,
ambiguous targets, non-executable/out-of-bounds/overlapping callee extents,
indirect calls, jumps misrepresented as calls, branches into instruction middles,
altered affine constants and variable rotation counts.

## Key expansion and round transforms

The three expansion and three transform bodies are pinned separately for each
compiler in `aes_linked_rounds.py`. Width is resolved from the decoded key-length
admission (16/24/32) or the two last-round-key loads (160/192/224), checked against
narrow/wide symbols and v0 generic parameters, then checked against its exact
policy. Duplicate or missing widths fail even when the symbol count is eleven.

| Body | MSRV instructions / bytes | Current instructions / bytes | Static calls |
| --- | --- | --- | --- |
| expand128 | 130 / 451 | 129 / 451 | 5 |
| expand192 | 144 / 514 | 145 / 522 | 5 |
| expand256 | 201 / 677 | 220 / 807 | 9 |
| transform128 | 204 / 854 | 199 / 840 | 12 |
| transform192 | 206 / 875 | 201 / 861 | 12 |
| transform256 | 206 / 875 | 201 / 861 | 12 |

Expansion first checks the public key length, then copies the key and generates
the schedule with public word/phase counters. AES-128 uses R12 from 19 to 179,
stepping by four; its phase test is `(R12 - 3) & 12`. AES-192 uses RBX from zero
through 45. MSRV computes its six-word phase using byte counters and multiplication
by 171; current Rust uses public counters and multiplication by
`0xAAAAAAAAAAAAAAAB`. Those multiply operands are not key bytes. AES-256 uses
R12 from 35 to 243 on MSRV and RBX from 32 to 240 on current Rust, stepping by
four, with public phase tests selecting the ordinary and extra SubWord cases.
Key-dependent bytes do not supply these indices or phase conditions.

Expansion calls only the independently reviewed inverse and zeroizer. Its
four-byte temporary word is cleared before return: at RSP except current
AES-256, where it is at RSP+8. Schedule retention is intentional and belongs to
the caller's owner lifecycle. Stack-frame restoration does not erase affine
intermediates or compiler spills, and this review does not claim otherwise.

Transform direction comes from public EDX. Forward and inverse round counts
are fixed by the width; the final round omits MixColumns. MSRV's inverse counter
starts at 10/12/14 and decrements, while its forward counter starts at one and
ends at 10/12/14. Current Rust's inverse R13 starts at 11/13/15 with the round
index R13-2; forward R15 starts at zero and checks 9/11/13 before the final
round. Secret state does not set these counters. Status branches consume the
previously reviewed round-key helper's public bounds result.

Each transform has four static substitution calls, two mixing calls, two calls
to its narrow/wide round-key helper and four zeroizer calls. The latter clear
the sixteen-byte ShiftRows copy before proceeding, including before a round-key
error return. Four read-only ELF mask loads bind the two forward/inverse
ShiftRows masks. Error returns here do not establish cleanup of the caller's
whole state or schedule; that requires the surrounding wrapper review.

Every direct call must target the exact admitted helper entry, whose body is
checked separately during the same inspection. Short and near JE/JNE/JA/JMP
branches must have matching decoded, annotated and encoded destinations on a
local instruction boundary. Only validated call/RIP relocations are masked;
loop bounds, branch offsets, cleanup sizes, register operands and all other
instruction bytes remain pinned. Policies have no automatic refresh path.

Eight negative controls per body reject indexed-memory replacement, wrong
numeric call target, wrong callee name, misbound branch, changed loop bound,
zero cleanup length, removed cleanup call and changed instruction bytes in
both the executable and decoded stream. Together with the preceding helper
checks, this accounts for 80 mutations per binary. Synthetic tests also
check short/near forward/backward branches, width/population errors and that
synthetic policies cannot satisfy the real reviewed profiles.

## Surviving secret-output wrappers and copy routine

Six secret-output wrapper bodies survive linking: ordinary-key transforms for
128/192/256, the cached 128-bit transform, and the two wide `secret` helpers.
Their symbol population is separately required, with exact owner namespaces
and both supported Rust manglings. Opaque wide-helper hashes are resolved by
their single call to the already reviewed 192- or 256-bit transform; v0 generic
width parameters must agree. Both wide roles must be present exactly once.
The core `copy_bytes` symbol must also be unique and have a nonzero extent.

`aes_linked_wrappers.py` pins complete instruction text, local branch offsets,
encoding bytes and exact direct-call identities. Only validated relative call
displacements are normalized; there are no constant-pool loads in these bodies.
The resulting pins agree for both import routes. They distinguish panic profiles
and compiler differences rather than accepting either stream interchangeably.

| Body | Instructions / bytes | Static calls |
| --- | --- | --- |
| ordinary 128 | 79 / 318, both compilers/profiles | 8 |
| cached 128 | abort 59 / 200; unwind 58 / 197, both compilers | 5 |
| ordinary 192 | 66 / 281, with distinct abort/unwind instruction order | 5 |
| ordinary 256 | 68 / 297, with distinct abort/unwind instruction order | 5 |
| wide secret, each width | MSRV 64 / 218; current 63 / 211 | 6 |
| core copy | 22 / 63, both compilers/profiles | 0 |

Ordinary-key transforms first clear the admitted sixteen-byte destination.
The 128-bit body zero-initializes its 176-byte stack schedule at RSP+16, expands,
and only on expansion success copies input to the sixteen-byte state at RSP.
An expansion failure clears schedule and destination; a transform failure
additionally clears state. Success copies exactly sixteen state bytes to the
destination, constructs the success/owned-region fields, then clears state and
schedule without clearing the newly owned output. The return discriminator is
set to error before failure cleanup, and success only follows the copy.

The 192/256-bit ordinary bodies use a 208/240-byte schedule at RSP+32 and an
initialization descriptor at RSP+8. They clear the destination before expansion;
on failure they clear schedule and destination, and on success delegate output
ownership to the width-matched `secret` helper before clearing the schedule.
Their key pointer/length conditional moves depend on public owner metadata,
not key contents. Abort/unwind builds differ only in the ordering of these
metadata operations and the final zero-initialization store; both are pinned.

The cached 128-bit body admits/clears output before checking that its schedule
pointer exists and its length is 176. It never re-expands or destroys the
cached schedule. It clears local state after transform/copy, and clears output
on metadata/transform errors. Abort combines the public metadata predicates
with AND/compare; unwind uses TEST. Neither condition inspects secret bytes.

Each wide `secret` helper stages a sixteen-byte state, calls the matching
portable transform, and handles the initialization descriptor's optional
pointer, capacity and written offset. The `offset + 16` overflow/capacity
checks precede copying. A complete write transfers the pointer/length into the
success result; an incomplete write clears the admitted destination and returns
error. All ordinary return paths clear state. MSRV also stores the updated
written offset in the consumed descriptor; current Rust eliminates that store.
Transform-error status and descriptor branches are public control, not secret
block or key content. These checks do not admit arbitrary fabricated descriptors
or extend the Rust API's safety contract.

The copy routine moves eight-byte chunks and then remaining bytes, with indices
and branches determined solely by the public length. It calls nothing and uses
no secret-indexed addressing. It explicitly zeros EAX/ECX/EDX before return;
this is a local observation, not a guarantee about all secret registers/spills.
Pointers, extents and non-overlap are established by the callers/typed region
contract, not independently rediscovered by this low-level routine.

Eight negative controls for each of these seven bodies add 56 cases, bringing
the runner total to **136 rejected mutations per binary**. Wrapper cases change
an indexed operand, branch destination, numeric/named callee, clearing call,
clearing length, error discriminator and encoded bytes. Copy cases additionally
change chunk bounds, store width, index step, register clearing and source
pointer. Tests cover duplicate/missing/overlapping symbols, wrong namespaces,
generic-width mismatches, ambiguous transform binding and branch encodings.

This reviews the emitted normal and explicit-error bodies; it does not force
internal invariant failures dynamically, or qualify exception tables/unwind
dispatch. The separate caller-unwind fixture remains the dynamic observation
described above. Constructors, public-output operations, other cached wrappers
and owner destruction are **not** approved merely because these surviving
functions pass; the explicit public boundaries receive the additional review below.

## Public-output boundaries and constructors

`aes_linked_public.py` requires exactly six named consumer boundaries and six
production constructors in each final binary. Exact namespace/owner/width
matching, nonempty nonoverlapping extents, complete instruction decoding,
ELF-backed bytes and direct-call entry binding apply to all twelve. Constructor
and width-matched expansion/transform call targets are independently reviewed;
resolving a target name alone is not acceptance. Both compiler endpoints,
panic profiles and direct/facade routes match the same twelve normalized
policies. Only validated call relocations and local branch annotations are
normalized; no operands, status tests, stores or cleanup lengths are erased.

| Body | Instructions / bytes (128, 192, 256) | Static calls |
| --- | --- | ---: |
| Ordinary constructor | 20 / 68 each | 2 |
| Cached constructor | 51 / 214; 53 / 230; 55 / 246 | 5 |
| Ordinary public consumer | 70 / 268; 72 / 284; 74 / 300 | 6 |
| Cached public consumer | 54 / 161 each | 4 |

Ordinary constructors clear the caller's 16/24/32-byte region before copying
exactly that many input key bytes. The returned owner records that pointer,
matching length and success discriminator. These typed-array constructors have
no key-content-dependent checks or branches.

Cached constructors first clear the caller's 176/208/240-byte schedule region,
zero-initialize an equally sized local schedule, and expand with the fixed
16/24/32-byte input length. Expansion failure writes the error discriminator,
clears local schedule and caller storage, and returns. Success copies the
entire local schedule to caller storage, records the pointer/length/success,
then clears the local schedule. The final zeroizer is shared by those paths,
but its pointer is the caller region on failure and local schedule on success.
This distinction is retained in the exact policy.

Ordinary public consumers call the constructor and inspect its returned status
before using its metadata. The local schedule is at RSP+16 and the state at RSP,
with frames of 192/224/256 bytes. The key pointer/length conditional moves handle
public optional-owner metadata; they do not inspect key bytes. Only successful
expansion stages the input state and calls the width-matched forward transform.
Only a successful transform permits the sixteen-byte state store to the caller's
public output. Both transform outcomes clear local state. Expansion and transform
return paths clear the local schedule, then clear owned key storage if present.

Cached public consumers use a 32-byte frame, call the cached constructor, and
check its status plus the returned schedule pointer and exact 176/208/240 length.
They stage state in the frame, call the matching forward transform, and use the
same success-guarded sixteen-byte publication followed by local-state clearing.
The returned owner's schedule region is cleared before return. Invalid metadata
skips transformation/publication and clears any present owned region. These
functions intentionally import/use/clear for observation; they do not change the
API's ability to retain a cached key for many operations.

Failure paths do not publish a partial result or clear the unadmitted public
destination: its previous contents remain. Status, owner presence and public
lengths select the branches, never key or block contents. No echo/fixed-point
filter or provider policy is introduced. None of these twelve emitted bodies
contains an unwind landing pad; this body review does **not** qualify the
executable's exception tables, runtime unwinder or other inlined caller paths.

Ten negative controls per body add 120 cases, for **256 rejected mutations per
binary**. Shared cases alter an indexed operand, numeric/named callee, clearing
call/length and encoded byte. Constructor cases also alter copy length/source,
owner length, success/error status, final cleanup or a branch destination.
Public cases additionally bypass the transform-success guard, substitute input
for transformed state, skip owner clearing and misbind a branch. Unit tests
replay all three real ordinary-constructor streams and use explicitly synthetic
non-AES policies to test the other mutation paths; those synthetic streams are
rejected by the real policies. Every actual binary also runs all 120 new controls.

## Focused caller cleanup and unwind landing pads

The lifecycle executable has six consumer-only `inline(never)` boundaries,
one for each ordinary/cached AES key owner. Each takes ownership of a real key
and `SecretBlock`, invokes an opaque public function pointer, then drops the
output and key. The operation producing the block occurs before this boundary;
this does not inject a failure during AES rounds. The callback either returns
or starts the typed caller unwind described above.

The full emitted streams were reviewed for both compiler endpoints and panic
profiles. The six widths differ only in their public completion-size constant.
Each exact text/encoding policy is pinned separately, without an automatic
refresh path:

| Compiler / panic | Instructions / bytes per boundary | Stack frame | Callback slot |
| --- | --- | --- | --- |
| 1.90.0 / abort | 28 / 115 | 40 bytes | `rsp + 0` |
| 1.90.0 / unwind | 48 / 198 | 48 bytes, plus saved RBX | `rsp + 8` |
| 1.99.1 / abort | 28 / 127 | 56 bytes | `rsp + 8` |
| 1.99.1 / unwind | 48 / 190 | 48 bytes, plus saved RBX | `rsp + 0` |

The key pointer/length arrive in RDI/RSI and output pointer/length in RDX/RCX;
the public callback arrives in R8. The exact reviewed streams preserve these
descriptors on fixed stack offsets, invoke the callback exactly once and clear
the output before the key/schedule. Clearing branches test owner-pointer
presence, not secret contents. The unwind landing pads preserve the exception
pointer in RBX, clear the same output and owner descriptors and pass the
exception pointer to `_Unwind_Resume`. The full extents of these bodies, including
the landing pads, are checked; the stream is not truncated at the normal return.

Only these cleanup policies allow the single observed stack-indirect callback
instruction, with its exact opcode and source/slot flow bound by the policy.
The other AES helper policies still reject indirect calls. Direct clearing
calls must reach the independently reviewed zeroizer from this same executable.
The resume call must reach the actual file-backed executable PLT entry; its
opcode, GOT displacement, relocation index and jump back to the PLT base are
bound to the unique `_Unwind_Resume` dynamic relocation. This identifies a
trusted runtime dependency, **not** an approval of the dynamic loader or
unwinder implementation.

Each abort boundary rejects ten mutations and each unwind boundary twelve,
including changed callback source/target, clearing length, skipped clearing,
branch/callee misbinding, completion constant and encoded bytes. Together with
three zeroizer controls per executable, this is 63 rejected mutations per
abort binary and 75 per unwind binary: **552 across eight builds**. Unit tests
also reject malformed symbol populations and PLT/relocation bindings. Synthetic
unit-test streams are not accepted by the real body policies.

Actual caller unwinds exercise the exception dispatch into these landing pads,
but exception tables, the runtime unwinder and other inlined callers are not
statically qualified by this slice. Abort builds exercise normal cleanup only.
Neither stack restoration nor dropping the source owners proves erasure of
compiler-created spills or registers.

## Residuals and unfinished work

The inverse **does spill secret intermediate values to the stack/red zone**.
The reviewed fixed addresses avoid secret-indexed access; they do not erase
those spills. Restoring the stack pointer/callee-saved registers is not secret
erasure, and no spill/register/dump/swap guarantee is made here.

All eleven surviving portable AES helper bodies, six secret wrappers, six
public consumer boundaries, six constructors and the core copy/zeroizer are
reviewed in the known-answer executable, with the six cleanup boundaries and
their zeroizer separately reviewed in the lifecycle executable, **not** either
whole final executable. Other inlined caller paths,
exception tables/runtime unwind dispatch, other dependency code and other
optimizations still need their scoped review. Inlined code is not covered merely
because helper symbols remain. Native AArch64 timing and bounded final-linked
review are recorded separately in [portable acceptance](aes-portable-acceptance.md)
and [the ARM linked review](aes-aarch64-linked-review.md); this x86_64 result
does not substitute for them.

These observations remain independent of the existing finite publication gate.
They add no HSM requirement, certification profile or release approval record.
