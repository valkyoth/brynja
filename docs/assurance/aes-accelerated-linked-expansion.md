# Hardware AES expansion: final-linked body review

This v0.27.3 development review covers the complete AES-128/192/256 hardware
expansion bodies in the packaged ELF consumers, including compiler-generated
instructions. It does not close review of callers, startup admission, ownership,
or their cleanup. It does not replace native AArch64 testing or establish
physical side-channel/fault resistance. No release gate is added.

## Binding and reproduction

The existing `aes-linked-kernel` configurations now require both round and
expansion review. Run `brynja-verify run aes --needed --category aes-linked-kernel`.
The [round-kernel review](aes-accelerated-linked-kernels.md) describes the six
compiler/target/admission configurations and the four consumers per configuration.
Capture-only mode still performs no machine review and emits no pass marker.

`aes_accelerated_linked_expansion.py` contains independent, explicit instruction
and encoding templates, not hashes learned from the executable under review.
The templates admit exactly the three public key/schedule pairs: 16/176,
24/208 and 32/240 bytes. Symbol selection accepts the reviewed legacy/v0 Rust
manglings, requires three distinct nonoverlapping text extents, and rejects the
wrong architecture. The body, rather than symbol spelling, determines width;
the three bodies must contain one of each width. Decoded bytes must match a
unique executable ELF mapping. Only local branch addresses are normalized,
after checking the annotation and destination instruction boundary. Encodings,
registers, instruction lengths and all branch displacements remain exact.

## Shared recurrence and bounds

Both implementations copy the original key into the beginning of the schedule
in four-byte words. A public byte offset advances from zero to K, then to S,
never exceeding the schedule. At generated offset i, the previous word i-4
and the word i-K are already initialized. Reads/writes are unaligned four-byte
accesses; valid, disjoint caller borrows are a precondition, not established by
these machine-body checks.

The phase counter starts at zero after copying the key and advances by four,
resetting at K. Phase zero applies SubWord, RotWord and Rcon. The AES-256-only
phase 16 applies SubWord without rotation/Rcon. Every other phase directly XORs
the previous word with the word K bytes earlier. Thus key width, schedule
extent, phase and the public Rcon recurrence determine every branch and address.
No secret word is used as a memory index or branch condition. These observations
are scoped to the exact checked bodies, not all compilers or processors.

## x86_64 (45 instructions, 145 bytes per width)

RDI/RSI are the input/output pointers. RAX is the byte offset; R8 is the phase;
ECX starts at one for Rcon. EDX contains the working secret word. R10 contains
only a public width or an earlier output offset.

- Offsets 0x00–0x19 initialize/copy the key, then initialize phase and Rcon.
- 0x1a–0x34 load the previous word and choose SubWord on phase zero or the
  AES-256 half-key boundary. All tests here use R8 or the public K constant.
- 0x35–0x58 replicate EDX into XMM0, apply AESKEYGENASSIST with immediate zero,
  and take lane zero for SubWord. At phase zero, rotating the little-endian
  word right eight bits implements RotWord. XOR with ECX adds Rcon. `addb cl,cl`
  sets carry from public Rcon; `jae` skips reduction when carry is clear,
  otherwise XOR 0x1b reduces it. The prior secret XOR flags are overwritten
  before this branch. ECX's upper bytes remain zero.
- 0x59–0x7f compute the prior-key-width address, XOR/store the generated word,
  advance/reset the public phase, and loop until the public schedule extent.
- 0x80–0x90 clear XMM0, EAX, ECX, EDX, R8D and R10D and return. The 32-bit
  clears also zero the upper halves of the corresponding general registers.

There are no calls, stack accesses, secret-dependent branches, or secret-indexed
tables inside the complete symbol. This does not erase input/output memory or
copies previously made by callers.

## Little-endian AArch64 (49 instructions, 196 bytes per width)

X0/X1 are the input/output pointers. X9 is the byte offset, X10 the phase, W11
public Rcon. W12/W13 carry working secret words; X14 is a public address/width
temporary, or W14 the public Rcon intermediate. V1 is initialized to zero.

- 0x00–0x23 initialize/copy the key and set phase/Rcon.
- 0x24–0x43 load the previous word and select the same phase cases as x86.
- 0x44–0x6f duplicate W12 into all four columns of V0, apply AESE with zero V1,
  and take lane zero. Equal columns make ShiftRows an identity, leaving SubWord.
  Phase zero rotates right eight bits and XORs W11. Rcon shifts left; `tbz`
  examines its public bit seven, conditionally XORs 0x1b and masks to a byte.
- 0x70–0x9b XOR the already initialized prior-key-width word, store, and update
  the public offset/phase until S. Word accesses have the same bounds as x86.
- 0x9c–0xc3 clear V0/V1, X9–X14 and NZCV, then return. No callee-saved vector
  registers, calls or stack accesses appear anywhere in the body.

These ELF bodies can be inspected and executed under QEMU without pretending
that emulation establishes native timing, CPU behavior, or macOS/Mach-O code.

## Regression controls

Each actual consumer review rejects every single-byte XOR-one mutation and
every replaced instruction independently: 570 expansion controls on x86 or
735 on AArch64, in addition to the round-kernel controls. Byte mutations also
change the synthetic ELF mapping, so they must fail the exact template rather
than only the file/disassembly comparison. Tests additionally cover secret
address/branch substitutions, incorrect SubWord/rotation/Rcon/erasure operands,
malformed mappings and disassembly, missing/extra/overlapping symbols, invalid
v0 shapes, wrong architecture, duplicate widths, and branch annotation lies.
The runner must reject a consumer missing either the round or expansion bodies.

The evidence is an unauthenticated local observation. Trusted inspection tools
and valid callers remain assumptions. Cached/per-operation wrapper policies
that describe the previous portable expansion must still be re-reviewed;
passing these kernel checks does not turn those stale policies into passes.
