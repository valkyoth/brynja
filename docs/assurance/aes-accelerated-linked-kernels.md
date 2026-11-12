# Accelerated AES final-linked kernel review (v0.27.3 development)

This is a bounded review of the three complete round-kernel bodies in each
retained executable, not a whole-program constant-time or erasure claim.
The same runner now also requires the three complete
[hardware expansion bodies](aes-accelerated-linked-expansion.md).
The surrounding dispatch, owner operations and cleanup still need
their separate final-linked review. Native ARM qualification remains separate
from the emulated ELF checks below. No release gate is added.

## Reproduction and binding

```sh
brynja-verify run aes --needed --category aes-linked-kernel
```

Six configurations cover Rust 1.90.0 and 1.99.1: native x86 static admission,
AArch64 QEMU static admission, and AArch64 QEMU hosted admission with global AES
disabled. Each builds four offline, package-external consumers: direct/facade
routes with abort/unwind panic profiles, optimization level 3, fat LTO, one
codegen unit and overflow checks. Both ephemeral and cached owners execute
published AES-128/192/256 answers in both directions, public encryption,
clearing and post-revocation rejection checks. Hosted selection is required;
unavailability cannot silently select portable execution.

`scripts/aes/check-aes-accelerated-linked.py` retains executable, metadata,
disassembly, symbols, build/execution logs and review JSON beneath
`target/aes-accelerated-linked`. Executable and inspection-tool hashes are
checked across inspection/execution. This is unauthenticated local evidence;
it neither authenticates the tools nor measures their shared libraries.
`--capture-only` deliberately emits no verification pass marker.

On an Apple AArch64 host, `--mode apple-native --capture-only` captures the
same direct/facade and abort/unwind fixture as native `aarch64-apple-darwin`
Mach-O executables. Both static and hosted admission are supported for capture.
This mode uses the platform linker, not the Linux musl linker. Symbols are
captured without ELF symbol-size fields, and each report explicitly records
`machine_review: not-performed`. All machine-review flags are rejected before
packaging. The ELF byte-mapping/template reviews below do not apply to Mach-O;
executing the correctness fixture and saving disassembly is not code qualification.
The subsequent [Apple body-only reviewer](aes-apple-linked-kernels.md) independently
maps Mach-O metadata and matches complete function encodings in the retained
executables. It does not change capture reports or approve Apple callers,
admission, cleanup or unwind paths.

The reviewer requires exactly three nonoverlapping kernel symbols with one
body for each width. It checks the complete symbol extent, not just instructions
before the first return. Every decoded byte must match a unique read/execute
ELF load mapping. Local branch addresses, symbol annotations and instruction
boundaries must agree. Instruction text, encodings and lengths must then match
the explicit reviewed templates. No instruction/register/branch wildcard or
automatic hash-refresh acceptance is provided. Alignment outside the symbol
extent is excluded. Compiler changes require an explicit review.

## x86_64 AES-NI bodies

Each body is 32 instructions / 123 bytes. The ABI supplies the state pointer in
RDI, schedule pointer in RSI and public direction in EDX. The compiler copies
direction into ECX and sets EDX to the public final-key byte offset 160, 192 or
224. A 16-byte unaligned load initializes XMM0. Direction chooses two paths:

- Encryption XORs round key zero, then uses AESENC for offsets 16 through
  final-minus-16 and AESENCLAST for the final key. RAX advances by 16; the loop
  has 9, 11 or 13 middle rounds.
- Decryption XORs the final key, decreases RAX by 16 before each middle-key
  load, applies AESIMC to that key and AESDEC to the state, and stops at offset
  16. AESDECLAST uses key zero. The stored forward schedule is never modified.

Both paths join at one 16-byte state store. XMM0, XMM1 and EAX are cleared
before return. All branches depend on public direction or fixed loop indices;
all schedule offsets are bounded multiples of 16. There are no calls or stack
accesses within the complete symbol, including compiler-generated instructions.
This does not claim erasure of every caller register or earlier spill slot.

## AArch64 AES bodies

Each body is 38 instructions / 152 bytes. X0 and X1 hold state/schedule pointers;
W2 is the public direction, copied to W8. W11 contains final-key offset 160,
192 or 224. A 16-byte load initializes V0.

- Encryption starts at offset zero and uses AESE then AESMC while advancing X9
  by 16 up to final-minus-16. The last AESE uses that penultimate key; XOR with
  the final key completes the state. The key ordering is intentionally different
  from AES-NI.
- Decryption starts with AESD using the final key and AESIMC on the state.
  Subsequent keys are loaded at descending offsets and inverse-mixed in V1
  before AESD. At offset 16 the loop omits the state AESIMC and finishes with
  XOR against key zero. The total AESD count is 10, 12 or 14.

Both paths join at one 16-byte state store. V0, V1, X9, X10 and NZCV are cleared
before return. Direction and fixed round indices are the only branch inputs;
schedule reads are bounded, and no schedule writes, calls or stack accesses
occur within the symbol. Working vector registers are caller-clobbered.

## Regression controls and limits

Every reviewed executable must reject one encoded-byte mutation at each byte
position and one textual mutation at each instruction position: 465 controls
across its three x86 kernels or 570 across its three ARM kernels. Encoded
mutations also change the synthetic executable mapping so rejection tests the
reviewed template, not merely a disassembly/file mismatch. Additional unit
tests cover missing/extra symbols, duplicate widths, branch-address lies,
malformed ELF mappings, altered memory operands, bounds and register clearing,
and invalid execution populations/configurations.

These checks assume trusted local inspection tools and valid callers providing
the documented pointers, public direction and schedule layout. They do not
establish those caller properties, whole-consumer constant-time behavior,
compiler-spill erasure, native ARM performance, timing/power/EM resistance or
physical fault resistance. See the
[development status](aes-acceleration-development.md) for remaining work.
