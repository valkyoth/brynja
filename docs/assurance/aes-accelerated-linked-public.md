# Accelerated cached public-encryption caller review

Status: bounded v0.27.3 development review, not whole-consumer qualification.
This extends the [linked kernel review](aes-accelerated-linked-kernels.md) to
the complete surviving x86 `Aes{128,192,256}ExpandedKey::encrypt_block_public`
symbols in the same package-external fixture. It does not cover the other
owner methods or ARM callers.

```sh
brynja-verify run aes --needed --category aes-linked-public
```

The runner builds and executes four native x86 static-admission consumers per
compiler (direct/facade, abort/unwind), using Rust 1.90.0 or 1.99.1 and the
existing opt3/fat-LTO/one-codegen-unit/overflow-check profile. It preserves the
known-answer, clearing and post-quarantine rejection checks. No production
code or public API is changed for the review. Capture-only and emulated modes
cannot satisfy this review.

## Complete wrapper dataflow

The inspected layout contains the authority pointer, session generation,
schedule pointer and schedule length. The complete instruction streams first
check health, generation and selected-kernel state. These are public admission
metadata, not key-derived values. A null schedule or wrong public extent
(176/208/240 bytes) triggers the emitted quarantine path, without reading the
input or writing caller output. Other admission failures return without
releasing output or reaching a kernel. The fixed generation update in this
specialized consumer is pinned as emitted; it is not a proof of every generic
authority construction or generation-exhaustion path.

After all checks, the wrapper copies exactly 16 input bytes to private stack
staging. It passes the staging address, admitted schedule pointer and constant
zero (encryption direction) to the matching reviewed AES-NI kernel. The caller
output pointer is preserved separately. Only after the kernel returns does the
wrapper load the transformed staging and store exactly 16 bytes to that output.
It then clears exactly the 16-byte staging through the reviewed volatile-clear
routine and returns success. There is no table lookup or key/plaintext-derived
branch or address within these wrapper bodies. The only calls are the matched
round kernel, volatile clear and, for the older unwind profile, unwind resume.

Rust 1.90.0 abort bodies have 48 instructions / 139 bytes. Its unwind bodies
have 73 instructions / 228 bytes, including the emitted landing pad. That pad
saves the exception pointer, quarantines unless already quarantined, clears
the staging, checks/quarantines again for the outer operation guard, and calls
`_Unwind_Resume`. It does not publish staging on that path. The resume import is
bound to the actual executable PLT bytes and GOT relocation by the existing
PLT validator. Exception tables, loader and unwinder behavior remain outside
this instruction review; no injected hardware exception or landing-pad
dispatch test is claimed.

Rust 1.99.1 produces 47 instructions / 138 bytes in both panic profiles. In
this fixture the compiler proves the selected call path cannot Rust-unwind and
removes the landing pad. The resulting complete stream still includes all
admission, schedule-bound, publication and normal cleanup instructions. These
separate policies cannot be substituted across compiler profiles. Each width
has its own pinned schedule-bound encoding and digest.

## Binding and negative controls

`aes_accelerated_linked_public.py` requires exactly the three named wrappers
and one volatile-clear helper. The kernel symbols are resolved by their
reviewed executable bodies and must contain exactly one of each AES width.
Calls must agree in decoded address, symbol name and encoded displacement,
and point to the corresponding width or reviewed clear body. The three
complete kernels and the 105-byte volatile-clear body are checked again;
matching a callee name alone is insufficient.

The existing ELF observer binds each wrapper's entire decoded stream to the
executable bytes and checks every local branch boundary and direct call.
Only validated call displacements are normalized; operands, guard conditions,
schedule sizes, stores, clear lengths, error values and landing-pad instructions
are pinned. There is no automatic policy refresh. A changed stream requires
an explicit new review.

Every wrapper rejects one textual mutation per instruction and one encoded
mutation per byte, including matching changes to the executable mapping:
561 controls per 1.90.0 abort binary, 903 per 1.90.0 unwind binary, and 555
per 1.99.1 binary, plus three volatile-clear controls. Dedicated regression
tests use a byte-backed synthetic ELF containing transcribed real 1.99.1
wrappers, all three real kernel templates and the real clear body. They reject
a valid but wrong-width kernel call, altered guards, publication addresses,
clear lengths, quarantine updates, helper bytes and unsupported configurations.

## Residual scope

Normal caller output deliberately contains ciphertext. The wrapper's XMM0
can retain ciphertext after publication; this is not a secret-register-erasure
claim. Stack padding, upstream copies, constructors, cached key lifetime,
secret-output operations, ephemeral expansion, inlined consumer code and ARM
wrappers remain separate review work. Neither these checks nor kernel source
properties establish native timing, physical side-channel or fault resistance.
Artifacts remain unauthenticated local observations, not certification evidence
or new release requirements. See the
[development status](aes-acceleration-development.md) for the remaining milestone.
