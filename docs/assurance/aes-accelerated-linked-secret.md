# Accelerated AES: bounded x86 cached secret-output caller review

This v0.27.3 development review covers the complete emitted
`Aes128ExpandedKey::secret`, `Aes192ExpandedKey::secret` and
`Aes256ExpandedKey::secret` bodies under static x86 AES-NI admission.
It is not whole-consumer qualification. Constructors, ephemeral owners,
returned-owner destruction, ARM callers and native timing remain separate work.

## Reproduction and boundary

```sh
brynja-verify run aes --needed --category aes-linked-secret
```

The registered runner packages byte-checked sources into isolated offline
consumers, then executes and inspects direct/facade routes with both abort and
unwind on Rust 1.90.0 and 1.99.1. Profiles use opt3, fat LTO, one codegen unit
and overflow checks. Each consumer exercises six successful operations per
width, returned-output clearing and quarantine rejection. The fixture also
checks that cached encryption and decryption clear a prefilled destination
when authority has been quarantined; public rejection preserves its destination.

Artifacts are retained under `target/aes-accelerated-linked/`: executable,
symbols, decoded bytes, relocations, build/execution logs, package metadata and
JSON reports with executable and inspection-tool hashes. Capture-only runs do
not establish a review pass. The report is a local observation, not signed
certification evidence.

## Inspected dataflow

The ABI supplies a result location, cached owner, input block, destination and
public direction selector. The wrappers preserve those arguments, clear the
16-byte destination before admission, and test authority health, generation and
kernel selection. They check that the cached schedule exists and is exactly
176, 208 or 240 bytes. Only these public metadata and direction values govern
the wrapper branches; the pinned streams contain no secret-indexed lookup.

After admission, one 16-byte input is staged on the stack. The wrapper passes
the matching-width schedule and public direction to the separately reviewed
kernel. A reviewed `copy_bytes` helper copies exactly 16 bytes from staging to
the admitted destination; the volatile helper then clears staging. Success
stores the destination pointer, length 16 and successful result discriminant,
transferring responsibility to the returned secret owner. The output deliberately
remains live on success. This bounded caller review does not inspect the later
owner destructor; the executable checks returned-owner clearing behavior.

Admission failure stores an error and clears the destination. A missing or
wrong-sized schedule additionally quarantines the authority and updates its
generation. Rust 1.90.0 uses an ordinary clearing call before its epilogue;
1.99.1 restores its frame and tail-jumps to the same volatile helper. The
observer admits only this named tail role, checks its E9 rel32 encoding and
destination against the executable, and rejects indirect or redirected edges.
Other users of the shared observer still reject external jumps by default.

Rust 1.90.0 unwind bodies separately select encrypt/decrypt kernel calls. Their
emitted landing pad quarantines, clears both staging and destination, preserves
the exception argument and calls the bound `_Unwind_Resume` import. The binding
validates the PLT/GOT relocation, not the external unwinder implementation or
exception-table dispatch. Rust 1.99.1 emits no such landing pad in these bodies.
An abort cannot be claimed to execute cleanup.

## Exact streams and negative controls

| Compiler / panic | Instructions per width | Bytes per width | Direct calls | Tail calls |
|---|---:|---:|---:|---:|
| 1.90.0 / abort | 69 | 232 | 5 | 0 |
| 1.90.0 / unwind | 95 | 338 | 9 | 0 |
| 1.99.1 / either | 73 | 250 | 4 | 1 |

The reviewer pins both complete normalized instruction and encoding hashes.
Only validated direct-call/tail-call displacement bytes are normalized. Branch
destinations must be actual instruction boundaries. Every decoded byte is bound
to a unique read/execute file-backed ELF range. The actual kernel body determines
its width; a valid but wrong-width kernel is not accepted. The 63-byte copy helper
and 105-byte volatile helper have their own exact reviewed policies.

Per consumer, changing every instruction individually and every byte individually
(including the matching ELF bytes) rejects 903, 1299 or 969 wrapper mutations for
the three profiles above. The copy helper has eight negative controls and the
volatile helper three; the runner also executes the full kernel mutation review.
Independent synthetic fixtures transcribe the inspected current compiler stream
and test admission, direction, copy length/source, result owner fields, clearing,
tail redirection, symbol populations, helper bytes and unsupported configurations.
Policies have no automatic refresh path.

## Limitations

This extends the [kernel review](aes-accelerated-linked-kernels.md) and complements
the [public-output review](aes-accelerated-linked-public.md). It does not cover
all caller instructions, expansion, dispatch, constructors or lifetime transitions.
Clearing the explicit regions does not prove removal of all register/spill copies,
stack padding, swap or diagnostic records. It establishes neither physical
fault resistance nor power/EM resistance. Native timing and broader target
qualification remain in the [development work list](aes-acceleration-development.md).
