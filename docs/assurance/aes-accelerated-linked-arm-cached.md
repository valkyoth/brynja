# Accelerated AES: bounded AArch64 cached caller review

This review covers three cached public-encryption bodies and three shared
cached secret encrypt/decrypt bodies in package-external final-linked consumers.
It does not cover per-operation-key callers, arbitrary downstream inlining,
every fixture call site, native hardware qualification, exception-table
dispatch, unwinder internals, timing, physical faults or register/spill erasure.
Production AES, dependencies and the runtime fixture are unchanged by this step.

```sh
brynja-verify run aes --needed --category aes-linked-arm-cached
```

Four registrations cover Rust 1.90.0/1.99.1 and static/hosted admission.
Each builds direct/facade, abort/unwind consumers with release fat LTO on
`aarch64-unknown-linux-musl` and executes them under QEMU. These are emulated
observations, not a substitute for Apple/AWS native qualification.

## Reviewed data flow

Public encryption checks authority health, the owner's captured generation,
the admitted instruction bundle and, for hosted admission, the runtime bundle.
The schedule pointer must be present and its length exactly 176, 208 or 240
bytes. Invalid schedule state quarantines the authority. Ordinary admission
errors return without writing the public destination. Success copies the input
to a 16-byte stack temporary, calls the matching-width ARM kernel with the
encrypt selector, publishes the transformed block, and clears that temporary.
The ciphertext is intentionally public; the vector register used for its final
copy is not claimed erased.

Secret operations first clear the entire 16-byte destination, then perform the
same health/generation/bundle/schedule admission checks. They retain the input,
destination and direction selector across that clear. Success stages input,
calls the matching kernel, copies exactly sixteen bytes using the reviewed
transfer helper, clears staging storage and returns a guarded secret owner
bound to the destination and its extent. Error paths clear the destination
again before returning. In the ordinary bodies that final clear is a bound
external tail branch, not an unexamined jump. Invalid schedule state also
quarantines the authority.

The Rust 1.90.0 unwind secret bodies branch on the direction bit and call the
same width's kernel with literal encrypt/decrypt selectors on the respective
paths. Other reviewed bodies pass the retained selector directly. The existing
fixture exercises both directions for all widths, clears returned secret
blocks, and checks that quarantine clears secret destinations but leaves public
destinations unchanged. This does not prove every fixture call site's encoding.

## Compiler and unwind differences

| Compiler/admission/panic | Public body instructions | Secret body instructions |
| --- | ---: | ---: |
| 1.90.0 static abort | 52 | 76 |
| 1.90.0 static unwind | 91 | 106 |
| 1.90.0 hosted abort | 57 | 81 |
| 1.90.0 hosted unwind | 99 | 111 |
| 1.99.1 static, both | 51 | 76 |
| 1.99.1 hosted, both | 55 | 80 |

Within each row the only width-dependent instruction is the exact schedule
length comparison. All three whole-body hashes remain separately pinned.
Compiler-specific error representations, restoration order, branches and
boolean tests are retained, not normalized away. The 1.99.1 abort/unwind
streams match; both profiles must still be built and executed.

The 1.90.0 unwind bodies retain explicit exceptional paths that quarantine the
authority, clear staging storage (and the secret destination), preserve the
exception pointer and call `_Unwind_Resume`. The checker binds that call to a
unique global symbol, its executable mapping and exact 184 linked bytes,
separately pinned for the static/hosted layouts. This identifies a trusted
runtime boundary; it does not qualify libunwind or prove that exception tables
select the inspected cleanup path. A changed runtime/layout fails closed and
requires explicit re-review. No unwind boundary is silently substituted for a
missing caller or dependency. The runtime binding is now shared with the
constructor reviewer; its layout-specific hashes were rechecked after integrated
hardware expansion changed the final link layout. Cached caller policies
themselves are unchanged and must still replay exactly.

## Policy and regression controls

The policies in `scripts/aes/accelerated-arm-cached-review.json` were pinned
after inspection of complete bodies and compiler/profile/width differences.
There is no automatic policy-refresh mode. Disassembly bytes must match the
actual executable image. Only external relocations bound to exact reviewed
targets are normalized; local offsets, predicates, registers, sizes and all
other instruction bytes remain fixed. Selectors require all six exact symbols,
non-overlapping extents and all three matched-width kernels. Only the clear
helper is permitted as an external tail target.

Every run replays the [constructor review](aes-accelerated-linked-arm-constructors.md),
including complete hardware expansion bodies, post-expansion admission and
constructor unwind cleanup, copy, clearing, destruction and round kernels.
A failed dependency prevents any caller pass. The old portable expansion/inverse
closure is not accepted as evidence for integrated hardware expansion.

Every caller instruction is independently replaced, and every caller byte is
independently changed in both the supplied body and ELF. Rejection counts per
consumer are respectively 1920, 2955, 2070, 3150, 1905 and 2025 for the table
rows above. Each retained unwind runtime boundary also rejects 184 independent
byte mutations. Unit tests cover missing/duplicate/overlapping symbols, unknown
configurations, malformed runtime identity and mapping, changed call targets,
missing dependencies, duplicate kernel widths, exclusive runner modes and
registry input/marker binding. Synthetic fixtures cannot match production
caller policies.

See [development status](aes-acceleration-development.md) for recorded runs and
the unfinished per-operation caller and native qualification work.
