# Accelerated AES: bounded x86 per-operation secret-output review

This v0.27.3 development review covers the complete final-linked
`Aes128Key::secret`, `Aes192Key::secret` and `Aes256Key::secret` bodies under
static x86 AES-NI admission. Both encryption and decryption share these bodies.
The [cached secret review](aes-accelerated-linked-secret.md) is replayed in each
binary, including its copy and volatile-clear helpers. This is not approval of
constructors, per-operation public-output callers, destruction entry points,
ARM callers, or whole-consumer constant-time behavior.

```sh
brynja-verify run aes --needed --category aes-linked-ephemeral
```

The runner executes four package-external consumers per compiler (direct/facade,
abort/unwind) with opt3, fat LTO, one codegen unit and overflow checks. Archives
are byte-checked and built offline. Tool identities, binary hashes, complete
disassembly, symbols, relocations, logs and review JSON remain under
`target/aes-accelerated-linked/`. Capture-only runs cannot produce a pass.

## Inspected operation flow

1. Clear the admitted 16-byte destination. Reject unhealthy, stale-generation
   or wrong-kernel authority before expansion; an admission failure leaves the
   destination cleared.
2. Initialize the whole temporary schedule, 176/208/240 bytes, with zero stores.
   Validate the owned raw-key pointer and exact 16/24/32-byte length before
   calling the matching hardware expansion helper. A missing owner region or
   wrong length fails before reading the key, clears the schedule and
   destination, and quarantines the authority.
3. Recheck authority health, saved generation and selected kernel after
   expansion. Failure clears the schedule and destination and quarantines.
   Stage the input block and select the matching session encrypt/decrypt method
   using the public direction. The session repeats the authority checks before
   calling the hardware round kernel. Session failure clears staging,
   destination and schedule and quarantines; there is no portable fallback.
4. After session success, copy exactly 16 bytes with the reviewed core
   helper. Clear both staging and the complete temporary schedule. Return the
   destination pointer, length 16 and successful secret-owner discriminant.
   Successful output remains live under the returned owner's responsibility.

For abort and 1.99.1 unwind, staging starts at stack offset 0 and the schedule
at offset 16, with 200/232/264-byte frames. For 1.90.0 unwind, staging starts at
offset 16; the schedule starts at offset 32 for AES-128/192 (216/248-byte frames)
and offset 48 for AES-256 (296-byte frame). Public generation and cleanup flags
occupy separate slots. Width variants change schedule initialization stores,
frame size, key length, cleanup length, register allocation and corresponding
local branch offsets. Every variant has its own complete text and encoding
digest; those differences are not wildcarded. Branch conditions use public
authority metadata, direction or length/status results, not key bytes.

Rust 1.90.0's emitted unwind pads clear admitted staging, destination and
schedule, quarantine, preserve the exception argument and call the validated
resume import. The cleanup flags distinguish failures before staging is live;
the full post-return landing-pad extent is included. The PLT/GOT binding is
checked, not the unwinder implementation or the
exception-table dispatch. Rust 1.99.1 emits no such pad in these bodies; its
abort and unwind layouts differ and are pinned separately. No abort cleanup is
claimed.

## Hardware expansion and session dependencies

The three [hardware expansion bodies](aes-accelerated-linked-expansion.md) are
checked against exact instruction/encoding templates and executable bytes.
Their actual key and schedule extents identify the width, independently of the
symbol hash. Each wrapper is bound to the corresponding reviewed expansion;
there is no portable scalar-inverse dependency on this path.

The six `Session::encrypt/decrypt{128,192,256}` bodies are separately selected
with strict legacy/v0 symbol grammars and non-overlapping extents. Each has a
complete text/encoding policy and is bound to its matching-width round kernel.
They read authority health at offset 8, compare the generation at offset 0 to
the saved generation, and require the x86 kernel selector at offset 9. Public
error returns cover unavailable, quarantined, stale and wrong-kernel admission.
Only the successful path remaps block/schedule pointers to the kernel arguments
and passes direction 0 for encryption or 1 for decryption. The compiler-specific
success discriminants (6 on 1.90.0, 255 on 1.99.1) are pinned, not generalized.
These bodies do not themselves read key or block bytes; their callees do.

The 1.90.0 unwind session body also has an emitted landing pad that quarantines
health/generation unless already quarantined, preserves the exception pointer
and calls the bound resume import. No equivalent pad is emitted by 1.99.1 here.
As for the wrappers, this is not exception-table dispatch proof. Startup and
hosted admission remain separate review boundaries.

## Controls and execution coverage

| Compiler / panic | Instructions (128/192/256) | Bytes (128/192/256) | Wrapper mutations rejected |
|---|---|---|---:|
| 1.90.0 / abort | 137 / 139 / 141 | 494 / 510 / 526 | 1947 |
| 1.90.0 / unwind | 172 / 174 / 174 | 671 / 687 / 693 | 2571 |
| 1.99.1 / abort | 136 / 138 / 140 | 528 / 544 / 560 | 2046 |
| 1.99.1 / unwind | 132 / 134 / 136 | 496 / 512 / 528 | 1938 |

Each wrapper instruction is changed individually, as is each byte with its
matching executable byte. Every case must be rejected. The six session bodies
reject 489 such mutations per binary, or 813 for 1.90.0 unwind. Encryption and
decryption respectively contain 24 instructions / 56 and 59 bytes, except
1.90.0 unwind's 36 instructions / 98 and 101 bytes. Each binary also rejects
570 hardware-expansion mutations, the cached-secret controls, and the runner's
kernel controls. Unit tests use deliberately synthetic streams and
explicit test-only policies to exercise validation; those streams are rejected
by every production policy. Fresh real builds exercise the production policies.
No runtime policy-refresh mechanism exists.

The shared executable checks six positive operations per width against known
answers, output/key clearing and rejection after quarantine. It now also checks
per-operation decryption rejection and constructor rejection for both key-owner
forms, with prefilled storage required to become zero. The authority reference
is retained before quarantine so these tests actually reach the constructors,
not just the fixture's healthy-authority lookup. These constructor observations
are behavioral checks, not a machine-code review of the inlined constructors.

Clearing explicit owned regions does not establish erasure of all compiler
copies, registers, spills or stack padding. Physical faults, power/EM behavior,
native timing, broader platforms and the remaining caller boundaries stay in
the [development work list](aes-acceleration-development.md). Local observations
are not signed certification evidence.
