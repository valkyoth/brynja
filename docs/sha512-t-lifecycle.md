# General SHA-512/t secret lifecycle closure

v0.24.27 freezes the existing mandatory, portable hardened ownership model.
It does not add a second hash engine, change digest results, admit acceleration,
or complete the family ahead of v0.24.28 package and v0.24.29 final acceptance.
The public API remains available through the default-off `general-sha512-t`
feature in `brynja-hash-sha2`; no new dependency is required.

## Live state versus terminal ownership

| Operation | State on rejection/success | Output ownership |
| --- | --- | --- |
| `update`, length preflight | Overflow rejects before mutation; prior state remains usable | None |
| Four consuming finalizers | State destroyed on success and error | Public digest only with explicit declassification, or affine secret owner |
| Four hardened one-shot functions | Local state destroyed on success, error, recoverable unwind | Same classification as finalizers |
| Wrong secret destination width | Clear the entire supplied destination; a consumed state is destroyed | No partially initialized secret escapes |
| `cancel` / ordinary Drop | Destroy the owned state | None |
| Secret owner Drop / unwind | Clear the entire borrowed destination | Borrow ends; caller regains cleared storage |
| Secret `declassify` | Clear original destination after making a deliberate public copy | Returned public copies no longer zeroize |

Borrowed validation errors are deliberately **not** destructive. Erasing a live
state on preflight failure would violate its transactional API. Conversely,
consuming finalization cannot be retried, even after rejection. Invalid secret
destination admission precedes hashing and length-finalization checks, so size
errors take precedence and still clear the whole supplied region. Empty storage
is already clear. Original input bytes and copies made by callers are never ours
to erase. Canonical-bit descriptors borrow input; they do not own it.

## Private storage inventory

All durable secret storage uses the same `HardenedSha2Owner` as named SHA-2:

| Region | Bytes | Use and clearing |
| --- | ---: | --- |
| `chaining_state` | 64 | Hash state; terminal wipe |
| `partial_input` | 128 | Buffered message; completed-block/finalization and terminal wipe |
| `message_length` | 16 | Public length metadata; terminal wipe |
| `phase` | 2 | Public state/buffer metadata; terminal wipe |
| `message_schedule` | 640 | Expanded 80-word schedule; compression scratch and terminal wipe |
| `block_copy` | 128 | Input/padding compression copy; scratch and terminal wipe |
| `padding_block` | 128 | Final padding; terminal wipe |
| `output_staging` | 64 | Intermediate digest; terminal wipe |

The additional t descriptor and derived IV/ASCII label are public metadata,
independent of input. Typed secret destinations are exact-width (1–64 bytes),
managed by `SecretRegionInitialization` then `OwnedSecretRegion`. They cannot
be cloned, formatted or implicitly imported into a public digest. All private
arrays clear through `brynja-core::clear_owned_region`; the optional sanitization
adapter is not responsible for this mandatory path.

Arithmetic words, byte extraction expressions, partial-tail values, references
and compiler-generated temporaries are not separate securely erasable owners.
The inventory of owned regions is not a claim that every transient value in the
Rust source, compiler IR, registers or stack has been erased. No register, spill,
cache, swap, dump, DMA, physical-memory or caller-copy erasure is guaranteed.
No destructor can run after `mem::forget`, abort, double-panic termination, forced
termination or power loss. State is movable, not pinned or memory-locked.

## Runnable evidence

Run `python3 scripts/sha2/check-general-sha512-t.py` for all-parameter digest
and lifecycle acceptance, endpoint MIR/LLVM/assembly checks and the isolated
destructor probe. Run `python3 scripts/sha2/test-general-sha512-t.py` for compiled
negative controls, ownership compile failures and source-policy regressions.

The lifecycle suite tests all 510 t values against every destination width
0–65, all four secret routes, borrowed-input preservation, red zones outside the
destination, cancellation, overflow precedence and unwind. Internal overflow
tests compare every one of the 1170 owned bytes before/after rejection, without
constructing an impossibly large input buffer. These are synthetic boundary
tests, not digest vectors for an actual maximum-size message.

The destructor probe compiles a temporary source copy with test-only observation
inside the actual owner Drop. It checks all eight cleared regions while they
are still live, records exactly one Drop per consumed state, and exercises
cancel, finalization, errors, all four one-shot routes and recoverable unwind.
A poisoned-storage case ensures already-zero arrays cannot hide missing wipes.
Debug/release mutants remove each region's clear or bypass consuming cleanup;
only executed assertion failures count, never compilation failures. The observer
does not ship in any package, add unsafe code, read freed memory or prove erasure
of compiler-created copies. Source-bound compiler checks remain separate.

Scoped Miri and AddressSanitizer execute the new public lifecycle cases. The
existing compiler owner checks bind real cleanup to source; passing runtime
tests alone would not prove that an optimizer retains clearing. No new complete
Kani proof, independent cryptographic review or FIPS validation is claimed.
