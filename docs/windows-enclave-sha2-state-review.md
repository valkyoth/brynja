# Saved scalar SHA-2 state construction and consumption

The [saved report](../assurance/windows-protection-observations/sha2-state-20261005.json)
continues the [owner operation review](windows-enclave-sha2-stream-operations.md)
in the same scalar streaming image. It binds the complete `State::new` and
`State::finish` bodies, nine dispatch tables, five external constant regions
and their actual caller/callee connections. These are offline author-review
results, not independent retest or complete cryptographic/runtime qualification.

Subsequent work: the [primitive review](windows-enclave-sha2-primitives.md) adds
the called update/finalize/compression/output/copy/mask helpers. The open-callee
statements below describe the scope of this state-only checkpoint, not a claim
that those later helper reviews have not happened.

| Body | RVA | Bytes | Fixed frame, including pushes |
| --- | ---: | ---: | ---: |
| `State::new` | 10,736 | 3,100 | 1,304 |
| `State::finish` | 14,624 | 2,738 | 1,384 |

Full body and relocation hashes are checked against the saved Rust object and
linked PE extents. Begin and rehash must call this constructor; owner finish
and rehash must call this state finalizer. The previously reviewed workspace
wipe and volatile clearer resolve to the same bodies at RVAs 6,208 and 5,920.
Other callee addresses are reconciled but their implementations remain listed
as unqualified by this step.

## Construction and public derivation

The constructor dispatches on seven private algorithm tags. Named variants
place their active workspace at destination+1; general SHA-512/t uses
destination+4 and stores its public t parameter at destination+2. The emitted
named paths zero a 1,024-byte temporary workspace prefix using 896 bytes of
`memset` and eight explicit 16-byte stores, copy that prefix, write the initial
state and remaining zero regions, and commit the variant tag. The general path
does the corresponding placement after its public IV derivation.

The general-t path builds the public `SHA-512/t` label, expands a fixed-block
schedule and runs the inlined IV-derivation computation. Its only inputs are
the admitted algorithm/tag/t values, not a message or retained secret output.
The complete code and the 640-byte round table are bound. Four 16-byte named
IV regions are separately bound, including agreement between symbol values
and stored bytes. Read-only mapping and relocation-free constant storage are
required. This inspection is about emitted construction and storage lifetimes;
it does not replace the existing cryptographic vector/oracle campaigns.

The constructor saves and restores XMM6 at stack offset 1,216. The saved value
may originate in its caller, so calling the constructor's computation public
does **not** make that spill harmless by assumption. The full save region is
inside the enclosing cleared window. There is no new claim of individually
zeroing the save slot or immediately erasing all restored registers here.

## Compiler preconditions

The saved IR marks the constructor's internal tag as `0..7` and its t argument
as `0..512`, with exclusive upper bounds. The preceding owner decoder provides
the stricter general-t admission: nonzero and not 384. Dispatch therefore relies
on valid private variants, not a new local check against corrupted tags.

The finalizer's output-length argument has the emitted range `0..65`. The
reviewed owner callers bound it to at most 64 bytes, allowing the compiler to
remove the source-level `staging.get_mut(..output.len())` rejection. The saved
IR identity and these exact internal preconditions are regression checked.
An arbitrary direct call to the internal address with a larger length is not
covered by this review. The existing bitstring/sequence ingress requirements
also remain part of the complete caller chain.

## Consuming state and output staging

Finalization zero-initializes 64 staging bytes at stack offset 80. Named paths
copy the 1,170-byte active workspace to offset 148. General-t copies t plus its
workspace (1,172 bytes) to offset 148, putting the active workspace at offset
150. These are distinct copies from the consumed state in the caller's frame.

Named paths check conversion of accumulated byte counts to bit counts and
addition of the final bitstring: narrow variants test shifted-out bits and
carry, while wide variants check the high word and carry of the 128-bit sum.
Fractional final input separates the last byte from the complete-byte prefix.
The selected update/finalize callees receive the copied workspace, bit length,
tail and output width. Widths passed to `write_secret` are 28, 32, 48, 64, 28
and 32 for the six named identities. This step records the caller behavior;
padding/compression and helper semantics inside those callees remain open.

Every named early-error path wipes the copied workspace. Following
`write_secret`, the copied workspace is also wiped before inspecting that
result. Successful result ownership is then used for the checked copy into the
retained destination; the result's exposed staging region and the full 64-byte
scratch are cleared whether the copy succeeds or fails. Rejection paths clear
the full scratch before cleanup dispatch and return the bits error. The owner
caller remains responsible for clearing its retained output on rejection.

The seven cleanup tables each skip exactly the variant already consumed on
that path. Their other destinations either wipe a named source workspace,
wipe the general-t workspace, or return the failure. Every table relocation
and linked destination is checked. Skipping the consumed variant is not proof
that its original by-value bytes disappeared: its old storage can retain a
copy until the outer stack-window clear. Only the active copied workspace is
individually wiped on these paths.

## General-t final output

The general path checks the requested width against `ceil(t/8)`, enforces the
accumulated-length limit and feeds the same wide finalizer. It masks the final
output byte before copying into staging, with the selected byte bounded to
the 64-byte output region. It checks staging length, wipes the copied active
workspace, performs the checked retained-output copy, and clears both the
exposed staging region and all 64 scratch bytes. Failures clear staging, wipe
the copied workspace and pass through the appropriate cleanup table.

A focused arithmetic cross-check covers all 510 admitted t values, including
width rounding, last-byte location and mask. It is an interpretation check,
not execution of the machine code or a substitute for the general-t oracle.
The actual mask, copy, render and finalization helpers still need their own
saved-image review.

## Stack extent and validation

The constructor reaches H-3,920 under begin and H-4,064 under rehash. State
finalization reaches H-5,232 under owner finish and H-4,144 under rehash. The
selected temporary, result, staging and XMM-save spans are inside the admitted
window at three tested address bases. Tag/padding bytes, consumed source copies,
caller registers and save slots still rely on the enclosing cleanup boundary.
Unknown callee entry/home space is recorded without inventing maximum depth.
No arbitrary-exception, fatal-termination or privileged-snapshot guarantee is
added.

Nine focused tests pass on Linux and Windows with identical parsed reports.
All 5,838 actual state-body byte mutations and 252 actual table-byte mutations
are rejected per host. Separate regressions cover instruction landmarks without
body-hash checks, complete references, constant identity, table mapping and
consumed-variant choices, exact compiler preconditions, callee/frame mismatches,
XMM-save placement and general-t arithmetic. The related operation, lifecycle,
entry and frame tests pass locally. Production code, signed images, native
campaign counts and release-gate policy remain unchanged.
