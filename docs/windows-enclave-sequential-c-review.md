# Shared sequential C scaffolding review

The [saved observation](../assurance/windows-protection-observations/sequential-c-20261005.json)
reconciles four complete C functions across all eighteen current sequential
images. The [input catalog](../assurance/windows-protection-observations/sequential-c-inputs-20261005.json)
pins each route, signed image and original C object separately. This is offline
author inspection of saved development images, not another native campaign,
independent qualification or a whole-image cleanup claim.

## Reuse boundary

| Complete shared function | Code bytes | Relocations | Runtime fragments per image |
| --- | ---: | ---: | ---: |
| `PublicLockedAdmit` | 604 | 46 | 5 |
| `PublicLockedFinish` | 111 | 4 | 1 |
| `PublicGuardRestore` | 230 | 18 | 1 |
| `PublicRustBody` | 870 | 63 | 3 |

All eighteen objects contain identical function bytes and complete relocation
identities for these four functions. Each is independently bound to its own
image, with the full contiguous runtime extent and supported unwind chains.
In particular, the first runtime fragment of `PublicRustBody` is only 37 bytes:
binding that entry fragment alone would miss almost all of its dispatch logic.
The existing complete-section binder checks all 870 bytes and 63 references.
The fragment-oriented handler binder remains appropriate for its own selected
funclet scope; its result must not be substituted for a complete-function match.

Each image's four entry addresses agree with the tested `PublicLockedFrame`
wrapper. Shared global/helper references agree within that image, and SDK IAT
references agree with its named `vertdll.dll` imports. The report preserves
each image's resolved `RetainedWork` address. An identical call instruction and
symbol name do **not** establish that the eighteen Rust workers are equivalent.
No worker review is transferred by this record. Nor does an on-disk IAT binding
attest the loaded SDK or validate its implementation.

## Inspected normal-control paths

Admission rejects inactive entry, outstanding changed guards, a window other
than 64 KiB, a misaligned lower address or insufficient lower guard space.
It checks both boundary pages, attempts their `PAGE_NOACCESS` transitions,
records successful changes before subsequent checks, and requires the host
admission acknowledgement. Restore can therefore still attempt to repair a
partially established pair of guards. Page-query, host-callback and OS semantics
remain separate dependencies, not proved by the shared C template.

The body first calls `BaseLockedBody`, then conditionally performs retained-owner
work. Construction allocates three pages, checks separation from the work window,
establishes guard pages and requests the retained-storage acknowledgement before
calling `RetainedWork`. Only worker status one marks construction live. Other
operations require a live retained region, guard checks and acknowledgement
before entering that image's Rust worker. The public result/report handling is
distinct from secret payload processing inside the worker.

Disposal requires operation three and exact worker result four. It marks the
owner no longer live, then reads and ORs **all 4,096 bytes** of the retained middle
page. Nonzero residue records failure 113 and skips freeing; it does not erase
the page itself or turn failure into success. Clean readback requests the
post-disposal acknowledgement; failure 114 also skips freeing. Only the clean,
acknowledged path calls the free helper, whose failure becomes 115. The scan is
after the Rust disposal result, not a read of a concurrently live borrowed owner.
The Rust worker's actual lifecycle, returned status and clearing implementation
still need their own image-specific reconciliation.

On normal return the C body restores its saved nonvolatile registers and returns
the public base-body result to the clearing wrapper. `PublicLockedFinish`
preserves the wrapper's public result only if `CallEnclave` succeeds and the host
returns acknowledgement one; otherwise it returns zero. Guard restoration
attempts both recorded transitions, clears flags only for successful changes,
and requires the expected resulting page protections. Those callbacks execute
below the cleared window, so their storage is not included in its 64-KiB wipe.
The wrapper's pre-callback/final register clearing remains necessary.

These are normal-control observations. They do not establish arbitrary-exception,
fatal-exit or SDK cleanup, nor protection for caller copies or privileged
snapshots. Retained-storage refusal on residue is an error path, not a stronger
claim that the C layer can repair a worker that failed to clear memory.

## Validation and remaining work

Six focused regression tests pass on Linux and Windows. They reject incomplete
function records, changed body bytes/lengths, missing or changed relocations,
different wrapper callees, inconsistent shared symbols, wrong import slots,
catalog drift, and altered instruction/branch landmarks. The complete saved
image inspection produces identical parsed JSON on both hosts: 72 bindings
covering 1,815 distinct shared-template bytes. Synthetic mutation tests are
inspection regressions, not cryptographic or native execution evidence.

The subsequent [shared helper review](windows-enclave-sequential-helpers.md)
reconciles eight called C bodies, including the public-marker routine, across
these same images. Next are the distinct retained Rust caller/storage paths,
keeping SDK, compiler and normal-return scope explicit.
The completed nineteen-image and scoped dump campaigns are retained unchanged;
this review does not change production code, signed images or release gates.
Independent retest and whole-image qualification remain outstanding.

```sh
python3 scripts/cryptography/test-windows-enclave-sequential-c.py
python3 scripts/cryptography/windows_enclave_sequential_c.py SAVED_DIRECTORY
```
