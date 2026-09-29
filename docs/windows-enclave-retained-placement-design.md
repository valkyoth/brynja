# Retained result placement boundary

Status: isolated component, **not native enclave integration or Windows strict
qualification**. Production code, API availability and release gates are unchanged.

[`retained_placement.rs`](../assurance/windows-enclave-probe/retained_placement.rs)
places the [retained SHA-256 owner](windows-enclave-retained-digest-design.md) in
an exclusively borrowed external page. The result occupies bytes 0–31; owner
metadata starts at offset 256. Exact page length/alignment is checked before any
write; compile-time bounds reject overlapping, unaligned or oversized owner
layouts. A zero identity rejects after clearing the page.

The handle contains pointers and a lifetime-bound exclusive page borrow. Moving
that handle does not move the in-page owner or result. Safe callers cannot borrow
the page again, construct another live owner there, escape its lifetime or copy,
clone, send or share the handle. The page is represented as `MaybeUninit<u8>`:
construction initializes bytes without reading arbitrary prior contents.

Destruction first drops the initialized owner, ending its internal result borrow
and clearing the result. Only afterward does a volatile byte loop erase the full
page, including metadata and padding. Tests inspect the result between those two
steps and use an unused-region canary to distinguish owner cleanup from full-page
cleanup. They do not interpret Rust object padding in deliberately broken mutants.

This does not authenticate a page or establish residency. The native adapter still
must establish enclave membership, guards and locks before construction, serialize
entry, retain the allocation across returns, and destroy the handle before unlock
or release. A forgotten handle or fatal abort does not run this destructor. No
raw-pointer constructor, allocator, OS teardown receipt or application callback
API is added to a shipping crate. The closure remains a trusted test seam.

## Focused verification

```text
python3 scripts/cryptography/test-windows-enclave-retained-placement.py
python3 scripts/cryptography/test-windows-enclave-retained-digest.py
python3 scripts/cryptography/windows_enclave_placement_build.py <windows-build-directory>
python3 scripts/cryptography/windows_enclave_placement_build.py <miri-build-directory> --miri
```

- Four Rust tests pass at O0/O2: retained SHA-256 across worker return and handle
  movement; cancellation/replay/reuse; ready-result abandonment; failed copy and
  recoverable unwind; invalid page geometry and identity.
- Five compiled regressions are rejected at both levels: omitted owner drop,
  omitted page erase, overlapping regions, out-of-page owner and misalignment.
- A positive downstream consumer compiles; eleven negative consumers reject
  trait, aliasing, lifetime, private-pointer access and double-use violations.
- All four tests pass under Miri nightly-2026-09-11 with strict provenance and
  its default Stacked Borrows checking. This is interpreted component execution,
  not OS residency, native machine-code or enclave evidence.
- Miri originally rejected a pointer derived from `&mut page[0]`: its borrow
  authority covered one byte, not the entire page. The corrected implementation
  derives from the full mutable slice. A dedicated negative Miri test reconstructs
  the original bug and requires the specific invalid-write/provenance diagnostic.
- Rust 1.98.1 cross-compiles the component for Windows x86-64 MSVC with warnings
  denied, O2 and panic=abort. The build record binds source/compiler/commands and
  archives; the Miri record preserves output logs. Neither is a native capture.

The placement consumer also exposed transitive rlib discovery and test panic-mode
issues in the research builder. Its retained-digest archive names now include the
actual crate name, and unwind testing builds compatible dependencies. The prior
retained-digest tests were rerun successfully; historical artifact records remain
unchanged and bound to their original source.

## Next step

Wire this component into the [native retained allocation](windows-enclave-persistent-slot-results.md)
and guarded worker, replacing the public-marker-only body with fixed public-vector
SHA-256 operations. Keep the separate images and test native destruction before
unlock/free, cross-return export, cancellation, stale tokens and failure paths.
An affine host handle owning the enclave instance, arbitrary borrowed-input
protocol, composition and broader algorithm coverage remain separate work in the
[release checklist](windows-v02450-remaining.md).
