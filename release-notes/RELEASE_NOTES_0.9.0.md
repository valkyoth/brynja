# Brynja 0.9.0 Release Notes

Status: implementation complete; pentest required

Brynja 0.9.0 implements a protocol-neutral caller-owned workspace partition
and monotonic arena allocator. It does not implement integer encoding, TLS
framing, a protocol parser or state machine, cryptography, PKI, secret
destruction, or a production-ready transport and must not be used to secure
network traffic.

## Exact Workspace Partition

`brynja-core 0.6.0` provides `WorkspaceLayoutBuilder`, `WorkspaceLayout`,
`Workspace`, and `Arena` without allocation or external dependencies. The
layout builder requires one explicit byte capacity for each of five domains:
secret, plaintext, transcript, certificate, and output. Repeated assignments,
missing assignments, and aggregate `usize` overflow fail before storage is
borrowed.

`Workspace::new` accepts exactly one caller-owned mutable byte slice. Its
length must equal the checked layout total; both short and oversized storage
are rejected without mutation. Successful construction safe-splits every byte
once in fixed domain order. It never accepts independent buffers, so callers
cannot submit slices whose provenance or overlap Brynja would need to infer.

Non-empty arenas never share a byte. Empty arenas may have equal boundary
addresses, but an empty range contains no byte and therefore does not overlap.
`WorkspaceArenas` exposes simultaneous named mutable arena borrows without a
positional domain-selection footgun. Sealed zero-sized domain markers make the
five handles different Rust types, so secret and output fields cannot be
accidentally swapped and the distinction adds no runtime storage.

## Monotonic Arena Accounting

Each `Arena` admits only complete monotonic allocations. A successful
non-empty allocation returns the next disjoint range and advances its used
bytes, high-water mark, remaining capacity, and successful allocation count
once. An empty allocation succeeds without changing accounting. End-offset
overflow or insufficient capacity changes neither bytes nor telemetry.

Allocated ranges retain their caller-provided contents. Callers must initialize
them before use. This milestone deliberately provides no release, rewind,
reuse, ownership, zeroization, or destruction operation. Secret lifetime and
destruction remain separately gated at v0.10.0 and v0.11.0.

## API And Diagnostic Boundaries

Workspace and arena state is private, `must_use`, non-clonable, and implements
neither `Debug` nor `Display`. `WorkspaceLayout` is copyable policy but is also
non-formattable so configured capacities do not enter accidental diagnostics.
The exclusive backing-slice lifetime prevents safe outside access while the
workspace is live.

`WorkspaceError` carries only duplicate/incomplete arena identities or
value-free length/capacity categories. `ArenaError` carries only
`LengthOverflow` or `InsufficientCapacity`. Neither error contains caller
bytes, configured capacities, offsets, requested lengths, remaining lengths,
allocation counts, arbitrary strings, or provider-native detail.

## Verification

- every one of the five domains is tested for duplicate and omitted layout
  assignment;
- every small combination of the five capacities is constructed and checked
  against its exact partition;
- both backing-length mismatch directions preserve sentinel-filled storage;
- every consumed position and request length around an eight-byte arena is
  checked for exact success or byte- and accounting-transactional failure;
- aggregate and end-offset `usize` overflow, exact exhaustion, one-byte
  overrun, empty workspaces, empty arenas, and zero-length allocations are
  covered explicitly;
- pointer identity, fixed partition order, simultaneous named use, retained
  caller bytes, and byte-for-byte cross-domain isolation are verified;
- compile-fail doctests reject cross-domain handle swaps, workspace formatting,
  and outside backing-buffer mutation while the exclusive borrow remains live;
- workspace lints forbid indexing, explicit panic paths, unchecked arithmetic,
  unsafe code, external dependencies, and source files above 500 lines.

The full release gate additionally covers Rust 1.90.0 through 1.97.1, host and
OS-less targets, `no_std`, modern/legacy isolation, source and requirement
reproducibility, assurance policy, package contents, SBOM, dependency policy,
advisories, documentation, and live standards and tool drift.

## Requirements And Protocol Claims

The workspace model is a source-free shared foundation. No protocol surface or
normative protocol requirement advances to implemented, tested, or evidenced.
Encoding, canonical framing, protocol parsing, mutable arena reclamation,
secret destruction, record protection, and protocol state remain owned by
later milestones.

Project tests, CI, pentesting, fuzzing, Miri, sanitizers, or future Kani
harnesses are not independent cryptographic or protocol verification. Brynja
has no FIPS 140-3 validation, certificate, approved module, or validated
operational-environment claim.

## Publication Set

The candidate selects `brynja-core 0.6.0`, eight dependency-only modern
support patches at `0.1.5`, and the mandatory `brynja 0.9.0` facade.
`brynja-crypto` remains unchanged at `0.1.0`; legacy and repository-only
packages remain unpublished. The guarded publisher enforces exact pins,
dependency order, and the facade-last rule.

Publication remains blocked until the repository owner completes pentesting,
the permanent `PASS`/`PASS` report and any remediation are committed, GitHub is
green, and the user explicitly authorizes the signed release tag.

## Limitations

This milestone classifies and monotonically reserves caller-owned bytes. It
does not initialize, interpret, encode, authenticate, encrypt, release, reuse,
own, or erase them. High-water currently equals used bytes because reclamation
is intentionally absent; keeping both counters makes the stable accounting
contract explicit for later bounded callers without pretending reuse exists.
