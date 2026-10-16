# Apple Silicon resident/clearing profile

Status: implementation in progress; independent review and release qualification
pending. This is **not** the strict profile and **does not guarantee core-dump
exclusion**. Applications that require that guarantee must not use it as fallback
after strict construction fails.

The owner approved this distinct scope on 2026-10-16 after a bounded feasibility
assessment. Two synthetic kernel-crash probes produced no dump; an administrator
live-dump probe exceeded its 256 MiB safety bound. These results are inconclusive,
not evidence of dump exclusion or proof that exclusion is impossible. No system
security settings were changed. Further dump-isolation research is not part of
this milestone.

## Contract

The default-off `macos-resident` feature of `brynja-crypto-cpu-std` exposes
`macos_resident`, a separate API/type family. It is not re-exported by
`brynja-strict`. Existing strict constructors continue to reject macOS.
Only native little-endian 64-bit Apple Silicon macOS is admitted; Intel Macs,
other Apple OSes and interpreter/model builds reject construction.

| Property | Resident profile |
| --- | --- |
| Guarded output and worker mappings | Acquired before accepting input |
| Resident pages | `mlock` required; failure rejects, no ordinary allocation fallback |
| Fork inheritance | `VM_INHERIT_NONE` required; application must still prohibit fork while resources are live |
| Worker lifetime | Private callback, caller-supplied stack, synchronous native join |
| Owned-memory cleanup | Whole payload including page padding; stack after join, output on loan drop/reuse/error, mappings before release |
| Core-dump exclusion | **Not guaranteed**; locked memory may be dumped |
| Hardware/SIMD | Scalar sessions unchanged; explicit Arm SHA2/SHA512/Keccak via separate opt-in feature; SIMD batching pending |
| Independent verification/certification | Not claimed |

No process-wide dump policy is changed. Applications retain responsibility for
their crash-reporting and deployment policy. Inputs and caller-created copies
remain outside owned resident storage. OS/TLS allocations, panic hooks, fatal
aborts, arbitrary register capture, hibernation, snapshots and privileged
inspection remain outside the profile. Instrumented builds are diagnostic only:
interposed locking or relocated stacks cannot establish residency. The host must
not revoke locks/protections or cancel native threads. Insufficient stack capacity
may terminate the process; limits bound resources, not arbitrary call depth.

`mlock` is a residency operation, not a dump-exclusion mechanism. Its resource
limits and release-on-unmap behavior are described in the
[Apple manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/mlock.2.html).
Darwin pthread and Mach ABIs are taken from the installed Apple SDK; Linux ABI
definitions are not reused merely because their sizes look similar.

## Scalar APIs

Add the feature without copying a stale crate version into your manifest:

```sh
cargo add brynja-crypto-cpu-std --no-default-features --features macos-resident
```

```rust,no_run
use brynja_crypto_cpu_std::macos_resident::{Error, Limits, Sha256Session};

fn example() -> Result<(), Error> {
    let mut session = Sha256Session::new(Limits {
        stack_bytes: 262144,
        max_stack_mapping_bytes: 1048576,
        max_output_mapping_bytes: 65536,
        max_message_bytes: 8192,
        max_chunks: 16,
    })?;
    let digest = session.hash_chunks(&[b"a", b"bc"])?;
    assert_eq!(digest.expose().len(), 32);
    // Explicit exposure is not declassification. Copies become caller-owned.
    drop(digest);
    Ok(())
}
```

The session and its digest loans are neither Send, Sync, Copy, Clone nor Debug.
A live output loan prevents reuse. Forgetting a loan does not forget its session's
output owner; the next operation clears it before checking the request. Worker
join failure aborts rather than returning while borrowed inputs could be live.
Recoverable worker panic clears stack and output before returning an error.

The `sha2::Session` API adds SHA-224/256/384/512, named SHA-512/224 and /256, and
all valid general SHA-512/t parameters. Input tails are canonical MSB-first bits.
The `sha3::Session` API adds SHA3-224/256/384/512, SHAKE128/256 and cSHAKE128/256;
message/N/S tails and partial XOF output use the FIPS 202 LSB-first convention.
Both hold one fixed public algorithm identity and create fresh state per call.
They are distinct from persistent streaming sessions: callers submit borrowed
chunk lists, not an updateable secret state. All populated state and staging are
created inside the resident worker. Only borrowed addresses/public metadata cross
the worker boundary; no digest is returned by value from the worker.

See the compiled [SHA-2 example](../crates/brynja-crypto-cpu-std/src/macos_resident/sha2/mod.rs)
and [SHA-3 example](../crates/brynja-crypto-cpu-std/src/macos_resident/sha3/mod.rs).
`hash_chunks` supports raw bit tails and cooperative cancellation;
`sha3::Session::hash_customized_chunks` additionally accepts raw N/S bits.
Public-length budgets are checked before launch; secret byte canonicality is
checked only on the worker. Cancellation is checked at most every 4096 message
or output bytes, before/after bounded cSHAKE prefix construction, and before
returning output. Prefix construction is not internally interruptible. A request
arriving after the final check can still complete; cancellation is not forced
thread termination. Cancellation and ordinary input rejection allow reuse.
Recoverable panic joins and clears before returning; fatal abort cannot do so.

Output remains a clearing, affine borrowed `Digest`. Explicit `declassify`
requires the existing public-output acknowledgement; an incorrect destination
length preserves the destination and clears the secret loan. Zero-length XOF
output reserves a resident placeholder byte, never exposed as output.

## Explicit Arm acceleration

Enable `macos-resident-acceleration` in addition to deploying on a compatible
Apple Silicon CPU. `sha2::CompiledSession` accepts `Kernel::ArmSha256` for
SHA-224/256 and `Kernel::ArmSha512` for all wide/general-t SHA-2 identities.
`sha3::CompiledSession` accepts only `Kernel::ArmKeccak`. x86 routes and wrong
algorithm/kernel pairs reject; no accelerated request silently becomes scalar.
The general SHA-512/t IV derivation remains portable by design, and the request
report checks that exact distinction.

Build-wide `-C target-feature=+neon,+sha2,+sha3` enables all three routes. A Cargo
feature alone does not enable CPU instructions. The application must establish
compatible CPU/OS support for the entire deployment lifetime, before construction;
static admission is not runtime detection, a scheduler lock or a migration
monitor. Use the scalar `Session` instead when that cannot be established.

Authority, startup KAT, scoped hash state and output staging are created inside
the preacquired resident worker. Backend/invariant failure or recoverable worker
panic irreversibly quarantines the wrapper; cancellation and invalid input allow
reuse. The worker joins and both owned resources clear before errors return.
These properties do not add dump exclusion or fatal-abort cleanup.

Development checks cover native Arm execution, independent extracted-package
oracles, fault injection, compiled mutations and ownership rejection. The focused
Darwin compiler checker covers retained resource/start/join/clear calls, worker
state placement and the exact three hardware-kernel register erase tails. Its
call-order checks are not a complete LLVM control-flow or whole-image erasure
proof; native lifecycle tests provide complementary conditional-path checks.
It must run on artifacts emitted separately with panic=unwind and panic=abort.
Independent review and final native release qualification remain pending.

## KMAC and TupleHash

The separate default-off `macos-resident-kmac` and `macos-resident-tuplehash`
features add resident scalar `kmac::Session` and `tuplehash::Session` APIs.
Their respective `-acceleration` features add explicit `CompiledSession`
wrappers accepting only `Kernel::ArmKeccak`, with the same build-wide and
deployment prerequisites above. These features do not activate strict Mac
admission, and `macos-resident` alone does not activate either keyed family.

KMAC128/256 and KMACXOF128/256 accept borrowed canonical LSB-first key,
customization and message bits. Keys must meet the selected strength even if
conformance features are unified elsewhere. Fixed tags and verification require
full-strength output; XOF derivation may have empty output. Verification compares
the complete canonical equal-width candidate on the resident worker, clears the
computed tag and comparison accumulator, and releases only the authentication
decision. It does not retain a key between calls. Key/prefix setup is bounded by
explicit limits, not internally cancellable.

TupleHash128/256 and TupleHashXOF128/256 preserve item identity: fragments within
one `Item` are one element, not multiple elements; empty elements still count.
Item lengths are checked and derived rather than trusted from the caller. Writers
and partial-bit suffix handling remain inside the worker; incomplete or failed
writers cannot produce output. Fixed and XOF domains remain distinct.

Both families acquire separate stack, staging and output mappings before input
processing. State, compiled authority and KMAC comparison storage live inside
the worker; original input/candidate buffers and explicit output copies remain
caller-owned. Output loans clear on drop/reuse; failure paths clear staging and
output, and join precedes full stack clearing. These are resident/clearing APIs,
not dump-excluded owners. See the compiled [KMAC examples](../crates/brynja-crypto-cpu-std/src/macos_resident/kmac/mod.rs)
and [TupleHash examples](../crates/brynja-crypto-cpu-std/src/macos_resident/tuplehash/mod.rs).

Focused native checks cover scalar and required Arm routes, partial keys/items,
framing, multi-fragment output, candidate mismatch positions, cancellation,
quarantine, unwinding and actual owned-mapping placement. The packaged oracle
checks 512 independently composed cases on each route in debug/unwind,
release/unwind and release/abort. Compiler review includes keyed coordinators,
worker state, comparison and owner cleanup; it remains a bounded call/placement
review, not whole-image erasure proof. Independent review is pending.

## Finite implementation sequence

The legacy hosted crates separately expose `macos-resident::Session` via their
default-off `macos-resident` feature. Scalar SHA-1/MD5 accept canonical MSB-first
bit tails and borrowed chunk lists. `macos-resident-acceleration` adds SHA-1
`CompiledSession` requiring Arm SHA1/NEON, and MD5 `batch::Session` requiring
NEON work across eligible lanes. These are compatibility-only algorithms with
broken collision resistance, not authentication mechanisms. No legacy export
is added to the modern or strict facade.

Each legacy crate keeps its Darwin adapter private: no general-purpose worker
callback is exported, and activating resident features does not pull in the
modern hosted dependency. The private adapters match the reviewed shared
Darwin implementation byte-for-byte (apart from the private error import), with
source-hash and copy-parity regressions. They share the residency, cleanup and
NO dump-exclusion contract above. See the [SHA-1 API](../crates/brynja-legacy-sha1-std/src/macos_resident/mod.rs)
and [MD5 API](../crates/brynja-legacy-md5-std/src/macos_resident/mod.rs).

Focused checks cover official vectors, independent packaged bit oracles,
actual Arm/NEON work, cancellation, rejection/reuse versus quarantine, forgotten
loans, mapped state/staging/output placement, join and clearing. Darwin compiler
review covers six coordinator/worker roots and eight existing opaque scalar,
hardware and transfer blocks in both panic modes; it is not whole-image erasure.

1. Darwin mapping/thread foundation and scalar SHA-256 vertical slice.
2. Remaining scalar SHA-2/general-t and SHA-3/SHAKE/cSHAKE; explicit Arm routes.
3. KMAC/TupleHash and separately scoped legacy SHA-1/MD5 adapters.
4. SHA-2/Keccak SIMD batching and bounded threaded ParallelHash.
5. Reconcile route coverage, packaging, emitted-code cleanup and native evidence;
   prepare the independent retest candidate using existing release gates.

Each package includes its own failure, ownership and cleanup tests. Scalar
SHA-2/general-t and SHA-3/SHAKE/cSHAKE scalar and explicit Arm routes are
development-tested. Package 02 includes a bounded Darwin emitted-code review,
not whole-image or dump-erasure qualification.
KMAC/TupleHash scalar/Arm wrappers and separate legacy SHA-1 scalar/Arm and MD5
scalar/NEON adapters complete package 03 at this bounded development scope.
The legacy packaged oracle covers 507 scalar/Arm comparisons and 712 NEON lanes
per build profile, plus 43 ownership/lifetime negatives and 13 compiled mutants.
Modern batching and ParallelHash are not implied by the legacy MD5 batch adapter.
No Intel Mac qualification or new isolation framework is scheduled here.

Development baseline: Apple M2 Pro, macOS 27.0.1 (26A434), 16-KiB pages,
Apple clang/SDK 21-generation tools and Rust 1.99.1. This is a tested development
baseline, not a claim of compatibility with every earlier macOS release. Earlier
receipts retain their actual compiler; final qualification remains pending.
