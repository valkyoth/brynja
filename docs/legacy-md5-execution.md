# Ordinary MD5 batch SIMD execution

Status: implementation in progress; exceptional pentest and fresh native
qualification remain required before tagging v0.24.43. Hardened SIMD ownership
is a separate v0.24.44 milestone. MD5 is collision-broken (RFC 6151); none of these
APIs authorizes new authentication, signatures, password hashing or modern TLS.
There is no independent cryptographic verification or FIPS validation.

## Explicit, separate APIs

`brynja-legacy-md5` exposes `execution` only with its default-off `execution`
feature. `brynja-legacy-md5-std` exposes hosted selection only with its separate
default-off `runtime-execution` feature. Neither crate enters the modern facade.
Existing `Md5Batch`, portable hardened owners and `RuntimeMd5Backend` retain
their behavior. The old candidate session remains unadmitted; it is not the
operational authority and no candidate admission flag was changed.

`Executor::for_compiled_target`, hosted `execution::select`, or an explicit
`Authority` select a policy. An authority is not a report, boolean or backend
identity. Authority and executor are not Send, Sync, Copy, Clone or Debug; no
raw-session export is provided. Explicit quarantine is irreversible. A failed
startup KAT, revoked authority or backend error does not permit portable fallback.

| Mode | Selection and workload behavior |
| --- | --- |
| Portable | Never creates an instruction authority, even in a specialized binary. |
| Prefer | Missing capabilities before construction allow portable selection. An ineligible batch uses portable work with an honest scalar report. |
| Require | Missing capabilities fail. A batch without an eligible SIMD group is rejected before output or work-budget mutation. |

Every digest call requires `PublicData::acknowledge()`: all messages **and their
lengths** must be public. This is a caller classification obligation, not a
compiler proof about arbitrary bytes. There is no secret-output method or
hardened-owner conversion. SIMD local state, blocks, registers and spills are
not cleanup-qualified. Use the separate portable hardened APIs for confidential
legacy compatibility; ordinary SIMD is not a substitute for them.

## Complete batch contract

The fixed input and output arrays have eight stable slots. `None` is inactive;
`Some(BitString::new(&[], 0)?)` is an active empty message. Successful inactive
outputs become zero; active empty outputs are the MD5 empty-message digest.
All errors preserve the entire caller output array. Batches have fresh owned
state; the executor can be reused but has no stream to resume or finalize twice.

An AVX2 invocation processes eight independent messages. Little-endian AArch64
NEON processes four, using groups 0–3 and 4–7. A group is eligible only when every
slot is active and has at least one complete 64-byte **message** block. There is
no lane compaction or reordering. Common full-block prefixes are vectorized;
unequal suffixes and **all padding** are scalar. Canonical MSB-first partial-byte
tails are accepted through `BitString`; inactive, empty and partial-bit messages
are never confused. A single-message hash is not accelerated by this API.

`Report.backend` and `vector_width` describe actual work in the completed batch,
not just configured capability. They are None/0 when no SIMD ran. The nested
`Md5BatchReport` counts active lanes, scalar compression calls (including padding)
and vectorized message blocks: one AVX2 invocation counts eight vector blocks,
one NEON invocation counts four. It never counts vector instructions as blocks.
Work admission uses the same compression-block units, including final padding.
Cancelled or budget-rejected work is not refunded. Such failures can be retried
with fresh batch state; backend failure and callback unwinding revoke authority.
The final health check occurs before public-output commit, including after the
last cancellation callback. Callbacks cannot authorize a silent route switch.

## Platform authority, not a current-core observation

Static selection requires the full compiler target bundle to hold on **every CPU
that can execute the binary**, including OS scheduling and VM migration:
`+avx2` with OS-enabled YMM state on x86-64, or `+neon` on little-endian AArch64.
This is the binary's deployment obligation. It is not a runtime feature check.
An incorrectly deployed specialized binary may execute an illegal instruction.

Generic hosted x86-64 remains portable/unavailable: a CPUID observation alone is
not imported as a lifetime-wide platform authority. Explicit AVX2 specialization
can select the static authority. Hosted AArch64 uses Rust's NEON detector on its
allowlisted operating systems; unsupported systems reject required selection.

| Hosted AArch64 OS | Authority boundary |
| --- | --- |
| Linux | Rust's OS feature ABI detector; correctness depends on the kernel's advertised features. |
| Android | Rust's Android/Linux detector and its platform handling, not a promise about arbitrary vendor kernels. |
| macOS / iOS | Rust's Darwin detector and platform feature contract, not arbitrary VM migration proof. |
| Windows | Rust's Windows detector and OS feature contract, not arbitrary hotplug or migration proof. |

Detection can be cached: revalidation is **not live revocation** of changed
hardware. A non-Send owner does not prevent scheduler migration. Applications
must uphold the applicable OS/hypervisor contract throughout use. The explicit
unsafe `Authority::from_platform` entry requires that full lifetime-wide contract
and a non-panicking revalidator; a boolean callback, affinity or a report is not
proof. False revalidation and recoverable callback unwind quarantine the owner.

## Evidence and release boundary

The operational suite covers all activity masks, canonical bit tails, unequal
lengths, deterministic order, exact vector/scalar accounting, output poisoning,
work/cancellation failures, revocation and ownership/classification rejection.
The packaged adapter is checked against an independent RFC 1321 bit-level oracle;
compiled output/report mutants must fail runtime assertions, not merely fail to
compile. Native Linux x86 ASan runs force leak detection and fatal error exits.
QEMU NEON execution is emulated evidence, never substituted for native evidence.

Fresh, source-bound AMD x86-64, Intel x86-64, AWS AArch64 and Apple M2 observations
must be reviewed before tagging. The pending evidence index fails closed until
all four lanes are present. Observations bind commit, compiler, host, complete
features, actual route markers and the reviewed source closure. They establish
tested functional execution, not independent review, timing/side-channel safety,
FIPS certification, secret-state cleanup or military deployment approval.

The normative algorithm remains the pinned RFC 1321; its security limitations
remain the pinned RFC 6151. Existing candidate evidence stays historical and
non-authorizing. Only this separate operational contract exposes ordinary SIMD.
