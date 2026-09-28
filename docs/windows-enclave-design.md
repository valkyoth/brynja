# Windows enclave feasibility review

Status: research proposal for v0.24.50, not an implemented or qualified backend.
The existing strict API still rejects Windows. Linux behavior, default-off
acceleration and release gates are unchanged. See the preceding
[Windows protection experiments](windows-strict-profile.md).

## Why this is not a memory-adapter replacement

The current resource API returns borrowed host slices through
`ProtectedBytes::as_bytes`/`as_bytes_mut`. Strict SHA-2's `Digest::expose` also
borrows protected output. Its worker creates scoped secret state on a joined
protected host stack. An enclave must not provide host-dereferenceable slices to
its private state or copy that state into ordinary memory to emulate these APIs.
Likewise, `ProtectedStack::run` cannot send arbitrary Rust closures, captured
objects and vtables into a separately linked image as though it were a thread.

An enclave implementation therefore needs an explicit operation boundary and
different ownership for secret results. It cannot silently replace the current
resource adapter while claiming identical API and storage semantics.

Microsoft describes separate host and signed enclave images, an enclave-specific
runtime/link environment and controlled entry points. Debuggable enclaves are
not production protection. Test signing and production signing are different
deployment paths. [Microsoft development guide](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide).

## Candidate design, subject to review

| Component | Proposed responsibility | Must not do |
| --- | --- | --- |
| Host facade | Validate public bounds, select an explicit route, own scoped session handles | Return enclave secrets as ordinary borrowed output or silently switch to host hashing |
| Enclave image | Execute first-party Rust cryptography, own state, temporary buffers and secret results | Substitute platform cryptographic providers for Brynja algorithms |
| Request boundary | Fixed-width versioned messages, checked lengths/offsets, bounded copies and session generations | Trust host pointers, Rust object layout, aliases or caller-provided CPU authority |
| Output boundary | Keep secret results inside; support explicit declassification and in-enclave composition | Call an ordinary host buffer protected, or export internal addresses |
| Worker lifetime | Bound concurrency, drain workers, clear owned state before reuse/release | Claim isolation alone proves full stack, spill, TLS or register cleanup |

This table is a proposed design, not new exported API. Session tokens must be
bound to their instance and generation, non-forgeable at the Rust facade, and
validated inside the enclave even if an application bypasses that facade.
Public errors must not contain secret data. Quarantine, cancellation, partial
startup and output-commit behavior need the same deliberate classification as
the existing implementations. Host inputs remain caller-owned; temporary input
copies created inside the enclave become owned regions requiring clearing.

All SHA-2/SHA-3, KMAC, TupleHash, batch and ParallelHash paths would need explicit
operation adapters. Start feasibility with one bounded scalar SHA-256 operation,
not a feature claiming the whole facade is operational. Only after storage and
worker obligations are proved should SIMD/hardware routes be integrated and
qualified under each enclave ABI. Unsupported instructions must fail before
entry; host CPUID or an existing platform authority is not sufficient evidence
about enclave execution. No production platform support is inferred here.

The available enclave API surface is restricted. The reviewed Vertdll list has
allocation/protection APIs but does not list `VirtualLock`; that absence is not
proof that memory pages are pageable or nonpageable. Residency, guard geometry,
OS-owned worker stacks, complete cleanup and failure semantics remain explicit
unresolved proof obligations. Confidentiality from the host is not automatically
equivalent to our nonpageable/cleared-owned-memory contract.
[Available APIs](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/enclaves-available-in-vertdll).

Calls can reject when no enclave thread is available rather than wait without a
bound. Our proposed adapter must use bounded resource admission; no enclave call
or cross-boundary unwind may be treated as an ordinary Rust callback.
[CallEnclave](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-callenclave).

## Build and deployment feasibility

Microsoft's SDK advertises Rust 1.88+ and x64/Arm64 support, but this does not
qualify Brynja's compiler set, inline assembly, Windows unwind ABI or dependencies.
Its current SDK has newer Windows/SDK requirements than the basic enclave API
overview. Select and pin an exact tooling version before importing it, review
generated bindings and dependencies, and inspect every linked runtime import.
No SDK, third-party crate or generated boundary has been added to Brynja.
[Microsoft enclave tooling](https://github.com/microsoft/VbsEnclaveTooling).

An operational host must actually report enclave support with VBS/HVCI running.
A supported CPU model or an exported function is insufficient. A releasable
image needs a non-debug policy, reviewed identity/import binding and the required
signing setup. Test-signed experiments cannot satisfy production identity claims.
[VBS device/development prerequisites](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves).

The disposable EC2 host currently reports VBS, SGX and SGX2 unavailable; VBS status
is zero and guest virtualization-extension observations are false. The
[committed read-only observation](../assurance/windows-protection-observations/enclave-availability-x86_64-e3d3c5ff.json)
is not enclave execution evidence. The probe does not allocate an enclave or
change boot policy, machine configuration, signing certificates or privileges.
It queries exact enclave type flags and preserves negative API results and
their last-error values. A false return with last-error zero is not success.

The observation was collected on 2026-09-28 at clean commit
`e3d3c5ff46735d3cd6c336e1c583810f74fad8af`. All three source hashes were checked
against the committed probe. The downloaded JSON SHA-256 is
`9f256c5fb5ebae331a03e0824ad07e70467b71de2a4ca6ded38531e488a76266`;
only line endings were normalized for the committed record. All eight probe
tests passed on Windows; seven pass on Linux with the Windows-only PowerShell
parser test explicitly skipped. An initial diagnostic query syntax error was
fixed and regression-tested before collecting this record; the failed attempt
produced no observation and is not counted as native evidence.

AWS documents that enabling nested virtualization on Windows EC2 disables VSM.
Therefore, simply enabling that option or provisioning a larger C8i instance
is not an established way to obtain this test platform. This is not a claim
that every AWS/bare-metal configuration is impossible; obtain provider-supported
VBS availability and test the exact host before requesting expensive capacity.
[AWS nested virtualization constraints](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-nested-virtualization.html).

## Next decision and proof sequence

1. Obtain a host where the read-only probe reports VBS support and running
   protection; separately establish exact OS revision and HVCI configuration.
2. Resolve residency and full owned-worker cleanup from documented mechanisms
   plus a bounded synthetic experiment. Do not infer them from isolation.
3. Review a minimal first-party scalar operation boundary and its new secret
   result ownership. Obtain approval for API/deployment changes before replacing
   or extending the shipped facade.
4. Build and identify a synthetic enclave using reviewed tooling; verify dump
   exclusion with positive controls, resource failure, lifecycle/cleanup and
   signing-policy rejection. Development success is not production admission.
5. Only then extend supported operations and architecture-specific acceleration,
   run focused regressions and exceptional security review, and use the existing
   native-evidence/release flow.

If the required contract cannot be established, keep Windows strict unavailable.
A narrower deployment-dependent profile would be a separately approved design,
not a renamed pass for these experiments.
