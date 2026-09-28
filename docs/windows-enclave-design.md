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

### Azure host prerequisite observation

On 2026-09-28, a disposable Azure Windows Server 2025 Datacenter Azure Edition
guest (10.0.26100.33438, AMD EPYC 9V45, two logical processors) reported VBS
enclave support. Before setup, VBS was running but HVCI was not. With the
owner's authorization, the original DeviceGuard settings were backed up,
HVCI was enabled without UEFI lock using Microsoft's Secure-Boot-only settings,
and the guest was rebooted. After reboot, Secure Boot remained enabled,
`VirtualizationBasedSecurityStatus` was 2 and both service arrays contained 2
(memory integrity). HVCI `Enabled=1` and `Locked=0` were also checked directly.
[Microsoft HVCI setup and status definitions](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity).

The [source-bound capability record](../assurance/windows-protection-observations/enclave-availability-azure-x86_64-3023f736.json)
was collected from clean commit `3023f736611dad90e1fa6cbaab78d1a9531c4528`.
All eight probe tests passed natively, including the real PowerShell parser.
Its three source hashes match that commit. The original downloaded JSON hash is
`f27002b4680d04ed69b8ba02c83a87b700e37fa31290893e2c19b41523532abd`;
only line endings were normalized for the committed record. Its
`machine_policy_changed=false` describes the read-only probe itself, not the
preceding authorized HVCI setup. SGX and SGX2 remain unavailable. The differing
CPU virtualization observations are preserved rather than interpreted as an
override of the actual enclave API or DeviceGuard results.

This establishes host prerequisites only: no enclave has been loaded, no
cryptography executed, and no residency, dump exclusion or cleanup guarantee
qualified. The ordinary EC2 probe results remain valid negative observations;
that disposable host is no longer needed for this investigation.

Microsoft's local test-signing walkthrough requires Secure Boot off, test-signing
mode enabled and memory integrity running. Such a development configuration
must be recorded separately from the Secure-Boot-enabled observation above;
it cannot qualify production signing or deployment. Secure Boot remains enabled
at this checkpoint. An Azure control-plane change is needed before that local
test-signing route can proceed; production Trusted Signing is a separate route.
[Microsoft synthetic enclave walkthrough](https://github.com/microsoft/VbsEnclaveTooling/blob/main/docs/HelloWorldWalkthrough.md).

### Development-only lifecycle smoke observation

Later on 2026-09-28, the owner disabled Secure Boot in the Azure portal, leaving
vTPM enabled. That reboot initially left VBS enabled but not running: the guest
still required Secure Boot. For this disposable development host only, the
original boot/DeviceGuard settings were saved, `RequirePlatformSecurityFeatures`
was set to 0 and test-signing was enabled. After the next reboot, VBS status was
2, configured/running service arrays both contained 2, and the boot configuration
reported test-signing enabled. This is a different, weaker boot configuration
from the preceding prerequisite observation, not a production recommendation.
[Microsoft's platform requirement values](https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/always-encrypted-enclaves-host-guardian-service-register).

A temporary non-cryptographic C image and Python host exercised the enclave
lifecycle with public integer values only. This research prototype is not linked
into Brynja, does not add a production native dependency, and is not committed
release-qualification evidence. MSVC build tools 14.44.35207 (linker
14.44.35229.0) and the Windows SDK 10.0.26100.0 directory were used; that directory
name alone is not a claim about the SDK servicing revision. The image was linked
with enclave, integrity-check, mixed-CFG and enclave-only runtime libraries,
then processed by VEIID. Inspection showed policy flags 0 (not debuggable), one
enclave thread, and image-ID-bound imports of `ucrtbase_enclave.dll` and
`vertdll.dll`.

Both the initial and repeated native smoke runs observed:

- An unsigned image was rejected by `LoadEnclaveImageW` with error 577; deletion
  of the uninitialized enclave succeeded.
- The locally test-signed image loaded and initialized. Four calls, using public
  inputs 0, 1, 0x1234 and 0xffffffff, returned the expected XOR-with-0x4252594e
  values. Calls did not wait for an available thread.
- Termination and deletion succeeded. A parent process imposed a 30-second
  bound on each smoke child; these successful calls do not establish complete
  memory erasure or abnormal-termination behavior.
- The ephemeral certificate was removed with private-key deletion requested,
  and a separate certificate-store query confirmed its absence. No trusted-root
  certificate was imported.

The signing command produced a signed image but warned about changed VBS OS
compatibility. The setup wrapper rejected its nonzero result, and is **not**
recorded as a clean automated signing pass. The subsequent explicit loader test
of the produced image succeeded. Likewise, an initial host prototype used a
missing `kernel32` export; the corrected host used the documented
`api-ms-win-core-enclave-l1-1-0.dll` contract. That failed attempt created no
enclave and is not counted as execution evidence.

Diagnostic SHA-256 identifiers (not source-review or qualification approvals):

| Temporary artifact | SHA-256 |
| --- | --- |
| C public-value image source | `7b1f78931861542350bbe2f9256e343a19ecf431e45c724944102ba9540d240f` |
| Python host prototype | `dd608298ae29ec06f2dc237887c06aa2b97103f66d23da08df21110d764a850b` |
| Unsigned image | `354ee12b36337c6ab10c0233b79e56bfdc69abaac023f96e5a6e7c8d13ea3710` |
| Test-signed image | `eeeeadb009b1d52bcac0c547286dca84ffdef525c0a55c45982f21e29c5baef3` |

These observations demonstrate that synthetic enclave execution is feasible on
this development host. They do **not** establish protected allocation residency,
full-dump exclusion, worker-stack/TLS/register cleanup, interruption behavior,
production signing, Rust runtime compatibility or any Brynja cryptographic API.
Windows strict constructors therefore remain unsupported. Before this prototype
can become an assurance lane, its source, failure regressions, signing-warning
handling and complete experiment records must be made reproducible and reviewed.

### Remaining proof sequence (after smoke test)

The lifecycle prototype is now preserved as a
[standalone synthetic experiment](../assurance/windows-enclave-probe/README.md),
not a package dependency or a new release gate. Eight failure-injection tests
pass on Linux and native Windows, covering wrong results, unsigned acceptance,
wrong rejection errors, create/load/initialize/call failures, cleanup failures,
retention of the original failure, timeouts and false qualification flags.
After rebuilding from clean commit `f6d27d520b75161fe7636a64a2acf07a0b7e896b`,
the [unsigned rejection](../assurance/windows-protection-observations/enclave-lifecycle-unsigned-azure-f6d27d52.json)
and [signed execution](../assurance/windows-protection-observations/enclave-lifecycle-signed-azure-f6d27d52.json)
checks passed on the same development host. Signed execution was repeated and
the checkout remained clean. All five source hashes match that commit.

The [build transcript](../assurance/windows-protection-observations/enclave-lifecycle-build-azure-f6d27d52.txt)
and [signing transcript](../assurance/windows-protection-observations/enclave-lifecycle-sign-azure-f6d27d52.txt)
are retained, including the compatibility warning and wrapper failure rather
than replacing them with a PASS. The image-source association is an operator
review of this build, not something established by hashing arbitrary image/source
files together. The records still explicitly deny strict qualification and
production signing. Original downloaded hashes before line-ending normalization:

| Record | SHA-256 |
| --- | --- |
| Unsigned observation | `63ed83298a79f1fb35496fd61b5be7181e3f8f102d0561deb9bf771d766b7a65` |
| Signed observation | `8cd9b85107be5a2eae1f068a0f411cff4ae4774820fb185c35eabeb2d3c1ea7e` |
| Build transcript | `288c489e343d2fdc2f5877a877d13df74d53c52fbd56e106c8bfc44dbace9f88` |
| Signing transcript | `f343692cc2cdae25b60658938172f3acdd1f95ae40c37b20600316472c5c920e` |

### Controlled full-local-dump observation

On 2026-09-28 the synthetic dump experiment ran twice from clean commit
`3ccc5034972e52b6253d825fb199d29b79599131` on the same Azure x86-64 development
configuration: VBS/HVCI running, Secure Boot off and test signing on. The
non-debuggable enclave internally filled and verified an 8-KiB public marker,
cleared/read back the whole region, then refilled/reverified it. A separate
ordinary mapping held a distinct positive control before a deliberate child-only
fail-fast. No cryptographic or real secret input was used.

| Observation | First run | Repeat |
| --- | --- | --- |
| Full local dump size | 54,592,913 bytes | 54,363,377 bytes |
| Ordinary control included and matched | 8,192 / 8,192 bytes | 8,192 / 8,192 bytes |
| Enclave region included | 0 / 8,192 bytes | 0 / 8,192 bytes |
| Internal verification and clear/refill preflight | passed | passed |

The [first observation](../assurance/windows-protection-observations/enclave-dump-azure-3ccc5034.json)
and [repeat](../assurance/windows-protection-observations/enclave-dump-repeat-azure-3ccc5034.json)
bind nine source hashes and the same test-signed image hash. The image was built
from `dump.c` at `3a25fdef`; that image source and its included `synthetic.c` are
unchanged at the observation commit. The
[build transcript](../assurance/windows-protection-observations/enclave-dump-build-3a25fdef.txt)
confirms policy flags zero, one enclave thread and image-ID-bound enclave runtime
imports. The [signing transcript](../assurance/windows-protection-observations/enclave-dump-sign-3a25fdef.txt)
again retains the compatibility warning and resulting wrapper failure. Successful
execution is not a clean signing-automation pass or production approval.

The initial experiment was **inconclusive** because the parser rejected a
zero-sized memory descriptor. A second bounded diagnostic identified descriptor
56 as zero length without address overflow; the
[diagnostic](../assurance/windows-protection-observations/enclave-dump-azure-745e31a2.err)
is preserved. The parser now consumes zero-length descriptors as zero bytes,
with bounded descriptor counts and unchanged positive-control requirements.
Microsoft's [memory descriptor layout](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory_descriptor64)
defines sequential payload offsets by the sum of preceding `DataSize` values.
Zero-byte entries neither advance this offset nor establish any marker coverage.
Regressions cover empty descriptors before/between/after real ranges, all-empty
lists, incomplete controls, partial enclave coverage, corrupted markers and
zero-filled (but included) regions. Twelve enclave-dump, eight parser and nine
WER orchestration tests passed locally and natively.

The [separate cleanup observation](../assurance/windows-protection-observations/enclave-dump-cleanup-azure-3ccc5034.json)
found no owned probe process, executable, dump directory, application WER rule or
temporary signing certificate. Raw dumps were deleted on Azure and never
downloaded. Only summaries, public build/signing transcripts and exact operator
scripts were retained. Downloaded record hashes before CRLF normalization:

| Record | SHA-256 |
| --- | --- |
| First dump observation | `fb11fd0bffb84d4031221665c7a19ca44790d5bb7e38dc622a73ec8c5b264d44` |
| Repeat dump observation | `d98cec81feb4dfe09a365633be3171ea1d9fc2052dbe3daeb313cfbb138e0a16` |
| Cleanup/configuration observation | `65f06fcea255acbdc6f4d5f9064284afa2245e6441a58d039c359e13ddac0b22` |

This is evidence of exclusion for this full-local-dump path and configuration.
It does **not** establish nonpageability, arbitrary snapshot protection, complete
worker-stack/TLS/register cleanup or production signing. The intentional crash
skips destructors; preflight clearing is not abort cleanup. Windows strict
constructors remain unsupported. Next work is residency and complete enclave
worker/resource ownership, not cryptographic integration based on isolation alone.

### Remaining implementation sequence

1. Obtain a host where the read-only probe reports VBS support and running
   protection; separately establish exact OS revision and HVCI configuration.
   The Azure observation above satisfies this initial prerequisite, not the
   subsequent execution or production qualification steps.
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
