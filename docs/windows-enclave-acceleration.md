# Windows enclave acceleration development

Scalar constructors remain scalar. An explicit SHA-NI SHA-224/256 host route is
now development-tested; other accelerated session routes are still pending.
The historical public-vector diagnostics below are not, by themselves, secret
input qualification. Release-gate policy and dependencies are unchanged.

## Platform observations

Microsoft lists `IsProcessorFeaturePresent` among the
[Vertdll APIs available inside VBS enclaves](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/enclaves-available-in-vertdll).
Its [feature definitions](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent)
include SSE2, XSAVE, AVX and AVX2. The diagnostic queries that API inside the
enclave, along with bounded CPUID leaves and guarded XGETBV. It does not copy a
host feature mask into an authority. Faults, malformed queries, missing
prerequisites and changing observations reject the experiment.

The Azure Windows Server 2025 x64 development guest reports AMD EPYC 9V45,
SHA-NI, AVX2 and enabled XMM/YMM state inside VBS. Dedicated x86 SHA-512 is absent;
no dedicated SHA-512 execution is claimed. SHA-512 **batch** compression below
uses AVX2 integer instructions, not the dedicated SHA-512 instruction extension.
Feature discovery and KATs do not prove that arbitrary scheduling, hotplug or VM
migration preserves these features, nor confer production trust or cleanup proof.

## Native public-vector experiment

C performs only OS/CPU queries and bounded routing. Cryptography uses existing
first-party Rust hardened kernels unchanged. The whole Rust image is compiled
with `+sha,+sse2,+avx,+avx2`, so the baseline C entry requires the **complete**
bundle before entering any Rust routine, even the SHA-NI experiment. There is
no fallback or dedicated-SHA512 route. Each campaign revokes its authority and
requires subsequent work to fail.

| Existing hardened kernel | Independent comparisons |
| --- | ---: |
| SHA-256 SHA-NI | 32 |
| Single-state Keccak AVX2 | 16 |
| Eight-lane SHA-256 AVX2 | 256 |
| Four-lane SHA-512 AVX2 | 128 |
| Four-lane Keccak AVX2 | 64 |

All 496 comparisons passed inside the development VBS enclave. SHA-2 expectations
come from Python hashlib; Keccak uses the existing independent Python oracle.
Lane inputs differ; successful batch call counts are checked. Startup KATs run
in addition to these comparisons.

Local and ordinary Windows-process tests pass. Three corrupted oracle tables
cause exactly the five relevant campaigns to fail. Seven Python tests cover
malformed inventory, missing prerequisites, result tampering, timeouts, cleanup
and rejection without execution. A separate test compiles the **actual C entry**
against mock public feature queries and rejects eleven compiled guard mutations.
The mock test is not enclave execution evidence.

The [source-bound observations](../assurance/windows-protection-observations/cpu-kernels-20260930.json)
reference the saved image, emitted assembly, commands and native results. All
166 build/capture source hashes match. Temporary signing certificates/private
keys were removed; enclave deletion succeeded. SignTool reported success with
its SDK compatibility warning; the wrapper returned nonzero. No clean production
signing result is claimed.

## Retained SHA-NI component

A separate **private component**, not a shipping host route, now implements
retained SHA-224/256 using the existing hardened SHA-NI streams. It borrows an
exact `X86Sha256` authority, rejects wide/unknown identities, and never selects
portable hashing. Its version-13, 64-byte request header requires an explicit
route identity, zero reserved fields and bounded copied payloads. Decode failure
revokes retained state in the placement adapter; empty updates, cancellation and
export also check authority health. The copy callback is a private OS-adapter
seam, not a new application callback API.

The placement layer keeps the authority and borrowing owner in nonoverlapping,
aligned slots in one borrowed page. It exposes neither object, destroys the
owner before its authority, then volatile-clears the entire page, including
padding and inactive enum storage. Backing bytes use `MaybeUninit` because typed
object placement may introduce uninitialized padding. These are placement rules,
**not residency guarantees**: the future enclave entry must admit the actual
page and worker stack and must perform deterministic destruction. Forgetting a
Rust owner is not equivalent to running its clearing destructor.

The focused tests cover 242 fragmented arbitrary-bit comparisons, 32 independent
hashlib byte-message cases (including million-byte inputs), all four retained
SHA-224/256 compositions, revocation, copied-header validation, output failures,
recoverable unwind, cancellation and reuse. Nine component and four real-owner
placement tests reject fifteen component and three placement mutations, plus
thirteen compiled ownership/lifetime violations.
These pass locally and in an ordinary Windows process, not inside the enclave.
All 251 Windows build-source hashes match; the
[component observations](../assurance/windows-protection-observations/sha2-accelerated-component-20260930.json)
bind the saved build, binaries and test diagnostics outside `target/`.

A separate Miri **placement model** uses explicit non-cryptographic lifetime
doubles because the real kernels contain inline assembly. It executes the same
placement/destruction implementation without runtime source changes, exercises
alignment and full-page provenance, and rejects narrowed pointer provenance,
overlapping slots and reversed destruction order. This is not Miri coverage of
SHA-NI, the real owner internals, Windows OS admission or enclave execution.

## Retained SHA-NI enclave worker

The private version-13 component is now connected to the existing admitted
64-KiB worker window and guarded retained page in a development image. The
baseline C entry validates the complete SHA/SSE2/AVX/AVX2 bundle before **any**
specialized Rust entry, including destruction. A rejected feature query latches
failure; restoring advertised features does not reopen it. If features disappear,
the adapter must not call an unsupported Rust destructor and pretend cleanup
completed. Arbitrary CPU migration is not qualified by this check.

Only allocation/lifetime metadata lives in the worker's static slot. The page
keeps the borrowing owner and authority alive across returns. The worker copies
and validates the 64-byte header before copying its bounded payload, revokes the
owner after copy/decoding/receipt failures, and clears both snapshot buffers before
reporting completion. Destruction drops the stream before its authority; C then
checks all 4096 backing bytes are zero before unlock/free.

One sequential real-owner worker test passes on Linux and ordinary Windows,
rejecting nine compiled Rust mutations. Eleven compiled feature-gate mutations
and four mutations of the actual generated C entry are rejected as well. These
include entry without feature validation and entry after restriction failure.
The mutation runner restores original **bytes**, including line endings, and
checks every generated build artifact against its recorded digest. An initial
Windows run exposed CRLF restoration drift; the corrected run is recorded
separately rather than treating its first artifact manifest as current.

The final development VBS image passes 21 independent hashlib comparisons in
151 calls, covering SHA-224/256 boundaries, fragmented input, retained rehash,
cancellation/reuse, seven malformed/copy-failure cases and terminal rejection.
There are 207 page-residency/lifecycle events. The native adapter checks worker
and allocation geometry, copy/clear receipts, locked-page observations and
zero-before-release outcomes. It also verifies that the internal Rust and copy
entry points are not exported, preventing direct bypass of the baseline gate.
These are public-vector author experiments, **not**
current-image dump/register qualification or approval for real secret inputs.
All 344 capture-source hashes and 24 generated artifact hashes match the
[saved worker observations](../assurance/windows-protection-observations/sha2-accelerated-worker-20261001.json).
SignTool's compatibility warning/nonzero exit is preserved; temporary signing
certificates and keys were removed, and native enclave deletion succeeded.

## Explicit host session route

The existing `sha2::Session` now has a separate `open_sha_ni` constructor behind
`strict-sha2-acceleration` (facade feature `acceleration`). Mandatory production
signature, image identity and imports remain enforced. An additional baseline
enclave export identifies the version-13 route and checks its full feature bundle;
missing or wrong protocol rejects construction. This identity check supplements,
and never replaces, the trusted signed-image policy.

Only SHA-224/256 may start or receive a retained rehash. Wide/general identities
reject and quarantine before transport, and failures never select scalar hashing.
The existing `open` constructor and 48-byte scalar protocol remain unchanged;
the new route checks the entire 64-byte accelerated header and receipt.

Native development debug/release tests each pass 46 accelerated cases and 631
scalar cases. They also reject development signatures through both public
constructors, mismatched scalar images, incorrect image policies, unsupported
identities and invalid output sizes, and cover cancellation/reuse and abandonment.
Windows scoped Clippy passes. Linux packaged consumers check that the new method
is absent without acceleration and available when explicitly enabled. The actual
C protocol export adds four compiled mutants to the worker checks (nine Rust and
nineteen C mutants rejected on Linux and Windows).

These are source-bound author tests, not production signing or independent
qualification. Current-image ABI/register/stack/dump review remains open, as do
wider algorithm acceleration and Windows ARM64. See the
[host observations](../assurance/windows-protection-observations/sha2-accelerated-host-20261001.json)
and [API guide](windows-enclave-sha2.md).

## Next integration boundary

- Extend explicit opt-in selection beyond SHA-224/256 and bind each route to its
  trusted image policy. Scalar constructors remain scalar; failed acceleration
  must not silently choose scalar execution.
- Keep backend owners and scratch in enclave storage. Preserve streamed
  framing, retained composition, output transactionality and quarantine.
- Inspect Windows ABI/register behavior for the actual integrated image. This
  public diagnostic does not qualify caller frames, stacks, secret placement,
  spills or erasure merely because it invokes hardened kernels.
- Complete differential, negative-selection, cleanup and independent review;
  qualify bounded multicore ParallelHash separately.

These observations concern one development x64 guest. Windows ARM64, production
signing, arbitrary migration and privileged snapshots are not qualified.
