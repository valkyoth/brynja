# v0.29.3 — Integrating accelerated AES-GCM and GMAC

The ordinary AES-GCM and GMAC constructors still use portable AES and GHASH.
Separate default-off `aes-gcm-execution` and `gmac-execution` features
expose explicitly selected paired owners from the checkout, both directly
and through the facade. Neither feature enables raw AES or raw GHASH. The frozen
[v0.29.2 archive fixture](../../assurance/aead-portable-acceptance/README.md)
is the portable baseline; do not replace its pinned expectations with values
computed by the new backend.

| Step | Status |
| --- | --- |
| Route both GHASH uses through the same selection per operation, sharing the existing framing, nonce and commit code | Implemented internally. The 96-bit IV shortcut requires only the message hash; general IVs require both hashes. |
| Exercise an actual hardware pair | AES-NI + PCLMUL on Linux/Windows x86-64 and AES + PMULL on little-endian Linux/macOS AArch64, for all three AES widths. See native observations below. |
| Admit a complete pair and bind it to a public owner | Implemented for both specialized instruction pairs. Both startup checks precede application key import. No mixed pair or automatic fallback. |
| Preserve lifecycle at the public x86 boundary | Tested at all three key widths: baseline unavailability, retirement across keys, ordinary bad-tag recovery, and the error/unwind sweeps below. |
| Replay packaged native APIs, including isolation of the selected feature and dependency graph | Passed on Linux x86-64 for both import routes and compiler endpoints (below). Local Cargo archives, not crates.io publications. |
| Inspect the linked x86 message and verification paths | Passed the bounded screen below on the same eight executables that replayed the vectors. |
| Observe timing of the integrated x86 pair | One predeclared AMD observation per compiler completed (below). Not an observation of Windows or Arm, or deployment qualification. |

### Native observations on Windows, Linux ARM64 and Apple Silicon

On November 25, 2026 the following builders each passed the same offline
bundle on Rust **1.90.0 and 1.100.0**. Compilers, tests and packaged consumer
executables ran inside the named OS; these were not cross-build results.

| Builder | Admitted pair | Functional result per compiler |
| --- | --- | --- |
| Linux ARM64, AWS Neoverse-V2 | Arm AES + PMULL | 17 route/lifecycle tests; all eight corpus replays |
| macOS, Apple M2 Pro | Arm AES + PMULL | Same |
| Windows 11 x64, MSVC, QEMU/KVM guest using the host CPU | AES-NI + PCLMUL | Same; not a bare-metal Windows claim |

The 17 tests include a baseline build refusing acceleration, specialized
builds requiring the expected pair, and nine interruption tests. Four
downstream executables per compiler (GCM and GMAC, direct and facade)
each ran the Go and NIST populations tabulated below. Negative corpus rows
require rejection, not just process success.

Run `brynja-verify run aes_gcm native-pair-functional-records` to check the
[retained records](../../assurance/aead-native-observations/v0.29.3) without
contacting a host. This verifies the recorded input and executable identities
and populations; it does not execute the binaries again. All 841 packaged
Rust sources and original crate manifests matched the working tree when these
records were collected. A subsequent Clippy fix removed redundant single-operand
`all(...)` predicates from the downstream test selector; no test body or
library code changed. These six records predate the native runner's exact-tree
and Cargo-configuration checks. They are observations from those builders,
not proof of hermetic builds. To make a **fresh** observation:

1. On the packaging host, install the compiler endpoints and Go and supply
   the pinned NIST ZIP described below. Run
   `python3 scripts/aes-gcm/prepare-native-pairs.py native.tgz`.
2. Transfer the bundle to a compatible host, compare its SHA-256 with the
   trusted producer's output **before extraction or executing the bundled
   script**, and extract it into an empty directory. Install Python,
   both native Rust toolchains via rustup, and a native linker (on Windows,
   use an x64 Visual Studio developer prompt).
3. In that directory run
   `python3 -I run.py linux-arm64 ../results --inputs-sha256 PRODUCER_MANIFEST_SHA256`
   using the producer's **input manifest** digest (not the tarball digest), substituting
   `macos-arm64` or `windows-x64` as appropriate (use `python` on Windows).
   The results directory must not already exist. Keep the archive, toolchains,
   temporary directory and logs outside the extracted bundle. The runner
   rejects additional or linked entries and ambient Cargo config, and works
   from a new private copy of the verified bytes. Use a trusted builder,
   toolchain, SDK, PATH and temporary parent. This is not sandboxing against
   a hostile process with the same account, or signed build attestation.

These observations do **not** extend the Linux x86 linked-code inspection
or timing screen to the other platforms. Arm GHASH timing remains unresolved;
no timing experiment was repeated or reclassified here.

### Replaying the packaged x86 check

On a compatible Linux x86-64 host, run
`brynja-verify run aes_gcm x86-packaged-pair`. Install both compiler
endpoints, Go and `llvm-objdump`, and supply the [pinned NIST GCMVS ZIP](aes-gcm-development.md)
at `references/local/gcmtestvectors.zip`. Missing or altered inputs do not
produce a pass. The command builds local Cargo archives, then runs isolated
consumers using **only** the selected composition feature. It uses temporary
copies of the frozen replay programs: only the AES owner imports, pair
admission, and constructor arguments change. Vector expectations come from
the original archive and independently generated, digest-checked Go outputs.

| Cases per compiler and import route | GCM | GMAC |
| --- | ---: | ---: |
| Independent Go boundary rows | 66,150 | 8,190 |
| NIST GCMVS rows (GMAC: AAD-only subset) | 33,750 | 6,750 |

Rust 1.90.0 and 1.100.0 each passed both the direct and facade runs.
The Go replay exercises all three key widths, all five permitted tag widths,
13 IV widths and both GCM buffer layouts. Nonempty negative controls must
fail when an expected tag, ciphertext, plaintext or authentication decision
is changed. The NIST subset is **not** an additional independent oracle for
GMAC. These runs do not measure speed or timing leakage.

### What the linked x86 check establishes

The runner takes the release example executable identified by Cargo, inspects
its linked instructions and relocations, then executes that same file for both
replays. It prints the ELF SHA-256 after confirming it did not change; the
[observed executable identities](../../assurance/aead-x86-linked/v0.29.3.sha256)
refer to that run, not a reproducible-build claim. Merely
finding AES-NI or PCLMUL instructions in a startup self-test does not pass.

Each of the eight executables has 30 message-processing bodies: ten per AES
width, of which five verify tags. The screen follows calls from the paired
owner to these bodies, from each body to its width-specific forward AES rounds,
and through the authentication frame to the four-instruction carryless multiply.
It also checks the linked byte-difference and final zero-test helpers. In the
verification bodies Rust 1.90.0 emits one accumulation call site per tag-width
variant; Rust 1.100.0 emits 12 through 16 sites for the five variants. These
are static call-site counts, not counts of executed calls.

This checks selected edges and instruction sequences, not every branch or
memory access. It does not prove constant time, erasure of registers or spills,
or equivalence for other compilers, profiles or downstream binaries. A compiler
that changes these shapes needs review, even when the vector replay still passes.

### Scoped x86 timing result

The [protocol](aead-x86-timing-protocol.md) was written before sampling.
Both compiler endpoints completed their first and only collection on the local
AMD Ryzen 9 9950X3D. Across the 24 ordinary campaigns per endpoint (including
the matched-input controls), the largest absolute paired or Welch score was
1.68 on Rust 1.90.0 and 1.64 on Rust 1.100.0 (rounded up; alarm threshold
4.5). Both sensitivity controls detected the intentional delay in the
expected direction. No timing alarm occurred in this screen.

`brynja-verify run aes_gcm x86-pair-timing-record` checks the pinned records
and recomputes the statistics without measuring again. The [raw samples,
summaries and build identities](../../assurance/aead-x86-observations/v0.29.3-amd)
belong to the release timing fixtures, not the vector-replay executables.
This is not a constant-time proof, not a measurement of other x86 CPUs, and
not evidence about ARM.

### Focused composition and lifecycle checks

Run `brynja-verify run aes_gcm x86-pair-development` on a Linux x86-64 host
where AES-NI, SSE2 and PCLMUL remain usable on every CPU that can run the
test. The preflight uses a baseline binary before starting the static AES
binary; GHASH uses required runtime admission. No affinity settings change.
The tests require real host execution, check the selected GHASH identity,
and count the hash starts so a hard-wired portable IV or tag path cannot
satisfy them. The test adapter starts a GHASH owner for each frame; its
startup cost is not a production performance measurement. The public owners
instead borrow the same admitted multiplier for every frame.

The interruption sweep calls the native public owners and, for each case,
requires the expected sequence of stages before returning an error or unwinding.
It covers guard entry, completed key expansion, each completed AES block,
each GHASH frame start and completed product, and the final guarded check.
A 17-byte GCM message needs two counter blocks, so interruption at the second
also exercises cleanup after the first has already written to scratch.

Per compiler endpoint there are **678 interrupted calls**: 18 during key
import, 516 during GCM seal/open (including invalid tags and both buffer
layouts), and 144 during GMAC generation/verification. GCM uses a hashed
eight-byte IV here; GMAC exercises the 96-bit shortcut. Sends must spend
their single reservation, and receives must not. Neither a partial result
nor a tag may escape; admitted message scratch must clear and subsequent
work must observe retirement. Another check revokes the pair before the
actual final health check for both a successful computation and a rejected tag.
The private frame-start boundary also rejects a retired pair before touching
the workspace. A paired-only frame test interrupts the second product and
checks that an error or unwind immediately wipes the live accumulator and
prevents update or finish, even without the standalone GHASH runtime feature.

These checkpoints exist only in Rust test builds and simulate recoverable
errors or Rust stack unwinding. They do not establish process-abort cleanup,
hardware fault detection, or properties of the final linked machine code.

To use it, call `aes_gcm::execution::AesPair::require()` and pass
`&pair` as the first argument to a constructor such as
`aes_gcm::execution::Aes256Gcm::<16>::from_reserved_range`. GMAC uses
`gmac::execution` and accepts the same pair (use a separate raw key).
`PairError::Unavailable` means an application may choose the ordinary
portable constructor **before** importing the key. `Failed` and errors
after selection are not fallback signals. An invalid tag rejects only
that message. Retiring the pair retires all owners borrowing it.
A specialized binary requires compatible hardware before it starts; the
constructor is not a baseline dispatcher. On `x86_64-unknown-none` use the
portable `aes-gcm` and `gmac` features, not the hosted execution features:
the static CPU dependency does not build for that soft-float target.

On Rust 1.90.0 and 1.100.0 the check covers the three AES widths, NIST
96-bit-IV empty-message tags, general-IV partial payload and AAD-only
comparisons against portable, invalid tags, and failure at IV or tag hashing
after reserving a nonce. This is not a claim about a hosted x86 detector,
Arm timing, RISC-V admission, hardware-fault resistance or a published API.
Apply the [existing timing stop rule](aes-gcm-development.md#aarch64-timing-stop-rule)
to any new Arm timing observation. Native vector runs are functional evidence only.
