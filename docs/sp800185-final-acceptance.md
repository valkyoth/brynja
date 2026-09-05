# SP 800-185 Final Execution Acceptance — v0.24.17

Status: owner-supplied pentest, native observation review and local release checks PASS; awaiting green GitHub/CodeQL.

This milestone adds assurance tooling, not cryptographic implementation. The
combined SP 800-185 family is now **Fully implemented** after the review below.
No result here is independent cryptographic verification or FIPS validation.

## Reproduce the consumer contract

From the repository root, with Python 3.11+ and the repository Rust toolchain:

```sh
python3 scripts/sp800185/check-execution-acceptance.py
python3 scripts/sp800185/test-execution-acceptance.py
cargo run --release --locked --manifest-path assurance/sp800185-final/Cargo.toml -- --benchmark
```

The original eight Rust files and representative input are frozen against the
signed v0.24.16 tag in `scripts/sp800185/frozen-portable-contract.toml`. They
remain byte-identical after checkout newline normalization. Only Cargo
manifest/lock facade-version metadata advances to resolve the current facade;
no fixture input, expectation or API call changes. Its original executable
still prints the historical portable-stage status. The new execution fixture
records pre-review observations. Its fixed pending-closure line and the raw
JSON `PENDING_REVIEW` field are not live release-status flags. Neither executable
alone changes a verification table; the reviewed disposition is recorded here.

The hosted fixture reruns all fourteen identities, fourteen official examples,
fourteen hardened profiles and three public layers. It then performs 540
comparisons: 360 sequential/threaded byte and arbitrary-bit comparisons plus
180 caller-scheduled comparisons, covering all four ParallelHash identities,
empty and multi-leaf messages, three block sizes and 1/2/4 workers. It checks
24 typed cancellation, work-limit and invalid-block failures with unchanged
public output. Four independently compiled corruption cases prove that byte,
bit, scheduled-output and failure-output mismatches are actually detected.

The existing executor unit tests remain the source of injected spawn-failure,
worker-panic, joining, concurrency and cleanup coverage. The fixture does not
add production test hooks or pretend to inject OS faults through public APIs.
The optional std adapter is used only by this hosted fixture, never by the
portable fixture or the default cryptography graph.

## Backend disposition

| Route | Disposition | Evidence still required for admission |
| --- | --- | --- |
| Portable ordinary/hardened SP 800-185 | Executed by frozen consumer contract | Native final review below |
| Sequential, caller-scheduled, std ParallelHash | Portable Keccak; output/failure comparisons | Native execution/performance review |
| x86_64 AVX2 Keccak candidate | **Unadmitted**; no public SP 800-185 integration | Keyed cleanup equivalence, timing, migration and architecture admission |
| AArch64 SHA3 Keccak candidate | **Unadmitted**; no public SP 800-185 integration | Keyed cleanup equivalence, timing, migration and architecture admission |
| RISC-V | Portable Keccak only; no accelerated candidate | Future qualifying hardware and separately reviewed implementation |

The acceptance fixture must observe zero admitted CPU backends and no ordinary
Keccak session. It never uses evidence-only cfgs or unsafe ISA attestations.
Candidate unit tests run KAT/quarantine/differential cases only when the test
process detects suitable instructions; on unsupported hardware those cases
return early. A green test summary is therefore **not** evidence that an ISA
executed. Review CPU capabilities separately before describing candidate
execution. CPU migration and secret-erasure restrictions remain unchanged.

## Native capture

After pentest, use the same clean committed checkout on each machine. Reuse an
installed Rust 1.98.1; install it with rustup only if absent. No nightly, QEMU,
new Rust dependency or large-memory server is needed for these observations.
The usual native Rust linker prerequisites still apply (including Apple's
command-line developer tools on macOS); no C cryptographic implementation is
built. Warm the existing locked workspace dependency cache once with
`cargo +1.98.1 fetch --locked`; capture itself runs offline. Four available
logical CPUs and 2 GiB RAM are convenient;
this is a small bounded workload, not the full Miri/Kani gate.

```sh
python3 scripts/sp800185/capture-sp800185-native.py local-amd-x86_64 target/sp800185-amd.json
python3 scripts/sp800185/capture-sp800185-native.py aws-intel-x86_64 target/sp800185-intel.json
python3 scripts/sp800185/capture-sp800185-native.py aws-aarch64 target/sp800185-arm.json
python3 scripts/sp800185/capture-sp800185-native.py apple-m2-aarch64 target/sp800185-m2.json
```

Run only the command matching the machine. An optional `riscv64-cloud` lane
records **native portable** behavior, not accelerated Keccak. Record emulator
runs separately as emulation; never label QEMU as native. The available slow
RISC-V server and unavailable hardware may receive an explicit reviewed
limitation instead of pretending that acceleration has been proved.

Capture refuses dirty trees, common target/compiler overrides, wrong lane
architecture/vendor and existing destinations. Each command has a 15-minute
bound and 2 MiB per-output-stream bound through the shared assurance runner.
The POSIX runner uses cooperative process groups for these trusted tools, not
a containment claim for malicious compilers or detached processes. Use a
trusted native checkout/toolchain; lane names and OS reports are operator
attestations, not hardware certification or proof that virtualization is absent.

Reports contain commit, compiler, OS/architecture, allowlisted vendor labels,
commands, stdout hashes, policy hash and results. Hostname, login, IP, CPU serial
and compiler stderr paths are not archived. Return the JSON under `target/`;
it stays gitignored until manually reviewed. Reports cannot admit a backend or
mark the family complete; their initial status is always `PENDING_REVIEW`.
Do not feed returned JSON paths or commands into a shell.

Benchmarks compare four identities at 16 KiB, B=1024, 1/2/4 workers, two warmup
and eight measured rounds with alternating execution order. They include thread
creation/join cost. Numbers are observations, not a speedup or constant-time
guarantee. The KMAC first/last mismatched-tag timing probe is one limited
heuristic, not general side-channel proof. Review noisy failures rather than
silently dropping them or weakening the threshold.

## Final closure checklist

- [x] Owner-supplied pentest PASS recorded for c58711b; no findings or remediation.
- [x] Same-commit AMD, Apple M2 and AWS AArch64 execution reports reviewed;
      Intel and RISC-V results or explicit unavailability dispositions recorded.
- [x] CPU candidates remain unadmitted; no cleanup-qualified accelerated
      SP 800-185 route is claimed. Changed admission requires new review.
- [x] Current compiler/target KMAC and shared hardened cleanup/codegen evidence,
      package acceptance, official examples and all four differential campaigns pass.
- [x] Rust 1.90.0–1.98.1, no_std target matrix, hosted std checks and repository
      gate pass; staged local dynamic-analysis requirements are satisfied.
- [x] Evidence binds the final implementation and fixture. Repeat affected
      checks after any source or expectation change; document metadata-only deltas.
- [x] Family table, permanent report and release status reconciled after technical
      acceptance. No independent-review or FIPS status is promoted.
- [ ] Green GitHub/CodeQL and explicit tag authorization. Publish nothing.

The [four native observations](../assurance/sp800185-observations/v0.24.17/README.md)
all bind f264a0351d4f8d86d056e7582986a297aee50672 and Rust 1.98.1. Each passed
540 comparisons, 24 bounded failures, worker-fault and conditional candidate
tests, twelve benchmark rows and the bounded tag-timing probe. RISC-V has an
explicit portable-only/no-native-observation disposition, not a claimed run.

The complete repository gate, twelve-version Rust matrix, three bare-metal
targets, supplemental QEMU checks, current standards/tool/dependency checks,
SBOM, AddressSanitizer, all seven full Miri groups and all 25 Kani proofs passed.
KMAC/shared cleanup codegen passed on x86_64 and AArch64 at Rust 1.90.0/1.98.1.
The Miri groups used the existing isolated-cache runner, with the remaining
groups run concurrently; no group was replaced by a smoke test.

Later evidence archival, release documentation and status-policy reconciliation
do not change production Rust, fixture Rust, test inputs, capture commands or
dependency resolution. Raw captures remain bound to their original policy hash,
not retrospectively relabeled as captures of this documentation commit.

Memory clearing remains limited to declared crate-owned regions during normal
execution/unwind. No register, spill, cache, DMA, swap, dump, abort, forced
termination or caller-copy erasure guarantee is added by this milestone.
