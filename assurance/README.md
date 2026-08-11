# Assurance Harness And Bare-Metal Matrix

Status: v0.4.0 assurance foundation released; v0.12.0 emitted-code and v0.13.0-v0.13.3 provider/CPU evidence added

This directory freezes the first-party assurance boundary before protocol or
cryptographic implementation begins. It is infrastructure evidence, not proof
that TLS exists or is secure.

The v0.13.0 provider contract adds a separate hash-locked source validator and
thirteen broken fixtures through `scripts/check-provider-contract.py` and
`scripts/test-provider-contract.py`. The additional remediation fixtures reject
request-side result construction, exact-provider detachment, caller-supplied
work claims, and verification byte output. That policy enforces authority and
dependency structure; it is not provider-effect, algorithm, interoperability,
or formal-verification evidence.

The v0.13.1 CPU-backend contract adds a separate four-file hash-locked source
validator and thirteen broken fixtures through
`scripts/check-backend-contract.py` and
`scripts/test-backend-contract.py`. It rejects ISA execution, public evidence
forgery, thread-token drift, atomics/global state, stale generations,
resettable quarantine, unsupported-operation dispatch, recursive fallback,
validated-policy substitution, registries, and unreviewed source changes. It
does not provide a CPU probe, backend implementation, KAT corpus, concurrency
model checker, native-host result, performance evidence, or FIPS validation.

The v0.13.2 boundary reserves two inert CPU packages and eight exact future
kernel locations while granting zero executable or low-level authority. The
v0.13.3 evidence layer adds a separately hash-bound schema, five native and
three QEMU supplemental lanes, thirteen correctness, negative, fault,
code-generation, performance, and side-channel harness contracts, an explicit
zero-admission register, a deterministic ledger, and 39 broken evidence
fixtures. Its dependency-free `no_std` state fixture exercises scalar,
positive mock, unsupported, required-mode, KAT, quarantine, differential, and
independent-session behavior on host and OS-less targets. These are admission
contracts only: no native result, benchmark, side-channel result, CPU detector,
ISA kernel, cryptographic primitive, unsafe allowance, performance claim, or
FIPS approval exists.

`policy.toml` defines bounded deterministic mutation, raw-stdin differential
adapters, OS-less compilation targets, and exact external-tool source pins.
`evidence.json` is generated from that policy and the scripts, workflows, and
Cargo manifests that enforce it.

The harness protocol sends one bounded raw byte string to a child process on
standard input. A differential adapter returns exactly one canonical JSON
object:

```json
{"class":"accept","output":"00ff"}
```

`class` is `accept`, `reject`, or `unsupported`; `output` is lowercase
even-length hexadecimal. Adapters run without a shell, under a timeout and
input/output caps. A nonzero exit, timeout, malformed result, excess output, or
difference between implementations fails closed. Campaigns must use at least
two independently maintained implementations and record exact executable
hashes separately.

On Windows, each adapter starts suspended and enters a kill-on-close Job Object
before it can execute; native Windows CI exercises this path. On POSIX, the
runner starts a separate session and kills its process group, but a hostile
descendant can call `setsid()` and leave that group. The POSIX group is
therefore cooperative defense-in-depth, not complete tree containment.

Hostile POSIX execution fails closed unless `--tree-containment` names an
externally enforced `linux-cgroup-v2`, `pid-namespace`, `container-vm`, or
`fork-setsid-denied-sandbox` boundary. The option is a launcher contract, not
proof that containment exists; campaigns must retain configuration and
operational evidence for the named boundary. A loudly named test-only
cooperative mode is available only to the internal fixture API and is rejected
by production command-line runners.

Harness input is public test data, never a secret. The runners do not claim to
provide an OS sandbox: every campaign launcher must independently deny network
access and unwanted filesystem, process, and device capabilities.

Seed and corpus inputs are opened before inspection, must be regular files, and
reject symlinks or Windows reparse points. Reads request at most the configured
limit plus one byte, corpus enumeration stops at the case limit, and
differential and generated mutation cases execute one at a time rather than
being accumulated in memory.

Repository assurance probes are bounded as well: local Rust target discovery
and each remote Git tag query have an explicit 30-second timeout. Expiration
fails the check instead of leaving development or release automation hanging.

Mutation order is deterministic and deduplicated. The runner covers the empty
case, original input, every bounded truncation, byte deletion, bit flip, and
zero/`0xff` insertion until the policy case limit. A failing case is identified
by SHA-256 and replay index; the runner does not persist input automatically.

The bare-metal matrix builds the complete workspace with all features for:

- `thumbv7em-none-eabi`;
- `riscv32imac-unknown-none-elf`; and
- `x86_64-unknown-none`.

These are OS-less compile claims only. They do not provide entropy, time,
transport, storage, allocation, interrupts, startup code, or an Aesynx support
claim.

The tool entries are exact source-policy pins, and no tool may enter a
repository Cargo manifest. Kani and the process fuzzers remain policy-only
until their owning later milestones. Version 0.11.0 executes the pinned Miri
and AddressSanitizer toolchain only against the owned-region zeroization tests;
that narrow evidence does not establish constant-time behavior, physical
erasure, protocol security, or independent verification. The latest-tools gate
compares both nightly tools to the current official Rust nightly manifest and
requires Miri to be available for the evidence host.

Version 0.12.0 adds a standalone `no_std` constant-time code-generation
witness, a machine-readable ten-compiler/nine-target evidence matrix, and
optimized LLVM/assembly inspection for word and fixed 32-byte equality,
selection, swap, and the compiler barrier. The checker rejects panic and
variable-work library calls, target-specific conditional branches in non-array
witnesses, forward/non-public array branches, direct RV32 Choice-register
branches or memory addressing, and missing barrier fences. RISC-V argument
register aliases are canonicalized and all eighteen base, pseudo, and compressed
conditional forms are classified. Ten focused negative target-assembly
fixtures reproduce branch, address, alias, and loop-classification regressions.
The witness is deliberately small and reproducible; it is not a proof of every
monomorphization, a
statistical timing test, independent review, or a claim about caches,
speculation, power, electromagnetic leakage, or another microarchitecture.

Run:

```bash
python3 scripts/check-assurance.py
python3 scripts/test-assurance.py
scripts/check-bare-metal.sh
scripts/check-zeroization-miri.sh
scripts/check-zeroization-sanitizer.sh
python3 scripts/check-constant-time.py
python3 scripts/test-constant-time.py
scripts/check-constant-time-codegen.sh 1.97.1 x86_64-unknown-linux-gnu
python3 scripts/test-constant-time-codegen.py
python3 scripts/check-constant-time-evidence.py
python3 scripts/test-constant-time-evidence.py
python3 scripts/check-provider-contract.py
python3 scripts/test-provider-contract.py
python3 scripts/check-backend-contract.py
python3 scripts/test-backend-contract.py
python3 scripts/check-cpu-evidence.py
python3 scripts/test-cpu-evidence.py
scripts/check-cpu-admission-fixture.sh
```
