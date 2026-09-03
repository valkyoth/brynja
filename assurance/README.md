# Assurance Harness And Bare-Metal Matrix

Status: v0.4.0 assurance foundation released; v0.12.0 emitted-code and v0.13.0-v0.13.3 provider/CPU evidence added

This directory freezes the first-party assurance boundary before protocol or
cryptographic implementation begins. It is infrastructure evidence, not proof
that TLS exists or is secure.

The v0.22.3 `sha256-public-api` fixture is a standalone downstream `no_std`
consumer of only documented public APIs. It checks authoritative real inputs,
one-shot and irregular streaming, explicit backend reporting and skips,
message-length exhaustion, and the same behavior after installation from
safely extracted package artifacts. Packaging runs offline in an isolated
four-crate workspace with an empty Cargo home, so unrelated workspace packages
and a warm registry index cannot satisfy the gate. Its negative harness proves
that the gate rejects corrupted digests, missing exports, backend misreporting,
exhaustion bypass, an unadmitted feature, and altered package contents. This is
usability acceptance, not independent cryptographic review or FIPS validation.

The v0.23.4 `sha2-public-api` fixture extends that package-external acceptance
to all six SHA-2 algorithms through both the leaf and main facade. It checks 30
one-shot and 36 irregular-streaming results, exact identities and output
widths, deterministic exhaustion, and all five optional candidate
dispositions. Its isolated empty-home packaging closure contains exactly the
15 required first-party archives. Negative fixtures independently corrupt
each algorithm expectation and reject API, documentation, width, backend,
feature, and package-content gaps. It establishes public usability, not
independent cryptographic review, FIPS validation, accelerated admission, or
secret-state erasure.

The v0.24.0-v0.24.2 `sha3-differential` fixture is an isolated repository-only
host adapter. It feeds 328 deterministic public messages through all four
public SHA-3 digest APIs and both public SHAKE XOF APIs, then compares every
result with Python's independently maintained `hashlib` implementation. The
corpus spans every length from zero through 320 bytes plus larger block and
file-like boundaries and SHAKE outputs from zero through 343 bytes. The Rust
stdin boundary independently enforces that 343-byte ceiling, an 8 MiB input
ceiling, and the exact 1,968-case campaign size; decode and render allocations
are fallible, and clean rejection covers 344, `usize::MAX`, numeric parse
overflow, oversized aggregate input, and excess valid cases. Every child run
has a 240-second timeout.
This is differential correctness evidence, not package-external acceptance,
independent cryptographic review, side-channel evidence, or FIPS validation.
Run it with `python3 scripts/sha3/check-sha3-differential.py`.

The v0.24.6 `api-profile-contract` fixture is a standalone zero-dependency
`no_std` consumer of the real `brynja-core` secret-region lifecycle. It proves
the hardened capability is sealed against downstream implementations,
ordinary-state substitution and wrapper forgery; distinguishes explicit public
declassification from typed secret output; preserves public destinations on
failure; clears partial secret output; and clears successful owners on Drop and
recoverable panic unwinding. The surrounding policy admits no capability owner
implicitly: current owners must pass adjacent compiler contracts for exact
types, private fields and sanitizer signatures plus exact optimized-MIR cleanup
targets under Rust 1.90.0 and 1.98.0; every future registration must match a
separate canonical compiler contract; three exact-coverage identity maps
derive its unique owner-specific adjacent test, nonempty caller headers, and
nonempty declared-sanitizer MIR target; strict future-owner MIR data-flow binds
the cleanup receiver to `_1` and requires cleanup dominance over every exit;
the registered capability-owner set is explicitly
empty; and every secret-producing operation has its own fail-closed
information-flow contract. Twenty-five structural mutations and twenty-two
secret-output downgrade mutations, lexical raw/cfg/macro/same-name fixtures,
ten empty/target/data-flow/dominance and twenty-two registered identity/namespace/coverage mutations
exercise those boundaries. It is
architectural assurance, not a hardened
hash implementation, independent review, or FIPS validation.

The v0.24.3 `sha3-public-api` fixture is the frozen package-external portable
consumer for all four SHA-3 digests and both SHAKE XOFs. It checks 24 fixed-
output, ten XOF and twenty incremental-squeeze results through leaf and facade
APIs over official examples, independent real content, exact and multiple
rates, zero output, checked exhaustion and domain separation. It packages the
exact sixteen-package closure in an empty Cargo home, validates safe archive
contents, and reruns offline with version-only dependencies. Negative fixtures
reject six corrupt outputs plus API, rate, zero-output, failure, domain, path,
feature, phase, private-module and package regressions. This freezes portable
byte-oriented usability for v0.24.4 and feeds the later complete v0.24.11 API
gate; it is not acceleration, independent review, secret-state erasure, or
FIPS validation. Its standalone forbidden Clippy lints run
with warnings denied in both the complete local gate and hosted CI.

The v0.24.11 `hash-final-acceptance` fixture links the complete SHA-2,
SHA-3/SHAKE, and hardened FIPS 202 downstream consumers into one `no_std`
program. It requires all twelve identities, both hardened-owner claims, and
the exact seven-candidate/zero-admission backend disposition to pass together.
The surrounding `scripts/hash` policy binds the separately packaged fixtures,
supported Rust and target matrices, standards surfaces, normative
requirements, secret-owner evidence, public status tables, and residual
independent-review/FIPS statements before either family can remain marked
Fully implemented.

The v0.13.0 provider contract adds a separate hash-locked source validator and
thirteen broken fixtures through `scripts/foundations/check-provider-contract.py` and
`scripts/foundations/test-provider-contract.py`. The additional remediation fixtures reject
request-side result construction, exact-provider detachment, caller-supplied
work claims, and verification byte output. That policy enforces authority and
dependency structure; it is not provider-effect, algorithm, interoperability,
or formal-verification evidence.

The v0.13.1 CPU-backend contract adds a separate four-file hash-locked source
validator and thirteen broken fixtures through
`scripts/cpu/check-backend-contract.py` and
`scripts/cpu/test-backend-contract.py`. It rejects ISA execution, public evidence
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
zero-admission register, a deterministic ledger, and 55 broken evidence
fixtures. Exact machine-readable artifact semantics and backend-specific
operating state are enforced, while candidate and native claims remain
forbidden until a separately reviewed trusted-runner verifier exists. Its
dependency-free `no_std` state fixture exercises scalar,
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
until their owning later milestones. The local pre-tag gate executes the pinned
Miri and AddressSanitizer toolchain against the registered zeroization and hash
coverage. Ordinary GitHub CI validates the exact scripts, tool pins, coverage
bindings, mutations, and emitted-code matrices but does not execute the full
dynamic-analysis suites, whose runtime exceeds the bounded hosted-CI window.
That local evidence does not establish constant-time behavior, physical
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
python3 scripts/sha2/check-sha256-public-api.py
python3 scripts/sha2/test-sha256-public-api.py
python3 scripts/assurance/check-assurance.py
python3 scripts/assurance/test-assurance.py
scripts/assurance/check-bare-metal.sh
scripts/zeroization/check-zeroization-miri.sh
scripts/zeroization/check-zeroization-sanitizer.sh
python3 scripts/constant-time/check-constant-time.py
python3 scripts/constant-time/test-constant-time.py
scripts/constant-time/check-constant-time-codegen.sh 1.98.0 x86_64-unknown-linux-gnu
python3 scripts/constant-time/test-constant-time-codegen.py
python3 scripts/constant-time/check-constant-time-evidence.py
python3 scripts/constant-time/test-constant-time-evidence.py
python3 scripts/foundations/check-provider-contract.py
python3 scripts/foundations/test-provider-contract.py
python3 scripts/cpu/check-backend-contract.py
python3 scripts/cpu/test-backend-contract.py
python3 scripts/cpu/check-cpu-evidence.py
python3 scripts/cpu/test-cpu-evidence.py
scripts/cpu/check-cpu-admission-fixture.sh
```
