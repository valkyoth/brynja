# Brynja 0.4.0 Release Notes

Status: implementation stop reached; pentest required

Brynja 0.4.0 establishes first-party assurance infrastructure and a true
OS-less compile matrix. It does not implement TLS, cryptography, PKI, QUIC,
DTLS, platform services, or legacy protocols and must not be used to secure
network traffic.

## Bounded First-Party Harnesses

The deterministic mutation runner accepts public test bytes and emits a stable,
deduplicated sequence covering:

- empty and original inputs;
- every bounded truncation and single-byte deletion;
- every bounded single-bit flip; and
- zero and `0xff` insertion at every bounded offset.

Every failure reports its replay index and SHA-256 without automatically
persisting input. The policy caps input bytes, each output stream, case count,
and wall-clock time.

The differential runner sends the same raw bytes to at least two distinct
external process adapters. Each adapter must return exactly one canonical JSON
object containing an `accept`, `reject`, or `unsupported` class and lowercase
hexadecimal output. Crashes, timeouts, output floods, malformed or
noncanonical results, invalid classes, duplicate adapters, and differences
fail closed.

Processes are launched without a shell, and stdout and stderr are bounded
concurrently while produced. Each adapter starts in an isolated POSIX session
or a suspended Windows process assigned to a kill-on-close Job Object before
execution. Direct-parent completion, timeout, overflow, and cleanup terminate
the complete tree, including descendants holding output pipes.

Seeds and corpus entries use descriptor-bound, no-follow or reparse-point
rejecting, limit-plus-one reads from already-open regular files. Corpus
enumeration is case-bounded and differential cases execute one at a time, so
policy limits apply before allocation and total corpus size is not resident in
memory. Generated mutation cases likewise execute one at a time while
preserving the original exact deduplicated order. The runners do not claim to
provide an OS sandbox; campaign launchers must independently deny network
access and unwanted filesystem, process, and device capabilities.

## Bare-Metal Matrix

CI and the v0.4.0 release gate compile the complete all-feature workspace for:

- `thumbv7em-none-eabi`;
- `riscv32imac-unknown-none-elf`; and
- `x86_64-unknown-none`.

These are compile claims only. They do not supply an allocator, startup,
interrupts, entropy, time, transport, storage, device access, linker image,
emulator, hardware evidence, or an Aesynx support claim.

## External Tool And Kani Policy

The machine-readable policy pins exact upstream versions and revisions for
Kani 0.67.0, AFL++ 5.02c, honggfuzz 2.6, Miri, and Rust sanitizers. Networked
release checks verify the three released Git tags. All five tools remain
outside repository Cargo manifests and outside shipped dependency graphs.

Brynja follows the established `base64-ng` verifier model:

- normal builds and releases use stable Rust 1.97.1;
- the supported crate range remains Rust 1.90.0 through 1.97.1; and
- Kani 0.67.0 uses its separately documented compatible Rust 1.90.0 verifier
  pairing.

No Kani proof harness is admitted at v0.4.0. The policy check explicitly
reports that state, and no formal-verification claim is permitted. Later
arithmetic and cryptographic milestones introduce scoped bounded harnesses;
v0.155.0 completes their claim and residual-gap register.

## Verification

The release candidate includes:

- 40 assurance policy, mutation, differential, process, input, target, and
  tool-pin positive and broken fixtures;
- deterministic byte-for-byte assurance evidence generation;
- a fail-closed independent cryptography and protocol review-status register
  in the root, published facade, and every applicable component README,
  including an explicit statement that no FIPS 140-3 validation exists;
- prospective commit classification that prevents documentation, policy,
  evidence, test, or tooling-only remediation from masquerading as a Rust
  `fix:` or pentest-code change;
- exact CI membership checks for all three OS-less targets;
- Cargo-manifest exclusion checks for every external assurance tool;
- simultaneous process-output exhaustion and timeout tests;
- parent-exit pipe retention, descendant timeout, descendant output flood, and
  post-termination descendant-survival tests;
- limit-plus-one file-read, oversized-file, symlink/reparse, bounded
  enumeration, and one-case corpus-streaming tests;
- explicit 30-second bounds on local Rust target and remote Git tag probes;
- the existing 167-requirement, 126-authority, and 4,424-surface normative
  baseline;
- no external Cargo packages and `no_std` production packages;
- Rust 1.90.0 through 1.97.1 compatibility; and
- source files no larger than 500 lines.

## Publication

Only `brynja 0.4.0` is selected for crates.io publication. All unchanged
supporting crates retain their independently published `0.1.0` versions and
are not republished. Legacy and repository-only crates remain unpublished.

Publication remains blocked until the repository-owner pentest is complete,
the permanent committed report records `PASS`/`PASS` with zero open findings,
GitHub checks are green, and the user explicitly authorizes tagging.

## Limitations

This milestone establishes harness and compile infrastructure, not successful
protocol fuzzing, differential interoperability, Kani proof, Miri, sanitizer,
side-channel, or cryptographic campaign evidence. Every later implementation
must add scoped corpora, independent adapters, proofs, campaign reports,
residual gaps, and external review at its owning milestone.
