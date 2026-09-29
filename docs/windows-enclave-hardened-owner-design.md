# Scoped hardened-owner enclave experiment

This v0.24.50 research step replaces the ordinary hash in the previous
[public-vector experiment](windows-enclave-sha256-results.md) with the existing
`hardened_in_place::Sha256Workspace` and `SecretRegionInitialization` APIs.
Production implementations and release gates are unchanged. Windows strict
remains unsupported; no confidential input is accepted by this experiment.

## Bounded ownership model

The entry accepts only a fixed public mode and scaffold-provided window bounds,
not a host data pointer, key, arbitrary callback or requested length. It creates
workspace, 1024-byte input and 33-byte output storage inside the existing guarded,
locked 64 KiB window. All three complete ranges must be inside the window; the
runner also rejects overlapping reported ranges. A local public template generates
the same twenty independently checked SHA-256 messages as the earlier experiment.
The template is not confidential input and is not a protected-input protocol.

Each operation initializes typed input ownership, borrows its message prefix and
enters the existing workspace scope. Only public diagnostic counts, addresses and
pass/fail flags leave the enclave; neither the hash state nor the digest is exported.
The successful mode hashes each message with both whole-message and seven-byte
updates, obtaining a secret output owner after workspace scope exit. It checks
the public expected digest, drops the output, verifies the destination is zero,
drops input ownership and verifies the entire input is zero. The workspace is
checked separately before input/output guards or the outer window can hide defects.

Other modes perform genuine state cancellation, reject a 33-byte secret destination
with `OutputLength` (checking the whole rejected destination is cleared), or
deliberately forget the state handle (checking the independent scope guard clears
its owner). Each runs all twenty messages. A final buffer guard clears input/output
storage on early exits but cannot turn a failed inner check into success.

## Narrow inspection safety

The workspace is opaque to ordinary consumers. This experiment alone inspects its
initialized bytes through a live shared reference after the exclusive scope ends.
That unsafe read is justified by the exact reviewed source layout: eight fully
initialized byte arrays totaling 1170 bytes, wrapped only in zero-sized
`PhantomData`. The builder rejects any different field model; Rust compile-time
checks require size 1170 and alignment 1, excluding padding in this specific layout.
Layout mutation tests reject added/changed fields. This is not a general opaque-
object inspection helper or a new public API. A layout change requires fresh review,
not relaxing the assertions. No read occurs after object destruction.

## Controls and limits

Four separately built Rust archives cover the normal worker, a forgotten output
owner, forced digest-comparison failure and an early-return mutant in the actual
SHA-2 owner's `wipe`. Only the generated mutant fixture copy changes, never repository
production source. Its mutation and bytes are recorded in the build manifest.
The unchanged assembly missing-outer-clear control remains separate. Inner failures
must remain failures even if the enclosing window subsequently clears successfully.

Local tests compile and run the normal worker and all three Rust mutants. Native
execution must additionally establish ABI, actual address ranges, page locking,
guard restoration, repeated calls and teardown. The C exception control completes
before Rust entry; `panic=abort` has no cleanup claim. This is not a Rust unwind,
concurrency, secret-ingress/egress, full-worker dump or production-signing test.

The existing baseline hardened compression and borrowed-transfer kernels are used
without optional hardware features. Their normal-return working-register contract
does not erase arbitrary caller registers, saved registers, compiler copies or
interrupt snapshots. Enclave runtime, TLS, callback and platform coverage remain
separate obligations. None of these experiments changes the strict facade's
unsupported result on Windows.
