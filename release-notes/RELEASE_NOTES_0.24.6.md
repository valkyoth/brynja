# Brynja 0.24.6 Release Notes

Status: implementation and complete local repository verification passed;
pentest and the signed candidate commit remain pending; no crates.io
publication is selected

Brynja 0.24.6 turns cryptographic API completeness and private secret-state
cleanup into a deterministic, fail-closed design contract. It changes no
production cryptographic implementation or runtime behavior.

## Added

- A reviewed machine-readable policy assigning all 129 current semantic
  cryptographic and protocol capabilities to one of 13 exact profile classes.
- Twenty-two API dimensions for every capability, including operation
  direction, byte and bit input, one-shot and incremental use, fixed and XOF
  output, verification, buffers, overlap, ownership, provider/backend use,
  `no_std`, hosted adapters, import, export, generation, reset, clone, snapshot,
  and cancellation.
- A generated JSON register and concise human-readable projection containing
  seven implemented, 117 future, three legacy-only, one intentionally rejected,
  and one safely ignored capability disposition.
- An exact inventory of eight current secret owners and 75 planned secret
  owners. Every owner binds fields, temporaries, lifecycle exits, mandatory
  cleanup symbols, output classification, evidence, consumers, and residual
  risks.
- Explicit ordinary-versus-hardened ownership separation. Hardened capability
  markers are sealed and cannot be implemented, wrapped, or forged downstream.
- Explicit public declassification and typed secret-output paths. Failed public
  output remains unchanged; failed partial secret output is cleared.
- Non-panicking cleanup requirements for success, error, cancellation,
  replacement, rekey, failed construction, recoverable panic unwinding, and
  `Drop`, including adjacent cleanup failures.
- Exact residual disclosures for `mem::forget`, process abort, forced
  termination, power loss, registers, caches, OS snapshots, DMA-visible copies,
  concurrency, compiler-created copies, and hardware-visible memory.

## Verification

- Deterministic regeneration checks the reviewed policy against the exact
  129-capability protocol-surface authority and reproduces both generated
  projections byte-for-byte.
- Fifteen mutation cases reject a missing capability, API dimension, bit
  domain, hardened owner, field, temporary, lifecycle edge, cleanup symbol,
  evidence artifact, consumer, rejection, residual, source hash, semantic
  capability, or mandatory-core-cleanup guarantee.
- Removing the optional `brynja-sanitization` adapter still leaves every
  mandatory cleanup duty bound to Brynja's dependency-free core volatile
  clearing primitive. The adapter cannot enter the FIPS graph or replace core
  cleanup.
- A standalone zero-dependency `no_std` fixture proves the sealed hardened
  capability cannot be forged by an ordinary state or wrapper, exercises
  explicit public and typed-secret output, preserves public output on failure,
  clears partial secret output, and clears successful secret ownership during
  `Drop` and recoverable panic unwinding.
- The fixture compiles for `thumbv7em-none-eabi` and uses the real
  `brynja-core` secret-region lifecycle rather than a mock zeroizer.
- Reviewed source hashes bind every current secret owner, the ordinary SHA-2
  and SHA-3 state owners whose hardened closures remain planned, and the new
  executable assurance contract.
- The release audit refreshed Miri and Rust sanitizer evidence to the latest
  available `nightly-2026-09-01` at exact Rust revision
  `0dfb098f3aeecbe38c2566ca090193280e7349e7`.

## Security Boundaries

This milestone is a design and assurance closure register. It does not make an
ordinary hash state secret-safe, implement a hardened SHA owner, add an
algorithm, admit a CPU backend, add a dependency, expand unsafe Rust, establish
independent cryptographic review, or create a FIPS 140-3 validation claim.
SHA-2 and SHA-3/SHAKE remain **In progress** until their separately owned bit
input, hardened ownership, backend, and combined acceptance milestones pass.

The mandatory core clearing primitive remains the authoritative cleanup path.
The optional `brynja-sanitization` adapter is separately selected and may only
provide equivalent fixed-region ownership; its absence cannot weaken any
secret-bearing construction.

## Release Process

Version 0.24.6 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range. It advances only the facade version and selects zero
crates.io packages. The repository-only scope does not schedule a pentest
unless an exceptional trigger or voluntary review is applied. Complete local
repository verification has passed. The pentest, signed candidate commit,
green hosted GitHub and CodeQL, and then the signed immutable tag remain
required.
