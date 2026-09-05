# Brynja 0.24.16 Release Notes

Status: awaiting pentest

## Summary

Brynja 0.24.16 freezes and passes one package-external portable consumer
contract for all fourteen named NIST SP 800-185 instances: cSHAKE128/256,
KMAC128/256, KMACXOF128/256, TupleHash128/256, TupleHashXOF128/256,
ParallelHash128/256, and ParallelHashXOF128/256.

This milestone adds assurance code, documentation, and facade-version metadata.
It does not change the cryptographic implementations, admit a CPU backend, or
publish a crate. The combined SP 800-185 family remains **In progress** until
v0.24.17 reruns the byte-identical contract through every admitted or explicitly
unadmitted backend and parallel execution disposition.

## Deliverables

- Add the standalone `brynja-sp800185-public-api-fixture` package with a
  `#![no_std]` library and no registry, git, native, or C dependency.
- Exercise all fourteen identities directly through their owning leaf packages
  and compare representative cSHAKE, KMAC, TupleHash, and ParallelHash results
  through `brynja-crypto` and the `brynja` facade.
- Bind one exact official NIST output to every named identity while retaining
  the complete family-specific official-vector suites.
- Exercise ordinary one-shot and streamed input, fixed and incrementally
  partitioned XOF output, arbitrary-bit message and output tails, exact tuple
  item streaming, caller-scheduled ParallelHash leaves, zero-length inputs and
  outputs, positive `B = 1`, invalid `B = 0`, full-strength KMAC constructors,
  and explicitly feature-gated weak-key conformance.
- Compare every live hardened identity result with the ordinary/public API
  result for identical test inputs and output lengths, before verifying that
  each typed-secret destination—and each ParallelHash workspace—is cleared
  when its owner ends. Fixture inputs are public test data, not real secrets.
- Freeze a real package-owned input file, fixture source, lockfile, public
  status, release metadata, official-vector sources, independent differential
  entry points, Rust matrix, bare-metal matrix, and hosted lanes by SHA-256.

## Verification

- The runnable fixture reports 14 named identities, 14 exact official examples,
  14 hardened identity profiles, and three compared public package layers.
- cSHAKE128 and cSHAKE256 pass one-shot, irregular streamed input,
  multi-squeeze output, arbitrary-bit N/S/message/output, zero-output, and
  hardened typed-secret cleanup paths.
- KMAC128, KMAC256, KMACXOF128, and KMACXOF256 pass official outputs,
  streamed message and output, arbitrary-bit finalization, strength rejection,
  explicit conformance admission, and typed-secret cleanup.
- TupleHash128/256 and TupleHashXOF128/256 pass official outputs, structural
  item boundaries, exact-length item writing, incremental output, arbitrary-bit
  items/output, empty tuples, and all four hardened cleanup profiles.
- ParallelHash128/256 and ParallelHashXOF128/256 pass official outputs,
  streamed input, multi-leaf real data, caller-scheduled 128/256-bit leaves,
  incremental output, arbitrary-bit tails, empty input, `B = 1`, rejected zero
  `B`, and all four hardened output/workspace cleanup profiles.
- Existing independent cSHAKE, KMAC, TupleHash, and ParallelHash differential
  campaigns remain mandatory and hash-bound to the combined acceptance.
- The new fixture runs under every supported Rust 1.90.0–1.98.1 lane and is
  checked as a library on every declared `no_std` target.
- Twenty-six policy mutation cases reject missing identities, `std`, hardened coverage,
  conformance, streamed tuples, scheduled leaves, honest status, CI wiring, or
  reviewed-hash integrity, including removal of any live-output comparison.
- Forty-two compiled executable mutations (zero output, constant output and
  a flipped final bit for each of fourteen hardened profiles) must report the
  expected typed acceptance failure. Compilation failures do not count as
  successful rejection; pristine fixtures must pass before and after.

## Security And Residual Limits

- This milestone validates only documented public portable paths. It does not
  strengthen, replace, or independently verify the underlying cryptography.
- KMAC state and hardened cSHAKE, TupleHash, and ParallelHash states retain the
  previously reviewed compiler-resistant cleanup boundary. Ordinary unkeyed
  states remain unsuitable for secret-bearing input.
- The optional native ParallelHash executor is not part of this `no_std`
  portable fixture. Its deterministic final acceptance belongs to v0.24.17.
- All Keccak CPU candidates remain unadmitted. No accelerated result is counted
  as passing portable acceptance.
- Brynja has no named independent cryptographic verification or FIPS 140-3
  validation, and it still has no usable TLS or certificate-validation engine.

## Release Process

Version 0.24.16 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range. It selects zero crates for crates.io publication.
The milestone does not contain a scheduled-pentest trigger because it changes
only downstream assurance and documentation; any repository-owner assessment
before tagging is voluntary. Tag authorization still requires the committed
review disposition, the complete local gate, and green GitHub and CodeQL.
