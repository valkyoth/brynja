# Packaged portable AES differential fixture

This host-only fixture uses the public AES re-export of the existing isolated
`aes-public-api` consumer. Its direct/facade dependencies come only from
byte-checked Cargo archives. It does not include production source modules,
change the implementation, introduce a mode API or add an OpenSSL dependency
to any published crate.

## Fixed coverage

For each AES-128/192/256 width:

- 64 deterministic public test keys, including all-zero and all-one keys.
- 32 blocks per key in each direction, with zero/one blocks and reproducible
  pseudorandom inputs. Inverse inputs are independently generated ciphertext,
  not ciphertext produced by the implementation under test.
- 4,096 reference cases through both ephemeral and cached owners. Forward
  cases check secret output and explicitly public ciphertext separately;
  inverse cases remain secret output only.
- Successful secret outputs and both key-storage forms are checked for
  clearing. Caller-created input/oracle copies are public fixture data and
  are not claimed erased.

The corpus generator is for reproducible testing, not cryptographic randomness.
Each compiler/import configuration runs debug and release. Per profile this is
12,288 reference cases, 24,576 secret-output comparisons across both owners,
plus 12,288 explicit-public encryption comparisons. The four registrations give
eight profiles and 294,912 output comparisons. Counts are not independent
random samples or a claim to cover all possible keys and blocks.

## Oracle boundary

The runner selects one absolute OpenSSL executable path, records its SHA-256
and version, checks all three published FIPS 197 examples in both directions,
and passes that exact executable to every consumer invocation. It requires
the executable hash to remain unchanged after both profiles. Ambient OpenSSL,
loader and CPU-capability overrides are rejected before packaging. The isolated
environment disables OpenSSL configuration for these synthetic comparisons.

The host, selected executable and system shared libraries are trusted. Hashing
the executable records identity, not authenticity or complete dynamic-library
closure. No signed attestation or new release receipt is required.

Every OpenSSL command uses argument arrays and public test keys only. Never
adapt this command-line oracle for application secrets. Registry execution
provides process-group cleanup and a bounded timeout; each Cargo subprocess
also has the archive helper's timeout. Failure, timeout, missing tests,
unexpectedly ignored tests, missing population markers or an oracle change
prevents overall success.

## Run explicitly

```sh
brynja-verify run aes packaged-diff-msrv-direct
brynja-verify run aes packaged-diff-msrv-facade
brynja-verify run aes packaged-diff-current-direct
brynja-verify run aes packaged-diff-current-facade
```

These select Rust 1.90.0/1.99.1 and direct/facade imports. The underlying command
is `python3 scripts/aes/check-aes-packaged-differential.py --toolchain 1.99.1 --route direct`.
Use a clean environment: if a launcher supplies `LD_LIBRARY_PATH`, explicitly
remove it for this command (`env -u LD_LIBRARY_PATH ...`), rather than weakening
the rejection policy or setting it to an empty string.

The runner requires exactly four executed Rust tests and nine comparison-count
markers per profile. Twelve Python runner controls join the existing registry
regression suite. Full comparison campaigns remain explicit and are not added
to the finite publication gate.

Results establish only scoped package/API correctness. They do not replace
fixed-versus-random timing, emitted-code review, target execution or physical
side-channel/fault qualification.
