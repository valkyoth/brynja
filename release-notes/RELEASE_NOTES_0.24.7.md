# Brynja 0.24.7 Release Notes

Status: implementation and local verification complete; exceptional pentest,
final repository gate, hosted GitHub and CodeQL, and signed tag pending; no
crates.io publication is selected

Brynja 0.24.7 completes the FIPS 180-4 arbitrary-bit input domain for SHA-224,
SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256. Existing byte APIs and
digest identities remain unchanged. The SHA-2 family remains **In progress**
until the separate hardened-state and combined acceptance work in
v0.24.8-v0.24.11 passes.

## Added

- An allocation-free borrowed `BitString` in `brynja-hash-core`. Empty,
  byte-aligned, and partial-byte inputs have distinct canonical widths;
  partial message bits occupy the high end of the final byte and every unused
  low bit must be zero.
- Portable `sha224_bits`, `sha256_bits`, `sha384_bits`, `sha512_bits`,
  `sha512_224_bits`, and `sha512_256_bits` one-shot functions.
- Consuming `finalize_bits` methods on every streaming state. Complete-byte
  prefixes continue through `update`; only the terminal call may carry a
  partial byte, making repeated partial tails and absorption after the tail
  unrepresentable in safe Rust.
- Matching forced-backend bit functions and `finalize_bits_with_backend`
  methods behind the existing optional `cpu` feature. They do not admit a
  backend or alter ordinary scalar selection.
- Exact `MAX_MESSAGE_BITS`, `message_bits`, and transactional
  `check_additional_bits` surfaces using checked 64-bit accounting for
  SHA-224/SHA-256 and checked 128-bit accounting for the SHA-512 family.
- Reexports through `brynja-crypto` and `brynja`, public examples, package
  contents, and a separately runnable downstream `no_std` consumer.

## Authoritative And Independent Evidence

- The test fixture contains 240 exact records selected from NIST CAVP's
  official `shabittestvectors.zip` archive, whose SHA-256 is
  `cd7b9f11680c6e0ccdbe13b28403f2017b5ff48789152162461e0a24fb4c5d45`.
  Each of the six identities has 40 records and covers every bit-length
  residue from zero through seven, empty input, the relevant final-padding
  transition, exact-block input, and multiblock input.
- A bounded zero-dependency Rust adapter is compared with a separately written
  Python SHA-2 oracle over 1,008 results. Its campaign covers small bit lengths,
  both block widths, both length-field boundaries, multiblock inputs, and
  deterministic arbitrary messages up to 4,096 bits; malformed and oversized
  requests, including oversized physical lines and numeric overflow, fail
  closed before unbounded allocation.
- Every byte-aligned bit API is compared with its frozen byte API. Every
  compiled candidate path is compared with portable output for partial tails;
  ordinary builds still execute zero accelerated backends.
- The package-external fixture checks eighteen exact results: leaf one-shot,
  facade one-shot, and incremental final-tail use for each identity.
- Two new Kani harnesses prove that the 64-bit and 128-bit exact bit-length
  helpers accept exactly the corresponding checked multiplication and
  addition domains. The complete local inventory is eleven SHA-2/SHA-3
  harnesses on the separately pinned verifier toolchain.
- Focused Miri and AddressSanitizer runs include the arbitrary-bit suite. The
  complete supported Rust, target, bare-metal, Clippy, documentation, package,
  dependency, source-policy, and repository gates remain mandatory.

## Security Boundaries

`BitString` has private storage metadata and intentionally does not implement
`Debug`. Construction rejects invalid final widths and nonzero unused bits
before the hash state changes. Exact message-length checks happen before
absorption. The implementation adds no allocation, foreign ABI, C code,
assembly, unsafe block, operating-system call, I/O, mutable global, runtime
detector, provider effect, or third-party dependency.

These are ordinary unkeyed hash states. They do not guarantee erasure of
buffered input, chaining words, schedules, block copies, compiler-created
copies, registers, caches, dumps, or suspend images. Callers cannot erase the
private state themselves. Secret-bearing SHA-2 use remains prohibited until
the distinct hardened owners and compiler-resistant internal cleanup planned
for v0.24.8 pass. This milestone does not establish collision resistance by
testing, independent cryptographic review, CPU-backend admission, FIPS 140-3
validation, or an approved operational environment.

## Release Process

The new public bit-input and padding behavior is an exceptional pentest trigger.
Version 0.24.7 is otherwise an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates.io packages. After the
exceptional assessment and any required retest are permanently recorded, the
exact report-bearing commit must pass the complete local gate plus hosted
GitHub and CodeQL before the signed tag is authorized.
