# In-place SHA-3 downstream probes

The eight reference-only wrappers accept caller-owned workspaces, use the public
scoped API, and destroy typed secret output before return. They cover fixed
SHA-3 plus SHAKE/cSHAKE absorption-to-reader transfers. Tests also check
SHA3-256 `abc` and SHAKE128 empty-message known answers. No unsafe code or new
external dependency.

Run `cargo test --locked --offline --manifest-path assurance/register-cleanup/in-place-sha3/Cargo.toml`.
The adjacent `check_in_place_sha3.py` driver copies the real crate into temporary
storage and requires six fixed-output and eight XOF compiled mutants to fail
at runtime in both debug and release. It never modifies production sources.

The optional `execution` feature adds eight borrowed-workspace wrappers for
explicit Keccak sessions, including absorbing-to-reader transfers for both
SHAKE and cSHAKE widths. `hosted` additionally tests available runtime authority
and reader revocation. The cSHAKE consumer checks a NIST known answer.
`BRYNJA_REQUIRE_SCOPED_KECCAK=1` requires the static route;
`BRYNJA_REQUIRE_SCOPED_KECCAK_HOSTED=1` requires the hosted route. These prevent
counting a missing backend as accelerated execution coverage.

The driver's `--native-x86` mode validates the Linux AVX2 inventory, rejects
eight fixed-output execution and ten XOF execution mutants in both profiles,
and tests the packaged accelerated consumer. Native x86 and QEMU Arm results
remain distinct; the latter cannot qualify native Arm deployment.

Emit this fixture's MIR/LLVM/assembly to inspect the borrowed-workspace ABI.
Passing tests or the absence of an owner-sized move in one compiler build do
not qualify whole-API register/spill erasure. Native platform qualification and
remaining framing work are separate. No release workflow changes.
