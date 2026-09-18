# In-place SHA-3 downstream probes

The four reference-only wrappers accept caller-owned workspaces, use the public
scoped API, and destroy typed secret output before return. The test also checks
the SHA3-256 `abc` known answer. No unsafe code or new external dependency.

Run `cargo test --locked --offline --manifest-path assurance/register-cleanup/in-place-sha3/Cargo.toml`.
The adjacent `check_in_place_sha3.py` driver copies the real crate into temporary
storage and requires six independently compiled lifecycle/output mutants to fail
at runtime in both debug and release. It never modifies production sources.

Emit this fixture's MIR/LLVM/assembly to inspect the borrowed-workspace ABI.
Passing tests or the absence of an owner-sized move in one compiler build do
not qualify whole-API register/spill erasure. Native platform qualification and
remaining framing work are separate. No release workflow changes.
