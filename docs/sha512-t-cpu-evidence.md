# General SHA-512/t ordinary CPU integration

v0.24.29 adds explicit ordinary APIs under both `general-sha512-t` and `cpu`
features of `brynja-hash-sha2`. Parameter validation and IV derivation remain
portable. Message blocks and padding use the existing SHA-512 session/kernel;
the public digest retains t and canonical MSB-first unused-bit handling.

| Operation | API |
| --- | --- |
| Byte one-shot | `sha512_t_with_backend` |
| Bit one-shot | `sha512_t_bits_with_backend` |
| Streaming update | `Sha512T::update_with_backend` |
| Consuming byte finish | `Sha512T::finalize_with_backend` |
| Consuming bit finish | `Sha512T::finalize_bits_with_backend` |

These operations return `Sha512TAcceleratedError`, preserving backend/length
errors separately from digest-rendering errors. They never silently fall back
after an explicit CPU request. Ordinary byte updates can mix portable and CPU
calls: state identity and byte count stay the same. Finalization consumes the
state even on error. Ordinary state/output is public-data-only, not erased.

All CPU candidates remain **unadmitted**. Normal builds cannot construct a
session, even with target features supplied. The private assurance build uses
the existing `brynja_cpu_evidence` cfg; applications must not use that override.
Hardened states have no CPU API and remain portable-only. No automatic runtime
detector, migration guarantee, new kernel, ISA support or unsafe block is added.

## Reproducible candidate checks

```sh
python3 scripts/sha2/test-general-sha512-t-cpu.py
python3 scripts/sha2/general_sha512_t_cpu.py
```

The second command needs the repository's AArch64 MUSL and RV64 GNU targets,
QEMU runners and RISC-V linker. It executes all 4590 frozen independent vectors
across all 510 t in debug and release, byte/bit one-shots and three irregular
stream partitions. Native and QEMU campaigns also check that ordinary builds
reject activation, inject startup-KAT failure in a disposable copied CPU crate,
and require every new operation to reject quarantine without silent fallback.
Failed updates preserve the previous portable state. QEMU additionally compiles
three portable-fallback mutants in each profile and requires runtime rejection.
These controls do not alter the production CPU source or its admission register.

The fixed benchmark measures 32 ordinary accelerated operations on 16 KiB public
data for five representative t. Each digest is compared with the portable
control. It is a local observation, not a speedup claim or side-channel proof.
Existing kernel emitted-instruction checks remain applicable; they are not
replaced by these API-level checks.

## Native collection after the fresh owner pentest

Use a clean checkout of the reviewed candidate on each machine. Do not reuse
older SHA-512 evidence as proof that these new wrappers ran. Both commands below
are single lines to avoid shell copy/paste continuation problems.

First populate the locked offline dependency cache:

```sh
cargo +1.98.1 fetch --locked --manifest-path assurance/general-sha512-t-cpu/Cargo.toml
```

Apple M2:

```sh
python3 scripts/sha2/capture-general-sha512-t-native.py apple-m2-aarch64 target/general-sha512-t-m2.json
```

AWS Arm Linux:

```sh
python3 scripts/sha2/capture-general-sha512-t-native.py aws-aarch64 target/general-sha512-t-aws-arm.json
```

The tool requires Rust 1.98.1, Python 3.11+, native target tooling, and reported
NEON/SHA-512/SHA-3 features before executing instructions. It runs both profiles
with fresh build directories, positive acceptance and the two negative controls.
It rejects source/commit drift, existing output and symlinked destinations.
Return the resulting JSON files. They contain source hashes, commit/compiler,
results and residuals, but no hostnames, IPs or credentials. Collection executes
trusted checkout tools: it is not a sandbox for hostile code or an attestation
against a malicious operator, compiler, runner, OS or hypervisor.

AWS identity is operator-labelled. Enumerated CPU flags do not prove future CPU
migration safety. Imported reports need exact-source and transcript review and
a recorded disposition before closing v0.24.29. A report alone cannot admit a
backend; native timing, migration, full side-channel review, independent crypto
review and FIPS validation remain separate, unfulfilled gates.

AMD/Intel currently have **no SHA-512 CPU candidate** here: their ordinary
general SHA-512/t execution remains portable. RISC-V Zknh is exercised under
QEMU; native qualification remains post-1.0/community work. Lack of native
RISC-V evidence must stay explicit and cannot be reported as hardware approval.
