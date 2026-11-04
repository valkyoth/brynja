# v0.27.0 candidate — portable AES-128 blocks

Raw AES requires explicit `hazmat-aes-block` opt-in on `brynja-crypto` or
`brynja`; it is absent from defaults. Software-only use requires no HSM.
See the [pentest dispositions](../docs/assurance/aes128-pentest-remediation.md)
for remaining platform limits and the separate future provider design.

Internal development candidate; no crates.io publication is selected. Scoped
pentest/retest, final release gate and exact-candidate GitHub/CodeQL are pending.

## Implemented boundary

`brynja_crypto::aes` and `brynja::crypto::aes` expose a caller-backed `Aes128Key`,
complete AES-128 key expansion and encrypt/decrypt operations on exact 16-byte
blocks. Secret output is the default. Public encryption requires an explicit
`PublicCiphertext` acknowledgement and commits only after successful completion.
Key/output owners and operation scratch use the existing clearing foundation.

This is a block primitive, not an encryption protocol. It supplies no mode,
authentication, nonce handling, padding, AES-192/256, acceleration or TLS
integration. Applications must not treat raw block encryption as authenticated
message encryption. The wider AES-family requirement remains planned.

## Assurance and limits

The [development contract](../docs/assurance/aes128-development.md) records
authoritative vectors, independent block comparisons, misuse and injected-fault
tests, Miri/ASan coverage, bounded arithmetic/index proofs, mutation controls,
fourteen-compiler public consumers, reviewed emitted helper streams and a
bounded synthetic timing observation. These are separately registered checks,
not a claim of full AESAVS/CAVP validation or whole-program constant-time proof.

The assembly review is limited to the recorded x86_64 compiler/profile pairs.
Other targets, final application binaries, physical/speculative leakage and
compiler-created secret copies require deployment-specific qualification.
Clearing owners do not promise erasure of registers, spills, forgotten owners,
aborts, paging or dumps. Packaged AES-family acceptance remains v0.27.2;
this milestone's AES consumers use isolated checkout dependencies.

## Candidate workflow

The finite checklist covers targeted composition/legacy-HKDF tests, lint and
formatting, bounded AES consumer endpoints, existing packaged HKDF compatibility,
registry/release/requirements controls, SBOM and dependency checks. It does not
implicitly launch the full compiler matrix, Miri, sanitizers, proofs, timing
campaigns or historical verification. Historical passes are not promoted.

The retained HKDF package runner now recognizes only the composition crate's
exact five-file AES fixture set in addition to its existing include forms.
Regression controls reject missing, extra, symlinked or altered archived
fixtures; this packaging compatibility fix is not AES-family acceptance.

The owner-requested scoped pentest must review the delta from v0.26.1 through
the committed candidate, including the new primitive, owners, verification
tooling and CI/release changes. No PASS report has been created for this work.
After accepted review and any tested remediation: run the finite final gate on
the clean committed candidate, obtain green exact-commit GitHub/CodeQL, and
request explicit signed-tag approval. These notes authorize none of those
external actions and do not claim independent security approval.
