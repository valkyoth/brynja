# Hardened SHA-2 native observations

Captured at `10c8bdfaccc2ec5aa6274db6e4267b714fd22421` with Rust 1.98.1,
reviewed on 2026-09-10. These are project-owned functional observations, not
independent cryptographic verification, remote attestation or FIPS validation.

| Artifact | Native host | Verified execution routes |
| --- | --- | --- |
| [Linux x86_64](linux-x86_64.json) | AWS Intel Xeon Platinum 8488C | Portable; static hardened SHA-256, with wide hashing explicitly portable |
| [Linux AArch64](linux-aarch64.json) | AWS Neoverse V1 (implementer 0x41, part 0xd40) | Portable; hosted and static hardened SHA-256/SHA-512 |
| [Apple AArch64](apple-aarch64.json) | Owner-operated Apple M2 Pro | Portable; hosted and static hardened SHA-256/SHA-512 |

Every consumer route passes 240 named SHA-2 vectors and 4,590 general SHA-512/t
cases. Kernel tests record 512 block comparisons per supported kernel and
scratch clearing/unwind success. All artifacts match the same 170-input tested
source, fixture, vector, compiler-configuration and dependency closure.
Linux observations use native instructions on virtualized AWS hosts, not QEMU
instruction emulation; they do not prove hypervisor or CPU-migration behavior.

The coding agent reviewed the result markers, actual routes, host/compiler
identities and source hashes against the checkout. The owner supplied the Mac
artifact; the coding agent ran and retrieved both AWS artifacts. The Mac log's
absolute checkout prefix was replaced with `/REDACTED/brynja` to remove the
owner's account name. No result, route, source hash or compiler identity was
changed. Index hashes bind the archived, redacted bytes.

The source-bound index is [security/sha2-hardened-native.json](../../security/sha2-hardened-native.json).
Validate committed evidence with:

```sh
python3 scripts/sha2/check-sha2-hardened-native-evidence.py
```

Register/spill/compiler-copy erasure, side channels, scheduling/hotplug/VM
migration, platform storage and caller-owned copies remain outside this
evidence. See [the execution boundary](../../docs/sha2-hardened-execution.md).
