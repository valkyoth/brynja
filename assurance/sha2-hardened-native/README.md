# Hardened SHA-2 native observations

Refreshed at `b6595c8e5e100014f68651e0ab6a974f2dd239af` with Rust 1.98.1,
reviewed on 2026-09-11 for v0.24.36's optional hosted dependency and verifier
closure changes. These are project-owned functional observations, not
independent cryptographic verification, remote attestation or FIPS validation.

| Artifact | Native host | Verified execution routes |
| --- | --- | --- |
| [Linux x86_64](linux-x86_64-v02436.json) | AWS Intel Xeon Platinum 8488C | Portable; static hardened SHA-256, with wide hashing explicitly portable |
| [Linux AArch64](linux-aarch64-v02436.json) | AWS Neoverse V1 (implementer 0x41, part 0xd40) | Portable; hosted and static hardened SHA-256/SHA-512 |
| [Apple AArch64](apple-aarch64-v02436.json) | Owner-operated Apple M2 Pro | Portable; hosted and static hardened SHA-256/SHA-512 |

Every consumer route passes 240 named SHA-2 vectors and 4,590 general SHA-512/t
cases. Kernel tests record 512 block comparisons per supported kernel and
scratch clearing/unwind success. All artifacts match the same 172-input tested
source, fixture, vector, compiler-configuration and dependency closure.
Linux observations use native instructions on virtualized AWS hosts, not QEMU
instruction emulation; they do not prove hypervisor or CPU-migration behavior.

The coding agent reviewed the result markers, actual routes, host/compiler
identities and source hashes against the checkout. The owner supplied the Mac
artifact; the coding agent ran and retrieved both AWS artifacts. Absolute
checkout prefixes were replaced with `/REDACTED/brynja` to remove account and
workspace names. No result, route, source hash or compiler identity was
changed. Index hashes bind the archived, redacted bytes.

The earlier v0.24.34 files remain at their original filenames for historical
provenance; they are not the active index entries for this release.

The source-bound index is [security/sha2-hardened-native.json](../../security/sha2-hardened-native.json).
Validate committed evidence with:

```sh
python3 scripts/sha2/check-sha2-hardened-native-evidence.py
```

Register/spill/compiler-copy erasure, side channels, scheduling/hotplug/VM
migration, platform storage and caller-owned copies remain outside this
evidence. See [the execution boundary](../../docs/sha2-hardened-execution.md).
