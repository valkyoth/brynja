# Verification catalog

Generated inventory, not a release gate or current-pass claim. All profiles are visible; overlapping profiles are not additional executions.
Use `brynja-verify list COMPONENT [PHASE]` and `brynja-verify show COMPONENT ID` for commands and historical provenance.
Runnable scoped bindings are in verification/checks.toml; list/show distinguish them from unresolved assessments. Owner-approved manual diagnostics, supporting entry points, workflow jobs and retired identities are references, not unfinished work. Do not rerun checks just to populate this list.

| Component | Category | Assessments | With historical observations |
| --- | --- | --- | --- |
| acceleration | entrypoint | 1 | 0 |
| acceleration | inventory-only | 1 | 1 |
| acceleration | miri | 3 | 2 |
| acceleration | repository | 2 | 2 |
| assurance | entrypoint | 5 | 0 |
| ci | entrypoint | 2 | 0 |
| core | asan | 1 | 1 |
| core | inventory-only | 1 | 1 |
| core | miri | 3 | 2 |
| core | repository | 20 | 20 |
| hmac | asan | 1 | 1 |
| hmac | entrypoint | 4 | 0 |
| hmac | kani | 1 | 1 |
| hmac | matrix | 56 | 56 |
| hmac | miri | 51 | 17 |
| hmac | repository | 61 | 61 |
| kmac | asan | 8 | 8 |
| kmac | entrypoint | 5 | 0 |
| kmac | kani | 1 | 1 |
| kmac | matrix | 28 | 28 |
| kmac | miri | 331 | 222 |
| kmac | repository | 17 | 17 |
| kmac | retired-history | 6 | 6 |
| legacy | asan | 2 | 2 |
| legacy | entrypoint | 4 | 0 |
| legacy | inventory-only | 1 | 1 |
| legacy | matrix | 28 | 28 |
| legacy | miri | 6 | 3 |
| legacy | repository | 6 | 6 |
| legacy | retired-history | 16 | 16 |
| legacy_hmac | asan | 1 | 1 |
| legacy_hmac | entrypoint | 2 | 0 |
| legacy_hmac | kani | 1 | 1 |
| legacy_hmac | matrix | 28 | 28 |
| legacy_hmac | miri | 33 | 11 |
| legacy_hmac | repository | 96 | 96 |
| md5 | asan | 4 | 4 |
| md5 | entrypoint | 11 | 0 |
| md5 | kani | 1 | 1 |
| md5 | matrix | 42 | 42 |
| md5 | miri | 1025 | 1016 |
| md5 | repository | 20 | 20 |
| parallelhash | asan | 7 | 7 |
| parallelhash | entrypoint | 21 | 0 |
| parallelhash | kani | 1 | 1 |
| parallelhash | matrix | 28 | 28 |
| parallelhash | miri | 351 | 179 |
| parallelhash | repository | 21 | 21 |
| parallelhash | retired-history | 172 | 172 |
| pki | repository | 4 | 4 |
| protocol | repository | 2 | 2 |
| release | entrypoint | 22 | 0 |
| repository | entrypoint | 33 | 0 |
| repository | matrix | 14 | 14 |
| repository | repository | 101 | 101 |
| repository | retired-history | 1 | 1 |
| repository | workflow | 11 | 0 |
| sanitization | inventory-only | 1 | 1 |
| sanitization | miri | 3 | 2 |
| sanitization | repository | 6 | 6 |
| sha1 | asan | 4 | 4 |
| sha1 | entrypoint | 12 | 0 |
| sha1 | kani | 1 | 1 |
| sha1 | matrix | 56 | 56 |
| sha1 | miri | 746 | 738 |
| sha1 | repository | 14 | 14 |
| sha2 | asan | 22 | 22 |
| sha2 | entrypoint | 12 | 0 |
| sha2 | kani | 1 | 1 |
| sha2 | matrix | 84 | 84 |
| sha2 | miri | 78 | 52 |
| sha2 | repository | 28 | 28 |
| sha3 | asan | 12 | 12 |
| sha3 | entrypoint | 9 | 0 |
| sha3 | kani | 1 | 1 |
| sha3 | matrix | 98 | 98 |
| sha3 | miri | 235 | 218 |
| sha3 | repository | 37 | 37 |
| shared-cryptography | entrypoint | 299 | 0 |
| sp800185 | entrypoint | 1 | 0 |
| standards | entrypoint | 1 | 0 |
| static_cpu | asan | 5 | 5 |
| static_cpu | inventory-only | 1 | 1 |
| static_cpu | matrix | 28 | 28 |
| static_cpu | miri | 18 | 12 |
| static_cpu | repository | 8 | 8 |
| tuplehash | asan | 9 | 9 |
| tuplehash | entrypoint | 2 | 0 |
| tuplehash | kani | 1 | 1 |
| tuplehash | matrix | 28 | 28 |
| tuplehash | miri | 2050 | 2046 |
| tuplehash | repository | 19 | 19 |
| tuplehash | retired-history | 187 | 187 |
| zeroization | entrypoint | 3 | 0 |

## Every catalog assessment

| ID | Components | Category | Assessment | Latest historical outcome | Original time |
| --- | --- | --- | --- | --- | --- |
| asan-04550050dcb9a814 | sha2 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha2 --features general-sha512-t --test general_hash --lib --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:53:27Z |
| asan-08702793c572dc40 | kmac | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-mac-kmac --features hardened-execution --lib --test execution --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:55:23Z |
| asan-0f03923a51baf0cb | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-crypto-cpu --features static-execution --lib static_authority --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:52:59Z |
| asan-106c9d5d31321a06 | md5 | asan | python3 scripts/md5/check-md5-execution-asan.py | passed | 2026-10-29T17:52:16Z |
| asan-2045c74f5ce3a389 | md5 | asan | python3 scripts/md5/check-md5-hardened-asan.py | passed | 2026-10-29T17:52:06Z |
| asan-22a4b40011da9ec9 | sha3 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha3 --tests --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:54:56Z |
| asan-29ef43204a4dca9a | md5 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-legacy-md5 --tests --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:56:17Z |
| asan-2c69d708fd5c0fe5 | sha2 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha2 --test sha512_224 --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:54:28Z |
| asan-2ca5d70133b3620f | sha2 | asan (manual diagnostic) | python3 scripts/sha2/check-sha2-hardened-asan.py | passed | 2026-10-29T17:51:38Z |
| asan-2d6979daa01be4ae | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-crypto-cpu-std --features runtime-execution --lib execution --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:53:00Z |
| asan-35879d3fe392918f | legacy | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:53:50Z |
| asan-3916df16ab897c1f | tuplehash | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-tuple --test api forgotten_or_manually_dropped_items_cannot_bypass_the_open_latch --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:55:48Z |
| asan-39a32d560a36f69b | md5 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-legacy-md5 --features cpu --lib --test cpu --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:56:26Z |
| asan-4281667f8a151cb1 | parallelhash | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-parallel --features runtime-execution --tests --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:56:03Z |
| asan-4f41d74e4de4c59a | legacy | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test --manifest-path assurance/legacy-hash-final/Cargo.toml --lib --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:53:39Z |
| asan-520d60426fa5aed2 | sha2 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha2 --test sha384 --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:54:17Z |
| asan-56d807bc48306bed | parallelhash | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-parallel-std --features runtime-execution --tests --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:56:06Z |
| asan-5a25677c4973093e | tuplehash | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-tuple --tests --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:55:52Z |
| asan-6056268d6d627340 | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-crypto-cpu --features runtime-execution --lib runtime_execution --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:52:48Z |
| asan-6ee45099731c4589 | sha2 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha2 --test bit_inputs --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:53:55Z |
| asan-721a39c8b6089628 | kmac | asan (manual diagnostic) | python3 scripts/kmac/check-kmac-execution.py --asan | passed | 2026-10-29T17:55:27Z |
| asan-75789fa22376eff8 | tuplehash | asan (manual diagnostic) | python3 scripts/tuplehash/check-tuplehash-execution.py --asan | passed | 2026-10-29T17:55:36Z |
| asan-7fd1d743efed9d4c | sha2 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test --manifest-path assurance/general-sha512-t/Cargo.toml --lib --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:53:12Z |
| asan-845714142f9d46b9 | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-crypto-cpu-std --features sponge-execution --lib sponge --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:52:37Z |
| asan-84d3b0f8bded00a0 | kmac | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-mac-kmac --tests --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:55:08Z |
| asan-861e3741e26062ef | sha2 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha2 --test sha512_256 --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:54:45Z |
| asan-86a15efc28b1bc63 | core | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-core --test secret_memory --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:53:44Z |
| asan-895e0181dc4a7150 | sha2 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha2 --features runtime-execution,general-sha512-t --test execution --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:52:49Z |
| asan-8bc071080d92e8fa | legacy_hmac | asan | python3 scripts/legacy-hmac/check-legacy-hmac-asan.py | passed | 2026-10-29T17:51:14Z |
| asan-8fc8f3a91475dba1 | sha2 | asan | python3 scripts/sha2/check-sha512-batch-asan.py | passed | 2026-10-29T17:51:51Z |
| asan-90cc767cfe1b9fa6 | sha1 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-legacy-sha1 --tests --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:56:15Z |
| asan-941ec9ae501e8ec5 | sha2 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha2 --features general-sha512-t --test general --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:53:22Z |
| asan-9585d55c2643dd11 | sha1 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-legacy-sha1 --features execution --test execution --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:52:27Z |
| asan-99cbd63d372920fc | sha2 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha2 --test sha224 --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:54:06Z |
| asan-a7bae143b7bf7abe | sha2 | asan | python3 scripts/sha2/check-sha256-batch-asan.py | passed | 2026-10-29T17:51:28Z |
| asan-ab78391f09dd5ff7 | sha3 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha3 --lib final_bit_output_clears_the_exact_reader_source --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:54:40Z |
| asan-b5b4abe9e5870423 | sha3 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha3 --lib borrowing_reader_never_extracts_the_absorbing_owner --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:54:56Z |
| asan-babb8a05e04b62ae | sha2 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha2 --test hardened --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:54:12Z |
| asan-c09513dded223753 | sha1 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-legacy-sha1 --features cpu --lib --test cpu --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:53:34Z |
| asan-c18989c46d372945 | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha2 -p brynja-crypto-cpu --all-features --lib hardened_execution --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:52:37Z |
| asan-c4be62d8f40f124d | sha3 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha3 --features static-execution --lib --test execution --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:55:11Z |
| asan-ced2204758dd4025 | sha3 | asan | python3 scripts/sha3/check-keccak-batch-asan.py | passed | 2026-10-29T17:52:04Z |
| asan-d376183b8436fa1e | sha3 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha3 --features static-execution --test cshake_execution --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:52:18Z |
| asan-d90dbfeeeda978b5 | sha2 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 run --locked --offline --release --manifest-path assurance/general-sha512-t/Cargo.toml --bin general-sha512-t-profile --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:53:11Z |
| asan-d9e527695c9f7e14 | sha2 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha2 --test sha512 --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:54:34Z |
| asan-dbb418559d074495 | tuplehash | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-tuple --features hardened-execution --lib --test execution --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:55:40Z |
| asan-df77b71218dda0fb | hmac | asan | python3 scripts/hmac/check-hmac-asan.py | passed | 2026-10-29T17:51:19Z |
| asan-e141e43786378d41 | sha1 | asan | python3 scripts/sha1/check-sha1-hardened-asan.py | passed | 2026-10-29T17:51:54Z |
| asan-e96236909f79ef96 | sha2 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha2 --lib --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:54:01Z |
| asan-f1863514a04ac11d | sha2 | asan | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test -p brynja-hash-sha2 --test sha256 --target x86_64-unknown-linux-gnu | passed | 2026-10-29T17:54:23Z |
| asan-f33cac91ce48591f | sha3 | asan | python3 scripts/sha3/check-keccak-hardened-asan.py | passed | 2026-10-29T17:51:42Z |
| entry-0049909471ced3a0 | shared-cryptography | entrypoint | scripts/cryptography/check-hardened-batch-asan.py | No mapped observation | — |
| entry-01f23426ff21d863 | hmac | entrypoint | scripts/hmac/check-hmac-x86-sha512.py | No mapped observation | — |
| entry-02450f79ea4896df | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-root-return.py | No mapped observation | — |
| entry-03a53245be32a556 | repository | entrypoint | scripts/repository/test_legacy_execution_package.py | No mapped observation | — |
| entry-05566cc7311df6b5 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha512-simd.py | No mapped observation | — |
| entry-0584eb00ddc491a5 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-awe-probe.py | No mapped observation | — |
| entry-05ddc524aa112fc8 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-stream-operations.py | No mapped observation | — |
| entry-06b63c1efd58c4c3 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-context.py | No mapped observation | — |
| entry-07a43ee0d65ffe9b | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-formatter.py | No mapped observation | — |
| entry-084403d141198d41 | repository | entrypoint | scripts/repository/check-legacy-resident-package.py | No mapped observation | — |
| entry-08a6398261b79bfb | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-finalize.py | No mapped observation | — |
| entry-09bf2ce70859d4c8 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-slot-review.py | No mapped observation | — |
| entry-0b91ef3fae8e0169 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-transport-data.py | No mapped observation | — |
| entry-0bb272fa7d312632 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-cpu-entry.py | No mapped observation | — |
| entry-0c00c49a27d8301b | sha3 | entrypoint | scripts/sha3/check-hardened-sha3-batch-codegen.py | No mapped observation | — |
| entry-0c679b429c11059f | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-batch-host-wire.py | No mapped observation | — |
| entry-0cb0d786540f3adb | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-wrapper-return.py | No mapped observation | — |
| entry-0cd277e9aa87f0ce | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-connections.py | No mapped observation | — |
| entry-0df14bd01515ca39 | zeroization | entrypoint | scripts/zeroization/check-zeroization-sanitizer.sh | No mapped observation | — |
| entry-0e233c0c5745c291 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-state-review.py | No mapped observation | — |
| entry-0e8dc8ba1b97a91f | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-rust-host.py | No mapped observation | — |
| entry-0ea196bec1778a19 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-runtime-arithmetic.py | No mapped observation | — |
| entry-0f39ab6809f50b2d | legacy | entrypoint | scripts/legacy-hash/check-legacy-vectors.py | No mapped observation | — |
| entry-0fd176eeeae22432 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-concurrent-stack.py | No mapped observation | — |
| entry-1052fb625b2ec3a5 | shared-cryptography | entrypoint | scripts/cryptography/test-batch-output-flow.py | No mapped observation | — |
| entry-106fa6be6151ac74 | sha2 | entrypoint | scripts/sha2/capture-sha2-hardened-native.py | No mapped observation | — |
| entry-10ba37ac2b45e8f8 | repository | entrypoint | scripts/repository/test_legacy_resident_package.py | No mapped observation | — |
| entry-1129338c73b7c2d4 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-namespace-admission.py | No mapped observation | — |
| entry-11bb090d33fc4c2c | sha1 | entrypoint | scripts/sha1/test-sha1-hardened-native.py | No mapped observation | — |
| entry-11d1cf99fcee15d5 | shared-cryptography | entrypoint | scripts/cryptography/test-hardened-keccak-batch-oracle.py | No mapped observation | — |
| entry-121eed355b31c0ab | repository | entrypoint | scripts/repository/test_strict_accelerated_consumer.py | No mapped observation | — |
| entry-1304ead6d216d597 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-batch.py | No mapped observation | — |
| entry-1353744f9ae6e3c4 | md5 | entrypoint | scripts/md5/capture-md5-execution-native.py | No mapped observation | — |
| entry-14bf4f6ee2a798f6 | sha2 | entrypoint | scripts/sha2/capture-general-sha512-t-native.py | No mapped observation | — |
| entry-14ed604be7c97204 | release | entrypoint | scripts/release/test-verification-registry.py | No mapped observation | — |
| entry-150f7fc7c5fcbc34 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-dispatch-helpers.py | No mapped observation | — |
| entry-158e96538da9431e | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha256-simd-resident-model.py | No mapped observation | — |
| entry-17ae7716094263be | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-owner.py | No mapped observation | — |
| entry-17b526bbe442c4b1 | shared-cryptography | entrypoint | scripts/cryptography/test-hardened-batch-native.py | No mapped observation | — |
| entry-17cdc4b2a085ecb1 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-outer-window.py | No mapped observation | — |
| entry-183eff0154ee7416 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-host-contract.py | No mapped observation | — |
| entry-1a610656dd6db70e | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-scheduler.py | No mapped observation | — |
| entry-1a66fcd83385fd7f | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-kmac-resident.py | No mapped observation | — |
| entry-1a7ee38cf29ec5d6 | sha1 | entrypoint | scripts/sha1/check-sha1-hardened-ci.py | No mapped observation | — |
| entry-1bc4402351851474 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-frame-geometry.py | No mapped observation | — |
| entry-1d1eb7464d5dfa1a | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-residency.py | No mapped observation | — |
| entry-1d811c99ca87e0e9 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-admission.py | No mapped observation | — |
| entry-1d94cd0fbbe4ade6 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-terminal.py | No mapped observation | — |
| entry-1dbc641e50e8d03f | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-keccak-simd-resident.py | No mapped observation | — |
| entry-1f04bde3ab341339 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-batch-worker.py | No mapped observation | — |
| entry-1f6bb76741c79b2f | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-resident-model.py | No mapped observation | — |
| entry-1f92fd93c12722b3 | release | entrypoint | scripts/release/test_dashboard_tests.py | No mapped observation | — |
| entry-1ff6ef47de01f3e6 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-batch-chains.py | No mapped observation | — |
| entry-20449c226841b4d7 | release | entrypoint | scripts/release/test-push-ci.py | No mapped observation | — |
| entry-21addfd42bb75756 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-wrapper-binding.py | No mapped observation | — |
| entry-21b195633f841f87 | shared-cryptography | entrypoint | scripts/cryptography/test-parallelhash-batch-bench.py | No mapped observation | — |
| entry-21b78fa0bceff1b3 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-batch-resident.py | No mapped observation | — |
| entry-21ce22218b4e48aa | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-glue-machine.py | No mapped observation | — |
| entry-2208605651f0a5f6 | shared-cryptography | entrypoint | scripts/cryptography/test-hardened-batch-asan.py | No mapped observation | — |
| entry-22244238d9c4dd70 | tuplehash | entrypoint | scripts/tuplehash/capture-tuplehash-execution-native.py | No mapped observation | — |
| entry-22e11fcbd1d7b86a | legacy_hmac | entrypoint | scripts/legacy-hmac/check-legacy-hmac-sha1-native.py | No mapped observation | — |
| entry-2362cc3d912173c1 | shared-cryptography | entrypoint | scripts/cryptography/test-macos-resident-batch-package.py | No mapped observation | — |
| entry-236483f09caf6eab | shared-cryptography | entrypoint | scripts/cryptography/check-macos-resident-codegen.py | No mapped observation | — |
| entry-239c0f3bd27dd9d4 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-stream.py | No mapped observation | — |
| entry-2419960d678a8330 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-kmac-resident-model.py | No mapped observation | — |
| entry-24587978723ef120 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-decoders.py | No mapped observation | — |
| entry-249aa278bf825ed6 | sha3 | entrypoint | scripts/sha3/test-hardened-sha3-batch-codegen.py | No mapped observation | — |
| entry-252932610350b969 | sha2 | entrypoint | scripts/sha2/check-hardened-sha2-batch-codegen.py | No mapped observation | — |
| entry-257ca863b1a58404 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-diagnostic.py | No mapped observation | — |
| entry-257cbb334945834e | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-tuple-accelerated.py | No mapped observation | — |
| entry-25c23e42cbc5fb7b | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-worker-memory.py | No mapped observation | — |
| entry-2614bb3171b2b35a | md5 | entrypoint | scripts/md5/test-md5-evidence-builds.py | No mapped observation | — |
| entry-26515e3545bcd8d7 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-concurrent-native.py | No mapped observation | — |
| entry-26b01fdb23d1edb9 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-kmac-stream.py | No mapped observation | — |
| entry-26db80fda886ce51 | release | entrypoint | scripts/release/test-internal-deferral.py | No mapped observation | — |
| entry-27cec0622e372530 | sha2 | entrypoint | scripts/sha2/capture-sha256-cpu-native.sh | No mapped observation | — |
| entry-289a2c63f2766de8 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-borrowed-worker.py | No mapped observation | — |
| entry-2ba48242d35f50f1 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-transfers.py | No mapped observation | — |
| entry-2c9663b5e8cbafa7 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-directory.py | No mapped observation | — |
| entry-2c9e75c12953e8ea | md5 | entrypoint | scripts/md5/capture-md5-cpu-native.py | No mapped observation | — |
| entry-2ccf880b2c2becec | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-provenance.py | No mapped observation | — |
| entry-2cd88fdcf0134aa9 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-batch-resident-model.py | No mapped observation | — |
| entry-2d7b5a465c8c1676 | sha2 | entrypoint | scripts/sha2/capture-sha512-batch-native.py | No mapped observation | — |
| entry-2e527a19dfa60fd1 | shared-cryptography | entrypoint | scripts/cryptography/test-hardened-sha512-batch-oracle.py | No mapped observation | — |
| entry-2eda6213cfef119c | shared-cryptography | entrypoint | scripts/cryptography/test-hardened-batch-platform.py | No mapped observation | — |
| entry-2fc025dc5f98daeb | sha1 | entrypoint | scripts/sha1/test-sha1-evidence-builds.py | No mapped observation | — |
| entry-30c47b95c036cc5e | release | entrypoint | scripts/release/run-verification.py | No mapped observation | — |
| entry-310c5a96770ff8c6 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-tuple-host-wire.py | No mapped observation | — |
| entry-32ca6ad130484c02 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-batch-host-wire.py | No mapped observation | — |
| entry-330f7a7eaeeb9b53 | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-unwind.py | No mapped observation | — |
| entry-34a5fc8e6643d8e0 | sha3 | entrypoint | scripts/sha3/check-sha3-cpu-qemu.sh | No mapped observation | — |
| entry-35cf0f33bc2651f5 | assurance | entrypoint | scripts/assurance/test-hardened-batch-kani.py | No mapped observation | — |
| entry-35e914c96a62978b | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-worker.py | No mapped observation | — |
| entry-3797bb3425f9b111 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-digest.py | No mapped observation | — |
| entry-380597d7dbb3eebd | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-stack.py | No mapped observation | — |
| entry-3822929c662f0bd0 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-accelerated.py | No mapped observation | — |
| entry-3869355679326395 | release | entrypoint | scripts/release/test-scoped-release.py | No mapped observation | — |
| entry-3893c48d178c2937 | repository | entrypoint | scripts/repository/test_facade_keccak.py | No mapped observation | — |
| entry-39413298edc34b17 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-request.py | No mapped observation | — |
| entry-39c31b9b029c8e4a | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-partial.py | No mapped observation | — |
| entry-3acd9cb5452b6c14 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha-ni-engine.py | No mapped observation | — |
| entry-3b2cb90b640f0741 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-input-native.py | No mapped observation | — |
| entry-3b93abf6d5650341 | repository | entrypoint | scripts/repository/test_facade_sha2_execution.py | No mapped observation | — |
| entry-3bd4b2fd67becc36 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-tuple-resident-model.py | No mapped observation | — |
| entry-3be1a2b77504a000 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-bounded-owner.py | No mapped observation | — |
| entry-3ccac9d21123cdc4 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-placement.py | No mapped observation | — |
| entry-3d7a8057b179e6d2 | sha3 | entrypoint | scripts/sha3/test-keccak-hardened-leaf.py | No mapped observation | — |
| entry-3f0a19b3bd526f0a | sha1 | entrypoint | scripts/sha1/test-sha1-hardened-asan.py | No mapped observation | — |
| entry-3fea0753136e46e8 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-owned.py | No mapped observation | — |
| entry-406c2560c50d5964 | sha3 | entrypoint | scripts/sha3/check-keccak-hardened-native.py | No mapped observation | — |
| entry-4199aa963bac8af5 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-runtime-catalog.py | No mapped observation | — |
| entry-42540a694136225a | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-sequential.py | No mapped observation | — |
| entry-42862cf7ab608f04 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-tuple-worker.py | No mapped observation | — |
| entry-4291be1241476ffb | repository | entrypoint | scripts/repository/test-darwin-resident-abi.py | No mapped observation | — |
| entry-42c487aaaa875b95 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-host-wire.py | No mapped observation | — |
| entry-430b4ccb8f1a1e3d | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-image-dump.py | No mapped observation | — |
| entry-4352d9524f3e1a56 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-waves.py | No mapped observation | — |
| entry-43bdf116d30839f7 | assurance | entrypoint | scripts/assurance/check-bare-metal.sh | No mapped observation | — |
| entry-4405dcdc0cf45a1c | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-stream.py | No mapped observation | — |
| entry-445bc5429ca400c1 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-window.py | No mapped observation | — |
| entry-44f70fb965911f3a | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-kmac-accelerated.py | No mapped observation | — |
| entry-458ec63b13fa7323 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-image-path.py | No mapped observation | — |
| entry-46c3f970c5098a49 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-bounded-dispatch.py | No mapped observation | — |
| entry-47c6adf09c82e878 | release | entrypoint | scripts/release/check-github-release-controls.py | No mapped observation | — |
| entry-48ef076b051c5dad | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-resident.py | No mapped observation | — |
| entry-491608c4eb318916 | release | entrypoint | scripts/release/run-kani-component.py | No mapped observation | — |
| entry-49628aea96aea246 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-host-scheduler.py | No mapped observation | — |
| entry-497000f3c618b027 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-update.py | No mapped observation | — |
| entry-4a45671895c383e7 | release | entrypoint | scripts/release/test_dashboard_store.py | No mapped observation | — |
| entry-4b1ee7bbeb5b4652 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-rehash-worker.py | No mapped observation | — |
| entry-4b4b9b6544a70540 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-batch-accelerated.py | No mapped observation | — |
| entry-4bd46d6387621992 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-identity.py | No mapped observation | — |
| entry-4becaeda333394a6 | kmac | entrypoint | scripts/kmac/test_kmac_retest.py | No mapped observation | — |
| entry-4c724bd31a83796a | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-memory-runtime.py | No mapped observation | — |
| entry-4c8d78111d5a1ca6 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-chains.py | No mapped observation | — |
| entry-4d60bed718a0daf7 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-worker.py | No mapped observation | — |
| entry-4f33000555f02862 | hmac | entrypoint | scripts/hmac/check-hmac-launch.py | No mapped observation | — |
| entry-4f6465fb34910c00 | sha2 | entrypoint | scripts/sha2/check-x86-sha512.py | No mapped observation | — |
| entry-4f82072494e84f2c | sha1 | entrypoint | scripts/sha1/capture-sha1-execution-native.py | No mapped observation | — |
| entry-4fb4cb37a3ae0bf1 | md5 | entrypoint | scripts/md5/check-md5-hardened-ci.py | No mapped observation | — |
| entry-4fd59a955a9a5497 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha512-simd-native.py | No mapped observation | — |
| entry-4ff24db408c7a820 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-runtime-native.py | No mapped observation | — |
| entry-5089da8c0a531f6c | repository | entrypoint | scripts/repository/test_facade_scoped_sha2.py | No mapped observation | — |
| entry-508b45f7e4d0770b | md5 | entrypoint | scripts/md5/capture-md5-hardened-native.py | No mapped observation | — |
| entry-521058c9d30894df | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-host.py | No mapped observation | — |
| entry-52afba82c228fc0c | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-caller-handlers.py | No mapped observation | — |
| entry-532c87539ba755b2 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-bounded-export.py | No mapped observation | — |
| entry-5368ae35221061a2 | assurance | entrypoint | scripts/assurance/check-parallel-batch-kani.py | No mapped observation | — |
| entry-5370bac0dce99b70 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-locking.py | No mapped observation | — |
| entry-5521fe79a87b836c | shared-cryptography | entrypoint | scripts/cryptography/test-batch-output-codegen.py | No mapped observation | — |
| entry-55459fa3082208ce | shared-cryptography | entrypoint | scripts/cryptography/test-windows-minidump.py | No mapped observation | — |
| entry-5624470c514d78cb | shared-cryptography | entrypoint | scripts/cryptography/check-macos-resident-package.py | No mapped observation | — |
| entry-567d19e6b68988d1 | repository | entrypoint | scripts/repository/test_strict_public_consumer.py | No mapped observation | — |
| entry-56abdeb19d89cb32 | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-cleanup.py | No mapped observation | — |
| entry-5845a6d968d6574f | parallelhash | entrypoint | scripts/parallelhash/test-parallelhash-package-fixtures.py | No mapped observation | — |
| entry-587141b79934d44f | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-persistent-result.py | No mapped observation | — |
| entry-58c26c2eceecbb24 | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-arguments.py | No mapped observation | — |
| entry-58fe4d2a06f71ad7 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-kmac-worker.py | No mapped observation | — |
| entry-59522fe91b421d9f | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-bounded-callbacks.py | No mapped observation | — |
| entry-595f81246e3245bb | release | entrypoint | scripts/release/check-family-completeness.py | No mapped observation | — |
| entry-59d373ceff803b6d | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-kmac-chains.py | No mapped observation | — |
| entry-5a1b189ef889e28a | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha-ni-lifecycle.py | No mapped observation | — |
| entry-5a28a83135e07f01 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha512-simd-gate.py | No mapped observation | — |
| entry-5a67d3f4b76926e4 | sha1 | entrypoint | scripts/sha1/check-sha1-cpu-qemu.sh | No mapped observation | — |
| entry-5a72684e11b23776 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-worker.py | No mapped observation | — |
| entry-5b4d21e04d06a2b0 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-exception.py | No mapped observation | — |
| entry-5c20716bf529419d | sha2 | entrypoint | scripts/sha2/check-sha256-cpu-qemu.sh | No mapped observation | — |
| entry-5dabe5edc9320938 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-lock-rollback.py | No mapped observation | — |
| entry-5dd3673decdf4947 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-guard-profile.py | No mapped observation | — |
| entry-5ef09b590e4f8d7c | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-inventory.py | No mapped observation | — |
| entry-5f4229a90c7cd43a | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-wave-native-gate.py | No mapped observation | — |
| entry-5f54a4e13fe60759 | repository | entrypoint | scripts/repository/test-package-contents.py | No mapped observation | — |
| entry-5f8a343149a70876 | sha1 | entrypoint | scripts/sha1/check-sha1-hardened-native.py | No mapped observation | — |
| entry-5fb5ad897b5b86bd | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-image-pin.py | No mapped observation | — |
| entry-610b08d748e6d3ce | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-return.py | No mapped observation | — |
| entry-61245296393a9521 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-window-rust.py | No mapped observation | — |
| entry-61525508249be618 | sha3 | entrypoint | scripts/sha3/test-sha3-batch-cleanup-flow.py | No mapped observation | — |
| entry-618e7003ef87f7ba | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha256-simd-resident.py | No mapped observation | — |
| entry-6237eed43c2b1d12 | legacy | entrypoint | scripts/legacy-hash/check-panic-profiles.py | No mapped observation | — |
| entry-6299884f7efc137d | shared-cryptography | entrypoint | scripts/cryptography/test-parallelhash-batch-oracle.py | No mapped observation | — |
| entry-62b419af7ec40b55 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-keccak-simd.py | No mapped observation | — |
| entry-636f9f5117371780 | sha1 | entrypoint | scripts/sha1/test-sha1-native-capture.py | No mapped observation | — |
| entry-645b43277fb67aae | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-stream-lifecycle.py | No mapped observation | — |
| entry-64cc55922d31a82d | repository | entrypoint | scripts/repository/test_legacy_hardened_package.py | No mapped observation | — |
| entry-652d8e556e891dc7 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-input.py | No mapped observation | — |
| entry-65590ac30c3cdfac | shared-cryptography | entrypoint | scripts/cryptography/check-hardened-sha512-batch-oracle.py | No mapped observation | — |
| entry-65bca3f670c4f054 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-resident-model.py | No mapped observation | — |
| entry-6710ac5c5776c101 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-hardened.py | No mapped observation | — |
| entry-6832f648c716ff22 | shared-cryptography | entrypoint | scripts/cryptography/check-hardened-sha256-batch-oracle.py | No mapped observation | — |
| entry-698405c5e9013c70 | sha2 | entrypoint | scripts/sha2/check-sha2-hardened-native-evidence.py | No mapped observation | — |
| entry-698dd66fc41fa8aa | md5 | entrypoint | scripts/md5/check-md5-execution-differential.py | No mapped observation | — |
| entry-6bc13745f52547a4 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-borrowed-host.py | No mapped observation | — |
| entry-6c20f0823229488e | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-scalar.py | No mapped observation | — |
| entry-6ca28651dfad5fcc | ci | entrypoint | scripts/ci/check_latest_tools.sh | No mapped observation | — |
| entry-6dcc245c84498239 | shared-cryptography | entrypoint | scripts/cryptography/test-hardened-sha256-batch-oracle.py | No mapped observation | — |
| entry-6e086df3e1fe7f97 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-runtime.py | No mapped observation | — |
| entry-6f12fcfb92d7f053 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-tuple-stream.py | No mapped observation | — |
| entry-6fe606860bfb4073 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-route-memory.py | No mapped observation | — |
| entry-70736da471b2dadb | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-wire.py | No mapped observation | — |
| entry-71ce4df005607e3c | repository | entrypoint | scripts/repository/test_strict_group_consumer.py | No mapped observation | — |
| entry-726a331aba3d056e | repository | entrypoint | scripts/repository/test_facade_keccak_routes.py | No mapped observation | — |
| entry-72fe54596b26eaf1 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-caller-binding.py | No mapped observation | — |
| entry-7306d90b414f5ddb | sha3 | entrypoint | scripts/sha3/capture-keccak-batch-native.py | No mapped observation | — |
| entry-744fd0d1eb4ff124 | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-arm-arguments.py | No mapped observation | — |
| entry-74db6c2fe67524dd | repository | entrypoint | scripts/repository/check-package-fixtures.py | No mapped observation | — |
| entry-74e896e2fa9a004b | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-borrowed.py | No mapped observation | — |
| entry-7539d3211d496944 | repository | entrypoint | scripts/repository/check-strict-windows-consumer.py | No mapped observation | — |
| entry-7769de482a1c06d1 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-leaf.py | No mapped observation | — |
| entry-778c59c111252130 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-batch.py | No mapped observation | — |
| entry-796cc08e1bd77e8a | repository | entrypoint | scripts/repository/test_facade_sha3_execution.py | No mapped observation | — |
| entry-7a8aa4068814b098 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sequential-helpers.py | No mapped observation | — |
| entry-7a968020ba89e65f | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-scheduler-dump.py | No mapped observation | — |
| entry-7b3f22c6f20ce42e | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-runtime-frames.py | No mapped observation | — |
| entry-7b542686aee99280 | release | entrypoint | scripts/release/test-verification-catalog.py | No mapped observation | — |
| entry-7b66ec846257ed2b | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-ancestor-identity.py | No mapped observation | — |
| entry-7b689783ecec6980 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-resident.py | No mapped observation | — |
| entry-7b9f6426722e89e9 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-keccak-simd-native.py | No mapped observation | — |
| entry-7ca3f1ff673dfab5 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-dispatch.py | No mapped observation | — |
| entry-7dc30671e3dee1b7 | shared-cryptography | entrypoint | scripts/cryptography/check-macos-resident-batch-package.py | No mapped observation | — |
| entry-7f71d24f3f3cf2b1 | acceleration | entrypoint | scripts/cpu/test-hosted-hardened-batch.py | No mapped observation | — |
| entry-7f925355f0340350 | shared-cryptography | entrypoint | scripts/cryptography/check-windows-enclave-window-lock.py | No mapped observation | — |
| entry-8001ed89fa74248d | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-input-copy.py | No mapped observation | — |
| entry-804c715b200f7a7f | md5 | entrypoint | scripts/md5/check-md5-hardened-native.py | No mapped observation | — |
| entry-81103e74c5db6b2e | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retirement-review.py | No mapped observation | — |
| entry-8163560f4bd71482 | shared-cryptography | entrypoint | scripts/cryptography/test-hardened-batch-bench.py | No mapped observation | — |
| entry-816f74b62d5056f2 | release | entrypoint | scripts/release/test_dashboard_run.py | No mapped observation | — |
| entry-8170bed3c61052e4 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-keccak-simd-gate.py | No mapped observation | — |
| entry-8227a34620658af1 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-framing.py | No mapped observation | — |
| entry-82e890d3d0678997 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-result-native.py | No mapped observation | — |
| entry-835958e48a38479b | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-unwind.py | No mapped observation | — |
| entry-835f7bb30fedbb1f | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-bounded-input.py | No mapped observation | — |
| entry-836f700e5930b9e7 | release | entrypoint | scripts/release/test_dashboard_provenance.py | No mapped observation | — |
| entry-83bee06d846c5050 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-conversion.py | No mapped observation | — |
| entry-847e53a28af7e051 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha512-simd-worker.py | No mapped observation | — |
| entry-85731254de37e668 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-borrowed-host.py | No mapped observation | — |
| entry-85f77e92fae122aa | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha512-simd-resident.py | No mapped observation | — |
| entry-872aad80def6fe78 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-borrowed-input.py | No mapped observation | — |
| entry-875a71cb6d0a63dd | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-native-host.py | No mapped observation | — |
| entry-8778d5219f3c0a1e | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-state.py | No mapped observation | — |
| entry-88a7543d7371ef41 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-request.py | No mapped observation | — |
| entry-88aa9cc82cd7e1e3 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-scheduler-gate.py | No mapped observation | — |
| entry-8a6d3571c44b3904 | repository | entrypoint | scripts/repository/check-legacy-strict-package.py | No mapped observation | — |
| entry-8ac3afc54929eaa2 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-native-host.py | No mapped observation | — |
| entry-8af19a10236f3412 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-engine-review.py | No mapped observation | — |
| entry-8c31e592ecf47f1f | shared-cryptography | entrypoint | scripts/cryptography/check-strict-profile-package.py | No mapped observation | — |
| entry-8ccda661b952b33f | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha512-simd-resident-model.py | No mapped observation | — |
| entry-8cd425c9f0d6fe5b | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha256-simd-gate.py | No mapped observation | — |
| entry-8d58b049e89049b6 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-concurrent-teardown.py | No mapped observation | — |
| entry-909014e16cebc498 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sequential-c.py | No mapped observation | — |
| entry-9157360d55822e14 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-persistent-native.py | No mapped observation | — |
| entry-918389d195dd23bb | release | entrypoint | scripts/release/test-family-completeness.py | No mapped observation | — |
| entry-93128c242399eb59 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-window-lock.py | No mapped observation | — |
| entry-93261be14168d6b0 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-borrowed-native.py | No mapped observation | — |
| entry-938525887408f6fb | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha256-simd-worker.py | No mapped observation | — |
| entry-940a68a493e60e39 | shared-cryptography | entrypoint | scripts/cryptography/test-macos-resident-package.py | No mapped observation | — |
| entry-944d32a173e56411 | ci | entrypoint | scripts/ci/check-rust-version-matrix.sh | No mapped observation | — |
| entry-95934667470a268e | shared-cryptography | entrypoint | scripts/cryptography/test-batch-output-assembly.py | No mapped observation | — |
| entry-95c3f73e384b2aa0 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-host-session.py | No mapped observation | — |
| entry-95dc91e88496591e | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-host-wire.py | No mapped observation | — |
| entry-96b86ec339eca58b | release | entrypoint | scripts/release/test_dashboard_catalog.py | No mapped observation | — |
| entry-972e19cda3a55c47 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-cross.py | No mapped observation | — |
| entry-983eeae3f56a9f45 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-concurrent-route.py | No mapped observation | — |
| entry-992920fea6c9111a | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-concurrent-c.py | No mapped observation | — |
| entry-9975e43599d14ec7 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha256-simd-native.py | No mapped observation | — |
| entry-9a93c67b64c01f45 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-result.py | No mapped observation | — |
| entry-9ad3816d06234a18 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-tuple-packer.py | No mapped observation | — |
| entry-9aeee58edc613495 | sha1 | entrypoint | scripts/sha1/test-sha1-execution-capture.py | No mapped observation | — |
| entry-9b8172c7aa6762f1 | parallelhash | entrypoint | scripts/parallelhash/check-parallelhash-execution-native.py | No mapped observation | — |
| entry-9bbfe011575a7775 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-native-teardown.py | No mapped observation | — |
| entry-9d2c32c1c625db32 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-transition.py | No mapped observation | — |
| entry-9d9ef2512180e900 | repository | entrypoint | scripts/repository/test-package-fixtures.py | No mapped observation | — |
| entry-9db95f8703278837 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-input-worker.py | No mapped observation | — |
| entry-9dcd2e7b0f2c6d74 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-concurrent-results.py | No mapped observation | — |
| entry-9de6fd8cdc3581f4 | repository | entrypoint | scripts/repository/test_facade_kmac.py | No mapped observation | — |
| entry-9dee2bbe0965f000 | shared-cryptography | entrypoint | scripts/cryptography/check-hardened-keccak-batch-oracle.py | No mapped observation | — |
| entry-9e7a05f56b341b6e | kmac | entrypoint | scripts/kmac/check-kmac-timing.sh | No mapped observation | — |
| entry-9e80cf354c8d66a8 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-prefix.py | No mapped observation | — |
| entry-9ec0b473fdb99c9f | hmac | entrypoint | scripts/hmac/check-hmac-hosted-native.py | No mapped observation | — |
| entry-a029b5dd12e66585 | parallelhash | entrypoint | scripts/parallelhash/test-parallelhash-batch.py | No mapped observation | — |
| entry-a11c3e21bbafc67f | shared-cryptography | entrypoint | scripts/cryptography/test-windows-wer-probe.py | No mapped observation | — |
| entry-a134480bcc10dd09 | shared-cryptography | entrypoint | scripts/cryptography/check-macos-resident-batch-codegen.py | No mapped observation | — |
| entry-a17eee2d0b245d2a | repository | entrypoint | scripts/repository/test_facade_parallelhash_execution.py | No mapped observation | — |
| entry-a1e0f0cd65c5aaec | md5 | entrypoint | scripts/md5/check-md5-execution-native.py | No mapped observation | — |
| entry-a33b22b309a3bbcf | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-window-guard.py | No mapped observation | — |
| entry-a364cf6a559faec0 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha256-simd.py | No mapped observation | — |
| entry-a434c06c7cb44245 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-wire-native.py | No mapped observation | — |
| entry-a4beb168ceeed7a3 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-avx2-chain.py | No mapped observation | — |
| entry-a52617eb9f5f3aad | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha-ni-state.py | No mapped observation | — |
| entry-a58f690c583d31da | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-worker-boundaries.py | No mapped observation | — |
| entry-a58f883594425ae9 | repository | entrypoint | scripts/repository/test_facade_hardened_sha3.py | No mapped observation | — |
| entry-a5b51a1c003e3572 | repository | entrypoint | scripts/repository/test_facade_parallelhash.py | No mapped observation | — |
| entry-a5da8f452aae4d5d | shared-cryptography | entrypoint | scripts/cryptography/test-strict-facade-examples.py | No mapped observation | — |
| entry-a5ec131fa9eacca2 | shared-cryptography | entrypoint | scripts/cryptography/check-parallelhash-batch-oracle.py | No mapped observation | — |
| entry-a6cdb4f2cef14418 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-cpu-kernels.py | No mapped observation | — |
| entry-a6feb635914207a1 | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-lifecycle.py | No mapped observation | — |
| entry-a756582e81042708 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-copy-success.py | No mapped observation | — |
| entry-a798c1c5719e585c | hmac | entrypoint | scripts/hmac/check-hmac-timing.py | No mapped observation | — |
| entry-a8dbf34253150600 | repository | entrypoint | scripts/repository/test_facade_tuplehash.py | No mapped observation | — |
| entry-a9ef943ba237e23d | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-state-operations.py | No mapped observation | — |
| entry-ab02cc61f737ac6f | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-tuple-chains.py | No mapped observation | — |
| entry-ac7a34eae58bb504 | sha1 | entrypoint | scripts/sha1/capture-sha1-cpu-native.py | No mapped observation | — |
| entry-acafb74a9648fec6 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-cpu-inventory.py | No mapped observation | — |
| entry-acf80178bd2f24e4 | release | entrypoint | scripts/release/check-acceptance-metadata.py | No mapped observation | — |
| entry-ad15649f722744e7 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-setup.py | No mapped observation | — |
| entry-ad571953599e6717 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-chain.py | No mapped observation | — |
| entry-adb3521cea8caf37 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-stack-compose.py | No mapped observation | — |
| entry-ae20dfc214f6ade9 | repository | entrypoint | scripts/repository/test-rust-freshness.py | No mapped observation | — |
| entry-afbc206dc3384808 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-state-cleanup.py | No mapped observation | — |
| entry-afc92e1c56335f8e | shared-cryptography | entrypoint | scripts/cryptography/check-hardened-batch-package.py | No mapped observation | — |
| entry-b0df1f3f81f3e248 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-accelerated.py | No mapped observation | — |
| entry-b1f6f87ef8bb942b | kmac | entrypoint | scripts/kmac/check-kmac-conformance-enabled.py | No mapped observation | — |
| entry-b3f675109e0960e5 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-wave-native.py | No mapped observation | — |
| entry-b4816c706db2c127 | parallelhash | entrypoint | scripts/parallelhash/capture-parallelhash-execution-native.py | No mapped observation | — |
| entry-b4a03914612c86fd | repository | entrypoint | scripts/repository/check-strict-group-consumer.py | No mapped observation | — |
| entry-b55c076af92864ac | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-bounded-memory.py | No mapped observation | — |
| entry-b6c9b15070ae1687 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-keccak-simd-worker.py | No mapped observation | — |
| entry-b7522b0380bcc367 | repository | entrypoint | scripts/repository/test-action-pins.py | No mapped observation | — |
| entry-b7da5c28d78f2e34 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-window-depth.py | No mapped observation | — |
| entry-b859192189b9f6ea | shared-cryptography | entrypoint | scripts/cryptography/check-macos-resident-parallel-package.py | No mapped observation | — |
| entry-b86440cde00c64ed | repository | entrypoint | scripts/repository/check-lean-package-builds.py | No mapped observation | — |
| entry-b895b5f2c3281260 | legacy_hmac | entrypoint | scripts/legacy-hmac/check-legacy-hmac-timing.py | No mapped observation | — |
| entry-b8e420110bc71bef | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-bridge.py | No mapped observation | — |
| entry-b9a881c2e0993772 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha512-simd-host.py | No mapped observation | — |
| entry-b9da1fee21506665 | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-machine.py | No mapped observation | — |
| entry-ba0ec15ead8756ee | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-dump.py | No mapped observation | — |
| entry-baa349639b7e22a5 | release | entrypoint | scripts/release/test-test-dashboard.py | No mapped observation | — |
| entry-baa55b0296038c70 | sha3 | entrypoint | scripts/sha3/test-keccak-hardened-batch.py | No mapped observation | — |
| entry-baad7f5c9ccfc266 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-protection-probe.py | No mapped observation | — |
| entry-bab7e75814e0c1be | repository | entrypoint | scripts/repository/check-strict-public-consumer.py | No mapped observation | — |
| entry-bad42f19894f360b | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-concurrent.py | No mapped observation | — |
| entry-bc7591a27946d2f3 | sha2 | entrypoint | scripts/sha2/capture-sha256-batch-native.py | No mapped observation | — |
| entry-bdda36514e9a747c | zeroization | entrypoint | scripts/zeroization/check-zeroization-miri.sh | No mapped observation | — |
| entry-be93d80f9aee7fd0 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-root-setup.py | No mapped observation | — |
| entry-bf020dfa068a545f | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-exception-arguments.py | No mapped observation | — |
| entry-bf71918e6059f45f | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha256-simd-host.py | No mapped observation | — |
| entry-c08705f665b35be8 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-lifecycle.py | No mapped observation | — |
| entry-c0ba7b8983acf7c8 | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-inline.py | No mapped observation | — |
| entry-c293156ec2cd4294 | repository | entrypoint | scripts/repository/test_legacy_strict_package.py | No mapped observation | — |
| entry-c2e25188d9fa05cc | shared-cryptography | entrypoint | scripts/cryptography/check-hardened-batch-bench.py | No mapped observation | — |
| entry-c31652b264fae5f9 | sha2 | entrypoint | scripts/sha2/test-sha256-hardened-batch.py | No mapped observation | — |
| entry-c36fc157b984feb1 | release | entrypoint | scripts/release/test-expansion-plan.py | No mapped observation | — |
| entry-c37a95765af18138 | shared-cryptography | entrypoint | scripts/cryptography/test-macos-resident-parallel-package.py | No mapped observation | — |
| entry-c453d3bee6ced947 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-bounded-rehash.py | No mapped observation | — |
| entry-c47fe4536617c848 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-host-dump.py | No mapped observation | — |
| entry-c4fba0afdaf8a793 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-terminal-review.py | No mapped observation | — |
| entry-c50fea73db31951e | sp800185 | entrypoint | scripts/sp800185/capture-sp800185-native.py | No mapped observation | — |
| entry-c580e0772a826d7a | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-construction-review.py | No mapped observation | — |
| entry-c6112f0b9d33158b | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-stack-flow.py | No mapped observation | — |
| entry-c6ad7408e8b0238c | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-native.py | No mapped observation | — |
| entry-c6d62079042ff7a0 | tuplehash | entrypoint | scripts/tuplehash/check-tuplehash-execution-native.py | No mapped observation | — |
| entry-c7aa5c5ccbb5e664 | sha2 | entrypoint | scripts/sha2/check-sha256-assembly-instruction.sh | No mapped observation | — |
| entry-c807d6dc4ae1aa32 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-isolated.py | No mapped observation | — |
| entry-c8dd8326c06578d2 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha-ni-receiver.py | No mapped observation | — |
| entry-c9196eaedd725aae | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-historical-replay.py | No mapped observation | — |
| entry-c94dcebe35b8c431 | release | entrypoint | scripts/release/test-roadmap-schedule.py | No mapped observation | — |
| entry-ca4ed703011ab0f0 | shared-cryptography | entrypoint | scripts/cryptography/check-protected-resource-codegen.py | No mapped observation | — |
| entry-ca6cdc4b6cbe53f7 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-stack-bridge.py | No mapped observation | — |
| entry-cac734893dd53a00 | shared-cryptography | entrypoint | scripts/cryptography/check-macos-legacy-resident-codegen.py | No mapped observation | — |
| entry-cb8ca743c32414c0 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-resident.py | No mapped observation | — |
| entry-cb95f017af03d4c1 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-session-runtime.py | No mapped observation | — |
| entry-cc4513f3cb612fdf | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-kmac-key-model.py | No mapped observation | — |
| entry-ccb2212c1332f744 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-callback-stack.py | No mapped observation | — |
| entry-cd28505b305efe74 | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-assembly.py | No mapped observation | — |
| entry-cf157b3643e95f21 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-resident-model.py | No mapped observation | — |
| entry-cf6aef6dbe91ec48 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-rust-host-runner.py | No mapped observation | — |
| entry-cfc31571d2e195fb | shared-cryptography | entrypoint | scripts/cryptography/check-parallelhash-batch-bench.py | No mapped observation | — |
| entry-cfcd26f631fb3886 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-nt-namespace.py | No mapped observation | — |
| entry-d0979efaeb822852 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-publication-review.py | No mapped observation | — |
| entry-d2239baece8e1ac2 | shared-cryptography | entrypoint | scripts/cryptography/check-macos-resident-ci.py | No mapped observation | — |
| entry-d2e6ec267b40f008 | md5 | entrypoint | scripts/md5/check-md5-execution-ci.py | No mapped observation | — |
| entry-d38287f56a2e0806 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-batch-chains.py | No mapped observation | — |
| entry-d3a57ce9e4c8fe7c | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-operations.py | No mapped observation | — |
| entry-d52be6c41722c78a | repository | entrypoint | scripts/repository/test_facade_sha2.py | No mapped observation | — |
| entry-d65ab7c4dbe185c2 | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-throwing.py | No mapped observation | — |
| entry-d76b905e4b0939fa | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-runtime-startup.py | No mapped observation | — |
| entry-d809ff3b9160fa17 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-stream-entry.py | No mapped observation | — |
| entry-d8ee1c5c55b98e0c | shared-cryptography | entrypoint | scripts/cryptography/test-hardened-batch-package.py | No mapped observation | — |
| entry-d9b00dcd37d8b8ab | shared-cryptography | entrypoint | scripts/cryptography/check-macos-legacy-resident-package.py | No mapped observation | — |
| entry-da0a3b48fc423525 | sha1 | entrypoint | scripts/sha1/capture-sha1-hardened-native.py | No mapped observation | — |
| entry-daad2608a9327b0d | assurance | entrypoint | scripts/assurance/test-parallel-batch-kani.py | No mapped observation | — |
| entry-db5efd91f3001bfb | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-tuple-resident.py | No mapped observation | — |
| entry-db62679a169974a2 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-concurrent.py | No mapped observation | — |
| entry-db8f24d431b26028 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-stream.py | No mapped observation | — |
| entry-dbf7867dda6716d8 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-input-bridge.py | No mapped observation | — |
| entry-dc7d02d1d9845a40 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-batch-accelerated.py | No mapped observation | — |
| entry-dc9653bc8407d2ed | release | entrypoint | scripts/release/test-catalogue-plan.py | No mapped observation | — |
| entry-dcb3c7afc98ed79e | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-input-native.py | No mapped observation | — |
| entry-dcd15fede4393e6c | shared-cryptography | entrypoint | scripts/cryptography/test-batch-cleanup-flow.py | No mapped observation | — |
| entry-de24dd670f1f9bf9 | legacy | entrypoint | scripts/legacy-hash/check-legacy-package.py | No mapped observation | — |
| entry-decbfdffd17d886f | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-worker.py | No mapped observation | — |
| entry-df1392db109e9457 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-kmac-host-wire.py | No mapped observation | — |
| entry-df78d8ae993e9116 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-wave-bridge.py | No mapped observation | — |
| entry-dfdefbc31738c0b1 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-batch-worker.py | No mapped observation | — |
| entry-dff10bc60580fc4a | shared-cryptography | entrypoint | scripts/cryptography/check-parallelhash-local-batch-oracle.py | No mapped observation | — |
| entry-e00fd4c2934d2a5c | zeroization | entrypoint | scripts/zeroization/check-tag-miri.sh | No mapped observation | — |
| entry-e027758f49772f49 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-bounded-sha256.py | No mapped observation | — |
| entry-e3d0bcf485bce0df | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-teardown-results.py | No mapped observation | — |
| entry-e4dadb07487bf25c | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-keccak-simd-resident-model.py | No mapped observation | — |
| entry-e5da2cf101705514 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-lifecycle.py | No mapped observation | — |
| entry-e7ddf120ef465faa | md5 | entrypoint | scripts/md5/check-md5-cpu-qemu.sh | No mapped observation | — |
| entry-e81a12deed32c115 | sha2 | entrypoint | scripts/sha2/test-hardened-sha2-batch-codegen.py | No mapped observation | — |
| entry-e83ef6f5a9c50acc | kmac | entrypoint | scripts/kmac/check-kmac-execution-native.py | No mapped observation | — |
| entry-e84835d68ff36c74 | repository | entrypoint | scripts/repository/test_strict_windows_consumer.py | No mapped observation | — |
| entry-e86720fcb451a9f8 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-route-transport.py | No mapped observation | — |
| entry-e9316e76fdd4b262 | parallelhash | entrypoint | scripts/parallelhash/check-parallel-batch-cleanup.py | No mapped observation | — |
| entry-e97cfccfb0f10e77 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-probe.py | No mapped observation | — |
| entry-e9e021c32f9f8597 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-frames.py | No mapped observation | — |
| entry-e9ed7e9825d866f7 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sdk-status.py | No mapped observation | — |
| entry-eaa41734fee57c16 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-rehash.py | No mapped observation | — |
| entry-eca9495b7928ef6e | parallelhash | entrypoint | scripts/parallelhash/test-parallel-batch-cleanup.py | No mapped observation | — |
| entry-ed9de8e108325bc6 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-batch-completion.py | No mapped observation | — |
| entry-ef6f6bd7c9ff2b83 | repository | entrypoint | scripts/repository/check-legacy-execution-package.py | No mapped observation | — |
| entry-f05e9d34e2d8bcb5 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-keccak-simd-host.py | No mapped observation | — |
| entry-f07e331feadbf8f0 | legacy | entrypoint | scripts/legacy-hash/check-legacy-isolation.py | No mapped observation | — |
| entry-f0f1a7ddfafd5f79 | standards | entrypoint | scripts/standards/capture-authority-landings.py | No mapped observation | — |
| entry-f124dafc638a49e8 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-transport-review.py | No mapped observation | — |
| entry-f15c2fa44290a61c | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-batch-resident-model.py | No mapped observation | — |
| entry-f205147eea79d38b | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-lifetime.py | No mapped observation | — |
| entry-f32694a5fd6bc02b | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-lifecycle.py | No mapped observation | — |
| entry-f32e4c4328c623fb | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-capture-runner.py | No mapped observation | — |
| entry-f37849e5159e1603 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-parallel-typed-host.py | No mapped observation | — |
| entry-f378d8c15b3d5542 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-isolation-design.py | No mapped observation | — |
| entry-f3c4584a53228de2 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-leaf-binding.py | No mapped observation | — |
| entry-f3ff91ff1d488f8b | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-namespace-fixture.py | No mapped observation | — |
| entry-f49a9e95935ce0b4 | release | entrypoint | scripts/release/test-acceleration-plan.py | No mapped observation | — |
| entry-f539ed0547a78e8c | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-register-boundary.py | No mapped observation | — |
| entry-f54f2c65eb4d77ce | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha256.py | No mapped observation | — |
| entry-f58de412d131307d | assurance | entrypoint | scripts/assurance/check-hardened-batch-kani.py | No mapped observation | — |
| entry-f5a3f9e8a35453e9 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-primitives.py | No mapped observation | — |
| entry-f72c49f2ae44dc96 | shared-cryptography | entrypoint | scripts/cryptography/check-macos-resident-parallel-codegen.py | No mapped observation | — |
| entry-f737487d659e7545 | sha3 | entrypoint | scripts/sha3/capture-keccak-hardened-native.py | No mapped observation | — |
| entry-f7efed342d0f1dc1 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-isolated-boundary.py | No mapped observation | — |
| entry-f7f74ade70eda067 | sha1 | entrypoint | scripts/sha1/test-sha1-hardened-ci.py | No mapped observation | — |
| entry-f81736ab5fefdb48 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha-ni-owner.py | No mapped observation | — |
| entry-f84f1d9abdad3481 | shared-cryptography | entrypoint | scripts/cryptography/test-parallelhash-local-batch-oracle.py | No mapped observation | — |
| entry-f8591b0293abf6d3 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-facade.py | No mapped observation | — |
| entry-f9105459065afaa2 | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-handoff.py | No mapped observation | — |
| entry-f93b7d8a781e5c8e | kmac | entrypoint | scripts/kmac/capture-kmac-execution-native.py | No mapped observation | — |
| entry-f96afb678ec1de91 | md5 | entrypoint | scripts/md5/test-md5-native-capture.py | No mapped observation | — |
| entry-f99347511e467df7 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-batch-resident.py | No mapped observation | — |
| entry-fa29e77fa35ef133 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha2-accelerated.py | No mapped observation | — |
| entry-fa9b7c2321fc5ab2 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-sha3-worker.py | No mapped observation | — |
| entry-fd441d00b99e331e | shared-cryptography | entrypoint | scripts/cryptography/check-batch-output-codegen.py | No mapped observation | — |
| entry-fef89b3a17138b79 | parallelhash | entrypoint | scripts/parallelhash/test-batch-worker-drop-glue.py | No mapped observation | — |
| entry-fefb67b564c42844 | shared-cryptography | entrypoint | scripts/cryptography/test-windows-enclave-retained-rehash-host.py | No mapped observation | — |
| entry-ff40121e98f21778 | repository | entrypoint | scripts/repository/check-strict-accelerated-consumer.py | No mapped observation | — |
| entry-ff909cabf1167dcb | shared-cryptography | entrypoint | scripts/cryptography/check-windows-enclave-lifecycle.py | No mapped observation | — |
| entry-ffb1af25b521da30 | release | entrypoint | scripts/release/test-acceptance-metadata.py | No mapped observation | — |
| entry-ffc65c297c030a45 | shared-cryptography | entrypoint | scripts/cryptography/capture-hardened-batch-native.py | No mapped observation | — |
| kani-10d6ccdfdeaa0adf | core | inventory-only | scripts/assurance/check-kani.sh --required-groups core | passed | 2026-10-29T17:56:28Z |
| kani-33bf8df89ab57816 | legacy | inventory-only | scripts/assurance/check-kani.sh --required-groups legacy | passed | 2026-10-29T17:57:59Z |
| kani-5f1277e588bf08fd | sanitization | inventory-only | scripts/assurance/check-kani.sh --required-groups sanitization | passed | 2026-10-29T17:56:36Z |
| kani-a3250b4c1fb307b3 | acceleration | inventory-only | scripts/assurance/check-kani.sh --required-groups acceleration | passed | 2026-10-29T17:57:27Z |
| kani-c6fdd91f57e49ff6 | static_cpu | inventory-only | scripts/assurance/check-kani.sh --required-groups static_cpu | passed | 2026-10-29T17:58:09Z |
| kani-0010bedf4627201f | sha2 | kani | scripts/assurance/check-kani.sh --required-groups sha2 | passed | 2026-10-29T17:56:58Z |
| kani-0359032efe7506a6 | sha1 | kani | scripts/assurance/check-kani.sh --required-groups sha1 | passed | 2026-10-29T17:56:48Z |
| kani-587c6eac14110d17 | sha3 | kani | scripts/assurance/check-kani.sh --required-groups sha3 | passed | 2026-10-29T17:57:39Z |
| kani-6963894ec5d793b1 | tuplehash | kani | scripts/assurance/check-kani.sh --required-groups tuplehash | passed | 2026-10-29T17:57:50Z |
| kani-78c99ce7f8ddb72a | legacy_hmac | kani | python3 scripts/legacy-hmac/check-legacy-hmac-kani.py | passed | 2026-10-29T17:58:20Z |
| kani-83b160642dda6ea2 | hmac | kani | python3 scripts/hmac/check-hmac-kani.py | passed | 2026-10-29T17:57:37Z |
| kani-e09c9345908c0249 | parallelhash | kani | scripts/assurance/check-kani.sh --required-groups parallelhash | passed | 2026-10-29T17:57:19Z |
| kani-e212c20e6c0cd514 | kmac | kani | scripts/assurance/check-kani.sh --required-groups kmac | passed | 2026-10-29T17:57:08Z |
| kani-f158c3ad14210065 | md5 | kani | scripts/assurance/check-kani.sh --required-groups md5 | passed | 2026-10-29T17:56:41Z |
| matrix-012a6e54bebebf21 | hmac | matrix | cargo "+1.99.0" test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac | passed | 2026-10-29T19:50:12Z |
| matrix-0194ae868ff74f8f | sha1 | matrix | cargo "+1.99.0" test --locked -p brynja-legacy-sha1-std | passed | 2026-10-29T19:20:30Z |
| matrix-0332858b86d1334f | md5 | matrix | cargo "+1.98.1" test --locked -p brynja-legacy-md5-std | passed | 2026-10-29T19:19:57Z |
| matrix-0428eaaab7c725ef | sha2 | matrix | cargo "+1.96.1" run --quiet --locked --manifest-path assurance/sha256-public-api/Cargo.toml | passed | 2026-10-29T19:16:30Z |
| matrix-066feb57b045ea3d | sha3 | matrix | cargo "+1.97.0" test --quiet --locked --manifest-path assurance/cshake-public-api/Cargo.toml | passed | 2026-10-29T19:42:50Z |
| matrix-0745c4c3aecda211 | hmac | matrix | cargo "+1.94.0" test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac | passed | 2026-10-29T19:35:11Z |
| matrix-07adeb79f13c05b8 | sha1 | matrix | cargo "+1.96.1" test --locked -p brynja-legacy-sha1 | passed | 2026-10-29T19:16:01Z |
| matrix-081fa9498451f07f | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.98.0" test --locked --offline --manifest-path assurance/hosted-cpu-execution/Cargo.toml | passed | 2026-10-29T19:18:55Z |
| matrix-083b038110791b2c | hmac | matrix | cargo "+1.91.0" test --locked --offline -p brynja-mac-hmac --all-features | passed | 2026-10-29T19:10:17Z |
| matrix-0a38e2fd30f32715 | sha3 | matrix | cargo "+1.94.0" run --quiet --locked --manifest-path assurance/sp800185-final/Cargo.toml | passed | 2026-10-29T19:13:52Z |
| matrix-0d3cc50b9958bb77 | legacy | matrix | cargo "+1.97.0" test --locked --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib | passed | 2026-10-29T19:16:51Z |
| matrix-0d6865b183512e57 | legacy_hmac | matrix | cargo "+1.91.0" test --locked --offline -p brynja-legacy-hmac-std --all-features | passed | 2026-10-29T19:29:16Z |
| matrix-0d7cab51fa13c381 | repository | matrix (manual diagnostic) | cargo "+1.93.0" check --workspace --all-features | passed | 2026-10-29T19:11:58Z |
| matrix-0e32e447f51b9a9b | legacy_hmac | matrix | cargo "+1.96.0" test --locked --offline -p brynja-legacy-hmac --all-features | passed | 2026-10-29T19:37:56Z |
| matrix-0ec0a6a203ef4b6e | hmac | matrix | cargo "+1.90.0" test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac | passed | 2026-10-29T19:27:28Z |
| matrix-0f5fe4c6e059fa85 | hmac | matrix | cargo "+1.96.1" test --locked --offline -p brynja-mac-hmac --all-features | passed | 2026-10-29T19:15:53Z |
| matrix-0f7bba3458d61c11 | sha2 | matrix | cargo "+1.98.0" run --quiet --locked --manifest-path assurance/sha2-public-api/Cargo.toml | passed | 2026-10-29T19:46:21Z |
| matrix-0f9ae412b9a4f7d2 | sha2, sha3 | matrix | cargo "+1.99.0" run --quiet --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml | passed | 2026-10-29T19:51:24Z |
| matrix-0fcb949a676fe356 | sha1 | matrix | cargo "+1.91.0" test --locked -p brynja-legacy-sha1 | passed | 2026-10-29T19:10:43Z |
| matrix-0ff99440b3431b51 | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.92.0" test --locked --offline --manifest-path assurance/hosted-cpu-execution/Cargo.toml | passed | 2026-10-29T19:31:27Z |
| matrix-108d40703d43b464 | md5 | matrix | cargo "+1.98.1" test --locked -p brynja-legacy-md5 --all-features | passed | 2026-10-29T19:47:36Z |
| matrix-123b2f65154b43c5 | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.91.0" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml | passed | 2026-10-29T19:29:41Z |
| matrix-1286ee624071abb3 | hmac | matrix | cargo "+1.96.0" test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac | passed | 2026-10-29T19:14:49Z |
| matrix-128897aa0d04296b | sha3 | matrix | cargo "+1.95.0" run --quiet --locked --manifest-path assurance/sha3-public-api/Cargo.toml | passed | 2026-10-29T19:38:10Z |
| matrix-1299fc6f4b2ce3cc | sha1 | matrix | cargo "+1.96.1" test --locked -p brynja-legacy-sha1 --features cpu --test cpu | passed | 2026-10-29T19:41:37Z |
| matrix-12eb49dee95f1522 | sha1 | matrix | cargo "+1.93.0" test --locked -p brynja-legacy-sha1 --features cpu --test cpu | passed | 2026-10-29T19:33:58Z |
| matrix-12ef1289db5a42b7 | legacy | matrix | cargo "+1.96.1" test --locked --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib | passed | 2026-10-29T19:40:38Z |
| matrix-130a3b7d5c3971ad | md5 | matrix | cargo "+1.91.0" test --locked -p brynja-legacy-md5 --all-features | passed | 2026-10-29T19:29:44Z |
| matrix-133f55c491c6bcc2 | sha3 | matrix | cargo "+1.96.0" test --quiet --locked --manifest-path assurance/cshake-public-api/Cargo.toml | passed | 2026-10-29T19:39:19Z |
| matrix-1360bf0c95e01021 | sha1 | matrix | cargo "+1.97.0" test --locked -p brynja-legacy-sha1 --features cpu --test cpu | passed | 2026-10-29T19:17:19Z |
| matrix-1367a935e636c2f1 | legacy_hmac | matrix | cargo "+1.94.0" test --locked --offline -p brynja-legacy-hmac-std --all-features | passed | 2026-10-29T19:34:56Z |
| matrix-136b6779cb6bfe48 | legacy | matrix | cargo "+1.95.0" run --locked --manifest-path assurance/legacy-hash-final/Cargo.toml | passed | 2026-10-29T19:37:45Z |
| matrix-13812643f4786b83 | legacy | matrix | cargo "+1.90.0" test --locked --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib | passed | 2026-10-29T19:28:04Z |
| matrix-139a4bd4384f1831 | md5 | matrix | cargo "+1.97.0" test --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib | passed | 2026-10-29T19:43:12Z |
| matrix-13b1afebef44666c | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.97.0" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml | passed | 2026-10-29T19:42:59Z |
| matrix-13f52d58da22f135 | sha1 | matrix | cargo "+1.90.0" test --locked -p brynja-legacy-sha1 | passed | 2026-10-29T19:28:16Z |
| matrix-1513a566c33a5f0d | md5 | matrix | cargo "+1.98.1" test --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib | passed | 2026-10-29T19:48:50Z |
| matrix-15a54f77764def64 | repository | matrix (manual diagnostic) | cargo "+1.98.1" check --workspace --all-features | passed | 2026-10-29T19:46:46Z |
| matrix-16077cb16435cf7a | legacy | matrix | cargo "+1.94.0" run --locked --manifest-path assurance/legacy-hash-final/Cargo.toml | passed | 2026-10-29T19:35:46Z |
| matrix-169776c778a6f629 | sha1 | matrix | cargo "+1.90.0" test --locked -p brynja-legacy-sha1 --features cpu --test cpu | passed | 2026-10-29T19:28:23Z |
| matrix-16af47635a8abb23 | legacy | matrix | cargo "+1.98.0" test --locked --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib | passed | 2026-10-29T19:45:57Z |
| matrix-16b9fef71688d65b | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.99.1" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml | passed | 2026-10-29T19:52:15Z |
| matrix-17077c1e964aeada | legacy | matrix | cargo "+1.98.0" run --locked --manifest-path assurance/legacy-hash-final/Cargo.toml | passed | 2026-10-29T19:47:04Z |
| matrix-1913f20e491a8a3a | legacy_hmac | matrix | cargo "+1.99.0" test --locked --offline -p brynja-legacy-hmac-std --all-features | passed | 2026-10-29T19:20:38Z |
| matrix-1917cace29d2d539 | sha2 | matrix | cargo "+1.95.0" run --quiet --locked --manifest-path assurance/sha256-public-api/Cargo.toml | passed | 2026-10-29T19:37:57Z |
| matrix-19c0b62d50442683 | sha1 | matrix | cargo "+1.96.0" test --locked -p brynja-legacy-sha1 | passed | 2026-10-29T19:38:53Z |
| matrix-1b24ce53883951e7 | hmac | matrix | cargo "+1.98.1" test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac | passed | 2026-10-29T19:47:12Z |
| matrix-1bc230ec71d1ed43 | md5 | matrix | cargo "+1.90.0" test --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib | passed | 2026-10-29T19:28:12Z |
| matrix-1bfef8b551581ea6 | legacy | matrix | cargo "+1.97.1" run --locked --manifest-path assurance/legacy-hash-final/Cargo.toml | passed | 2026-10-29T19:18:12Z |
| matrix-1ccb7ded1a8882e6 | hmac | matrix | cargo "+1.92.0" test --locked --offline -p brynja-mac-hmac --all-features | passed | 2026-10-29T19:30:58Z |
| matrix-1ccbe8af5ec777de | legacy | matrix | cargo "+1.98.1" test --locked --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib | passed | 2026-10-29T19:19:30Z |
| matrix-1d345aec2d5ce0af | hmac | matrix | cargo "+1.92.0" test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac | passed | 2026-10-29T19:30:56Z |
| matrix-1d7605b5d8932589 | md5 | matrix | cargo "+1.96.1" test --locked -p brynja-legacy-md5-std | passed | 2026-10-29T19:41:14Z |
| matrix-1e03b6b086d5e473 | sha1 | matrix | cargo "+1.99.1" test --locked -p brynja-legacy-sha1 | passed | 2026-10-29T19:21:18Z |
| matrix-1e8c28d5473b3b1b | repository | matrix (manual diagnostic) | cargo "+1.92.0" check --workspace --all-features | passed | 2026-10-29T19:30:44Z |
| matrix-1f4180d166bd9b10 | md5 | matrix | cargo "+1.96.1" test --locked -p brynja-legacy-md5 --all-features | passed | 2026-10-29T19:40:28Z |
| matrix-1f6c05d897e5c985 | sha1 | matrix | cargo "+1.96.0" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib | passed | 2026-10-29T19:38:32Z |
| matrix-2004a3360f95ce99 | legacy_hmac | matrix | cargo "+1.91.0" test --locked --offline -p brynja-legacy-hmac --all-features | passed | 2026-10-29T19:29:07Z |
| matrix-206405f3b9faf63f | sha2 | matrix | cargo "+1.91.0" run --quiet --locked --manifest-path assurance/sha2-public-api/Cargo.toml | passed | 2026-10-29T19:30:18Z |
| matrix-20712b165edc11ff | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.98.0" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml | passed | 2026-10-29T19:46:41Z |
| matrix-20756c39590ce5f0 | sha1 | matrix | cargo "+1.98.0" test --locked -p brynja-legacy-sha1 | passed | 2026-10-29T19:18:39Z |
| matrix-21aa3bdfbd3c8c6d | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.96.0" test --locked --offline --manifest-path assurance/hosted-cpu-execution/Cargo.toml | passed | 2026-10-29T19:39:07Z |
| matrix-21b109ab78364bba | sha2 | matrix | cargo "+1.99.0" run --quiet --locked --manifest-path assurance/sha256-public-api/Cargo.toml | passed | 2026-10-29T19:51:12Z |
| matrix-21dcbbefcaa014e4 | legacy_hmac | matrix | cargo "+1.92.0" test --locked --offline -p brynja-legacy-hmac-std --all-features | passed | 2026-10-29T19:31:15Z |
| matrix-22570611fbbbd077 | legacy | matrix | cargo "+1.99.1" run --locked --manifest-path assurance/legacy-hash-final/Cargo.toml | passed | 2026-10-29T19:52:35Z |
| matrix-2298b83961758bb6 | repository | matrix (manual diagnostic) | cargo "+1.90.0" check --workspace --all-features | passed | 2026-10-29T19:09:21Z |
| matrix-234baaef59179682 | legacy_hmac | matrix | cargo "+1.94.0" test --locked --offline -p brynja-legacy-hmac --all-features | passed | 2026-10-29T19:34:26Z |
| matrix-25830c4f5f72be28 | hmac | matrix | cargo "+1.97.0" test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac | passed | 2026-10-29T19:41:41Z |
| matrix-25dbd928c006135b | sha1 | matrix | cargo "+1.98.1" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib | passed | 2026-10-29T19:47:24Z |
| matrix-26b50b4efcddcbe4 | sha1 | matrix | cargo "+1.98.1" test --locked -p brynja-legacy-sha1 --features cpu --test cpu | passed | 2026-10-29T19:20:08Z |
| matrix-272b091e4fd1b487 | legacy | matrix | cargo "+1.97.1" test --locked --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib | passed | 2026-10-29T19:44:06Z |
| matrix-2841d939f209054c | hmac | matrix | cargo "+1.97.1" test --locked --offline -p brynja-mac-hmac --all-features | passed | 2026-10-29T19:44:20Z |
| matrix-2a5336ef5a6a67ba | sha2 | matrix | cargo "+1.96.1" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml | passed | 2026-10-29T19:40:11Z |
| matrix-2ecb4e1706ba6d8a | sha2 | matrix | cargo "+1.97.0" run --quiet --locked --manifest-path assurance/sha256-public-api/Cargo.toml | passed | 2026-10-29T19:43:36Z |
| matrix-2ee967de9092a1e8 | sha2 | matrix | cargo "+1.93.0" run --quiet --locked --manifest-path assurance/sha256-public-api/Cargo.toml | passed | 2026-10-29T19:34:11Z |
| matrix-2f1e47d95356f5ab | legacy | matrix | cargo "+1.93.0" run --locked --manifest-path assurance/legacy-hash-final/Cargo.toml | passed | 2026-10-29T19:12:33Z |
| matrix-300a91b77c7f6caf | sha3 | matrix | cargo "+1.90.0" run --quiet --locked --manifest-path assurance/sp800185-final/Cargo.toml | passed | 2026-10-29T19:29:00Z |
| matrix-30d9dddb3af78154 | sha2 | matrix | cargo "+1.94.0" run --quiet --locked --manifest-path assurance/sha256-public-api/Cargo.toml | passed | 2026-10-29T19:13:39Z |
| matrix-30e0dc2fa7176d0d | md5 | matrix | cargo "+1.95.0" test --locked -p brynja-legacy-md5-std | passed | 2026-10-29T19:14:18Z |
| matrix-313301c99b551518 | sha3 | matrix | cargo "+1.99.0" test --quiet --locked --manifest-path assurance/cshake-public-api/Cargo.toml | passed | 2026-10-29T19:49:58Z |
| matrix-315e140e6a4292bd | repository | matrix (manual diagnostic) | cargo "+1.98.0" check --workspace --all-features | passed | 2026-10-29T19:44:54Z |
| matrix-324a8d754a1f8ac9 | sha3 | matrix | cargo "+1.97.0" run --quiet --locked --manifest-path assurance/sp800185-final/Cargo.toml | passed | 2026-10-29T19:44:02Z |
| matrix-328e865d158b88f2 | md5 | matrix | cargo "+1.98.0" test --locked -p brynja-legacy-md5 --all-features | passed | 2026-10-29T19:45:46Z |
| matrix-32daffeeb94bf4eb | legacy | matrix | cargo "+1.96.0" run --locked --manifest-path assurance/legacy-hash-final/Cargo.toml | passed | 2026-10-29T19:15:21Z |
| matrix-331d0b4a465fafa6 | sha2 | matrix | cargo "+1.91.0" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml | passed | 2026-10-29T19:29:31Z |
| matrix-3470b417b3170742 | hmac | matrix | cargo "+1.91.0" test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac | passed | 2026-10-29T19:10:20Z |
| matrix-3488ee2fc6643130 | sha3 | matrix | cargo "+1.91.0" test --quiet --locked --manifest-path assurance/cshake-public-api/Cargo.toml | passed | 2026-10-29T19:10:55Z |
| matrix-36388565a72f2e22 | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.99.0" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml | passed | 2026-10-29T19:20:49Z |
| matrix-36e0f3e767515a0f | legacy_hmac | matrix | cargo "+1.96.1" test --locked --offline -p brynja-legacy-hmac --all-features | passed | 2026-10-29T19:39:46Z |
| matrix-38122be535eccb51 | hmac | matrix | cargo "+1.93.0" test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac | passed | 2026-10-29T19:12:10Z |
| matrix-3902d4b1d617765e | sha3 | matrix | cargo "+1.91.0" run --quiet --locked --manifest-path assurance/sp800185-final/Cargo.toml | passed | 2026-10-29T19:11:05Z |
| matrix-39e867bdeb36a977 | hmac | matrix | cargo "+1.97.1" test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac | passed | 2026-10-29T19:43:29Z |
| matrix-3aaab76df4acd979 | sha1 | matrix | cargo "+1.99.1" test --locked -p brynja-legacy-sha1-std | passed | 2026-10-29T19:51:25Z |
| matrix-3b4a11c2d52f9b37 | legacy | matrix | cargo "+1.96.0" test --locked --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib | passed | 2026-10-29T19:38:42Z |
| matrix-3b5b8756ad5940d2 | sha3 | matrix | cargo "+1.97.0" run --quiet --locked --manifest-path assurance/sha3-public-api/Cargo.toml | passed | 2026-10-29T19:43:49Z |
| matrix-3c66d944293fa8c0 | hmac | matrix | cargo "+1.93.0" test --locked --offline -p brynja-mac-hmac --all-features | passed | 2026-10-29T19:32:57Z |
| matrix-3c8c0ab3128dff00 | sha2, sha3 | matrix | cargo "+1.91.0" run --quiet --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml | passed | 2026-10-29T19:30:40Z |
| matrix-3d7c721ae4c16df5 | legacy_hmac | matrix | cargo "+1.97.0" test --locked --offline -p brynja-legacy-hmac-std --all-features | passed | 2026-10-29T19:42:37Z |
| matrix-3e4a603da1b2946f | hmac | matrix | cargo "+1.99.1" test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac | passed | 2026-10-29T19:20:55Z |
| matrix-3e76796f590246fe | md5 | matrix | cargo "+1.90.0" test --locked -p brynja-legacy-md5-std | passed | 2026-10-29T19:28:00Z |
| matrix-3e7f7433dc04ea7f | hmac | matrix | cargo "+1.99.0" test --locked --offline -p brynja-mac-hmac --all-features | passed | 2026-10-29T19:49:58Z |
| matrix-3f0f5176dc119876 | hmac | matrix | cargo "+1.98.0" test --locked --offline -p brynja-mac-hmac --all-features | passed | 2026-10-29T19:18:43Z |
| matrix-400a7408380de4cc | sha3 | matrix | cargo "+1.97.1" run --quiet --locked --manifest-path assurance/sp800185-final/Cargo.toml | passed | 2026-10-29T19:45:58Z |
| matrix-40f12c05b426f03d | sha3 | matrix | cargo "+1.91.0" run --quiet --locked --manifest-path assurance/sp800185-public-api/Cargo.toml | passed | 2026-10-29T19:30:31Z |
| matrix-40f5c7d8404e1068 | md5 | matrix | cargo "+1.98.0" test --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib | passed | 2026-10-29T19:19:06Z |
| matrix-418294787284505c | sha3 | matrix | cargo "+1.93.0" run --quiet --locked --manifest-path assurance/sha3-public-api/Cargo.toml | passed | 2026-10-29T19:12:45Z |
| matrix-42c918091e60f1e8 | repository | matrix (manual diagnostic) | cargo "+1.99.0" check --workspace --all-features | passed | 2026-10-29T19:19:55Z |
| matrix-438d861f394984a8 | sha1 | matrix | cargo "+1.98.1" test --locked -p brynja-legacy-sha1-std | passed | 2026-10-29T19:47:56Z |
| matrix-448f7e1322cd20bc | hmac | matrix | cargo "+1.99.0" test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac | passed | 2026-10-29T19:20:07Z |
| matrix-44a2a2df1d667a69 | sha2 | matrix | cargo "+1.94.0" run --quiet --locked --manifest-path assurance/sha2-public-api/Cargo.toml | passed | 2026-10-29T19:35:41Z |
| matrix-45eb665504677bf3 | sha1 | matrix | cargo "+1.97.1" test --locked -p brynja-legacy-sha1 --features cpu --test cpu | passed | 2026-10-29T19:45:19Z |
| matrix-469071311df8eebd | md5 | matrix | cargo "+1.93.0" test --locked -p brynja-legacy-md5 --all-features | passed | 2026-10-29T19:12:22Z |
| matrix-476965a962134aca | hmac | matrix | cargo "+1.92.0" test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac | passed | 2026-10-29T19:31:08Z |
| matrix-488f4f2645bed6be | sha2, sha3 | matrix | cargo "+1.97.0" run --quiet --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml | passed | 2026-10-29T19:17:32Z |
| matrix-48e376e6681ab8be | md5 | matrix | cargo "+1.96.0" test --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib | passed | 2026-10-29T19:39:29Z |
| matrix-48edba43a9b71ccc | sha2, sha3 | matrix | cargo "+1.96.1" run --quiet --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml | passed | 2026-10-29T19:42:02Z |
| matrix-4af32c66aad773bd | hmac | matrix | cargo "+1.90.0" test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac | passed | 2026-10-29T19:09:33Z |
| matrix-4c3203875ff14180 | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.96.1" test --locked --offline --manifest-path assurance/hosted-cpu-execution/Cargo.toml | passed | 2026-10-29T19:16:06Z |
| matrix-4c9a8c11942e21c9 | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.99.1" test --locked --offline --manifest-path assurance/hosted-cpu-execution/Cargo.toml | passed | 2026-10-29T19:21:41Z |
| matrix-4cf4b32f11972078 | hmac | matrix | cargo "+1.97.1" test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac | passed | 2026-10-29T19:17:29Z |
| matrix-4d13b41555532b1d | hmac | matrix | cargo "+1.98.1" test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac | passed | 2026-10-29T19:46:59Z |
| matrix-4e5cdcaf5f715a77 | sha3 | matrix | cargo "+1.99.0" run --quiet --locked --manifest-path assurance/sp800185-public-api/Cargo.toml | passed | 2026-10-29T19:20:42Z |
| matrix-5018f7c9b6836521 | hmac | matrix | cargo "+1.91.0" test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac | passed | 2026-10-29T19:29:18Z |
| matrix-504bf06db24e5876 | md5 | matrix | cargo "+1.99.0" test --locked -p brynja-legacy-md5-std | passed | 2026-10-29T19:50:36Z |
| matrix-5077a27b71ad516e | sha2 | matrix | cargo "+1.96.0" run --quiet --locked --manifest-path assurance/sha2-public-api/Cargo.toml | passed | 2026-10-29T19:39:06Z |
| matrix-50c98313069328c5 | hmac | matrix | cargo "+1.98.0" test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac | passed | 2026-10-29T19:18:17Z |
| matrix-51b8f98c45027911 | sha1 | matrix | cargo "+1.99.0" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib | passed | 2026-10-29T19:49:10Z |
| matrix-51ca5e5ddee7462a | sha2 | matrix | cargo "+1.96.1" run --quiet --locked --manifest-path assurance/sha2-public-api/Cargo.toml | passed | 2026-10-29T19:41:02Z |
| matrix-52837d599838c4fe | legacy_hmac | matrix | cargo "+1.97.1" test --locked --offline -p brynja-legacy-hmac-std --all-features | passed | 2026-10-29T19:17:48Z |
| matrix-53c9eed7077746d4 | legacy_hmac | matrix | cargo "+1.99.0" test --locked --offline -p brynja-legacy-hmac --all-features | passed | 2026-10-29T19:48:34Z |
| matrix-5419a080b2a60f1b | repository | matrix (manual diagnostic) | cargo "+1.97.0" check --workspace --all-features | passed | 2026-10-29T19:41:29Z |
| matrix-548db99a6926cf75 | sha2 | matrix | cargo "+1.95.0" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml | passed | 2026-10-29T19:13:59Z |
| matrix-54a9347af859046d | md5 | matrix | cargo "+1.96.0" test --locked -p brynja-legacy-md5 --all-features | passed | 2026-10-29T19:15:01Z |
| matrix-550ca01b69b8ce73 | md5 | matrix | cargo "+1.91.0" test --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib | passed | 2026-10-29T19:10:40Z |
| matrix-563ed64c52fcebea | legacy | matrix | cargo "+1.95.0" test --locked --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib | passed | 2026-10-29T19:14:10Z |
| matrix-56a300ba1e05ab17 | sha3 | matrix | cargo "+1.94.0" test --quiet --locked --manifest-path assurance/cshake-public-api/Cargo.toml | passed | 2026-10-29T19:13:33Z |
| matrix-571795f5b3a4fbf5 | sha2 | matrix | cargo "+1.98.1" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml | passed | 2026-10-29T19:19:18Z |
| matrix-58797a3595f97be8 | md5 | matrix | cargo "+1.94.0" test --locked -p brynja-legacy-md5-std | passed | 2026-10-29T19:35:35Z |
| matrix-587d9143cca1f590 | sha1 | matrix | cargo "+1.99.1" test --locked -p brynja-legacy-sha1 --features cpu --test cpu | passed | 2026-10-29T19:52:44Z |
| matrix-58d1aa56d0ce3e0d | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.91.0" test --locked --offline --manifest-path assurance/hosted-cpu-execution/Cargo.toml | passed | 2026-10-29T19:10:28Z |
| matrix-5a7f64cc5981345e | sha3 | matrix | cargo "+1.98.1" run --quiet --locked --manifest-path assurance/sha3-public-api/Cargo.toml | passed | 2026-10-29T19:49:27Z |
| matrix-5b41889248dbb4a5 | sha3 | matrix | cargo "+1.92.0" run --quiet --locked --manifest-path assurance/sha3-public-api/Cargo.toml | passed | 2026-10-29T19:32:25Z |
| matrix-5b89bf2878f05809 | sha3 | matrix | cargo "+1.97.1" test --quiet --locked --manifest-path assurance/cshake-public-api/Cargo.toml | passed | 2026-10-29T19:44:41Z |
| matrix-5c0f231672f6c69d | sha3 | matrix | cargo "+1.92.0" run --quiet --locked --manifest-path assurance/sp800185-public-api/Cargo.toml | passed | 2026-10-29T19:32:19Z |
| matrix-5c2d7254ad5b761c | sha2 | matrix | cargo "+1.93.0" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml | passed | 2026-10-29T19:32:56Z |
| matrix-5ce7583cd627f1d8 | legacy_hmac | matrix | cargo "+1.95.0" test --locked --offline -p brynja-legacy-hmac-std --all-features | passed | 2026-10-29T19:36:58Z |
| matrix-5d450857c88e5c0d | sha3 | matrix | cargo "+1.94.0" run --quiet --locked --manifest-path assurance/sp800185-public-api/Cargo.toml | passed | 2026-10-29T19:35:53Z |
| matrix-5e37646d4852a726 | sha2 | matrix | cargo "+1.95.0" run --quiet --locked --manifest-path assurance/sha2-public-api/Cargo.toml | passed | 2026-10-29T19:14:22Z |
| matrix-5ea082b9be54fa88 | sha3 | matrix | cargo "+1.99.1" run --quiet --locked --manifest-path assurance/sp800185-public-api/Cargo.toml | passed | 2026-10-29T19:51:49Z |
| matrix-5f4fe9b476e14b53 | sha1 | matrix | cargo "+1.97.1" test --locked -p brynja-legacy-sha1-std | passed | 2026-10-29T19:17:52Z |
| matrix-5f76ffa0b3cfb0a1 | hmac | matrix | cargo "+1.95.0" test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac | passed | 2026-10-29T19:36:19Z |
| matrix-5f7d32c22b29d217 | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.95.0" test --locked --offline --manifest-path assurance/hosted-cpu-execution/Cargo.toml | passed | 2026-10-29T19:37:10Z |
| matrix-61f0fd57177ef26e | md5 | matrix | cargo "+1.97.0" test --locked -p brynja-legacy-md5-std | passed | 2026-10-29T19:17:08Z |
| matrix-62ae4aeb6d13fee7 | sha2 | matrix | cargo "+1.97.1" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml | passed | 2026-10-29T19:43:43Z |
| matrix-636deb1c9ea2877b | sha2 | matrix | cargo "+1.90.0" run --quiet --locked --manifest-path assurance/sha256-public-api/Cargo.toml | passed | 2026-10-29T19:28:35Z |
| matrix-63f19903f891d40a | hmac | matrix | cargo "+1.96.1" test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac | passed | 2026-10-29T19:15:38Z |
| matrix-63fc02c770eceb6c | sha2 | matrix | cargo "+1.96.0" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml | passed | 2026-10-29T19:38:21Z |
| matrix-6499f790ef52ca36 | md5 | matrix | cargo "+1.97.1" test --locked -p brynja-legacy-md5-std | passed | 2026-10-29T19:44:57Z |
| matrix-64dd81d33f40dd03 | md5 | matrix | cargo "+1.99.1" test --locked -p brynja-legacy-md5-std | passed | 2026-10-29T19:52:24Z |
| matrix-65abf9fed1da87d3 | repository | matrix (manual diagnostic) | cargo "+1.99.1" check --workspace --all-features | passed | 2026-10-29T19:50:11Z |
| matrix-65af95ac5c09aaa7 | md5 | matrix | cargo "+1.92.0" test --locked -p brynja-legacy-md5-std | passed | 2026-10-29T19:11:30Z |
| matrix-6603de83b31b38a7 | sha1 | matrix | cargo "+1.98.0" test --locked -p brynja-legacy-sha1-std | passed | 2026-10-29T19:46:08Z |
| matrix-664a23eddb3d1e7e | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.97.1" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml | passed | 2026-10-29T19:18:00Z |
| matrix-66a88ac450cda76b | legacy | matrix | cargo "+1.99.0" test --locked --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib | passed | 2026-10-29T19:49:22Z |
| matrix-67163140119ccea5 | legacy_hmac | matrix | cargo "+1.90.0" test --locked --offline -p brynja-legacy-hmac --all-features | passed | 2026-10-29T19:27:16Z |
| matrix-673f4e8b7166ec87 | sha2 | matrix | cargo "+1.97.1" run --quiet --locked --manifest-path assurance/sha2-public-api/Cargo.toml | passed | 2026-10-29T19:44:29Z |
| matrix-689ba5a793e39694 | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.96.0" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml | passed | 2026-10-29T19:15:10Z |
| matrix-694c896a80876edf | sha2 | matrix | cargo "+1.99.1" run --quiet --locked --manifest-path assurance/sha2-public-api/Cargo.toml | passed | 2026-10-29T19:51:37Z |
| matrix-695c0258e6324cec | sha2 | matrix | cargo "+1.97.1" run --quiet --locked --manifest-path assurance/sha256-public-api/Cargo.toml | passed | 2026-10-29T19:45:32Z |
| matrix-6a490e6a27cd0971 | hmac | matrix | cargo "+1.98.1" test --locked --offline -p brynja-mac-hmac --all-features | passed | 2026-10-29T19:48:00Z |
| matrix-6a9e70cf32773ee2 | hmac | matrix | cargo "+1.96.0" test --locked --offline -p brynja-mac-hmac --all-features | passed | 2026-10-29T19:38:40Z |
| matrix-6aa767417e5fc1b9 | sha2, sha3 | matrix | cargo "+1.92.0" run --quiet --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml | passed | 2026-10-29T19:11:54Z |
| matrix-6ac6ec713a3c8dfc | sha1 | matrix | cargo "+1.96.1" test --locked -p brynja-legacy-sha1-std | passed | 2026-10-29T19:40:49Z |
| matrix-6ad9df6f8b16a29f | legacy_hmac | matrix | cargo "+1.96.0" test --locked --offline -p brynja-legacy-hmac-std --all-features | passed | 2026-10-29T19:14:59Z |
| matrix-6b1cc158f90697cb | hmac | matrix | cargo "+1.97.1" test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac | passed | 2026-10-29T19:44:34Z |
| matrix-6d45fabaa9d20cdc | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.97.0" test --locked --offline --manifest-path assurance/hosted-cpu-execution/Cargo.toml | passed | 2026-10-29T19:42:48Z |
| matrix-6d5f4c2caaf32460 | hmac | matrix | cargo "+1.91.0" test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac | passed | 2026-10-29T19:29:31Z |
| matrix-6d6f5c14fdbfd90f | sha2, sha3 | matrix | cargo "+1.98.1" run --quiet --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml | passed | 2026-10-29T19:20:21Z |
| matrix-6f12d469d4c2710f | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.94.0" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml | passed | 2026-10-29T19:35:23Z |
| matrix-7023b76843d6bcda | hmac | matrix | cargo "+1.99.0" test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac | passed | 2026-10-29T19:48:46Z |
| matrix-7118bf8c7ba0d141 | sha3 | matrix | cargo "+1.94.0" run --quiet --locked --manifest-path assurance/sha3-public-api/Cargo.toml | passed | 2026-10-29T19:36:09Z |
| matrix-71f0e22e021ddd09 | sha2, sha3 | matrix | cargo "+1.95.0" run --quiet --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml | passed | 2026-10-29T19:14:42Z |
| matrix-733ed3da8a1c66b3 | legacy | matrix | cargo "+1.97.0" run --locked --manifest-path assurance/legacy-hash-final/Cargo.toml | passed | 2026-10-29T19:43:24Z |
| matrix-7341a5e3e4985738 | sha2 | matrix | cargo "+1.92.0" run --quiet --locked --manifest-path assurance/sha256-public-api/Cargo.toml | passed | 2026-10-29T19:32:12Z |
| matrix-737871dcec3577da | legacy_hmac | matrix | cargo "+1.97.1" test --locked --offline -p brynja-legacy-hmac --all-features | passed | 2026-10-29T19:43:16Z |
| matrix-74233da409bfb13d | repository | matrix (manual diagnostic) | cargo "+1.91.0" check --workspace --all-features | passed | 2026-10-29T19:28:54Z |
| matrix-74d3c168bdaf9a52 | legacy | matrix | cargo "+1.96.1" run --locked --manifest-path assurance/legacy-hash-final/Cargo.toml | passed | 2026-10-29T19:41:25Z |
| matrix-7526eca179a27d55 | legacy_hmac | matrix | cargo "+1.93.0" test --locked --offline -p brynja-legacy-hmac-std --all-features | passed | 2026-10-29T19:12:11Z |
| matrix-7581f736b08200f5 | legacy | matrix | cargo "+1.91.0" test --locked --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib | passed | 2026-10-29T19:29:55Z |
| matrix-75a0357728740dbb | sha3 | matrix | cargo "+1.93.0" run --quiet --locked --manifest-path assurance/sp800185-public-api/Cargo.toml | passed | 2026-10-29T19:12:46Z |
| matrix-76d138d12e2ebd60 | legacy | matrix | cargo "+1.99.0" run --locked --manifest-path assurance/legacy-hash-final/Cargo.toml | passed | 2026-10-29T19:21:00Z |
| matrix-779479b04988454c | sha1 | matrix | cargo "+1.90.0" test --locked -p brynja-legacy-sha1-std | passed | 2026-10-29T19:09:56Z |
| matrix-7853e39b5ecc034d | sha3 | matrix | cargo "+1.98.0" run --quiet --locked --manifest-path assurance/sp800185-public-api/Cargo.toml | passed | 2026-10-29T19:46:33Z |
| matrix-78b479605604fd98 | sha2 | matrix | cargo "+1.99.0" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml | passed | 2026-10-29T19:48:59Z |
| matrix-79483e6e85fcf417 | md5 | matrix | cargo "+1.99.1" test --locked -p brynja-legacy-md5 --all-features | passed | 2026-10-29T19:51:03Z |
| matrix-79dce88f39b213f9 | sha2 | matrix | cargo "+1.98.0" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml | passed | 2026-10-29T19:45:34Z |
| matrix-7a93e9c6e6466b5f | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.93.0" test --locked --offline --manifest-path assurance/hosted-cpu-execution/Cargo.toml | passed | 2026-10-29T19:33:24Z |
| matrix-7b6d75fa3ddc195f | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.96.1" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml | passed | 2026-10-29T19:41:02Z |
| matrix-7bbb7398e8cfaf89 | sha3 | matrix | cargo "+1.98.0" run --quiet --locked --manifest-path assurance/sha3-public-api/Cargo.toml | passed | 2026-10-29T19:47:28Z |
| matrix-7bd2be162c86c129 | sha3 | matrix | cargo "+1.96.1" run --quiet --locked --manifest-path assurance/sp800185-final/Cargo.toml | passed | 2026-10-29T19:16:42Z |
| matrix-7bf22ff24718aae0 | sha3 | matrix | cargo "+1.93.0" test --quiet --locked --manifest-path assurance/cshake-public-api/Cargo.toml | passed | 2026-10-29T19:33:58Z |
| matrix-7d1b83dec23ca82a | sha3 | matrix | cargo "+1.98.0" test --quiet --locked --manifest-path assurance/cshake-public-api/Cargo.toml | passed | 2026-10-29T19:18:52Z |
| matrix-7f990826485145f2 | sha2 | matrix | cargo "+1.97.0" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml | passed | 2026-10-29T19:16:40Z |
| matrix-7fab6636382e91de | hmac | matrix | cargo "+1.99.1" test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac | passed | 2026-10-29T19:52:05Z |
| matrix-80284ed3dd7497f7 | sha3 | matrix | cargo "+1.99.1" run --quiet --locked --manifest-path assurance/sp800185-final/Cargo.toml | passed | 2026-10-29T19:22:12Z |
| matrix-80366c3187a0a246 | sha2 | matrix | cargo "+1.91.0" run --quiet --locked --manifest-path assurance/sha256-public-api/Cargo.toml | passed | 2026-10-29T19:10:52Z |
| matrix-80936aafae3a8bcf | repository | matrix (manual diagnostic) | cargo "+1.97.1" check --workspace --all-features | passed | 2026-10-29T19:17:17Z |
| matrix-815ea3afc55e6c81 | hmac | matrix | cargo "+1.97.0" test --locked --offline -p brynja-mac-hmac --all-features | passed | 2026-10-29T19:42:21Z |
| matrix-81b8f29a55ad900b | sha3 | matrix | cargo "+1.92.0" test --quiet --locked --manifest-path assurance/cshake-public-api/Cargo.toml | passed | 2026-10-29T19:32:06Z |
| matrix-8337dfaf87a255d3 | md5 | matrix | cargo "+1.97.0" test --locked -p brynja-legacy-md5 --all-features | passed | 2026-10-29T19:42:16Z |
| matrix-857310e62b01a172 | md5 | matrix | cargo "+1.97.1" test --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib | passed | 2026-10-29T19:45:08Z |
| matrix-87f4cd3e555044b6 | sha1 | matrix | cargo "+1.99.0" test --locked -p brynja-legacy-sha1 --features cpu --test cpu | passed | 2026-10-29T19:50:59Z |
| matrix-8954168c9cd5cc9c | sha3 | matrix | cargo "+1.97.0" run --quiet --locked --manifest-path assurance/sp800185-public-api/Cargo.toml | passed | 2026-10-29T19:43:03Z |
| matrix-897347d7a547437a | md5 | matrix | cargo "+1.99.0" test --locked -p brynja-legacy-md5 --all-features | passed | 2026-10-29T19:20:19Z |
| matrix-8a893768adc766c6 | sha2, sha3 | matrix | cargo "+1.93.0" run --quiet --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml | passed | 2026-10-29T19:34:26Z |
| matrix-8aa671a6f56bf726 | hmac | matrix | cargo "+1.93.0" test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac | passed | 2026-10-29T19:32:44Z |
| matrix-8db4682b8aa59a64 | legacy_hmac | matrix | cargo "+1.98.1" test --locked --offline -p brynja-legacy-hmac --all-features | passed | 2026-10-29T19:19:05Z |
| matrix-8e00dd86ff586b0f | hmac | matrix | cargo "+1.97.0" test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac | passed | 2026-10-29T19:41:54Z |
| matrix-919c9e5dbe5a2a82 | sha2 | matrix | cargo "+1.98.1" run --quiet --locked --manifest-path assurance/sha256-public-api/Cargo.toml | passed | 2026-10-29T19:49:13Z |
| matrix-92ea71fb23dc87bd | hmac | matrix | cargo "+1.92.0" test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac | passed | 2026-10-29T19:11:19Z |
| matrix-9528c77ebe9a275d | sha2, sha3 | matrix | cargo "+1.94.0" run --quiet --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml | passed | 2026-10-29T19:36:23Z |
| matrix-966c3d7b2ac06144 | md5 | matrix | cargo "+1.92.0" test --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib | passed | 2026-10-29T19:31:49Z |
| matrix-96d04d817a8fff5e | sha1 | matrix | cargo "+1.97.0" test --locked -p brynja-legacy-sha1 | passed | 2026-10-29T19:42:28Z |
| matrix-97549b2e2193c108 | md5 | matrix | cargo "+1.90.0" test --locked -p brynja-legacy-md5 --all-features | passed | 2026-10-29T19:09:45Z |
| matrix-9768f611b75db019 | sha2 | matrix | cargo "+1.99.1" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml | passed | 2026-10-29T19:50:50Z |
| matrix-981d0d40d713f10e | legacy | matrix | cargo "+1.98.1" run --locked --manifest-path assurance/legacy-hash-final/Cargo.toml | passed | 2026-10-29T19:49:01Z |
| matrix-987d14795ac8c6d1 | sha1 | matrix | cargo "+1.99.0" test --locked -p brynja-legacy-sha1 | passed | 2026-10-29T19:49:34Z |
| matrix-98a38e64db636c6c | sha2 | matrix | cargo "+1.92.0" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml | passed | 2026-10-29T19:11:20Z |
| matrix-99145fd9075b917c | md5 | matrix | cargo "+1.95.0" test --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib | passed | 2026-10-29T19:37:33Z |
| matrix-99d75d62401be17b | sha3 | matrix | cargo "+1.97.1" run --quiet --locked --manifest-path assurance/sp800185-public-api/Cargo.toml | passed | 2026-10-29T19:18:04Z |
| matrix-9a780a98686ab13f | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.92.0" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml | passed | 2026-10-29T19:31:37Z |
| matrix-9c8e831c21445852 | hmac | matrix | cargo "+1.96.0" test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac | passed | 2026-10-29T19:38:08Z |
| matrix-9cabd4ccb07d43b1 | hmac | matrix | cargo "+1.96.1" test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac | passed | 2026-10-29T19:40:51Z |
| matrix-9ce577293aebb690 | sha1 | matrix | cargo "+1.94.0" test --locked -p brynja-legacy-sha1 --features cpu --test cpu | passed | 2026-10-29T19:35:58Z |
| matrix-9e1e895408117236 | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.98.1" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml | passed | 2026-10-29T19:48:39Z |
| matrix-a10c6004260fd163 | legacy_hmac | matrix | cargo "+1.98.1" test --locked --offline -p brynja-legacy-hmac-std --all-features | passed | 2026-10-29T19:48:16Z |
| matrix-a200c64046e99d65 | sha2, sha3 | matrix | cargo "+1.98.0" run --quiet --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml | passed | 2026-10-29T19:47:41Z |
| matrix-a27fbce6c935f0ae | sha2, sha3 | matrix | cargo "+1.99.1" run --quiet --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml | passed | 2026-10-29T19:53:06Z |
| matrix-a43cf183de5c32e9 | legacy | matrix | cargo "+1.90.0" run --locked --manifest-path assurance/legacy-hash-final/Cargo.toml | passed | 2026-10-29T19:09:47Z |
| matrix-a4df7781ee71aafb | legacy_hmac | matrix | cargo "+1.93.0" test --locked --offline -p brynja-legacy-hmac --all-features | passed | 2026-10-29T19:32:32Z |
| matrix-a5b907332f7cc80e | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.99.0" test --locked --offline --manifest-path assurance/hosted-cpu-execution/Cargo.toml | passed | 2026-10-29T19:50:24Z |
| matrix-a70389e55d37e85b | sha2 | matrix | cargo "+1.92.0" run --quiet --locked --manifest-path assurance/sha2-public-api/Cargo.toml | passed | 2026-10-29T19:11:45Z |
| matrix-a7a17d74aea5a189 | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.97.1" test --locked --offline --manifest-path assurance/hosted-cpu-execution/Cargo.toml | passed | 2026-10-29T19:44:46Z |
| matrix-a807a04b172e1cd9 | sha1 | matrix | cargo "+1.94.0" test --locked -p brynja-legacy-sha1-std | passed | 2026-10-29T19:35:27Z |
| matrix-a9f0726fad3f1665 | legacy | matrix | cargo "+1.91.0" run --locked --manifest-path assurance/legacy-hash-final/Cargo.toml | passed | 2026-10-29T19:30:04Z |
| matrix-aa84a27728cb4ed3 | sha2 | matrix | cargo "+1.90.0" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml | passed | 2026-10-29T19:27:40Z |
| matrix-aafdfea0c25fcb01 | legacy_hmac | matrix | cargo "+1.92.0" test --locked --offline -p brynja-legacy-hmac --all-features | passed | 2026-10-29T19:11:08Z |
| matrix-ab026bc0fe4b67b6 | sha1 | matrix | cargo "+1.98.0" test --locked -p brynja-legacy-sha1 --features cpu --test cpu | passed | 2026-10-29T19:47:16Z |
| matrix-ab344c50633fe792 | sha3 | matrix | cargo "+1.95.0" test --quiet --locked --manifest-path assurance/cshake-public-api/Cargo.toml | passed | 2026-10-29T19:37:31Z |
| matrix-ac9b9c309d612153 | hmac | matrix | cargo "+1.98.0" test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac | passed | 2026-10-29T19:45:19Z |
| matrix-ad5ddcc9ebfbb019 | sha3 | matrix | cargo "+1.98.0" run --quiet --locked --manifest-path assurance/sp800185-final/Cargo.toml | passed | 2026-10-29T19:19:32Z |
| matrix-af331c62ad0d74f9 | sha3 | matrix | cargo "+1.97.1" run --quiet --locked --manifest-path assurance/sha3-public-api/Cargo.toml | passed | 2026-10-29T19:18:24Z |
| matrix-af3dc07000b8e364 | sha2, sha3 | matrix | cargo "+1.96.0" run --quiet --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml | passed | 2026-10-29T19:40:06Z |
| matrix-af60fbe34bcaaf62 | sha3 | matrix | cargo "+1.99.0" run --quiet --locked --manifest-path assurance/sha3-public-api/Cargo.toml | passed | 2026-10-29T19:21:13Z |
| matrix-b21dd53ecc61e5da | sha3 | matrix | cargo "+1.99.1" test --quiet --locked --manifest-path assurance/cshake-public-api/Cargo.toml | passed | 2026-10-29T19:21:29Z |
| matrix-b27701aa6d4cf232 | sha3 | matrix | cargo "+1.98.1" run --quiet --locked --manifest-path assurance/sp800185-public-api/Cargo.toml | passed | 2026-10-29T19:48:21Z |
| matrix-b27f6764cab5cd81 | legacy_hmac | matrix | cargo "+1.90.0" test --locked --offline -p brynja-legacy-hmac-std --all-features | passed | 2026-10-29T19:09:25Z |
| matrix-b2f3e0edfe831727 | sha1 | matrix | cargo "+1.94.0" test --locked -p brynja-legacy-sha1 | passed | 2026-10-29T19:13:20Z |
| matrix-b3c7ca42bdbc844f | sha2 | matrix | cargo "+1.93.0" run --quiet --locked --manifest-path assurance/sha2-public-api/Cargo.toml | passed | 2026-10-29T19:33:45Z |
| matrix-b535fdbb17c8e769 | legacy_hmac | matrix | cargo "+1.98.0" test --locked --offline -p brynja-legacy-hmac-std --all-features | passed | 2026-10-29T19:46:15Z |
| matrix-b555577d5a2e1121 | sha1 | matrix | cargo "+1.97.1" test --locked -p brynja-legacy-sha1 | passed | 2026-10-29T19:44:16Z |
| matrix-b6149e5627641009 | sha1 | matrix | cargo "+1.91.0" test --locked -p brynja-legacy-sha1 --features cpu --test cpu | passed | 2026-10-29T19:30:15Z |
| matrix-b646e9be5e8f8bb7 | md5 | matrix | cargo "+1.92.0" test --locked -p brynja-legacy-md5 --all-features | passed | 2026-10-29T19:31:32Z |
| matrix-b6dd8f5e5f564068 | sha3 | matrix | cargo "+1.90.0" run --quiet --locked --manifest-path assurance/sha3-public-api/Cargo.toml | passed | 2026-10-29T19:09:59Z |
| matrix-b86c20df31283d1a | legacy | matrix | cargo "+1.93.0" test --locked --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib | passed | 2026-10-29T19:33:20Z |
| matrix-b97e891269a97268 | sha3 | matrix | cargo "+1.96.0" run --quiet --locked --manifest-path assurance/sp800185-final/Cargo.toml | passed | 2026-10-29T19:40:18Z |
| matrix-ba5dc55cd4e2fd27 | legacy | matrix | cargo "+1.94.0" test --locked --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib | passed | 2026-10-29T19:35:15Z |
| matrix-ba688623ec13892d | legacy | matrix | cargo "+1.99.1" test --locked --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib | passed | 2026-10-29T19:51:14Z |
| matrix-ba6a81b0252bcecf | sha1 | matrix | cargo "+1.95.0" test --locked -p brynja-legacy-sha1 --features cpu --test cpu | passed | 2026-10-29T19:14:29Z |
| matrix-bca22d1e0bede2c0 | legacy_hmac | matrix | cargo "+1.97.0" test --locked --offline -p brynja-legacy-hmac --all-features | passed | 2026-10-29T19:16:27Z |
| matrix-bcd65061ed1d5b9f | md5 | matrix | cargo "+1.91.0" test --locked -p brynja-legacy-md5-std | passed | 2026-10-29T19:29:52Z |
| matrix-bd5147d3746ab6d0 | sha3 | matrix | cargo "+1.90.0" test --quiet --locked --manifest-path assurance/cshake-public-api/Cargo.toml | passed | 2026-10-29T19:28:41Z |
| matrix-becbc7256ba2f2a3 | hmac | matrix | cargo "+1.95.0" test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac | passed | 2026-10-29T19:36:32Z |
| matrix-bed8653f893e346a | sha1 | matrix | cargo "+1.93.0" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib | passed | 2026-10-29T19:33:08Z |
| matrix-c1268f3cb35d51ba | sha3 | matrix | cargo "+1.96.0" run --quiet --locked --manifest-path assurance/sp800185-public-api/Cargo.toml | passed | 2026-10-29T19:15:25Z |
| matrix-c1537ce068b26f44 | repository | matrix (manual diagnostic) | cargo "+1.95.0" check --workspace --all-features | passed | 2026-10-29T19:36:06Z |
| matrix-c1f3438a1b114b24 | md5 | matrix | cargo "+1.95.0" test --locked -p brynja-legacy-md5 --all-features | passed | 2026-10-29T19:36:54Z |
| matrix-c2bb8bf6dfe277a3 | sha1 | matrix | cargo "+1.95.0" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib | passed | 2026-10-29T19:36:42Z |
| matrix-c2e64302e9c34d84 | hmac | matrix | cargo "+1.90.0" test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac | passed | 2026-10-29T19:27:36Z |
| matrix-c3c60bfe30a4b2ed | md5 | matrix | cargo "+1.96.0" test --locked -p brynja-legacy-md5-std | passed | 2026-10-29T19:39:18Z |
| matrix-c3c938bc877bbdc4 | md5 | matrix | cargo "+1.99.1" test --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib | passed | 2026-10-29T19:21:51Z |
| matrix-c3dc4cc07a1a95ca | sha1 | matrix | cargo "+1.94.0" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib | passed | 2026-10-29T19:13:09Z |
| matrix-c3f4e989dc8bba9a | sha3 | matrix | cargo "+1.99.1" run --quiet --locked --manifest-path assurance/sha3-public-api/Cargo.toml | passed | 2026-10-29T19:52:55Z |
| matrix-c46f56042d6f1a9d | sha1 | matrix | cargo "+1.95.0" test --locked -p brynja-legacy-sha1 | passed | 2026-10-29T19:37:06Z |
| matrix-c62c2d5bf24dd159 | sha1 | matrix | cargo "+1.98.1" test --locked -p brynja-legacy-sha1 | passed | 2026-10-29T19:47:47Z |
| matrix-c7b1c66c0b90c02d | sha3 | matrix | cargo "+1.95.0" run --quiet --locked --manifest-path assurance/sp800185-final/Cargo.toml | passed | 2026-10-29T19:38:23Z |
| matrix-c844419dea00a045 | legacy_hmac | matrix | cargo "+1.99.1" test --locked --offline -p brynja-legacy-hmac --all-features | passed | 2026-10-29T19:50:24Z |
| matrix-c9af8302d7f570ee | sha2 | matrix | cargo "+1.98.1" run --quiet --locked --manifest-path assurance/sha2-public-api/Cargo.toml | passed | 2026-10-29T19:19:42Z |
| matrix-ca0262037c142ecb | sha1 | matrix | cargo "+1.96.1" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib | passed | 2026-10-29T19:15:49Z |
| matrix-ca1cda421a3bd0d0 | sha2 | matrix | cargo "+1.97.0" run --quiet --locked --manifest-path assurance/sha2-public-api/Cargo.toml | passed | 2026-10-29T19:17:04Z |
| matrix-ca8a6ed60ab62a35 | sha3 | matrix | cargo "+1.90.0" run --quiet --locked --manifest-path assurance/sp800185-public-api/Cargo.toml | passed | 2026-10-29T19:10:09Z |
| matrix-ca8d417834eef809 | sha2 | matrix | cargo "+1.99.0" run --quiet --locked --manifest-path assurance/sha2-public-api/Cargo.toml | passed | 2026-10-29T19:49:46Z |
| matrix-cbc718a4982083cd | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.93.0" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml | passed | 2026-10-29T19:12:21Z |
| matrix-cbd5be21734c9554 | legacy | matrix | cargo "+1.92.0" test --locked --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib | passed | 2026-10-29T19:11:32Z |
| matrix-cbe9dc3398cce774 | md5 | matrix | cargo "+1.93.0" test --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib | passed | 2026-10-29T19:33:47Z |
| matrix-cc7755d318c4addb | sha3 | matrix | cargo "+1.96.1" run --quiet --locked --manifest-path assurance/sp800185-public-api/Cargo.toml | passed | 2026-10-29T19:41:15Z |
| matrix-ccc6cfbe3a21c7d8 | hmac | matrix | cargo "+1.93.0" test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac | passed | 2026-10-29T19:33:12Z |
| matrix-ce378c7f63810e3b | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.90.0" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml | passed | 2026-10-29T19:09:36Z |
| matrix-cf5099598f6473bd | sha1 | matrix | cargo "+1.99.1" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib | passed | 2026-10-29T19:21:06Z |
| matrix-cfdb83c37c493870 | sha1 | matrix | cargo "+1.93.0" test --locked -p brynja-legacy-sha1 | passed | 2026-10-29T19:33:32Z |
| matrix-cfe746a762bb62eb | sha1 | matrix | cargo "+1.92.0" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib | passed | 2026-10-29T19:31:19Z |
| matrix-d08d6d8ecc25cd7a | md5 | matrix | cargo "+1.97.1" test --locked -p brynja-legacy-md5 --all-features | passed | 2026-10-29T19:17:41Z |
| matrix-d15d15d4c1ed4c42 | sha2 | matrix | cargo "+1.96.0" run --quiet --locked --manifest-path assurance/sha256-public-api/Cargo.toml | passed | 2026-10-29T19:39:53Z |
| matrix-d25de084fafd6663 | hmac | matrix | cargo "+1.94.0" test --locked --offline -p brynja-mac-hmac --all-features | passed | 2026-10-29T19:13:03Z |
| matrix-d2b3e0f4d5133936 | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.90.0" test --locked --offline --manifest-path assurance/hosted-cpu-execution/Cargo.toml | passed | 2026-10-29T19:27:48Z |
| matrix-d3fd625033d8d766 | sha2 | matrix | cargo "+1.98.0" run --quiet --locked --manifest-path assurance/sha256-public-api/Cargo.toml | passed | 2026-10-29T19:19:18Z |
| matrix-d5a40052187fb130 | sha1 | matrix | cargo "+1.91.0" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib | passed | 2026-10-29T19:10:31Z |
| matrix-d6fc6ef9e0c4b110 | legacy | matrix | cargo "+1.92.0" run --locked --manifest-path assurance/legacy-hash-final/Cargo.toml | passed | 2026-10-29T19:32:00Z |
| matrix-d75190fb131acacb | sha1 | matrix | cargo "+1.97.0" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib | passed | 2026-10-29T19:42:05Z |
| matrix-d7576875d76690ed | md5 | matrix | cargo "+1.98.0" test --locked -p brynja-legacy-md5-std | passed | 2026-10-29T19:46:52Z |
| matrix-d77e6299e660afc0 | sha1 | matrix | cargo "+1.92.0" test --locked -p brynja-legacy-sha1 | passed | 2026-10-29T19:31:43Z |
| matrix-d7888a0a8b64c995 | sha3 | matrix | cargo "+1.96.1" run --quiet --locked --manifest-path assurance/sha3-public-api/Cargo.toml | passed | 2026-10-29T19:41:49Z |
| matrix-d8115e91f10fe979 | sha3 | matrix | cargo "+1.98.1" test --quiet --locked --manifest-path assurance/cshake-public-api/Cargo.toml | passed | 2026-10-29T19:48:09Z |
| matrix-d954dd851f38759c | sha1 | matrix | cargo "+1.90.0" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib | passed | 2026-10-29T19:27:52Z |
| matrix-d9852a210ec36465 | sha1 | matrix | cargo "+1.96.0" test --locked -p brynja-legacy-sha1 --features cpu --test cpu | passed | 2026-10-29T19:39:41Z |
| matrix-da2a4fc6a672dfc0 | hmac | matrix | cargo "+1.90.0" test --locked --offline -p brynja-mac-hmac --all-features | passed | 2026-10-29T19:27:23Z |
| matrix-dbdc4855564401e6 | hmac | matrix | cargo "+1.98.0" test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac | passed | 2026-10-29T19:46:29Z |
| matrix-dc4c5c425f0dca12 | legacy_hmac | matrix | cargo "+1.98.0" test --locked --offline -p brynja-legacy-hmac --all-features | passed | 2026-10-29T19:45:07Z |
| matrix-dd06cbd00e04e187 | hmac | matrix | cargo "+1.96.1" test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac | passed | 2026-10-29T19:39:58Z |
| matrix-dd07719cf535bf7a | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.94.0" test --locked --offline --manifest-path assurance/hosted-cpu-execution/Cargo.toml | passed | 2026-10-29T19:13:15Z |
| matrix-ddca3e16cde9f4df | legacy_hmac | matrix | cargo "+1.96.1" test --locked --offline -p brynja-legacy-hmac-std --all-features | passed | 2026-10-29T19:40:36Z |
| matrix-dfa77dd379e110cc | sha3 | matrix | cargo "+1.93.0" run --quiet --locked --manifest-path assurance/sp800185-final/Cargo.toml | passed | 2026-10-29T19:34:39Z |
| matrix-e015eded3e5d6f29 | sha3 | matrix | cargo "+1.96.1" test --quiet --locked --manifest-path assurance/cshake-public-api/Cargo.toml | passed | 2026-10-29T19:16:13Z |
| matrix-e0685600aeddbca3 | hmac | matrix | cargo "+1.99.1" test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac | passed | 2026-10-29T19:50:37Z |
| matrix-e092515d784961c3 | hmac | matrix | cargo "+1.95.0" test --locked --offline -p brynja-mac-hmac --all-features | passed | 2026-10-29T19:36:41Z |
| matrix-e2820412ade4ea59 | sha1 | matrix | cargo "+1.96.0" test --locked -p brynja-legacy-sha1-std | passed | 2026-10-29T19:15:13Z |
| matrix-e32bb07746fa4c93 | sha1 | matrix | cargo "+1.97.1" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib | passed | 2026-10-29T19:43:54Z |
| matrix-e5a622c86c99a00a | sha1 | matrix | cargo "+1.93.0" test --locked -p brynja-legacy-sha1-std | passed | 2026-10-29T19:12:33Z |
| matrix-e5b53d6e8209b252 | repository | matrix (manual diagnostic) | cargo "+1.96.0" check --workspace --all-features | passed | 2026-10-29T19:14:36Z |
| matrix-e5ca999f2dd99a73 | repository | matrix (manual diagnostic) | cargo "+1.96.1" check --workspace --all-features | passed | 2026-10-29T19:39:32Z |
| matrix-e672d663fd6e4fbd | hmac | matrix | cargo "+1.97.0" test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac | passed | 2026-10-29T19:16:57Z |
| matrix-e93ee1eb9fa1b852 | sha3 | matrix | cargo "+1.99.0" run --quiet --locked --manifest-path assurance/sp800185-final/Cargo.toml | passed | 2026-10-29T19:51:36Z |
| matrix-e9f0b02ce411e295 | sha2 | matrix | cargo "+1.94.0" run --locked --offline --manifest-path assurance/general-sha512-t/Cargo.toml | passed | 2026-10-29T19:34:51Z |
| matrix-eaa1ff13e751bbaa | hmac | matrix | cargo "+1.94.0" test --locked --offline -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac | passed | 2026-10-29T19:34:38Z |
| matrix-eb024e9c56453dbe | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.98.1" test --locked --offline --manifest-path assurance/hosted-cpu-execution/Cargo.toml | passed | 2026-10-29T19:48:28Z |
| matrix-eb9d140759436dcc | hmac | matrix | cargo "+1.98.1" test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac | passed | 2026-10-29T19:19:46Z |
| matrix-ecdd533797b1fd36 | sha2 | matrix | cargo "+1.90.0" run --quiet --locked --manifest-path assurance/sha2-public-api/Cargo.toml | passed | 2026-10-29T19:28:29Z |
| matrix-edfabc4df3f319f1 | sha3 | matrix | cargo "+1.95.0" run --quiet --locked --manifest-path assurance/sp800185-public-api/Cargo.toml | passed | 2026-10-29T19:37:43Z |
| matrix-ee582dc27fca39bf | sha3 | matrix | cargo "+1.96.0" run --quiet --locked --manifest-path assurance/sha3-public-api/Cargo.toml | passed | 2026-10-29T19:15:35Z |
| matrix-ee89782131ce80d6 | sha1 | matrix | cargo "+1.92.0" test --locked -p brynja-legacy-sha1-std | passed | 2026-10-29T19:31:54Z |
| matrix-ef4222f0399f2b7d | md5 | matrix | cargo "+1.96.1" test --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib | passed | 2026-10-29T19:16:17Z |
| matrix-efe61f2345ce96a4 | md5 | matrix | cargo "+1.94.0" test --locked -p brynja-legacy-md5 --all-features | passed | 2026-10-29T19:35:04Z |
| matrix-f1843d8c1fbbfe84 | hmac | matrix | cargo "+1.95.0" test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac | passed | 2026-10-29T19:14:06Z |
| matrix-f2cdf2ef490b3c9e | sha1 | matrix | cargo "+1.98.0" test --locked --manifest-path assurance/sha1-public-api/Cargo.toml --lib | passed | 2026-10-29T19:18:29Z |
| matrix-f387b8e85b1dc706 | sha2, sha3 | matrix | cargo "+1.90.0" run --quiet --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml | passed | 2026-10-29T19:28:47Z |
| matrix-f39977b826c5fdcd | legacy_hmac | matrix | cargo "+1.95.0" test --locked --offline -p brynja-legacy-hmac --all-features | passed | 2026-10-29T19:13:46Z |
| matrix-f3c5defb54b4f246 | sha3 | matrix | cargo "+1.91.0" run --quiet --locked --manifest-path assurance/sha3-public-api/Cargo.toml | passed | 2026-10-29T19:30:27Z |
| matrix-f3cad23e60afae4f | kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | matrix | cargo "+1.95.0" check --manifest-path assurance/cpu-admission-fixture/Cargo.toml | passed | 2026-10-29T19:37:22Z |
| matrix-f76f19c59ab909fd | legacy_hmac | matrix | cargo "+1.99.1" test --locked --offline -p brynja-legacy-hmac-std --all-features | passed | 2026-10-29T19:51:52Z |
| matrix-f781992fa6dd2da7 | hmac | matrix | cargo "+1.94.0" test --locked --offline -p brynja-crypto-cpu-std --features hmac-execution --test hmac | passed | 2026-10-29T19:12:58Z |
| matrix-f79be810780a44ba | md5 | matrix | cargo "+1.99.0" test --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib | passed | 2026-10-29T19:50:48Z |
| matrix-f8df60a0dba4cd83 | sha1 | matrix | cargo "+1.95.0" test --locked -p brynja-legacy-sha1-std | passed | 2026-10-29T19:37:18Z |
| matrix-f910abe431438b9c | sha2 | matrix | cargo "+1.99.1" run --quiet --locked --manifest-path assurance/sha256-public-api/Cargo.toml | passed | 2026-10-29T19:22:01Z |
| matrix-fab86bcee9a16d04 | sha1 | matrix | cargo "+1.97.0" test --locked -p brynja-legacy-sha1-std | passed | 2026-10-29T19:42:38Z |
| matrix-fb52d49ce1c64956 | sha3 | matrix | cargo "+1.98.1" run --quiet --locked --manifest-path assurance/sp800185-final/Cargo.toml | passed | 2026-10-29T19:49:40Z |
| matrix-fb896009936390c3 | sha1 | matrix | cargo "+1.91.0" test --locked -p brynja-legacy-sha1-std | passed | 2026-10-29T19:30:06Z |
| matrix-fb98ef4d5bcd2452 | hmac | matrix | cargo "+1.96.0" test --locked --offline -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac | passed | 2026-10-29T19:38:55Z |
| matrix-fbf47473f3c51cae | sha3 | matrix | cargo "+1.92.0" run --quiet --locked --manifest-path assurance/sp800185-final/Cargo.toml | passed | 2026-10-29T19:32:38Z |
| matrix-fd2cfa70b205061b | sha1 | matrix | cargo "+1.92.0" test --locked -p brynja-legacy-sha1 --features cpu --test cpu | passed | 2026-10-29T19:11:41Z |
| matrix-fd335dab783e571c | hmac | matrix | cargo "+1.99.1" test --locked --offline -p brynja-mac-hmac --all-features | passed | 2026-10-29T19:21:30Z |
| matrix-fe8f101fdfa04496 | repository | matrix (manual diagnostic) | cargo "+1.94.0" check --workspace --all-features | passed | 2026-10-29T19:34:12Z |
| matrix-fefb30856b288917 | md5 | matrix | cargo "+1.93.0" test --locked -p brynja-legacy-md5-std | passed | 2026-10-29T19:33:35Z |
| matrix-ff5f5e8bb9d38a15 | sha2, sha3 | matrix | cargo "+1.97.1" run --quiet --locked --manifest-path assurance/hash-final-acceptance/Cargo.toml | passed | 2026-10-29T19:45:45Z |
| matrix-fff7d0fda3403f97 | md5 | matrix | cargo "+1.94.0" test --locked --manifest-path assurance/md5-public-api/Cargo.toml --lib | passed | 2026-10-29T19:13:26Z |
| miri-00060c42009dccb4 | tuplehash | miri | tuplehash-staging:170 [extended] | reused | 2026-10-28T15:07:26Z |
| miri-000e3050b00c0923 | tuplehash | miri | tuplehash-staging:54 [extended] | reused | 2026-10-28T14:29:15Z |
| miri-00364d3ea54c6466 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:11:width=2 [extended] | reused | 2026-10-28T22:46:21Z |
| miri-004d8d5825e9f7bd | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:6 [extended] | passed | 2026-10-29T14:07:21Z |
| miri-005e54c44eb2268b | kmac | miri | kmac-scoped-lifecycle:6 [extended] | reused | 2026-10-28T13:53:13Z |
| miri-00689c9df6c40663 | md5 | miri | md5-batch-mask:86 [extended] | reused | 2026-10-28T12:24:45Z |
| miri-008d91acd20b6714 | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join256:0 [extended] | passed | 2026-10-29T15:06:00Z |
| miri-00a47f0b925d9c72 | md5 | miri | md5-bulk:248 [extended] | reused | 2026-10-28T11:57:08Z |
| miri-00c0b50577deddb4 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:1:width=0 [extended] | reused | 2026-10-29T04:23:03Z |
| miri-00c9dcd4a8819e70 | sha3 | miri | sha3-fixed-boundaries:1 [routine] | passed | 2026-10-19T11:32:34Z |
| miri-00ca4d7ae31fb798 | tuplehash | miri | tuplehash-staging:274 [extended] | reused | 2026-10-28T15:40:48Z |
| miri-00df1f62ddcdf1fe | md5 | miri | md5-batch-mask:35 [extended] | reused | 2026-10-28T12:09:52Z |
| miri-00e6a5e0c684acce | md5 | miri | md5-scoped:140 [extended] | reused | 2026-10-28T12:02:30Z |
| miri-00e7448e7c624dcb | tuplehash | miri | tuplehash-staging:71 [extended] | reused | 2026-10-28T20:37:32Z |
| miri-00eb02491ab2b213 | sha1 | miri | sha1-scoped:210 [extended] | reused | 2026-10-28T13:18:56Z |
| miri-01277366016a6fa6 | md5 | miri | md5-batch-mask:11 [extended] | reused | 2026-10-28T12:08:04Z |
| miri-012e4587e710d7f3 | sha1 | miri | sha1-bulk:139 [extended] | reused | 2026-10-28T12:57:02Z |
| miri-0130b59a90affe12 | sha1 | miri | sha1-padding:70 [extended] | reused | 2026-10-28T12:45:05Z |
| miri-01364c38bc159ffd | tuplehash | miri | scoped_tuplexof128_differential:7:width=1 [extended] | reused | 2026-10-29T01:24:29Z |
| miri-013985a879099b2d | md5 | miri | md5-batch-mask:228 [extended] | reused | 2026-10-28T12:30:40Z |
| miri-014c5e70351a6c0e | md5 | miri | md5-scoped:209 [extended] | reused | 2026-10-28T12:01:50Z |
| miri-0178e3062e3addd7 | tuplehash | miri | tuplehash-staging:872 [extended] | reused | 2026-10-28T18:49:44Z |
| miri-01a605c11c27a1d4 | sha1 | miri | sha1-bulk:147 [extended] | reused | 2026-10-28T12:57:52Z |
| miri-01bdfaa737cefe16 | md5 | miri | md5-padding:54 [routine] | passed | 2026-10-19T11:25:47Z |
| miri-01beb14f288e0d97 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:45:width=2 [extended] | reused | 2026-10-29T03:28:25Z |
| miri-01c53d9955d32099 | tuplehash | miri | tuplehash-staging:858 [extended] | reused | 2026-10-28T18:48:38Z |
| miri-01d7eef463c5f917 | tuplehash | miri | tuplehash-staging:341 [extended] | reused | 2026-10-28T16:15:02Z |
| miri-01e2d146428f23e7 | sha3 | miri | -p brynja-hash-sha3 --test shake256 suffix_and_rate_boundaries_have_exact_output [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-020084a03e24daba | tuplehash | miri | scoped_tuplexof128_differential:36:width=1 [extended] | reused | 2026-10-29T01:46:32Z |
| miri-02094a2fd5db3f96 | tuplehash | miri | scoped_tuplexof128_differential:0 [routine] | passed | 2026-10-19T12:11:34Z |
| miri-020c0a8d9403da26 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:8:width=3 [extended] | reused | 2026-10-28T22:09:27Z |
| miri-0222a42992d9c0a4 | tuplehash | miri | scoped_tuplexof128_differential:13:width=1 [extended] | passed | 2026-10-29T10:51:07Z |
| miri-023356fefff3df80 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:39 [routine] | No mapped observation | — |
| miri-0241efe7caf25bf4 | tuplehash | miri | tuplehash-staging:770 [extended] | reused | 2026-10-28T18:20:29Z |
| miri-024aab63b1c26f2d | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:33:width=3 [extended] | reused | 2026-10-29T05:32:49Z |
| miri-02577ed23bf05fa7 | sha1 | miri | sha1-scoped:75 [extended] | reused | 2026-10-28T13:21:11Z |
| miri-026ef12e67bd6e3f | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:15:width=1 [extended] | reused | 2026-10-28T20:13:06Z |
| miri-028cb1e8bea66d2c | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:2:width=3 [extended] | reused | 2026-10-28T19:26:23Z |
| miri-02a3682e060da584 | tuplehash | miri | tuplehash-staging:128 [extended] | reused | 2026-10-28T14:50:12Z |
| miri-02c01b27fbd1e0fb | acceleration | miri | --manifest-path assurance/acceleration-contract/Cargo.toml --lib [remaining suite; inspect skips with show] | passed | 2026-10-19T13:43:07Z |
| miri-02cbc3d3156ad5c9 | md5 | miri | md5-batch-mask:126 [extended] | reused | 2026-10-28T12:27:56Z |
| miri-02f8293b0812e4be | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:52:width=1 [extended] | reused | 2026-10-29T00:23:27Z |
| miri-0308fe373c1d9f1e | md5 | miri | md5-padding:90 [extended] | reused | 2026-10-28T11:24:44Z |
| miri-030e1eb98934c6fb | parallelhash | miri | [bounded-parallelhash-v1] parallelhashxof-official:1 [routine] | No mapped observation | — |
| miri-0315591bc18d2201 | tuplehash | miri | hardened_in_place::tests::scoped_tuple128_terminal_writer_and_output_lifecycle [extended] | reused | 2026-10-29T04:04:41Z |
| miri-0322b504c99873d7 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:15 [extended] | passed | 2026-10-29T13:45:04Z |
| miri-0344b3da851d860b | sha2 | miri | -p brynja-hash-sha2 --test sha512_224 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | reused | 2026-10-28T13:28:26Z |
| miri-03563de545c1b902 | tuplehash | miri | tuplehash-execution-fixed:7 [extended] | reused | 2026-10-29T01:25:36Z |
| miri-0356db106ddd0da1 | md5 | miri | md5-scoped:170 [extended] | reused | 2026-10-28T12:09:48Z |
| miri-0358b13329c75f02 | tuplehash | miri | scoped_tuplexof128_differential:41:width=4 [extended] | passed | 2026-10-29T12:00:50Z |
| miri-036809b66e826efa | sha1 | miri | sha1-bulk:22 [extended] | reused | 2026-10-28T12:42:06Z |
| miri-037eb453ba455ce6 | tuplehash | miri | tuplehash-staging:56 [extended] | reused | 2026-10-28T14:26:34Z |
| miri-03899ddace541a60 | sha1 | miri | sha1-scoped:229 [extended] | reused | 2026-10-28T13:28:00Z |
| miri-03b1f0c4a92a4793 | md5 | miri | md5-bulk:255 [extended] | reused | 2026-10-28T11:47:25Z |
| miri-03d1abf58ca08382 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-official:4 [extended] | passed | 2026-10-29T14:12:32Z |
| miri-03d68450429aec10 | sha1 | miri | sha1-scoped:22 [extended] | reused | 2026-10-28T13:04:23Z |
| miri-03dd7f501918e458 | tuplehash | miri | scoped_tuplexof128_differential:41:width=3 [extended] | passed | 2026-10-29T11:49:48Z |
| miri-03df9d7ebb6c3720 | tuplehash | miri | scoped_tuplexof256_differential:2:width=2 [extended] | reused | 2026-10-29T02:17:15Z |
| miri-04348b90916e917a | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:48:width=3 [extended] | reused | 2026-10-28T21:27:32Z |
| miri-044097eb2f8d1141 | tuplehash | miri | scoped_tuplexof256_differential:7:width=3 [extended] | reused | 2026-10-29T03:16:31Z |
| miri-045c1734632ed43f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:17:width=0 [extended] | reused | 2026-10-29T04:53:46Z |
| miri-0463d3710192649a | md5 | miri | md5-scoped:236 [extended] | reused | 2026-10-28T12:09:12Z |
| miri-0468d94def8cfc34 | tuplehash | miri | tuplehash-staging:433 [extended] | reused | 2026-10-28T16:46:23Z |
| miri-046b99658dad3d7d | tuplehash | miri | scoped_tuplexof256_differential:0:width=1 [extended] | reused | 2026-10-29T02:17:57Z |
| miri-047636d1538f16cc | sanitization | miri | -p brynja-sanitization --test behavior [remaining suite; inspect skips with show] | passed | 2026-10-19T11:25:36Z |
| miri-047abd0a36aaacdc | kmac | miri | kmac-streamed-setup:51 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-048cb927acf019d1 | parallelhash | miri | streamed_scheduled_and_one_shot_are_identical [extended] | passed | 2026-10-29T15:00:21Z |
| miri-0494b7e5535e5ee1 | kmac | miri | kmac-streamed-setup:43 [routine] | No mapped observation | — |
| miri-04a851be4c848c48 | hmac | miri | output_clears_during_consumer_unwind [routine] | No mapped observation | — |
| miri-04b0ce2590e94bce | md5 | miri | md5-bulk:245 [extended] | reused | 2026-10-28T11:46:12Z |
| miri-04b2b3d836eb8733 | tuplehash | miri | scoped_tuplexof128_differential:10:width=4 [extended] | reused | 2026-10-29T00:42:19Z |
| miri-04c2786ddc8dd7f0 | tuplehash | miri | scoped_tuplexof128_differential:44:width=0 [extended] | reused | 2026-10-29T02:11:09Z |
| miri-04e24b63f55529de | sha1 | miri | sha1-bulk:26 [extended] | reused | 2026-10-28T12:42:21Z |
| miri-04eac344e7820351 | sha3 | miri | sha3-fixed-boundaries:55 [routine] | passed | 2026-10-19T11:27:56Z |
| miri-04ef18e2abeb690c | md5 | miri | md5-batch-mask:71 [extended] | reused | 2026-10-28T12:12:39Z |
| miri-04f4622b39bfdb67 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:35:width=1 [extended] | reused | 2026-10-28T23:42:23Z |
| miri-04f85b5e7bd1f73c | tuplehash | miri | tuplehash-staging:74 [extended] | reused | 2026-10-28T14:35:54Z |
| miri-0503a028ac9d4105 | sha1 | miri | sha1-scoped:52 [extended] | reused | 2026-10-28T13:07:56Z |
| miri-05082462afa98b92 | tuplehash | miri | scoped_tuplexof256_differential:2:width=4 [extended] | reused | 2026-10-29T02:17:15Z |
| miri-0516f641d3b40960 | kmac | miri | kmac-scoped-xof-lifecycle:7 [routine] | passed | 2026-10-19T15:34:58Z |
| miri-0518c40fb296cf40 | kmac | miri | kmac-streamed-setup:59 [routine] | No mapped observation | — |
| miri-0534792fec5181ed | kmac | miri | streaming_and_one_shot_are_identical_at_rate_boundaries [extended] | reused | 2026-10-28T14:05:14Z |
| miri-054600a8b8a8d4e7 | parallelhash | miri | -p brynja-hash-parallel --features hardened-execution --lib execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-054d80528e66d381 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:25:width=3 [extended] | reused | 2026-10-29T02:33:53Z |
| miri-0563fdf2aea70994 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:34:width=0 [extended] | reused | 2026-10-28T23:01:09Z |
| miri-05790d5497ff58ed | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:9:width=0 [extended] | reused | 2026-10-29T04:37:02Z |
| miri-05809131b9424546 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:5:width=4 [extended] | reused | 2026-10-29T04:30:03Z |
| miri-0598a173d7506531 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:0 [extended] | passed | 2026-10-29T12:34:56Z |
| miri-059ec9dd8c317d4b | md5 | miri | md5-batch-mask:140 [extended] | reused | 2026-10-28T12:23:37Z |
| miri-05afd3799d7933b2 | tuplehash | miri | tuplehash-staging:615 [extended] | reused | 2026-10-28T23:41:16Z |
| miri-05bcbe8f81765ee1 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:30:width=2 [extended] | reused | 2026-10-28T20:22:51Z |
| miri-05c539a731f920ce | sha1 | miri | sha1-scoped:154 [extended] | reused | 2026-10-28T13:14:22Z |
| miri-05d463f98addc720 | md5 | miri | md5-padding:126 [extended] | reused | 2026-10-28T11:27:32Z |
| miri-05dac0bcac73c42f | tuplehash | miri | tuplehash-staging:256 [routine] | passed | 2026-10-19T11:53:52Z |
| miri-05dcdc7f68e429bf | kmac | miri | kmac-streamed-setup:5 [routine] | No mapped observation | — |
| miri-05eb45c962033ab6 | sha1 | miri | sha1-scoped:108 [routine] | passed | 2026-10-19T11:29:47Z |
| miri-05eef2e19dcf15c1 | tuplehash | miri | tuplehash-staging:29 [extended] | reused | 2026-10-28T14:30:20Z |
| miri-061549867e6dce68 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:16:width=1 [extended] | reused | 2026-10-28T22:25:09Z |
| miri-0623e2a93d1a44d9 | sha2 | miri | -p brynja-hash-sha2 --features batch512-execution --test batch512 bounded_batch_lifecycle_smoke [remaining suite; inspect skips with show] | reused | 2026-10-28T13:32:55Z |
| miri-0627a79a315ac181 | tuplehash | miri | tuplehash-staging:609 [extended] | reused | 2026-10-28T17:44:44Z |
| miri-063ce2560741cb30 | tuplehash | miri | scoped_tuplexof256_differential:15:width=2 [extended] | reused | 2026-10-29T03:30:33Z |
| miri-063f647cb7aabf04 | tuplehash | miri | scoped_tuplexof256_differential:36:width=2 [extended] | reused | 2026-10-29T03:35:29Z |
| miri-0645a70523c97c34 | tuplehash | miri | tuplehash-staging:268 [extended] | reused | 2026-10-28T15:35:50Z |
| miri-064f43c79ae48ad7 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:33:width=3 [extended] | reused | 2026-10-29T02:53:27Z |
| miri-0653396b13cf5e8e | md5 | miri | md5-batch-mask:40 [extended] | reused | 2026-10-28T12:15:55Z |
| miri-0654cc9b05823663 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:54:width=1 [extended] | reused | 2026-10-29T00:22:37Z |
| miri-065f56a331f151e6 | sha1 | miri | sha1-bulk:84 [extended] | reused | 2026-10-28T12:44:56Z |
| miri-06600d50171c6dfa | tuplehash | miri | tuplehash-execution-fixed:0 [extended] | reused | 2026-10-28T19:01:20Z |
| miri-06705d371bcc71b7 | sha1 | miri | sha1-scoped:180 [extended] | reused | 2026-10-28T13:17:59Z |
| miri-06906c498f71ac99 | tuplehash | miri | tuplehash-staging:10 [extended] | reused | 2026-10-28T14:15:32Z |
| miri-06a6c49400650fef | tuplehash | miri | scoped_tuplexof256_differential:21:width=2 [extended] | passed | 2026-10-29T12:31:46Z |
| miri-06b17186644dfbcc | tuplehash | miri | tuplehash-staging:867 [extended] | reused | 2026-10-29T01:06:15Z |
| miri-06b52afbf86b63d2 | md5 | miri | md5-batch-mask:113 [extended] | reused | 2026-10-28T12:16:09Z |
| miri-06b5ecf684075ee4 | md5 | miri | md5-bulk:10 [extended] | reused | 2026-10-28T11:33:05Z |
| miri-06c553fd58546c03 | sha1 | miri | sha1-bulk:251 [extended] | reused | 2026-10-28T13:10:03Z |
| miri-06c8999c8a554b42 | tuplehash | miri | tuplehash-staging:209 [extended] | reused | 2026-10-28T15:31:14Z |
| miri-06d28f14158acb48 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-order:0 [routine] | No mapped observation | — |
| miri-06dd616374edb89d | tuplehash | miri | tuplehash-staging:191 [extended] | reused | 2026-10-28T21:18:22Z |
| miri-06ded221f9ce4c15 | md5 | miri | md5-scoped:161 [extended] | reused | 2026-10-28T11:58:25Z |
| miri-06f0a03bc7f6f9af | tuplehash | miri | tuplehash-execution-fixed:6 [extended] | reused | 2026-10-28T19:09:43Z |
| miri-06f4e64e23668b28 | sha1 | miri | sha1-bulk:1 [routine] | passed | 2026-10-19T11:29:00Z |
| miri-06fad442493a4adf | md5 | miri | md5-padding:23 [extended] | reused | 2026-10-28T11:25:03Z |
| miri-070285feadf516b8 | sha3 | miri | sha3-fixed-boundaries:5 [extended] | reused | 2026-10-28T13:31:50Z |
| miri-071d5e0095e13602 | tuplehash | miri | scoped_tuplexof128_differential:4:width=4 [extended] | reused | 2026-10-29T00:36:36Z |
| miri-07323d09f4d9b9dd | sha1 | miri | sha1-scoped:35 [extended] | reused | 2026-10-28T13:18:18Z |
| miri-07355c211a9200a8 | tuplehash | miri | tuplehash-staging:112 [extended] | reused | 2026-10-28T14:44:58Z |
| miri-073e5c9e7437401a | tuplehash | miri | tuplehash-staging:481 [extended] | reused | 2026-10-28T17:01:48Z |
| miri-0762ac9f1da318b8 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:1:width=1 [extended] | reused | 2026-10-29T01:43:26Z |
| miri-076d1332a5a92717 | tuplehash | miri | tuplehash-staging:339 [extended] | reused | 2026-10-28T22:08:42Z |
| miri-077f7143a956ae81 | md5 | miri | md5-bulk:23 [extended] | reused | 2026-10-28T11:29:34Z |
| miri-077f8485cbea84c3 | tuplehash | miri | tuplehash-staging:782 [extended] | reused | 2026-10-28T18:24:20Z |
| miri-078c2ebb97e4f031 | sha1 | miri | sha1-bulk:92 [extended] | reused | 2026-10-28T12:45:35Z |
| miri-0793a87252f78462 | tuplehash | miri | tuplehash-staging:361 [extended] | reused | 2026-10-28T16:21:45Z |
| miri-079c261750fd4784 | sha1 | miri | sha1-bulk:51 [extended] | reused | 2026-10-28T12:49:24Z |
| miri-079cf146e2791895 | kmac | miri | domain_substitution_changes_outputs_and_fixed_is_not_xof_prefix [extended] | reused | 2026-10-28T14:16:38Z |
| miri-079de82bd88e69d2 | sha1 | miri | sha1-bulk:137 [extended] | reused | 2026-10-28T13:01:36Z |
| miri-079e628937c2a42e | md5 | miri | md5-padding:29 [extended] | reused | 2026-10-28T11:29:48Z |
| miri-07bed4fd8673fc39 | sha1 | miri | sha1-bulk:250 [extended] | reused | 2026-10-28T13:03:27Z |
| miri-07dfa3682f923775 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:17:width=1 [extended] | reused | 2026-10-29T04:53:46Z |
| miri-07ec9478739ea314 | sha1 | miri | sha1-scoped:66 [extended] | reused | 2026-10-28T13:07:30Z |
| miri-07f13cbd9bdd9d99 | sha1 | miri | sha1-scoped:59 [extended] | reused | 2026-10-28T13:20:02Z |
| miri-07f49785fa80bfa2 | md5 | miri | md5-padding:115 [extended] | reused | 2026-10-28T11:31:19Z |
| miri-0800b7877ba6089f | tuplehash | miri | scoped_tuplexof256_differential:47:width=3 [extended] | reused | 2026-10-29T04:53:59Z |
| miri-08028b90ac4a632b | sha1 | miri | sha1-padding:20 [extended] | reused | 2026-10-28T12:35:53Z |
| miri-080938fa8aaa6b3f | sha1 | miri | sha1-bulk:255 [extended] | reused | 2026-10-28T13:10:34Z |
| miri-081a76001974445b | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:37:width=0 [extended] | reused | 2026-10-29T03:03:13Z |
| miri-081bdcef8e241b3b | sha3 | miri | sha3-fixed-boundaries:45 [extended] | reused | 2026-10-28T13:37:02Z |
| miri-08206b5f0488629c | tuplehash | miri | tuplehash-staging:64 [extended] | reused | 2026-10-28T14:28:49Z |
| miri-08217bd9a0f0ebcd | kmac | miri | kmac-streamed-setup:60 [routine] | No mapped observation | — |
| miri-0825931fcc8d0da6 | md5 | miri | md5-padding:9 [extended] | reused | 2026-10-28T11:28:28Z |
| miri-08292ae654ad4731 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-order:1 [routine] | No mapped observation | — |
| miri-082adaa512227f36 | parallelhash | miri | [bounded-parallelhash-v1] parallelhashxof-official:2 [extended] | passed | 2026-10-29T14:14:07Z |
| miri-082b47fe9e38f01f | sha1 | miri | sha1-padding:93 [extended] | reused | 2026-10-28T12:35:51Z |
| miri-083f6f6d991d4e33 | kmac | miri | kmac-streamed-setup:28 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-0846e5d8e5c3fde5 | sha3 | miri | sha3-fixed-bits:19 [extended] | reused | 2026-10-28T13:48:39Z |
| miri-086a93087e12d562 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:32:width=4 [extended] | reused | 2026-10-28T23:01:38Z |
| miri-0871c85f5edf6c6c | sha2 | miri | -p brynja-hash-sha2 --features runtime-execution,general-sha512-t --test execution bounded_execution_lifecycle_smoke [remaining suite; inspect skips with show] | passed | 2026-10-19T11:35:46Z |
| miri-087f1426afcc7ed7 | hmac | miri | -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac [remaining suite; inspect skips with show] | passed | 2026-10-29T16:04:37Z |
| miri-087f26a9f1e09c79 | tuplehash | miri | scoped_tuplexof128_differential:7:width=4 [extended] | reused | 2026-10-29T01:24:29Z |
| miri-0885844b85d39da2 | sha1 | miri | sha1-bulk:209 [extended] | reused | 2026-10-28T13:09:26Z |
| miri-0899fe7c92ea7ac5 | md5 | miri | md5-scoped:82 [extended] | reused | 2026-10-28T12:03:39Z |
| miri-08a5da9f2df3d971 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:9 [routine] | No mapped observation | — |
| miri-08b5ec9daa97a9c0 | sha1 | miri | sha1-bulk:143 [extended] | reused | 2026-10-28T12:57:29Z |
| miri-08b8ae14518fa0e6 | sha3 | miri | sha3-secret-xof-bits:3 [routine] | passed | 2026-10-19T11:30:28Z |
| miri-08ba5bae66863335 | sha1 | miri | sha1-bulk:235 [extended] | reused | 2026-10-28T13:08:00Z |
| miri-08bbc917e615016f | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:3:width=3 [extended] | reused | 2026-10-28T19:52:05Z |
| miri-08caa9490180df70 | tuplehash | miri | tuplehash-staging:106 [extended] | reused | 2026-10-28T14:46:00Z |
| miri-08cfd169615c1a7f | md5 | miri | md5-scoped:205 [extended] | reused | 2026-10-28T12:01:33Z |
| miri-09253cd56be0f1ca | tuplehash | miri | tuplehash-staging:110 [extended] | reused | 2026-10-28T14:47:42Z |
| miri-0929f5655493a914 | md5 | miri | md5-padding:19 [extended] | reused | 2026-10-28T11:24:49Z |
| miri-092bdae0882ec8f7 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:27:width=3 [extended] | reused | 2026-10-28T23:22:47Z |
| miri-0938804c32fc1663 | kmac | miri | kmac-streamed-setup:43 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-096219eaa531d23f | kmac | miri | kmac-streamed-setup:39 [routine] | No mapped observation | — |
| miri-096a3e46d9274817 | tuplehash | miri | scoped_tuplexof128_differential:8:width=2 [extended] | reused | 2026-10-29T00:43:10Z |
| miri-099da94df842aedc | tuplehash | miri | scoped_tuplexof256_differential:21:width=3 [extended] | passed | 2026-10-29T12:03:27Z |
| miri-09ade87295629b22 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:14 [routine] | No mapped observation | — |
| miri-09af1a590326e67d | md5 | miri | md5-scoped:187 [extended] | reused | 2026-10-28T11:59:57Z |
| miri-09c11a351e3b93a4 | tuplehash | miri | scoped_tuplexof256_differential:31:width=0 [extended] | reused | 2026-10-29T04:09:27Z |
| miri-09c31f6fd2acd751 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:18:width=2 [extended] | reused | 2026-10-28T19:55:16Z |
| miri-09d0858093ffb673 | tuplehash | miri | scoped_tuplexof128_differential:18:width=0 [extended] | reused | 2026-10-29T00:58:05Z |
| miri-09d7a1a1b5ca1214 | sha1 | miri | sha1-bulk:63 [routine] | passed | 2026-10-19T11:16:08Z |
| miri-09e3704c836fcceb | md5 | miri | md5-bulk:24 [extended] | reused | 2026-10-28T11:39:04Z |
| miri-09ef8fb4ab44b112 | sha1 | miri | sha1-bulk:3 [extended] | reused | 2026-10-28T12:46:20Z |
| miri-0a08950594942856 | kmac | miri | kmac-streamed-setup:25 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-0a13f89d5db9618c | kmac | miri | -p brynja-mac-kmac --features hardened-execution --test execution [remaining suite; inspect skips with show] | passed | 2026-10-29T10:47:02Z |
| miri-0a192e9c0a922a54 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:45 [routine] | passed | 2026-10-19T16:13:35Z |
| miri-0a2237d4fcad861f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:40:width=3 [extended] | reused | 2026-10-28T23:22:29Z |
| miri-0a266fd4b65617ae | md5 | miri | md5-bulk:172 [extended] | reused | 2026-10-28T11:50:08Z |
| miri-0a4f2afa3fe654d1 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:29:width=3 [extended] | reused | 2026-10-29T05:23:03Z |
| miri-0a595372541212cd | md5 | miri | md5-batch-mask:211 [extended] | reused | 2026-10-28T12:24:02Z |
| miri-0a602825f8535be3 | sha1 | miri | sha1-scoped:50 [extended] | reused | 2026-10-28T13:06:22Z |
| miri-0a9c384f49c26eb1 | sha1 | miri | -p brynja-legacy-sha1 --features execution --test execution revocation_empty_updates_capacity_and_finalization_fail_closed [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-0ab043095cd69040 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:6 [routine] | No mapped observation | — |
| miri-0ab334601b1f1ed9 | tuplehash | miri | tuplehash-staging:111 [extended] | reused | 2026-10-28T20:51:49Z |
| miri-0ab637192c5390be | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:24:width=2 [extended] | reused | 2026-10-28T22:43:23Z |
| miri-0abae9a16c8faba2 | md5 | miri | md5-bulk:145 [extended] | reused | 2026-10-28T11:37:58Z |
| miri-0ae506ff55e52006 | parallelhash | miri | -p brynja-hash-parallel-std --features runtime-execution --lib execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-0af273ad4c22994a | sha3 | miri | sha3-fixed-boundaries:28 [extended] | reused | 2026-10-28T13:48:24Z |
| miri-0af657c6777ab888 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:55 [routine] | No mapped observation | — |
| miri-0b3923d94f93ab3b | tuplehash | miri | tuplehash-staging:553 [extended] | reused | 2026-10-28T17:25:52Z |
| miri-0b43ca3e23143e4a | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:36 [routine] | No mapped observation | — |
| miri-0b483ecb8a85d436 | tuplehash | miri | tuplehash-staging:771 [extended] | reused | 2026-10-29T00:33:06Z |
| miri-0b524ae344e8b504 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:51:width=0 [extended] | reused | 2026-10-28T22:01:22Z |
| miri-0b84221d90cbf403 | kmac | miri | kmac-streamed-setup:30 [routine] | No mapped observation | — |
| miri-0b89c275f2b0d023 | sha1 | miri | sha1-bulk:255 [routine] | passed | 2026-10-19T11:35:19Z |
| miri-0ba97e114c0cad34 | kmac | miri | kmac-streamed-setup:16 [routine] | No mapped observation | — |
| miri-0bae4435995d8c1e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:3:width=2 [extended] | reused | 2026-10-28T22:32:17Z |
| miri-0bc4d744c62e0be0 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:49:width=2 [extended] | reused | 2026-10-29T03:52:14Z |
| miri-0bd7db1efad20df0 | tuplehash | miri | tuplehash-staging:594 [extended] | reused | 2026-10-28T17:24:30Z |
| miri-0bddaca939882fde | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:12:width=3 [extended] | reused | 2026-10-28T22:16:00Z |
| miri-0be2ac96bd2deea8 | md5 | miri | md5-padding:128 [routine] | passed | 2026-10-19T11:28:58Z |
| miri-0be8a448c5049b77 | tuplehash | miri | scoped_tuplexof128_differential:45:width=0 [extended] | passed | 2026-10-29T12:02:04Z |
| miri-0bef63f9c16249ea | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:18 [extended] | passed | 2026-10-29T13:29:12Z |
| miri-0befe3b7e5ea80da | sha1 | miri | sha1-padding:19 [extended] | reused | 2026-10-28T12:31:04Z |
| miri-0bf2912eee6e69ca | md5 | miri | md5-bulk:112 [extended] | reused | 2026-10-28T11:45:19Z |
| miri-0bfda00bf8417565 | tuplehash | miri | scoped_tuplexof256_differential:37:width=4 [extended] | passed | 2026-10-29T12:46:43Z |
| miri-0c063dc77376b15d | sha1 | miri | sha1-bulk:95 [extended] | reused | 2026-10-28T12:52:59Z |
| miri-0c0a144e73eb977f | kmac | miri | kmac-streamed-setup:91 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-0c0ef1f6166fb983 | kmac | miri | kmac-streamed-setup:36 [routine] | No mapped observation | — |
| miri-0c14ae5f023c42ac | tuplehash | miri | scoped_tuplexof128_differential:45:width=2 [extended] | passed | 2026-10-29T12:03:18Z |
| miri-0c16a218a5b558cf | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:17:width=2 [extended] | reused | 2026-10-29T04:53:46Z |
| miri-0c2b61b9ea87e240 | md5 | miri | md5-bulk:197 [extended] | reused | 2026-10-28T11:42:04Z |
| miri-0c3980df81ad6903 | md5 | miri | md5-batch-mask:179 [extended] | reused | 2026-10-28T12:21:23Z |
| miri-0c406e9769198d45 | tuplehash | miri | tuplehash-staging:400 [extended] | reused | 2026-10-28T16:18:19Z |
| miri-0c4a83ef57ff37ac | tuplehash | miri | scoped_tuplexof128_differential:9:width=1 [extended] | passed | 2026-10-29T10:49:29Z |
| miri-0c50178cd8ee9a4b | tuplehash | miri | scoped_tuplexof128_differential:47:width=2 [extended] | reused | 2026-10-29T03:02:30Z |
| miri-0c55fd8c54761ddf | tuplehash | miri | scoped_tuplexof128_differential:23:width=0 [extended] | reused | 2026-10-29T01:58:09Z |
| miri-0c56e04b48ae2541 | legacy_hmac | miri | sha1_short [routine] | No mapped observation | — |
| miri-0c7e8e5d44ee16c1 | tuplehash | miri | tuplehash-staging:445 [extended] | reused | 2026-10-28T16:50:03Z |
| miri-0c90ec5f2f3e39f5 | tuplehash | miri | tuplehash-staging:455 [extended] | reused | 2026-10-28T22:47:26Z |
| miri-0c9d5ad6ef1dc7ce | md5 | miri | -p brynja-legacy-md5 --features cpu --lib [remaining suite; inspect skips with show] | reused | 2026-10-28T11:27:39Z |
| miri-0ca58740de4d78c4 | tuplehash | miri | tuplehash-staging:819 [extended] | reused | 2026-10-29T00:49:42Z |
| miri-0cb8cc0ddc47c72d | sha3 | miri | sha3-fixed-bits:2 [extended] | reused | 2026-10-28T13:46:31Z |
| miri-0cc726334f2d1274 | md5 | miri | md5-padding:64 [routine] | passed | 2026-10-19T11:13:43Z |
| miri-0cc77751a5e7ae2a | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:39:width=2 [extended] | reused | 2026-10-28T21:12:11Z |
| miri-0cc9320d13a6ce4a | sha1 | miri | sha1-scoped:15 [extended] | reused | 2026-10-28T13:16:52Z |
| miri-0cf49dfd81d5fd22 | tuplehash | miri | scoped_tuplexof128_differential:9:width=0 [extended] | passed | 2026-10-29T10:48:59Z |
| miri-0d081b86bff655da | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:14 [extended] | passed | 2026-10-29T12:59:17Z |
| miri-0d2a4f78b2a078b8 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:1:width=4 [extended] | reused | 2026-10-29T01:43:26Z |
| miri-0d389fcd434c847e | sha1 | miri | sha1-bulk:170 [extended] | reused | 2026-10-28T12:54:31Z |
| miri-0d6ebf98f3c2fba1 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:5:width=3 [extended] | reused | 2026-10-29T01:50:26Z |
| miri-0d804f21dabf8b0d | tuplehash | miri | tuplehash-staging:661 [extended] | reused | 2026-10-28T18:02:38Z |
| miri-0d8e1c8e5a0a0212 | md5 | miri | md5-bulk:93 [extended] | reused | 2026-10-28T11:34:02Z |
| miri-0d8e39f80635473a | kmac | miri | kmac-scoped-lifecycle:7 [routine] | passed | 2026-10-19T11:50:04Z |
| miri-0d8fc304a74cea75 | kmac | miri | kmac-streamed-setup:66 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-0d922f6127eff0d5 | sha1 | miri | sha1-scoped:32 [extended] | reused | 2026-10-28T13:06:30Z |
| miri-0d977fe8b07273ec | sha1 | miri | sha1-scoped:217 [extended] | reused | 2026-10-28T13:27:01Z |
| miri-0dc3c9babc7b8b3b | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:28:width=4 [extended] | reused | 2026-10-28T20:23:14Z |
| miri-0def76114d5af7ec | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:393 [extended] | passed | 2026-10-29T13:46:25Z |
| miri-0df31ebfae0e390b | tuplehash | miri | scoped_tuplexof256_differential:37:width=2 [extended] | passed | 2026-10-29T12:45:15Z |
| miri-0df6b08f8833069c | hmac | miri | -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-0df7e4ee7b0ca426 | md5 | miri | md5-bulk:48 [extended] | reused | 2026-10-28T11:40:38Z |
| miri-0e1c72cdd80285b1 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_unwind_reuse:1 [extended] | passed | 2026-10-29T14:05:44Z |
| miri-0e2820b23869a237 | sha3 | miri | -p brynja-hash-sha3 --features hardened-execution --lib hardened::accelerated::engine::tests::every_memory_region_is_explicitly_cleared [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-0e30b631e241112b | md5 | miri | md5-bulk:179 [extended] | reused | 2026-10-28T11:40:53Z |
| miri-0e44ea87ec29480d | tuplehash | miri | tuplehash-staging:286 [extended] | reused | 2026-10-28T15:45:24Z |
| miri-0e54d0acd60e7cb2 | md5 | miri | md5-batch-mask:192 [extended] | reused | 2026-10-28T12:27:45Z |
| miri-0e57f33d0958266b | tuplehash | miri | tuplehash-staging:377 [extended] | reused | 2026-10-28T16:27:32Z |
| miri-0e5ac5fc45126fed | md5 | miri | md5-batch-mask:87 [extended] | reused | 2026-10-28T12:13:53Z |
| miri-0e5c540a0271a762 | md5 | miri | md5-bulk:38 [extended] | reused | 2026-10-28T11:34:54Z |
| miri-0e93a75473850556 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:16:width=3 [extended] | reused | 2026-10-28T19:55:42Z |
| miri-0e95d00d298edbc4 | sha1 | miri | sha1-bulk:190 [extended] | reused | 2026-10-28T12:56:32Z |
| miri-0eb2ec189f53ea90 | md5 | miri | md5-scoped:75 [extended] | reused | 2026-10-28T11:52:18Z |
| miri-0ebef60595a9a850 | md5 | miri | md5-padding:92 [extended] | reused | 2026-10-28T11:25:08Z |
| miri-0ebf7dc255ef204a | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:36 [extended] | passed | 2026-10-29T12:45:45Z |
| miri-0ec19e48e792573a | sha1 | miri | sha1-padding:31 [extended] | reused | 2026-10-28T12:31:59Z |
| miri-0ec417f76abcaffd | tuplehash | miri | tuplehash-staging:772 [extended] | reused | 2026-10-28T18:17:44Z |
| miri-0ec49c129f1ae763 | sha1 | miri | sha1-scoped:14 [extended] | reused | 2026-10-28T13:03:49Z |
| miri-0ee052ccdba5e544 | tuplehash | miri | tuplehash-staging:91 [extended] | reused | 2026-10-28T20:44:41Z |
| miri-0efaf02be169b4ba | sha3 | miri | sha3-fixed-bits:8 [extended] | reused | 2026-10-28T13:55:18Z |
| miri-0f0062d197f6175a | kmac | miri | streaming_and_one_shot_are_identical_at_rate_boundaries [routine] | passed | 2026-10-19T11:50:12Z |
| miri-0f0586056f20a7ff | tuplehash | miri | tuplehash-staging:373 [extended] | reused | 2026-10-28T16:25:47Z |
| miri-0f18534cee059a5d | tuplehash | miri | tuplehash-staging:157 [extended] | reused | 2026-10-28T15:13:43Z |
| miri-0f1d1d7635909c8a | tuplehash | miri | tuplehash-staging:47 [extended] | reused | 2026-10-28T20:29:57Z |
| miri-0f1ecf8e058b1590 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:39:width=0 [extended] | reused | 2026-10-28T23:52:11Z |
| miri-0f2acf732c90e1dc | md5 | miri | md5-scoped:222 [extended] | reused | 2026-10-28T12:13:33Z |
| miri-0f2e47c6b242b82a | tuplehash | miri | tuplehash-staging:197 [extended] | reused | 2026-10-28T15:26:24Z |
| miri-0f308cc57708221b | tuplehash | miri | tuplehash-staging:552 [extended] | reused | 2026-10-28T17:07:36Z |
| miri-0f3c3ada90938716 | tuplehash | miri | tuplehash-staging:622 [extended] | reused | 2026-10-28T17:33:29Z |
| miri-0f44dd662b6e6b2a | tuplehash | miri | -p brynja-hash-tuple --features hardened-execution --test execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-0f492e482794e8eb | kmac | miri | kmac-streamed-setup:12 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-0f5a398e3ba60fb5 | sha2 | miri | -p brynja-hash-sha2 --features runtime-execution,general-sha512-t --lib execution_transaction [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-0f6a1e22de74b997 | sha1 | miri | sha1-scoped:39 [extended] | reused | 2026-10-28T13:18:35Z |
| miri-0f72fff99cd9b14c | tuplehash | miri | scoped_tuplexof256_differential:47:width=2 [extended] | reused | 2026-10-29T04:53:59Z |
| miri-0f73ada6f8419188 | sha1 | miri | sha1-scoped:73 [extended] | reused | 2026-10-28T13:15:43Z |
| miri-0f871bddeddb3302 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:27 [routine] | No mapped observation | — |
| miri-0f885641c27deb3d | kmac | miri | kmac-streamed-setup:82 [routine] | No mapped observation | — |
| miri-0f948ae93ebc9452 | tuplehash | miri | scoped_tuplexof256_differential:45 [routine] | passed | 2026-10-19T16:18:58Z |
| miri-0f97a38a5a0f1f14 | md5 | miri | md5-scoped:165 [extended] | reused | 2026-10-28T11:58:41Z |
| miri-0fa8c415ca156bd5 | tuplehash | miri | tuplehash-staging:349 [extended] | reused | 2026-10-28T16:18:07Z |
| miri-0fb8f597e9ec307a | sha2 | miri | -p brynja-hash-sha2 --features general-sha512-t --test general_hash dynamic_general_secret_lifecycle [remaining suite; inspect skips with show] | reused | 2026-10-28T13:33:49Z |
| miri-0fc9d6c30458a2d7 | md5 | miri | md5-bulk:8 [extended] | reused | 2026-10-28T11:38:00Z |
| miri-1008e21a42c3791d | tuplehash | miri | scoped_tuplexof256_differential:35:width=4 [extended] | reused | 2026-10-29T04:19:13Z |
| miri-100fe963ca3fce82 | md5 | miri | -p brynja-legacy-md5 --features execution --test execution callback_unwind_is_terminal_and_transactional [remaining suite; inspect skips with show] | passed | 2026-10-19T11:13:27Z |
| miri-1022fb47fa0f3357 | sha1 | miri | sha1-bulk:122 [extended] | reused | 2026-10-28T12:49:46Z |
| miri-102e36255c52906e | tuplehash | miri | scoped_tuplexof128_differential:30:width=0 [extended] | reused | 2026-10-29T01:26:26Z |
| miri-103ed2fac4267f39 | tuplehash | miri | scoped_tuplexof256_differential:18:width=1 [extended] | reused | 2026-10-29T02:47:19Z |
| miri-10404332de37835c | tuplehash | miri | tuplehash-staging:102 [extended] | reused | 2026-10-28T14:45:04Z |
| miri-1043e0ce62793d86 | md5 | miri | md5-batch-mask:226 [extended] | reused | 2026-10-28T12:36:05Z |
| miri-106f7c1a01ce7838 | md5 | miri | md5-padding:54 [extended] | reused | 2026-10-28T11:21:50Z |
| miri-108ac50b26afeffe | md5 | miri | md5-bulk:82 [extended] | reused | 2026-10-28T11:38:01Z |
| miri-108b97a777a99725 | sha1 | miri | sha1-scoped:115 [extended] | reused | 2026-10-28T13:24:11Z |
| miri-108d798332509793 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:4 [routine] | No mapped observation | — |
| miri-1090363322254565 | sha1 | miri | sha1-bulk:148 [extended] | reused | 2026-10-28T12:50:46Z |
| miri-1095988a3a0a8cee | tuplehash | miri | tuplehash-execution-fixed:11 [routine] | passed | 2026-10-19T16:04:02Z |
| miri-1099620049306c49 | tuplehash | miri | scoped_tuplexof256_differential:13:width=4 [extended] | passed | 2026-10-29T12:26:31Z |
| miri-109d46223f311446 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:22:width=0 [extended] | reused | 2026-10-28T22:33:52Z |
| miri-10ad27743cd6adf6 | tuplehash | miri | tuplehash-staging:642 [extended] | reused | 2026-10-28T17:39:32Z |
| miri-10ae5575509abfb3 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:45:width=1 [extended] | reused | 2026-10-29T03:28:25Z |
| miri-10bec021d32a02f4 | legacy_hmac | miri | -p brynja-legacy-hmac --features sha1-execution --lib execution::retained::tests [remaining suite; inspect skips with show] | passed | 2026-10-29T16:05:25Z |
| miri-10ca8a2a6db2fb8c | sha1 | miri | sha1-scoped:34 [extended] | reused | 2026-10-28T13:05:14Z |
| miri-10da77abe85fad76 | sha2 | miri | -p brynja-hash-sha2 --test hardened [remaining suite; inspect skips with show] | passed | 2026-10-19T11:35:02Z |
| miri-10dd5fa07759a17c | md5 | miri | md5-scoped:208 [extended] | reused | 2026-10-28T12:07:12Z |
| miri-10e70393b2e7f45c | sha3 | miri | xof_secret_fragments_transfer_and_clear_independently [routine] | passed | 2026-10-19T11:31:37Z |
| miri-10ebb9bd5987e300 | md5 | miri | md5-scoped:211 [extended] | reused | 2026-10-28T12:01:42Z |
| miri-10f12082f3d7a183 | md5 | miri | md5-batch-mask:4 [routine] | passed | 2026-10-19T11:26:50Z |
| miri-10f614cd52010967 | sha2 | miri | -p brynja-hash-sha2 --features general-sha512-t --test general_hash --lib dynamic_lifecycle_ [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-110f3841fcefbac1 | tuplehash | miri | scoped_tuplexof128_differential:12:width=2 [extended] | reused | 2026-10-29T00:49:44Z |
| miri-1114eaf96f3bb206 | kmac | miri | kmac-scoped-xof-lifecycle:6 [routine] | passed | 2026-10-19T11:37:57Z |
| miri-112515b8a0f44237 | tuplehash | miri | tuplehash-staging:342 [extended] | reused | 2026-10-28T16:03:43Z |
| miri-112db3ff8cf7d1c8 | sha1 | miri | sha1-scoped:44 [extended] | reused | 2026-10-28T13:07:21Z |
| miri-112e073e0c7eb20a | md5 | miri | md5-batch-mask:167 [extended] | reused | 2026-10-28T12:20:24Z |
| miri-114bdb1018e3cabe | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:26:width=2 [extended] | reused | 2026-10-28T20:13:39Z |
| miri-114dd7632053e2c2 | md5 | miri | md5-batch-mask:216 [extended] | reused | 2026-10-28T12:29:41Z |
| miri-11526d4b12aad8f5 | tuplehash | miri | tuplehash-staging:320 [routine] | passed | 2026-10-19T12:02:37Z |
| miri-1152b8feb5411749 | tuplehash | miri | tuplehash-staging:319 [extended] | reused | 2026-10-28T22:01:35Z |
| miri-1161b279bacf9fed | kmac | miri | kmac-scoped-lifecycle:2 [extended] | reused | 2026-10-28T13:52:40Z |
| miri-11647806c1e67ef7 | md5 | miri | md5-batch-mask:160 [extended] | reused | 2026-10-28T12:25:10Z |
| miri-116effc0303f7da5 | md5 | miri | md5-batch-mask:88 [extended] | reused | 2026-10-28T12:19:32Z |
| miri-117847ef3335c5dd | sha2 | miri | -p brynja-hash-sha2 --features general-sha512-t --test general_hash unwind_clears_secret_destination [remaining suite; inspect skips with show] | passed | 2026-10-19T11:23:23Z |
| miri-11b6afc3aa8f23c1 | md5 | miri | md5-bulk:128 [routine] | passed | 2026-10-19T11:32:31Z |
| miri-11bfe2a37cc2adc8 | tuplehash | miri | tuplehash-staging:370 [extended] | reused | 2026-10-28T16:12:50Z |
| miri-11ca9a58f7b1e47c | sha1 | miri | sha1-padding:85 [extended] | reused | 2026-10-28T12:35:07Z |
| miri-11cc34e11ebcf218 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:28 [routine] | No mapped observation | — |
| miri-12088a3779cdde56 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:45:width=4 [extended] | reused | 2026-10-29T03:28:25Z |
| miri-12195babe7b37c1a | tuplehash | miri | tuplehash-staging:316 [extended] | reused | 2026-10-28T15:51:03Z |
| miri-1235ef54c3f733e7 | md5 | miri | md5-batch-mask:172 [extended] | reused | 2026-10-28T12:26:06Z |
| miri-12362f0cd1d0569e | kmac | miri | kmac-streamed-setup:74 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-1246cf346c09ad44 | sha3 | miri | sha3-fixed-bits:14 [routine] | passed | 2026-10-19T11:39:03Z |
| miri-125e2d20132cb0d1 | md5 | miri | md5-scoped:42 [extended] | reused | 2026-10-28T12:00:55Z |
| miri-1262eb3dde238812 | tuplehash | miri | tuplehash-staging:419 [extended] | reused | 2026-10-28T22:35:39Z |
| miri-12681659349de66e | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:18 [extended] | passed | 2026-10-29T12:36:24Z |
| miri-126aa4481f72a041 | tuplehash | miri | scoped_tuplexof256_differential:39:width=0 [extended] | reused | 2026-10-29T04:28:59Z |
| miri-12a40b2dab641cc2 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-order:2 [extended] | passed | 2026-10-29T14:53:53Z |
| miri-12a6cbc8bbc8476e | tuplehash | miri | tuplehash-staging:126 [extended] | reused | 2026-10-28T14:52:57Z |
| miri-12ada714b9f9273a | sha1 | miri | sha1-scoped:148 [extended] | reused | 2026-10-28T13:15:26Z |
| miri-12b2b777ee8f7bbd | sha1 | miri | sha1-scoped:24 [extended] | reused | 2026-10-28T13:05:56Z |
| miri-12b75eecacc0f06c | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:31:width=4 [extended] | reused | 2026-10-28T20:52:30Z |
| miri-12b84c0cf253a933 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:1:width=3 [extended] | reused | 2026-10-29T01:43:26Z |
| miri-12ce4d58c857e0ac | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:0 [routine] | No mapped observation | — |
| miri-12ed162b683d7ff6 | tuplehash | miri | tuplehash-staging:291 [extended] | reused | 2026-10-28T21:52:09Z |
| miri-12ed8e541b96feca | md5 | miri | md5-scoped:188 [extended] | reused | 2026-10-28T12:05:48Z |
| miri-12f64c830d06a5cf | kmac | miri | kmac-scoped-xof-lifecycle:6 [extended] | reused | 2026-10-28T14:01:58Z |
| miri-12fdec86f0a29fdb | sha3 | miri | -p brynja-hash-sha3 --features batch-execution --lib batch::tests::shape_staging_empty_and_scalar_tail_boundaries [remaining suite; inspect skips with show] | passed | 2026-10-19T11:25:15Z |
| miri-1305117b2e4b6ead | sha1 | miri | sha1-bulk:138 [extended] | reused | 2026-10-28T12:51:17Z |
| miri-13080cdb91ed1ade | sha1 | miri | sha1-bulk:230 [extended] | reused | 2026-10-28T13:01:05Z |
| miri-1312a81e627f369b | md5 | miri | md5-scoped:268 [extended] | reused | 2026-10-28T12:11:36Z |
| miri-1328b6c2bbade53f | tuplehash | miri | tuplehash-staging:379 [extended] | reused | 2026-10-28T22:21:22Z |
| miri-1331ffc4ae12b8ee | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:21:width=3 [extended] | reused | 2026-10-29T02:24:05Z |
| miri-133c277de5c25afe | tuplehash | miri | scoped_tuplexof128_differential:28:width=1 [extended] | reused | 2026-10-29T01:27:22Z |
| miri-133fb421cd7fa1fa | tuplehash | miri | scoped_tuplexof128_differential:30:width=3 [extended] | reused | 2026-10-29T01:26:26Z |
| miri-13621b8d93624801 | sha3 | miri | sha3-fixed-boundaries:56 [routine] | passed | 2026-10-19T11:37:33Z |
| miri-1373bddf374c4250 | md5 | miri | md5-batch-mask:181 [extended] | reused | 2026-10-28T12:21:35Z |
| miri-138612944e426e06 | sha1 | miri | sha1-scoped:131 [extended] | reused | 2026-10-28T13:25:24Z |
| miri-1389324f1404d5b6 | parallelhash | miri | hardened_in_place::tests::scoped_parallel128_lifecycle [routine] | No mapped observation | — |
| miri-13a4f97ea37247e2 | tuplehash | miri | tuplehash-staging:290 [extended] | reused | 2026-10-28T15:46:42Z |
| miri-13bb5df9e1f3e66f | md5 | miri | md5-scoped:85 [extended] | reused | 2026-10-28T11:53:15Z |
| miri-13c7b3b426abd8f6 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:50:width=4 [extended] | reused | 2026-10-28T21:27:05Z |
| miri-13c7f56991803c1c | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:14 [extended] | passed | 2026-10-29T13:11:34Z |
| miri-13d59a2a026404b9 | tuplehash | miri | tuplehash-staging:21 [extended] | reused | 2026-10-28T14:28:05Z |
| miri-13d90ac923bdb004 | tuplehash | miri | scoped_tuplexof128_differential:3:width=1 [extended] | reused | 2026-10-29T01:17:27Z |
| miri-13fcca3b56a07216 | tuplehash | miri | tuplehash-staging:608 [extended] | reused | 2026-10-28T17:25:34Z |
| miri-140886cfc13a08a0 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:0 [extended] | passed | 2026-10-29T13:25:59Z |
| miri-143a56f3e3a4f419 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:7:width=2 [extended] | reused | 2026-10-28T22:39:20Z |
| miri-144893e3ed4878c6 | md5 | miri | md5-bulk:125 [extended] | reused | 2026-10-28T11:36:22Z |
| miri-14514c6b847eb374 | tuplehash | miri | scoped_tuplexof128_differential:22:width=2 [extended] | reused | 2026-10-29T01:07:25Z |
| miri-1454d049467eb1eb | kmac | miri | kmac-framing:1 [routine] | passed | 2026-10-19T15:28:57Z |
| miri-1462ed45368e69c7 | legacy | miri | --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib dynamic_ [remaining suite; inspect skips with show] | passed | 2026-10-29T15:01:25Z |
| miri-146f97ccf8cb8923 | tuplehash | miri | tuplehash-staging:353 [extended] | reused | 2026-10-28T16:19:27Z |
| miri-149375fdf75da15c | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:35:width=0 [extended] | reused | 2026-10-28T21:02:20Z |
| miri-149c256ba1e8f407 | sha1 | miri | sha1-scoped:261 [extended] | reused | 2026-10-28T13:30:38Z |
| miri-14a3f09489922832 | sha1 | miri | sha1-bulk:70 [extended] | reused | 2026-10-28T12:45:19Z |
| miri-14b631aadebc64e8 | tuplehash | miri | tuplehash-staging:886 [extended] | reused | 2026-10-28T18:57:35Z |
| miri-14b8d91c9f7e5247 | kmac | miri | kmac-streamed-setup:97 [routine] | No mapped observation | — |
| miri-14bc09e26530091d | tuplehash | miri | tuplehash-staging:783 [extended] | reused | 2026-10-29T00:37:57Z |
| miri-14cf4ffe04751bc7 | md5 | miri | md5-batch-mask:7 [extended] | reused | 2026-10-28T12:07:47Z |
| miri-14dd97a4e75a1d4a | legacy_hmac | miri | md5_short [extended] | passed | 2026-10-29T15:08:29Z |
| miri-14f6535734393db6 | md5 | miri | md5-bulk:109 [extended] | reused | 2026-10-28T11:35:11Z |
| miri-14fff165d54e5066 | md5 | miri | md5-scoped:11 [extended] | reused | 2026-10-28T11:48:05Z |
| miri-150acbdd312ca95f | tuplehash | miri | tuplehash-staging:104 [extended] | reused | 2026-10-28T14:42:43Z |
| miri-153055c1ee77aff7 | md5 | miri | md5-scoped:197 [extended] | reused | 2026-10-28T12:00:57Z |
| miri-154eadf0b2d4c42e | md5 | miri | md5-padding:79 [extended] | reused | 2026-10-28T11:28:38Z |
| miri-154ebcebbcf38e70 | md5 | miri | md5-bulk:146 [extended] | reused | 2026-10-28T11:43:06Z |
| miri-155947beb37883b7 | tuplehash | miri | tuplehash-staging:534 [extended] | reused | 2026-10-28T17:04:54Z |
| miri-155b1d89deac4ff5 | sha1 | miri | sha1-padding:29 [extended] | reused | 2026-10-28T12:30:21Z |
| miri-155d9144d0d4eebc | sha1 | miri | sha1-scoped:238 [extended] | reused | 2026-10-28T13:21:10Z |
| miri-156113349500512e | sha1 | miri | sha1-scoped:137 [extended] | reused | 2026-10-28T13:20:46Z |
| miri-1562e0857d3f1b62 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:29:width=0 [extended] | reused | 2026-10-29T02:43:39Z |
| miri-1566f3ba8c907a42 | tuplehash | miri | tuplehash-staging:624 [extended] | reused | 2026-10-28T17:29:58Z |
| miri-156ba6d2880f7316 | sha3 | miri | sha3-fixed-boundaries:53 [routine] | passed | 2026-10-19T11:34:15Z |
| miri-1578b0f45bedffe7 | sha1 | miri | sha1-padding:123 [extended] | reused | 2026-10-28T12:40:08Z |
| miri-1579d7d42f4b92b9 | sha2 | miri | -p brynja-hash-sha2 --lib buffer_length_rejects_invalid_values_without_mutation [remaining suite; inspect skips with show] | passed | 2026-10-19T11:35:43Z |
| miri-158e8b2244f867cb | md5 | miri | md5-scoped:64 [extended] | reused | 2026-10-28T11:57:15Z |
| miri-15946bddf0654db3 | md5 | miri | md5-scoped:254 [extended] | reused | 2026-10-28T12:15:50Z |
| miri-15a5bcf777544e17 | sha1 | miri | sha1-bulk:201 [extended] | reused | 2026-10-28T13:08:26Z |
| miri-15b29987ad4d2d86 | sha2 | miri | -p brynja-hash-sha2 --features batch-execution --test batch bounded_batch_lifecycle_smoke [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-15be6add55033298 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:25:width=2 [extended] | reused | 2026-10-29T02:33:53Z |
| miri-15be7489da5f0626 | sha1 | miri | sha1-bulk:53 [extended] | reused | 2026-10-28T12:54:24Z |
| miri-15beb635e612eae4 | md5 | miri | md5-scoped:195 [extended] | reused | 2026-10-28T12:00:31Z |
| miri-15d76724b7c25540 | tuplehash | miri | tuplehash-staging:636 [extended] | reused | 2026-10-28T17:34:34Z |
| miri-15e9d92b88280cc2 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:38:width=4 [extended] | reused | 2026-10-28T23:10:13Z |
| miri-1607e76592ab4cd9 | md5 | miri | md5-scoped:19 [extended] | reused | 2026-10-28T11:48:36Z |
| miri-160ce4126cbf7834 | sha1 | miri | sha1-bulk:7 [extended] | reused | 2026-10-28T12:46:34Z |
| miri-160dadd0a94f3f7c | tuplehash | miri | scoped_tuplexof128_differential:34:width=1 [extended] | reused | 2026-10-29T01:36:07Z |
| miri-16189a89136e5d0a | tuplehash | miri | scoped_tuplexof128_differential:31:width=1 [extended] | reused | 2026-10-29T02:17:45Z |
| miri-16256ff8843ba214 | md5 | miri | md5-scoped:104 [extended] | reused | 2026-10-28T12:00:01Z |
| miri-16293f64eeaa82ba | kmac | miri | kmac-streamed-setup:75 [routine] | No mapped observation | — |
| miri-1635fba66ba3c193 | sha1 | miri | sha1-bulk:253 [extended] | reused | 2026-10-28T13:15:07Z |
| miri-163a5d7e0f14e003 | tuplehash | miri | tuplehash-staging:65 [extended] | reused | 2026-10-28T14:42:24Z |
| miri-163db3fbe21bacf3 | kmac | miri | kmac-scoped-xof-lifecycle:9 [routine] | passed | 2026-10-19T11:52:51Z |
| miri-165b9c9cbbce69ed | tuplehash | miri | scoped_tuplexof128_differential:4:width=3 [extended] | reused | 2026-10-29T00:36:36Z |
| miri-165ecdcbc4220ff2 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:9 [routine] | No mapped observation | — |
| miri-1673ab3b1c5858cd | tuplehash | miri | scoped_tuplexof128_differential:23:width=3 [extended] | reused | 2026-10-29T01:58:09Z |
| miri-167a163176d3b7ea | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:0 [extended] | passed | 2026-10-29T13:56:56Z |
| miri-167f41c0f27b714e | md5 | miri | md5-scoped:286 [extended] | reused | 2026-10-28T12:18:09Z |
| miri-1696f705f8ab52bf | hmac | miri | sha3_512 [routine] | No mapped observation | — |
| miri-169cfba001595f0f | tuplehash | miri | scoped_tuplexof128_differential:26:width=0 [extended] | reused | 2026-10-29T01:16:55Z |
| miri-16a098f5a7ccd116 | kmac | miri | kmac-streamed-setup:27 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-16ca06c4c5d84a8b | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:26:width=3 [extended] | reused | 2026-10-28T20:13:39Z |
| miri-16d8d8e9a8ef79dc | sha1 | miri | sha1-bulk:157 [extended] | reused | 2026-10-28T13:03:41Z |
| miri-16d8e9cc5b9cf592 | sha1 | miri | sha1-bulk:187 [extended] | reused | 2026-10-28T13:02:08Z |
| miri-16e204dc5ef2d7dc | md5 | miri | md5-padding:62 [routine] | passed | 2026-10-19T11:25:52Z |
| miri-16e2c3d0844c70fc | sha1 | miri | sha1-padding:105 [extended] | reused | 2026-10-28T12:36:58Z |
| miri-16e864b83a102a4d | sha1 | miri | sha1-padding:59 [extended] | reused | 2026-10-28T12:34:09Z |
| miri-16e943ca0ca5c7dd | tuplehash | miri | scoped_tuplexof128_differential:42:width=3 [extended] | reused | 2026-10-29T01:58:04Z |
| miri-16ee09ba21261b27 | tuplehash | miri | tuplehash-staging:417 [extended] | reused | 2026-10-28T16:40:36Z |
| miri-16efa2a368e18c39 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:27 [routine] | No mapped observation | — |
| miri-16f19fb92262d84c | sha1 | miri | sha1-bulk:181 [extended] | reused | 2026-10-28T13:06:07Z |
| miri-1716aee717cc4339 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_unwind_reuse:1 [routine] | No mapped observation | — |
| miri-171d8ce200112fc8 | tuplehash | miri | tuplehash-staging:293 [extended] | reused | 2026-10-28T15:59:15Z |
| miri-1721d7368b4fa9dd | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:27 [extended] | passed | 2026-10-29T13:04:40Z |
| miri-172c108c2406f2bb | md5 | miri | md5-padding:120 [extended] | reused | 2026-10-28T11:27:18Z |
| miri-172dff1157ea0330 | tuplehash | miri | tuplehash-staging:570 [extended] | reused | 2026-10-28T17:16:49Z |
| miri-173ea2db73b1bb6e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:15:width=1 [extended] | reused | 2026-10-28T22:53:23Z |
| miri-1743b155c45bd847 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:9 [routine] | passed | 2026-10-19T16:11:49Z |
| miri-1744b3e5bd451532 | md5 | miri | md5-scoped:279 [extended] | reused | 2026-10-28T12:06:39Z |
| miri-1746eca3b02864ae | tuplehash | miri | scoped_tuplexof128_differential:9:width=2 [extended] | passed | 2026-10-29T10:49:40Z |
| miri-1748158ce2aa488e | tuplehash | miri | scoped_tuplexof128_differential:10:width=0 [extended] | reused | 2026-10-29T00:42:19Z |
| miri-1748f3285c238fbe | sha1 | miri | sha1-bulk:36 [extended] | reused | 2026-10-28T12:41:22Z |
| miri-1754b52472bdbf92 | md5 | miri | md5-scoped:107 [extended] | reused | 2026-10-28T11:54:30Z |
| miri-1759b04d605a228b | tuplehash | miri | scoped_tuplexof256_differential:29:width=4 [extended] | passed | 2026-10-29T12:39:56Z |
| miri-177c5be006a21bf9 | md5 | miri | md5-scoped:76 [extended] | reused | 2026-10-28T11:58:02Z |
| miri-1787b5f674b6c60b | tuplehash | miri | tuplehash-staging:352 [extended] | reused | 2026-10-28T16:03:09Z |
| miri-179548145e4b9ebd | tuplehash | miri | scoped_tuplexof256_differential:10:width=0 [extended] | reused | 2026-10-29T02:30:56Z |
| miri-17962f7593930596 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:7 [routine] | No mapped observation | — |
| miri-17d311759d93efbc | tuplehash | miri | tuplehash-staging:351 [extended] | reused | 2026-10-28T22:11:56Z |
| miri-17daba85cb22f38c | md5 | miri | md5-batch-mask:20 [extended] | reused | 2026-10-28T12:14:26Z |
| miri-17de4f7f5add03aa | tuplehash | miri | scoped_tuplexof128_differential:16:width=3 [extended] | reused | 2026-10-29T00:58:58Z |
| miri-17ebc42b1538ba78 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:44:width=3 [extended] | reused | 2026-10-28T21:05:12Z |
| miri-17ee533f03727f74 | tuplehash | miri | tuplehash-staging:889 [extended] | reused | 2026-10-28T19:19:01Z |
| miri-17eff9f36a606608 | md5 | miri | md5-scoped:237 [extended] | reused | 2026-10-28T12:03:53Z |
| miri-18027346397a190c | md5 | miri | md5-batch-mask:159 [extended] | reused | 2026-10-28T12:19:44Z |
| miri-1811d7aaaea4e53f | md5 | miri | md5-bulk:137 [extended] | reused | 2026-10-28T11:37:20Z |
| miri-181359cfcc336cef | md5 | miri | md5-bulk:194 [extended] | reused | 2026-10-28T11:47:11Z |
| miri-18137ba38860cf6f | tuplehash | miri | -p brynja-hash-tuple --test api forgotten_or_manually_dropped_items_cannot_bypass_the_open_latch [remaining suite; inspect skips with show] | passed | 2026-10-19T11:44:57Z |
| miri-181cb43ec1f9c0c5 | tuplehash | miri | scoped_tuplexof128_differential:3:width=2 [extended] | reused | 2026-10-29T01:17:27Z |
| miri-181f0d7b16d32b6c | tuplehash | miri | tuplehash-staging:245 [extended] | reused | 2026-10-28T15:42:40Z |
| miri-18219339b433ee79 | md5 | miri | md5-padding:105 [extended] | reused | 2026-10-28T11:35:33Z |
| miri-182acfa91a03dd08 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:22 [extended] | passed | 2026-10-29T13:22:45Z |
| miri-187607f746662f76 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:27:width=1 [extended] | reused | 2026-10-28T23:22:47Z |
| miri-18830761b15736a5 | md5 | miri | md5-bulk:154 [extended] | reused | 2026-10-28T11:43:46Z |
| miri-188a706810172fb4 | tuplehash | miri | tuplehash-staging:826 [extended] | reused | 2026-10-28T18:38:23Z |
| miri-188e3e14841252e9 | sha1 | miri | sha1-scoped:57 [extended] | reused | 2026-10-28T13:14:35Z |
| miri-18b0867d529011e3 | tuplehash | miri | scoped_tuplexof256_differential:23:width=3 [extended] | reused | 2026-10-29T03:50:03Z |
| miri-18dc982fc23945ad | md5 | miri | md5-bulk:224 [extended] | reused | 2026-10-28T11:54:49Z |
| miri-18de96f5cc3a872b | tuplehash | miri | tuplehash-staging:880 [extended] | reused | 2026-10-28T18:52:17Z |
| miri-18def9c4425d385a | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:18:width=1 [extended] | reused | 2026-10-28T19:55:16Z |
| miri-18fc1a457f1cc5ae | md5 | miri | md5-bulk:217 [extended] | reused | 2026-10-28T11:43:46Z |
| miri-19010a2182e67269 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:5:width=3 [extended] | reused | 2026-10-29T04:30:03Z |
| miri-191c4518f4cd844b | sha1 | miri | sha1-scoped:149 [extended] | reused | 2026-10-28T13:21:40Z |
| miri-191e8f12aa36ca06 | tuplehash | miri | tuplehash-staging:241 [extended] | reused | 2026-10-28T15:41:43Z |
| miri-1925a9753852e0e3 | kmac | miri | kmac-streamed-setup:87 [routine] | No mapped observation | — |
| miri-1949c98d1fb198cf | tuplehash | miri | tuplehash-staging:598 [extended] | reused | 2026-10-28T17:25:48Z |
| miri-1953dce92880e068 | tuplehash | miri | tuplehash-staging:133 [extended] | reused | 2026-10-28T15:05:15Z |
| miri-196f51553793d6a7 | sha1 | miri | sha1-scoped:278 [extended] | reused | 2026-10-28T13:24:29Z |
| miri-1975a098876feece | tuplehash | miri | tuplehash-staging:507 [extended] | reused | 2026-10-28T23:04:50Z |
| miri-197be7753b1b2502 | md5 | miri | md5-scoped:259 [extended] | reused | 2026-10-28T12:05:12Z |
| miri-199a2ca5e0d51d39 | sha3 | miri | sha3-fixed-boundaries:11 [routine] | passed | 2026-10-19T11:36:52Z |
| miri-199d58e03e8f0cec | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:43:width=2 [extended] | reused | 2026-10-28T21:24:50Z |
| miri-19ce428ab5e9cf33 | kmac | miri | kmac-streamed-setup:94 [routine] | No mapped observation | — |
| miri-19d6c0cfcdc882b2 | tuplehash | miri | tuplehash-staging:571 [extended] | reused | 2026-10-28T23:26:05Z |
| miri-19d8c913130445e5 | tuplehash | miri | scoped_tuplexof128_differential:27:width=4 [extended] | reused | 2026-10-29T02:07:59Z |
| miri-19dc759c87b5c1bf | sha3 | miri | -p brynja-hash-sha3 --lib final_bit_output_clears_the_exact_reader_source [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-19de1df6e1844ec2 | md5 | miri | md5-bulk:166 [extended] | reused | 2026-10-28T11:44:49Z |
| miri-19e0fab833148db3 | tuplehash | miri | tuplehash-staging:300 [extended] | reused | 2026-10-28T15:46:33Z |
| miri-19ea2ce2a88dec88 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:12:width=0 [extended] | reused | 2026-10-28T19:46:30Z |
| miri-19ef84520580becf | kmac | miri | kmac-streamed-setup:41 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-19fb6d26f0e0ce63 | md5 | miri | md5-scoped:202 [extended] | reused | 2026-10-28T12:12:05Z |
| miri-1a0e552c1b5c215e | tuplehash | miri | tuplehash-staging:281 [extended] | reused | 2026-10-28T15:54:25Z |
| miri-1a1846035dababed | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:36 [routine] | No mapped observation | — |
| miri-1a1c32afcf2851d8 | kmac | miri | kmac-streamed-setup:75 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-1a1fa10bc7781337 | md5 | miri | md5-bulk:150 [extended] | reused | 2026-10-28T11:43:25Z |
| miri-1a275868c726c4c6 | md5 | miri | md5-batch-mask:185 [extended] | reused | 2026-10-28T12:21:55Z |
| miri-1a2df801b72b7bce | tuplehash | miri | hardened_in_place::tests::scoped_tuple256_terminal_writer_and_output_lifecycle [routine] | passed | 2026-10-19T16:22:49Z |
| miri-1a3bcf9198baecdd | sha1 | miri | sha1-scoped:263 [extended] | reused | 2026-10-28T13:36:04Z |
| miri-1a53f75decb894dc | sha1 | miri | sha1-scoped:273 [extended] | reused | 2026-10-28T13:31:37Z |
| miri-1a62c91eab2b3fe5 | tuplehash | miri | scoped_tuplexof256_differential:43:width=3 [extended] | reused | 2026-10-29T04:41:29Z |
| miri-1a6bf995af5d9a84 | tuplehash | miri | scoped_tuplexof128_differential:1:width=4 [extended] | reused | 2026-10-29T07:08:40Z |
| miri-1a7f0760392ddcfb | tuplehash | miri | scoped_tuplexof128_differential:19:width=3 [extended] | reused | 2026-10-29T01:48:20Z |
| miri-1a7f0b42bc0011f6 | tuplehash | miri | tuplehash-staging:698 [extended] | reused | 2026-10-28T17:57:24Z |
| miri-1a806b0faa404853 | md5 | miri | md5-scoped:213 [extended] | reused | 2026-10-28T12:02:08Z |
| miri-1aa4122a620037d2 | sha1 | miri | sha1-scoped:33 [routine] | passed | 2026-10-19T11:35:24Z |
| miri-1aa5a3e9e5675ee7 | md5 | miri | md5-padding:104 [extended] | reused | 2026-10-28T11:26:03Z |
| miri-1aa74dfa8990bf29 | sha1 | miri | sha1-bulk:254 [extended] | reused | 2026-10-28T13:03:56Z |
| miri-1aa8e3c5aa2e0eb5 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:48:width=0 [extended] | reused | 2026-10-28T23:58:48Z |
| miri-1adabc195caaa574 | tuplehash | miri | tuplehash-staging:214 [extended] | reused | 2026-10-28T15:21:38Z |
| miri-1ae1ef268c619983 | kmac | miri | kmac128_mismatch_and_exact_width [extended] | reused | 2026-10-28T19:45:58Z |
| miri-1ae2b05463f9f395 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:11:width=4 [extended] | reused | 2026-10-28T22:46:21Z |
| miri-1aebc391ca0219ed | md5 | miri | md5-bulk:126 [extended] | reused | 2026-10-28T11:41:25Z |
| miri-1afdcca79a1eebfa | tuplehash | miri | scoped_tuplexof128_differential:43:width=0 [extended] | reused | 2026-10-29T02:49:54Z |
| miri-1b049c5b71ab2036 | md5 | miri | md5-batch-mask:68 [extended] | reused | 2026-10-28T12:18:02Z |
| miri-1b0e0ead219defa1 | tuplehash | miri | scoped_tuplexof256_differential:13:width=2 [extended] | passed | 2026-10-29T12:14:14Z |
| miri-1b29f37996ce9c87 | tuplehash | miri | scoped_tuplexof256_differential:18:width=0 [extended] | reused | 2026-10-29T02:47:19Z |
| miri-1b334dde3b9af5cc | tuplehash | miri | scoped_tuplexof128_differential:11:width=0 [extended] | reused | 2026-10-29T01:31:31Z |
| miri-1b41f74c6a34733e | md5 | miri | md5-scoped:179 [extended] | reused | 2026-10-28T11:59:24Z |
| miri-1b46a91bcb3f76ff | tuplehash | miri | scoped_tuplexof128_differential:39:width=4 [extended] | reused | 2026-10-29T02:37:19Z |
| miri-1b4a8976ee16f465 | tuplehash | miri | scoped_tuplexof256_differential:42:width=1 [extended] | reused | 2026-10-29T03:47:02Z |
| miri-1b57c85fc38907e2 | sha1 | miri | sha1-bulk:47 [extended] | reused | 2026-10-28T12:49:08Z |
| miri-1b6302c482d2c677 | sha1 | miri | sha1-bulk:130 [extended] | reused | 2026-10-28T12:50:29Z |
| miri-1b66100cfcbfc048 | tuplehash | miri | scoped_tuplexof256_differential:12:width=4 [extended] | reused | 2026-10-29T02:38:28Z |
| miri-1b6fbdbf54c8af7f | tuplehash | miri | tuplehash-staging:450 [extended] | reused | 2026-10-28T16:38:23Z |
| miri-1b9e917ad48d2a5b | kmac | miri | kmac-streamed-setup:81 [routine] | No mapped observation | — |
| miri-1ba219f8d95e2d05 | sha1 | miri | sha1-padding:3 [extended] | reused | 2026-10-28T12:29:50Z |
| miri-1ba2fcdef451f521 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:10:width=2 [extended] | reused | 2026-10-28T22:09:09Z |
| miri-1baf6335b95fcfff | md5 | miri | md5-bulk:124 [extended] | reused | 2026-10-28T11:46:13Z |
| miri-1bb423b31c646a1f | kmac | miri | kmac-streamed-setup:70 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-1bb8129144cb1939 | sha3 | miri | -p brynja-crypto-cpu-std --features sponge-execution --lib sponge::tests::portable_sponge [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-1bec2998e3d2e827 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:15:width=3 [extended] | reused | 2026-10-28T20:13:06Z |
| miri-1c0a458031d0ad19 | tuplehash | miri | scoped_tuplexof256_differential:22:width=3 [extended] | reused | 2026-10-29T02:56:47Z |
| miri-1c0c6567d4986c0d | sha1 | miri | sha1-scoped:248 [extended] | reused | 2026-10-28T13:23:38Z |
| miri-1c0d8aa16e31115a | tuplehash | miri | scoped_tuplexof128_differential:36:width=4 [extended] | reused | 2026-10-29T01:46:32Z |
| miri-1c12679d877722d7 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:450 [routine] | No mapped observation | — |
| miri-1c21b700a51235be | tuplehash | miri | tuplehash-staging:654 [extended] | reused | 2026-10-28T17:43:44Z |
| miri-1c24cde7f21b2835 | sha1 | miri | sha1-scoped:262 [extended] | reused | 2026-10-28T13:23:14Z |
| miri-1c2cd1e5d4257fab | tuplehash | miri | tuplehash-staging:697 [extended] | reused | 2026-10-28T18:14:19Z |
| miri-1c3dd703b1b12ed6 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:33:width=1 [extended] | reused | 2026-10-29T05:32:49Z |
| miri-1c450d4308cd1e28 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:6:width=2 [extended] | reused | 2026-10-28T19:32:57Z |
| miri-1c4e8734dac52eca | tuplehash | miri | tuplehash-staging:20 [extended] | reused | 2026-10-28T14:15:24Z |
| miri-1c5718c432b11b9a | md5 | miri | md5-padding:106 [extended] | reused | 2026-10-28T11:25:58Z |
| miri-1c613b2e9815772a | tuplehash | miri | tuplehash-staging:144 [extended] | reused | 2026-10-28T14:55:28Z |
| miri-1c6362b5831a0ee7 | kmac | miri | kmac-scoped-lifecycle:11 [extended] | reused | 2026-10-28T14:06:11Z |
| miri-1c65048ac9bd2a64 | sha1 | miri | sha1-bulk:123 [extended] | reused | 2026-10-28T12:55:28Z |
| miri-1c706ae02c964814 | md5 | miri | md5-scoped:139 [extended] | reused | 2026-10-28T11:56:40Z |
| miri-1c74b20ee3b65590 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-slots:1 [extended] | passed | 2026-10-29T14:51:51Z |
| miri-1c7aef1e7473979b | tuplehash | miri | scoped_tuplexof128_differential:21:width=0 [extended] | passed | 2026-10-29T10:57:47Z |
| miri-1c7cb965b9c29bd3 | sha3 | miri | -p brynja-hash-sha3 --features batch-execution --lib batch::tests::shape_staging_empty_and_scalar_tail_boundaries [remaining suite; inspect skips with show] | reused | 2026-10-28T13:34:41Z |
| miri-1c884e6517f1fdbc | kmac | miri | kmac-streamed-setup:69 [routine] | No mapped observation | — |
| miri-1c91c675a5c94dde | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:18 [extended] | passed | 2026-10-29T13:06:50Z |
| miri-1c9cac893b859e21 | md5 | miri | md5-scoped:99 [extended] | reused | 2026-10-28T11:53:57Z |
| miri-1ca2868475eaab79 | sha1 | miri | sha1-bulk:127 [extended] | reused | 2026-10-28T12:55:48Z |
| miri-1cace28f95851855 | tuplehash | miri | scoped_tuplexof256_differential:6:width=2 [extended] | reused | 2026-10-29T02:24:07Z |
| miri-1caef78460c8b244 | tuplehash | miri | tuplehash-staging:597 [extended] | reused | 2026-10-28T17:40:41Z |
| miri-1cb94e8350af1dbf | sha1 | miri | sha1-padding:48 [extended] | reused | 2026-10-28T12:38:07Z |
| miri-1cbe79325442015c | md5 | miri | md5-bulk:47 [extended] | reused | 2026-10-28T11:31:08Z |
| miri-1cbf46f99df08551 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:34:width=1 [extended] | reused | 2026-10-28T23:01:09Z |
| miri-1cc5ff3f015f6485 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:50:width=0 [extended] | reused | 2026-10-28T21:27:05Z |
| miri-1cd4c28ab1163342 | tuplehash | miri | tuplehash-staging:317 [extended] | reused | 2026-10-28T16:06:57Z |
| miri-1cfa6998ec8c56a5 | tuplehash | miri | scoped_tuplexof256_differential:18:width=3 [extended] | reused | 2026-10-29T02:47:19Z |
| miri-1cfb5ade6e383238 | sha1 | miri | sha1-scoped:170 [extended] | reused | 2026-10-28T13:15:40Z |
| miri-1d00a953ceee08d8 | tuplehash | miri | scoped_tuplexof128_differential:25:width=1 [extended] | passed | 2026-10-29T10:57:22Z |
| miri-1d235e83a2984d3a | md5 | miri | md5-batch-mask:184 [extended] | reused | 2026-10-28T12:27:06Z |
| miri-1d46dcf361ba3995 | kmac | miri | kmac-streamed-setup:47 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-1d5458ae4cc5e995 | tuplehash | miri | tuplehash-staging:848 [extended] | reused | 2026-10-28T18:41:39Z |
| miri-1d6ce0fdc25910bc | tuplehash | miri | tuplehash-staging:538 [extended] | reused | 2026-10-28T17:06:34Z |
| miri-1d795439e3bb11de | tuplehash | miri | scoped_tuplexof128_differential:13:width=3 [extended] | passed | 2026-10-29T10:52:03Z |
| miri-1d88434c82da1178 | sha1 | miri | sha1-padding:88 [extended] | reused | 2026-10-28T12:41:58Z |
| miri-1d8dab220802ec1d | sha1 | miri | sha1-scoped:211 [extended] | reused | 2026-10-28T13:31:42Z |
| miri-1d91c458c794d897 | tuplehash | miri | tuplehash-staging:564 [extended] | reused | 2026-10-28T17:11:06Z |
| miri-1d9a5b23931883b0 | parallelhash | miri | -p brynja-hash-parallel-std --features runtime-execution --lib execution [remaining suite; inspect skips with show] | passed | 2026-10-29T13:01:39Z |
| miri-1daad97641bb8838 | sha1 | miri | sha1-bulk:161 [extended] | reused | 2026-10-28T13:04:05Z |
| miri-1daedcf6d3958cbc | sha1 | miri | sha1-scoped:130 [extended] | reused | 2026-10-28T13:12:26Z |
| miri-1dd073ce39cc4c4e | tuplehash | miri | tuplehash-staging:234 [extended] | reused | 2026-10-28T15:28:26Z |
| miri-1dd7d44dfa7402fd | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:45 [extended] | passed | 2026-10-29T13:06:08Z |
| miri-1ddeff6dddea4cec | tuplehash | miri | tuplehash-staging:470 [extended] | reused | 2026-10-28T16:44:16Z |
| miri-1de8dbe4c3f01172 | md5 | miri | md5-batch-mask:176 [extended] | reused | 2026-10-28T12:26:26Z |
| miri-1deb8be6a2238470 | sha1 | miri | sha1-padding:72 [extended] | reused | 2026-10-28T12:40:23Z |
| miri-1e08f97169174c50 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:2:width=1 [extended] | reused | 2026-10-28T19:26:23Z |
| miri-1e0a0bdc2195298a | tuplehash | miri | scoped_tuplexof256_differential:25:width=4 [extended] | passed | 2026-10-29T12:36:33Z |
| miri-1e11bc05d04646cd | sha3 | miri | -p brynja-hash-sha3 --test sha3_384 suffix_and_rate_boundaries_have_exact_digests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-1e2b84fbdea4d5d6 | tuplehash | miri | tuplehash-staging:717 [extended] | reused | 2026-10-28T18:21:29Z |
| miri-1e30442047f1c84e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:1:width=3 [extended] | reused | 2026-10-29T04:23:03Z |
| miri-1e30d046d3e00c9b | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:14:width=3 [extended] | reused | 2026-10-28T22:15:42Z |
| miri-1e3a6df4762f8add | tuplehash | miri | scoped_tuplexof128_differential:2:width=0 [extended] | reused | 2026-10-29T00:29:11Z |
| miri-1e409a67dd675c90 | sha1 | miri | sha1-padding:25 [extended] | reused | 2026-10-28T12:30:03Z |
| miri-1e51a2d60254bdd7 | tuplehash | miri | tuplehash-staging:140 [extended] | reused | 2026-10-28T14:54:09Z |
| miri-1e6731883255d1d6 | kmac | miri | kmac-streamed-setup:63 [routine] | No mapped observation | — |
| miri-1e6884153f51b7c8 | sha1 | miri | sha1-bulk:23 [extended] | reused | 2026-10-28T12:47:37Z |
| miri-1e7080b6f026969e | md5 | miri | md5-padding:47 [extended] | reused | 2026-10-28T11:26:27Z |
| miri-1e754088eb3f77a1 | sha1 | miri | sha1-scoped:127 [extended] | reused | 2026-10-28T13:25:06Z |
| miri-1e803368d2cf76d7 | sha1 | miri | sha1-padding:14 [extended] | reused | 2026-10-28T12:40:22Z |
| miri-1e89f0973bcd7747 | tuplehash | miri | tuplehash-staging:776 [extended] | reused | 2026-10-28T18:19:23Z |
| miri-1e9a82655ec3b772 | md5 | miri | md5-bulk:2 [routine] | passed | 2026-10-19T11:13:55Z |
| miri-1e9b636298c54131 | tuplehash | miri | tuplehash-staging:707 [extended] | reused | 2026-10-29T00:11:53Z |
| miri-1e9f80b3f7f66de1 | tuplehash | miri | tuplehash-staging:862 [extended] | reused | 2026-10-28T18:49:32Z |
| miri-1ea086c8b1020abe | tuplehash | miri | tuplehash-staging:768 [extended] | reused | 2026-10-28T18:16:27Z |
| miri-1ea5f83fd6d0eaca | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:21:width=2 [extended] | reused | 2026-10-29T05:03:33Z |
| miri-1eab3034e0c74ec6 | tuplehash | miri | tuplehash-staging:283 [extended] | reused | 2026-10-28T21:49:51Z |
| miri-1eb85bb3f3076164 | sha1 | miri | sha1-scoped:82 [extended] | reused | 2026-10-28T13:08:42Z |
| miri-1ecb9da16f61ecba | sha1 | miri | sha1-scoped:271 [extended] | reused | 2026-10-28T13:36:43Z |
| miri-1ef242c8e773f051 | sha1 | miri | sha1-bulk:126 [extended] | reused | 2026-10-28T12:50:05Z |
| miri-1ef8c1a41881bc4a | tuplehash | miri | tuplehash-staging:568 [extended] | reused | 2026-10-28T17:11:59Z |
| miri-1ef9f48b84384c9f | kmac | miri | kmac-streamed-setup:53 [routine] | No mapped observation | — |
| miri-1f05fb0ceeb701ac | md5 | miri | -p brynja-legacy-md5 --features cpu --lib [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-1f357483b0d10ca8 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:5:width=0 [extended] | reused | 2026-10-29T04:30:03Z |
| miri-1f78fe915ef6ed54 | sha1 | miri | sha1-padding:102 [extended] | reused | 2026-10-28T12:48:12Z |
| miri-1f8c771e6e1575bb | tuplehash | miri | tuplehash-staging:626 [extended] | reused | 2026-10-28T17:34:46Z |
| miri-1f8fce821f72678a | sha1 | miri | sha1-scoped:28 [extended] | reused | 2026-10-28T13:06:12Z |
| miri-1fa2627caa7b6df4 | sha1 | miri | sha1-padding:54 [extended] | reused | 2026-10-28T12:43:33Z |
| miri-1fa91576b687d048 | sha1 | miri | sha1-padding:54 [routine] | passed | 2026-10-19T11:30:39Z |
| miri-1fb1eef48efd4d92 | tuplehash | miri | scoped_tuplexof256_differential:11:width=2 [extended] | reused | 2026-10-29T03:23:30Z |
| miri-1fb83f10f0a16fcf | tuplehash | miri | tuplehash-staging:205 [extended] | reused | 2026-10-28T15:29:29Z |
| miri-1fc31add39a638f1 | sha1 | miri | sha1-scoped:284 [extended] | reused | 2026-10-28T13:26:25Z |
| miri-1fc4526090d43fbb | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:15:width=2 [extended] | reused | 2026-10-28T20:13:06Z |
| miri-1fc70026a3e2f6e5 | md5 | miri | md5-batch-mask:243 [extended] | reused | 2026-10-28T12:26:41Z |
| miri-1fec248da61f1e78 | sha1 | miri | sha1-bulk:65 [extended] | reused | 2026-10-28T12:55:18Z |
| miri-1ff38c2a25d6e680 | md5 | miri | md5-bulk:206 [extended] | reused | 2026-10-28T11:48:18Z |
| miri-201e467cfaa59db0 | md5 | miri | md5-bulk:64 [routine] | passed | 2026-10-19T11:26:10Z |
| miri-2021ec27c6262620 | md5 | miri | md5-batch-mask:233 [extended] | reused | 2026-10-28T12:25:47Z |
| miri-204a1b4fbe30913f | parallelhash | miri | hardened_in_place::xof::tests::scoped_parallel_xof256_lifecycle [routine] | No mapped observation | — |
| miri-20651d8d06dd2ec3 | kmac | miri | kmac-streamed-setup:64 [routine] | No mapped observation | — |
| miri-20661bf52b89d3c9 | tuplehash | miri | tuplehash-staging:128 [routine] | passed | 2026-10-19T11:45:55Z |
| miri-2080526292b23c1b | kmac | miri | kmac-streamed-setup:76 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-2080a2353590e8d7 | kmac | miri | kmac-scoped-xof-lifecycle:3 [routine] | passed | 2026-10-19T15:34:04Z |
| miri-208d97b3acd1cd7b | sha3 | miri | sha3-fixed-boundaries:56 [extended] | reused | 2026-10-28T13:52:07Z |
| miri-2091dcbdf7c085f0 | tuplehash | miri | tuplehash-staging:276 [extended] | reused | 2026-10-28T15:38:51Z |
| miri-20964d6df1aa7ced | md5 | miri | md5-padding:118 [extended] | reused | 2026-10-28T11:26:53Z |
| miri-209fe295229834a2 | tuplehash | miri | scoped_tuplexof256_differential:21:width=4 [extended] | passed | 2026-10-29T12:33:12Z |
| miri-20a022bc8d312047 | tuplehash | miri | scoped_tuplexof256_differential:20:width=1 [extended] | reused | 2026-10-29T02:57:28Z |
| miri-20a41082cd136ca6 | md5 | miri | md5-bulk:130 [extended] | reused | 2026-10-28T11:41:45Z |
| miri-20b18696def73d05 | tuplehash | miri | scoped_tuplexof256_differential:8:width=1 [extended] | reused | 2026-10-29T02:31:37Z |
| miri-20b1e7326259539a | tuplehash | miri | tuplehash-staging:465 [extended] | reused | 2026-10-28T16:56:56Z |
| miri-20bbda7838e2229e | kmac | miri | kmac-streamed-setup:63 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-20db5b6326374ff9 | sha1 | miri | sha1-scoped:112 [extended] | reused | 2026-10-28T13:12:32Z |
| miri-20e0174a9dbe665d | sha2 | miri | -p brynja-hash-sha2 --test sha384 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | passed | 2026-10-19T11:24:51Z |
| miri-20ed2dc47d56c36f | kmac | miri | kmac-scoped-lifecycle:3 [routine] | passed | 2026-10-19T11:49:45Z |
| miri-2111870bd6206f63 | md5 | miri | md5-scoped:248 [extended] | reused | 2026-10-28T12:10:07Z |
| miri-2115a1076a51a8fc | sha1 | miri | sha1-scoped:43 [extended] | reused | 2026-10-28T13:18:53Z |
| miri-2127788b24d16162 | tuplehash | miri | scoped_tuplexof128_differential:44:width=4 [extended] | reused | 2026-10-29T02:11:09Z |
| miri-21315e1b3c7d51ec | tuplehash | miri | tuplehash-staging:748 [extended] | reused | 2026-10-28T18:10:25Z |
| miri-213ad2da73f0df6b | sha3 | miri | sha3-fixed-boundaries:3 [extended] | reused | 2026-10-28T13:36:58Z |
| miri-214351aa87dd35a7 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:27 [extended] | passed | 2026-10-29T13:28:07Z |
| miri-21523e22625d5f5b | md5 | miri | md5-batch-mask:214 [extended] | reused | 2026-10-28T12:35:04Z |
| miri-2154744e9d958e6f | md5 | miri | md5-batch-mask:201 [extended] | reused | 2026-10-28T12:23:12Z |
| miri-21639f8f272fce41 | tuplehash | miri | scoped_tuplexof128_differential:34:width=2 [extended] | reused | 2026-10-29T01:36:07Z |
| miri-217d9d2bac72028d | md5 | miri | md5-scoped:33 [routine] | passed | 2026-10-19T11:14:25Z |
| miri-21879a84b27c399a | parallelhash | miri | [bounded-parallelhash-v1] parallelhashxof-official:4 [routine] | No mapped observation | — |
| miri-218ee0f4b0c3575c | tuplehash | miri | tuplehash-staging:142 [extended] | reused | 2026-10-28T14:58:14Z |
| miri-219863abc989da8a | tuplehash | miri | scoped_tuplexof128_differential:40:width=3 [extended] | reused | 2026-10-29T01:58:45Z |
| miri-219dd5fb895cb122 | md5 | miri | md5-batch-mask:59 [extended] | reused | 2026-10-28T12:11:44Z |
| miri-21aa4163c15f0fbf | tuplehash | miri | hardened_in_place::xof::tests::scoped_tuplexof128_lifecycle [extended] | reused | 2026-10-29T04:04:30Z |
| miri-21afdb340f107df9 | kmac | miri | -p brynja-mac-kmac --tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-21b20f80170ce4dd | md5 | miri | md5-batch-mask:238 [extended] | reused | 2026-10-28T12:37:07Z |
| miri-21bae134c9602d92 | tuplehash | miri | tuplehash-staging:131 [extended] | reused | 2026-10-28T20:58:09Z |
| miri-21cd529e2c8fefec | md5 | miri | md5-scoped:119 [extended] | reused | 2026-10-28T11:55:18Z |
| miri-21cf31b4e7980872 | tuplehash | miri | tuplehash-staging:541 [extended] | reused | 2026-10-28T17:21:50Z |
| miri-21e10e962c99f868 | sha1 | miri | sha1-padding:46 [extended] | reused | 2026-10-28T12:42:54Z |
| miri-21f72a132e287e60 | tuplehash | miri | scoped_tuplexof256_differential:31:width=4 [extended] | reused | 2026-10-29T04:09:27Z |
| miri-22201b68664dc78c | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_unwind_reuse:2 [extended] | passed | 2026-10-29T14:18:27Z |
| miri-222fae5f4264ea70 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:20:width=1 [extended] | reused | 2026-10-28T22:34:16Z |
| miri-2231fe7cf444e525 | tuplehash | miri | scoped_tuplexof256_differential:0:width=4 [extended] | reused | 2026-10-29T02:17:57Z |
| miri-2242015ce1b32956 | tuplehash | miri | tuplehash-staging:265 [extended] | reused | 2026-10-28T15:49:49Z |
| miri-2242627de661dc2c | tuplehash | miri | tuplehash-staging:884 [extended] | reused | 2026-10-28T18:53:33Z |
| miri-2268f2d740ac85dd | md5 | miri | md5-batch-mask:123 [extended] | reused | 2026-10-28T12:16:47Z |
| miri-2274d1f0d16568dc | md5 | miri | md5-bulk:175 [extended] | reused | 2026-10-28T11:40:34Z |
| miri-22837db73a974c02 | tuplehash | miri | tuplehash-staging:695 [extended] | reused | 2026-10-29T00:07:50Z |
| miri-2285b57dc20084fb | tuplehash | miri | tuplehash-staging:53 [extended] | reused | 2026-10-28T14:38:26Z |
| miri-2296d74407903f97 | sha1 | miri | sha1-bulk:21 [extended] | reused | 2026-10-28T12:52:16Z |
| miri-229c745c4729bc82 | md5 | miri | md5-batch-mask:47 [extended] | reused | 2026-10-28T12:10:48Z |
| miri-22a5ad344c91e6c2 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:18 [extended] | passed | 2026-10-29T14:55:28Z |
| miri-22cb9ed29b4e2c85 | tuplehash | miri | scoped_tuplexof256_differential:34:width=3 [extended] | reused | 2026-10-29T03:25:12Z |
| miri-22d908fe216069ab | tuplehash | miri | tuplehash-execution-fixed:3 [routine] | passed | 2026-10-19T15:55:57Z |
| miri-22e271f57d7341de | parallelhash | miri | streamed_scheduled_and_one_shot_are_identical [routine] | passed | 2026-10-19T13:42:27Z |
| miri-22f50208f14a5d5c | md5 | miri | md5-bulk:54 [extended] | reused | 2026-10-28T11:35:58Z |
| miri-23057a0db6c24008 | tuplehash | miri | scoped_tuplexof128_differential:35:width=1 [extended] | reused | 2026-10-29T02:27:31Z |
| miri-2308eeffd948ca60 | tuplehash | miri | tuplehash-staging:138 [extended] | reused | 2026-10-28T14:56:54Z |
| miri-230d0ed5e21af62b | tuplehash | miri | scoped_tuplexof256_differential:22:width=4 [extended] | reused | 2026-10-29T02:56:47Z |
| miri-2328df8d117bca0d | tuplehash | miri | tuplehash-staging:51 [extended] | reused | 2026-10-28T20:31:15Z |
| miri-2334411d9eaaec45 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:36 [extended] | passed | 2026-10-29T13:09:04Z |
| miri-234150cd16f30674 | sha1 | miri | sha1-scoped:214 [extended] | reused | 2026-10-28T13:19:15Z |
| miri-234abc4d74e66f43 | tuplehash | miri | tuplehash-staging:387 [extended] | reused | 2026-10-28T22:24:27Z |
| miri-234eba2b612ab306 | sha1 | miri | sha1-scoped:200 [extended] | reused | 2026-10-28T13:19:36Z |
| miri-237d908722c3935a | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:9 [routine] | No mapped observation | — |
| miri-2398f2ae37dff1a1 | tuplehash | miri | tuplehash-staging:818 [extended] | reused | 2026-10-28T18:36:12Z |
| miri-23c0d566d12e62d1 | sha3 | miri | sha3-fixed-bits:22 [routine] | passed | 2026-10-19T11:39:27Z |
| miri-23d5981fcddb6eb2 | sha1 | miri | sha1-bulk:144 [extended] | reused | 2026-10-28T12:50:23Z |
| miri-23ec2a2b6c26e146 | tuplehash | miri | tuplehash-execution-fixed:0 [routine] | passed | 2026-10-19T11:59:28Z |
| miri-23efbd56e01bb532 | tuplehash | miri | scoped_tuplexof128_differential:17:width=3 [extended] | passed | 2026-10-29T10:54:13Z |
| miri-23fc66ca2d7113c4 | md5 | miri | md5-bulk:35 [extended] | reused | 2026-10-28T11:30:22Z |
| miri-23fe20df58986891 | tuplehash | miri | scoped_tuplexof256_differential:31:width=3 [extended] | reused | 2026-10-29T04:09:27Z |
| miri-240a0a727e1bb227 | tuplehash | miri | tuplehash-staging:213 [extended] | reused | 2026-10-28T15:32:33Z |
| miri-24207d2867834ea5 | tuplehash | miri | tuplehash-staging:478 [extended] | reused | 2026-10-28T16:47:07Z |
| miri-24256700ab260dd8 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:55:width=4 [extended] | reused | 2026-10-29T01:10:24Z |
| miri-2461944bae98978a | tuplehash | miri | tuplehash-staging:820 [extended] | reused | 2026-10-28T18:32:42Z |
| miri-2467b67ef2a59ca3 | tuplehash | miri | tuplehash-staging:151 [extended] | reused | 2026-10-28T21:04:54Z |
| miri-247b33245f0d4b0e | sha1 | miri | sha1-scoped:258 [extended] | reused | 2026-10-28T13:22:53Z |
| miri-2487973362c889ad | md5 | miri | md5-padding:89 [extended] | reused | 2026-10-28T11:34:16Z |
| miri-249022c9dcdc7a55 | sha2 | miri | -p brynja-hash-sha2 --features batch512-execution --test batch512 batch512_general::derived_iv_work_is_bounded_and_named_identity_is_distinct [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-2492043a1e64b178 | sha3 | miri | sha3-fixed-bits:5 [extended] | reused | 2026-10-28T13:41:56Z |
| miri-24974ce1ff12fddd | sha1 | miri | sha1-bulk:54 [extended] | reused | 2026-10-28T12:44:09Z |
| miri-249958bf6858e97b | tuplehash | miri | scoped_tuplexof128_differential:18:width=4 [extended] | reused | 2026-10-29T00:58:05Z |
| miri-249a3903dfaa3b50 | hmac | miri | sha3_384 [existing-full] | No mapped observation | — |
| miri-24a1a91a6bd094a4 | md5 | miri | md5-batch-mask:63 [extended] | reused | 2026-10-28T12:12:04Z |
| miri-24ad111ee1dece73 | md5 | miri | md5-bulk:253 [extended] | reused | 2026-10-28T11:46:55Z |
| miri-24c0993f21fb0e43 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:27:width=2 [extended] | reused | 2026-10-28T20:42:37Z |
| miri-24d989652df6d3bd | tuplehash | miri | tuplehash-staging:149 [extended] | reused | 2026-10-28T15:10:38Z |
| miri-250a41c8f1190b54 | tuplehash | miri | tuplehash-staging:89 [extended] | reused | 2026-10-28T14:50:27Z |
| miri-251b4866899b2c5f | tuplehash | miri | tuplehash-staging:262 [extended] | reused | 2026-10-28T15:37:40Z |
| miri-2548bb6455d5d419 | sha1 | miri | sha1-scoped:91 [extended] | reused | 2026-10-28T13:22:23Z |
| miri-254bed0209e3dead | md5 | miri | md5-padding:43 [extended] | reused | 2026-10-28T11:26:13Z |
| miri-256bbedf28bd106f | md5 | miri | md5-batch-mask:191 [routine] | passed | 2026-10-19T11:33:12Z |
| miri-258f085b878f6fd2 | sha1 | miri | sha1-scoped:279 [extended] | reused | 2026-10-28T13:37:22Z |
| miri-258fe7a19111e65c | tuplehash | miri | tuplehash-staging:64 [routine] | passed | 2026-10-19T12:01:20Z |
| miri-259a77f570161a6f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:38:width=1 [extended] | reused | 2026-10-28T23:10:13Z |
| miri-259deb1e0ef95542 | tuplehash | miri | tuplehash-staging:221 [extended] | reused | 2026-10-28T15:34:51Z |
| miri-25c352e9c61de209 | sha2 | miri | -p brynja-hash-sha2 --test bit_inputs selected_official_nist_bit_vectors_match_every_identity [remaining suite; inspect skips with show] | reused | 2026-10-28T13:33:49Z |
| miri-25c38e856fa6d9ed | kmac | miri | kmac-streamed-setup:17 [routine] | No mapped observation | — |
| miri-25cf0fb570ed59eb | md5 | miri | md5-bulk:230 [extended] | reused | 2026-10-28T11:50:28Z |
| miri-25d5c8a1ae7d45d9 | sha1 | miri | sha1-scoped:283 [extended] | reused | 2026-10-28T13:37:42Z |
| miri-25e45cfd5245c717 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:10 [extended] | passed | 2026-10-29T13:56:27Z |
| miri-25f9a632c0a54f47 | sha1 | miri | sha1-padding:34 [extended] | reused | 2026-10-28T12:41:57Z |
| miri-260b3303d60acfa1 | kmac | miri | kmac-streamed-setup:35 [routine] | No mapped observation | — |
| miri-26130a5cb2803c7a | sha3 | miri | sha3-fixed-bits:7 [extended] | reused | 2026-10-28T13:47:29Z |
| miri-26271bfd1b8dfa9d | tuplehash | miri | tuplehash-staging:495 [extended] | reused | 2026-10-28T23:00:31Z |
| miri-262aea0ef4388100 | tuplehash | miri | scoped_tuplexof256_differential:10:width=1 [extended] | reused | 2026-10-29T02:30:56Z |
| miri-263003ddb62b3102 | sha1 | miri | sha1-bulk:97 [extended] | reused | 2026-10-28T12:57:59Z |
| miri-264c0dca0f717eff | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-domains:1 [routine] | No mapped observation | — |
| miri-26511630be01f0f8 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:41:width=2 [extended] | reused | 2026-10-29T03:15:49Z |
| miri-26559d2f9b000df5 | kmac | miri | kmac-streamed-setup:98 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-2656f492843e3857 | md5 | miri | md5-scoped:18 [extended] | reused | 2026-10-28T11:59:18Z |
| miri-265eb05f2795ee6f | sha1 | miri | sha1-bulk:166 [extended] | reused | 2026-10-28T12:54:06Z |
| miri-266cdb0c23c82ae8 | tuplehash | miri | scoped_tuplexof128_differential:6:width=2 [extended] | reused | 2026-10-29T00:35:44Z |
| miri-267452c2f69b54ee | hmac | miri | general_129 [extended] | passed | 2026-10-29T15:07:52Z |
| miri-2675087923bf6aae | tuplehash | miri | tuplehash-staging:650 [extended] | reused | 2026-10-28T17:42:27Z |
| miri-268eaa9f0c02aea3 | hmac | miri | -p brynja-crypto-cpu-std --features hmac-execution --test hmac [remaining suite; inspect skips with show] | passed | 2026-10-29T16:04:26Z |
| miri-269d597457b32e04 | md5 | miri | md5-bulk:30 [extended] | reused | 2026-10-28T11:34:23Z |
| miri-26cfa7b122b01bc5 | sha1 | miri | sha1-scoped:64 [extended] | reused | 2026-10-28T13:08:46Z |
| miri-26d172410a3c2a8d | tuplehash | miri | tuplehash-execution-fixed:2 [extended] | reused | 2026-10-28T19:04:56Z |
| miri-26d2782acc304422 | md5 | miri | md5-batch-mask:101 [extended] | reused | 2026-10-28T12:15:11Z |
| miri-26d36edfc9e793ba | sha3 | miri | sha3-fixed-boundaries:68 [extended] | reused | 2026-10-28T13:54:05Z |
| miri-26d3871a10698531 | md5 | miri | md5-batch-mask:70 [extended] | reused | 2026-10-28T12:23:32Z |
| miri-26d70f4287220bda | sha1 | miri | sha1-scoped:37 [extended] | reused | 2026-10-28T13:13:15Z |
| miri-26f6cc2f8e714ba3 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:23:width=1 [extended] | reused | 2026-10-28T23:12:58Z |
| miri-26f8dfecc39864f4 | md5 | miri | md5-scoped:41 [extended] | reused | 2026-10-28T11:50:18Z |
| miri-26fe332085f8560e | tuplehash | miri | tuplehash-staging:876 [extended] | reused | 2026-10-28T18:50:38Z |
| miri-2715120609e620ee | tuplehash | miri | tuplehash-staging:67 [extended] | reused | 2026-10-28T20:36:35Z |
| miri-271ac6b2338441de | kmac | miri | kmac-streamed-setup:56 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-273bbf21bc6fa473 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:450 [extended] | passed | 2026-10-29T14:02:41Z |
| miri-27457000f2fb9bbc | sha1 | miri | sha1-bulk:150 [extended] | reused | 2026-10-28T12:52:28Z |
| miri-2746aef83fcef3e4 | tuplehash | miri | scoped_tuplexof128_differential:3:width=4 [extended] | reused | 2026-10-29T01:17:27Z |
| miri-2755bf52f535dbfb | md5 | miri | md5-padding:127 [routine] | passed | 2026-10-19T11:13:51Z |
| miri-275d1d83167e15d5 | tuplehash | miri | -p brynja-hash-tuple --test api forgotten_or_manually_dropped_items_cannot_bypass_the_open_latch [remaining suite; inspect skips with show] | passed | 2026-10-29T10:48:47Z |
| miri-2760e6609e565684 | sha2 | miri | -p brynja-hash-sha2 --test sha256 downstream_style_real_content_uses_only_public_api [remaining suite; inspect skips with show] | passed | 2026-10-19T11:30:36Z |
| miri-2761a31859e69d7a | md5 | miri | md5-scoped:8 [extended] | reused | 2026-10-28T11:53:31Z |
| miri-27681b39ec77e2fb | tuplehash | miri | tuplehash-staging:304 [extended] | reused | 2026-10-28T15:47:52Z |
| miri-2769e0169479e9f3 | sha1 | miri | sha1-scoped:8 [extended] | reused | 2026-10-28T13:04:48Z |
| miri-276ce5e5470cf02d | md5 | miri | md5-scoped:173 [extended] | reused | 2026-10-28T11:59:15Z |
| miri-276f6f5a3b2b834c | hmac | miri | sha224 [existing-full] | No mapped observation | — |
| miri-279176f74073e02c | md5 | miri | md5-scoped:34 [extended] | reused | 2026-10-28T12:00:23Z |
| miri-27a664ccd27e1403 | tuplehash | miri | tuplehash-staging:452 [extended] | reused | 2026-10-28T16:35:35Z |
| miri-27b038ad830d8508 | md5 | miri | md5-padding:101 [extended] | reused | 2026-10-28T11:35:14Z |
| miri-27bec8b6d9090c34 | kmac | miri | kmac-streamed-setup:29 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-27cb064e239bee62 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:40:width=0 [extended] | reused | 2026-10-28T23:22:29Z |
| miri-27cef8aa66bb5532 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:1 [routine] | No mapped observation | — |
| miri-27e868ff5ef7f750 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:0 [extended] | passed | 2026-10-29T12:42:29Z |
| miri-27f8d7d6c242c34f | kmac | miri | kmac-scoped-lifecycle:6 [routine] | passed | 2026-10-19T11:41:23Z |
| miri-2802d28ca47a96df | sha1 | miri | sha1-scoped:70 [extended] | reused | 2026-10-28T13:07:48Z |
| miri-28146d5f0b58a614 | md5 | miri | md5-batch-mask:26 [extended] | reused | 2026-10-28T12:20:10Z |
| miri-28224899a2440109 | tuplehash | miri | tuplehash-staging:83 [extended] | reused | 2026-10-28T20:42:23Z |
| miri-282b1f6d0ad64173 | tuplehash | miri | tuplehash-staging:421 [extended] | reused | 2026-10-28T16:41:33Z |
| miri-2867b61fd88c6cd9 | tuplehash | miri | scoped_tuplexof256_differential:4:width=2 [extended] | reused | 2026-10-29T02:24:45Z |
| miri-288b7904eb7047d3 | md5 | miri | md5-padding:48 [extended] | reused | 2026-10-28T11:21:37Z |
| miri-2895f9f90cbb8b08 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:45 [routine] | passed | 2026-10-19T16:10:55Z |
| miri-289f17eb625057ad | tuplehash | miri | tuplehash-staging:878 [extended] | reused | 2026-10-28T18:55:24Z |
| miri-28afe827791e20f8 | md5 | miri | md5-scoped:218 [extended] | reused | 2026-10-28T12:13:16Z |
| miri-28ba6112ee2108d3 | tuplehash | miri | scoped_tuplexof256_differential:44:width=2 [extended] | reused | 2026-10-29T03:59:50Z |
| miri-28bb50cddac9d2e1 | kmac | miri | kmac-streamed-setup:40 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-28cdef07e6c5c57d | tuplehash | miri | tuplehash-staging:827 [extended] | reused | 2026-10-29T00:52:00Z |
| miri-28d0d408d4dddf7d | md5 | miri | md5-padding:12 [extended] | reused | 2026-10-28T11:18:55Z |
| miri-28e684a601bfd207 | sha1 | miri | sha1-bulk:237 [extended] | reused | 2026-10-28T13:13:02Z |
| miri-28eaf76d07e7e363 | sha3 | miri | -p brynja-hash-sha3 --features static-execution --test execution execution_smoke [remaining suite; inspect skips with show] | passed | 2026-10-19T11:36:21Z |
| miri-28f6e20aa551dc18 | tuplehash | miri | tuplehash-staging:279 [extended] | reused | 2026-10-28T21:48:30Z |
| miri-28f9b597b3a2e3c9 | kmac | miri | kmac-streamed-setup:46 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-2901bcdb22940d21 | tuplehash | miri | scoped_tuplexof256_differential:27:width=3 [extended] | reused | 2026-10-29T03:59:46Z |
| miri-29172f19789d865f | md5 | miri | md5-scoped:130 [extended] | reused | 2026-10-28T12:06:58Z |
| miri-2921ad95d5867237 | md5 | miri | md5-batch-mask:125 [extended] | reused | 2026-10-28T12:17:09Z |
| miri-2922176c13342360 | tuplehash | miri | tuplehash-staging:329 [extended] | reused | 2026-10-28T16:10:59Z |
| miri-2929eb0100c30753 | sha2 | miri | -p brynja-hash-sha2 --features hardened-execution,general-sha512-t --lib hardened_execution::tests::output_owner_clears_during_recoverable_unwind [remaining suite; inspect skips with show] | passed | 2026-10-19T11:32:28Z |
| miri-297667eca47cdfd2 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:9 [routine] | No mapped observation | — |
| miri-29b7ed135187e223 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:15:width=2 [extended] | reused | 2026-10-28T22:53:23Z |
| miri-29b8d6c607465252 | sha1 | miri | sha1-padding:117 [extended] | reused | 2026-10-28T12:38:02Z |
| miri-29c2aae62d8e0df2 | md5 | miri | md5-bulk:162 [extended] | reused | 2026-10-28T11:44:29Z |
| miri-29c808e224b71231 | sha3 | miri | -p brynja-hash-sha3 --test bit_inputs curated_nist_cavp_vectors_cover_every_function_and_bit_residue [remaining suite; inspect skips with show] | passed | 2026-10-19T11:32:21Z |
| miri-29cc9ed6d10ea8d8 | sha3 | miri | sha3-fixed-boundaries:26 [routine] | passed | 2026-10-19T11:36:48Z |
| miri-29cd841b19606ad2 | tuplehash | miri | scoped_tuplexof128_differential:21:width=2 [extended] | passed | 2026-10-29T10:58:45Z |
| miri-29d3632d26365694 | md5 | miri | md5-bulk:1 [extended] | reused | 2026-10-28T11:27:48Z |
| miri-29e71020ab5a1f5a | md5 | miri | md5-bulk:53 [extended] | reused | 2026-10-28T11:31:12Z |
| miri-2a16ab61fa1a35cb | sha1 | miri | sha1-bulk:75 [extended] | reused | 2026-10-28T12:51:12Z |
| miri-2a208f564545ff02 | sha1 | miri | sha1-scoped:61 [extended] | reused | 2026-10-28T13:14:53Z |
| miri-2a26f97c2ed64889 | tuplehash | miri | tuplehash-staging:582 [extended] | reused | 2026-10-28T17:19:55Z |
| miri-2a3616437e3b5e21 | sha1 | miri | sha1-scoped:133 [extended] | reused | 2026-10-28T13:20:26Z |
| miri-2a5e887f8bd199f9 | kmac | miri | kmac-scoped-xof-lifecycle:3 [extended] | reused | 2026-10-28T19:55:07Z |
| miri-2a5ed2cc679e1cc9 | md5 | miri | md5-bulk:41 [extended] | reused | 2026-10-28T11:30:25Z |
| miri-2a63b92b3cceeadf | tuplehash | miri | scoped_tuplexof128_differential:32:width=2 [extended] | reused | 2026-10-29T01:36:57Z |
| miri-2a663f7f27947525 | tuplehash | miri | scoped_tuplexof128_differential:33:width=4 [extended] | passed | 2026-10-29T11:53:11Z |
| miri-2a70dd35ae9ceceb | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:42 [extended] | passed | 2026-10-29T14:59:40Z |
| miri-2a72f06a2b341ffb | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:30:width=2 [extended] | reused | 2026-10-28T22:52:04Z |
| miri-2a7b478f64c39c9b | tuplehash | miri | tuplehash-staging:857 [extended] | reused | 2026-10-28T19:08:38Z |
| miri-2a88c2a7b05579bc | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:40:width=1 [extended] | reused | 2026-10-28T20:53:24Z |
| miri-2a8e4dc9dec66304 | md5 | miri | md5-batch-mask:239 [extended] | reused | 2026-10-28T12:26:21Z |
| miri-2a9cba42fe826ad0 | sha3 | miri | sha3-fixed-boundaries:53 [extended] | reused | 2026-10-28T13:38:33Z |
| miri-2a9e354fe15fe339 | tuplehash | miri | scoped_tuplexof256_differential:7:width=4 [extended] | reused | 2026-10-29T03:16:31Z |
| miri-2aa0b8c6c6f7c20d | md5 | miri | md5-bulk:105 [extended] | reused | 2026-10-28T11:34:54Z |
| miri-2abfd641d1b76ebf | tuplehash | miri | tuplehash-staging:892 [extended] | reused | 2026-10-28T18:56:30Z |
| miri-2add9a2f6f218834 | sha3 | miri | -p brynja-hash-sha3 --lib borrowing_reader_never_extracts_the_absorbing_owner [remaining suite; inspect skips with show] | passed | 2026-10-19T11:35:54Z |
| miri-2b168543e0069e20 | sha1 | miri | sha1-scoped:138 [extended] | reused | 2026-10-28T13:13:05Z |
| miri-2b2d83d458a8f8a5 | sha1 | miri | sha1-scoped:41 [extended] | reused | 2026-10-28T13:13:30Z |
| miri-2b42022c93682cd2 | md5 | miri | md5-batch-mask:81 [extended] | reused | 2026-10-28T12:13:36Z |
| miri-2b434d5cc9656d10 | md5 | miri | md5-bulk:211 [extended] | reused | 2026-10-28T11:43:33Z |
| miri-2b44abcb566e2cb6 | tuplehash | miri | tuplehash-staging:559 [extended] | reused | 2026-10-28T23:22:27Z |
| miri-2b51b299b41fea57 | tuplehash | miri | tuplehash-staging:548 [extended] | reused | 2026-10-28T17:05:57Z |
| miri-2b6458d3b60e9e2e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:3:width=0 [extended] | reused | 2026-10-28T19:52:05Z |
| miri-2baf93d216effa0b | tuplehash | miri | tuplehash-staging:504 [extended] | reused | 2026-10-28T16:51:48Z |
| miri-2bb67853071e17fd | md5 | miri | md5-bulk:63 [extended] | reused | 2026-10-28T11:32:12Z |
| miri-2bbdb94402634946 | tuplehash | miri | scoped_tuplexof256_differential:14:width=1 [extended] | reused | 2026-10-29T02:37:48Z |
| miri-2be6827df004f5e8 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:15 [extended] | passed | 2026-10-29T14:09:57Z |
| miri-2be73824c1daa05a | sha1 | miri | -p brynja-legacy-sha1 --features cpu --test cpu [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-2c1135e922923466 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:27 [extended] | passed | 2026-10-29T13:49:05Z |
| miri-2c1fbb242e1c4b35 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:29:width=2 [extended] | reused | 2026-10-29T02:43:39Z |
| miri-2c200d8de40bb6bf | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:48:width=2 [extended] | reused | 2026-10-28T21:27:32Z |
| miri-2c3202ff2254ac0d | tuplehash | miri | tuplehash-staging:397 [extended] | reused | 2026-10-28T16:33:52Z |
| miri-2c32d62e86207f37 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:46 [extended] | passed | 2026-10-29T13:37:34Z |
| miri-2c518bee3c2871a7 | parallelhash | miri | hardened_output_and_workspace_clear_on_drop [extended] | passed | 2026-10-29T15:15:51Z |
| miri-2c791a40c069f9c3 | md5 | miri | md5-scoped:61 [extended] | reused | 2026-10-28T11:51:37Z |
| miri-2c7fcb8a6668f7ad | md5 | miri | md5-bulk:223 [extended] | reused | 2026-10-28T11:44:36Z |
| miri-2c85ce32c73ca756 | tuplehash | miri | scoped_tuplexof128_differential:27:width=0 [extended] | reused | 2026-10-29T02:07:59Z |
| miri-2c8ba8f5234912cf | tuplehash | miri | tuplehash-staging:702 [extended] | reused | 2026-10-28T17:58:42Z |
| miri-2c90c3ed73942de3 | sha1 | miri | sha1-bulk:178 [extended] | reused | 2026-10-28T12:55:19Z |
| miri-2c99e5ad6548eda7 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:9 [routine] | No mapped observation | — |
| miri-2ca78bf180a2577f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:42:width=2 [extended] | reused | 2026-10-28T23:21:51Z |
| miri-2cb4560c9bc06fdb | tuplehash | miri | scoped_tuplexof128_differential:17:width=2 [extended] | passed | 2026-10-29T10:55:22Z |
| miri-2cc985acf15aa1fd | tuplehash | miri | scoped_tuplexof256_differential:18:width=4 [extended] | reused | 2026-10-29T02:47:19Z |
| miri-2d18876aa20bb8a2 | sha3 | miri | -p brynja-hash-sha3 --test sha3_384 suffix_and_rate_boundaries_have_exact_digests [remaining suite; inspect skips with show] | passed | 2026-10-19T11:31:06Z |
| miri-2d392d121eaa9844 | tuplehash | miri | tuplehash-staging:307 [extended] | reused | 2026-10-28T21:57:56Z |
| miri-2d5323b6b4c44724 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:20:width=3 [extended] | reused | 2026-10-28T22:34:16Z |
| miri-2d5545f9c8b387df | md5 | miri | md5-batch-mask:239 [routine] | passed | 2026-10-19T11:30:13Z |
| miri-2d564456bd612891 | md5 | miri | md5-bulk:27 [extended] | reused | 2026-10-28T11:29:50Z |
| miri-2d5f7bf2da1523e6 | tuplehash | miri | tuplehash-staging:211 [extended] | reused | 2026-10-28T21:24:44Z |
| miri-2d621f364ac3a9d0 | sha1 | miri | sha1-bulk:189 [extended] | reused | 2026-10-28T13:06:57Z |
| miri-2d6a31de03818d1a | tuplehash | miri | tuplehash-staging:895 [extended] | reused | 2026-10-29T01:15:42Z |
| miri-2d78ef7a3db0dbba | tuplehash | miri | scoped_tuplexof256_differential:36:width=0 [extended] | reused | 2026-10-29T03:35:29Z |
| miri-2d8961436c7acfe0 | tuplehash | miri | tuplehash-staging:546 [extended] | reused | 2026-10-28T17:08:44Z |
| miri-2d8bc6524e36cb95 | tuplehash | miri | tuplehash-staging:9 [extended] | reused | 2026-10-28T14:24:10Z |
| miri-2d9ef96ac15b7473 | tuplehash | miri | scoped_tuplexof128_differential:44:width=2 [extended] | reused | 2026-10-29T02:11:09Z |
| miri-2da00a98c779737e | md5 | miri | md5-bulk:170 [extended] | reused | 2026-10-28T11:45:09Z |
| miri-2dcbae71a01b16df | md5 | miri | md5-scoped:48 [extended] | reused | 2026-10-28T11:56:11Z |
| miri-2dcd9092dd7b33cb | sha1 | miri | sha1-padding:95 [extended] | reused | 2026-10-28T12:37:29Z |
| miri-2de582506a79aa79 | md5 | miri | md5-scoped:126 [extended] | reused | 2026-10-28T12:06:41Z |
| miri-2ded40b4814da177 | md5 | miri | md5-batch-mask:118 [extended] | reused | 2026-10-28T12:27:16Z |
| miri-2df4c921ede96485 | tuplehash | miri | tuplehash-staging:554 [extended] | reused | 2026-10-28T17:10:56Z |
| miri-2e0b42eafbe0ff1b | sha2 | miri | -p brynja-hash-sha2 --features hardened-execution,general-sha512-t --lib hardened_execution::engine::tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-2e0bece879f8564e | tuplehash | miri | tuplehash-execution-fixed:4 [extended] | reused | 2026-10-28T19:06:07Z |
| miri-2e0e848c903114a9 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:53:width=1 [extended] | reused | 2026-10-29T07:01:39Z |
| miri-2e158ba344d7d3b9 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:47:width=0 [extended] | reused | 2026-10-29T00:17:25Z |
| miri-2e1cd4efafd16254 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:4 [extended] | passed | 2026-10-29T13:32:29Z |
| miri-2e239d78f8f61c3e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:26:width=2 [extended] | reused | 2026-10-28T22:42:58Z |
| miri-2e2c5fbdad99804c | kmac | miri | kmac-streamed-setup:38 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-2e361468fbc86744 | sha1 | miri | sha1-scoped:227 [extended] | reused | 2026-10-28T13:33:05Z |
| miri-2e4889ed312721e5 | sha1 | miri | sha1-scoped:202 [extended] | reused | 2026-10-28T13:18:16Z |
| miri-2e4c0d8b78f92ea0 | md5 | miri | md5-scoped:168 [extended] | reused | 2026-10-28T12:04:25Z |
| miri-2e6b59a472569517 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:47:width=3 [extended] | reused | 2026-10-29T00:17:25Z |
| miri-2e8b6910087b32d2 | tuplehash | miri | tuplehash-staging:479 [extended] | reused | 2026-10-28T22:55:38Z |
| miri-2e8cbfe9d444a3b7 | kmac | miri | kmac-streamed-setup:45 [routine] | No mapped observation | — |
| miri-2ebbba953b918af1 | md5 | miri | md5-batch-mask:98 [extended] | reused | 2026-10-28T12:25:41Z |
| miri-2ed4ff2af4c9f9f6 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:13:width=3 [extended] | reused | 2026-10-29T04:44:00Z |
| miri-2edc080f2bf60b04 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:13:width=0 [extended] | reused | 2026-10-29T02:04:31Z |
| miri-2edf477aa5da1339 | sha1 | miri | sha1-scoped:123 [extended] | reused | 2026-10-28T13:24:48Z |
| miri-2ef275b58ce9fbc4 | tuplehash | miri | tuplehash-staging:879 [extended] | reused | 2026-10-29T01:09:54Z |
| miri-2f02100334cd37ac | tuplehash | miri | tuplehash-staging:658 [extended] | reused | 2026-10-28T17:44:38Z |
| miri-2f06494678c9c28c | sha1 | miri | sha1-scoped:167 [extended] | reused | 2026-10-28T13:28:10Z |
| miri-2f27dfcac7ffe957 | kmac | miri | kmac-streamed-setup:94 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-2f2c7e878bdf8728 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:507 [extended] | passed | 2026-10-29T13:47:42Z |
| miri-2f328ff3055219cd | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:9 [extended] | passed | 2026-10-29T13:16:33Z |
| miri-2f38ca60df909714 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:0:width=0 [extended] | reused | 2026-10-28T21:56:20Z |
| miri-2f45cc0abbbd07d8 | md5 | miri | md5-padding:61 [extended] | reused | 2026-10-28T11:32:01Z |
| miri-2f5fdf16f074b79c | md5 | miri | md5-batch-mask:9 [extended] | reused | 2026-10-28T12:08:11Z |
| miri-2f60bcfb39b43a22 | tuplehash | miri | tuplehash-staging:344 [extended] | reused | 2026-10-28T16:00:12Z |
| miri-2f6228f721814d96 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:22:width=2 [extended] | reused | 2026-10-28T20:04:30Z |
| miri-2f65081e7f6d0fda | md5 | miri | md5-bulk:22 [extended] | reused | 2026-10-28T11:33:50Z |
| miri-2f694af321dc1d99 | sha1 | miri | sha1-scoped:128 [extended] | reused | 2026-10-28T13:13:49Z |
| miri-2f759bc8ab5c14f7 | sha1 | miri | sha1-bulk:240 [extended] | reused | 2026-10-28T13:00:50Z |
| miri-2f7f54465cc04bfe | md5 | miri | md5-bulk:90 [extended] | reused | 2026-10-28T11:38:38Z |
| miri-2f90071360714d86 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:9 [routine] | passed | 2026-10-19T16:09:06Z |
| miri-2f9098a1540d4c55 | tuplehash | miri | tuplehash-staging:139 [extended] | reused | 2026-10-28T21:01:15Z |
| miri-2f9242616fb541ac | sha1 | miri | sha1-scoped:208 [extended] | reused | 2026-10-28T13:20:15Z |
| miri-2f9c233be4f51098 | md5 | miri | md5-bulk:193 [routine] | passed | 2026-10-19T11:32:39Z |
| miri-2fd79dcc781050b5 | tuplehash | miri | tuplehash-staging:832 [routine] | passed | 2026-10-19T11:49:25Z |
| miri-2fdf3170b558ea62 | kmac | miri | kmac-streamed-setup:1 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-2fea437e9ef56531 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:39:width=0 [extended] | reused | 2026-10-28T21:12:11Z |
| miri-2ff36a6b69ee90e6 | md5 | miri | md5-scoped:98 [extended] | reused | 2026-10-28T12:04:45Z |
| miri-300fd4ea54fecd0e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:34:width=0 [extended] | reused | 2026-10-28T20:32:01Z |
| miri-302fda71a0bdce82 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-official:3 [routine] | No mapped observation | — |
| miri-30485c0691c44f55 | tuplehash | miri | scoped_tuplexof128_differential:12:width=0 [extended] | reused | 2026-10-29T00:49:44Z |
| miri-3058f7fd16042413 | sha3 | miri | sha3-fixed-bits:6 [routine] | passed | 2026-10-19T11:38:37Z |
| miri-3062c0f6d73e2cc5 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:46:width=3 [extended] | reused | 2026-10-28T21:04:48Z |
| miri-306bd4ed90510243 | sha2 | miri | -p brynja-hash-sha2 --test sha512_224 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-3087cdf20660f9f7 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:6:width=0 [extended] | reused | 2026-10-28T19:32:57Z |
| miri-309441ba57a461cf | sha1 | miri | sha1-bulk:216 [extended] | reused | 2026-10-28T12:58:05Z |
| miri-309cc6908c892566 | tuplehash | miri | scoped_tuplexof128_differential:11:width=4 [extended] | reused | 2026-10-29T01:31:31Z |
| miri-30a730cab9e44198 | sha1 | miri | sha1-padding:13 [extended] | reused | 2026-10-28T12:29:09Z |
| miri-30b12fb42a5af7e2 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:36:width=2 [extended] | reused | 2026-10-28T20:41:38Z |
| miri-30b9c8a4f45a2693 | md5 | miri | md5-batch-mask:72 [extended] | reused | 2026-10-28T12:18:19Z |
| miri-30c3d097aea88767 | tuplehash | miri | scoped_tuplexof256_differential:18 [routine] | passed | 2026-10-19T12:24:29Z |
| miri-30c7b08a69c3b2a3 | sha3 | miri | sha3-fixed-boundaries:4 [extended] | reused | 2026-10-28T13:45:15Z |
| miri-30d33b4b5cff91b4 | md5 | miri | md5-scoped:156 [extended] | reused | 2026-10-28T12:03:36Z |
| miri-3127960943713ab6 | md5 | miri | md5-padding:80 [extended] | reused | 2026-10-28T11:24:11Z |
| miri-3132f407223ab243 | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib only_pre_entry_thread_errors_are_reusable [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-313613d355e40ead | tuplehash | miri | scoped_tuplexof128_differential:26:width=2 [extended] | reused | 2026-10-29T01:16:55Z |
| miri-31385b67eaca5281 | tuplehash | miri | tuplehash-staging:740 [extended] | reused | 2026-10-28T18:07:29Z |
| miri-317d9621eb127709 | md5 | miri | md5-scoped:17 [extended] | reused | 2026-10-28T11:48:43Z |
| miri-3192cf49cf653d29 | tuplehash | miri | tuplehash-staging:141 [extended] | reused | 2026-10-28T15:07:33Z |
| miri-31b18c6f43bd888a | sha1 | miri | sha1-scoped:218 [extended] | reused | 2026-10-28T13:19:34Z |
| miri-31c100398a628b55 | sha1 | miri | sha1-bulk:249 [extended] | reused | 2026-10-28T13:14:35Z |
| miri-31c54885014e0d77 | md5 | miri | md5-padding:39 [extended] | reused | 2026-10-28T11:25:59Z |
| miri-31cd82e23f485a9b | tuplehash | miri | tuplehash-staging:206 [extended] | reused | 2026-10-28T15:19:24Z |
| miri-31d5618c932cad03 | kmac | miri | kmac-streamed-setup:13 [routine] | No mapped observation | — |
| miri-31d864c43f4e65e5 | sha2 | miri | -p brynja-hash-sha2 --features general-sha512-t --test general_hash unwind_clears_secret_destination [remaining suite; inspect skips with show] | reused | 2026-10-28T13:32:12Z |
| miri-31de29f61ff9e11c | sha1 | miri | sha1-bulk:80 [extended] | reused | 2026-10-28T12:44:36Z |
| miri-31e2d023c03153cb | tuplehash | miri | tuplehash-execution-fixed:10 [routine] | passed | 2026-10-19T12:01:46Z |
| miri-31e600f92afee9dc | sha3 | miri | -p brynja-hash-sha3 --test shake128 suffix_and_rate_boundaries_have_exact_output [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-31f39be381803621 | tuplehash | miri | tuplehash-staging:527 [extended] | reused | 2026-10-28T23:11:11Z |
| miri-3200a1b4897c9e23 | sha1 | miri | sha1-scoped:6 [extended] | reused | 2026-10-28T13:03:17Z |
| miri-3205b3447b76f172 | tuplehash | miri | scoped_tuplexof256_differential:29:width=3 [extended] | passed | 2026-10-29T12:07:45Z |
| miri-3216f11bac9fc3a3 | tuplehash | miri | tuplehash-staging:328 [extended] | reused | 2026-10-28T15:55:45Z |
| miri-3226914866c07600 | kmac | miri | kmac-scoped-xof-lifecycle:2 [routine] | passed | 2026-10-19T11:37:03Z |
| miri-322b877d7774a64e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:19:width=0 [extended] | reused | 2026-10-28T23:03:10Z |
| miri-3242bbb2d1bc0ae8 | tuplehash | miri | scoped_tuplexof128_differential:45:width=4 [extended] | passed | 2026-10-29T12:05:01Z |
| miri-32524f4bc1a1de74 | tuplehash | miri | scoped_tuplexof128_differential:14:width=0 [extended] | reused | 2026-10-29T00:48:52Z |
| miri-3252c43883d58b75 | sha1 | miri | sha1-bulk:205 [extended] | reused | 2026-10-28T13:08:56Z |
| miri-32594eb4b0a1566f | hmac | miri | sha3_384 [extended] | passed | 2026-10-29T15:22:03Z |
| miri-325ee93315ae808f | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:21:width=2 [extended] | reused | 2026-10-29T02:24:05Z |
| miri-32620300f6ec799b | md5 | miri | md5-scoped:89 [extended] | reused | 2026-10-28T11:53:31Z |
| miri-3262b149e63d80ff | tuplehash | miri | tuplehash-staging:84 [extended] | reused | 2026-10-28T14:35:48Z |
| miri-3268519e9e4a648d | tuplehash | miri | tuplehash-staging:222 [extended] | reused | 2026-10-28T15:24:12Z |
| miri-326af1b329500cb0 | md5 | miri | md5-scoped:149 [extended] | reused | 2026-10-28T11:57:37Z |
| miri-3284c208d677d520 | tuplehash | miri | scoped_tuplexof256_differential:15:width=4 [extended] | reused | 2026-10-29T03:30:33Z |
| miri-32937a710780f741 | md5 | miri | md5-padding:26 [extended] | reused | 2026-10-28T11:19:44Z |
| miri-32c600656a0a5394 | tuplehash | miri | scoped_tuplexof128_differential:22:width=1 [extended] | reused | 2026-10-29T01:07:25Z |
| miri-32ca81caa59aa64d | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:25:width=3 [extended] | reused | 2026-10-29T05:13:15Z |
| miri-32cb44adbc850364 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-faults:2 [routine] | No mapped observation | — |
| miri-32e7a293e3b62294 | tuplehash | miri | scoped_tuplexof256_differential:21:width=1 [extended] | passed | 2026-10-29T12:02:15Z |
| miri-330c0fc95de7af4e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:51:width=2 [extended] | reused | 2026-10-28T22:01:22Z |
| miri-3314de23a4fc87c9 | tuplehash | miri | tuplehash-staging:294 [extended] | reused | 2026-10-28T15:47:36Z |
| miri-331f60a137776510 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:6 [routine] | No mapped observation | — |
| miri-334139b8499e5a4c | sha1 | miri | sha1-scoped:233 [extended] | reused | 2026-10-28T13:28:20Z |
| miri-334b56ceacd8b26f | md5 | miri | md5-bulk:88 [extended] | reused | 2026-10-28T11:43:30Z |
| miri-3370bd750bc19ced | sha3 | miri | sha3-fixed-bits:3 [routine] | passed | 2026-10-19T11:28:54Z |
| miri-33726c16793b6be6 | md5 | miri | md5-padding:82 [extended] | reused | 2026-10-28T11:24:06Z |
| miri-338d91a892589977 | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join256:3 [routine] | No mapped observation | — |
| miri-3390167f4b920f0e | md5 | miri | md5-bulk:77 [extended] | reused | 2026-10-28T11:32:53Z |
| miri-33a0936a7ebcc073 | tuplehash | miri | tuplehash-staging:36 [extended] | reused | 2026-10-28T14:19:50Z |
| miri-33b595d18e036c24 | md5 | miri | md5-batch-mask:100 [extended] | reused | 2026-10-28T12:20:26Z |
| miri-33bb2dec992f9157 | md5 | miri | md5-bulk:61 [extended] | reused | 2026-10-28T11:31:44Z |
| miri-33d4daf52d2bdfdb | sha1 | miri | sha1-padding:124 [extended] | reused | 2026-10-28T12:45:39Z |
| miri-33d6d5834d9cb6d4 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:53:width=4 [extended] | reused | 2026-10-29T04:16:00Z |
| miri-33d77138588b5311 | md5 | miri | md5-scoped:105 [extended] | reused | 2026-10-28T11:54:38Z |
| miri-33e7fe3a2146d403 | sha1 | miri | sha1-bulk:188 [extended] | reused | 2026-10-28T12:54:46Z |
| miri-33f21203b39bdb0d | kmac | miri | kmac-streamed-setup:50 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-33f2688ecf9fa78b | tuplehash | miri | tuplehash-staging:260 [extended] | reused | 2026-10-28T15:32:49Z |
| miri-34016d3ee9a3b377 | tuplehash | miri | tuplehash-staging:669 [extended] | reused | 2026-10-28T18:04:55Z |
| miri-3403978f2a78a50e | tuplehash | miri | scoped_tuplexof256_differential:33:width=4 [extended] | passed | 2026-10-29T12:43:19Z |
| miri-3412ab575ab662ae | md5 | miri | md5-padding:100 [extended] | reused | 2026-10-28T11:25:45Z |
| miri-342af35db34820d6 | tuplehash | miri | scoped_tuplexof256_differential:26:width=4 [extended] | reused | 2026-10-29T03:06:14Z |
| miri-34315b941b85b071 | tuplehash | miri | scoped_tuplexof256_differential:29:width=2 [extended] | passed | 2026-10-29T12:38:28Z |
| miri-344645bfaef8be8d | md5 | miri | md5-batch-mask:16 [extended] | reused | 2026-10-28T12:14:08Z |
| miri-3450418463e693a4 | md5 | miri | md5-scoped:174 [extended] | reused | 2026-10-28T12:10:04Z |
| miri-3489d2d9f6e7da4a | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:5 [extended] | passed | 2026-10-29T13:21:06Z |
| miri-348a770ca3e511bf | md5 | miri | md5-scoped:6 [extended] | reused | 2026-10-28T11:58:28Z |
| miri-348baaf31a762d47 | tuplehash | miri | tuplehash-execution-fixed:13 [extended] | reused | 2026-10-28T19:41:40Z |
| miri-348cb141e77c45ba | sha1 | miri | sha1-bulk:132 [extended] | reused | 2026-10-28T12:49:11Z |
| miri-3497f84daa49d91a | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:6 [extended] | passed | 2026-10-29T14:57:35Z |
| miri-349939d9cd9bfcbc | md5 | miri | md5-scoped:55 [extended] | reused | 2026-10-28T11:50:58Z |
| miri-34acb5d5949ed803 | tuplehash | miri | tuplehash-staging:480 [extended] | reused | 2026-10-28T16:44:19Z |
| miri-34b027791de85067 | kmac | miri | kmac-streamed-setup:68 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-34c591e4f4736058 | md5 | miri | md5-bulk:180 [extended] | reused | 2026-10-28T11:50:49Z |
| miri-34cfb82d31c826f1 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:17:width=3 [extended] | reused | 2026-10-29T02:14:18Z |
| miri-34ec512e306d7aab | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib missing_native [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-3505ff29a43d2afc | tuplehash | miri | tuplehash-staging:705 [extended] | reused | 2026-10-28T18:17:03Z |
| miri-35073f755e40e4e9 | sha1 | miri | sha1-scoped:208 [routine] | passed | 2026-10-19T11:29:53Z |
| miri-3512b827e41977a3 | md5 | miri | md5-padding:72 [extended] | reused | 2026-10-28T11:23:33Z |
| miri-3517a11f0dbf9789 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:45 [routine] | No mapped observation | — |
| miri-351d08d19662c972 | sha1 | miri | sha1-scoped:77 [extended] | reused | 2026-10-28T13:16:03Z |
| miri-351f59aa120990c5 | tuplehash | miri | tuplehash-execution-fixed:2 [routine] | passed | 2026-10-19T11:53:25Z |
| miri-352a88e5a188b020 | tuplehash | miri | tuplehash-staging:451 [extended] | reused | 2026-10-28T22:46:28Z |
| miri-353fe99ca74333cd | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:55:width=3 [extended] | reused | 2026-10-29T01:10:24Z |
| miri-3541e6edc10e6ef3 | acceleration | miri | --manifest-path assurance/acceleration-contract/Cargo.toml --lib [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-3547619e3cb2f1c5 | tuplehash | miri | scoped_tuplexof128_differential:15:width=2 [extended] | reused | 2026-10-29T01:38:34Z |
| miri-3549e3f745caf302 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:0 [extended] | passed | 2026-10-29T12:52:30Z |
| miri-354be6fac10f8d8a | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib batch_metadata_and_public_admission [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-3583b95bf406958a | md5 | miri | md5-batch-mask:248 [extended] | reused | 2026-10-28T12:32:23Z |
| miri-359c7812f5bf3270 | tuplehash | miri | tuplehash-execution-fixed:12 [extended] | reused | 2026-10-28T19:16:34Z |
| miri-359d047f66623bb8 | md5 | miri | md5-batch-mask:106 [extended] | reused | 2026-10-28T12:26:18Z |
| miri-35ab092379c6e3a7 | tuplehash | miri | tuplehash-staging:544 [extended] | reused | 2026-10-28T17:04:40Z |
| miri-35c6817d399c9716 | tuplehash | miri | tuplehash-staging:380 [extended] | reused | 2026-10-28T16:12:15Z |
| miri-35d49c2e1caa524e | kmac | miri | kmac-streamed-setup:50 [routine] | No mapped observation | — |
| miri-35de3880b3b8d3d1 | parallelhash | miri | [bounded-parallelhash-v1] parallelhashxof-official:3 [routine] | No mapped observation | — |
| miri-35e8316f8bc3c979 | md5 | miri | md5-scoped:217 [extended] | reused | 2026-10-28T12:02:26Z |
| miri-35f2048902240c2b | sha3 | miri | sha3-fixed-bits:19 [routine] | passed | 2026-10-19T11:29:42Z |
| miri-35fe110ec556974c | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:55:width=2 [extended] | reused | 2026-10-28T22:25:13Z |
| miri-360f655de6d9e755 | md5 | miri | md5-padding:55 [extended] | reused | 2026-10-28T11:26:56Z |
| miri-3613b0a498220586 | kmac | miri | kmac-streamed-setup:28 [routine] | No mapped observation | — |
| miri-361879714863b844 | md5 | miri | md5-bulk:102 [extended] | reused | 2026-10-28T11:39:33Z |
| miri-36314c90c14ddac3 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:621 [extended] | passed | 2026-10-29T13:50:38Z |
| miri-363aa7bbd56835bc | tuplehash | miri | tuplehash-staging:486 [extended] | reused | 2026-10-28T16:49:56Z |
| miri-363ac20f1101a1a0 | tuplehash | miri | tuplehash-staging:765 [extended] | reused | 2026-10-28T18:37:16Z |
| miri-364c5c9455304084 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:5 [routine] | No mapped observation | — |
| miri-364eb4f54325a6c8 | kmac | miri | kmac-official:4 [extended] | reused | 2026-10-28T14:01:51Z |
| miri-3655c823cad1165d | tuplehash | miri | tuplehash-execution-fixed:1 [extended] | reused | 2026-10-28T19:25:26Z |
| miri-3660eced8744e358 | tuplehash | miri | tuplehash-staging:309 [extended] | reused | 2026-10-28T16:03:51Z |
| miri-367f29c451bc1a0a | sha1 | miri | sha1-bulk:55 [routine] | passed | 2026-10-19T11:29:03Z |
| miri-368a8a6a6b96d944 | sha1 | miri | -p brynja-legacy-sha1 --features cpu --test cpu [remaining suite; inspect skips with show] | reused | 2026-10-28T12:39:06Z |
| miri-36b4e8f5f28c0f0e | legacy_hmac | miri | sha1_long [extended] | passed | 2026-10-29T16:05:15Z |
| miri-36bd253c575ee3ab | sha1 | miri | sha1-scoped:174 [extended] | reused | 2026-10-28T13:16:00Z |
| miri-36cf1ac40a33f66b | sha1 | miri | sha1-bulk:234 [extended] | reused | 2026-10-28T13:01:33Z |
| miri-36e2eed271da5bea | md5 | miri | md5-batch-mask:114 [extended] | reused | 2026-10-28T12:26:57Z |
| miri-36e65168133e92c7 | md5 | miri | md5-scoped:23 [extended] | reused | 2026-10-28T11:48:52Z |
| miri-36f46a6cc4a9a073 | tuplehash | miri | tuplehash-staging:596 [extended] | reused | 2026-10-28T17:21:00Z |
| miri-36f7d04103d33d13 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:16:width=0 [extended] | reused | 2026-10-28T19:55:42Z |
| miri-371800aa22de1525 | tuplehash | miri | tuplehash-staging:494 [extended] | reused | 2026-10-28T16:52:08Z |
| miri-371bf3d534ab3a17 | tuplehash | miri | tuplehash-staging:192 [extended] | reused | 2026-10-28T15:11:33Z |
| miri-3725a6123c492555 | tuplehash | miri | tuplehash-staging:476 [extended] | reused | 2026-10-28T16:43:04Z |
| miri-372ec33f13b25063 | md5 | miri | md5-bulk:65 [extended] | reused | 2026-10-28T11:32:01Z |
| miri-373599e19a699b08 | md5 | miri | md5-batch-mask:1 [routine] | passed | 2026-10-19T11:14:39Z |
| miri-373a10676d8b35ca | md5 | miri | md5-scoped:128 [extended] | reused | 2026-10-28T12:01:41Z |
| miri-373ca4189b91788f | tuplehash | miri | exact_length_streaming_matches_whole_items [routine] | passed | 2026-10-19T16:23:25Z |
| miri-3749004d4c2e44d5 | tuplehash | miri | tuplehash-staging:115 [extended] | reused | 2026-10-28T20:53:10Z |
| miri-3758aab60f8ddab4 | static_cpu | miri | -p brynja-crypto-cpu --features hardened-execution --lib hardened_execution [remaining suite; inspect skips with show] | passed | 2026-10-19T17:30:29Z |
| miri-37661c28d4c5e833 | sha2 | miri | -p brynja-hash-sha2 --test sha512 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | reused | 2026-10-28T13:42:36Z |
| miri-379db9b0cfc1ac41 | tuplehash | miri | scoped_tuplexof128_differential:42:width=2 [extended] | reused | 2026-10-29T01:58:04Z |
| miri-37b02258d08d5f21 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:26:width=0 [extended] | reused | 2026-10-28T20:13:39Z |
| miri-37b038d253dec4e0 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:36:width=2 [extended] | reused | 2026-10-28T23:10:45Z |
| miri-37b61905cd3182fc | tuplehash | miri | scoped_tuplexof256_differential:5:width=0 [extended] | passed | 2026-10-29T12:08:15Z |
| miri-37bddc209581c5b7 | sha3 | miri | both_xofs_match_across_irregular_absorb_and_squeeze_boundaries [extended] | reused | 2026-10-28T13:51:42Z |
| miri-37c30c31571dfe01 | tuplehash | miri | scoped_tuplexof128_differential:37:width=3 [extended] | passed | 2026-10-29T11:05:07Z |
| miri-37c41c039612bab6 | tuplehash | miri | tuplehash-staging:815 [extended] | reused | 2026-10-29T00:48:45Z |
| miri-37ce4d099c5f6766 | md5 | miri | -p brynja-legacy-md5 --features hardened-execution --lib cpu::secret::tests [remaining suite; inspect skips with show] | reused | 2026-10-28T11:17:26Z |
| miri-37d0f2dc1a9e16b9 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:39 [extended] | passed | 2026-10-29T14:13:49Z |
| miri-37d1b5b6656f330d | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:2 [routine] | No mapped observation | — |
| miri-37e66faa171f8931 | sha1 | miri | sha1-padding:7 [extended] | reused | 2026-10-28T12:30:09Z |
| miri-37e79d84f0b6f905 | tuplehash | miri | abandoned_or_incomplete_items_fail_closed [routine] | passed | 2026-10-19T12:29:50Z |
| miri-37ef976b912c1388 | tuplehash | miri | scoped_tuplexof256_differential:39:width=4 [extended] | reused | 2026-10-29T04:28:59Z |
| miri-37f265c2d43aa050 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:15:width=3 [extended] | reused | 2026-10-28T22:53:23Z |
| miri-3808115f9b724352 | tuplehash | miri | -p brynja-hash-tuple --tests [remaining suite; inspect skips with show] | passed | 2026-10-19T15:48:44Z |
| miri-380dc810b54c2987 | md5 | miri | md5-padding:56 [routine] | passed | 2026-10-19T11:13:37Z |
| miri-38245f4734b49373 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:33:width=4 [extended] | reused | 2026-10-29T05:32:49Z |
| miri-3830186804eb81be | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:13:width=1 [extended] | reused | 2026-10-29T02:04:31Z |
| miri-383597b0eb3da4b0 | md5 | miri | -p brynja-legacy-md5 --features cpu --test cpu [remaining suite; inspect skips with show] | passed | 2026-10-19T11:25:43Z |
| miri-3835c8e377bd1c21 | sha1 | miri | sha1-scoped:142 [extended] | reused | 2026-10-28T13:13:24Z |
| miri-3837ea3a82b18a7a | sha1 | miri | sha1-padding:73 [extended] | reused | 2026-10-28T12:34:02Z |
| miri-383bc9dfa8dacd1e | tuplehash | miri | tuplehash-staging:492 [extended] | reused | 2026-10-28T16:48:02Z |
| miri-38584703bbebce1b | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:44:width=0 [extended] | reused | 2026-10-28T21:05:12Z |
| miri-385c0c44d73fca47 | sha1 | miri | sha1-padding:37 [extended] | reused | 2026-10-28T12:30:58Z |
| miri-3867f558ddf9246e | md5 | miri | md5-bulk:17 [extended] | reused | 2026-10-28T11:28:50Z |
| miri-386e4b28baa5ded6 | tuplehash | miri | tuplehash-staging:3 [extended] | reused | 2026-10-28T20:15:53Z |
| miri-38706171d677f2a5 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:19:width=3 [extended] | reused | 2026-10-28T20:22:54Z |
| miri-38804860d8372979 | tuplehash | miri | tuplehash-staging:249 [extended] | reused | 2026-10-28T15:44:01Z |
| miri-388bfc1f56e0ed74 | tuplehash | miri | tuplehash-staging:42 [extended] | reused | 2026-10-28T14:25:25Z |
| miri-3897d1a497212357 | sha1 | miri | sha1-scoped:198 [extended] | reused | 2026-10-28T13:17:56Z |
| miri-389845ebe9fd75d7 | sha3 | miri | bit_input_and_bit_output_match_both_ordinary_xofs [extended] | reused | 2026-10-28T14:00:00Z |
| miri-389e23d622343b80 | md5 | miri | md5-bulk:106 [extended] | reused | 2026-10-28T11:39:52Z |
| miri-38a04c2800cd18e4 | sha1 | miri | sha1-padding:64 [routine] | passed | 2026-10-19T11:34:26Z |
| miri-38b249636e533bab | sha1 | miri | sha1-padding:65 [extended] | reused | 2026-10-28T12:33:18Z |
| miri-38b90e289faca807 | sha3 | miri | sha3-fixed-bits:25 [routine] | passed | 2026-10-19T11:35:58Z |
| miri-38c8586153f793c9 | tuplehash | miri | scoped_tuplexof128_differential:6:width=1 [extended] | reused | 2026-10-29T00:35:44Z |
| miri-38cc7e7ef734f86e | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:10 [routine] | No mapped observation | — |
| miri-38d2d211ae539918 | kmac | miri | kmac-streamed-setup:13 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-38d99ca67ae900f8 | sha1 | miri | sha1-padding:32 [extended] | reused | 2026-10-28T12:36:50Z |
| miri-38e185aa1d79fe52 | md5 | miri | md5-scoped:251 [extended] | reused | 2026-10-28T12:04:38Z |
| miri-38e74ff9aee27547 | tuplehash | miri | tuplehash-staging:392 [extended] | reused | 2026-10-28T16:16:08Z |
| miri-38e7aa87b9eaaa8d | sha1 | miri | sha1-padding:60 [extended] | reused | 2026-10-28T12:39:11Z |
| miri-38f19e2414a11516 | sha1 | miri | sha1-scoped:53 [extended] | reused | 2026-10-28T13:14:19Z |
| miri-38f569c77c9c3faf | tuplehash | miri | scoped_tuplexof128_differential:9:width=3 [extended] | passed | 2026-10-29T10:50:25Z |
| miri-38f666df4bc0e01e | md5 | miri | md5-bulk:20 [extended] | reused | 2026-10-28T11:38:48Z |
| miri-390fee6e68194537 | sha2 | miri | -p brynja-hash-sha2 --test sha224 official_short_and_long_vectors_match_fips_and_nist_cavp [remaining suite; inspect skips with show] | passed | 2026-10-19T11:30:33Z |
| miri-3913bb7d693dd707 | md5 | miri | md5-scoped:183 [extended] | reused | 2026-10-28T11:59:40Z |
| miri-3919708f123247db | tuplehash | miri | tuplehash-staging:752 [extended] | reused | 2026-10-28T18:11:42Z |
| miri-3919ab37ea1b5c3d | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_unwind_reuse:2 [routine] | No mapped observation | — |
| miri-3921668d181ef5c8 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:18:width=0 [extended] | reused | 2026-10-28T22:24:48Z |
| miri-3926e5c1bb6d04c1 | sha1 | miri | sha1-bulk:81 [extended] | reused | 2026-10-28T12:56:39Z |
| miri-393c23e69ed5e5a5 | sha1 | miri | sha1-scoped:251 [extended] | reused | 2026-10-28T13:35:07Z |
| miri-3946403bcd1cfa97 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:50:width=2 [extended] | reused | 2026-10-28T21:27:05Z |
| miri-394bf15950d60e38 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:12:width=3 [extended] | reused | 2026-10-28T19:46:30Z |
| miri-3956910bf369c82a | tuplehash | miri | scoped_tuplexof256_differential:42:width=4 [extended] | reused | 2026-10-29T03:47:02Z |
| miri-39822076b6659e6f | sha1 | miri | sha1-bulk:102 [extended] | reused | 2026-10-28T12:48:06Z |
| miri-398aab7a381c8b7c | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:34:width=2 [extended] | reused | 2026-10-28T23:01:09Z |
| miri-398b07a413379ffa | tuplehash | miri | tuplehash-staging:231 [extended] | reused | 2026-10-28T21:31:53Z |
| miri-399e55954c562bef | md5 | miri | md5-batch-mask:152 [extended] | reused | 2026-10-28T12:24:33Z |
| miri-39ac93d1eacdba36 | parallelhash | miri | [bounded-parallelhash-v1] parallelhashxof-official:0 [routine] | No mapped observation | — |
| miri-39ad9dc9f6034b3c | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:30:width=4 [extended] | reused | 2026-10-28T20:22:51Z |
| miri-39b425f342f902c7 | kmac | miri | domain_substitution_changes_outputs_and_fixed_is_not_xof_prefix [routine] | passed | 2026-10-19T11:57:57Z |
| miri-39b98245ed56a393 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:0 [routine] | No mapped observation | — |
| miri-39c59c6d1a6803eb | tuplehash | miri | scoped_tuplexof128_differential:24:width=2 [extended] | reused | 2026-10-29T01:17:49Z |
| miri-39cba76588fb2abf | tuplehash | miri | tuplehash-staging:627 [extended] | reused | 2026-10-28T23:44:55Z |
| miri-39d86aa915610f19 | tuplehash | miri | tuplehash-staging:160 [extended] | reused | 2026-10-28T15:01:04Z |
| miri-39da796af029cff5 | tuplehash | miri | tuplehash-execution-fixed:5 [extended] | reused | 2026-10-28T19:30:30Z |
| miri-39e241f2ae060a37 | sha2 | miri | -p brynja-hash-sha2 --features hardened-execution,general-sha512-t --lib hardened_execution::engine::tests [remaining suite; inspect skips with show] | reused | 2026-10-28T13:31:08Z |
| miri-39e7d5dd52a1211f | tuplehash | miri | scoped_tuplexof256_differential:40:width=2 [extended] | reused | 2026-10-29T03:47:39Z |
| miri-39fc8f8cb568c678 | md5 | miri | md5-scoped:242 [extended] | reused | 2026-10-28T12:14:57Z |
| miri-3a08bf1b2c73bb9f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:42:width=0 [extended] | reused | 2026-10-28T23:21:51Z |
| miri-3a0e7e0234dc4ff8 | kmac | miri | kmac-streamed-setup:21 [routine] | No mapped observation | — |
| miri-3a0eb72a33b65784 | tuplehash | miri | scoped_tuplexof256_differential:33:width=1 [extended] | passed | 2026-10-29T12:08:43Z |
| miri-3a31e8e9ab3d9389 | tuplehash | miri | tuplehash-staging:41 [extended] | reused | 2026-10-28T14:34:54Z |
| miri-3a33ef739016d143 | sha1 | miri | sha1-bulk:242 [extended] | reused | 2026-10-28T13:02:28Z |
| miri-3a561714e63e9f9c | kmac | miri | kmac-streamed-setup:32 [routine] | No mapped observation | — |
| miri-3a57360812c4ace3 | md5 | miri | md5-bulk:52 [extended] | reused | 2026-10-28T11:40:54Z |
| miri-3a6979a7c004567b | tuplehash | miri | scoped_tuplexof128_differential:16:width=0 [extended] | reused | 2026-10-29T00:58:58Z |
| miri-3a758d7dff656c7b | sha1 | miri | sha1-bulk:133 [extended] | reused | 2026-10-28T13:01:10Z |
| miri-3a77ea99b34a843b | tuplehash | miri | scoped_tuplexof128_differential:3:width=0 [extended] | reused | 2026-10-29T01:17:27Z |
| miri-3a7fcb33cd65bf73 | md5 | miri | md5-scoped:229 [extended] | reused | 2026-10-28T12:03:18Z |
| miri-3a803dc02ceb0c81 | tuplehash | miri | tuplehash-staging:751 [extended] | reused | 2026-10-29T00:26:45Z |
| miri-3ab69bb6ec955a69 | kmac | miri | kmac-scoped-lifecycle:9 [extended] | reused | 2026-10-28T19:50:17Z |
| miri-3abd65a27f227469 | sha1 | miri | sha1-scoped:126 [extended] | reused | 2026-10-28T13:12:07Z |
| miri-3ac25a4f7516d379 | sha1 | miri | sha1-bulk:99 [extended] | reused | 2026-10-28T12:53:19Z |
| miri-3ac369bbb95ee617 | sha1 | miri | sha1-scoped:196 [extended] | reused | 2026-10-28T13:19:17Z |
| miri-3ac81298083392f3 | sha1 | miri | sha1-padding:10 [extended] | reused | 2026-10-28T12:40:02Z |
| miri-3adf0a200a7ac36e | tuplehash | miri | scoped_tuplexof128_differential:46:width=2 [extended] | reused | 2026-10-29T02:10:19Z |
| miri-3aea65f757e01deb | md5 | miri | md5-batch-mask:105 [extended] | reused | 2026-10-28T12:15:30Z |
| miri-3aec49aca4d5c158 | kmac | miri | kmac-streamed-setup:67 [routine] | No mapped observation | — |
| miri-3b008d171c961f7b | tuplehash | miri | tuplehash-staging:556 [extended] | reused | 2026-10-28T17:08:54Z |
| miri-3b015f68d64c2981 | parallelhash | miri | [bounded-parallelhash-v1] parallelhashxof-official:5 [extended] | passed | 2026-10-29T14:01:07Z |
| miri-3b04b928e672bee8 | tuplehash | miri | scoped_tuplexof128_differential:8:width=3 [extended] | reused | 2026-10-29T00:43:10Z |
| miri-3b16d468b4e39755 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:23 [extended] | passed | 2026-10-29T13:33:34Z |
| miri-3b1c9165fd84e739 | tuplehash | miri | tuplehash-staging:851 [extended] | reused | 2026-10-29T01:00:29Z |
| miri-3b2142ee6d8427e1 | md5 | miri | md5-bulk:107 [extended] | reused | 2026-10-28T11:35:21Z |
| miri-3b24721008d5f1dd | tuplehash | miri | scoped_tuplexof128_differential:26:width=1 [extended] | reused | 2026-10-29T01:16:55Z |
| miri-3b37d94a7ceef34a | kmac | miri | kmacxof-official:4 [extended] | reused | 2026-10-28T14:08:11Z |
| miri-3b38b105b0602ec2 | md5 | miri | md5-batch-mask:183 [extended] | reused | 2026-10-28T12:21:43Z |
| miri-3b5184d85c610d4f | sha3 | miri | -p brynja-hash-sha3 --features batch-execution --lib batch::tests::bounded_batch_lifecycle [remaining suite; inspect skips with show] | reused | 2026-10-28T13:43:00Z |
| miri-3b54cec81ed88848 | sha1 | miri | sha1-scoped:216 [extended] | reused | 2026-10-28T13:20:55Z |
| miri-3b56b14fec6643ea | tuplehash | miri | tuplehash-staging:460 [extended] | reused | 2026-10-28T16:38:06Z |
| miri-3b5dc35a5bd90b75 | tuplehash | miri | tuplehash-staging:536 [extended] | reused | 2026-10-28T17:02:06Z |
| miri-3b68b13cc795ae74 | kmac | miri | kmac-streamed-setup:21 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-3b6a06852f9f36a3 | tuplehash | miri | scoped_tuplexof128_differential:40:width=0 [extended] | reused | 2026-10-29T01:58:45Z |
| miri-3b6a964e7911bb21 | md5 | miri | md5-padding:109 [extended] | reused | 2026-10-28T11:35:52Z |
| miri-3b75cc12a057f600 | md5 | miri | md5-padding:44 [extended] | reused | 2026-10-28T11:21:19Z |
| miri-3b7af14d923a0737 | md5 | miri | md5-bulk:239 [extended] | reused | 2026-10-28T11:46:00Z |
| miri-3b853efe00abf107 | md5 | miri | md5-batch-mask:103 [extended] | reused | 2026-10-28T12:15:09Z |
| miri-3b9edee81697392d | tuplehash | miri | tuplehash-staging:107 [extended] | reused | 2026-10-28T20:50:04Z |
| miri-3bbeda93dda7d964 | tuplehash | miri | tuplehash-staging:299 [extended] | reused | 2026-10-28T21:54:50Z |
| miri-3bda103510dfb36c | sha1 | miri | sha1-bulk:125 [extended] | reused | 2026-10-28T13:00:20Z |
| miri-3be28a905243fb5a | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:14:width=3 [extended] | reused | 2026-10-28T19:46:05Z |
| miri-3bf3e0a7f3be90fc | sanitization | miri | -p brynja-sanitization --test behavior [remaining suite; inspect skips with show] | reused | 2026-10-28T11:17:05Z |
| miri-3c0d51b2a64d4783 | tuplehash | miri | tuplehash-staging:810 [extended] | reused | 2026-10-28T18:33:16Z |
| miri-3c1fd3b4381446be | kmac | miri | kmac-scoped-lifecycle:4 [extended] | reused | 2026-10-28T13:55:37Z |
| miri-3c2ecf4f8eafaa1c | sha3 | miri | sha3-fixed-bits:18 [routine] | passed | 2026-10-19T11:39:15Z |
| miri-3c3c808d2d679d9b | tuplehash | miri | tuplehash-staging:800 [extended] | reused | 2026-10-28T18:26:42Z |
| miri-3c6b10d9b78db1a9 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:9:width=3 [extended] | reused | 2026-10-29T04:37:02Z |
| miri-3c71eb283fce29c1 | md5 | miri | md5-padding:64 [extended] | reused | 2026-10-28T11:22:54Z |
| miri-3c75ae23d6081577 | tuplehash | miri | scoped_tuplexof128_differential:35:width=4 [extended] | reused | 2026-10-29T02:27:31Z |
| miri-3c773aaff557af71 | sha1 | miri | sha1-padding:9 [extended] | reused | 2026-10-28T12:28:53Z |
| miri-3c9ea1f1e4a24df0 | sha2 | miri | -p brynja-crypto-cpu --features sha512-batch --lib sha512_batch::tests::failed_revalidation_and_unwind_revoke_before_instruction_entry [remaining suite; inspect skips with show] | passed | 2026-10-19T11:32:23Z |
| miri-3ca17858f8ae4300 | md5 | miri | md5-bulk:243 [extended] | reused | 2026-10-28T11:46:22Z |
| miri-3ca701933c6c0695 | sha1 | miri | sha1-bulk:46 [extended] | reused | 2026-10-28T12:43:38Z |
| miri-3cb6a6efa3498dca | sha2 | miri | -p brynja-hash-sha2 --test bit_inputs selected_official_nist_bit_vectors_match_every_identity [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-3cccadd46a292473 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:30:width=0 [extended] | reused | 2026-10-28T20:22:51Z |
| miri-3cd16ec6a69f56ca | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:55:width=1 [extended] | reused | 2026-10-29T01:10:24Z |
| miri-3cd519cf31efe7a5 | md5 | miri | md5-bulk:141 [extended] | reused | 2026-10-28T11:37:39Z |
| miri-3cef715f558b215c | sha1 | miri | sha1-padding:83 [extended] | reused | 2026-10-28T12:36:23Z |
| miri-3d07476631744018 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:26:width=1 [extended] | reused | 2026-10-28T20:13:39Z |
| miri-3d1d51cc4c312f52 | sha2 | miri | -p brynja-hash-sha2 --features batch512-execution --test batch512 batch512_general::derived_iv_work_is_bounded_and_named_identity_is_distinct [remaining suite; inspect skips with show] | reused | 2026-10-28T13:25:23Z |
| miri-3d2a44d49e9a2c06 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:22 [routine] | No mapped observation | — |
| miri-3d429297adbf9d1f | md5 | miri | md5-batch-mask:138 [extended] | reused | 2026-10-28T12:28:52Z |
| miri-3d5b5fdbb1bbd532 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:16:width=2 [extended] | reused | 2026-10-28T19:55:42Z |
| miri-3d6417e21ba6bf64 | md5 | miri | -p brynja-legacy-md5 --test api [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-3d754354f8492fa7 | md5 | miri | md5-padding:65 [extended] | reused | 2026-10-28T11:32:19Z |
| miri-3d77abac707f8df2 | md5 | miri | md5-batch-mask:13 [extended] | reused | 2026-10-28T12:08:28Z |
| miri-3d78911ac309f337 | tuplehash | miri | scoped_tuplexof128_differential:40:width=2 [extended] | reused | 2026-10-29T01:58:45Z |
| miri-3d7ae8b635f771f9 | kmac | miri | kmac-streamed-setup:77 [routine] | No mapped observation | — |
| miri-3d8d29b9192119f9 | md5 | miri | md5-scoped:16 [extended] | reused | 2026-10-28T11:54:02Z |
| miri-3da8469e3e2d5603 | sha3 | miri | sha3-fixed-bits:7 [routine] | passed | 2026-10-19T11:29:06Z |
| miri-3db21a225262f897 | tuplehash | miri | tuplehash-staging:804 [extended] | reused | 2026-10-28T18:28:20Z |
| miri-3db48d75e1c00b70 | tuplehash | miri | tuplehash-staging:660 [extended] | reused | 2026-10-28T17:41:52Z |
| miri-3dc9e31b38594288 | sha3 | miri | sha3-fixed-boundaries:46 [extended] | reused | 2026-10-28T13:42:14Z |
| miri-3dca5f95547427cf | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:43:width=0 [extended] | reused | 2026-10-29T00:04:50Z |
| miri-3dcd7918bfea5ee7 | sha3 | miri | sha3-fixed-bits:10 [extended] | reused | 2026-10-28T13:47:23Z |
| miri-3dd0e3dcae0e459e | md5 | miri | md5-padding:107 [extended] | reused | 2026-10-28T11:30:42Z |
| miri-3dd5a6c712f15e0e | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_unwind_reuse:0 [routine] | No mapped observation | — |
| miri-3dd63c4f16c55cbd | sha2 | miri | -p brynja-hash-sha2 --test sha512_224 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | passed | 2026-10-19T11:30:40Z |
| miri-3dda2f14569ffcbd | tuplehash | miri | tuplehash-staging:72 [extended] | reused | 2026-10-28T14:31:50Z |
| miri-3de00d9e8af1bc38 | tuplehash | miri | scoped_tuplexof256_differential:17:width=2 [extended] | passed | 2026-10-29T12:28:25Z |
| miri-3de03ba369453e57 | sha3 | miri | sha3-fixed-boundaries:1 [extended] | reused | 2026-10-28T13:31:27Z |
| miri-3de29f86d355d1b1 | md5 | miri | md5-bulk:44 [extended] | reused | 2026-10-28T11:40:22Z |
| miri-3ded754dea6ced32 | tuplehash | miri | tuplehash-execution-xof:0 [routine] | passed | 2026-10-19T12:14:45Z |
| miri-3df4ccfb62786a69 | tuplehash | miri | scoped_tuplexof256_differential:8:width=0 [extended] | reused | 2026-10-29T02:31:37Z |
| miri-3dfdc31f9a6a7cca | sha3 | miri | sha3-fixed-boundaries:71 [routine] | passed | 2026-10-19T11:28:43Z |
| miri-3e008742d7de7ad8 | tuplehash | miri | tuplehash-staging:306 [extended] | reused | 2026-10-28T15:51:33Z |
| miri-3e01752c8fbc0cea | sha1 | miri | sha1-padding:50 [extended] | reused | 2026-10-28T12:43:13Z |
| miri-3e21bedab34c519a | md5 | miri | md5-batch-mask:66 [extended] | reused | 2026-10-28T12:23:12Z |
| miri-3e230eb3e62b9185 | kmac | miri | kmac-scoped-xof-lifecycle:15 [extended] | reused | 2026-10-28T19:58:23Z |
| miri-3e2bb05ad52d77a0 | kmac | miri | kmac-streamed-setup:73 [routine] | No mapped observation | — |
| miri-3e3d54fb8d77595e | sha3 | miri | sha3-fixed-boundaries:61 [extended] | reused | 2026-10-28T13:39:43Z |
| miri-3e4cd8628520d803 | tuplehash | miri | scoped_tuplexof128_differential:30:width=1 [extended] | reused | 2026-10-29T01:26:26Z |
| miri-3e5259e17b506c9b | kmac | miri | kmac-streamed-setup:37 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-3e5e64682e13fa2a | tuplehash | miri | scoped_tuplexof128_differential:28:width=2 [extended] | reused | 2026-10-29T01:27:22Z |
| miri-3e6e9c8c920ec1da | tuplehash | miri | tuplehash-staging:690 [extended] | reused | 2026-10-28T17:54:51Z |
| miri-3e7981d905f531f1 | md5 | miri | md5-batch-mask:157 [extended] | reused | 2026-10-28T12:19:41Z |
| miri-3e82861ef1f0ddc9 | md5 | miri | md5-batch-mask:56 [extended] | reused | 2026-10-28T12:17:09Z |
| miri-3e86ff3a685c9e32 | tuplehash | miri | tuplehash-staging:186 [extended] | reused | 2026-10-28T15:12:36Z |
| miri-3e8bef0df45e79cc | tuplehash | miri | tuplehash-staging:436 [extended] | reused | 2026-10-28T16:30:21Z |
| miri-3e920b92c845169d | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-domains:3 [routine] | No mapped observation | — |
| miri-3eac89c27e05aec4 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-faults:1 [extended] | passed | 2026-10-29T14:19:29Z |
| miri-3eb17de0c84b327d | md5 | miri | md5-batch-mask:169 [extended] | reused | 2026-10-28T12:20:37Z |
| miri-3eb50820f3976f49 | hmac | miri | sha3_384 [routine] | No mapped observation | — |
| miri-3ebc715a0e3d3824 | sha1 | miri | sha1-padding:15 [extended] | reused | 2026-10-28T12:30:45Z |
| miri-3f0274e3c6e8d6d9 | parallelhash | miri | arbitrary_bit_input_and_output_partition_are_stable [routine] | passed | 2026-10-19T13:43:03Z |
| miri-3f182af1566cfd72 | md5 | miri | md5-scoped:283 [extended] | reused | 2026-10-28T12:06:56Z |
| miri-3f22f1171b451ed2 | sha1 | miri | sha1-padding:40 [extended] | reused | 2026-10-28T12:37:29Z |
| miri-3f2707d71c3f2d2d | tuplehash | miri | scoped_tuplexof256_differential:47:width=4 [extended] | reused | 2026-10-29T04:53:59Z |
| miri-3f2d609d37f1a1a3 | md5 | miri | md5-scoped:97 [extended] | reused | 2026-10-28T11:54:04Z |
| miri-3f327b1bcbe82961 | sha2 | miri | -p brynja-hash-sha2 --test sha256 downstream_style_real_content_uses_only_public_api [remaining suite; inspect skips with show] | reused | 2026-10-28T13:28:12Z |
| miri-3f3d427c1f0ecc85 | tuplehash | miri | tuplehash-staging:116 [extended] | reused | 2026-10-28T14:46:17Z |
| miri-3f3d4d585161e1ad | kmac | miri | kmac-scoped-lifecycle:4 [routine] | passed | 2026-10-19T11:33:12Z |
| miri-3f42ce2109609bd5 | sha3 | miri | sha3-fixed-bits:12 [extended] | reused | 2026-10-28T13:55:42Z |
| miri-3f60c2b0f5d2c127 | kmac | miri | kmac-streamed-setup:23 [routine] | No mapped observation | — |
| miri-3f78cf3cf716b933 | sha1 | miri | sha1-padding:78 [extended] | reused | 2026-10-28T12:45:50Z |
| miri-3fa7da2003c4d143 | tuplehash | miri | tuplehash-staging:330 [extended] | reused | 2026-10-28T15:59:04Z |
| miri-3faf5a7a99b1f028 | sha1 | miri | -p brynja-legacy-sha1 --features hardened-execution --lib cpu::secret::tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-3fbe26ef0a84b929 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:41:width=0 [extended] | reused | 2026-10-29T05:55:08Z |
| miri-3fcfef18b93740a3 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:31:width=3 [extended] | reused | 2026-10-28T20:52:30Z |
| miri-3fe122bca567821f | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:507 [routine] | No mapped observation | — |
| miri-3fe59f8e0f55f706 | tuplehash | miri | tuplehash-staging:188 [extended] | reused | 2026-10-28T15:10:14Z |
| miri-3fec221f8f03de25 | sha1 | miri | sha1-padding:127 [routine] | passed | 2026-10-19T11:34:38Z |
| miri-3ff4e465bde770fd | tuplehash | miri | tuplehash-staging:706 [extended] | reused | 2026-10-28T18:00:21Z |
| miri-3ff94392493a0cb5 | tuplehash | miri | scoped_tuplexof256_differential:11:width=4 [extended] | reused | 2026-10-29T03:23:30Z |
| miri-3ffda370df18b1f6 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-faults:5 [routine] | No mapped observation | — |
| miri-402a732948fe712e | kmac | miri | kmac-scoped-lifecycle:0 [routine] | passed | 2026-10-19T11:32:34Z |
| miri-40323785c1949b9e | parallelhash | miri | -p brynja-hash-parallel --features hardened-execution --lib execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-404a768e26227b75 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:50:width=4 [extended] | reused | 2026-10-28T23:58:01Z |
| miri-404e1fc52cc174ee | sha3 | miri | sha3-fixed-boundaries:10 [extended] | reused | 2026-10-28T13:37:26Z |
| miri-405d557905f4f68d | sha1 | miri | sha1-padding:97 [extended] | reused | 2026-10-28T12:36:13Z |
| miri-405e2fd90a8cdef2 | sha1 | miri | sha1-bulk:149 [extended] | reused | 2026-10-28T13:02:52Z |
| miri-406f188a61b41480 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:45:width=3 [extended] | reused | 2026-10-29T06:07:36Z |
| miri-40704a71a23355c1 | tuplehash | miri | tuplehash-staging:466 [extended] | reused | 2026-10-28T16:43:22Z |
| miri-408071ccd293a67f | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:15 [routine] | No mapped observation | — |
| miri-408265828b95cf3c | sha1 | miri | sha1-padding:51 [extended] | reused | 2026-10-28T12:33:30Z |
| miri-40d71d8053b60bd9 | kmac | miri | kmac-streamed-setup:71 [routine] | No mapped observation | — |
| miri-40f45f3f735d57fd | md5 | miri | md5-scoped:153 [extended] | reused | 2026-10-28T11:57:53Z |
| miri-40f5ddd8b4d96f66 | sha1 | miri | sha1-scoped:226 [extended] | reused | 2026-10-28T13:20:12Z |
| miri-410ef205907e5973 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:36 [extended] | passed | 2026-10-29T12:37:38Z |
| miri-411e97c50893c8fd | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:1 [extended] | passed | 2026-10-29T13:54:39Z |
| miri-4121016de495d8dc | tuplehash | miri | scoped_tuplexof256_differential:25:width=3 [extended] | passed | 2026-10-29T12:05:35Z |
| miri-4138b28035bc6a7d | tuplehash | miri | scoped_tuplexof128_differential:2:width=3 [extended] | reused | 2026-10-29T00:29:11Z |
| miri-414158293d937f40 | tuplehash | miri | scoped_tuplexof128_differential:20:width=4 [extended] | reused | 2026-10-29T01:08:19Z |
| miri-41449be73fe88016 | kmac | miri | kmac-streamed-setup:51 [routine] | No mapped observation | — |
| miri-4156e2b826837b92 | hmac | miri | sha512 [extended] | passed | 2026-10-29T15:02:34Z |
| miri-415c53665306f31c | tuplehash | miri | scoped_tuplexof128_differential:41:width=2 [extended] | passed | 2026-10-29T11:59:06Z |
| miri-415e06e217aff96e | tuplehash | miri | tuplehash-staging:489 [extended] | reused | 2026-10-28T17:04:47Z |
| miri-415ea89cfcc58fb5 | kmac | miri | kmacxof-official:2 [extended] | reused | 2026-10-28T14:03:24Z |
| miri-41690ca62a386ea0 | md5 | miri | md5-bulk:210 [extended] | reused | 2026-10-28T11:48:40Z |
| miri-41761c684dad6262 | tuplehash | miri | tuplehash-staging:563 [extended] | reused | 2026-10-28T23:23:48Z |
| miri-4178910ae1af1fe5 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:9:width=1 [extended] | reused | 2026-10-29T04:37:02Z |
| miri-417c6df7011fc524 | md5 | miri | md5-scoped:127 [extended] | reused | 2026-10-28T11:55:51Z |
| miri-417d0310851a9a79 | md5 | miri | md5-batch-mask:139 [extended] | reused | 2026-10-28T12:18:02Z |
| miri-4187e2a1017e6ae4 | md5 | miri | md5-bulk:237 [extended] | reused | 2026-10-28T11:45:29Z |
| miri-418a4aa682bf5524 | tuplehash | miri | tuplehash-staging:604 [extended] | reused | 2026-10-28T17:23:54Z |
| miri-418dc2fd73760c1e | md5 | miri | md5-batch-mask:15 [extended] | reused | 2026-10-28T12:08:21Z |
| miri-41a3d7248da54446 | legacy_hmac | miri | -p brynja-legacy-hmac --features sha1-execution --lib execution::retained::tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-41bdfc432c7de34b | tuplehash | miri | tuplehash-staging:318 [extended] | reused | 2026-10-28T15:55:54Z |
| miri-41c5ad64e04bca16 | tuplehash | miri | tuplehash-staging:350 [extended] | reused | 2026-10-28T16:05:54Z |
| miri-41e149082359076b | md5 | miri | md5-scoped:175 [extended] | reused | 2026-10-28T11:59:07Z |
| miri-41e4b036ca391788 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:38:width=3 [extended] | reused | 2026-10-28T23:10:13Z |
| miri-4210fc972f8c167c | md5 | miri | md5-bulk:68 [extended] | reused | 2026-10-28T11:42:03Z |
| miri-421d3f479a89741b | sha2 | miri | -p brynja-hash-sha2 --test sha224 official_short_and_long_vectors_match_fips_and_nist_cavp [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-4227dbe9a2003eac | md5 | miri | md5-batch-mask:64 [extended] | reused | 2026-10-28T12:17:45Z |
| miri-42285b2aeb8f8a75 | md5 | miri | md5-scoped:27 [extended] | reused | 2026-10-28T11:49:08Z |
| miri-4231bd56bd7adcd6 | tuplehash | miri | tuplehash-staging:166 [extended] | reused | 2026-10-28T15:06:06Z |
| miri-427aff289d09e03d | tuplehash | miri | tuplehash-staging:198 [extended] | reused | 2026-10-28T15:16:27Z |
| miri-42c4339d7a92c2c7 | md5 | miri | md5-scoped:123 [extended] | reused | 2026-10-28T11:55:35Z |
| miri-42cdadd8ac5e94e0 | sha1 | miri | sha1-bulk:49 [extended] | reused | 2026-10-28T12:54:09Z |
| miri-42d66c396786be5e | sha1 | miri | sha1-bulk:4 [extended] | reused | 2026-10-28T12:39:21Z |
| miri-42d92ed3acc694dc | md5 | miri | md5-bulk:231 [extended] | reused | 2026-10-28T11:45:17Z |
| miri-42e8c01cd0158e87 | tuplehash | miri | tuplehash-staging:181 [extended] | reused | 2026-10-28T15:21:48Z |
| miri-42f17acb7edd225a | tuplehash | miri | tuplehash-staging:631 [extended] | reused | 2026-10-28T23:45:52Z |
| miri-4317d2912dcfb259 | tuplehash | miri | tuplehash-staging:704 [routine] | passed | 2026-10-19T11:55:28Z |
| miri-432dca753391925d | sha1 | miri | sha1-padding:64 [extended] | reused | 2026-10-28T12:39:34Z |
| miri-4333b3c9d90e48fb | hmac | miri | sha3_256 [existing-full] | No mapped observation | — |
| miri-43485e5a1dd7ebf2 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_unwind_reuse:1 [routine] | No mapped observation | — |
| miri-4353f7b13525e2d5 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:46:width=4 [extended] | reused | 2026-10-28T21:04:48Z |
| miri-4357dcbd0c82449f | sha1 | miri | sha1-scoped:27 [extended] | reused | 2026-10-28T13:17:44Z |
| miri-435f34a99016576d | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:9 [routine] | No mapped observation | — |
| miri-436028ed8f830ff7 | tuplehash | miri | tuplehash-execution-fixed:15 [extended] | reused | 2026-10-29T01:36:28Z |
| miri-4360ac709f819135 | parallelhash | miri | empty_input_has_zero_leaves_and_b_one_is_valid [routine] | passed | 2026-10-19T17:29:40Z |
| miri-436a8f6e40f2d85d | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:20:width=2 [extended] | reused | 2026-10-28T22:34:16Z |
| miri-4376e4bbd53d4d63 | tuplehash | miri | tuplehash-staging:855 [extended] | reused | 2026-10-29T01:01:26Z |
| miri-4392466d2dbb57dc | kmac | miri | kmac-streamed-setup:11 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-439c0a10b46c99b2 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:32:width=2 [extended] | reused | 2026-10-28T23:01:38Z |
| miri-43a3b80f258d31d2 | md5 | miri | md5-scoped:166 [extended] | reused | 2026-10-28T12:09:31Z |
| miri-43aa0b471be0eb7d | sha1 | miri | sha1-bulk:113 [extended] | reused | 2026-10-28T12:59:20Z |
| miri-43c50e3355f4579c | tuplehash | miri | tuplehash-staging:793 [extended] | reused | 2026-10-28T18:46:42Z |
| miri-43d2145e46b59e41 | md5 | miri | md5-scoped:157 [extended] | reused | 2026-10-28T11:58:09Z |
| miri-43fb19c03b89d962 | tuplehash | miri | scoped_tuplexof256_differential:15 [routine] | passed | 2026-10-19T12:37:50Z |
| miri-4405df43490b8709 | sha1 | miri | sha1-bulk:210 [extended] | reused | 2026-10-28T12:58:49Z |
| miri-4421b8e0c46b4401 | tuplehash | miri | tuplehash-staging:719 [extended] | reused | 2026-10-29T00:15:55Z |
| miri-4421d8f4321b2502 | sha1 | miri | sha1-scoped:40 [extended] | reused | 2026-10-28T13:07:04Z |
| miri-442872e7ed1d1957 | sha1 | miri | sha1-padding:16 [extended] | reused | 2026-10-28T12:35:35Z |
| miri-44289a7ba928ae11 | md5 | miri | md5-batch-mask:97 [extended] | reused | 2026-10-28T12:14:52Z |
| miri-442910dad219661b | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:12 [routine] | No mapped observation | — |
| miri-442d7cd34df9efcf | tuplehash | miri | scoped_tuplexof128_differential:43:width=2 [extended] | reused | 2026-10-29T02:49:54Z |
| miri-443c1d66f0b3213e | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:64 [extended] | passed | 2026-10-29T13:38:20Z |
| miri-4446081a2034bf5c | sha1 | miri | sha1-scoped:191 [extended] | reused | 2026-10-28T13:30:01Z |
| miri-4455afd012feb553 | tuplehash | miri | tuplehash-staging:459 [extended] | reused | 2026-10-28T22:48:45Z |
| miri-4456cb881be0dca3 | md5 | miri | md5-scoped:260 [extended] | reused | 2026-10-28T12:11:00Z |
| miri-4457e2ceb6a052da | sha1 | miri | sha1-scoped:241 [extended] | reused | 2026-10-28T13:28:59Z |
| miri-446468ac569d2710 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:15 [extended] | passed | 2026-10-29T13:14:16Z |
| miri-44779bdeef1d1b06 | tuplehash | miri | tuplehash-staging:883 [extended] | reused | 2026-10-29T01:10:52Z |
| miri-448534a46a576637 | tuplehash | miri | tuplehash-staging:13 [extended] | reused | 2026-10-28T14:25:50Z |
| miri-4491b3c30190e87f | md5 | miri | md5-scoped:83 [extended] | reused | 2026-10-28T11:52:51Z |
| miri-449de26f2610553a | md5 | miri | md5-padding:46 [extended] | reused | 2026-10-28T11:21:14Z |
| miri-44c10c058a5f847f | tuplehash | miri | tuplehash-staging:567 [extended] | reused | 2026-10-28T23:24:45Z |
| miri-44e52ba7e40a37f1 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:2 [extended] | passed | 2026-10-29T14:06:30Z |
| miri-44e61571a1504633 | sha2 | miri | -p brynja-hash-sha2 --test sha224 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | passed | 2026-10-19T11:36:00Z |
| miri-44f6406873e5cde3 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:51:width=3 [extended] | reused | 2026-10-29T00:43:55Z |
| miri-4520afe7d3650a12 | md5 | miri | md5-bulk:33 [extended] | reused | 2026-10-28T11:29:54Z |
| miri-45371d566b370f48 | md5 | miri | md5-scoped:227 [extended] | reused | 2026-10-28T12:02:53Z |
| miri-453736e857fa7bdb | tuplehash | miri | tuplehash-staging:94 [extended] | reused | 2026-10-28T14:42:49Z |
| miri-453ec023355e4881 | kmac | miri | kmac-streamed-setup:34 [routine] | No mapped observation | — |
| miri-454d4ee0dd5b76d8 | md5 | miri | md5-scoped:215 [extended] | reused | 2026-10-28T12:02:00Z |
| miri-457d4e11adeaba86 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:37:width=2 [extended] | reused | 2026-10-29T03:03:13Z |
| miri-4583b915d4f94b36 | md5 | miri | md5-batch-mask:202 [extended] | reused | 2026-10-28T12:34:02Z |
| miri-45936342ea688491 | sha2 | miri | -p brynja-hash-sha2 --lib buffer_length_rejects_invalid_values_without_mutation [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-459c0d45e7a3179c | sha1 | miri | sha1-scoped:25 [extended] | reused | 2026-10-28T13:12:26Z |
| miri-45a4cb529510ca73 | md5 | miri | md5-batch-mask:53 [extended] | reused | 2026-10-28T12:11:28Z |
| miri-45e5c5b3615b0d67 | md5 | miri | -p brynja-legacy-md5 --test api [remaining suite; inspect skips with show] | passed | 2026-10-19T11:31:50Z |
| miri-45ed8f1b411a21d0 | md5 | miri | md5-batch-mask:170 [extended] | reused | 2026-10-28T12:31:24Z |
| miri-45f08a67709e23e2 | md5 | miri | md5-padding:0 [routine] | passed | 2026-10-19T11:13:31Z |
| miri-460128224694ecbc | sha1 | miri | sha1-scoped:18 [extended] | reused | 2026-10-28T13:04:06Z |
| miri-46090edde7a8bc98 | md5 | miri | md5-batch-mask:197 [extended] | reused | 2026-10-28T12:22:53Z |
| miri-460bed10039ec44c | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:39:width=4 [extended] | reused | 2026-10-28T23:52:11Z |
| miri-462d3538aaaa6d9e | sha3 | miri | sha3-fixed-bits:16 [routine] | passed | 2026-10-19T11:38:35Z |
| miri-463cd01172ad0b75 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:24 [extended] | passed | 2026-10-29T14:58:59Z |
| miri-4641a0fe690dff65 | sha1 | miri | sha1-padding:5 [extended] | reused | 2026-10-28T12:28:36Z |
| miri-46430b2e811d5fa8 | tuplehash | miri | tuplehash-staging:363 [extended] | reused | 2026-10-28T22:16:46Z |
| miri-4643f76d9380c393 | kmac | miri | kmac-streamed-setup:14 [routine] | No mapped observation | — |
| miri-4669da62bfd87e5a | kmac | miri | kmac-framing:2 [routine] | passed | 2026-10-19T11:40:22Z |
| miri-46791177753629e8 | md5 | miri | -p brynja-legacy-md5 --features hardened-execution --lib cpu::scratch::tests [remaining suite; inspect skips with show] | reused | 2026-10-28T11:22:16Z |
| miri-469391b0082da36d | kmac | miri | kmac-streamed-setup:96 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-4698986c41594ac2 | md5 | miri | md5-scoped:30 [extended] | reused | 2026-10-28T12:00:06Z |
| miri-46a273f841e3ab5c | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:1:width=2 [extended] | reused | 2026-10-29T04:23:03Z |
| miri-46bafd6ea9182222 | sha3 | miri | sha3-fixed-boundaries:23 [extended] | reused | 2026-10-28T13:39:10Z |
| miri-46bd429eee7c2cc5 | kmac | miri | kmac-scoped-xof-lifecycle:11 [extended] | reused | 2026-10-28T19:57:07Z |
| miri-46c04db87edf7495 | sha1 | miri | sha1-bulk:118 [extended] | reused | 2026-10-28T12:49:27Z |
| miri-46ce603f1489f329 | sha3 | miri | sha3-fixed-boundaries:35 [extended] | reused | 2026-10-28T13:41:08Z |
| miri-46dea7b7d295a9df | md5 | miri | md5-padding:11 [extended] | reused | 2026-10-28T11:24:21Z |
| miri-46e43c9b397dad53 | md5 | miri | md5-bulk:225 [extended] | reused | 2026-10-28T11:44:27Z |
| miri-4701c10a17cc8467 | md5 | miri | md5-scoped:282 [extended] | reused | 2026-10-28T12:17:52Z |
| miri-4709371e82d53fbb | kmac | miri | kmac-framing:2 [extended] | reused | 2026-10-28T13:50:48Z |
| miri-470a2fcfad054f75 | md5 | miri | md5-bulk:212 [extended] | reused | 2026-10-28T11:53:41Z |
| miri-47137bdf1bac6938 | tuplehash | miri | scoped_tuplexof128_differential:1:width=3 [extended] | reused | 2026-10-29T07:08:40Z |
| miri-4740a1121e7222d2 | sha1 | miri | sha1-bulk:93 [extended] | reused | 2026-10-28T12:57:39Z |
| miri-4751e01410579f53 | md5 | miri | md5-scoped:234 [extended] | reused | 2026-10-28T12:14:23Z |
| miri-47567ef0259988f3 | tuplehash | miri | tuplehash-staging:612 [extended] | reused | 2026-10-28T17:26:52Z |
| miri-47570c760a539dcd | sha1 | miri | sha1-scoped:158 [extended] | reused | 2026-10-28T13:14:42Z |
| miri-47616b9950abfa2c | tuplehash | miri | tuplehash-staging:232 [extended] | reused | 2026-10-28T15:23:44Z |
| miri-47976c9e74a4eaf6 | sha3 | miri | sha3-fixed-bits:13 [extended] | reused | 2026-10-28T13:42:43Z |
| miri-4799e0607312cecd | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:54:width=0 [extended] | reused | 2026-10-28T21:49:32Z |
| miri-479c032ea59a839f | tuplehash | miri | tuplehash-staging:27 [extended] | reused | 2026-10-28T20:23:45Z |
| miri-47a9751cd95211a9 | md5 | miri | -p brynja-legacy-md5 --features execution --lib batch::execution::tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-47a9e9385955dfe3 | md5 | miri | md5-padding:76 [extended] | reused | 2026-10-28T11:23:53Z |
| miri-47c9a0fccf221440 | tuplehash | miri | scoped_tuplexof128_differential:24:width=1 [extended] | reused | 2026-10-29T01:17:49Z |
| miri-47caee4b21c95306 | tuplehash | miri | scoped_tuplexof256_differential:5:width=2 [extended] | passed | 2026-10-29T12:08:57Z |
| miri-47cf045b1f8ddcb3 | sha3 | miri | -p brynja-hash-sha3 --features static-execution --test execution execution_smoke [remaining suite; inspect skips with show] | reused | 2026-10-28T13:35:19Z |
| miri-47d4693477e7514c | sha1 | miri | sha1-padding:126 [extended] | reused | 2026-10-28T12:50:44Z |
| miri-47e47e3c41bb6207 | md5 | miri | md5-scoped:183 [routine] | passed | 2026-10-19T11:26:42Z |
| miri-47f071ce96602fe4 | md5 | miri | md5-batch-mask:208 [extended] | reused | 2026-10-28T12:29:02Z |
| miri-47fb5416ad5577be | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:9:width=3 [extended] | reused | 2026-10-29T01:57:28Z |
| miri-47ff9e0025a35a49 | sha3 | miri | sha3-fixed-bits:17 [routine] | passed | 2026-10-19T11:35:34Z |
| miri-481099aa367148dc | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:4:width=2 [extended] | reused | 2026-10-28T19:33:24Z |
| miri-48319f4b7a4a5dfa | tuplehash | miri | scoped_tuplexof128_differential:44:width=1 [extended] | reused | 2026-10-29T02:11:09Z |
| miri-483457a93ca633a7 | md5 | miri | md5-bulk:188 [extended] | reused | 2026-10-28T11:51:30Z |
| miri-4844f3ec6093eb3b | sha1 | miri | sha1-bulk:13 [extended] | reused | 2026-10-28T12:51:45Z |
| miri-485bccccbf0e7809 | sha1 | miri | sha1-padding:108 [extended] | reused | 2026-10-28T12:43:58Z |
| miri-4869910c93aa430d | tuplehash | miri | tuplehash-staging:767 [extended] | reused | 2026-10-29T00:32:09Z |
| miri-48b722dba7418e13 | sha3 | miri | sha3-fixed-boundaries:33 [extended] | reused | 2026-10-28T13:35:36Z |
| miri-48bcf587e63cad36 | sha1 | miri | sha1-bulk:206 [extended] | reused | 2026-10-28T12:58:21Z |
| miri-48be66055153e112 | tuplehash | miri | tuplehash-staging:679 [extended] | reused | 2026-10-29T00:02:26Z |
| miri-48becfcdce9f4a2c | kmac | miri | kmac-streamed-setup:69 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-48c1fe1b4200c9fb | tuplehash | miri | tuplehash-staging:425 [extended] | reused | 2026-10-28T16:43:18Z |
| miri-48c76f97fe9216c7 | md5 | miri | md5-bulk:80 [extended] | reused | 2026-10-28T11:42:56Z |
| miri-48d40b4282300202 | tuplehash | miri | scoped_tuplexof128_differential:2:width=1 [extended] | reused | 2026-10-29T00:29:11Z |
| miri-48d93ab679c028e5 | tuplehash | miri | tuplehash-staging:5 [extended] | reused | 2026-10-28T14:22:52Z |
| miri-48e25a7d8e8ab50b | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-order:0 [extended] | passed | 2026-10-29T14:52:52Z |
| miri-48faea1026ddedb8 | sha1 | miri | sha1-scoped:141 [extended] | reused | 2026-10-28T13:21:04Z |
| miri-491a161b2691aa92 | tuplehash | miri | scoped_tuplexof256_differential:40:width=0 [extended] | reused | 2026-10-29T03:47:39Z |
| miri-491d8af7486798e0 | tuplehash | miri | tuplehash-staging:301 [extended] | reused | 2026-10-28T16:01:33Z |
| miri-492146dc8a0eeb0f | sha1 | miri | sha1-scoped:141 [routine] | passed | 2026-10-19T11:35:29Z |
| miri-49302c3814a2857c | sha1 | miri | sha1-scoped:0 [extended] | reused | 2026-10-28T13:04:13Z |
| miri-49383bcc208c9c28 | tuplehash | miri | scoped_tuplexof128_differential:8:width=0 [extended] | reused | 2026-10-29T00:43:10Z |
| miri-495a44da7030729f | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:47:width=2 [extended] | reused | 2026-10-28T21:37:27Z |
| miri-495b45eb21eed19e | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:27 [routine] | No mapped observation | — |
| miri-4967ce888860b410 | md5 | miri | md5-scoped:231 [extended] | reused | 2026-10-28T12:03:10Z |
| miri-497801948c3f357e | tuplehash | miri | tuplehash-staging:659 [extended] | reused | 2026-10-28T23:55:19Z |
| miri-497af8b644ce2806 | sha2 | miri | -p brynja-hash-sha2 --test sha256 padding_boundaries_have_exact_digests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-49820c745131df68 | tuplehash | miri | tuplehash-staging:382 [extended] | reused | 2026-10-28T16:16:20Z |
| miri-498ec9462eb94b90 | md5 | miri | md5-bulk:184 [extended] | reused | 2026-10-28T11:51:09Z |
| miri-499a8c17f0cd6353 | tuplehash | miri | tuplehash-staging:640 [routine] | passed | 2026-10-19T15:51:19Z |
| miri-49b8e205d55ea7ef | sha3 | miri | sha3-fixed-boundaries:21 [extended] | reused | 2026-10-28T13:34:00Z |
| miri-49b9eec296ca44de | static_cpu | miri | -p brynja-crypto-cpu --features hardened-execution --lib hardened_execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-49c7c0291d654604 | kmac | miri | scoped_mismatch_propagates_and_workspace_can_be_reused [routine] | No mapped observation | — |
| miri-49d0cbf6cdc68f0f | kmac | miri | kmac-streamed-setup:64 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-49dec68bcc409914 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:49:width=3 [extended] | reused | 2026-10-29T03:52:14Z |
| miri-49e8827d50d781bb | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:14:width=4 [extended] | reused | 2026-10-28T19:46:05Z |
| miri-49fc2804b35dd84a | md5 | miri | -p brynja-legacy-md5 --features execution --lib batch::execution::tests [remaining suite; inspect skips with show] | reused | 2026-10-28T11:17:20Z |
| miri-4a09ae06a7660900 | md5 | miri | md5-batch-mask:19 [extended] | reused | 2026-10-28T12:08:38Z |
| miri-4a46c5c0e6447b70 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:0 [routine] | passed | 2026-10-19T12:07:05Z |
| miri-4a520760170179aa | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:564 [routine] | No mapped observation | — |
| miri-4a5fb395d7d4eaea | tuplehash | miri | tuplehash-execution-fixed:14 [extended] | reused | 2026-10-28T19:20:16Z |
| miri-4a764993cfd180f2 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:45:width=0 [extended] | reused | 2026-10-29T03:28:25Z |
| miri-4a7f01898ef05d83 | sha1 | miri | sha1-bulk:180 [extended] | reused | 2026-10-28T12:53:56Z |
| miri-4aac7bed1e9fe242 | tuplehash | miri | tuplehash-staging:431 [extended] | reused | 2026-10-28T22:39:18Z |
| miri-4ab7f60ad3f3e2f7 | md5 | miri | md5-scoped:217 [routine] | passed | 2026-10-19T11:14:35Z |
| miri-4acc2b5feb43edde | sha1 | miri | sha1-scoped:245 [extended] | reused | 2026-10-28T13:29:19Z |
| miri-4aeaad42ac9764a2 | sha3 | miri | sha3-fixed-boundaries:64 [extended] | reused | 2026-10-28T13:53:19Z |
| miri-4aed5e0d1c949d6e | tuplehash | miri | tuplehash-staging:37 [extended] | reused | 2026-10-28T14:33:18Z |
| miri-4b2d66ae16f1d427 | tuplehash | miri | tuplehash-staging:655 [extended] | reused | 2026-10-28T23:54:22Z |
| miri-4b2fa7603ef8981e | tuplehash | miri | tuplehash-staging:750 [extended] | reused | 2026-10-28T18:13:42Z |
| miri-4b3d8b2a7715363b | md5 | miri | md5-bulk:158 [extended] | reused | 2026-10-28T11:44:07Z |
| miri-4b3fe0721e0b7a00 | md5 | miri | md5-bulk:214 [extended] | reused | 2026-10-28T11:49:01Z |
| miri-4b4f9ecab55091cf | sha1 | miri | sha1-padding:63 [routine] | passed | 2026-10-19T11:28:45Z |
| miri-4b6283380ee49638 | kmac | miri | kmac-streamed-setup:81 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-4b76ed11f6bb7483 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-official:0 [extended] | passed | 2026-10-29T14:10:51Z |
| miri-4b77b6cc5a2f345d | parallelhash | miri | hardened_in_place::tests::scoped_parallel256_lifecycle [routine] | No mapped observation | — |
| miri-4b9fc8fbc7a2be50 | md5 | miri | md5-batch-mask:235 [extended] | reused | 2026-10-28T12:26:01Z |
| miri-4ba7594fd04d8f5a | md5 | miri | md5-batch-mask:107 [extended] | reused | 2026-10-28T12:15:28Z |
| miri-4bc9325442af7b71 | sha1 | miri | sha1-scoped:118 [extended] | reused | 2026-10-28T13:11:28Z |
| miri-4bcb0f78a4d7ed41 | md5 | miri | md5-scoped:208 [routine] | passed | 2026-10-19T11:32:51Z |
| miri-4bd52419ab5ea630 | md5 | miri | md5-bulk:118 [extended] | reused | 2026-10-28T11:40:48Z |
| miri-4bf3b5c9d5e387f2 | md5 | miri | md5-padding:78 [extended] | reused | 2026-10-28T11:23:47Z |
| miri-4bf7d411bb5638d3 | sha1 | miri | sha1-bulk:160 [extended] | reused | 2026-10-28T12:51:56Z |
| miri-4bf9f3d8cfd2ee69 | sha1 | miri | sha1-scoped:30 [extended] | reused | 2026-10-28T13:04:57Z |
| miri-4c09f0d5e23e0e0a | sha3 | miri | sha3-fixed-bits:12 [routine] | passed | 2026-10-19T11:38:22Z |
| miri-4c0eb66b0bb8b217 | parallelhash | miri | hardened_in_place::tests::scoped_parallel256_lifecycle [extended] | passed | 2026-10-29T15:11:55Z |
| miri-4c15a9c0748b276a | kmac | miri | kmac-streamed-setup:54 [routine] | No mapped observation | — |
| miri-4c53a7a5a5a79dc6 | sha1 | miri | sha1-scoped:76 [extended] | reused | 2026-10-28T13:09:39Z |
| miri-4c60a98507847af7 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:36 [routine] | No mapped observation | — |
| miri-4c682c50cc05aafc | tuplehash | miri | tuplehash-staging:167 [extended] | reused | 2026-10-28T21:10:41Z |
| miri-4c6ea5e787875b11 | md5 | miri | md5-padding:62 [extended] | reused | 2026-10-28T11:22:28Z |
| miri-4c759b1871ff32c7 | sha3 | miri | sha3-fixed-bits:2 [routine] | passed | 2026-10-19T11:38:23Z |
| miri-4c893a45ce143a57 | md5 | miri | md5-batch-mask:148 [extended] | reused | 2026-10-28T12:24:14Z |
| miri-4cabf34bc190544c | sha1 | miri | sha1-padding:92 [extended] | reused | 2026-10-28T12:42:23Z |
| miri-4cb44261eabe11a8 | md5 | miri | md5-batch-mask:188 [extended] | reused | 2026-10-28T12:27:26Z |
| miri-4cb91d66e0478625 | md5 | miri | md5-scoped:247 [extended] | reused | 2026-10-28T12:04:21Z |
| miri-4cd1e907ba12b4d7 | sha1 | miri | sha1-bulk:195 [extended] | reused | 2026-10-28T13:03:03Z |
| miri-4ce36f7b3e709b3a | sha1 | miri | sha1-bulk:168 [extended] | reused | 2026-10-28T12:52:44Z |
| miri-4cea0ee1a8353706 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:2:width=4 [extended] | reused | 2026-10-28T21:56:04Z |
| miri-4ced80506bddde68 | md5 | miri | md5-batch-mask:23 [extended] | reused | 2026-10-28T12:08:56Z |
| miri-4cf14f50fb9bc3e6 | sha1 | miri | sha1-padding:68 [extended] | reused | 2026-10-28T12:39:57Z |
| miri-4d0be24b51101c25 | tuplehash | miri | scoped_tuplexof256_differential:6 [routine] | passed | 2026-10-19T12:25:23Z |
| miri-4d0dcd5706722a33 | md5 | miri | md5-padding:45 [extended] | reused | 2026-10-28T11:30:52Z |
| miri-4d2afa9b1ec4d81c | sha1 | miri | sha1-bulk:129 [extended] | reused | 2026-10-28T13:00:45Z |
| miri-4d37b9b257fae2d4 | sha1 | miri | sha1-scoped:189 [extended] | reused | 2026-10-28T13:24:40Z |
| miri-4d405f8cf6fa8cbf | sha1 | miri | sha1-bulk:120 [extended] | reused | 2026-10-28T12:48:01Z |
| miri-4d4ac6fc9122729a | md5 | miri | md5-scoped:223 [extended] | reused | 2026-10-28T12:02:35Z |
| miri-4d4d1e0ecec388f3 | tuplehash | miri | tuplehash-staging:87 [extended] | reused | 2026-10-28T20:43:44Z |
| miri-4d5af37304fb2319 | md5 | miri | md5-scoped:190 [extended] | reused | 2026-10-28T12:11:13Z |
| miri-4d63996df3fce9f4 | tuplehash | miri | tuplehash-staging:840 [extended] | reused | 2026-10-28T18:39:27Z |
| miri-4d6c1dcdb0180717 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:25:width=1 [extended] | reused | 2026-10-29T02:33:53Z |
| miri-4d8c33877408fcf5 | md5 | miri | md5-padding:74 [extended] | reused | 2026-10-28T11:23:27Z |
| miri-4d91e6e81ecc1aa8 | md5 | miri | md5-scoped:56 [extended] | reused | 2026-10-28T11:56:43Z |
| miri-4da8854c94e688d5 | tuplehash | miri | tuplehash-staging:385 [extended] | reused | 2026-10-28T16:29:50Z |
| miri-4dbba98b907ef136 | sha1 | miri | sha1-bulk:2 [extended] | reused | 2026-10-28T12:40:49Z |
| miri-4dc21fe4ec8b43e4 | tuplehash | miri | tuplehash-staging:638 [extended] | reused | 2026-10-28T17:37:53Z |
| miri-4dd531a62150df77 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-faults:3 [routine] | No mapped observation | — |
| miri-4dded38fc4e48a56 | md5 | miri | md5-batch-mask:93 [extended] | reused | 2026-10-28T12:14:34Z |
| miri-4de896dc111347eb | sha1 | miri | sha1-bulk:124 [extended] | reused | 2026-10-28T12:48:21Z |
| miri-4df7587600c1ba94 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:13:width=1 [extended] | reused | 2026-10-29T04:44:00Z |
| miri-4e02a1edea1966af | md5 | miri | md5-batch-mask:136 [extended] | reused | 2026-10-28T12:23:17Z |
| miri-4e04e6835f33ac30 | legacy_hmac | miri | md5_long [existing-full] | No mapped observation | — |
| miri-4e1333f75ddb22ba | md5 | miri | md5-scoped:113 [extended] | reused | 2026-10-28T11:55:10Z |
| miri-4e2051d9301d1f21 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:47:width=3 [extended] | reused | 2026-10-28T21:37:27Z |
| miri-4e460a26b9caf5d1 | tuplehash | miri | scoped_tuplexof128_differential:19:width=2 [extended] | reused | 2026-10-29T01:48:20Z |
| miri-4e47ab1747e0a052 | md5 | miri | md5-bulk:173 [extended] | reused | 2026-10-28T11:40:08Z |
| miri-4e5adbe6af736ead | md5 | miri | md5-bulk:201 [extended] | reused | 2026-10-28T11:42:24Z |
| miri-4e5c696b73b5c0a0 | kmac | miri | kmac-streamed-setup:27 [routine] | No mapped observation | — |
| miri-4e6b012f73ec1b2c | tuplehash | miri | scoped_tuplexof256_differential:26:width=2 [extended] | reused | 2026-10-29T03:06:14Z |
| miri-4e812069219de199 | md5 | miri | md5-bulk:120 [extended] | reused | 2026-10-28T11:45:54Z |
| miri-4e8e0a91c143626f | kmac | miri | kmac-streamed-setup:2 [routine] | No mapped observation | — |
| miri-4e9162406f6dcf51 | tuplehash | miri | tuplehash-staging:189 [extended] | reused | 2026-10-28T15:24:06Z |
| miri-4e93e21846ef4ee2 | md5 | miri | md5-batch-mask:79 [extended] | reused | 2026-10-28T12:13:15Z |
| miri-4ea830e73bed25b8 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:28:width=2 [extended] | reused | 2026-10-28T20:23:14Z |
| miri-4eb71b289757a3a6 | tuplehash | miri | tuplehash-staging:32 [extended] | reused | 2026-10-28T14:18:55Z |
| miri-4eb940baa86cc28a | sha1 | miri | sha1-bulk:64 [routine] | passed | 2026-10-19T11:31:15Z |
| miri-4eb9588dc96c49ae | tuplehash | miri | tuple_boundaries_order_and_empty_items_are_distinct [extended] | reused | 2026-10-29T04:06:35Z |
| miri-4ecec7f47377512a | kmac | miri | kmac-streamed-setup:6 [routine] | No mapped observation | — |
| miri-4ed2d3638bd6024c | md5 | miri | md5-batch-mask:241 [extended] | reused | 2026-10-28T12:26:27Z |
| miri-4ed489cefad090f5 | kmac | miri | kmac-streamed-setup:55 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-4edbcfe6e0fff52d | md5 | miri | md5-scoped:233 [extended] | reused | 2026-10-28T12:03:36Z |
| miri-4edf0e3e061e3e85 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-official:1 [extended] | passed | 2026-10-29T13:57:04Z |
| miri-4efdbf570504780b | md5 | miri | md5-scoped:182 [extended] | reused | 2026-10-28T12:10:37Z |
| miri-4f09987e6e796e50 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:28 [extended] | passed | 2026-10-29T13:36:58Z |
| miri-4f0b84b6ca34153e | sha1 | miri | sha1-bulk:163 [extended] | reused | 2026-10-28T12:59:33Z |
| miri-4f190d8c23d28c0e | parallelhash | miri | -p brynja-hash-parallel --tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-4f1d7851e69eef92 | sha1 | miri | sha1-scoped:230 [extended] | reused | 2026-10-28T13:20:32Z |
| miri-4f25a79530a82611 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:18 [routine] | No mapped observation | — |
| miri-4f3bd19e5dc173ba | tuplehash | miri | tuplehash-staging:384 [routine] | passed | 2026-10-19T11:47:12Z |
| miri-4f555fd47e23952b | md5 | miri | md5-scoped:206 [extended] | reused | 2026-10-28T12:12:22Z |
| miri-4f60da3409de58b5 | kmac | miri | kmac-framing:5 [extended] | reused | 2026-10-28T19:47:53Z |
| miri-4f60fe7ded06b0e3 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:33 [extended] | passed | 2026-10-29T14:10:50Z |
| miri-4f7d0a7b236962be | sha1 | miri | sha1-scoped:135 [extended] | reused | 2026-10-28T13:25:43Z |
| miri-4f8b17c35abc88fe | md5 | miri | md5-batch-mask:77 [extended] | reused | 2026-10-28T12:13:18Z |
| miri-4f923b3d064db838 | tuplehash | miri | tuplehash-staging:758 [extended] | reused | 2026-10-28T18:16:39Z |
| miri-4f99695adfcb712e | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:31 [extended] | passed | 2026-10-29T13:54:16Z |
| miri-4fa182d3ed0e91b9 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:52:width=3 [extended] | reused | 2026-10-28T21:49:46Z |
| miri-4fa1ad1e3d6ffba4 | kmac | miri | kmac-scoped-xof-lifecycle:12 [extended] | reused | 2026-10-28T13:59:06Z |
| miri-4fb995320b9a6dd6 | sha1 | miri | sha1-padding:114 [extended] | reused | 2026-10-28T12:49:24Z |
| miri-4fbd7cd4dd945e5e | md5 | miri | md5-bulk:96 [extended] | reused | 2026-10-28T11:44:07Z |
| miri-4fda4fb0ebf2912a | sha1 | miri | sha1-bulk:110 [extended] | reused | 2026-10-28T12:48:46Z |
| miri-4ff7079ef062706a | kmac | miri | kmac-streamed-setup:44 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-4ff7b738054b175b | sha1 | miri | sha1-bulk:193 [routine] | passed | 2026-10-19T11:29:36Z |
| miri-4ff89a01c6ca9e54 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:294 [routine] | No mapped observation | — |
| miri-50011837be87fe57 | md5 | miri | md5-scoped:198 [extended] | reused | 2026-10-28T12:11:47Z |
| miri-50390a941426e139 | sha1 | miri | sha1-bulk:29 [extended] | reused | 2026-10-28T12:52:49Z |
| miri-503c17017e2f76e3 | tuplehash | miri | tuplehash-staging:724 [extended] | reused | 2026-10-28T18:02:43Z |
| miri-5046cfa1dc793ba5 | md5 | miri | md5-padding:50 [extended] | reused | 2026-10-28T11:21:32Z |
| miri-504f449c65955bb5 | kmac | miri | kmac-official:1 [extended] | reused | 2026-10-28T14:12:03Z |
| miri-505fd5084dcd3603 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:31:width=2 [extended] | reused | 2026-10-28T20:52:30Z |
| miri-50609f15e977f3f6 | tuplehash | miri | scoped_tuplexof128_differential:5:width=2 [extended] | reused | 2026-10-29T07:15:40Z |
| miri-50651d1e2f21100b | sha1 | miri | sha1-scoped:5 [extended] | reused | 2026-10-28T13:11:06Z |
| miri-5069b5ce60ebbf01 | tuplehash | miri | tuplehash-staging:45 [extended] | reused | 2026-10-28T14:36:12Z |
| miri-506e5b151df89333 | tuplehash | miri | scoped_tuplexof256_differential:42:width=2 [extended] | reused | 2026-10-29T03:47:02Z |
| miri-50721109b7855295 | md5 | miri | md5-batch-mask:27 [extended] | reused | 2026-10-28T12:09:13Z |
| miri-5086bbec77ce6e45 | tuplehash | miri | tuplehash-staging:681 [extended] | reused | 2026-10-28T18:08:58Z |
| miri-5097c6b57bf6e2a9 | sha3 | miri | fixed_output_failure_is_atomic_by_classification [routine] | passed | 2026-10-19T11:36:42Z |
| miri-50a1a8b3fb8eaa88 | sha3 | miri | sha3-secret-xof-bits:4 [routine] | passed | 2026-10-19T11:39:44Z |
| miri-50b1733c8e0ef1bd | tuplehash | miri | scoped_tuplexof256_differential:16:width=1 [extended] | reused | 2026-10-29T02:47:58Z |
| miri-50bb91f731e8f34f | sha1 | miri | sha1-padding:81 [extended] | reused | 2026-10-28T12:34:45Z |
| miri-50bbeb5e07b50763 | parallelhash | miri | -p brynja-hash-parallel --tests [remaining suite; inspect skips with show] | passed | 2026-10-29T12:30:40Z |
| miri-50c5a8200e5d7867 | md5 | miri | md5-bulk:83 [extended] | reused | 2026-10-28T11:33:38Z |
| miri-50c724899e2fd732 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:32:width=1 [extended] | reused | 2026-10-28T20:32:25Z |
| miri-50e263cd83363e58 | tuplehash | miri | tuplehash-staging:589 [extended] | reused | 2026-10-28T17:37:36Z |
| miri-511277945d0df877 | tuplehash | miri | tuplehash-staging:39 [extended] | reused | 2026-10-28T20:27:19Z |
| miri-51203fb53b4d453c | tuplehash | miri | tuplehash-staging:874 [extended] | reused | 2026-10-28T18:54:07Z |
| miri-5120a543946db1b0 | tuplehash | miri | scoped_tuplexof256_differential:44:width=4 [extended] | reused | 2026-10-29T03:59:50Z |
| miri-51292b5b0b5ba8c9 | sha1 | miri | -p brynja-legacy-sha1 --test api [remaining suite; inspect skips with show] | passed | 2026-10-19T11:28:29Z |
| miri-513265cc75653fe2 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:54:width=1 [extended] | reused | 2026-10-28T21:49:32Z |
| miri-51587661d83023b7 | tuplehash | miri | scoped_tuplexof128_differential:17:width=1 [extended] | passed | 2026-10-29T10:53:00Z |
| miri-51743aeb300f8945 | tuplehash | miri | tuplehash-staging:381 [extended] | reused | 2026-10-28T16:28:53Z |
| miri-5175fb110b392558 | tuplehash | miri | tuplehash-staging:182 [extended] | reused | 2026-10-28T15:11:18Z |
| miri-517dbcb37d6d4a0f | tuplehash | miri | scoped_tuplexof128_differential:15:width=3 [extended] | reused | 2026-10-29T01:38:34Z |
| miri-518d1709958fcd97 | tuplehash | miri | tuplehash-staging:704 [extended] | reused | 2026-10-28T17:55:56Z |
| miri-51977cc7ef89e7f2 | hmac | miri | sha224 [routine] | No mapped observation | — |
| miri-519ac532f66f5e90 | legacy | miri | --manifest-path assurance/legacy-hash-final/Cargo.toml --no-default-features --lib dynamic_ [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-519e3876c0cf92b2 | md5 | miri | md5-bulk:220 [extended] | reused | 2026-10-28T11:54:27Z |
| miri-519e57ac470dd802 | tuplehash | miri | scoped_tuplexof128_differential:6:width=3 [extended] | reused | 2026-10-29T00:35:44Z |
| miri-519ee61dd1c22f0a | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:46:width=3 [extended] | reused | 2026-10-28T23:33:28Z |
| miri-51a320949dd082d2 | tuplehash | miri | tuplehash-staging:774 [extended] | reused | 2026-10-28T18:21:47Z |
| miri-51a83eb2a23b3a90 | tuplehash | miri | tuplehash-staging:256 [extended] | reused | 2026-10-28T15:31:53Z |
| miri-51a93fd68896280a | md5 | miri | md5-bulk:160 [extended] | reused | 2026-10-28T11:49:09Z |
| miri-51ab2319a7d9de24 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:0:width=0 [extended] | reused | 2026-10-28T19:26:50Z |
| miri-51ae04d42ebe3201 | sha1 | miri | sha1-bulk:231 [extended] | reused | 2026-10-28T13:07:29Z |
| miri-51b5fa39132ed593 | tuplehash | miri | tuplehash-staging:497 [extended] | reused | 2026-10-28T17:07:03Z |
| miri-51ba57dfc9f73c45 | tuplehash | miri | tuplehash-staging:302 [extended] | reused | 2026-10-28T15:49:52Z |
| miri-51bc73159903b7b9 | tuplehash | miri | tuplehash-staging:891 [extended] | reused | 2026-10-29T01:13:57Z |
| miri-51c2889e1aafa6b7 | tuplehash | miri | tuplehash-staging:14 [extended] | reused | 2026-10-28T14:16:28Z |
| miri-51c8cb2c95317d8a | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:17:width=2 [extended] | reused | 2026-10-29T02:14:18Z |
| miri-51d1aba1f70a218b | md5 | miri | md5-scoped:26 [extended] | reused | 2026-10-28T11:59:50Z |
| miri-51f19f0e15ebeaef | tuplehash | miri | tuplehash-staging:146 [extended] | reused | 2026-10-28T14:59:55Z |
| miri-51fbb7d6622cf8cb | tuplehash | miri | tuplehash-staging:458 [extended] | reused | 2026-10-28T16:41:12Z |
| miri-520c710e2b514749 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-slots:0 [extended] | passed | 2026-10-29T15:08:03Z |
| miri-5219b10b572a2c77 | sha1 | miri | sha1-scoped:178 [extended] | reused | 2026-10-28T13:16:19Z |
| miri-521b2d778377cb73 | tuplehash | miri | tuplehash-staging:796 [extended] | reused | 2026-10-28T18:25:25Z |
| miri-5249dd6dd4a368ab | tuplehash | miri | tuplehash-staging:395 [extended] | reused | 2026-10-28T22:27:32Z |
| miri-524ca503856cf09c | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:294 [extended] | passed | 2026-10-29T14:00:34Z |
| miri-524fa81937f62c3c | sha1 | miri | sha1-padding:104 [extended] | reused | 2026-10-28T12:43:34Z |
| miri-52543ef836e914bd | sha1 | miri | sha1-bulk:252 [extended] | reused | 2026-10-28T13:02:13Z |
| miri-52549a87c4be0f14 | tuplehash | miri | tuplehash-staging:415 [extended] | reused | 2026-10-28T22:33:53Z |
| miri-52872bc407351a4b | md5 | miri | md5-batch-mask:2 [routine] | passed | 2026-10-19T11:29:52Z |
| miri-52b0f70aafab06b0 | tuplehash | miri | tuplehash-staging:639 [extended] | reused | 2026-10-28T23:48:58Z |
| miri-52b308e9b70e293b | tuplehash | miri | scoped_tuplexof128_differential:47:width=4 [extended] | reused | 2026-10-29T03:02:30Z |
| miri-52b7ddcda2c9d3f1 | md5 | miri | md5-bulk:57 [extended] | reused | 2026-10-28T11:31:28Z |
| miri-52c358037f99ba7b | sha1 | miri | sha1-padding:4 [extended] | reused | 2026-10-28T12:34:38Z |
| miri-52dbafb2e8289852 | kmac | miri | kmac-framing:7 [extended] | reused | 2026-10-28T14:03:46Z |
| miri-52f58502a12a39d2 | sha1 | miri | sha1-scoped:159 [extended] | reused | 2026-10-28T13:27:34Z |
| miri-52f717a42727efb5 | kmac | miri | kmac-streamed-setup:65 [routine] | No mapped observation | — |
| miri-52ff8daf9eae0370 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-order:1 [extended] | passed | 2026-10-29T15:09:39Z |
| miri-530fe03283c8264a | md5 | miri | md5-batch-mask:28 [extended] | reused | 2026-10-28T12:15:02Z |
| miri-53157aa0dd6c3424 | tuplehash | miri | tuplehash-staging:680 [extended] | reused | 2026-10-28T17:47:53Z |
| miri-531ccb941625c09a | sha3 | miri | sha3-fixed-boundaries:20 [extended] | reused | 2026-10-28T13:47:19Z |
| miri-531e6fbce0528bdc | md5 | miri | md5-batch-mask:163 [extended] | reused | 2026-10-28T12:20:04Z |
| miri-53328b5c1e386466 | sha1 | miri | sha1-padding:67 [extended] | reused | 2026-10-28T12:34:53Z |
| miri-5349d67829f7534e | md5 | miri | md5-batch-mask:135 [extended] | reused | 2026-10-28T12:17:43Z |
| miri-5362c53c4fda620d | sha1 | miri | sha1-scoped:60 [extended] | reused | 2026-10-28T13:08:29Z |
| miri-5362fa023bb9c3f8 | tuplehash | miri | scoped_tuplexof256_differential:14:width=3 [extended] | reused | 2026-10-29T02:37:48Z |
| miri-538c6689e61b91f7 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:11:width=0 [extended] | reused | 2026-10-28T22:46:21Z |
| miri-53b7407719170799 | md5 | miri | md5-padding:1 [routine] | passed | 2026-10-19T11:28:36Z |
| miri-53c2d26f33afaa4a | tuplehash | miri | tuplehash-staging:727 [extended] | reused | 2026-10-29T00:19:03Z |
| miri-53c37c56969babb8 | tuplehash | miri | tuplehash-staging:407 [extended] | reused | 2026-10-28T22:30:47Z |
| miri-53c8b546160f4107 | tuplehash | miri | tuplehash-staging:338 [extended] | reused | 2026-10-28T16:02:04Z |
| miri-53d5e6230c8efbf2 | tuplehash | miri | tuplehash-staging:701 [extended] | reused | 2026-10-28T18:15:17Z |
| miri-53e5d7ea1b192497 | kmac | miri | -p brynja-mac-kmac --features hardened-execution --lib execution [remaining suite; inspect skips with show] | passed | 2026-10-29T10:40:43Z |
| miri-53fb46fc067fda35 | md5 | miri | md5-batch-mask:174 [extended] | reused | 2026-10-28T12:31:45Z |
| miri-53fea883f3425a5e | tuplehash | miri | scoped_tuplexof128_differential:27 [routine] | passed | 2026-10-19T12:33:01Z |
| miri-54093f4c6f6629dd | tuplehash | miri | tuplehash-staging:190 [extended] | reused | 2026-10-28T15:13:30Z |
| miri-5428f8bde4e9ebb3 | tuplehash | miri | tuplehash-staging:590 [extended] | reused | 2026-10-28T17:22:51Z |
| miri-54305a3c6ce5ac8d | sha1 | miri | sha1-bulk:111 [extended] | reused | 2026-10-28T12:54:23Z |
| miri-5438fb281656214b | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:30 [extended] | passed | 2026-10-29T15:01:56Z |
| miri-543f60a7be84a8c2 | tuplehash | miri | tuplehash-staging:799 [extended] | reused | 2026-10-29T00:42:33Z |
| miri-544f2fc553245c88 | tuplehash | miri | scoped_tuplexof256_differential:39:width=3 [extended] | reused | 2026-10-29T04:28:59Z |
| miri-54646e7c80dc5a83 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:21:width=1 [extended] | reused | 2026-10-29T02:24:05Z |
| miri-546ca48a904d1fc8 | tuplehash | miri | tuplehash-staging:273 [extended] | reused | 2026-10-28T15:52:07Z |
| miri-54715eb314408047 | md5 | miri | md5-batch-mask:52 [extended] | reused | 2026-10-28T12:16:50Z |
| miri-5481d680d1169fa4 | tuplehash | miri | tuplehash-staging:720 [extended] | reused | 2026-10-28T18:01:26Z |
| miri-54862e459206c44c | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:18:width=3 [extended] | reused | 2026-10-28T22:24:48Z |
| miri-548865c24bb65b53 | md5 | miri | md5-bulk:222 [extended] | reused | 2026-10-28T11:49:43Z |
| miri-548d002fa21c71b9 | sha1 | miri | sha1-bulk:241 [extended] | reused | 2026-10-28T13:13:33Z |
| miri-54b3ffef4d5a0075 | md5 | miri | md5-batch-mask:116 [extended] | reused | 2026-10-28T12:21:43Z |
| miri-54b72ce332891ff2 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:31:width=2 [extended] | reused | 2026-10-28T23:32:36Z |
| miri-54bbc4f9102e1f34 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-official:5 [extended] | passed | 2026-10-29T13:58:46Z |
| miri-54d43af987abbb0d | sha3 | miri | recoverable_unwind_clears_typed_secret_destination [routine] | passed | 2026-10-19T11:31:48Z |
| miri-54d9f9fd04cc58a2 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:23:width=0 [extended] | reused | 2026-10-28T20:32:45Z |
| miri-54e2e323785081e5 | tuplehash | miri | tuplehash-staging:99 [extended] | reused | 2026-10-28T20:46:59Z |
| miri-54e43446abba3379 | md5 | miri | md5-padding:24 [extended] | reused | 2026-10-28T11:19:48Z |
| miri-54fcc32ef7c0faa1 | md5 | miri | md5-scoped:111 [extended] | reused | 2026-10-28T11:54:46Z |
| miri-54ff2dacffbca190 | sha3 | miri | sha3-fixed-boundaries:31 [extended] | reused | 2026-10-28T13:40:21Z |
| miri-5505c2b234128c4b | tuplehash | miri | tuplehash-staging:741 [extended] | reused | 2026-10-28T18:29:35Z |
| miri-5509fd65ee93510b | tuplehash | miri | tuplehash-staging:846 [extended] | reused | 2026-10-28T18:45:09Z |
| miri-5549887c638600e6 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:25:width=4 [extended] | reused | 2026-10-29T05:13:15Z |
| miri-55741d76af83a71c | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:36:width=0 [extended] | reused | 2026-10-28T20:41:38Z |
| miri-559a3d0519c2fc14 | md5 | miri | md5-padding:4 [extended] | reused | 2026-10-28T11:18:19Z |
| miri-559e43d270cd8e6d | tuplehash | miri | scoped_tuplexof128_differential:1:width=1 [extended] | reused | 2026-10-29T07:08:40Z |
| miri-55b689a9adcb36c1 | sha3 | miri | bit_input_and_bit_output_match_both_ordinary_xofs [routine] | passed | 2026-10-19T11:41:00Z |
| miri-55b8f03a9f834bf6 | tuplehash | miri | tuplehash-staging:888 [extended] | reused | 2026-10-28T18:55:12Z |
| miri-55ca783f0317b472 | tuplehash | miri | tuplehash-staging:68 [extended] | reused | 2026-10-28T14:30:31Z |
| miri-55e36dca031d03ff | md5 | miri | -p brynja-legacy-md5 --features execution --test execution callback_unwind_is_terminal_and_transactional [remaining suite; inspect skips with show] | reused | 2026-10-28T11:17:43Z |
| miri-55fb2718d1f822b0 | tuplehash | miri | tuplehash-staging:821 [extended] | reused | 2026-10-28T18:56:07Z |
| miri-55fe83bd4da5adea | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:4 [routine] | No mapped observation | — |
| miri-55feaf6a23a9e28f | md5 | miri | md5-bulk:247 [extended] | reused | 2026-10-28T11:46:43Z |
| miri-5605118123bffa47 | sha1 | miri | -p brynja-legacy-sha1 --features hardened-execution --lib cpu::secret::tests [remaining suite; inspect skips with show] | reused | 2026-10-28T12:27:45Z |
| miri-5614f7094a2545c0 | tuplehash | miri | scoped_tuplexof128_differential:31:width=2 [extended] | reused | 2026-10-29T02:17:45Z |
| miri-5617697a60748ffe | sha3 | miri | -p brynja-crypto-cpu-std --features sponge-execution --lib sponge::tests::portable_sponge [remaining suite; inspect skips with show] | reused | 2026-10-28T13:29:08Z |
| miri-5626143c596a7434 | sha1 | miri | sha1-scoped:66 [routine] | passed | 2026-10-19T11:17:01Z |
| miri-562cbae7645a64d8 | tuplehash | miri | scoped_tuplexof256_differential:36 [routine] | passed | 2026-10-19T12:15:09Z |
| miri-563a945a7fe07ffe | tuplehash | miri | tuplehash-staging:787 [extended] | reused | 2026-10-29T00:39:18Z |
| miri-565a0bf31dda4d7a | sha1 | miri | sha1-scoped:42 [extended] | reused | 2026-10-28T13:05:47Z |
| miri-565bcb3f8bb060c5 | md5 | miri | -p brynja-legacy-md5 --features hardened-execution --lib cpu::scratch::tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-568687b0f76934cd | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:11:width=3 [extended] | reused | 2026-10-28T20:06:05Z |
| miri-568f07cfed917c13 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:0:width=3 [extended] | reused | 2026-10-28T21:56:20Z |
| miri-5692d7716e6ece68 | tuplehash | miri | scoped_tuplexof256_differential:3:width=0 [extended] | reused | 2026-10-29T03:09:31Z |
| miri-56a198bc3ee30fbb | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:45:width=1 [extended] | reused | 2026-10-29T06:07:36Z |
| miri-56b23b9686fef103 | tuplehash | miri | scoped_tuplexof256_differential:9 [routine] | passed | 2026-10-19T16:17:11Z |
| miri-56ce50268d013266 | tuplehash | miri | tuplehash-staging:150 [extended] | reused | 2026-10-28T15:01:13Z |
| miri-56d2cec5399ab0a9 | tuplehash | miri | tuplehash-staging:531 [extended] | reused | 2026-10-28T23:12:58Z |
| miri-56d6c407aab922eb | md5 | miri | md5-bulk:6 [extended] | reused | 2026-10-28T11:32:49Z |
| miri-56da187d95176184 | tuplehash | miri | scoped_tuplexof256_differential:25:width=2 [extended] | passed | 2026-10-29T12:35:06Z |
| miri-56ea8513b0e0119f | kmac | miri | kmac-streamed-setup:95 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-56ff2f539b21d01d | tuplehash | miri | tuplehash-staging:726 [extended] | reused | 2026-10-28T18:06:24Z |
| miri-56ff999bca070a5b | md5 | miri | md5-batch-mask:0 [extended] | reused | 2026-10-28T12:13:02Z |
| miri-57007a9a8aa2eadd | md5 | miri | md5-scoped:244 [extended] | reused | 2026-10-28T12:09:50Z |
| miri-57058a6129d39970 | md5 | miri | md5-scoped:120 [extended] | reused | 2026-10-28T12:01:09Z |
| miri-571230c72264cbb8 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:39:width=1 [extended] | reused | 2026-10-28T21:12:11Z |
| miri-5721c6291370d90e | kmac | miri | kmac-streamed-setup:31 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-572d774cf233a362 | kmac | miri | kmac-framing:3 [extended] | reused | 2026-10-28T14:02:46Z |
| miri-572e3c7649539515 | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib only_pre_entry_thread_errors_are_reusable [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-572fb65f88fd72f7 | tuplehash | miri | tuplehash-staging:62 [extended] | reused | 2026-10-28T14:32:17Z |
| miri-5736a717e2155997 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:22:width=4 [extended] | reused | 2026-10-28T22:33:52Z |
| miri-5741a779defebb6a | sha1 | miri | sha1-bulk:171 [extended] | reused | 2026-10-28T13:00:23Z |
| miri-574bf20f33847042 | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib unsupported_target_or_model_never_falls_back [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-574cc17fe141a33f | md5 | miri | md5-bulk:147 [extended] | reused | 2026-10-28T11:38:23Z |
| miri-5782290019a6404c | tuplehash | miri | tuplehash-staging:201 [extended] | reused | 2026-10-28T15:28:08Z |
| miri-578656b79f00dcbb | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:14:width=0 [extended] | reused | 2026-10-28T19:46:05Z |
| miri-579061c92963bdbd | md5 | miri | md5-batch-mask:99 [extended] | reused | 2026-10-28T12:14:50Z |
| miri-57915eac69205a7e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:53:width=0 [extended] | reused | 2026-10-29T07:01:39Z |
| miri-57a169e07c2b7236 | md5 | miri | md5-batch-mask:64 [routine] | passed | 2026-10-19T11:26:55Z |
| miri-57a6a711dfd0e8c1 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:53:width=0 [extended] | reused | 2026-10-29T04:16:00Z |
| miri-57b317889fc7af9c | legacy_hmac | miri | sha1_short [extended] | passed | 2026-10-29T16:04:54Z |
| miri-57b698d720ee80b3 | tuplehash | miri | scoped_tuplexof128_differential:0:width=1 [extended] | passed | 2026-10-29T08:38:40Z |
| miri-57d7787f7c78eb28 | tuplehash | miri | tuplehash-staging:95 [extended] | reused | 2026-10-28T20:46:02Z |
| miri-57ddf660baf5578c | tuplehash | miri | scoped_tuplexof128_differential:30:width=4 [extended] | reused | 2026-10-29T01:26:26Z |
| miri-57f471c331f900e6 | tuplehash | miri | tuplehash-staging:561 [extended] | reused | 2026-10-28T17:28:10Z |
| miri-57fe65213e9922af | sha1 | miri | sha1-bulk:18 [extended] | reused | 2026-10-28T12:41:50Z |
| miri-581aebe7c37954cd | kmac | miri | kmac-scoped-lifecycle:1 [routine] | passed | 2026-10-19T15:29:38Z |
| miri-5826156e99b90dc4 | tuplehash | miri | tuplehash-staging:196 [extended] | reused | 2026-10-28T15:12:27Z |
| miri-5828bb71a3dcfed7 | sha1 | miri | sha1-bulk:182 [extended] | reused | 2026-10-28T12:55:44Z |
| miri-582b28dbc8c9bb92 | md5 | miri | md5-batch-mask:245 [extended] | reused | 2026-10-28T12:26:48Z |
| miri-583e1f9750fd7df2 | sha1 | miri | sha1-scoped:186 [extended] | reused | 2026-10-28T13:16:58Z |
| miri-5846320c032751cd | md5 | miri | md5-scoped:74 [extended] | reused | 2026-10-28T12:03:05Z |
| miri-58467df17d1f58ec | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:19 [routine] | No mapped observation | — |
| miri-5852b217559daea3 | md5 | miri | md5-scoped:3 [extended] | reused | 2026-10-28T11:47:33Z |
| miri-5859bd5a73047c89 | kmac | miri | kmac-scoped-xof-lifecycle:14 [routine] | passed | 2026-10-19T11:39:19Z |
| miri-5884240b5719e43b | tuplehash | miri | tuplehash-staging:103 [extended] | reused | 2026-10-28T20:48:43Z |
| miri-58948d50d014d81b | tuplehash | miri | tuplehash-staging:502 [extended] | reused | 2026-10-28T16:54:38Z |
| miri-5895331081b6aa52 | sha1 | miri | sha1-bulk:120 [routine] | passed | 2026-10-19T11:16:16Z |
| miri-5897264f774890d8 | sha1 | miri | sha1-bulk:200 [extended] | reused | 2026-10-28T12:56:14Z |
| miri-58a113485570f533 | sha1 | miri | sha1-bulk:214 [extended] | reused | 2026-10-28T12:59:16Z |
| miri-58bf9ddf1106238e | tuplehash | miri | tuplehash-staging:378 [extended] | reused | 2026-10-28T16:15:02Z |
| miri-58e6abc1d0c82878 | sha1 | miri | sha1-scoped:140 [extended] | reused | 2026-10-28T13:14:47Z |
| miri-58f27cf58e3b3eae | md5 | miri | md5-scoped:138 [extended] | reused | 2026-10-28T12:07:31Z |
| miri-58f55a1f892b6176 | md5 | miri | md5-bulk:229 [extended] | reused | 2026-10-28T11:44:48Z |
| miri-5901d6ee3c3a13a1 | kmac | miri | kmac-streamed-setup:20 [routine] | No mapped observation | — |
| miri-5904d13ae2100c44 | sha1 | miri | sha1-scoped:49 [extended] | reused | 2026-10-28T13:14:02Z |
| miri-59156e89ca0e3049 | sha1 | miri | sha1-scoped:285 [extended] | reused | 2026-10-28T13:32:39Z |
| miri-5916c605605cece2 | tuplehash | miri | tuplehash-staging:195 [extended] | reused | 2026-10-28T21:20:07Z |
| miri-5917540feaa0863a | kmac | miri | -p brynja-mac-kmac --tests [remaining suite; inspect skips with show] | passed | 2026-10-29T10:42:03Z |
| miri-59224b6eb69c3626 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:19:width=2 [extended] | reused | 2026-10-28T20:22:54Z |
| miri-59336f450bc8caa6 | md5 | miri | md5-batch-mask:187 [extended] | reused | 2026-10-28T12:22:04Z |
| miri-5936dd1aa8b34ddf | tuplehash | miri | tuplehash-staging:834 [extended] | reused | 2026-10-28T18:40:35Z |
| miri-5939871695b0f02a | legacy | miri | --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib dynamic_ [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-594b54817035d8e5 | md5 | miri | -p brynja-legacy-md5 --features hardened-execution --lib cpu::secret::tests [remaining suite; inspect skips with show] | passed | 2026-10-19T11:13:23Z |
| miri-595f73aa0152e171 | tuplehash | miri | scoped_tuplexof128_differential:27:width=1 [extended] | reused | 2026-10-29T02:07:59Z |
| miri-59663d63ce028561 | tuplehash | miri | tuplehash-staging:402 [extended] | reused | 2026-10-28T16:23:05Z |
| miri-596e1aa12977ed2e | sha1 | miri | sha1-bulk:5 [extended] | reused | 2026-10-28T12:51:14Z |
| miri-5985eefacdc2fa96 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:27 [routine] | passed | 2026-10-19T12:29:32Z |
| miri-59a69c9bcfd488c5 | md5 | miri | md5-scoped:92 [extended] | reused | 2026-10-28T11:59:11Z |
| miri-59d12d8b2c6a703e | md5 | miri | md5-padding:94 [extended] | reused | 2026-10-28T11:25:03Z |
| miri-59da2a7356120ce9 | md5 | miri | md5-bulk:208 [extended] | reused | 2026-10-28T11:53:19Z |
| miri-59dd279cbe3cb342 | sha1 | miri | sha1-scoped:20 [extended] | reused | 2026-10-28T13:05:39Z |
| miri-59e30376e30fe07d | sha1 | miri | sha1-scoped:84 [extended] | reused | 2026-10-28T13:10:16Z |
| miri-59f1f4994c43dd10 | tuplehash | miri | tuplehash-staging:79 [extended] | reused | 2026-10-28T20:40:39Z |
| miri-59faf0360eac1fe8 | md5 | miri | md5-batch-mask:193 [extended] | reused | 2026-10-28T12:22:34Z |
| miri-5a019e43d55e466a | tuplehash | miri | scoped_tuplexof128_differential:36 [routine] | passed | 2026-10-19T12:12:55Z |
| miri-5a034c4ac1df5a02 | md5 | miri | md5-batch-mask:36 [extended] | reused | 2026-10-28T12:15:37Z |
| miri-5a0d2a21d7f9d435 | md5 | miri | md5-batch-mask:39 [extended] | reused | 2026-10-28T12:10:10Z |
| miri-5a0e75d033598c88 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:42:width=2 [extended] | reused | 2026-10-28T20:52:59Z |
| miri-5a12e15539f34dac | kmac | miri | kmac-streamed-setup:10 [routine] | No mapped observation | — |
| miri-5a190a257d4a9648 | md5 | miri | md5-bulk:15 [extended] | reused | 2026-10-28T11:29:03Z |
| miri-5a237f09e26ee9e1 | md5 | miri | md5-batch-mask:6 [extended] | reused | 2026-10-28T12:18:41Z |
| miri-5a25b77681955d01 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:41:width=3 [extended] | reused | 2026-10-29T05:55:08Z |
| miri-5a3b4adcc2c04b1a | sha1 | miri | sha1-bulk:169 [extended] | reused | 2026-10-28T13:04:55Z |
| miri-5a46f9ab01b354f3 | sha2 | miri | -p brynja-hash-sha2 --test sha512_256 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-5a50f400e5308991 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:21:width=1 [extended] | reused | 2026-10-29T05:03:33Z |
| miri-5a658ae8340c4701 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:53:width=2 [extended] | reused | 2026-10-29T04:16:00Z |
| miri-5a692af11a597915 | sha1 | miri | sha1-bulk:2 [routine] | passed | 2026-10-19T11:34:42Z |
| miri-5a93a2af76491296 | sha1 | miri | sha1-scoped:207 [extended] | reused | 2026-10-28T13:31:21Z |
| miri-5a9959e0fb6e592b | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:0 [routine] | No mapped observation | — |
| miri-5aa9d49998f40977 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:31 [routine] | No mapped observation | — |
| miri-5ab5aab5a637d1b6 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:16:width=4 [extended] | reused | 2026-10-28T22:25:09Z |
| miri-5ac3e7ae528f1017 | md5 | miri | md5-batch-mask:186 [extended] | reused | 2026-10-28T12:32:47Z |
| miri-5ad6894263d66e4c | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:46:width=0 [extended] | reused | 2026-10-28T23:33:28Z |
| miri-5ad84625033e9ea4 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-domains:5 [extended] | passed | 2026-10-29T14:17:29Z |
| miri-5ae49bb609e3f0b1 | sha3 | miri | sha3-fixed-bits:6 [extended] | reused | 2026-10-28T13:46:56Z |
| miri-5aec8a7737e56698 | md5 | miri | md5-scoped:224 [extended] | reused | 2026-10-28T12:08:20Z |
| miri-5aed3cba99a1f694 | sha3 | miri | sha3-fixed-boundaries:26 [extended] | reused | 2026-10-28T13:39:25Z |
| miri-5af4601e12f170a3 | tuplehash | miri | tuplehash-staging:525 [extended] | reused | 2026-10-28T17:16:26Z |
| miri-5afb02b2be54161b | tuplehash | miri | tuplehash-staging:887 [extended] | reused | 2026-10-29T01:12:36Z |
| miri-5b017db350b6df75 | kmac | miri | kmacxof-official:5 [routine] | passed | 2026-10-19T15:39:14Z |
| miri-5b01dd5ed0b8750b | sha1 | miri | sha1-scoped:259 [extended] | reused | 2026-10-28T13:35:45Z |
| miri-5b1718d4700624f7 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:18:width=0 [extended] | reused | 2026-10-28T19:55:16Z |
| miri-5b1c46ea515543c7 | kmac | miri | kmac-streamed-setup:61 [routine] | No mapped observation | — |
| miri-5b45962766c99d6d | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:10:width=1 [extended] | reused | 2026-10-28T19:39:30Z |
| miri-5b6889514d549609 | sha3 | miri | sha3-fixed-boundaries:14 [extended] | reused | 2026-10-28T13:38:05Z |
| miri-5b6c920e64e3cb01 | tuplehash | miri | scoped_tuplexof256_differential:5:width=3 [extended] | passed | 2026-10-29T11:55:52Z |
| miri-5b716a32b46c08c9 | tuplehash | miri | scoped_tuplexof256_differential:22:width=1 [extended] | reused | 2026-10-29T02:56:47Z |
| miri-5b7c9c7bf3bb4701 | sha1 | miri | sha1-scoped:117 [extended] | reused | 2026-10-28T13:19:10Z |
| miri-5ba48453d348f806 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:55 [extended] | passed | 2026-10-29T13:56:05Z |
| miri-5ba83d0c71ad2624 | md5 | miri | md5-bulk:26 [extended] | reused | 2026-10-28T11:34:08Z |
| miri-5bd853f45fd15f85 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:9 [extended] | passed | 2026-10-29T13:25:52Z |
| miri-5bf5814203f0cee3 | md5 | miri | md5-padding:49 [extended] | reused | 2026-10-28T11:31:08Z |
| miri-5bfe12a2e9f5b8d9 | tuplehash | miri | scoped_tuplexof128_differential:33:width=3 [extended] | passed | 2026-10-29T11:02:56Z |
| miri-5c03e7a4dff5aa7a | tuplehash | miri | tuplehash-staging:732 [extended] | reused | 2026-10-28T18:04:56Z |
| miri-5c0bed33944dfb3b | hmac | miri | sha512 [routine] | No mapped observation | — |
| miri-5c1486c8a9b2a8a2 | tuplehash | miri | tuplehash-staging:404 [extended] | reused | 2026-10-28T16:19:58Z |
| miri-5c22ac27bc572886 | tuplehash | miri | tuplehash-staging:386 [extended] | reused | 2026-10-28T16:17:13Z |
| miri-5c261b0c82d9f069 | sha3 | miri | sha3-fixed-boundaries:30 [extended] | reused | 2026-10-28T13:40:00Z |
| miri-5c47dcad1ec37c0e | sha1 | miri | sha1-scoped:86 [extended] | reused | 2026-10-28T13:09:00Z |
| miri-5c609229ef8d84bb | md5 | miri | md5-padding:42 [extended] | reused | 2026-10-28T11:20:55Z |
| miri-5c6257b9b9bd1da9 | kmac | miri | kmac-streamed-setup:84 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-5c68dafb39024edc | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:0 [routine] | No mapped observation | — |
| miri-5c6f3b2cb33becd2 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:40:width=2 [extended] | reused | 2026-10-28T20:53:24Z |
| miri-5c6fb12a439f928d | tuplehash | miri | tuplehash-staging:88 [extended] | reused | 2026-10-28T14:37:07Z |
| miri-5c74594b45daa351 | tuplehash | miri | tuplehash-staging:401 [extended] | reused | 2026-10-28T16:35:13Z |
| miri-5c783d9daf137af6 | sha1 | miri | sha1-padding:21 [extended] | reused | 2026-10-28T12:29:45Z |
| miri-5ca0f298635d75f8 | tuplehash | miri | tuplehash-staging:347 [extended] | reused | 2026-10-28T22:10:59Z |
| miri-5cafb61cd328aa80 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:5:width=1 [extended] | reused | 2026-10-29T04:30:03Z |
| miri-5cb376f1d0874b21 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:37 [routine] | No mapped observation | — |
| miri-5cb4973e1851e6ab | tuplehash | miri | tuplehash-staging:533 [extended] | reused | 2026-10-28T17:18:44Z |
| miri-5cb5c17ac39b8490 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:43:width=3 [extended] | reused | 2026-10-29T00:04:50Z |
| miri-5cd030c96fc66741 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:43:width=1 [extended] | reused | 2026-10-29T00:04:50Z |
| miri-5ce3f1c34db57e63 | md5 | miri | md5-bulk:135 [extended] | reused | 2026-10-28T11:37:27Z |
| miri-5cf0fccca51399fb | sha2 | miri | -p brynja-hash-sha2 --features batch-execution --test batch bounded_batch_lifecycle_smoke [remaining suite; inspect skips with show] | reused | 2026-10-28T13:26:39Z |
| miri-5cfc65ffa8e9fdaa | sha1 | miri | sha1-padding:62 [routine] | passed | 2026-10-19T11:30:51Z |
| miri-5d0409100607f51e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:3:width=3 [extended] | reused | 2026-10-28T22:32:17Z |
| miri-5d14a9cbf4902928 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:12:width=1 [extended] | reused | 2026-10-28T19:46:30Z |
| miri-5d2f58fb053c4824 | sha3 | miri | sha3-fixed-bits:1 [routine] | passed | 2026-10-19T11:34:48Z |
| miri-5d3fddb7cc0f827e | sha1 | miri | sha1-bulk:101 [extended] | reused | 2026-10-28T12:58:19Z |
| miri-5d429e498dae0d78 | sha1 | miri | sha1-padding:62 [extended] | reused | 2026-10-28T12:44:19Z |
| miri-5d5867e6226fd3ff | sha1 | miri | sha1-bulk:152 [extended] | reused | 2026-10-28T12:51:09Z |
| miri-5d63a5b3c5dd125c | sha1 | miri | sha1-bulk:108 [extended] | reused | 2026-10-28T12:46:58Z |
| miri-5d98bef3f04fc571 | md5 | miri | md5-scoped:90 [extended] | reused | 2026-10-28T12:04:12Z |
| miri-5db41a585e0fd044 | tuplehash | miri | tuplehash-staging:841 [extended] | reused | 2026-10-28T19:02:28Z |
| miri-5dbc2775aac8718c | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:54:width=3 [extended] | reused | 2026-10-29T00:22:37Z |
| miri-5dc1cbf35272f02b | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:42:width=1 [extended] | reused | 2026-10-28T23:21:51Z |
| miri-5df49080f040352b | tuplehash | miri | tuplehash-staging:513 [extended] | reused | 2026-10-28T17:12:24Z |
| miri-5e01c164c1df0475 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:29:width=1 [extended] | reused | 2026-10-29T05:23:03Z |
| miri-5e213fbfc5be65f4 | tuplehash | miri | tuplehash-staging:153 [extended] | reused | 2026-10-28T15:12:22Z |
| miri-5e3171805bb711de | kmac | miri | kmac-scoped-xof-lifecycle:2 [extended] | reused | 2026-10-28T14:00:44Z |
| miri-5e39911f4d35f16a | tuplehash | miri | scoped_tuplexof256_differential:32:width=4 [extended] | reused | 2026-10-29T03:25:53Z |
| miri-5e48b29832f46f4f | sha1 | miri | sha1-scoped:92 [extended] | reused | 2026-10-28T13:10:55Z |
| miri-5e500da0c0849060 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:19:width=4 [extended] | reused | 2026-10-28T20:22:54Z |
| miri-5e5d4687cf01e41d | sha3 | miri | -p brynja-hash-sha3 --lib borrowing_reader_never_extracts_the_absorbing_owner [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-5e71b90006933c35 | md5 | miri | md5-scoped:121 [extended] | reused | 2026-10-28T11:55:43Z |
| miri-5ebbecc48a6d1afb | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:4:width=4 [extended] | reused | 2026-10-28T19:33:24Z |
| miri-5ec78a81af511e2c | sha1 | miri | sha1-scoped:144 [extended] | reused | 2026-10-28T13:15:07Z |
| miri-5ecd095041a9a2f4 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:23:width=2 [extended] | reused | 2026-10-28T23:12:58Z |
| miri-5edfd8a77f329937 | tuplehash | miri | tuplehash-staging:308 [extended] | reused | 2026-10-28T15:48:48Z |
| miri-5ee58237701ab837 | tuplehash | miri | scoped_tuplexof256_differential:20:width=3 [extended] | reused | 2026-10-29T02:57:28Z |
| miri-5eef61e2ff88eecb | sha1 | miri | sha1-bulk:140 [extended] | reused | 2026-10-28T12:49:59Z |
| miri-5ef316f08da0266c | md5 | miri | md5-batch-mask:108 [extended] | reused | 2026-10-28T12:21:03Z |
| miri-5f14c5d0b2f7faee | kmac | miri | kmac-streamed-setup:9 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-5f184b5fb0d65dae | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:32:width=2 [extended] | reused | 2026-10-28T20:32:25Z |
| miri-5f1efd0c5f11d297 | md5 | miri | md5-batch-mask:170 [routine] | passed | 2026-10-19T11:27:01Z |
| miri-5f2e83a3e2bcd75e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:9:width=2 [extended] | reused | 2026-10-29T04:37:02Z |
| miri-5f36d6b359bd41e5 | sha1 | miri | sha1-padding:82 [extended] | reused | 2026-10-28T12:46:12Z |
| miri-5f3d9dce0c26ff5c | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:55:width=1 [extended] | reused | 2026-10-28T22:25:13Z |
| miri-5f3e6cfc651403b2 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:28:width=0 [extended] | reused | 2026-10-28T20:23:14Z |
| miri-5f40088fc750e583 | tuplehash | miri | tuplehash-staging:742 [extended] | reused | 2026-10-28T18:11:31Z |
| miri-5f48d3f02fe3fe83 | sha1 | miri | sha1-bulk:62 [extended] | reused | 2026-10-28T12:44:39Z |
| miri-5f491e632ce7151b | kmac | miri | kmac-streamed-setup:48 [routine] | No mapped observation | — |
| miri-5f4ce7ae1854d5c5 | tuplehash | miri | tuplehash-staging:744 [extended] | reused | 2026-10-28T18:08:46Z |
| miri-5f5b28d6d1cb33f2 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:16:width=4 [extended] | reused | 2026-10-28T19:55:42Z |
| miri-5f6c778de039a068 | md5 | miri | md5-padding:7 [extended] | reused | 2026-10-28T11:24:06Z |
| miri-5f6f83c563318309 | tuplehash | miri | tuplehash-execution-fixed:9 [extended] | reused | 2026-10-28T19:36:04Z |
| miri-5f84fec434cfd8f5 | sha1 | miri | sha1-bulk:213 [extended] | reused | 2026-10-28T13:09:57Z |
| miri-5f96807c3dc7faf0 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:48:width=4 [extended] | reused | 2026-10-28T23:58:48Z |
| miri-5f96db4995e1cc78 | kmac | miri | kmac-streamed-setup:44 [routine] | No mapped observation | — |
| miri-5fa828083c987ca6 | tuplehash | miri | tuplehash-staging:625 [extended] | reused | 2026-10-28T17:50:07Z |
| miri-5fad739b381896b6 | tuplehash | miri | scoped_tuplexof256_differential:11:width=3 [extended] | reused | 2026-10-29T03:23:30Z |
| miri-5fc810f9177e76bd | tuplehash | miri | tuplehash-staging:773 [extended] | reused | 2026-10-28T18:40:21Z |
| miri-5fcd3d5d51805385 | tuplehash | miri | scoped_tuplexof256_differential:32:width=0 [extended] | reused | 2026-10-29T03:25:53Z |
| miri-5fdb9ea946b577bd | md5 | miri | md5-batch-mask:31 [extended] | reused | 2026-10-28T12:09:33Z |
| miri-5fee6b4c1b12fc3d | md5 | miri | md5-scoped:77 [extended] | reused | 2026-10-28T11:52:42Z |
| miri-5ff68d5174ee5cb0 | kmac | miri | kmac-streamed-setup:88 [routine] | No mapped observation | — |
| miri-6009a0ef5c9dda85 | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib only_pre_entry_thread_errors_are_reusable [remaining suite; inspect skips with show] | passed | 2026-10-29T15:09:16Z |
| miri-600acfa9e8190fde | tuplehash | miri | scoped_tuplexof256_differential:19:width=1 [extended] | reused | 2026-10-29T03:40:19Z |
| miri-6013f34842aac43c | md5 | miri | md5-bulk:1 [routine] | passed | 2026-10-19T11:32:14Z |
| miri-6032358714562ca5 | tuplehash | miri | scoped_tuplexof128_differential:26:width=4 [extended] | reused | 2026-10-29T01:16:55Z |
| miri-604038dffdf2ed53 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:35:width=3 [extended] | reused | 2026-10-28T21:02:20Z |
| miri-6044ecb19ff29541 | md5 | miri | md5-batch-mask:4 [extended] | reused | 2026-10-28T12:13:18Z |
| miri-604bb80cf58f388a | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:6 [extended] | passed | 2026-10-29T12:39:24Z |
| miri-6056e8b23aab50d6 | tuplehash | miri | tuplehash-staging:226 [extended] | reused | 2026-10-28T15:25:29Z |
| miri-605cf5b1962dc2d7 | tuplehash | miri | tuplehash-staging:721 [extended] | reused | 2026-10-28T18:22:26Z |
| miri-606f9a19d6a88d73 | tuplehash | miri | tuplehash-staging:674 [extended] | reused | 2026-10-28T17:49:45Z |
| miri-6070c86728b7e754 | tuplehash | miri | tuplehash-staging:16 [extended] | reused | 2026-10-28T14:13:47Z |
| miri-609cfb691fa44d37 | md5 | miri | -p brynja-legacy-md5 --features hardened-execution --lib cpu::secret::tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-60aacd5cbb256ac9 | sha3 | miri | -p brynja-crypto-cpu --features hardened-execution --lib hardened_execution::keccak::tests::all_seven_regions_clear [remaining suite; inspect skips with show] | reused | 2026-10-28T13:34:55Z |
| miri-60b45e354b43b237 | md5 | miri | md5-batch-mask:84 [extended] | reused | 2026-10-28T12:19:14Z |
| miri-60b52939747b1867 | md5 | miri | md5-batch-mask:43 [extended] | reused | 2026-10-28T12:10:29Z |
| miri-60be23f5b246dc05 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:0:width=2 [extended] | reused | 2026-10-28T21:56:20Z |
| miri-60d2f92b6330c98a | tuplehash | miri | scoped_tuplexof128_differential:22:width=3 [extended] | reused | 2026-10-29T01:07:25Z |
| miri-60db1c4d944aac2e | md5 | miri | md5-padding:18 [extended] | reused | 2026-10-28T11:19:08Z |
| miri-60e4a36e0faa078c | tuplehash | miri | tuplehash-staging:865 [extended] | reused | 2026-10-28T19:10:56Z |
| miri-60e83706a1d68d37 | sha3 | miri | -p brynja-hash-sha3 --test sha3_512 suffix_and_rate_boundaries_have_exact_digests [remaining suite; inspect skips with show] | reused | 2026-10-28T13:35:38Z |
| miri-6101f06af6250316 | kmac | miri | kmac-scoped-xof-lifecycle:0 [extended] | reused | 2026-10-28T13:55:22Z |
| miri-610ed4f09b4dd3eb | md5 | miri | md5-padding:37 [extended] | reused | 2026-10-28T11:30:20Z |
| miri-6117c47373d6d4f6 | tuplehash | miri | tuplehash-staging:512 [routine] | passed | 2026-10-19T12:03:16Z |
| miri-6127b62ec10ed038 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:47:width=0 [extended] | reused | 2026-10-28T21:37:27Z |
| miri-612a84e143668159 | tuplehash | miri | tuplehash-staging:448 [extended] | reused | 2026-10-28T16:34:17Z |
| miri-6134c8c620223462 | sha1 | miri | sha1-bulk:1 [extended] | reused | 2026-10-28T12:50:59Z |
| miri-6134e5a880fe3779 | sha3 | miri | sha3-fixed-boundaries:41 [routine] | passed | 2026-10-19T11:37:36Z |
| miri-61359a0d4227d702 | tuplehash | miri | tuplehash-staging:384 [extended] | reused | 2026-10-28T16:13:56Z |
| miri-613a637f4eaf45c4 | sha1 | miri | -p brynja-legacy-sha1 --features hardened-execution --test hardened_execution revocation_cancellation_and_output_failures [remaining suite; inspect skips with show] | reused | 2026-10-28T12:38:51Z |
| miri-613a745932083be9 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:15:width=4 [extended] | reused | 2026-10-28T22:53:23Z |
| miri-614e860ffd356b4f | tuplehash | miri | tuplehash-staging:410 [extended] | reused | 2026-10-28T16:25:19Z |
| miri-61680e4a875f33ea | tuplehash | miri | tuplehash-staging:688 [extended] | reused | 2026-10-28T17:50:48Z |
| miri-616a3261ab56bde2 | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join256:3 [extended] | passed | 2026-10-29T14:19:08Z |
| miri-617891381405d962 | tuplehash | miri | scoped_tuplexof256_differential:41:width=4 [extended] | passed | 2026-10-29T12:50:55Z |
| miri-6190405ac7e8afbe | kmac | miri | arbitrary_bits_are_canonical_and_streaming_xof_tracks_output [routine] | passed | 2026-10-19T15:40:07Z |
| miri-61914db4a1a0c474 | sha1 | miri | sha1-padding:26 [extended] | reused | 2026-10-28T12:41:18Z |
| miri-6191b4dbdb99ba62 | sha1 | miri | sha1-bulk:115 [extended] | reused | 2026-10-28T12:54:45Z |
| miri-61a63719a6348ed9 | md5 | miri | md5-bulk:95 [extended] | reused | 2026-10-28T11:34:29Z |
| miri-61b8a9afba3e4bd1 | kmac | miri | kmac-streamed-setup:36 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-61c30f223b5e48e7 | tuplehash | miri | tuplehash-staging:714 [extended] | reused | 2026-10-28T18:02:32Z |
| miri-61c61d8cfb6a1a45 | md5 | miri | md5-batch-mask:61 [extended] | reused | 2026-10-28T12:12:06Z |
| miri-61f89e2dd7b14f7c | sha1 | miri | sha1-bulk:177 [extended] | reused | 2026-10-28T13:05:42Z |
| miri-61fb64f4fc13c4c6 | sha1 | miri | sha1-bulk:218 [extended] | reused | 2026-10-28T12:59:43Z |
| miri-61fcbb5c7ac50e90 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:23:width=2 [extended] | reused | 2026-10-28T20:32:45Z |
| miri-6208f725fc508a62 | md5 | miri | md5-batch-mask:155 [extended] | reused | 2026-10-28T12:19:24Z |
| miri-6235f343390184ce | tuplehash | miri | tuplehash-staging:849 [extended] | reused | 2026-10-28T19:05:33Z |
| miri-62404bc9530c6221 | sha1 | miri | sha1-bulk:256 [extended] | reused | 2026-10-28T13:02:45Z |
| miri-62455ffee01d8a17 | sha2 | miri | -p brynja-hash-sha2 --test sha512 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-625345321e779cde | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:38:width=2 [extended] | reused | 2026-10-28T20:41:14Z |
| miri-62607a66650371da | md5 | miri | md5-padding:87 [extended] | reused | 2026-10-28T11:29:14Z |
| miri-6265abd542c7c3fd | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:28:width=3 [extended] | reused | 2026-10-28T22:52:29Z |
| miri-626f9bbac817a940 | sha1 | miri | sha1-bulk:60 [extended] | reused | 2026-10-28T12:42:56Z |
| miri-62807cb798474d63 | sha2 | miri | -p brynja-hash-sha2 --features general-sha512-t --test general bounded_public_api_smoke [remaining suite; inspect skips with show] | reused | 2026-10-28T13:40:42Z |
| miri-6281b59040b5702b | tuplehash | miri | scoped_tuplexof128_differential:25:width=2 [extended] | passed | 2026-10-29T11:02:10Z |
| miri-6281e7ac87ed1e92 | sha1 | miri | sha1-bulk:174 [extended] | reused | 2026-10-28T12:54:55Z |
| miri-629cba99c73d079a | legacy_hmac | miri | md5_long [routine] | No mapped observation | — |
| miri-629ec80600167db1 | md5 | miri | md5-bulk:36 [extended] | reused | 2026-10-28T11:39:51Z |
| miri-62ad7de16b0e38bc | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:5:width=2 [extended] | reused | 2026-10-29T04:30:03Z |
| miri-62cb384e04024b7e | tuplehash | miri | tuplehash-staging:303 [extended] | reused | 2026-10-28T21:56:11Z |
| miri-62cdf8266ed5f4e3 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:11:width=1 [extended] | reused | 2026-10-28T20:06:05Z |
| miri-62cfa9918d42efc4 | tuplehash | miri | tuplehash-execution-xof:0 [extended] | reused | 2026-10-28T19:19:44Z |
| miri-62d273b4df6cb5f7 | sha1 | miri | sha1-bulk:19 [extended] | reused | 2026-10-28T12:47:20Z |
| miri-62d2bfdb00788af5 | sha1 | miri | sha1-padding:100 [extended] | reused | 2026-10-28T12:43:09Z |
| miri-62d34234ab3db085 | md5 | miri | md5-bulk:110 [extended] | reused | 2026-10-28T11:40:10Z |
| miri-62dc105b5daf192a | sha3 | miri | sha3-fixed-bits:21 [routine] | passed | 2026-10-19T11:35:46Z |
| miri-62fd2f2ea9069b3a | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:6 [routine] | passed | 2026-10-19T12:17:25Z |
| miri-630b4bdd68fed6d1 | sha1 | miri | sha1-bulk:14 [extended] | reused | 2026-10-28T12:41:35Z |
| miri-63213d3019b122ad | tuplehash | miri | scoped_tuplexof256_differential:43:width=1 [extended] | reused | 2026-10-29T04:41:29Z |
| miri-632eb3aa5328f57e | tuplehash | miri | scoped_tuplexof256_differential:13:width=0 [extended] | passed | 2026-10-29T12:13:31Z |
| miri-6347ab87d8f9d8f4 | tuplehash | miri | tuplehash-staging:499 [extended] | reused | 2026-10-28T23:01:49Z |
| miri-634f862c078ca099 | sha1 | miri | sha1-scoped:46 [extended] | reused | 2026-10-28T13:06:04Z |
| miri-6354b40792a68e6b | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:6:width=1 [extended] | reused | 2026-10-28T22:02:39Z |
| miri-63694f7f7c0992fd | tuplehash | miri | tuplehash-staging:393 [extended] | reused | 2026-10-28T16:32:08Z |
| miri-636af526b2338d43 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:22 [routine] | No mapped observation | — |
| miri-63852235ed59da31 | kmac | miri | kmac-streamed-setup:83 [routine] | No mapped observation | — |
| miri-63a213d0e500f145 | sha1 | miri | sha1-bulk:76 [extended] | reused | 2026-10-28T12:44:16Z |
| miri-63b06165a151da10 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:8:width=4 [extended] | reused | 2026-10-28T19:39:57Z |
| miri-63be25e8e3b4fb0b | tuplehash | miri | scoped_tuplexof128_differential:32:width=4 [extended] | reused | 2026-10-29T01:36:57Z |
| miri-63e49f21a5f37ab7 | sha1 | miri | sha1-padding:0 [routine] | passed | 2026-10-19T11:34:07Z |
| miri-63f9b0d501366c09 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:40:width=3 [extended] | reused | 2026-10-28T20:53:24Z |
| miri-64041f3fd7c44f84 | static_cpu | miri | --manifest-path assurance/static-cpu-execution/Cargo.toml --lib [remaining suite; inspect skips with show] | passed | 2026-10-19T13:55:14Z |
| miri-64072ff6a1e1aa76 | kmac | miri | kmac-streamed-setup:12 [routine] | No mapped observation | — |
| miri-640a713da0f0cdb9 | tuplehash | miri | hardened_in_place::tests::scoped_tuple256_terminal_writer_and_output_lifecycle [extended] | passed | 2026-10-29T12:57:40Z |
| miri-64341aafe7786f3b | sha1 | miri | sha1-bulk:165 [extended] | reused | 2026-10-28T13:04:30Z |
| miri-6438e65cc1f0af1a | tuplehash | miri | tuplehash-staging:619 [extended] | reused | 2026-10-28T23:42:37Z |
| miri-643915693d002500 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:5 [routine] | No mapped observation | — |
| miri-643c5c7e901c0891 | md5 | miri | md5-batch-mask:127 [routine] | passed | 2026-10-19T11:14:52Z |
| miri-643d0eefc4bd07ce | kmac | miri | kmac-streamed-setup:34 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-6448b775379f5863 | kmac | miri | kmac-streamed-setup:3 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-64532503c432b9e1 | sha1 | miri | sha1-bulk:151 [extended] | reused | 2026-10-28T12:58:17Z |
| miri-64770923f4a8277f | md5 | miri | md5-batch-mask:215 [extended] | reused | 2026-10-28T12:24:22Z |
| miri-648728623e699b5d | md5 | miri | md5-padding:125 [extended] | reused | 2026-10-28T11:37:13Z |
| miri-649d079953061e37 | kmac | miri | kmac-streamed-setup:52 [routine] | No mapped observation | — |
| miri-64aed868b28c1509 | sha1 | miri | sha1-padding:86 [extended] | reused | 2026-10-28T12:46:36Z |
| miri-64ba000d6198711f | kmac | miri | kmac-streamed-setup:5 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-64ba4e6c9df10c20 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:36:width=4 [extended] | reused | 2026-10-28T20:41:38Z |
| miri-64d50ba64de5239b | tuplehash | miri | tuplehash-staging:700 [extended] | reused | 2026-10-28T17:54:38Z |
| miri-64da6b9347c1491c | tuplehash | miri | tuplehash-staging:217 [extended] | reused | 2026-10-28T15:33:29Z |
| miri-64f562ed0a8861e6 | tuplehash | miri | tuplehash-staging:649 [extended] | reused | 2026-10-28T17:58:12Z |
| miri-64f61d32d6b4af8b | tuplehash | miri | tuplehash-staging:580 [extended] | reused | 2026-10-28T17:16:33Z |
| miri-64f8a0bb3143a2e7 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:50:width=2 [extended] | reused | 2026-10-28T23:58:01Z |
| miri-64fa7b6afab743dd | tuplehash | miri | tuplehash-staging:618 [extended] | reused | 2026-10-28T17:31:50Z |
| miri-64ffd83735866cf2 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:18 [extended] | passed | 2026-10-29T12:54:46Z |
| miri-6528a2d2b3afc216 | md5 | miri | md5-batch-mask:112 [extended] | reused | 2026-10-28T12:21:23Z |
| miri-652b2f7438073398 | tuplehash | miri | scoped_tuplexof256_differential:35:width=3 [extended] | reused | 2026-10-29T04:19:13Z |
| miri-6536d23b05abff6b | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:336 [routine] | No mapped observation | — |
| miri-6538dae1bd80361c | sha1 | miri | sha1-bulk:146 [extended] | reused | 2026-10-28T12:52:04Z |
| miri-654bdcae9070ce1b | hmac | miri | sha3_512 [extended] | passed | 2026-10-29T15:07:38Z |
| miri-655280e876b25f5b | parallelhash | miri | arbitrary_bit_input_and_output_partition_are_stable [extended] | passed | 2026-10-29T15:01:12Z |
| miri-655475c0af8707da | sha1 | miri | sha1-scoped:150 [routine] | passed | 2026-10-19T11:17:06Z |
| miri-655be884449974f2 | sha1 | miri | sha1-padding:127 [extended] | reused | 2026-10-28T12:40:34Z |
| miri-657142d137fd0a09 | tuplehash | miri | tuplehash-staging:114 [extended] | reused | 2026-10-28T14:49:01Z |
| miri-6594948e89722cc1 | tuplehash | miri | scoped_tuplexof128_differential:23:width=1 [extended] | reused | 2026-10-29T01:58:09Z |
| miri-65af358d6bd0da58 | tuplehash | miri | tuplehash-staging:438 [extended] | reused | 2026-10-28T16:34:30Z |
| miri-65c2168e93f8bee1 | tuplehash | miri | tuplehash-staging:715 [extended] | reused | 2026-10-29T00:14:10Z |
| miri-65cdc3f6aa37bd08 | md5 | miri | md5-bulk:21 [extended] | reused | 2026-10-28T11:29:06Z |
| miri-65daaf8fa8f0cff4 | sha1 | miri | sha1-bulk:33 [extended] | reused | 2026-10-28T12:53:05Z |
| miri-65ddbc99a77e00f9 | md5 | miri | md5-batch-mask:200 [extended] | reused | 2026-10-28T12:28:22Z |
| miri-65df0029c3aebd60 | md5 | miri | md5-batch-mask:225 [extended] | reused | 2026-10-28T12:25:08Z |
| miri-65ea28bb58befc8f | tuplehash | miri | tuplehash-staging:394 [extended] | reused | 2026-10-28T16:20:09Z |
| miri-65f055f67c3472a4 | tuplehash | miri | scoped_tuplexof256_differential:26:width=1 [extended] | reused | 2026-10-29T03:06:14Z |
| miri-65fade58db563272 | md5 | miri | md5-scoped:191 [extended] | reused | 2026-10-28T12:00:13Z |
| miri-6600fd4bba25c70f | tuplehash | miri | tuplehash-staging:675 [extended] | reused | 2026-10-29T00:01:28Z |
| miri-660bc3fbf7f66edd | md5 | miri | md5-batch-mask:37 [extended] | reused | 2026-10-28T12:10:14Z |
| miri-661f71e17706c0fe | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:4:width=3 [extended] | reused | 2026-10-28T19:33:24Z |
| miri-66406337332be22b | sha3 | miri | sha3-fixed-bits:13 [routine] | passed | 2026-10-19T11:35:23Z |
| miri-664854740786d4d7 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:21:width=4 [extended] | reused | 2026-10-29T05:03:33Z |
| miri-664b81ef0001706f | md5 | miri | md5-scoped:253 [extended] | reused | 2026-10-28T12:05:04Z |
| miri-665193b74d4cd13c | tuplehash | miri | tuplehash-staging:117 [extended] | reused | 2026-10-28T14:59:52Z |
| miri-66605a8e94c0ca7c | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:15:width=4 [extended] | reused | 2026-10-28T20:13:06Z |
| miri-6661b15461529680 | sha3 | miri | sha3-fixed-bits:0 [routine] | passed | 2026-10-19T11:37:45Z |
| miri-667f231fb86d7ca1 | sha3 | miri | sha3-fixed-boundaries:41 [extended] | reused | 2026-10-28T13:36:25Z |
| miri-668c7ef0e4aac429 | md5 | miri | md5-bulk:241 [extended] | reused | 2026-10-28T11:45:51Z |
| miri-66988f2b4bad1a3c | sha3 | miri | sha3-fixed-boundaries:58 [routine] | passed | 2026-10-19T11:38:10Z |
| miri-669a9792ed9e384a | tuplehash | miri | scoped_tuplexof128_differential:41:width=0 [extended] | passed | 2026-10-29T11:57:51Z |
| miri-66a19eddcd2e3715 | md5 | miri | md5-batch-mask:90 [extended] | reused | 2026-10-28T12:25:03Z |
| miri-66a3587e2e3fcc0e | sha1 | miri | sha1-scoped:153 [extended] | reused | 2026-10-28T13:21:58Z |
| miri-66add23226462314 | md5 | miri | md5-batch-mask:223 [routine] | passed | 2026-10-19T11:15:01Z |
| miri-66bf7726aae362c7 | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib metadata_and_preselected_tag_policy [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-66c3f3c211c3441e | md5 | miri | md5-scoped:32 [extended] | reused | 2026-10-28T11:55:06Z |
| miri-66c95dcfdec7a6b8 | tuplehash | miri | tuplehash-staging:854 [extended] | reused | 2026-10-28T18:47:20Z |
| miri-66d4dd547cd733ae | tuplehash | miri | tuplehash-staging:1 [extended] | reused | 2026-10-28T14:21:12Z |
| miri-66d5878594732981 | md5 | miri | md5-batch-mask:134 [extended] | reused | 2026-10-28T12:28:32Z |
| miri-66e7d50cdb1f9e32 | static_cpu | miri | --manifest-path assurance/static-cpu-execution/Cargo.toml --lib [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-66f9248542faba94 | tuplehash | miri | tuplehash-staging:753 [extended] | reused | 2026-10-28T18:33:13Z |
| miri-67025d2a10055115 | tuplehash | miri | tuplehash-staging:288 [extended] | reused | 2026-10-28T15:41:58Z |
| miri-6702c7d49607eecf | tuplehash | miri | tuplehash-staging:165 [extended] | reused | 2026-10-28T15:16:01Z |
| miri-6718deafe6af1691 | tuplehash | miri | tuplehash-staging:510 [extended] | reused | 2026-10-28T16:57:33Z |
| miri-6719a72b27dc1424 | sha1 | miri | sha1-bulk:221 [extended] | reused | 2026-10-28T13:10:59Z |
| miri-67216f6f2e8c8ecd | tuplehash | miri | tuplehash-staging:30 [extended] | reused | 2026-10-28T14:21:36Z |
| miri-6722a2f122eed3c3 | sha3 | miri | sha3-fixed-boundaries:37 [routine] | passed | 2026-10-19T11:33:37Z |
| miri-672aa3301ba6cac0 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:6 [extended] | passed | 2026-10-29T12:47:45Z |
| miri-673d96ab12dc23e9 | md5 | miri | -p brynja-legacy-md5 --features execution --lib operational_revalidator_unwind_quarantines_without_instructions [remaining suite; inspect skips with show] | passed | 2026-10-19T11:30:59Z |
| miri-675325b2be86c82b | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:14:width=0 [extended] | reused | 2026-10-28T22:15:42Z |
| miri-67605a767f29ce8f | kmac | miri | kmac-streamed-setup:9 [routine] | No mapped observation | — |
| miri-677a39659ac9a066 | md5 | miri | md5-batch-mask:249 [extended] | reused | 2026-10-28T12:27:08Z |
| miri-67b7a8d48d285128 | sha1 | miri | sha1-padding:116 [extended] | reused | 2026-10-28T12:44:45Z |
| miri-67c5387c6fc49955 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:9 [extended] | passed | 2026-10-29T14:07:07Z |
| miri-67c9e36629e5f4d5 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:38:width=3 [extended] | reused | 2026-10-28T20:41:14Z |
| miri-67cd7ee4ad5d4def | tuplehash | miri | scoped_tuplexof256_differential:39:width=2 [extended] | reused | 2026-10-29T04:28:59Z |
| miri-67ed40a2281d1b85 | sha1 | miri | sha1-scoped:80 [extended] | reused | 2026-10-28T13:09:57Z |
| miri-67f280dbb4b0cf35 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:27 [routine] | passed | 2026-10-19T12:26:03Z |
| miri-6807f558da3ebd33 | sha1 | miri | sha1-bulk:74 [extended] | reused | 2026-10-28T12:45:38Z |
| miri-6819e273613bcebb | kmac | miri | kmac-streamed-setup:61 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-68235290340868d8 | sha3 | miri | -p brynja-hash-sha3 --features hardened-execution --lib hardened::accelerated::engine::tests::every_memory_region_is_explicitly_cleared [remaining suite; inspect skips with show] | passed | 2026-10-19T11:36:13Z |
| miri-683a4b2cc9cb60fb | tuplehash | miri | tuplehash-staging:135 [extended] | reused | 2026-10-28T20:59:30Z |
| miri-684d8177fb583c90 | md5 | miri | md5-bulk:207 [extended] | reused | 2026-10-28T11:43:12Z |
| miri-684e9f89576564ee | tuplehash | miri | scoped_tuplexof128_differential:43:width=3 [extended] | reused | 2026-10-29T02:49:54Z |
| miri-6851852bcf8c9a88 | tuplehash | miri | tuplehash-staging:284 [extended] | reused | 2026-10-28T15:41:03Z |
| miri-685346bad12ca3c7 | kmac | miri | kmac-scoped-lifecycle:17 [extended] | reused | 2026-10-28T19:54:22Z |
| miri-6859690ff4578bff | sha3 | miri | -p brynja-hash-sha3 --test hardened [remaining suite; inspect skips with show] | passed | 2026-10-19T11:36:40Z |
| miri-68621bf532a4c961 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:45 [routine] | No mapped observation | — |
| miri-68661746e7ae366d | md5 | miri | md5-scoped:71 [extended] | reused | 2026-10-28T11:52:01Z |
| miri-6866223ad5f2e196 | sha1 | miri | sha1-scoped:26 [extended] | reused | 2026-10-28T13:04:40Z |
| miri-68892e764bc7c6fd | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:1 [routine] | No mapped observation | — |
| miri-6894f35babbe8774 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:18 [routine] | passed | 2026-10-19T12:19:10Z |
| miri-6898f3f06549369a | sha3 | miri | sha3-fixed-boundaries:66 [extended] | reused | 2026-10-28T13:45:18Z |
| miri-689a2b4326d97b0c | md5 | miri | md5-bulk:123 [extended] | reused | 2026-10-28T11:36:32Z |
| miri-68a3e5d91fea90de | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:23:width=1 [extended] | reused | 2026-10-28T20:32:45Z |
| miri-68b4f5ecb39d33b4 | tuplehash | miri | arbitrary_bit_items_and_outputs_are_canonical [routine] | passed | 2026-10-19T12:42:44Z |
| miri-68c182a49c71c4f2 | tuplehash | miri | scoped_tuplexof256_differential:19:width=2 [extended] | reused | 2026-10-29T03:40:19Z |
| miri-68ce30e817283a3e | md5 | miri | md5-batch-mask:189 [extended] | reused | 2026-10-28T12:22:15Z |
| miri-68d81fcd3fc97420 | md5 | miri | md5-bulk:12 [extended] | reused | 2026-10-28T11:38:17Z |
| miri-68d98434e454afa7 | tuplehash | miri | tuplehash-staging:606 [extended] | reused | 2026-10-28T17:27:59Z |
| miri-68ef288c58e55e4e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:0:width=4 [extended] | reused | 2026-10-28T19:26:50Z |
| miri-68f6c0e767038b8c | hmac | miri | -p brynja-mac-hmac --features hardened-execution --lib execution::tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-690fa09c95ddbdad | sha1 | miri | sha1-scoped:155 [extended] | reused | 2026-10-28T13:27:15Z |
| miri-69183c31895bfc6c | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-domains:4 [routine] | No mapped observation | — |
| miri-691f258959cafc80 | kmac | miri | kmacxof-official:1 [routine] | passed | 2026-10-19T15:38:05Z |
| miri-69288af1f3205ae4 | sha1 | miri | sha1-padding:17 [extended] | reused | 2026-10-28T12:29:26Z |
| miri-692b23502fab3028 | tuplehash | miri | scoped_tuplexof256_differential:30:width=0 [extended] | reused | 2026-10-29T03:15:42Z |
| miri-697f06e4670782c0 | md5 | miri | md5-batch-mask:48 [extended] | reused | 2026-10-28T12:16:32Z |
| miri-6988c2593ea1a4cc | kmac | miri | kmac-streamed-setup:45 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-699c47b0a5f99e43 | tuplehash | miri | scoped_tuplexof128_differential:7:width=0 [extended] | reused | 2026-10-29T01:24:29Z |
| miri-699c480a545fc68a | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:22:width=2 [extended] | reused | 2026-10-28T22:33:52Z |
| miri-699d86dcc2373ea8 | md5 | miri | md5-padding:25 [extended] | reused | 2026-10-28T11:29:32Z |
| miri-69a220a7024bc9ba | sha1 | miri | sha1-bulk:100 [extended] | reused | 2026-10-28T12:46:15Z |
| miri-69a26e98178a8618 | tuplehash | miri | scoped_tuplexof128_differential:39:width=0 [extended] | reused | 2026-10-29T02:37:19Z |
| miri-69a465fdc0606ad9 | md5 | miri | md5-batch-mask:111 [extended] | reused | 2026-10-28T12:15:47Z |
| miri-69aaa5c21942bcf5 | kmac | miri | kmac-streamed-setup:83 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-69beb8013ea9e498 | hmac | miri | general_511 [routine] | No mapped observation | — |
| miri-69f86017b533e58a | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:15 [extended] | passed | 2026-10-29T13:07:36Z |
| miri-69fa8b841091d2d2 | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib metadata_and_preselected_tag_policy [remaining suite; inspect skips with show] | passed | 2026-10-29T15:09:06Z |
| miri-6a2beabaa945d4a8 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:47:width=1 [extended] | reused | 2026-10-28T21:37:27Z |
| miri-6a3441eb96396a3f | tuplehash | miri | tuplehash-staging:708 [extended] | reused | 2026-10-28T17:56:50Z |
| miri-6a3b2fedea74a0c2 | hmac | miri | sha512 [existing-full] | No mapped observation | — |
| miri-6a41bff2854d55d4 | md5 | miri | md5-scoped:44 [extended] | reused | 2026-10-28T11:55:53Z |
| miri-6a4987bcf8e20eae | sha3 | miri | -p brynja-hash-sha3 --features hardened-execution --lib hardened::accelerated::reader::tests [remaining suite; inspect skips with show] | passed | 2026-10-19T11:30:45Z |
| miri-6a4cd7624941ef2f | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-domains:1 [extended] | passed | 2026-10-29T14:14:52Z |
| miri-6a8d1cb869026c40 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:44:width=2 [extended] | reused | 2026-10-28T21:05:12Z |
| miri-6aa8f32fe43ef480 | sha1 | miri | sha1-scoped:212 [extended] | reused | 2026-10-28T13:20:35Z |
| miri-6ab9fc08c6e823be | tuplehash | miri | tuplehash-staging:156 [extended] | reused | 2026-10-28T14:59:24Z |
| miri-6ad5497290884732 | sha3 | miri | sealed_capabilities_accept_only_registered_public_types [routine] | passed | 2026-10-19T11:37:01Z |
| miri-6b03ba5146a707de | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:33 [routine] | No mapped observation | — |
| miri-6b167768f38e8e28 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:32:width=3 [extended] | reused | 2026-10-28T20:32:25Z |
| miri-6b422d43af88ed36 | tuplehash | miri | tuplehash-staging:405 [extended] | reused | 2026-10-28T16:36:57Z |
| miri-6b45876285591d7f | tuplehash | miri | tuplehash-staging:261 [extended] | reused | 2026-10-28T15:48:03Z |
| miri-6b467b982ace1c03 | sha1 | miri | sha1-padding:47 [extended] | reused | 2026-10-28T12:33:12Z |
| miri-6b57f9abda5c1097 | tuplehash | miri | tuplehash-staging:172 [extended] | reused | 2026-10-28T15:04:39Z |
| miri-6b5815a5c99e6eff | kmac | miri | kmac-streamed-setup:46 [routine] | No mapped observation | — |
| miri-6b651dafad9b4f76 | md5 | miri | md5-scoped:277 [extended] | reused | 2026-10-28T12:06:47Z |
| miri-6b682599bba378ff | md5 | miri | md5-padding:128 [extended] | reused | 2026-10-28T11:27:59Z |
| miri-6b6c6aa06c9b6622 | md5 | miri | md5-bulk:42 [extended] | reused | 2026-10-28T11:35:11Z |
| miri-6b749ceb4fd15458 | md5 | miri | md5-bulk:129 [routine] | passed | 2026-10-19T11:14:12Z |
| miri-6b7900f9d82da493 | tuplehash | miri | tuplehash-staging:272 [extended] | reused | 2026-10-28T15:37:31Z |
| miri-6b79d3bf915bbfe6 | tuplehash | miri | scoped_tuplexof256_differential:17:width=4 [extended] | passed | 2026-10-29T12:29:53Z |
| miri-6b82dcb7275dc55d | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:43:width=3 [extended] | reused | 2026-10-28T21:24:50Z |
| miri-6b87e8bf645e1f5a | kmac | miri | kmac-streamed-setup:87 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-6b991c5cec9d4a0d | tuplehash | miri | tuplehash-staging:219 [extended] | reused | 2026-10-28T21:27:50Z |
| miri-6b9cc32667f41eb0 | tuplehash | miri | tuplehash-staging:798 [extended] | reused | 2026-10-28T18:29:25Z |
| miri-6b9f8ad498454e3d | tuplehash | miri | tuplehash-staging:519 [extended] | reused | 2026-10-28T23:08:05Z |
| miri-6bc05694f320d6d6 | sha1 | miri | sha1-padding:118 [extended] | reused | 2026-10-28T12:49:50Z |
| miri-6bc2be32e6c8e3e9 | md5 | miri | -p brynja-legacy-md5 --features execution --lib batch::execution::tests [remaining suite; inspect skips with show] | passed | 2026-10-19T11:25:40Z |
| miri-6bc452b9368c118b | kmac | miri | kmac-official:3 [routine] | passed | 2026-10-19T15:37:12Z |
| miri-6bcee6bac7635b77 | md5 | miri | md5-batch-mask:209 [extended] | reused | 2026-10-28T12:23:50Z |
| miri-6bd94e8afbf7a604 | tuplehash | miri | scoped_tuplexof128_differential:37:width=2 [extended] | passed | 2026-10-29T11:55:08Z |
| miri-6be1068c35234f47 | kmac | miri | kmacxof-official:0 [extended] | reused | 2026-10-28T14:06:39Z |
| miri-6bf583c2262d3bdb | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:30:width=0 [extended] | reused | 2026-10-28T22:52:04Z |
| miri-6c2da181c32cfaf7 | tuplehash | miri | tuplehash-staging:355 [extended] | reused | 2026-10-28T22:13:41Z |
| miri-6c3a3879a3cfea51 | kmac | miri | kmac-official:2 [routine] | passed | 2026-10-19T11:40:28Z |
| miri-6c3b14c0014db59d | kmac | miri | kmac-scoped-lifecycle:1 [extended] | reused | 2026-10-28T19:48:48Z |
| miri-6c4a93eab4fc65cb | kmac | miri | kmac-scoped-lifecycle:16 [routine] | passed | 2026-10-19T11:36:34Z |
| miri-6c6f2c237a59f09f | tuplehash | miri | tuplehash-staging:807 [extended] | reused | 2026-10-29T00:45:39Z |
| miri-6c75aa6525aee52a | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:47:width=1 [extended] | reused | 2026-10-29T00:17:25Z |
| miri-6c7908cb422972b0 | md5 | miri | md5-bulk:60 [extended] | reused | 2026-10-28T11:41:27Z |
| miri-6c7a7b0568cbde9b | md5 | miri | md5-scoped:62 [extended] | reused | 2026-10-28T12:02:16Z |
| miri-6c97a043fd788260 | md5 | miri | md5-padding:83 [extended] | reused | 2026-10-28T11:28:55Z |
| miri-6cad89fd7ff588f0 | md5 | miri | md5-batch-mask:85 [extended] | reused | 2026-10-28T12:13:55Z |
| miri-6cc8c2192a7a9857 | sha2 | miri | -p brynja-hash-sha2 --test sha512_256 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | passed | 2026-10-19T11:36:08Z |
| miri-6cd66f14a44dbd29 | md5 | miri | md5-bulk:58 [extended] | reused | 2026-10-28T11:36:14Z |
| miri-6ced4c2d2d9f04bc | tuplehash | miri | tuplehash-staging:235 [extended] | reused | 2026-10-28T21:33:14Z |
| miri-6cf4254e3472c104 | tuplehash | miri | tuplehash-staging:17 [extended] | reused | 2026-10-28T14:27:08Z |
| miri-6cf9661f9226e63e | sha2 | miri | -p brynja-hash-sha2 --features hardened-execution,general-sha512-t --lib hardened_execution::tests::output_owner_clears_during_recoverable_unwind [remaining suite; inspect skips with show] | reused | 2026-10-28T13:38:33Z |
| miri-6d0dbb62c102e2d4 | md5 | miri | md5-batch-mask:33 [extended] | reused | 2026-10-28T12:09:56Z |
| miri-6d17cf45546bcc22 | sha1 | miri | sha1-scoped:169 [extended] | reused | 2026-10-28T13:23:11Z |
| miri-6d2259c8a2e53516 | sha1 | miri | sha1-padding:96 [extended] | reused | 2026-10-28T12:42:46Z |
| miri-6d24c3b47af0a6b6 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:46:width=2 [extended] | reused | 2026-10-28T21:04:48Z |
| miri-6d300fd65c647dbf | md5 | miri | md5-batch-mask:165 [extended] | reused | 2026-10-28T12:20:19Z |
| miri-6d3c9f99f6534903 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:8:width=0 [extended] | reused | 2026-10-28T22:09:27Z |
| miri-6d4644f8e4f1cf35 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:23 [extended] | passed | 2026-10-29T13:23:20Z |
| miri-6d4af02af0b98e23 | tuplehash | miri | tuplehash-staging:578 [extended] | reused | 2026-10-28T17:19:01Z |
| miri-6d5b24422db4a49f | sha2 | miri | -p brynja-crypto-cpu --features sha512-batch --lib sha512_batch::tests::failed_revalidation_and_unwind_revoke_before_instruction_entry [remaining suite; inspect skips with show] | reused | 2026-10-28T13:38:17Z |
| miri-6d60880cd0b7cdb3 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:2:width=0 [extended] | reused | 2026-10-28T19:26:23Z |
| miri-6d6586a38e841079 | kmac | miri | kmac-scoped-lifecycle:14 [extended] | reused | 2026-10-28T13:54:38Z |
| miri-6d96b96d53916cdd | kmac | miri | kmac-streamed-setup:90 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-6db51c859b8d6f1d | sha1 | miri | sha1-padding:128 [routine] | passed | 2026-10-19T11:16:00Z |
| miri-6db9203c8e7c4a88 | sha1 | miri | sha1-padding:94 [extended] | reused | 2026-10-28T12:47:24Z |
| miri-6dc6fb851eed7780 | tuplehash | miri | scoped_tuplexof256_differential:39:width=1 [extended] | reused | 2026-10-29T04:28:59Z |
| miri-6ddfbe76faffd861 | md5 | miri | md5-bulk:157 [extended] | reused | 2026-10-28T11:38:53Z |
| miri-6de018afe88e7359 | tuplehash | miri | tuplehash-staging:693 [extended] | reused | 2026-10-28T18:12:59Z |
| miri-6def9c2397d7a9bd | tuplehash | miri | tuplehash-staging:671 [extended] | reused | 2026-10-29T00:00:08Z |
| miri-6df3865ac0ffa135 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:40:width=4 [extended] | reused | 2026-10-28T20:53:24Z |
| miri-6df92bca0971a01c | kmac | miri | kmac-streamed-setup:65 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-6e16a144d610a15d | kmac | miri | kmac-scoped-lifecycle:7 [extended] | reused | 2026-10-28T14:05:15Z |
| miri-6e1cf5f8602f8d6f | md5 | miri | md5-scoped:84 [extended] | reused | 2026-10-28T11:58:36Z |
| miri-6e24dde0553d9a25 | md5 | miri | md5-bulk:129 [extended] | reused | 2026-10-28T11:36:42Z |
| miri-6e35fd47e7da9362 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:52:width=4 [extended] | reused | 2026-10-28T21:49:46Z |
| miri-6e4b06c6a0b35aa9 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:0 [routine] | No mapped observation | — |
| miri-6e56661931092790 | md5 | miri | md5-bulk:153 [extended] | reused | 2026-10-28T11:38:35Z |
| miri-6e60122f704d344a | md5 | miri | md5-batch-mask:44 [extended] | reused | 2026-10-28T12:16:14Z |
| miri-6e7252ef8be1e8c3 | tuplehash | miri | scoped_tuplexof256_differential:32:width=3 [extended] | reused | 2026-10-29T03:25:53Z |
| miri-6e94b191ecd9a902 | md5 | miri | md5-batch-mask:38 [extended] | reused | 2026-10-28T12:21:02Z |
| miri-6e957bd366edaa4b | tuplehash | miri | tuplehash-staging:113 [extended] | reused | 2026-10-28T14:58:08Z |
| miri-6ea7b3bdd7e5eeda | sha1 | miri | sha1-scoped:51 [extended] | reused | 2026-10-28T13:19:27Z |
| miri-6eccf4d6655f9bb7 | tuplehash | miri | hardened_in_place::xof::tests::scoped_tuplexof128_lifecycle [routine] | passed | 2026-10-19T12:29:39Z |
| miri-6ed0f08359e74268 | tuplehash | miri | scoped_tuplexof256_differential:44:width=1 [extended] | reused | 2026-10-29T03:59:50Z |
| miri-6edc0a1232771d6e | sha1 | miri | sha1-padding:44 [extended] | reused | 2026-10-28T12:37:49Z |
| miri-6f492d81c64dd255 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:25:width=0 [extended] | reused | 2026-10-29T05:13:15Z |
| miri-6f52a726c625867b | tuplehash | miri | scoped_tuplexof128_differential:17:width=4 [extended] | passed | 2026-10-29T10:56:50Z |
| miri-6f5dd5460f9dbe5a | tuplehash | miri | tuplehash-execution-xof:1 [extended] | reused | 2026-10-28T19:45:03Z |
| miri-6f67b956667f5de1 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:9 [extended] | passed | 2026-10-29T13:09:21Z |
| miri-6f7c68d9fb8fd33a | md5 | miri | md5-scoped:75 [routine] | passed | 2026-10-19T11:26:37Z |
| miri-6f7e1c77884f1277 | sha1 | miri | sha1-padding:6 [extended] | reused | 2026-10-28T12:39:43Z |
| miri-6f838bfcd6c0b74b | tuplehash | miri | scoped_tuplexof128_differential:0:width=0 [extended] | reused | 2026-10-29T00:30:00Z |
| miri-6f8f6e6fbb6758dc | tuplehash | miri | tuplehash-staging:430 [extended] | reused | 2026-10-28T16:32:15Z |
| miri-6f93f5c9ba9446f7 | md5 | miri | md5-scoped:118 [extended] | reused | 2026-10-28T12:06:08Z |
| miri-6f94abe54381c70f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:51:width=2 [extended] | reused | 2026-10-29T00:43:55Z |
| miri-6fa2968c4ce1bc80 | sha1 | miri | sha1-scoped:260 [extended] | reused | 2026-10-28T13:24:35Z |
| miri-6fb7b870c2d65c46 | md5 | miri | md5-batch-mask:32 [routine] | passed | 2026-10-19T11:29:58Z |
| miri-6fcb0d4e73e04e6d | kmac | miri | -p brynja-mac-kmac --features hardened-execution --lib execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-6fd40a3d64e434c5 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:31:width=3 [extended] | reused | 2026-10-28T23:32:36Z |
| miri-6fd9d7a1a3521bc2 | legacy_hmac | miri | output_unwind [routine] | No mapped observation | — |
| miri-6fe5681fd96cf5f2 | kmac | miri | kmac-streamed-setup:72 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-6febc719f8ab9c72 | tuplehash | miri | tuplehash-staging:423 [extended] | reused | 2026-10-28T22:37:00Z |
| miri-6ff076d37f24f02a | tuplehash | miri | scoped_tuplexof128_differential:3:width=3 [extended] | reused | 2026-10-29T01:17:27Z |
| miri-700add6be63594a6 | sha3 | miri | sha3-fixed-boundaries:58 [extended] | reused | 2026-10-28T13:43:54Z |
| miri-70217d3cd7baaf5f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:31:width=0 [extended] | reused | 2026-10-28T23:32:36Z |
| miri-70254a16cd2cbf1c | sha1 | miri | sha1-bulk:175 [extended] | reused | 2026-10-28T13:00:49Z |
| miri-702afc5f75aab6fc | sha1 | miri | sha1-scoped:266 [extended] | reused | 2026-10-28T13:23:33Z |
| miri-70342bff4cfb6df8 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:55:width=3 [extended] | reused | 2026-10-28T22:25:13Z |
| miri-703ee5c092c6cf65 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:24:width=0 [extended] | reused | 2026-10-28T20:14:03Z |
| miri-70544cbb6f3aeb10 | md5 | miri | md5-scoped:134 [extended] | reused | 2026-10-28T12:07:15Z |
| miri-7060112eb33c2734 | tuplehash | miri | tuplehash-staging:683 [extended] | reused | 2026-10-29T00:03:46Z |
| miri-7066628d999a5e40 | md5 | miri | md5-batch-mask:253 [routine] | passed | 2026-10-19T11:15:11Z |
| miri-706c9840474274f2 | md5 | miri | md5-bulk:256 [routine] | passed | 2026-10-19T11:29:33Z |
| miri-70888400e5efe83a | tuplehash | miri | tuplehash-staging:33 [extended] | reused | 2026-10-28T14:32:00Z |
| miri-7091e364f84a5fc6 | tuplehash | miri | tuplehash-staging:269 [extended] | reused | 2026-10-28T15:51:10Z |
| miri-709623c9eb311db3 | tuplehash | miri | scoped_tuplexof128_differential:24:width=3 [extended] | reused | 2026-10-29T01:17:49Z |
| miri-70be6bea560622d2 | sha1 | miri | sha1-scoped:109 [extended] | reused | 2026-10-28T13:18:33Z |
| miri-70c7a611ee3d5a99 | md5 | miri | md5-scoped:112 [extended] | reused | 2026-10-28T12:00:36Z |
| miri-70d8b5b0e840fba5 | md5 | miri | md5-batch-mask:57 [extended] | reused | 2026-10-28T12:11:47Z |
| miri-70dfa1fe29616879 | tuplehash | miri | scoped_tuplexof256_differential:34:width=0 [extended] | reused | 2026-10-29T03:25:12Z |
| miri-70e131e0601cbcf3 | sanitization | miri | -p brynja-sanitization --test behavior [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-70e7bc842e83a88c | md5 | miri | md5-bulk:5 [extended] | reused | 2026-10-28T11:28:03Z |
| miri-70f6aeb2b7c8e62f | md5 | miri | md5-batch-mask:34 [extended] | reused | 2026-10-28T12:20:44Z |
| miri-7105ca6009b8397f | tuplehash | miri | scoped_tuplexof128_differential:8:width=1 [extended] | reused | 2026-10-29T00:43:10Z |
| miri-7112ab03bd0ed623 | kmac | miri | kmac-streamed-setup:22 [routine] | No mapped observation | — |
| miri-7113d2778749835a | tuplehash | miri | tuplehash-staging:453 [extended] | reused | 2026-10-28T16:52:39Z |
| miri-711ee0ad83ba9714 | md5 | miri | md5-scoped:262 [extended] | reused | 2026-10-28T12:16:26Z |
| miri-713480991d1a1099 | kmac | miri | kmac-scoped-xof-lifecycle:15 [routine] | passed | 2026-10-19T15:36:19Z |
| miri-714085db561ae6b2 | tuplehash | miri | tuplehash-staging:176 [extended] | reused | 2026-10-28T15:05:34Z |
| miri-714cd1156efcdf21 | md5 | miri | md5-batch-mask:22 [extended] | reused | 2026-10-28T12:19:52Z |
| miri-7163ab37fc1fc30d | tuplehash | miri | scoped_tuplexof256_differential:38:width=4 [extended] | reused | 2026-10-29T03:34:42Z |
| miri-7177ab36994404f8 | sha3 | miri | sha3-secret-xof-bits:1 [extended] | reused | 2026-10-28T13:44:31Z |
| miri-71a0209f5ae5c0c5 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:19 [extended] | passed | 2026-10-29T13:55:06Z |
| miri-71be8f31a663f2ba | sha1 | miri | sha1-bulk:34 [extended] | reused | 2026-10-28T12:42:52Z |
| miri-71cc405dc75063e5 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:38:width=1 [extended] | reused | 2026-10-28T20:41:14Z |
| miri-71db5aaeb05c009a | sha1 | miri | sha1-bulk:224 [extended] | reused | 2026-10-28T12:59:00Z |
| miri-71e574e17435bea4 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:9 [routine] | No mapped observation | — |
| miri-71ef648f8e7637c8 | md5 | miri | md5-scoped:154 [extended] | reused | 2026-10-28T12:08:38Z |
| miri-7202c606af15e677 | tuplehash | miri | tuplehash-staging:667 [extended] | reused | 2026-10-28T23:58:24Z |
| miri-720ecc397b6a06bf | sha1 | miri | sha1-scoped:11 [extended] | reused | 2026-10-28T13:16:35Z |
| miri-72121d3361d05e01 | kmac | miri | kmac-streamed-setup:62 [routine] | No mapped observation | — |
| miri-7212c5fd358374b8 | md5 | miri | md5-scoped:116 [extended] | reused | 2026-10-28T12:00:53Z |
| miri-72199c02095a8588 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:15 [routine] | passed | 2026-10-19T12:27:22Z |
| miri-721ae7c7f55331c7 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:18 [routine] | No mapped observation | — |
| miri-7220c230a2b3af4b | md5 | miri | md5-scoped:148 [extended] | reused | 2026-10-28T12:03:03Z |
| miri-722d2e38eb4e54d5 | md5 | miri | md5-padding:81 [extended] | reused | 2026-10-28T11:33:36Z |
| miri-723c70eaff97f18e | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:13 [routine] | No mapped observation | — |
| miri-7247a60858c263ce | tuplehash | miri | scoped_tuplexof256_differential:46:width=2 [extended] | reused | 2026-10-29T03:59:12Z |
| miri-724b50fc9b618202 | sha3 | miri | sha3-fixed-boundaries:25 [extended] | reused | 2026-10-28T13:34:27Z |
| miri-725228c13b288196 | tuplehash | miri | tuplehash-staging:875 [extended] | reused | 2026-10-29T01:08:33Z |
| miri-7286f1affe286b02 | sha1 | miri | sha1-scoped:183 [extended] | reused | 2026-10-28T13:29:24Z |
| miri-7289cd69cd0f2052 | sha1 | miri | sha1-scoped:182 [extended] | reused | 2026-10-28T13:16:39Z |
| miri-728bd987ded30fae | md5 | miri | md5-batch-mask:231 [extended] | reused | 2026-10-28T12:25:41Z |
| miri-72910176e13bbfad | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:49:width=0 [extended] | reused | 2026-10-29T06:33:54Z |
| miri-72991c25fa6619dc | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:2:width=0 [extended] | reused | 2026-10-28T21:56:04Z |
| miri-72a68a4b96f9f759 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:29:width=4 [extended] | reused | 2026-10-29T05:23:03Z |
| miri-72aebf018ee0f775 | md5 | miri | md5-bulk:91 [extended] | reused | 2026-10-28T11:34:12Z |
| miri-72b8181c3ce631af | sha1 | miri | sha1-scoped:239 [extended] | reused | 2026-10-28T13:34:05Z |
| miri-72b8336967c20440 | tuplehash | miri | tuplehash-staging:187 [extended] | reused | 2026-10-28T21:17:02Z |
| miri-72bf2c9ff67a7fe7 | sha3 | miri | sha3-fixed-boundaries:60 [extended] | reused | 2026-10-28T13:52:44Z |
| miri-72c7c7f934136aa7 | md5 | miri | md5-scoped:29 [extended] | reused | 2026-10-28T11:49:31Z |
| miri-72ce09b0b30f038a | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:51:width=4 [extended] | reused | 2026-10-29T00:43:55Z |
| miri-72cfcad4fc31c93c | tuplehash | miri | tuplehash-staging:868 [extended] | reused | 2026-10-28T18:48:26Z |
| miri-72d070a1ca556546 | sha3 | miri | sha3-fixed-boundaries:24 [extended] | reused | 2026-10-28T13:47:46Z |
| miri-72f939a93556dfcc | tuplehash | miri | tuplehash-staging:537 [extended] | reused | 2026-10-28T17:20:29Z |
| miri-730052a352c0a681 | md5 | miri | md5-bulk:74 [extended] | reused | 2026-10-28T11:37:23Z |
| miri-730623a1935fcb9d | tuplehash | miri | tuplehash-staging:4 [extended] | reused | 2026-10-28T14:10:02Z |
| miri-730f0c70fa094981 | kmac | miri | kmac-streamed-setup:11 [routine] | No mapped observation | — |
| miri-732b8dcd667dcb66 | md5 | miri | md5-batch-mask:75 [extended] | reused | 2026-10-28T12:12:57Z |
| miri-733f4d934c78678f | tuplehash | miri | tuplehash-staging:562 [extended] | reused | 2026-10-28T17:13:53Z |
| miri-7345b6c0e3e741ed | sha1 | miri | sha1-scoped:110 [extended] | reused | 2026-10-28T13:10:50Z |
| miri-734cf4f15ce5375f | sha3 | miri | sha3-fixed-bits:18 [extended] | reused | 2026-10-28T13:48:15Z |
| miri-734ebd8e7ea82116 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:27:width=4 [extended] | reused | 2026-10-28T20:42:37Z |
| miri-7353a38868f83c31 | md5 | miri | md5-bulk:163 [extended] | reused | 2026-10-28T11:39:38Z |
| miri-735a191b621fc9ad | md5 | miri | md5-batch-mask:254 [extended] | reused | 2026-10-28T12:38:36Z |
| miri-735aa0726fdc09f0 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:31:width=4 [extended] | reused | 2026-10-28T23:32:36Z |
| miri-7377da7cd7f4c60d | md5 | miri | md5-scoped:141 [routine] | passed | 2026-10-19T11:14:30Z |
| miri-737aaa3e1ac9a027 | sha1 | miri | sha1-bulk:52 [extended] | reused | 2026-10-28T12:42:24Z |
| miri-73856c44b3c7f9bb | tuplehash | miri | scoped_tuplexof128_differential:0:width=4 [extended] | reused | 2026-10-29T00:30:00Z |
| miri-739878c846fd3770 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-faults:3 [extended] | passed | 2026-10-29T14:20:04Z |
| miri-7399787c2aaf58ba | md5 | miri | md5-scoped:152 [extended] | reused | 2026-10-28T12:03:19Z |
| miri-739dfb0543887dac | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:37:width=1 [extended] | reused | 2026-10-29T03:03:13Z |
| miri-73a1aa420f94f0c6 | sha1 | miri | sha1-scoped:9 [extended] | reused | 2026-10-28T13:11:22Z |
| miri-73b00c233871e138 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:114 [routine] | No mapped observation | — |
| miri-73bcfcb39503dcee | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:33:width=0 [extended] | reused | 2026-10-29T05:32:49Z |
| miri-73d1502648b9c0ee | tuplehash | miri | tuplehash-staging:28 [extended] | reused | 2026-10-28T14:17:37Z |
| miri-73dc8e66159467b0 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:34:width=3 [extended] | reused | 2026-10-28T20:32:01Z |
| miri-73f583a032cbd857 | sha3 | miri | -p brynja-hash-sha3 --test bit_inputs curated_nist_cavp_vectors_cover_every_function_and_bit_residue [remaining suite; inspect skips with show] | reused | 2026-10-28T13:31:02Z |
| miri-73ffb84e967e6e88 | tuplehash | miri | tuplehash-staging:730 [extended] | reused | 2026-10-28T18:07:41Z |
| miri-7409f2085128ed56 | sha1 | miri | sha1-bulk:225 [extended] | reused | 2026-10-28T13:11:30Z |
| miri-74347fec84360254 | md5 | miri | md5-scoped:9 [extended] | reused | 2026-10-28T11:48:12Z |
| miri-743a3c2eaa1a77ef | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:45 [routine] | No mapped observation | — |
| miri-744af6a396abd201 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:15 [routine] | passed | 2026-10-19T12:30:50Z |
| miri-74566d263b38607b | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:4 [extended] | passed | 2026-10-29T13:19:58Z |
| miri-7457fe0294eb28c0 | md5 | miri | md5-bulk:37 [extended] | reused | 2026-10-28T11:30:09Z |
| miri-746168677a36abc8 | md5 | miri | md5-batch-mask:229 [extended] | reused | 2026-10-28T12:25:27Z |
| miri-7481ed5f8b201ebb | tuplehash | miri | -p brynja-hash-tuple --features hardened-execution --lib execution [remaining suite; inspect skips with show] | passed | 2026-10-19T11:52:16Z |
| miri-74860d5fc0a331ed | sha3 | miri | sha3-fixed-bits:11 [extended] | reused | 2026-10-28T13:47:52Z |
| miri-749098cdbf76f8e1 | sha1 | miri | sha1-scoped:93 [extended] | reused | 2026-10-28T13:17:20Z |
| miri-74aa0af7324eddb0 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:5:width=4 [extended] | reused | 2026-10-29T01:50:26Z |
| miri-74aa10eb51b9528c | tuplehash | miri | tuplehash-staging:442 [extended] | reused | 2026-10-28T16:35:25Z |
| miri-74c499139a3b0552 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:42:width=4 [extended] | reused | 2026-10-28T23:21:51Z |
| miri-74dac25fb83b51a6 | tuplehash | miri | tuplehash-staging:784 [extended] | reused | 2026-10-28T18:21:35Z |
| miri-74eb8cf6eebea7d0 | tuplehash | miri | tuplehash-staging:477 [extended] | reused | 2026-10-28T17:00:08Z |
| miri-74f5b9654e9ade09 | md5 | miri | md5-scoped:160 [extended] | reused | 2026-10-28T12:03:52Z |
| miri-74faf26715956c8e | tuplehash | miri | scoped_tuplexof128_differential:21:width=3 [extended] | passed | 2026-10-29T10:56:24Z |
| miri-751182067e47afdc | md5 | miri | md5-bulk:155 [extended] | reused | 2026-10-28T11:39:00Z |
| miri-75173ae216ad4da3 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:0 [routine] | No mapped observation | — |
| miri-751d295b7cfd46a2 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:4 [routine] | No mapped observation | — |
| miri-751d31432a75233f | kmac | miri | kmac-streamed-setup:49 [routine] | No mapped observation | — |
| miri-7534cd376e8603bf | md5 | miri | md5-padding:77 [extended] | reused | 2026-10-28T11:33:17Z |
| miri-753e37b7a8e79188 | sha1 | miri | sha1-scoped:250 [extended] | reused | 2026-10-28T13:22:12Z |
| miri-7542ccf7f0b15bd5 | tuplehash | miri | tuplehash-staging:483 [extended] | reused | 2026-10-28T22:56:35Z |
| miri-7543500d526b4de5 | tuplehash | miri | tuplehash-staging:603 [extended] | reused | 2026-10-28T23:36:27Z |
| miri-754ea2309acbf491 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_unwind_reuse:2 [routine] | No mapped observation | — |
| miri-75514c3d70b1e446 | tuplehash | miri | scoped_tuplexof128_differential:21:width=4 [extended] | passed | 2026-10-29T11:00:14Z |
| miri-756fe373703630d6 | sha1 | miri | sha1-scoped:81 [extended] | reused | 2026-10-28T13:16:22Z |
| miri-7571b599009b29de | tuplehash | miri | tuplehash-staging:270 [extended] | reused | 2026-10-28T15:39:54Z |
| miri-7577a42a13027896 | tuplehash | miri | tuplehash-staging:584 [extended] | reused | 2026-10-28T17:17:51Z |
| miri-757a13a91c287490 | md5 | miri | md5-bulk:143 [extended] | reused | 2026-10-28T11:38:05Z |
| miri-757e3b9a23688b21 | tuplehash | miri | scoped_tuplexof256_differential:33:width=2 [extended] | passed | 2026-10-29T12:41:50Z |
| miri-758669dc16fe3eb4 | tuplehash | miri | tuplehash-staging:15 [extended] | reused | 2026-10-28T20:19:06Z |
| miri-759e3bf45a08465d | tuplehash | miri | tuplehash-staging:632 [extended] | reused | 2026-10-28T17:32:54Z |
| miri-75b57cb811282ecf | tuplehash | miri | tuplehash-staging:49 [extended] | reused | 2026-10-28T14:37:09Z |
| miri-75bcd30e6a9b4cce | md5 | miri | md5-bulk:233 [extended] | reused | 2026-10-28T11:45:09Z |
| miri-75bd949038668d7f | kmac | miri | kmac-scoped-xof-lifecycle:1 [extended] | reused | 2026-10-28T14:07:30Z |
| miri-75d5c53f1bdd7f66 | sha1 | miri | sha1-padding:28 [extended] | reused | 2026-10-28T12:36:30Z |
| miri-75e08206b2168fdb | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:30:width=4 [extended] | reused | 2026-10-28T22:52:04Z |
| miri-75e8f43ca06aa35e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:13:width=0 [extended] | reused | 2026-10-29T04:44:00Z |
| miri-75ef58546510ecd2 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:28:width=1 [extended] | reused | 2026-10-28T22:52:29Z |
| miri-75f46c98d54ac3e2 | sha3 | miri | sha3-fixed-boundaries:42 [extended] | reused | 2026-10-28T13:41:39Z |
| miri-75f69dc6ccf8ef68 | tuplehash | miri | scoped_tuplexof256_differential:19:width=0 [extended] | reused | 2026-10-29T03:40:19Z |
| miri-75faacd3d0a8bf8f | sha1 | miri | sha1-bulk:15 [extended] | reused | 2026-10-28T12:47:05Z |
| miri-76062492631dff0e | tuplehash | miri | tuplehash-staging:358 [extended] | reused | 2026-10-28T16:08:09Z |
| miri-760931bc9febdaea | sha3 | miri | sha3-secret-xof-bits:5 [extended] | reused | 2026-10-28T13:45:05Z |
| miri-760e5ade79499dc1 | sha2 | miri | -p brynja-hash-sha2 --features runtime-execution,general-sha512-t --test execution bounded_execution_lifecycle_smoke [remaining suite; inspect skips with show] | reused | 2026-10-28T13:33:26Z |
| miri-76269d64ed681391 | sha3 | miri | sha3-fixed-boundaries:48 [extended] | reused | 2026-10-28T13:51:05Z |
| miri-762d9d3391a644ff | sha3 | miri | sha3-fixed-boundaries:7 [extended] | reused | 2026-10-28T13:37:23Z |
| miri-7637b36032a1c471 | tuplehash | miri | scoped_tuplexof128_differential:32:width=0 [extended] | reused | 2026-10-29T01:36:57Z |
| miri-76380427ce8ca85a | tuplehash | miri | scoped_tuplexof256_differential:16:width=2 [extended] | reused | 2026-10-29T02:47:58Z |
| miri-763a2a30807f9310 | md5 | miri | md5-batch-mask:164 [extended] | reused | 2026-10-28T12:25:29Z |
| miri-7640b7f2516b5180 | md5 | miri | md5-bulk:113 [extended] | reused | 2026-10-28T11:35:28Z |
| miri-76411c13ebb66ec4 | sha1 | miri | sha1-padding:98 [extended] | reused | 2026-10-28T12:47:48Z |
| miri-764c53006510b6e3 | tuplehash | miri | tuplehash-staging:80 [extended] | reused | 2026-10-28T14:34:53Z |
| miri-7651c7e44977067b | md5 | miri | md5-scoped:167 [extended] | reused | 2026-10-28T11:58:33Z |
| miri-765a001ca331fdf4 | md5 | miri | md5-bulk:192 [routine] | passed | 2026-10-19T11:26:23Z |
| miri-766503d10de9d6ea | md5 | miri | md5-scoped:228 [extended] | reused | 2026-10-28T12:08:37Z |
| miri-7685f318727f5da7 | md5 | miri | md5-bulk:122 [extended] | reused | 2026-10-28T11:41:05Z |
| miri-7695896d5390163e | md5 | miri | md5-padding:56 [extended] | reused | 2026-10-28T11:22:14Z |
| miri-76a623e791191ad9 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:50:width=0 [extended] | reused | 2026-10-28T23:58:01Z |
| miri-76aa0cdd018a958c | md5 | miri | md5-batch-mask:191 [extended] | reused | 2026-10-28T12:22:25Z |
| miri-76aa373482a1fcde | tuplehash | miri | scoped_tuplexof256_differential:45:width=4 [extended] | passed | 2026-10-29T12:55:08Z |
| miri-76aa81cd6031ec9a | tuplehash | miri | tuplehash-staging:657 [extended] | reused | 2026-10-28T18:01:17Z |
| miri-76d7ddf2508a509c | tuplehash | miri | scoped_tuplexof256_differential:14:width=4 [extended] | reused | 2026-10-29T02:37:48Z |
| miri-76f793dbc8628ca8 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:41:width=4 [extended] | reused | 2026-10-29T03:15:49Z |
| miri-7715e54135f5661a | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:41:width=3 [extended] | reused | 2026-10-29T03:15:49Z |
| miri-774815c27ccf60c1 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:25:width=0 [extended] | reused | 2026-10-29T02:33:53Z |
| miri-774c518cedbb2e51 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:26:width=4 [extended] | reused | 2026-10-28T22:42:58Z |
| miri-775c988a60915712 | parallelhash | miri | [bounded-parallelhash-v1] parallelhashxof-official:1 [extended] | passed | 2026-10-29T13:59:22Z |
| miri-77b32e7323317e65 | sha1 | miri | sha1-scoped:29 [extended] | reused | 2026-10-28T13:12:43Z |
| miri-77b7cc3c6f4cbece | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-slots:2 [extended] | passed | 2026-10-29T15:08:37Z |
| miri-77bf4fdbae4b87e9 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:351 [extended] | passed | 2026-10-29T13:51:50Z |
| miri-77c891f0b6b2b02d | tuplehash | miri | tuplehash-staging:388 [extended] | reused | 2026-10-28T16:15:14Z |
| miri-77feedd121657f53 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:14 [routine] | No mapped observation | — |
| miri-7805d464bc085fcd | md5 | miri | md5-bulk:2 [extended] | reused | 2026-10-28T11:32:33Z |
| miri-7805d8ab872d7002 | tuplehash | miri | tuplehash-staging:257 [extended] | reused | 2026-10-28T15:46:42Z |
| miri-781ac3f171738150 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:9 [extended] | passed | 2026-10-29T13:03:10Z |
| miri-781aefbc8f13f49a | md5 | miri | md5-batch-mask:246 [extended] | reused | 2026-10-28T12:37:51Z |
| miri-7820c55702a3ce0d | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:36:width=3 [extended] | reused | 2026-10-28T20:41:38Z |
| miri-7831094192ff493b | tuplehash | miri | tuplehash-staging:124 [extended] | reused | 2026-10-28T14:48:55Z |
| miri-7835226d28465f04 | md5 | miri | md5-scoped:180 [extended] | reused | 2026-10-28T12:05:15Z |
| miri-7842a5fd7ef8eb10 | md5 | miri | md5-padding:113 [extended] | reused | 2026-10-28T11:36:11Z |
| miri-7856be7f93856197 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:19:width=1 [extended] | reused | 2026-10-28T23:03:10Z |
| miri-78672dbfa91a8fa6 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:10:width=0 [extended] | reused | 2026-10-28T19:39:30Z |
| miri-786b73935cce2a6e | sha1 | miri | sha1-scoped:220 [extended] | reused | 2026-10-28T13:21:15Z |
| miri-786e85075630453a | md5 | miri | md5-scoped:275 [extended] | reused | 2026-10-28T12:06:22Z |
| miri-7878c78e8505ff9a | md5 | miri | md5-scoped:46 [extended] | reused | 2026-10-28T12:01:11Z |
| miri-787a077ecf4d0929 | tuplehash | miri | scoped_tuplexof256_differential:23:width=1 [extended] | reused | 2026-10-29T03:50:03Z |
| miri-789f9a9614d2ebdd | tuplehash | miri | scoped_tuplexof128_differential:40:width=1 [extended] | reused | 2026-10-29T01:58:45Z |
| miri-78b4410f8ca8d0ab | md5 | miri | md5-scoped:216 [extended] | reused | 2026-10-28T12:07:46Z |
| miri-78b81b6213b59574 | kmac | miri | kmac-scoped-xof-lifecycle:10 [extended] | reused | 2026-10-28T14:02:42Z |
| miri-78bc5e05c2fe77b5 | static_cpu | miri | -p brynja-crypto-cpu-std --features runtime-execution --lib execution [remaining suite; inspect skips with show] | passed | 2026-10-19T13:59:03Z |
| miri-78ce4e02fd3a7701 | tuplehash | miri | scoped_tuplexof256_differential:33:width=0 [extended] | passed | 2026-10-29T12:40:53Z |
| miri-78d14a81ce5684f2 | hmac | miri | sha256 [routine] | No mapped observation | — |
| miri-78e4a2107eb2c5d7 | sha1 | miri | sha1-scoped:79 [extended] | reused | 2026-10-28T13:21:29Z |
| miri-78fb2761cf499ea9 | tuplehash | miri | scoped_tuplexof256_differential:15:width=3 [extended] | reused | 2026-10-29T03:30:33Z |
| miri-790b644262b125e5 | kmac | miri | kmac-streamed-setup:26 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-790f00bbd4ab5f8f | kmac | miri | kmac-streamed-setup:79 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-79162718b8bb8dcf | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:51:width=3 [extended] | reused | 2026-10-28T22:01:22Z |
| miri-7930e4dbb24a42bc | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:49:width=1 [extended] | reused | 2026-10-29T06:33:54Z |
| miri-7930f87d5c52a88d | kmac | miri | kmac-streamed-setup:35 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-794015ca387aac36 | md5 | miri | md5-bulk:187 [extended] | reused | 2026-10-28T11:41:31Z |
| miri-7960f9acd575f794 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:18:width=2 [extended] | reused | 2026-10-28T22:24:48Z |
| miri-79667b024816d662 | kmac | miri | kmac-streamed-setup:47 [routine] | No mapped observation | — |
| miri-796b609fe529b25a | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:29:width=2 [extended] | reused | 2026-10-29T05:23:03Z |
| miri-796ea352fd982b69 | kmac | miri | kmac-streamed-setup:4 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-7975135ac2fc4626 | sha1 | miri | sha1-bulk:164 [extended] | reused | 2026-10-28T12:52:20Z |
| miri-79782692f1252117 | md5 | miri | md5-padding:36 [extended] | reused | 2026-10-28T11:20:42Z |
| miri-797a576c8ec7b389 | md5 | miri | -p brynja-legacy-md5 --features cpu --test cpu [remaining suite; inspect skips with show] | reused | 2026-10-28T11:17:38Z |
| miri-7985cff9005424b7 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:9:width=4 [extended] | reused | 2026-10-29T04:37:02Z |
| miri-798de7787caf112f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:27:width=0 [extended] | reused | 2026-10-28T23:22:47Z |
| miri-799bfb273f2e23ed | tuplehash | miri | tuplehash-staging:345 [extended] | reused | 2026-10-28T16:16:23Z |
| miri-79b9f2a4b7189995 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:46 [routine] | No mapped observation | — |
| miri-79c15fd434d4b9d1 | md5 | miri | md5-batch-mask:8 [extended] | reused | 2026-10-28T12:13:35Z |
| miri-79de59f5a8f87cb9 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:16:width=3 [extended] | reused | 2026-10-28T22:25:09Z |
| miri-79ed1fa59e6ed642 | md5 | miri | md5-batch-mask:230 [extended] | reused | 2026-10-28T12:36:25Z |
| miri-79eedc2c11812e54 | legacy_hmac | miri | output_unwind [existing-full] | No mapped observation | — |
| miri-7a0df3a658b28b3e | tuplehash | miri | tuplehash-staging:847 [extended] | reused | 2026-10-29T00:59:08Z |
| miri-7a25017ea988286f | tuplehash | miri | scoped_tuplexof256_differential:37:width=1 [extended] | passed | 2026-10-29T12:10:56Z |
| miri-7a33446c32fb86c5 | tuplehash | miri | tuplehash-staging:777 [extended] | reused | 2026-10-28T18:41:18Z |
| miri-7a3e2e95c51d3d9c | tuplehash | miri | scoped_tuplexof128_differential:19:width=1 [extended] | reused | 2026-10-29T01:48:20Z |
| miri-7a4b0e4bbb6efc76 | md5 | miri | md5-scoped:109 [extended] | reused | 2026-10-28T11:54:54Z |
| miri-7a5455228c0d3309 | tuplehash | miri | scoped_tuplexof256_differential:16:width=3 [extended] | reused | 2026-10-29T02:47:58Z |
| miri-7a5c7e32a0c00e87 | md5 | miri | md5-padding:0 [extended] | reused | 2026-10-28T11:18:02Z |
| miri-7a773ec585df73c7 | md5 | miri | md5-scoped:38 [extended] | reused | 2026-10-28T12:00:39Z |
| miri-7a81cae3f47dda97 | kmac | miri | kmac-streamed-setup:71 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-7a8663584d20628a | tuplehash | miri | scoped_tuplexof256_differential:32:width=1 [extended] | reused | 2026-10-29T03:25:53Z |
| miri-7a8ee81cca069351 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:1:width=2 [extended] | reused | 2026-10-29T01:43:26Z |
| miri-7aab66eb07929e16 | md5 | miri | md5-bulk:75 [extended] | reused | 2026-10-28T11:33:03Z |
| miri-7ab396dc83c21c64 | sha3 | miri | sha3-fixed-boundaries:65 [extended] | reused | 2026-10-28T13:40:18Z |
| miri-7ab9f8e6c7031c34 | tuplehash | miri | scoped_tuplexof128_differential:34:width=3 [extended] | reused | 2026-10-29T01:36:07Z |
| miri-7ac06a2f3eb34f27 | md5 | miri | md5-scoped:150 [routine] | passed | 2026-10-19T11:29:41Z |
| miri-7ad3c8ef4aacdb3a | tuplehash | miri | scoped_tuplexof128_differential:26:width=3 [extended] | reused | 2026-10-29T01:16:55Z |
| miri-7b07d72ba43002d4 | md5 | miri | -p brynja-legacy-md5 --features execution --lib operational_revalidator_unwind_quarantines_without_instructions [remaining suite; inspect skips with show] | reused | 2026-10-28T11:22:30Z |
| miri-7b2132a5cd6a0181 | md5 | miri | md5-bulk:193 [extended] | reused | 2026-10-28T11:41:44Z |
| miri-7b3b2177e398892e | md5 | miri | md5-batch-mask:119 [extended] | reused | 2026-10-28T12:16:27Z |
| miri-7b55781ce723da62 | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib metadata_and_preselected_tag_policy [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-7b5d253dd0635172 | kmac | miri | kmac-scoped-lifecycle:16 [extended] | reused | 2026-10-28T14:00:01Z |
| miri-7b5da32dba44d151 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:0 [extended] | passed | 2026-10-29T13:14:22Z |
| miri-7b7500cbf3d12a87 | hmac | miri | sha512_224 [existing-full] | No mapped observation | — |
| miri-7b8ff9e272dc54f8 | tuplehash | miri | tuplehash-staging:60 [extended] | reused | 2026-10-28T14:27:54Z |
| miri-7b9b630e0ab7c5e2 | md5 | miri | md5-scoped:243 [extended] | reused | 2026-10-28T12:04:02Z |
| miri-7baa4fb15a8dae19 | tuplehash | miri | scoped_tuplexof128_differential:1:width=2 [extended] | reused | 2026-10-29T07:08:40Z |
| miri-7bad10c7e240111c | sha1 | miri | sha1-bulk:228 [extended] | reused | 2026-10-28T12:59:28Z |
| miri-7bc4523ab0b6d0aa | tuplehash | miri | tuplehash-staging:617 [extended] | reused | 2026-10-28T17:47:02Z |
| miri-7bcefebc5e98a845 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:36 [routine] | No mapped observation | — |
| miri-7bd36f8df650ddb8 | sha1 | miri | sha1-padding:36 [extended] | reused | 2026-10-28T12:37:09Z |
| miri-7bd5478ffe6dead0 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:7:width=4 [extended] | reused | 2026-10-28T22:39:20Z |
| miri-7bd8031ab44a2fa0 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_unwind_reuse:3 [routine] | No mapped observation | — |
| miri-7bdb0072b839ba5b | md5 | miri | md5-scoped:212 [extended] | reused | 2026-10-28T12:07:29Z |
| miri-7bdb9c05fdc2c542 | md5 | miri | md5-bulk:228 [extended] | reused | 2026-10-28T11:55:12Z |
| miri-7bde4c1abc6b66dc | md5 | miri | md5-batch-mask:42 [extended] | reused | 2026-10-28T12:21:21Z |
| miri-7be0426877f658d2 | md5 | miri | md5-padding:17 [extended] | reused | 2026-10-28T11:29:00Z |
| miri-7bedaff948185abd | sha1 | miri | sha1-scoped:124 [extended] | reused | 2026-10-28T13:13:30Z |
| miri-7bf20c2b76de5d07 | sha1 | miri | sha1-scoped:209 [extended] | reused | 2026-10-28T13:26:20Z |
| miri-7bf94d69ee0247c3 | md5 | miri | md5-batch-mask:128 [extended] | reused | 2026-10-28T12:22:40Z |
| miri-7c00fb060be0faa0 | tuplehash | miri | tuplehash-staging:24 [extended] | reused | 2026-10-28T14:16:42Z |
| miri-7c15e3dc5d873caf | sha3 | miri | sha3-fixed-bits:24 [routine] | passed | 2026-10-19T11:39:01Z |
| miri-7c251daef5b615c8 | md5 | miri | md5-batch-mask:247 [extended] | reused | 2026-10-28T12:27:02Z |
| miri-7c71c615fc4ba9d1 | tuplehash | miri | scoped_tuplexof128_differential:42:width=1 [extended] | reused | 2026-10-29T01:58:04Z |
| miri-7c775c03f882ec50 | kmac | miri | verification_accepts_exact_tag_and_rejects_first_last_and_length_changes [extended] | reused | 2026-10-28T14:10:50Z |
| miri-7c77f7d92f55dc5d | tuplehash | miri | tuplehash-staging:532 [extended] | reused | 2026-10-28T17:00:48Z |
| miri-7c82c0b389d41016 | tuplehash | miri | tuplehash-staging:686 [extended] | reused | 2026-10-28T17:53:33Z |
| miri-7c94d42a221006fb | sha1 | miri | sha1-scoped:162 [extended] | reused | 2026-10-28T13:15:01Z |
| miri-7c9607bbdfa52983 | md5 | miri | md5-bulk:198 [extended] | reused | 2026-10-28T11:47:33Z |
| miri-7caebe8a03ce699a | md5 | miri | md5-batch-mask:69 [extended] | reused | 2026-10-28T12:12:42Z |
| miri-7cbf9528e9d17c90 | sha1 | miri | sha1-bulk:158 [extended] | reused | 2026-10-28T12:53:17Z |
| miri-7ce7d143c9b5e7a0 | sha1 | miri | sha1-padding:125 [extended] | reused | 2026-10-28T12:38:52Z |
| miri-7cf474dadf9892ca | tuplehash | miri | tuplehash-staging:320 [extended] | reused | 2026-10-28T15:52:44Z |
| miri-7d16e2f2d2fe99a2 | tuplehash | miri | tuplehash-staging:252 [extended] | reused | 2026-10-28T15:30:32Z |
| miri-7d17af41a28e383b | sha1 | miri | sha1-bulk:83 [extended] | reused | 2026-10-28T12:51:55Z |
| miri-7d1ca53d9e3aa607 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:7:width=3 [extended] | reused | 2026-10-28T22:39:20Z |
| miri-7d23d1306b4abd54 | kmac | miri | kmac-framing:3 [routine] | passed | 2026-10-19T11:49:04Z |
| miri-7d25d546d4d9fb67 | md5 | miri | md5-padding:108 [extended] | reused | 2026-10-28T11:26:21Z |
| miri-7d2eb37ab82b3572 | tuplehash | miri | tuplehash-staging:542 [extended] | reused | 2026-10-28T17:07:50Z |
| miri-7d333d45f6a95f7a | sha1 | miri | sha1-scoped:67 [extended] | reused | 2026-10-28T13:20:36Z |
| miri-7d386e34d8492597 | tuplehash | miri | tuplehash-staging:424 [extended] | reused | 2026-10-28T16:26:26Z |
| miri-7d3982270bedd3d1 | sha1 | miri | sha1-scoped:225 [extended] | reused | 2026-10-28T13:27:41Z |
| miri-7d46b7f5a85f5b3c | tuplehash | miri | scoped_tuplexof256_differential:25:width=1 [extended] | passed | 2026-10-29T12:04:23Z |
| miri-7d499f67e16db4ab | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:29:width=0 [extended] | reused | 2026-10-29T05:23:03Z |
| miri-7d5bfc2d5b42c05a | kmac | miri | kmac-streamed-setup:72 [routine] | No mapped observation | — |
| miri-7d68d3ae26c92338 | md5 | miri | md5-bulk:205 [extended] | reused | 2026-10-28T11:42:45Z |
| miri-7d6a948103ca8702 | kmac | miri | kmac-streamed-setup:19 [routine] | No mapped observation | — |
| miri-7d8d4d554cc3b59e | tuplehash | miri | tuplehash-staging:745 [extended] | reused | 2026-10-28T18:30:55Z |
| miri-7d914516b5fecae7 | sha1 | miri | sha1-bulk:82 [extended] | reused | 2026-10-28T12:46:20Z |
| miri-7d9c57e19cb36d2c | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:38:width=2 [extended] | reused | 2026-10-28T23:10:13Z |
| miri-7dad65fdbe7b1bc6 | tuplehash | miri | xof_partitions_and_hardened_output_match [routine] | passed | 2026-10-19T12:21:36Z |
| miri-7db6beb2d6d1d918 | kmac | miri | kmac-streamed-setup:38 [routine] | No mapped observation | — |
| miri-7dd0476ba69428f1 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:45:width=4 [extended] | reused | 2026-10-29T06:07:36Z |
| miri-7df3499b7044ded6 | tuplehash | miri | tuplehash-staging:757 [extended] | reused | 2026-10-28T18:34:10Z |
| miri-7dfb662258f52186 | md5 | miri | md5-bulk:56 [extended] | reused | 2026-10-28T11:41:10Z |
| miri-7e019985b3d28896 | tuplehash | miri | tuplehash-execution-fixed:8 [extended] | reused | 2026-10-28T19:11:21Z |
| miri-7e03bf5017951015 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:23:width=3 [extended] | reused | 2026-10-28T23:12:58Z |
| miri-7e17f5edf2b1a803 | static_cpu | miri | -p brynja-crypto-cpu-std --features runtime-execution --lib execution [remaining suite; inspect skips with show] | passed | 2026-10-29T15:16:24Z |
| miri-7e18e1428a40049e | sha1 | miri | sha1-bulk:27 [extended] | reused | 2026-10-28T12:47:51Z |
| miri-7e1eacb2b05fba72 | tuplehash | miri | tuplehash-staging:263 [extended] | reused | 2026-10-28T21:42:42Z |
| miri-7e2590cce794e649 | sha1 | miri | sha1-padding:77 [extended] | reused | 2026-10-28T12:34:24Z |
| miri-7e2b83ea93aa48e9 | sha3 | miri | sha3-fixed-bits:26 [extended] | reused | 2026-10-28T13:49:06Z |
| miri-7e2fcb1c0bfc90ed | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:0:width=1 [extended] | reused | 2026-10-28T21:56:20Z |
| miri-7e33992943df946e | tuplehash | miri | tuplehash-staging:321 [extended] | reused | 2026-10-28T16:08:41Z |
| miri-7e389a6facc2c374 | md5 | miri | md5-bulk:31 [routine] | passed | 2026-10-19T11:26:05Z |
| miri-7e39d0730c629a92 | sha1 | miri | -p brynja-legacy-sha1 --lib [remaining suite; inspect skips with show] | passed | 2026-10-19T11:34:01Z |
| miri-7e3a239070acd3e5 | tuplehash | miri | scoped_tuplexof128_differential:38:width=4 [extended] | reused | 2026-10-29T01:45:47Z |
| miri-7e51b4e784820165 | sha1 | miri | sha1-scoped:2 [extended] | reused | 2026-10-28T13:03:01Z |
| miri-7e752251023e9a59 | tuplehash | miri | scoped_tuplexof256_differential:4:width=1 [extended] | reused | 2026-10-29T02:24:45Z |
| miri-7e7e1a458b058f08 | md5 | miri | md5-scoped:131 [extended] | reused | 2026-10-28T11:56:08Z |
| miri-7e81aea4fb4508c1 | parallelhash | miri | -p brynja-hash-parallel --features hardened-execution --test execution_stream [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-7e86e26971182ef9 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:1:width=0 [extended] | reused | 2026-10-29T01:43:26Z |
| miri-7e8be236a677136e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:10:width=4 [extended] | reused | 2026-10-28T19:39:30Z |
| miri-7e9be1de2ae12251 | tuplehash | miri | scoped_tuplexof256_differential:7:width=2 [extended] | reused | 2026-10-29T03:16:31Z |
| miri-7ea45bf5d070299f | sha2 | miri | --manifest-path assurance/general-sha512-t/Cargo.toml --lib [remaining suite; inspect skips with show] | reused | 2026-10-28T13:40:26Z |
| miri-7eadfe60d4093e19 | md5 | miri | md5-bulk:100 [extended] | reused | 2026-10-28T11:44:26Z |
| miri-7eae8ca4d5c1d58a | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:42:width=1 [extended] | reused | 2026-10-28T20:52:59Z |
| miri-7ed46d144db60909 | tuplehash | miri | scoped_tuplexof128_differential:12:width=4 [extended] | reused | 2026-10-29T00:49:44Z |
| miri-7edd56dfba171923 | kmac | miri | kmac-streamed-setup:15 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-7ee57cf0509b169c | kmac | miri | kmac-streamed-setup:18 [routine] | No mapped observation | — |
| miri-7ef7c636a8780c90 | tuplehash | miri | tuplehash-staging:326 [extended] | reused | 2026-10-28T15:58:09Z |
| miri-7efc1edb79c2cce0 | sha1 | miri | sha1-scoped:69 [extended] | reused | 2026-10-28T13:15:25Z |
| miri-7f0355d86b4780ab | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:49:width=3 [extended] | reused | 2026-10-29T06:33:54Z |
| miri-7f3159eda56f2fb0 | md5 | miri | md5-scoped:53 [extended] | reused | 2026-10-28T11:51:06Z |
| miri-7f494bab6a2a85e8 | sha3 | miri | sha3-fixed-boundaries:6 [extended] | reused | 2026-10-28T13:36:57Z |
| miri-7f5238d0b4553e5d | kmac | miri | kmac-streamed-setup:89 [routine] | No mapped observation | — |
| miri-7f5cf5d9a091b3e6 | sha3 | miri | -p brynja-hash-sha3 --features batch-execution --lib batch::tests::bounded_batch_lifecycle [remaining suite; inspect skips with show] | passed | 2026-10-19T11:35:17Z |
| miri-7f647cb6522f3871 | kmac | miri | kmac-streamed-setup:3 [routine] | No mapped observation | — |
| miri-7f78858105c07206 | tuplehash | miri | tuplehash-staging:469 [extended] | reused | 2026-10-28T16:57:53Z |
| miri-7f79e12124a22b3d | sha1 | miri | sha1-padding:106 [extended] | reused | 2026-10-28T12:48:36Z |
| miri-7f8fbfb4ed6a8f6f | kmac | miri | verification_accepts_exact_tag_and_rejects_first_last_and_length_changes [routine] | passed | 2026-10-19T11:44:37Z |
| miri-7fa67a4c23a7f903 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:52:width=4 [extended] | reused | 2026-10-29T00:23:27Z |
| miri-7fb38bdbb0ba5ad0 | sha1 | miri | sha1-bulk:176 [extended] | reused | 2026-10-28T12:53:32Z |
| miri-7fc6046bf56f331e | parallelhash | miri | hardened_in_place::xof::tests::scoped_parallel_xof128_lifecycle [routine] | No mapped observation | — |
| miri-7fd84c9367e95717 | sha1 | miri | sha1-bulk:20 [extended] | reused | 2026-10-28T12:40:20Z |
| miri-7fe11b8c6b99de2d | sha1 | miri | sha1-bulk:226 [extended] | reused | 2026-10-28T13:00:38Z |
| miri-7ff0c8eeac59c9f1 | sha3 | miri | sha3-fixed-bits:27 [routine] | passed | 2026-10-19T11:30:07Z |
| miri-7ff329591de62f68 | tuplehash | miri | tuplehash-staging:346 [extended] | reused | 2026-10-28T16:05:00Z |
| miri-7ff96603a80ed9f9 | sha1 | miri | sha1-padding:103 [extended] | reused | 2026-10-28T12:38:12Z |
| miri-801208fca183a408 | sha3 | miri | sha3-fixed-boundaries:12 [extended] | reused | 2026-10-28T13:46:17Z |
| miri-8019da12d188dd08 | md5 | miri | md5-scoped:86 [extended] | reused | 2026-10-28T12:03:55Z |
| miri-8024d136b3662c35 | tuplehash | miri | tuplehash-staging:873 [extended] | reused | 2026-10-28T19:13:38Z |
| miri-802890109fece796 | md5 | miri | -p brynja-legacy-md5 --features hardened-execution --test hardened_execution bounded_portable_cleanup_smoke [remaining suite; inspect skips with show] | passed | 2026-10-19T11:24:47Z |
| miri-804035e825573900 | md5 | miri | md5-scoped:232 [extended] | reused | 2026-10-28T12:08:54Z |
| miri-8048f89423960c2c | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:37:width=4 [extended] | reused | 2026-10-29T05:42:32Z |
| miri-806964240da1bd9a | tuplehash | miri | tuplehash-staging:539 [extended] | reused | 2026-10-28T23:15:19Z |
| miri-806b8daa548f548e | sha2 | miri | -p brynja-crypto-cpu --features sha256-batch --lib sha256_batch::tests::failed_revalidation_and_unwind_revoke_before_instruction_entry [remaining suite; inspect skips with show] | passed | 2026-10-19T11:30:00Z |
| miri-806efe53fe620deb | sha3 | miri | sha3-fixed-boundaries:36 [routine] | passed | 2026-10-19T11:37:00Z |
| miri-8078e602b608d170 | tuplehash | miri | tuplehash-staging:96 [extended] | reused | 2026-10-28T14:39:43Z |
| miri-80889755626f1c9d | md5 | miri | md5-scoped:225 [extended] | reused | 2026-10-28T12:03:01Z |
| miri-808f4af7725a9f66 | kmac | miri | kmac-streamed-setup:53 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-809699f277ce0464 | sha1 | miri | sha1-scoped:255 [extended] | reused | 2026-10-28T13:35:25Z |
| miri-80a43c7e0bac0590 | tuplehash | miri | scoped_tuplexof256_differential:35:width=0 [extended] | reused | 2026-10-29T04:19:13Z |
| miri-80c3c377abc4e0cb | tuplehash | miri | scoped_tuplexof256_differential:42:width=3 [extended] | reused | 2026-10-29T03:47:02Z |
| miri-80c77757f1dc4f4c | tuplehash | miri | tuplehash-staging:154 [extended] | reused | 2026-10-28T15:02:08Z |
| miri-80ccae862091ac05 | md5 | miri | md5-bulk:116 [extended] | reused | 2026-10-28T11:45:36Z |
| miri-80f30ad7cd38731d | tuplehash | miri | scoped_tuplexof128_differential:41:width=1 [extended] | passed | 2026-10-29T11:06:22Z |
| miri-810cb2fb15c1da57 | kmac | miri | kmac-streamed-setup:0 [routine] | No mapped observation | — |
| miri-8111079046dcf44e | md5 | miri | md5-batch-mask:130 [extended] | reused | 2026-10-28T12:28:14Z |
| miri-81156af9eabdccfe | tuplehash | miri | tuplehash-staging:136 [extended] | reused | 2026-10-28T14:53:14Z |
| miri-81783975c9bf5bdc | sha3 | miri | sha3-fixed-boundaries:9 [extended] | reused | 2026-10-28T13:32:16Z |
| miri-817de49c49144166 | kmac | miri | kmac-streamed-setup:24 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-818885fb76d04459 | sha3 | miri | sha3-fixed-boundaries:34 [extended] | reused | 2026-10-28T13:40:36Z |
| miri-81ac21732ab35de7 | md5 | miri | md5-padding:40 [extended] | reused | 2026-10-28T11:21:00Z |
| miri-81b33908d0355630 | static_cpu | miri | -p brynja-crypto-cpu --features static-execution --lib static_authority [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-81b69c599c90518b | sha1 | miri | sha1-scoped:267 [extended] | reused | 2026-10-28T13:36:23Z |
| miri-81c4576943a7fd9a | sha3 | miri | fixed_output_failure_is_atomic_by_classification [extended] | reused | 2026-10-28T13:45:18Z |
| miri-81dca43ece15414a | md5 | miri | md5-scoped:129 [extended] | reused | 2026-10-28T11:56:15Z |
| miri-81f0da7626df4dad | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:2:width=2 [extended] | reused | 2026-10-28T21:56:04Z |
| miri-81f7b0e8fb129e0d | tuplehash | miri | scoped_tuplexof128_differential:0:width=3 [extended] | reused | 2026-10-29T00:30:00Z |
| miri-820814421c5ae5ad | tuplehash | miri | scoped_tuplexof256_differential:18:width=2 [extended] | reused | 2026-10-29T02:47:19Z |
| miri-820ded7f4c076b33 | tuplehash | miri | tuplehash-staging:305 [extended] | reused | 2026-10-28T16:02:54Z |
| miri-8214d43f223e1092 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-order:3 [routine] | No mapped observation | — |
| miri-821578c0ace60561 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-faults:5 [extended] | passed | 2026-10-29T14:20:28Z |
| miri-8217d152c34081cf | tuplehash | miri | tuplehash-staging:8 [extended] | reused | 2026-10-28T14:10:57Z |
| miri-8223e3bcd7eed67c | kmac | miri | kmac-scoped-lifecycle:8 [extended] | reused | 2026-10-28T13:58:36Z |
| miri-82294b149c3261db | md5 | miri | md5-bulk:161 [extended] | reused | 2026-10-28T11:39:12Z |
| miri-822995425877ae6c | sha3 | miri | sha3-fixed-boundaries:17 [extended] | reused | 2026-10-28T13:33:36Z |
| miri-822ae05f9de32d7a | tuplehash | miri | tuplehash-staging:663 [extended] | reused | 2026-10-28T23:57:03Z |
| miri-8239a26155265cac | kmac | miri | arbitrary_bits_are_canonical_and_streaming_xof_tracks_output [extended] | reused | 2026-10-28T20:03:45Z |
| miri-8250cae448494baf | tuplehash | miri | scoped_tuplexof256_differential:27:width=1 [extended] | reused | 2026-10-29T03:59:46Z |
| miri-82555f61b05a41c5 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:27:width=0 [extended] | reused | 2026-10-28T20:42:37Z |
| miri-825a63dd12360c9d | kmac | miri | kmacxof-official:5 [extended] | reused | 2026-10-28T20:02:30Z |
| miri-825bd20abf6ad85c | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:3:width=2 [extended] | reused | 2026-10-28T19:52:05Z |
| miri-8272a9142ac0b92d | tuplehash | miri | tuplehash-staging:125 [extended] | reused | 2026-10-28T15:02:58Z |
| miri-82771d93ba20a7c8 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:2:width=4 [extended] | reused | 2026-10-28T19:26:23Z |
| miri-82980610ad975b85 | tuplehash | miri | tuplehash-staging:691 [extended] | reused | 2026-10-29T00:06:29Z |
| miri-82b58f3fb17fdace | md5 | miri | md5-padding:73 [extended] | reused | 2026-10-28T11:32:59Z |
| miri-82d4b0bdb2a702d7 | tuplehash | miri | tuplehash-staging:853 [extended] | reused | 2026-10-28T19:07:17Z |
| miri-82f0d6c5eefc7057 | hmac | miri | sha512_256 [existing-full] | No mapped observation | — |
| miri-832c3b0a707fd30e | md5 | miri | md5-batch-mask:199 [extended] | reused | 2026-10-28T12:23:04Z |
| miri-833af647d9ca1438 | static_cpu | miri | -p brynja-crypto-cpu --features static-execution --lib static_authority [remaining suite; inspect skips with show] | passed | 2026-10-19T17:30:32Z |
| miri-836ffbde76c7b0ae | md5 | miri | md5-bulk:114 [extended] | reused | 2026-10-28T11:40:28Z |
| miri-839db54c28e0d942 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:6:width=3 [extended] | reused | 2026-10-28T22:02:39Z |
| miri-83afb3a09107d79e | md5 | miri | md5-padding:122 [extended] | reused | 2026-10-28T11:27:12Z |
| miri-83b1d46f094b05d1 | tuplehash | miri | scoped_tuplexof256_differential:12:width=0 [extended] | reused | 2026-10-29T02:38:28Z |
| miri-83b5e61c572dc1e7 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:29:width=4 [extended] | reused | 2026-10-29T02:43:39Z |
| miri-83f3b6064fac2d59 | tuplehash | miri | tuplehash-staging:652 [extended] | reused | 2026-10-28T17:38:58Z |
| miri-83f9c4a94f355155 | md5 | miri | md5-bulk:94 [extended] | reused | 2026-10-28T11:38:58Z |
| miri-840636cfa2819a91 | sha1 | miri | sha1-bulk:186 [extended] | reused | 2026-10-28T12:56:08Z |
| miri-840d4a5d7ec8ff1d | sha3 | miri | -p brynja-hash-sha3 --features static-execution --test execution execution_smoke [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-84171cb919f614fa | tuplehash | miri | scoped_tuplexof128_differential:20:width=0 [extended] | reused | 2026-10-29T01:08:19Z |
| miri-8421f6255bf2025b | sha1 | miri | sha1-scoped:95 [extended] | reused | 2026-10-28T13:22:41Z |
| miri-84241c6e0a9525d5 | sha1 | miri | sha1-padding:12 [extended] | reused | 2026-10-28T12:35:15Z |
| miri-84324ddde1b82c22 | md5 | miri | md5-batch-mask:17 [extended] | reused | 2026-10-28T12:08:44Z |
| miri-84416132fbecd054 | tuplehash | miri | tuplehash-staging:850 [extended] | reused | 2026-10-28T18:46:26Z |
| miri-8457e77eb8228c24 | static_cpu | miri | --manifest-path assurance/hosted-cpu-execution/Cargo.toml --lib [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-848290bd63021c77 | md5 | miri | -p brynja-legacy-md5 --features hardened-execution --test hardened_execution bounded_portable_cleanup_smoke [remaining suite; inspect skips with show] | reused | 2026-10-28T11:23:31Z |
| miri-8491e95cbd83564f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:38:width=0 [extended] | reused | 2026-10-28T23:10:13Z |
| miri-84b971da35783be6 | md5 | miri | md5-bulk:31 [extended] | reused | 2026-10-28T11:30:06Z |
| miri-84c70fec5764951d | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:50:width=3 [extended] | reused | 2026-10-28T23:58:01Z |
| miri-84ce1e792749a5ca | tuplehash | miri | tuplehash-staging:85 [extended] | reused | 2026-10-28T14:48:42Z |
| miri-84d123be32b23772 | tuplehash | miri | scoped_tuplexof256_differential:9:width=4 [extended] | passed | 2026-10-29T12:12:47Z |
| miri-84e9f67cbe7587c7 | kmac | miri | kmac-streamed-setup:41 [routine] | No mapped observation | — |
| miri-84fd4844efae82d8 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:26:width=0 [extended] | reused | 2026-10-28T22:42:58Z |
| miri-8503370f60dbb7f3 | tuplehash | miri | tuplehash-staging:482 [extended] | reused | 2026-10-28T16:48:41Z |
| miri-852c7011860af0ba | tuplehash | miri | tuplehash-staging:600 [extended] | reused | 2026-10-28T17:22:38Z |
| miri-853eccb32ed04637 | kmac | miri | kmac-scoped-xof-lifecycle:12 [routine] | passed | 2026-10-19T11:45:35Z |
| miri-8542dcb76fcbcae7 | tuplehash | miri | tuplehash-staging:134 [extended] | reused | 2026-10-28T14:55:11Z |
| miri-8553a2f24185f5ef | tuplehash | miri | scoped_tuplexof128_differential:15:width=0 [extended] | reused | 2026-10-29T01:38:34Z |
| miri-8563255a327b31b0 | sha1 | miri | sha1-bulk:196 [extended] | reused | 2026-10-28T12:55:44Z |
| miri-8566433877b3af13 | hmac | miri | general_129 [existing-full] | No mapped observation | — |
| miri-856c8f2f85a096cf | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:2:width=2 [extended] | reused | 2026-10-28T19:26:23Z |
| miri-857c06c29d0283f2 | md5 | miri | md5-bulk:120 [routine] | passed | 2026-10-19T11:29:13Z |
| miri-8590c9aaaaaa3dd0 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:7 [extended] | passed | 2026-10-29T14:09:51Z |
| miri-8592b320038e0d61 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:8 [routine] | No mapped observation | — |
| miri-859568b2a70d1bba | sha3 | miri | -p brynja-hash-sha3 --features hardened-execution --lib hardened::accelerated::reader::tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-85a51dfe678f40c6 | md5 | miri | md5-batch-mask:115 [extended] | reused | 2026-10-28T12:16:07Z |
| miri-85a990c762ac62f7 | tuplehash | miri | tuplehash-staging:685 [extended] | reused | 2026-10-28T18:10:42Z |
| miri-85bb94a2f7deea91 | tuplehash | miri | tuplehash-staging:43 [extended] | reused | 2026-10-28T20:28:16Z |
| miri-85dccddac2e7decb | tuplehash | miri | scoped_tuplexof256_differential:40:width=1 [extended] | reused | 2026-10-29T03:47:39Z |
| miri-85e5b2064cabdfce | md5 | miri | md5-batch-mask:82 [extended] | reused | 2026-10-28T12:24:26Z |
| miri-85efb4a79931c7c9 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:27 [routine] | No mapped observation | — |
| miri-8618c905dac2138f | md5 | miri | md5-scoped:78 [extended] | reused | 2026-10-28T12:03:22Z |
| miri-861d62bb02978956 | tuplehash | miri | tuplehash-staging:723 [extended] | reused | 2026-10-29T00:17:17Z |
| miri-862498c3b8b60359 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:31 [extended] | passed | 2026-10-29T13:43:28Z |
| miri-863287e4db06f91e | static_cpu | miri | --manifest-path assurance/hosted-cpu-execution/Cargo.toml --lib [remaining suite; inspect skips with show] | passed | 2026-10-19T13:43:11Z |
| miri-86354a652dc3d7cb | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:10 [extended] | passed | 2026-10-29T13:36:28Z |
| miri-864fa09338d99ef1 | md5 | miri | md5-scoped:37 [extended] | reused | 2026-10-28T11:50:02Z |
| miri-86511e5061b6ccbe | sha3 | miri | -p brynja-crypto-cpu --features hardened-execution --lib hardened_execution::keccak::tests::all_seven_regions_clear [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-8652313179e03505 | tuplehash | miri | tuplehash-staging:630 [extended] | reused | 2026-10-28T17:35:41Z |
| miri-865333d234fb29c3 | md5 | miri | md5-scoped:219 [extended] | reused | 2026-10-28T12:02:18Z |
| miri-86607c409e4adfb5 | hmac | miri | sha3_512 [existing-full] | No mapped observation | — |
| miri-8660970d01bc784b | md5 | miri | md5-batch-mask:133 [extended] | reused | 2026-10-28T12:17:44Z |
| miri-866f08eae1b11342 | tuplehash | miri | scoped_tuplexof256_differential:28:width=1 [extended] | reused | 2026-10-29T03:16:23Z |
| miri-867fb7f0c7d7190b | kmac | miri | kmac-streamed-setup:4 [routine] | No mapped observation | — |
| miri-8680d107f685668a | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:4:width=0 [extended] | reused | 2026-10-28T19:33:24Z |
| miri-86832505e1438cae | sha1 | miri | sha1-padding:115 [extended] | reused | 2026-10-28T12:39:18Z |
| miri-868ec66d06d6e21f | sha3 | miri | sha3-fixed-boundaries:55 [extended] | reused | 2026-10-28T13:43:45Z |
| miri-8693b9ead6194c98 | sha1 | miri | sha1-padding:53 [extended] | reused | 2026-10-28T12:32:11Z |
| miri-869fa9813857e663 | tuplehash | miri | scoped_tuplexof256_differential:8:width=4 [extended] | reused | 2026-10-29T02:31:37Z |
| miri-86a103e22b36ae84 | kmac | miri | kmac-official:5 [extended] | reused | 2026-10-28T14:13:38Z |
| miri-86a9a14aae857db0 | md5 | miri | md5-bulk:70 [extended] | reused | 2026-10-28T11:37:06Z |
| miri-86accae88312bed4 | md5 | miri | md5-scoped:181 [extended] | reused | 2026-10-28T11:59:48Z |
| miri-86b6da4333771553 | tuplehash | miri | tuplehash-staging:334 [extended] | reused | 2026-10-28T16:00:46Z |
| miri-86c2bf5e7eb613fb | sha1 | miri | sha1-bulk:107 [extended] | reused | 2026-10-28T12:54:03Z |
| miri-86c8ae4ce4e18365 | md5 | miri | md5-scoped:280 [extended] | reused | 2026-10-28T12:12:28Z |
| miri-86d3dbddb2c1fefe | md5 | miri | md5-batch-mask:94 [extended] | reused | 2026-10-28T12:25:22Z |
| miri-86e3ebf85f96be31 | tuplehash | miri | tuplehash-execution-xof:1 [routine] | passed | 2026-10-19T12:23:52Z |
| miri-86f00acf89037396 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-domains:5 [routine] | No mapped observation | — |
| miri-86fe5d45e9d558d3 | md5 | miri | md5-bulk:204 [extended] | reused | 2026-10-28T11:52:56Z |
| miri-870d3fd4deb47aaf | tuplehash | miri | tuplehash-staging:25 [extended] | reused | 2026-10-28T14:29:23Z |
| miri-873f1f8e6fa5b2c8 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:54:width=2 [extended] | reused | 2026-10-29T00:22:37Z |
| miri-87437d3524e1aa0a | tuplehash | miri | scoped_tuplexof256_differential:0:width=0 [extended] | reused | 2026-10-29T02:17:57Z |
| miri-87448f3a7138099c | sha3 | miri | sha3-fixed-bits:26 [routine] | passed | 2026-10-19T11:39:38Z |
| miri-874553432698fc5e | tuplehash | miri | scoped_tuplexof128_differential:9 [routine] | passed | 2026-10-19T16:14:29Z |
| miri-874890f588df74b5 | sha1 | miri | sha1-scoped:31 [extended] | reused | 2026-10-28T13:18:01Z |
| miri-87505549d7addf84 | tuplehash | miri | tuplehash-staging:647 [extended] | reused | 2026-10-28T23:52:02Z |
| miri-8775b3b1b109ef39 | sha1 | miri | sha1-scoped:106 [extended] | reused | 2026-10-28T13:10:30Z |
| miri-877ee83d7d5fb06e | md5 | miri | md5-bulk:252 [extended] | reused | 2026-10-28T11:57:31Z |
| miri-87890b199fb3a129 | tuplehash | miri | tuplehash-staging:722 [extended] | reused | 2026-10-28T18:04:44Z |
| miri-87a266d129a1edba | sha1 | miri | sha1-bulk:25 [extended] | reused | 2026-10-28T12:52:32Z |
| miri-87b5fd2a9b05822d | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:9:width=2 [extended] | reused | 2026-10-29T01:57:28Z |
| miri-87be994c8a5600f9 | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib unsupported_target_or_model_never_falls_back [remaining suite; inspect skips with show] | passed | 2026-10-29T15:09:26Z |
| miri-87c6d0192291d509 | md5 | miri | md5-bulk:167 [extended] | reused | 2026-10-28T11:39:57Z |
| miri-87d17346c8e8d27b | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib unsupported_target_or_model_never_falls_back [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-87d18f9c4844092b | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:57 [extended] | passed | 2026-10-29T13:39:37Z |
| miri-87d653e7d17b7ab4 | parallelhash | miri | hardened_in_place::tests::scoped_parallel128_lifecycle [extended] | passed | 2026-10-29T14:55:07Z |
| miri-87d9c5260c931f4b | tuplehash | miri | tuplehash-staging:687 [extended] | reused | 2026-10-29T00:04:43Z |
| miri-87de3147cf6e7975 | tuplehash | miri | scoped_tuplexof256_differential:32:width=2 [extended] | reused | 2026-10-29T03:25:53Z |
| miri-87ef49888e43bb17 | md5 | miri | md5-padding:65 [routine] | passed | 2026-10-19T11:28:49Z |
| miri-87ef938edae15c0c | tuplehash | miri | scoped_tuplexof256_differential:14:width=0 [extended] | reused | 2026-10-29T02:37:48Z |
| miri-87fb09f00d57b2a5 | static_cpu | miri | -p brynja-crypto-cpu --features runtime-execution --lib runtime_execution [remaining suite; inspect skips with show] | passed | 2026-10-29T15:01:45Z |
| miri-8800e94157b6f865 | md5 | miri | md5-scoped:164 [extended] | reused | 2026-10-28T12:04:08Z |
| miri-88376fd2b4c88016 | tuplehash | miri | scoped_tuplexof128_differential:25:width=3 [extended] | passed | 2026-10-29T10:58:34Z |
| miri-884cbdb1bfc08087 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-faults:0 [extended] | passed | 2026-10-29T15:06:30Z |
| miri-8854397905e15c57 | sha1 | miri | sha1-padding:84 [extended] | reused | 2026-10-28T12:41:33Z |
| miri-885932cfc24373b4 | tuplehash | miri | hardened_in_place::xof::tests::scoped_tuplexof256_lifecycle [routine] | passed | 2026-10-19T12:42:07Z |
| miri-885f50c3b4731ffe | sha3 | miri | sha3-fixed-boundaries:44 [extended] | reused | 2026-10-28T13:50:29Z |
| miri-886224333409658b | kmac | miri | kmac-streamed-setup:26 [routine] | No mapped observation | — |
| miri-8870f30057c3cadb | tuplehash | miri | tuplehash-staging:366 [extended] | reused | 2026-10-28T16:11:09Z |
| miri-8878118f5fa1efc0 | md5 | miri | md5-scoped:199 [extended] | reused | 2026-10-28T12:00:49Z |
| miri-887bd8f703b757e4 | tuplehash | miri | tuplehash-staging:105 [extended] | reused | 2026-10-28T14:55:50Z |
| miri-8891882253073e9e | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join128:1 [routine] | No mapped observation | — |
| miri-8895f90f79b09ffa | hmac | miri | sha3_256 [routine] | No mapped observation | — |
| miri-88976940ecb962bb | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:36:width=0 [extended] | reused | 2026-10-28T23:10:45Z |
| miri-88b5fa0f77145fc6 | sha1 | miri | sha1-padding:110 [extended] | reused | 2026-10-28T12:49:00Z |
| miri-88b668dd7a2a7b37 | tuplehash | miri | tuplehash-staging:535 [extended] | reused | 2026-10-28T23:14:22Z |
| miri-88b6b6376d3e5ef6 | tuplehash | miri | tuplehash-staging:759 [extended] | reused | 2026-10-29T00:29:51Z |
| miri-88b9afcec02d8fb8 | sha1 | miri | sha1-scoped:83 [extended] | reused | 2026-10-28T13:21:47Z |
| miri-88c20033879cd7e7 | md5 | miri | md5-scoped:265 [extended] | reused | 2026-10-28T12:05:56Z |
| miri-88e24e50ed5ac296 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:0 [routine] | No mapped observation | — |
| miri-88e26afd9accc9fb | md5 | miri | md5-bulk:87 [extended] | reused | 2026-10-28T11:33:55Z |
| miri-8909f5a51c382836 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:20:width=0 [extended] | reused | 2026-10-28T22:34:16Z |
| miri-890ab74a2beffc7f | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:0 [routine] | No mapped observation | — |
| miri-8910ebb834be10ed | tuplehash | miri | tuplehash-staging:412 [extended] | reused | 2026-10-28T16:22:54Z |
| miri-89129000c88f54ba | legacy | miri | --manifest-path assurance/legacy-hash-final/Cargo.toml --no-default-features --lib dynamic_ [remaining suite; inspect skips with show] | passed | 2026-10-29T15:16:03Z |
| miri-8932228e3537f328 | md5 | miri | md5-batch-mask:158 [extended] | reused | 2026-10-28T12:30:27Z |
| miri-89368e207a44b3e5 | tuplehash | miri | tuplehash-execution-fixed:8 [routine] | passed | 2026-10-19T12:07:48Z |
| miri-894ddb79740509c5 | tuplehash | miri | tuplehash-staging:457 [extended] | reused | 2026-10-28T16:53:58Z |
| miri-8952b67565f0feb0 | tuplehash | miri | tuplehash-staging:526 [extended] | reused | 2026-10-28T17:01:57Z |
| miri-898569b41f4e4e77 | md5 | miri | md5-padding:57 [extended] | reused | 2026-10-28T11:31:43Z |
| miri-898e04d5a54e71dc | sha1 | miri | sha1-bulk:69 [extended] | reused | 2026-10-28T12:55:38Z |
| miri-8994cd9e65d24d93 | tuplehash | miri | scoped_tuplexof128_differential:31:width=0 [extended] | reused | 2026-10-29T02:17:45Z |
| miri-89982143b33e7ec6 | sha1 | miri | -p brynja-legacy-sha1 --features cpu --lib quarantined_model_clears_all_regions_without_instructions [remaining suite; inspect skips with show] | reused | 2026-10-28T12:28:01Z |
| miri-8998661bcac79fad | tuplehash | miri | scoped_tuplexof256_differential:44:width=3 [extended] | reused | 2026-10-29T03:59:50Z |
| miri-89acbf3ec078da4f | tuplehash | miri | tuplehash-staging:215 [extended] | reused | 2026-10-28T21:26:30Z |
| miri-89b28ebf2e8bea61 | tuplehash | miri | scoped_tuplexof128_differential:11:width=3 [extended] | reused | 2026-10-29T01:31:31Z |
| miri-89bb9898c56a74aa | sha1 | miri | sha1-bulk:257 [routine] | passed | 2026-10-19T11:31:56Z |
| miri-89c0f184eca3068d | md5 | miri | -p brynja-legacy-md5 --test api [remaining suite; inspect skips with show] | reused | 2026-10-28T11:23:38Z |
| miri-89c9620acc57348f | md5 | miri | md5-bulk:121 [extended] | reused | 2026-10-28T11:36:04Z |
| miri-89d7e9f3bd5a3c67 | sha1 | miri | sha1-scoped:17 [extended] | reused | 2026-10-28T13:11:54Z |
| miri-89dce98e33dfb389 | sha2 | miri | -p brynja-hash-sha2 --test sha224 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | reused | 2026-10-28T13:34:06Z |
| miri-89e8b6a36e93aa37 | kmac | miri | kmac-streamed-setup:7 [routine] | No mapped observation | — |
| miri-89f549f45d27bced | parallelhash | miri | -p brynja-hash-parallel-std --features runtime-execution --lib execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-89fa9852eca01214 | sha1 | miri | sha1-bulk:112 [extended] | reused | 2026-10-28T12:47:19Z |
| miri-8a093823760e4669 | tuplehash | miri | tuplehash-staging:613 [extended] | reused | 2026-10-28T17:46:05Z |
| miri-8a14802e3915824d | sha1 | miri | sha1-bulk:173 [extended] | reused | 2026-10-28T13:05:19Z |
| miri-8a1a073c7395691e | tuplehash | miri | tuplehash-staging:66 [extended] | reused | 2026-10-28T14:33:37Z |
| miri-8a476f9b52450bde | sha1 | miri | sha1-bulk:191 [routine] | passed | 2026-10-19T11:16:30Z |
| miri-8a4bb623f6924b32 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:3:width=1 [extended] | reused | 2026-10-28T19:52:05Z |
| miri-8a50f6c7abf4e335 | md5 | miri | md5-bulk:152 [extended] | reused | 2026-10-28T11:48:30Z |
| miri-8a55268ecc9a7b0b | kmac | miri | kmac-scoped-lifecycle:15 [routine] | passed | 2026-10-19T11:51:01Z |
| miri-8a65419d66b6c4c4 | sha1 | miri | sha1-scoped:201 [extended] | reused | 2026-10-28T13:25:40Z |
| miri-8a87b168043fdc1d | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:40:width=2 [extended] | reused | 2026-10-28T23:22:29Z |
| miri-8a97ab8680740bbe | md5 | miri | md5-bulk:65 [routine] | passed | 2026-10-19T11:32:25Z |
| miri-8aa7fdb40df72aa0 | md5 | miri | md5-batch-mask:178 [extended] | reused | 2026-10-28T12:32:06Z |
| miri-8aa871ec08a1a020 | md5 | miri | md5-scoped:269 [extended] | reused | 2026-10-28T12:06:13Z |
| miri-8aaa614000b6498a | kmac | miri | kmac-scoped-lifecycle:12 [routine] | passed | 2026-10-19T11:36:14Z |
| miri-8aab1f7ad5853e9f | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:8:width=3 [extended] | reused | 2026-10-28T19:39:57Z |
| miri-8abbff8721638b63 | md5 | miri | md5-scoped:87 [extended] | reused | 2026-10-28T11:53:07Z |
| miri-8ac77fea51d8f3fc | hmac | miri | sha512_224 [extended] | passed | 2026-10-29T15:17:17Z |
| miri-8ad0d0553cf9e6fc | sha1 | miri | sha1-bulk:215 [extended] | reused | 2026-10-28T13:05:30Z |
| miri-8afa4c9794eee6f2 | tuplehash | miri | tuplehash-staging:398 [extended] | reused | 2026-10-28T16:21:48Z |
| miri-8b204a63d040a87a | md5 | miri | md5-batch-mask:218 [extended] | reused | 2026-10-28T12:35:25Z |
| miri-8b38a1217a175515 | md5 | miri | md5-batch-mask:247 [routine] | passed | 2026-10-19T11:27:09Z |
| miri-8b3fe84014e9e8da | tuplehash | miri | tuplehash-staging:237 [extended] | reused | 2026-10-28T15:40:22Z |
| miri-8b528acf2d56d242 | sha1 | miri | sha1-scoped:72 [extended] | reused | 2026-10-28T13:09:21Z |
| miri-8b5b7fc072f1a8e2 | tuplehash | miri | tuplehash-staging:119 [extended] | reused | 2026-10-28T20:54:07Z |
| miri-8b5d247c2e61997e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:41:width=0 [extended] | reused | 2026-10-29T03:15:49Z |
| miri-8b60f5627dcbd0c3 | kmac | miri | kmac256_mismatch_and_exact_width [routine] | No mapped observation | — |
| miri-8b76994e6ed1812b | sha1 | miri | sha1-bulk:239 [extended] | reused | 2026-10-28T13:08:30Z |
| miri-8b799e296a1d0481 | md5 | miri | md5-scoped:58 [extended] | reused | 2026-10-28T12:02:00Z |
| miri-8b7aa5d91e2cf821 | tuplehash | miri | tuplehash-staging:514 [extended] | reused | 2026-10-28T16:58:50Z |
| miri-8b7bb7b857633420 | kmac | miri | kmac-scoped-xof-lifecycle:4 [extended] | reused | 2026-10-28T13:56:53Z |
| miri-8b8ac946e5bd329d | sha1 | miri | sha1-scoped:190 [extended] | reused | 2026-10-28T13:17:17Z |
| miri-8b99108ce2a6b68f | tuplehash | miri | scoped_tuplexof256_differential:45:width=1 [extended] | passed | 2026-10-29T12:28:03Z |
| miri-8b9c3cd78e5e9e72 | sha1 | miri | sha1-scoped:113 [extended] | reused | 2026-10-28T13:18:52Z |
| miri-8ba486a68e25be86 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:7:width=3 [extended] | reused | 2026-10-28T19:59:05Z |
| miri-8ba6b7f2453c358d | sha1 | miri | sha1-scoped:193 [extended] | reused | 2026-10-28T13:25:00Z |
| miri-8bb54b6c74bfc38b | tuplehash | miri | tuplehash-staging:778 [extended] | reused | 2026-10-28T18:22:41Z |
| miri-8bc1645acf1a5a58 | tuplehash | miri | tuplehash-staging:323 [extended] | reused | 2026-10-28T22:02:32Z |
| miri-8bc4828b60ff6693 | sha1 | miri | sha1-scoped:139 [extended] | reused | 2026-10-28T13:26:02Z |
| miri-8bda77519a82bf38 | tuplehash | miri | tuplehash-staging:699 [extended] | reused | 2026-10-29T00:09:35Z |
| miri-8bdea2a5b59b2782 | tuplehash | miri | scoped_tuplexof256_differential:30:width=2 [extended] | reused | 2026-10-29T03:15:42Z |
| miri-8bec2ea5580737b9 | md5 | miri | md5-scoped:169 [extended] | reused | 2026-10-28T11:58:58Z |
| miri-8bf77bbd1a039542 | kmac | miri | kmac-streamed-setup:91 [routine] | No mapped observation | — |
| miri-8bf7a2b97212a841 | sha3 | miri | sha3-secret-xof-bits:0 [extended] | reused | 2026-10-28T13:57:31Z |
| miri-8bff67ea6ac2dea3 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:52:width=0 [extended] | reused | 2026-10-29T00:23:27Z |
| miri-8c000d3737e51e43 | sha1 | miri | sha1-bulk:193 [extended] | reused | 2026-10-28T13:07:27Z |
| miri-8c0ef2c54de2e3ba | tuplehash | miri | scoped_tuplexof256_differential:8:width=2 [extended] | reused | 2026-10-29T02:31:37Z |
| miri-8c1f1a5e30841ad8 | md5 | miri | md5-bulk:178 [extended] | reused | 2026-10-28T11:45:49Z |
| miri-8c395a575238fec4 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:23:width=4 [extended] | reused | 2026-10-28T20:32:45Z |
| miri-8c3d3360c60cdd17 | md5 | miri | md5-bulk:55 [extended] | reused | 2026-10-28T11:31:40Z |
| miri-8c59f52f1da4202f | tuplehash | miri | tuplehash-staging:177 [extended] | reused | 2026-10-28T15:20:03Z |
| miri-8c7350de72e61a09 | md5 | miri | md5-scoped:283 [routine] | passed | 2026-10-19T11:26:46Z |
| miri-8c7379861876a9f1 | sha1 | miri | sha1-scoped:71 [extended] | reused | 2026-10-28T13:20:53Z |
| miri-8c8236a466daa779 | md5 | miri | md5-scoped:100 [extended] | reused | 2026-10-28T11:59:45Z |
| miri-8c82fc2629ed703b | kmac | miri | kmac-streamed-setup:62 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-8cc3822107c87607 | tuplehash | miri | scoped_tuplexof128_differential:20:width=2 [extended] | reused | 2026-10-29T01:08:19Z |
| miri-8cd425b45fda107f | sha1 | miri | sha1-scoped:120 [extended] | reused | 2026-10-28T13:13:11Z |
| miri-8cdaf027d20168e9 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:34:width=4 [extended] | reused | 2026-10-28T23:01:09Z |
| miri-8ce1fe566992da8b | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:621 [routine] | No mapped observation | — |
| miri-8cec09af93a1a6fa | tuplehash | miri | tuplehash-staging:168 [extended] | reused | 2026-10-28T15:03:18Z |
| miri-8cf46beb42bd0b5b | sha3 | miri | sha3-fixed-bits:4 [extended] | reused | 2026-10-28T13:54:54Z |
| miri-8d1cceb88abc9ca7 | tuplehash | miri | tuplehash-staging:728 [extended] | reused | 2026-10-28T18:03:37Z |
| miri-8d1ecfae9621d5c5 | kmac | miri | kmac-streamed-setup:1 [routine] | No mapped observation | — |
| miri-8d2bd1da9a00df2b | tuplehash | miri | tuplehash-staging:76 [extended] | reused | 2026-10-28T14:33:32Z |
| miri-8d3a2674f60204c2 | sha1 | miri | sha1-bulk:89 [extended] | reused | 2026-10-28T12:57:19Z |
| miri-8d67f5bf11c748d2 | md5 | miri | md5-padding:58 [extended] | reused | 2026-10-28T11:22:09Z |
| miri-8d8672ff6f482c94 | sha1 | miri | sha1-bulk:246 [extended] | reused | 2026-10-28T13:02:56Z |
| miri-8d9462d77d7380d0 | kmac | miri | kmac-streamed-setup:8 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-8d9f37aafb1bde83 | static_cpu | miri | -p brynja-crypto-cpu --features static-execution --lib static_authority [remaining suite; inspect skips with show] | passed | 2026-10-29T15:16:35Z |
| miri-8da51fc4ad983e00 | tuplehash | miri | tuplehash-staging:610 [extended] | reused | 2026-10-28T17:28:53Z |
| miri-8da562a1ab0c05cc | md5 | miri | md5-batch-mask:142 [extended] | reused | 2026-10-28T12:29:10Z |
| miri-8da75c7aacac5375 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:2 [routine] | No mapped observation | — |
| miri-8daa3aaed946ba97 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:0 [routine] | No mapped observation | — |
| miri-8dada603e1b976ba | kmac | miri | kmac-streamed-setup:66 [routine] | No mapped observation | — |
| miri-8ddad06b4e46fa3b | sha1 | miri | sha1-scoped:143 [extended] | reused | 2026-10-28T13:26:20Z |
| miri-8dde1c754e5c9a01 | md5 | miri | md5-batch-mask:227 [extended] | reused | 2026-10-28T12:25:21Z |
| miri-8de7797535d15f07 | sha1 | miri | sha1-scoped:282 [extended] | reused | 2026-10-28T13:24:48Z |
| miri-8dfe9efc01847e83 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:47:width=4 [extended] | reused | 2026-10-29T00:17:25Z |
| miri-8e01dfd007b892b0 | tuplehash | miri | tuplehash-staging:572 [extended] | reused | 2026-10-28T17:13:38Z |
| miri-8e141da35b09f832 | md5 | miri | md5-bulk:190 [extended] | reused | 2026-10-28T11:46:49Z |
| miri-8e2efecec2b3c8af | md5 | miri | md5-bulk:174 [extended] | reused | 2026-10-28T11:45:30Z |
| miri-8e36543ec702102b | tuplehash | miri | tuplehash-staging:428 [extended] | reused | 2026-10-28T16:27:22Z |
| miri-8e65c008849c21d2 | tuplehash | miri | tuplehash-staging:516 [extended] | reused | 2026-10-28T16:55:40Z |
| miri-8e7de46cb4ab132b | md5 | miri | md5-scoped:81 [extended] | reused | 2026-10-28T11:52:59Z |
| miri-8e825c83f267b636 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:6 [routine] | passed | 2026-10-19T12:20:03Z |
| miri-8e88e8771388892e | tuplehash | miri | -p brynja-hash-tuple --features hardened-execution --lib execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-8e8b81b463e5c00e | tuplehash | miri | tuplehash-staging:524 [extended] | reused | 2026-10-28T16:58:35Z |
| miri-8e9e8915afd5005d | tuplehash | miri | tuplehash-staging:805 [extended] | reused | 2026-10-28T18:50:44Z |
| miri-8ea3255b040e2dd3 | md5 | miri | -p brynja-legacy-md5 --features execution --lib operational_revalidator_unwind_quarantines_without_instructions [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-8ea72a34a73b7f34 | md5 | miri | md5-padding:27 [extended] | reused | 2026-10-28T11:25:17Z |
| miri-8ec0438b1f742269 | legacy_hmac | miri | -p brynja-legacy-hmac --features sha1-execution --lib execution::retained::tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-8ece9e9bff3e00c7 | sha3 | miri | -p brynja-hash-sha3 --test shake128 suffix_and_rate_boundaries_have_exact_output [remaining suite; inspect skips with show] | reused | 2026-10-28T13:36:10Z |
| miri-8ed372372274f0db | kmac | miri | kmac-scoped-xof-lifecycle:4 [routine] | passed | 2026-10-19T11:43:57Z |
| miri-8ed6e5bd197c995d | kmac | miri | kmac-scoped-lifecycle:10 [extended] | reused | 2026-10-28T13:54:06Z |
| miri-8ee57b5e0f69e214 | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib missing_native [remaining suite; inspect skips with show] | passed | 2026-10-29T16:05:46Z |
| miri-8eec3e6b446753ed | tuplehash | miri | scoped_tuplexof256_differential:16:width=4 [extended] | reused | 2026-10-29T02:47:58Z |
| miri-8ef16e87e608be02 | parallelhash | miri | -p brynja-hash-parallel --features hardened-execution --test execution [remaining suite; inspect skips with show] | passed | 2026-10-29T12:32:08Z |
| miri-8ef7fcb98d22069e | kmac | miri | kmac-scoped-xof-lifecycle:1 [routine] | passed | 2026-10-19T11:51:29Z |
| miri-8f1139d5a8416b25 | tuplehash | miri | scoped_tuplexof128_differential:46:width=0 [extended] | reused | 2026-10-29T02:10:19Z |
| miri-8f4e8f42dd43e988 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:30:width=1 [extended] | reused | 2026-10-28T22:52:04Z |
| miri-8f5137bc11784878 | md5 | miri | md5-bulk:133 [extended] | reused | 2026-10-28T11:37:00Z |
| miri-8f5ce61efbdc328d | tuplehash | miri | scoped_tuplexof128_differential:39:width=2 [extended] | reused | 2026-10-29T02:37:19Z |
| miri-8f741fea91a52991 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:30:width=3 [extended] | reused | 2026-10-28T20:22:51Z |
| miri-8f80801b98ccea9b | tuplehash | miri | scoped_tuplexof128_differential:22:width=0 [extended] | reused | 2026-10-29T01:07:25Z |
| miri-8f9096ac7036c571 | sha1 | miri | sha1-padding:27 [extended] | reused | 2026-10-28T12:31:40Z |
| miri-8f90e96f68c13b5e | tuplehash | miri | tuplehash-staging:769 [extended] | reused | 2026-10-28T18:39:00Z |
| miri-8f9bade4571bdcf8 | sha1 | miri | sha1-bulk:198 [extended] | reused | 2026-10-28T12:57:26Z |
| miri-8fb38f2f7c60d06f | sha1 | miri | sha1-padding:56 [routine] | passed | 2026-10-19T11:34:17Z |
| miri-8fc7a9de133b9b91 | tuplehash | miri | tuplehash-staging:756 [extended] | reused | 2026-10-28T18:12:36Z |
| miri-8fd386e996c69a45 | sha1 | miri | sha1-padding:112 [extended] | reused | 2026-10-28T12:44:22Z |
| miri-8fd3f2ad2b8d3f77 | sha3 | miri | sha3-fixed-boundaries:70 [extended] | reused | 2026-10-28T13:46:06Z |
| miri-8fe1081146e08f24 | md5 | miri | md5-batch-mask:104 [extended] | reused | 2026-10-28T12:20:43Z |
| miri-900c7ff7ff7d8a58 | kmac | miri | kmac-streamed-setup:86 [routine] | No mapped observation | — |
| miri-902d64fcae9024f8 | hmac | miri | general_129 [routine] | No mapped observation | — |
| miri-903eb3ce2fad1a39 | tuplehash | miri | tuplehash-staging:512 [extended] | reused | 2026-10-28T16:54:01Z |
| miri-9049f6b363d5764e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:6:width=3 [extended] | reused | 2026-10-28T19:32:57Z |
| miri-90562739dabdc87d | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:53:width=4 [extended] | reused | 2026-10-29T07:01:39Z |
| miri-9061d23bc1069b3c | sha1 | miri | sha1-scoped:132 [extended] | reused | 2026-10-28T13:14:08Z |
| miri-9063b8445124be28 | sha1 | miri | sha1-scoped:171 [extended] | reused | 2026-10-28T13:28:29Z |
| miri-906e1a09335f9a25 | md5 | miri | md5-bulk:159 [extended] | reused | 2026-10-28T11:39:19Z |
| miri-9081e709a7d0120f | md5 | miri | md5-batch-mask:232 [extended] | reused | 2026-10-28T12:30:59Z |
| miri-9084695b23fc1c05 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:11:width=2 [extended] | reused | 2026-10-28T20:06:05Z |
| miri-9084f092deaff8a5 | sha1 | miri | sha1-scoped:164 [extended] | reused | 2026-10-28T13:16:44Z |
| miri-9094a6092df14bc9 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:336 [extended] | passed | 2026-10-29T14:01:26Z |
| miri-90a8ad49b7927648 | md5 | miri | md5-batch-mask:65 [extended] | reused | 2026-10-28T12:12:24Z |
| miri-90ad60206d7add59 | sha1 | miri | sha1-scoped:134 [extended] | reused | 2026-10-28T13:12:46Z |
| miri-90bd3f383a84ebdb | sha1 | miri | sha1-bulk:106 [extended] | reused | 2026-10-28T12:48:26Z |
| miri-90c2626e51ec3773 | tuplehash | miri | scoped_tuplexof128_differential:15:width=1 [extended] | reused | 2026-10-29T01:38:34Z |
| miri-90d04d703f1c4274 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:16:width=2 [extended] | reused | 2026-10-28T22:25:09Z |
| miri-90d0557a45be91f9 | parallelhash | miri | -p brynja-hash-parallel --features hardened-execution --test execution_stream [remaining suite; inspect skips with show] | passed | 2026-10-29T12:59:26Z |
| miri-90e019980d5fd018 | tuplehash | miri | tuplehash-staging:137 [extended] | reused | 2026-10-28T15:06:36Z |
| miri-90e34d7497c3d82e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:43:width=0 [extended] | reused | 2026-10-28T21:24:50Z |
| miri-90f3319972c8946e | tuplehash | miri | tuplehash-staging:637 [extended] | reused | 2026-10-28T17:54:09Z |
| miri-90f4f3b74b327784 | sha1 | miri | sha1-bulk:6 [extended] | reused | 2026-10-28T12:41:04Z |
| miri-91009b50f0eedb09 | tuplehash | miri | hardened_in_place::tests::scoped_tuple128_terminal_writer_and_output_lifecycle [routine] | passed | 2026-10-19T12:19:01Z |
| miri-9104b392398c14b5 | sha1 | miri | sha1-bulk:141 [extended] | reused | 2026-10-28T13:02:03Z |
| miri-9118199837965684 | tuplehash | miri | scoped_tuplexof256_differential:2:width=3 [extended] | reused | 2026-10-29T02:17:15Z |
| miri-91191d7e9a889066 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:34:width=2 [extended] | reused | 2026-10-28T20:32:01Z |
| miri-911dd8c7f8becd89 | md5 | miri | md5-batch-mask:54 [extended] | reused | 2026-10-28T12:22:16Z |
| miri-912feaffdf4d65bd | sha3 | miri | sha3-fixed-bits:3 [extended] | reused | 2026-10-28T13:47:06Z |
| miri-914460020dc43839 | sha1 | miri | sha1-scoped:4 [extended] | reused | 2026-10-28T13:04:31Z |
| miri-914801781d15ebb4 | md5 | miri | md5-bulk:3 [extended] | reused | 2026-10-28T11:28:15Z |
| miri-9152d5b9360e6f17 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:9:width=1 [extended] | reused | 2026-10-29T01:57:28Z |
| miri-9155ebc9872378ae | tuplehash | miri | scoped_tuplexof128_differential:5:width=1 [extended] | reused | 2026-10-29T07:15:40Z |
| miri-915aa68d20127d4d | md5 | miri | md5-bulk:257 [routine] | passed | 2026-10-19T11:26:33Z |
| miri-916b4a3783c2f893 | md5 | miri | md5-scoped:50 [extended] | reused | 2026-10-28T12:01:28Z |
| miri-9185ee567b450bcb | tuplehash | miri | scoped_tuplexof256_differential:24:width=4 [extended] | reused | 2026-10-29T03:06:57Z |
| miri-91888dcd4c4abd18 | sha3 | miri | sha3-fixed-bits:1 [extended] | reused | 2026-10-28T13:41:29Z |
| miri-918ca02eadba1c90 | sha1 | miri | sha1-scoped:275 [extended] | reused | 2026-10-28T13:37:03Z |
| miri-9192a9e53088ef00 | tuplehash | miri | scoped_tuplexof128_differential:27:width=3 [extended] | reused | 2026-10-29T02:07:59Z |
| miri-919443897d304611 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-slots:1 [routine] | No mapped observation | — |
| miri-919f468e6ca51838 | sha3 | miri | sha3-fixed-boundaries:54 [routine] | passed | 2026-10-19T11:37:48Z |
| miri-91af9fe2c2985bb6 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:15 [routine] | No mapped observation | — |
| miri-91b21ee573f98ee3 | md5 | miri | md5-bulk:171 [extended] | reused | 2026-10-28T11:40:15Z |
| miri-91b88edfb342fa36 | kmac | miri | kmac-streamed-setup:88 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-91be4da635ed2d86 | md5 | miri | md5-padding:68 [extended] | reused | 2026-10-28T11:23:14Z |
| miri-91d66d398ee6b305 | tuplehash | miri | tuplehash-staging:322 [extended] | reused | 2026-10-28T15:56:50Z |
| miri-91f25dc49df54a83 | tuplehash | miri | tuplehash-staging:282 [extended] | reused | 2026-10-28T15:43:45Z |
| miri-91f5cf2884b210b1 | sha1 | miri | sha1-bulk:90 [extended] | reused | 2026-10-28T12:47:03Z |
| miri-91fa57f0f3341e75 | tuplehash | miri | tuplehash-staging:801 [extended] | reused | 2026-10-28T18:49:47Z |
| miri-91fdd6749835d341 | tuplehash | miri | tuplehash-staging:545 [extended] | reused | 2026-10-28T17:23:34Z |
| miri-9215eb8f3f304741 | tuplehash | miri | tuplehash-staging:703 [extended] | reused | 2026-10-29T00:10:55Z |
| miri-921cde5fec2b5957 | md5 | miri | md5-padding:32 [extended] | reused | 2026-10-28T11:20:24Z |
| miri-922e7a9b5253c22a | hmac | miri | -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-92326243e36be08b | kmac | miri | kmac-scoped-xof-lifecycle:13 [routine] | passed | 2026-10-19T11:53:45Z |
| miri-92394b261900d02f | md5 | miri | md5-batch-mask:180 [extended] | reused | 2026-10-28T12:26:46Z |
| miri-923980de0fabbb39 | sha1 | miri | sha1-scoped:179 [extended] | reused | 2026-10-28T13:29:05Z |
| miri-9239d8722e14b943 | sha1 | miri | sha1-padding:56 [extended] | reused | 2026-10-28T12:38:48Z |
| miri-923d073d7e043818 | sha3 | miri | sha3-fixed-boundaries:32 [extended] | reused | 2026-10-28T13:49:00Z |
| miri-9269263dbf4286b8 | tuplehash | miri | tuplehash-staging:236 [extended] | reused | 2026-10-28T15:25:22Z |
| miri-9278a9d07d639612 | md5 | miri | -p brynja-legacy-md5 --features hardened-execution --test hardened_execution bounded_portable_cleanup_smoke [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-92917c3721aa11c5 | sha3 | miri | cancel_and_early_drop_cover_absorber_and_reader_lifecycles [extended] | reused | 2026-10-28T13:52:08Z |
| miri-9294f43bebd34481 | sha3 | miri | sha3-fixed-bits:4 [routine] | passed | 2026-10-19T11:37:56Z |
| miri-92a41fe62b623985 | md5 | miri | md5-scoped:101 [extended] | reused | 2026-10-28T11:54:21Z |
| miri-92ae9e2675b3553b | md5 | miri | md5-bulk:191 [extended] | reused | 2026-10-28T11:41:49Z |
| miri-92b4dc0a724926c7 | kmac | miri | kmac-streamed-setup:52 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-92ccd0b13a6042d5 | tuplehash | miri | tuplehash-staging:565 [extended] | reused | 2026-10-28T17:29:55Z |
| miri-92cd1f3087d7ca1e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:24:width=1 [extended] | reused | 2026-10-28T20:14:03Z |
| miri-92e5339f6bdc498a | md5 | miri | md5-batch-mask:80 [extended] | reused | 2026-10-28T12:18:56Z |
| miri-92f0b35eff5f20a0 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:37:width=3 [extended] | reused | 2026-10-29T05:42:32Z |
| miri-9300818785f6febc | tuplehash | miri | scoped_tuplexof256_differential:4:width=0 [extended] | reused | 2026-10-29T02:24:45Z |
| miri-9310cffe3dde2486 | tuplehash | miri | tuplehash-staging:163 [extended] | reused | 2026-10-28T21:08:57Z |
| miri-932a777fc7d93d98 | kmac | miri | -p brynja-mac-kmac --features hardened-execution --test execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-93375d11ae5fc43a | static_cpu | miri | -p brynja-crypto-cpu --features hardened-execution --lib hardened_execution [remaining suite; inspect skips with show] | passed | 2026-10-29T15:16:14Z |
| miri-934b58fd7e8152a1 | tuplehash | miri | tuplehash-staging:684 [extended] | reused | 2026-10-28T17:49:32Z |
| miri-9355b06d1bf28a51 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:3 [routine] | No mapped observation | — |
| miri-935784fd30ef321b | sha1 | miri | sha1-padding:76 [extended] | reused | 2026-10-28T12:40:47Z |
| miri-936bb6bc9becd2dc | sha1 | miri | sha1-padding:39 [extended] | reused | 2026-10-28T12:32:35Z |
| miri-93a80190afb13263 | sha1 | miri | sha1-bulk:39 [extended] | reused | 2026-10-28T12:48:37Z |
| miri-93b6318bc87562a2 | md5 | miri | md5-bulk:191 [routine] | passed | 2026-10-19T11:29:21Z |
| miri-93cc34296c1eab24 | md5 | miri | md5-scoped:106 [extended] | reused | 2026-10-28T12:05:18Z |
| miri-93ce51510ef5e684 | tuplehash | miri | tuplehash-staging:207 [extended] | reused | 2026-10-28T21:23:46Z |
| miri-93d8b6db46c5b58c | tuplehash | miri | tuplehash-execution-fixed:9 [routine] | passed | 2026-10-19T12:16:54Z |
| miri-93e9b4cb141cb845 | kmac | miri | kmac-streamed-setup:14 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-93fd9aca8f4f924e | tuplehash | miri | scoped_tuplexof256_differential:12:width=1 [extended] | reused | 2026-10-29T02:38:28Z |
| miri-9428f8ff463eb1a4 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:45 [extended] | passed | 2026-10-29T13:12:32Z |
| miri-943fcd967e7b8d44 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:55:width=0 [extended] | reused | 2026-10-28T22:25:13Z |
| miri-94489409d2c5d783 | md5 | miri | md5-scoped:287 [extended] | reused | 2026-10-28T12:07:13Z |
| miri-9454401d0bd74964 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:44:width=1 [extended] | reused | 2026-10-28T21:05:12Z |
| miri-9461a0eab852d171 | tuplehash | miri | tuplehash-staging:817 [extended] | reused | 2026-10-28T18:54:46Z |
| miri-948359c1ee164f47 | sha1 | miri | -p brynja-legacy-sha1 --test api [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-9496be5e2b9bd876 | tuplehash | miri | tuplehash-staging:824 [extended] | reused | 2026-10-28T18:34:20Z |
| miri-94aabb908ec57fdf | sha2 | miri | -p brynja-hash-sha2 --test sha256 downstream_style_real_content_uses_only_public_api [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-94c3b7b20b5c1504 | sha1 | miri | sha1-padding:55 [routine] | passed | 2026-10-19T11:28:36Z |
| miri-94c8d23dc2593889 | tuplehash | miri | tuplehash-staging:664 [extended] | reused | 2026-10-28T17:43:31Z |
| miri-94d26f69a4d0f88a | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:285 [routine] | No mapped observation | — |
| miri-94d4ebedb686dace | tuplehash | miri | tuplehash-staging:129 [extended] | reused | 2026-10-28T15:04:18Z |
| miri-94eb9731190b2b83 | tuplehash | miri | scoped_tuplexof256_differential:15:width=1 [extended] | reused | 2026-10-29T03:30:33Z |
| miri-94fac7ae76ae6c1b | md5 | miri | md5-batch-mask:110 [extended] | reused | 2026-10-28T12:26:37Z |
| miri-94ff054f98e5b371 | tuplehash | miri | scoped_tuplexof128_differential:32:width=3 [extended] | reused | 2026-10-29T01:36:57Z |
| miri-950b23030ba45bba | tuplehash | miri | scoped_tuplexof128_differential:24:width=4 [extended] | reused | 2026-10-29T01:17:49Z |
| miri-951f2ed443218c57 | tuplehash | miri | scoped_tuplexof256_differential:6:width=1 [extended] | reused | 2026-10-29T02:24:07Z |
| miri-95291e0ade81af80 | md5 | miri | md5-bulk:238 [extended] | reused | 2026-10-28T11:51:14Z |
| miri-9534ae507881a67f | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:34:width=1 [extended] | reused | 2026-10-28T20:32:01Z |
| miri-9545a145b93f19db | tuplehash | miri | tuplehash-staging:794 [extended] | reused | 2026-10-28T18:28:32Z |
| miri-956ab541c81d321d | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:17:width=0 [extended] | reused | 2026-10-29T02:14:18Z |
| miri-956bb26d56065311 | tuplehash | miri | tuplehash-staging:292 [extended] | reused | 2026-10-28T15:43:36Z |
| miri-9576a7f3e9eaa7d5 | md5 | miri | md5-batch-mask:254 [routine] | passed | 2026-10-19T11:30:24Z |
| miri-9576f302efec9233 | tuplehash | miri | scoped_tuplexof256_differential:24:width=0 [extended] | reused | 2026-10-29T03:06:57Z |
| miri-9583241a7ebb1e12 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:19:width=4 [extended] | reused | 2026-10-28T23:03:10Z |
| miri-959c495fa0fb48f5 | tuplehash | miri | tuplehash-staging:628 [extended] | reused | 2026-10-28T17:31:37Z |
| miri-959dacb56584a3a8 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:18:width=4 [extended] | reused | 2026-10-28T19:55:16Z |
| miri-95a603639127d4be | md5 | miri | md5-bulk:182 [extended] | reused | 2026-10-28T11:46:10Z |
| miri-95a7cc803f334432 | sha1 | miri | sha1-padding:80 [extended] | reused | 2026-10-28T12:41:10Z |
| miri-95b4d66a3f65c4b8 | sha1 | miri | sha1-bulk:103 [extended] | reused | 2026-10-28T12:53:40Z |
| miri-95b5a65305c3be59 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:23 [routine] | No mapped observation | — |
| miri-95cd78788872a9a2 | tuplehash | miri | scoped_tuplexof256_differential:10:width=2 [extended] | reused | 2026-10-29T02:30:56Z |
| miri-95cf20b3f3615954 | kmac | miri | kmac-streamed-setup:2 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-95d1909b8cdd717e | md5 | miri | md5-bulk:7 [extended] | reused | 2026-10-28T11:28:31Z |
| miri-95ece61ece74b714 | sha3 | miri | sha3-fixed-boundaries:37 [extended] | reused | 2026-10-28T13:36:01Z |
| miri-96193cd992c9e064 | sha3 | miri | both_xofs_match_across_irregular_absorb_and_squeeze_boundaries [routine] | passed | 2026-10-19T11:41:15Z |
| miri-961f261c0ced1b04 | tuplehash | miri | tuplehash-staging:605 [extended] | reused | 2026-10-28T17:43:47Z |
| miri-9650475de43cde00 | md5 | miri | md5-padding:112 [extended] | reused | 2026-10-28T11:26:40Z |
| miri-96688a3810681433 | sha1 | miri | -p brynja-legacy-sha1 --features hardened-execution --lib hardened_execution::stream::tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-966d788143f86aad | sha1 | miri | sha1-bulk:211 [extended] | reused | 2026-10-28T13:05:02Z |
| miri-968d4296343b59f9 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-slots:0 [routine] | No mapped observation | — |
| miri-969114390ee4ee23 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:12:width=4 [extended] | reused | 2026-10-28T22:16:00Z |
| miri-9694e836c0b1e92a | md5 | miri | md5-padding:60 [extended] | reused | 2026-10-28T11:22:34Z |
| miri-96ae18efd45d045e | tuplehash | miri | tuplehash-staging:779 [extended] | reused | 2026-10-29T00:36:12Z |
| miri-96b3987dd6e8149b | md5 | miri | md5-scoped:115 [extended] | reused | 2026-10-28T11:55:02Z |
| miri-96c831f9b0d5c504 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:7 [routine] | No mapped observation | — |
| miri-96cba574ad183608 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:46:width=2 [extended] | reused | 2026-10-28T23:33:28Z |
| miri-96d60b4e1d5961ca | tuplehash | miri | scoped_tuplexof128_differential:21:width=1 [extended] | passed | 2026-10-29T10:55:12Z |
| miri-96e7885ab5e68645 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_unwind_reuse:0 [routine] | No mapped observation | — |
| miri-96ee15596c97daa7 | md5 | miri | md5-padding:121 [extended] | reused | 2026-10-28T11:36:51Z |
| miri-96ff5ee90613d174 | parallelhash | miri | -p brynja-hash-parallel --features hardened-execution --test execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-96ff6273535d7b48 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:39:width=3 [extended] | reused | 2026-10-28T21:12:11Z |
| miri-9706cb4fb7f1904c | sha1 | miri | sha1-scoped:232 [extended] | reused | 2026-10-28T13:22:17Z |
| miri-97115c94dd38f30a | sha1 | miri | sha1-scoped:104 [extended] | reused | 2026-10-28T13:11:53Z |
| miri-97157176a22e6a06 | sha1 | miri | sha1-padding:79 [extended] | reused | 2026-10-28T12:36:00Z |
| miri-9766bed4367a828b | sha1 | miri | sha1-scoped:45 [extended] | reused | 2026-10-28T13:13:47Z |
| miri-979d70d997b35485 | tuplehash | miri | tuplehash-staging:711 [extended] | reused | 2026-10-29T00:13:13Z |
| miri-97a0b315a34c96db | md5 | miri | md5-scoped:284 [extended] | reused | 2026-10-28T12:12:46Z |
| miri-97b009daf32f33bc | tuplehash | miri | scoped_tuplexof256_differential:43:width=0 [extended] | reused | 2026-10-29T04:41:29Z |
| miri-97b230d8b57fb375 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:24:width=3 [extended] | reused | 2026-10-28T22:43:23Z |
| miri-97b765a9a258d71e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:0:width=1 [extended] | reused | 2026-10-28T19:26:50Z |
| miri-97f91b6fbb857a46 | md5 | miri | md5-batch-mask:149 [extended] | reused | 2026-10-28T12:19:03Z |
| miri-980a88d0a2c0085f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:4:width=4 [extended] | reused | 2026-10-28T22:02:53Z |
| miri-9819b5f870e84595 | tuplehash | miri | tuplehash-staging:311 [extended] | reused | 2026-10-28T21:59:17Z |
| miri-981a20f4cfd37e0e | sha1 | miri | sha1-scoped:160 [extended] | reused | 2026-10-28T13:16:25Z |
| miri-981d49adffbf8e4f | tuplehash | miri | tuplehash-staging:444 [extended] | reused | 2026-10-28T16:33:22Z |
| miri-9835dd58965b522e | tuplehash | miri | tuplehash-staging:560 [extended] | reused | 2026-10-28T17:09:47Z |
| miri-9881ea74ac113297 | tuplehash | miri | tuplehash-staging:852 [extended] | reused | 2026-10-28T18:43:18Z |
| miri-98843308b6743742 | sha3 | miri | sealed_capabilities_accept_only_registered_public_types [extended] | reused | 2026-10-28T13:45:52Z |
| miri-98846c1cbffe4149 | tuplehash | miri | tuplehash-staging:57 [extended] | reused | 2026-10-28T14:39:23Z |
| miri-98c713a581932770 | sha1 | miri | sha1-scoped:10 [extended] | reused | 2026-10-28T13:03:34Z |
| miri-98de2a17131f700e | tuplehash | miri | tuplehash-staging:46 [extended] | reused | 2026-10-28T14:26:42Z |
| miri-98df1431e424f3e4 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:4 [routine] | No mapped observation | — |
| miri-98f8b22215b0e883 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:48:width=1 [extended] | reused | 2026-10-28T23:58:48Z |
| miri-992e0e7f6854b82f | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_unwind_reuse:3 [extended] | passed | 2026-10-29T14:03:35Z |
| miri-993de8f13156ce40 | sha3 | miri | -p brynja-hash-sha3 --features batch-execution --lib batch::tests::shape_staging_empty_and_scalar_tail_boundaries [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-996dc426e9fbb239 | tuplehash | miri | scoped_tuplexof256_differential:3:width=2 [extended] | reused | 2026-10-29T03:09:31Z |
| miri-999c5ca13f58f981 | md5 | miri | md5-bulk:249 [extended] | reused | 2026-10-28T11:46:34Z |
| miri-99b19f9bdee94c6a | sha1 | miri | sha1-bulk:8 [extended] | reused | 2026-10-28T12:39:36Z |
| miri-99b21e92588db11b | md5 | miri | md5-bulk:18 [extended] | reused | 2026-10-28T11:33:35Z |
| miri-99b8d3e6e42bf3ec | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:44:width=0 [extended] | reused | 2026-10-28T23:34:09Z |
| miri-99be4d4835b03a59 | sha1 | miri | sha1-padding:119 [routine] | passed | 2026-10-19T11:31:01Z |
| miri-99c4515c3e17fee1 | md5 | miri | md5-scoped:5 [extended] | reused | 2026-10-28T11:47:56Z |
| miri-99c7b11a544142fd | tuplehash | miri | scoped_tuplexof256_differential:6:width=3 [extended] | reused | 2026-10-29T02:24:07Z |
| miri-99d159eaa4939e8a | tuplehash | miri | tuplehash-staging:725 [extended] | reused | 2026-10-28T18:23:47Z |
| miri-99f46d73511a2485 | hmac | miri | -p brynja-crypto-cpu-std --features hmac-execution --test hmac [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-99f49d08dc5a8022 | tuplehash | miri | tuplehash-staging:440 [extended] | reused | 2026-10-28T16:32:03Z |
| miri-9a02abe938541ce5 | sha1 | miri | sha1-scoped:99 [extended] | reused | 2026-10-28T13:22:59Z |
| miri-9a31c148d2af5140 | tuplehash | miri | tuplehash-staging:498 [extended] | reused | 2026-10-28T16:53:02Z |
| miri-9a3c9a94d470cda6 | md5 | miri | md5-bulk:213 [extended] | reused | 2026-10-28T11:43:25Z |
| miri-9a748055df9ce28e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:40:width=0 [extended] | reused | 2026-10-28T20:53:24Z |
| miri-9a77d3e331faa949 | sha1 | miri | sha1-padding:52 [extended] | reused | 2026-10-28T12:38:26Z |
| miri-9a7907c104336b82 | md5 | miri | md5-batch-mask:29 [extended] | reused | 2026-10-28T12:09:38Z |
| miri-9a7b2e23965228c3 | tuplehash | miri | tuplehash-staging:491 [extended] | reused | 2026-10-28T22:58:51Z |
| miri-9a849a2716819b0f | sha1 | miri | sha1-scoped:256 [extended] | reused | 2026-10-28T13:24:16Z |
| miri-9a8c8e7bd5654402 | tuplehash | miri | scoped_tuplexof128_differential:42:width=4 [extended] | reused | 2026-10-29T01:58:04Z |
| miri-9a9f614a97e19a88 | md5 | miri | md5-padding:96 [extended] | reused | 2026-10-28T11:25:27Z |
| miri-9aa51ac17bd5a7e4 | sha1 | miri | sha1-scoped:240 [extended] | reused | 2026-10-28T13:22:59Z |
| miri-9aa70c7bfb2d97e8 | tuplehash | miri | scoped_tuplexof128_differential:22:width=4 [extended] | reused | 2026-10-29T01:07:25Z |
| miri-9ab902c79edf4da1 | sha1 | miri | sha1-padding:91 [extended] | reused | 2026-10-28T12:37:07Z |
| miri-9abed768acd21229 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:33:width=2 [extended] | reused | 2026-10-29T02:53:27Z |
| miri-9ac67dca49ee49ad | sha3 | miri | -p brynja-hash-sha3 --lib final_bit_output_clears_the_exact_reader_source [remaining suite; inspect skips with show] | passed | 2026-10-19T11:26:00Z |
| miri-9acbf47f6afb64cf | sha1 | miri | sha1-bulk:119 [extended] | reused | 2026-10-28T12:55:07Z |
| miri-9acd53989da3fbc6 | tuplehash | miri | tuplehash-staging:644 [extended] | reused | 2026-10-28T17:36:46Z |
| miri-9af3928f5c131b91 | tuplehash | miri | tuplehash-staging:145 [extended] | reused | 2026-10-28T15:09:18Z |
| miri-9af9e7ebda5091dc | parallelhash | miri | hardened_in_place::xof::tests::scoped_parallel_xof256_lifecycle [extended] | passed | 2026-10-29T15:14:23Z |
| miri-9b0a1e343b3c16ba | sha1 | miri | sha1-bulk:56 [extended] | reused | 2026-10-28T12:42:40Z |
| miri-9b1070320daaf678 | sha3 | miri | sha3-fixed-boundaries:29 [extended] | reused | 2026-10-28T13:35:02Z |
| miri-9b15c698a8047f3d | tuplehash | miri | tuplehash-staging:223 [extended] | reused | 2026-10-28T21:29:35Z |
| miri-9b18975fc51026c2 | sha1 | miri | sha1-scoped:21 [extended] | reused | 2026-10-28T13:12:11Z |
| miri-9b1e5c1b7cf48d21 | sha1 | miri | sha1-bulk:38 [extended] | reused | 2026-10-28T12:43:08Z |
| miri-9b350bae8c12db48 | sha1 | miri | sha1-scoped:168 [extended] | reused | 2026-10-28T13:17:04Z |
| miri-9b38fd4e6a37cd77 | md5 | miri | md5-batch-mask:213 [extended] | reused | 2026-10-28T12:24:09Z |
| miri-9b3ecce71b2944cc | tuplehash | miri | scoped_tuplexof256_differential:28:width=4 [extended] | reused | 2026-10-29T03:16:23Z |
| miri-9b435fd93b79e87a | md5 | miri | md5-bulk:148 [extended] | reused | 2026-10-28T11:48:11Z |
| miri-9b444a63e75ce157 | sha1 | miri | -p brynja-legacy-sha1 --features execution --test execution revocation_empty_updates_capacity_and_finalization_fail_closed [remaining suite; inspect skips with show] | reused | 2026-10-28T12:27:59Z |
| miri-9b46f1533fbbfa62 | kmac | miri | kmac-scoped-lifecycle:13 [routine] | passed | 2026-10-19T15:31:11Z |
| miri-9b4c087f2bb7345f | md5 | miri | md5-batch-mask:240 [extended] | reused | 2026-10-28T12:31:41Z |
| miri-9b65abe3adb1a391 | md5 | miri | md5-bulk:119 [extended] | reused | 2026-10-28T11:36:14Z |
| miri-9b6ac314d85e6abd | md5 | miri | md5-batch-mask:14 [extended] | reused | 2026-10-28T12:19:16Z |
| miri-9b8402e732072c39 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:3:width=4 [extended] | reused | 2026-10-28T22:32:17Z |
| miri-9b8df4277568b108 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:28:width=4 [extended] | reused | 2026-10-28T22:52:29Z |
| miri-9b92455c62fbdc45 | sha3 | miri | sha3-fixed-boundaries:50 [extended] | reused | 2026-10-28T13:42:53Z |
| miri-9bc8e43c6e567e09 | sha1 | miri | sha1-scoped:244 [extended] | reused | 2026-10-28T13:23:19Z |
| miri-9bd9acd164044782 | sha1 | miri | sha1-bulk:65 [routine] | passed | 2026-10-19T11:29:11Z |
| miri-9bdabc13ff5fffcc | tuplehash | miri | tuplehash-staging:12 [extended] | reused | 2026-10-28T14:12:32Z |
| miri-9bfebb968e37867d | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:0 [routine] | passed | 2026-10-19T12:09:19Z |
| miri-9c15c696b65dc783 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:34:width=4 [extended] | reused | 2026-10-28T20:32:01Z |
| miri-9c1f44c807642263 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:31 [routine] | No mapped observation | — |
| miri-9c299a23abb8d618 | tuplehash | miri | tuplehash-staging:473 [extended] | reused | 2026-10-28T16:59:11Z |
| miri-9c3d2df55ef53855 | md5 | miri | md5-padding:119 [extended] | reused | 2026-10-28T11:31:37Z |
| miri-9c605fe7bd4aa78d | kmac | miri | kmac-official:0 [routine] | passed | 2026-10-19T11:46:28Z |
| miri-9c6e61907db5c12e | md5 | miri | md5-scoped:133 [extended] | reused | 2026-10-28T11:56:32Z |
| miri-9cb87dc36e1b7a0a | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-domains:2 [routine] | No mapped observation | — |
| miri-9cca5d234a10ea53 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-domains:3 [extended] | passed | 2026-10-29T14:16:11Z |
| miri-9ccde658577b6863 | sha3 | miri | sha3-fixed-bits:15 [routine] | passed | 2026-10-19T11:29:30Z |
| miri-9cd2c0839d9fc741 | tuplehash | miri | tuplehash-staging:716 [extended] | reused | 2026-10-28T17:59:46Z |
| miri-9cde8207f1ef7495 | tuplehash | miri | tuplehash-staging:93 [extended] | reused | 2026-10-28T14:51:48Z |
| miri-9ce12c675dae3b1d | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:49:width=1 [extended] | reused | 2026-10-29T03:52:14Z |
| miri-9cf007e445f99138 | md5 | miri | md5-batch-mask:129 [extended] | reused | 2026-10-28T12:17:26Z |
| miri-9cf44525ba40f3a5 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:53:width=1 [extended] | reused | 2026-10-29T04:16:00Z |
| miri-9cf8f9937956075e | sha3 | miri | sha3-fixed-bits:23 [extended] | reused | 2026-10-28T13:49:02Z |
| miri-9cfa9976cf37f21a | md5 | miri | md5-bulk:99 [extended] | reused | 2026-10-28T11:34:46Z |
| miri-9cfb1380bb06ec4f | tuplehash | miri | scoped_tuplexof256_differential:34:width=4 [extended] | reused | 2026-10-29T03:25:12Z |
| miri-9d0a9eb5e7c8ffe1 | sha3 | miri | every_fixed_identity_matches_the_ordinary_algorithm [routine] | passed | 2026-10-19T11:31:08Z |
| miri-9d1c25f718818dc0 | md5 | miri | md5-padding:86 [extended] | reused | 2026-10-28T11:24:25Z |
| miri-9d2241e02fd054c6 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:4:width=3 [extended] | reused | 2026-10-28T22:02:53Z |
| miri-9d22f7a425c1f4a4 | sha2 | miri | -p brynja-hash-sha2 --features hardened-execution,general-sha512-t --lib hardened_execution::engine::tests [remaining suite; inspect skips with show] | passed | 2026-10-19T11:22:37Z |
| miri-9d26f6dc50b21081 | tuplehash | miri | scoped_tuplexof256_differential:3:width=4 [extended] | reused | 2026-10-29T03:09:31Z |
| miri-9d292632b1f88d1e | tuplehash | miri | tuplehash-staging:833 [extended] | reused | 2026-10-28T19:00:10Z |
| miri-9d29ec7bc5cd4cc0 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-official:2 [routine] | No mapped observation | — |
| miri-9d2e8e4db8185fb8 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_unwind_reuse:3 [extended] | passed | 2026-10-29T14:06:15Z |
| miri-9d3804b38a8e8434 | sha1 | miri | sha1-bulk:162 [extended] | reused | 2026-10-28T12:53:41Z |
| miri-9d3cbac672bc994a | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:10:width=3 [extended] | reused | 2026-10-28T22:09:09Z |
| miri-9d3e2ed509946912 | sha1 | miri | sha1-scoped:283 [routine] | passed | 2026-10-19T11:32:18Z |
| miri-9d5bd569337d2f8c | sha1 | miri | sha1-bulk:135 [extended] | reused | 2026-10-28T12:56:37Z |
| miri-9d5f1aed0b3b2a95 | tuplehash | miri | scoped_tuplexof256_differential:26:width=3 [extended] | reused | 2026-10-29T03:06:14Z |
| miri-9d66c8e02aa6a3e4 | tuplehash | miri | tuplehash-staging:255 [extended] | reused | 2026-10-28T21:40:24Z |
| miri-9d8dd34df14c9709 | tuplehash | miri | scoped_tuplexof128_differential:38:width=0 [extended] | reused | 2026-10-29T01:45:47Z |
| miri-9d8f7b6dc74552ea | tuplehash | miri | tuplehash-staging:645 [extended] | reused | 2026-10-28T17:56:28Z |
| miri-9db055856d8f728e | hmac | miri | sha512_224 [routine] | No mapped observation | — |
| miri-9dc2640e254e574a | md5 | miri | md5-batch-mask:46 [extended] | reused | 2026-10-28T12:21:39Z |
| miri-9dcd8a589c4e98ec | tuplehash | miri | tuplehash-staging:143 [extended] | reused | 2026-10-28T21:02:36Z |
| miri-9dcff5d38dad0d8f | tuplehash | miri | scoped_tuplexof256_differential:30:width=1 [extended] | reused | 2026-10-29T03:15:42Z |
| miri-9dd3b94f2ee9419e | kmac | miri | kmac-scoped-lifecycle:3 [extended] | reused | 2026-10-28T14:04:41Z |
| miri-9dde1ae221dc5d6b | tuplehash | miri | tuplehash-staging:332 [extended] | reused | 2026-10-28T15:57:04Z |
| miri-9de21a927f058b1e | md5 | miri | md5-scoped:271 [extended] | reused | 2026-10-28T12:06:05Z |
| miri-9de51777a740a679 | sha3 | miri | -p brynja-crypto-cpu-std --features sponge-execution --lib sponge::tests::portable_sponge [remaining suite; inspect skips with show] | passed | 2026-10-19T11:30:59Z |
| miri-9df9e7a6100155d5 | md5 | miri | md5-scoped:266 [extended] | reused | 2026-10-28T12:16:43Z |
| miri-9dfc0d98db127f7b | md5 | miri | md5-bulk:236 [extended] | reused | 2026-10-28T11:55:58Z |
| miri-9e076cf585d36c0e | tuplehash | miri | scoped_tuplexof128_differential:29:width=4 [extended] | passed | 2026-10-29T11:49:44Z |
| miri-9e1a76f101dc142f | tuplehash | miri | tuplehash-staging:576 [extended] | reused | 2026-10-28T17:14:54Z |
| miri-9e21ab4848619225 | tuplehash | miri | tuplehash-staging:737 [extended] | reused | 2026-10-28T18:27:50Z |
| miri-9e363bcef56462de | kmac | miri | kmac-scoped-xof-lifecycle:13 [extended] | reused | 2026-10-28T14:10:47Z |
| miri-9e3741caf1dc8ca8 | tuplehash | miri | scoped_tuplexof128_differential:29:width=1 [extended] | passed | 2026-10-29T10:59:32Z |
| miri-9e3ada6b4d0f6dee | kmac | miri | kmac256_mismatch_and_exact_width [extended] | reused | 2026-10-28T19:45:58Z |
| miri-9e3db5264946e346 | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib batch_metadata_and_public_admission [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-9e4de077fa568404 | kmac | miri | kmac-scoped-xof-lifecycle:8 [extended] | reused | 2026-10-28T13:57:36Z |
| miri-9e541f1000034e03 | tuplehash | miri | tuplehash-staging:38 [extended] | reused | 2026-10-28T14:24:29Z |
| miri-9e6f4c9a0dfce12a | tuplehash | miri | tuplehash-staging:420 [extended] | reused | 2026-10-28T16:25:07Z |
| miri-9e76ee963f2dd408 | sha1 | miri | sha1-padding:38 [extended] | reused | 2026-10-28T12:42:17Z |
| miri-9e80636ae97654e7 | md5 | miri | md5-scoped:103 [extended] | reused | 2026-10-28T11:54:13Z |
| miri-9e97729f66b635ef | tuplehash | miri | scoped_tuplexof128_differential:25:width=0 [extended] | passed | 2026-10-29T11:01:12Z |
| miri-9eabe09300cc8c7a | tuplehash | miri | tuplehash-staging:463 [extended] | reused | 2026-10-28T22:49:42Z |
| miri-9eabf8532928e0ca | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:36 [routine] | passed | 2026-10-19T12:08:26Z |
| miri-9ebef1881cdb91e4 | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join256:1 [routine] | No mapped observation | — |
| miri-9ed3e23d580df974 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:4 [extended] | passed | 2026-10-29T14:06:50Z |
| miri-9ef67be956ac65fa | tuplehash | miri | tuplehash-staging:812 [extended] | reused | 2026-10-28T18:30:31Z |
| miri-9efd5ea4fd29297a | sha2 | miri | -p brynja-hash-sha2 --test sha512_256 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | reused | 2026-10-28T13:34:39Z |
| miri-9f08785ac6ab4483 | md5 | miri | md5-bulk:71 [extended] | reused | 2026-10-28T11:32:46Z |
| miri-9f0bbef5a7a82056 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:18 [routine] | No mapped observation | — |
| miri-9f0c1813ecfc3d08 | tuplehash | miri | tuplehash-staging:734 [extended] | reused | 2026-10-28T18:09:20Z |
| miri-9f44da9b51ca73c4 | tuplehash | miri | scoped_tuplexof128_differential:6 [routine] | passed | 2026-10-19T12:22:43Z |
| miri-9f51f5ec7c85eaec | tuplehash | miri | tuplehash-staging:243 [extended] | reused | 2026-10-28T21:35:56Z |
| miri-9f6b41fad41234b2 | tuplehash | miri | tuplehash-staging:735 [extended] | reused | 2026-10-29T00:21:21Z |
| miri-9f6b6a669718a990 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:27 [extended] | passed | 2026-10-29T13:38:29Z |
| miri-9f6cf834dbe68639 | sha1 | miri | sha1-scoped:165 [extended] | reused | 2026-10-28T13:22:52Z |
| miri-9f9efbec6ed5e64b | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:3 [extended] | passed | 2026-10-29T13:52:37Z |
| miri-9fc470efb3922292 | kmac | miri | kmac-streamed-setup:33 [routine] | No mapped observation | — |
| miri-9fef7f994cb1a8df | md5 | miri | md5-batch-mask:146 [extended] | reused | 2026-10-28T12:29:29Z |
| miri-9ff082e7e7d799f4 | md5 | miri | md5-bulk:151 [extended] | reused | 2026-10-28T11:38:42Z |
| miri-a004f774ac0eccf3 | md5 | miri | md5-batch-mask:207 [extended] | reused | 2026-10-28T12:23:42Z |
| miri-a012c7686c331a44 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:11:width=1 [extended] | reused | 2026-10-28T22:46:21Z |
| miri-a0182b68d888e231 | md5 | miri | md5-batch-mask:120 [extended] | reused | 2026-10-28T12:22:03Z |
| miri-a04d7855a4040591 | sha1 | miri | sha1-bulk:109 [extended] | reused | 2026-10-28T12:58:59Z |
| miri-a050556aaa10b47b | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:32:width=0 [extended] | reused | 2026-10-28T23:01:38Z |
| miri-a05532f9b371bfc8 | sha1 | miri | sha1-bulk:202 [extended] | reused | 2026-10-28T12:57:54Z |
| miri-a06be36155461a67 | md5 | miri | md5-bulk:218 [extended] | reused | 2026-10-28T11:49:22Z |
| miri-a072a7edbde93e0e | sha1 | miri | sha1-scoped:237 [extended] | reused | 2026-10-28T13:28:40Z |
| miri-a0737a366cf38e13 | tuplehash | miri | scoped_tuplexof256_differential:4:width=3 [extended] | reused | 2026-10-29T02:24:45Z |
| miri-a074f11e2c05692c | md5 | miri | md5-padding:127 [extended] | reused | 2026-10-28T11:32:18Z |
| miri-a07de24e501cef20 | md5 | miri | md5-scoped:114 [extended] | reused | 2026-10-28T12:05:51Z |
| miri-a080b5194e3838f5 | sha1 | miri | sha1-scoped:90 [extended] | reused | 2026-10-28T13:09:18Z |
| miri-a083c84e42f69c24 | kmac | miri | kmac-framing:7 [routine] | passed | 2026-10-19T11:49:08Z |
| miri-a0862675bcbcb8ae | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:12:width=2 [extended] | reused | 2026-10-28T19:46:30Z |
| miri-a0901363ffec106c | tuplehash | miri | tuplehash-staging:471 [extended] | reused | 2026-10-28T22:52:39Z |
| miri-a098d6048843032c | tuplehash | miri | tuplehash-staging:581 [extended] | reused | 2026-10-28T17:35:18Z |
| miri-a0a10e97f56871a1 | sha1 | miri | sha1-padding:22 [extended] | reused | 2026-10-28T12:41:00Z |
| miri-a0d381879871bfdb | tuplehash | miri | tuplehash-staging:233 [extended] | reused | 2026-10-28T15:38:43Z |
| miri-a0d81a3a65333a96 | kmac | miri | kmac-streamed-setup:78 [routine] | No mapped observation | — |
| miri-a0ea40b6568a0a5a | tuplehash | miri | scoped_tuplexof128_differential:40:width=4 [extended] | reused | 2026-10-29T01:58:45Z |
| miri-a0eb85e2394d834c | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:5 [extended] | passed | 2026-10-29T13:52:57Z |
| miri-a1004da17c14240d | tuplehash | miri | -p brynja-hash-tuple --features hardened-execution --lib execution [remaining suite; inspect skips with show] | passed | 2026-10-29T10:48:27Z |
| miri-a10a7b9fad36be80 | sha1 | miri | sha1-scoped:252 [extended] | reused | 2026-10-28T13:23:57Z |
| miri-a11e0c1d2f85f31a | sha3 | miri | sha3-fixed-boundaries:67 [extended] | reused | 2026-10-28T13:45:37Z |
| miri-a134e770fc5767e1 | kmac | miri | kmac-streamed-setup:40 [routine] | No mapped observation | — |
| miri-a141714011655dd4 | tuplehash | miri | tuplehash-staging:487 [extended] | reused | 2026-10-28T22:57:53Z |
| miri-a154fbc30868a006 | sha1 | miri | sha1-bulk:159 [extended] | reused | 2026-10-28T12:59:09Z |
| miri-a15f9b81a22fdd0d | md5 | miri | md5-batch-mask:203 [extended] | reused | 2026-10-28T12:23:23Z |
| miri-a176497462d80291 | kmac | miri | kmac-streamed-setup:10 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-a17981a0081c3b01 | legacy | miri | --manifest-path assurance/legacy-hash-public-api/current/Cargo.toml --lib dynamic_ [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-a183db4bd56638e9 | md5 | miri | md5-padding:114 [extended] | reused | 2026-10-28T11:26:34Z |
| miri-a19da3b8e76c807c | tuplehash | miri | tuplehash-staging:835 [extended] | reused | 2026-10-29T00:55:05Z |
| miri-a1afb4fe5020d353 | kmac | miri | kmac-scoped-lifecycle:14 [routine] | passed | 2026-10-19T11:42:19Z |
| miri-a1c597fac8ec7b03 | tuplehash | miri | tuplehash-staging:522 [extended] | reused | 2026-10-28T17:01:03Z |
| miri-a2098158b927705f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:55:width=2 [extended] | reused | 2026-10-29T01:10:24Z |
| miri-a2122600c08b92e9 | md5 | miri | md5-scoped:249 [extended] | reused | 2026-10-28T12:04:47Z |
| miri-a21b0b49ee1dc9f9 | sha1 | miri | sha1-padding:122 [extended] | reused | 2026-10-28T12:50:17Z |
| miri-a22889e6bf653fcc | tuplehash | miri | scoped_tuplexof128_differential:36:width=0 [extended] | reused | 2026-10-29T01:46:32Z |
| miri-a23ff3d98d9420e2 | tuplehash | miri | scoped_tuplexof256_differential:9:width=3 [extended] | passed | 2026-10-29T11:57:30Z |
| miri-a242ababa77b8ce7 | md5 | miri | md5-scoped:12 [extended] | reused | 2026-10-28T11:53:47Z |
| miri-a252c0646c66d164 | md5 | miri | md5-scoped:255 [extended] | reused | 2026-10-28T12:04:55Z |
| miri-a258f8c80bbb4ee7 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:3 [extended] | passed | 2026-10-29T14:08:21Z |
| miri-a26dbb2ab6217a46 | sha1 | miri | sha1-scoped:269 [extended] | reused | 2026-10-28T13:31:17Z |
| miri-a279355e76b6dab4 | sha1 | miri | sha1-scoped:231 [extended] | reused | 2026-10-28T13:33:24Z |
| miri-a27b060e387c3597 | kmac | miri | kmacxof-official:3 [extended] | reused | 2026-10-28T14:14:53Z |
| miri-a27bb0c8dc4c2eb6 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:21 [extended] | passed | 2026-10-29T14:09:04Z |
| miri-a2819f66320b07e0 | sha1 | miri | sha1-bulk:156 [extended] | reused | 2026-10-28T12:51:33Z |
| miri-a2ae6b41f45b847b | sha1 | miri | sha1-scoped:13 [extended] | reused | 2026-10-28T13:11:39Z |
| miri-a2d41b9128af337b | sha1 | miri | sha1-padding:41 [extended] | reused | 2026-10-28T12:31:16Z |
| miri-a2d7bda1d46e0505 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:1:width=1 [extended] | reused | 2026-10-29T04:23:03Z |
| miri-a2da3d46b2afd4d1 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:0 [routine] | No mapped observation | — |
| miri-a2dbf63e46588a11 | md5 | miri | md5-scoped:108 [extended] | reused | 2026-10-28T12:00:19Z |
| miri-a2e5a479de80ead3 | md5 | miri | md5-bulk:199 [extended] | reused | 2026-10-28T11:42:31Z |
| miri-a2ed174afb8f4509 | tuplehash | miri | tuplehash-staging:389 [extended] | reused | 2026-10-28T16:31:11Z |
| miri-a2f3ece7a89357c7 | static_cpu | miri | -p brynja-crypto-cpu-std --features runtime-execution --lib execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-a2fd23e9a1e99f99 | tuplehash | miri | scoped_tuplexof256_differential:15:width=0 [extended] | reused | 2026-10-29T03:30:33Z |
| miri-a3163ae2a6f82859 | sha1 | miri | sha1-scoped:224 [extended] | reused | 2026-10-28T13:21:36Z |
| miri-a31c07ae8d1b3577 | sha3 | miri | sha3-fixed-boundaries:2 [extended] | reused | 2026-10-28T13:36:32Z |
| miri-a31e7f26247ebcf2 | sha1 | miri | sha1-bulk:41 [extended] | reused | 2026-10-28T12:53:35Z |
| miri-a32c6e1aab747f01 | md5 | miri | md5-bulk:119 [routine] | passed | 2026-10-19T11:14:04Z |
| miri-a33292313ea7409e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:51:width=1 [extended] | reused | 2026-10-28T22:01:22Z |
| miri-a333b85f05d9be98 | sha1 | miri | sha1-scoped:75 [routine] | passed | 2026-10-19T11:32:03Z |
| miri-a3593364f8052caf | sha1 | miri | sha1-scoped:172 [extended] | reused | 2026-10-28T13:17:23Z |
| miri-a360b9a77431420e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:15:width=0 [extended] | reused | 2026-10-28T20:13:06Z |
| miri-a37fe045b3169535 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:49:width=2 [extended] | reused | 2026-10-29T06:33:54Z |
| miri-a3b11e5ad0a445a3 | tuplehash | miri | tuplehash-staging:806 [extended] | reused | 2026-10-28T18:31:37Z |
| miri-a3ee5906b0c203d7 | sha1 | miri | sha1-scoped:161 [extended] | reused | 2026-10-28T13:22:34Z |
| miri-a401ecc9a36a37c6 | sha1 | miri | sha1-bulk:24 [extended] | reused | 2026-10-28T12:40:35Z |
| miri-a405c9e162f8fb6a | tuplehash | miri | tuplehash-staging:843 [extended] | reused | 2026-10-29T00:58:11Z |
| miri-a40b9f39d2f6e835 | tuplehash | miri | scoped_tuplexof128_differential:33:width=1 [extended] | passed | 2026-10-29T11:01:43Z |
| miri-a41298936d75d6e3 | sha2 | miri | -p brynja-hash-sha2 --lib hardened::tests::checked_length_ [remaining suite; inspect skips with show] | reused | 2026-10-28T13:31:58Z |
| miri-a41b4020be3a5ed8 | md5 | miri | md5-scoped:204 [extended] | reused | 2026-10-28T12:06:56Z |
| miri-a42fa4627733be1d | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:36:width=1 [extended] | reused | 2026-10-28T23:10:45Z |
| miri-a43508e8f685eace | sha1 | miri | sha1-bulk:37 [extended] | reused | 2026-10-28T12:53:20Z |
| miri-a447b7eba056fcb8 | tuplehash | miri | scoped_tuplexof256_differential:38:width=1 [extended] | reused | 2026-10-29T03:34:42Z |
| miri-a451cf8c23314600 | kmac | miri | kmac-streamed-setup:90 [routine] | No mapped observation | — |
| miri-a45d1b9b94bf7605 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:0:width=2 [extended] | reused | 2026-10-28T19:26:50Z |
| miri-a465edf104c224da | md5 | miri | md5-scoped:43 [extended] | reused | 2026-10-28T11:50:11Z |
| miri-a4680fe10b296688 | md5 | miri | md5-bulk:39 [extended] | reused | 2026-10-28T11:30:37Z |
| miri-a46b768ba6ee921f | tuplehash | miri | tuplehash-staging:336 [extended] | reused | 2026-10-28T15:57:59Z |
| miri-a47e110a4801e706 | tuplehash | miri | -p brynja-hash-tuple --features hardened-execution --test execution [remaining suite; inspect skips with show] | passed | 2026-10-19T12:00:41Z |
| miri-a486881d909a3788 | tuplehash | miri | tuplehash-staging:692 [extended] | reused | 2026-10-28T17:52:27Z |
| miri-a4936ae1908e823c | sha1 | miri | sha1-bulk:58 [extended] | reused | 2026-10-28T12:44:24Z |
| miri-a494501182c352e1 | tuplehash | miri | tuplehash-staging:343 [extended] | reused | 2026-10-28T22:09:39Z |
| miri-a49be8f0249b9513 | tuplehash | miri | scoped_tuplexof128_differential:5:width=4 [extended] | reused | 2026-10-29T07:15:40Z |
| miri-a4a959a62b319743 | md5 | miri | md5-scoped:246 [extended] | reused | 2026-10-28T12:15:16Z |
| miri-a4c75ca3e1c0a521 | sha1 | miri | sha1-scoped:98 [extended] | reused | 2026-10-28T13:09:53Z |
| miri-a4cf195ce5e46b4a | kmac | miri | kmac-scoped-lifecycle:5 [extended] | reused | 2026-10-28T19:49:22Z |
| miri-a4ec9463df55ee63 | tuplehash | miri | tuplehash-staging:253 [extended] | reused | 2026-10-28T15:44:58Z |
| miri-a51e6f45375b8cf5 | sha1 | miri | sha1-padding:87 [extended] | reused | 2026-10-28T12:36:45Z |
| miri-a523c3e136c87ccd | tuplehash | miri | tuplehash-staging:508 [extended] | reused | 2026-10-28T16:53:05Z |
| miri-a5406e665b15768e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:12:width=1 [extended] | reused | 2026-10-28T22:16:00Z |
| miri-a54262dcb2b6b05e | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_unwind_reuse:0 [extended] | passed | 2026-10-29T14:16:21Z |
| miri-a54c388e65ee2361 | tuplehash | miri | scoped_tuplexof256_differential:33:width=3 [extended] | passed | 2026-10-29T12:09:57Z |
| miri-a57ca68993624bb3 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-order:2 [routine] | No mapped observation | — |
| miri-a58f967f0f1896c7 | sha1 | miri | sha1-bulk:0 [routine] | passed | 2026-10-19T11:31:04Z |
| miri-a59205d7ddf84b39 | tuplehash | miri | tuplehash-staging:296 [extended] | reused | 2026-10-28T15:44:54Z |
| miri-a5add9eef9cd6639 | tuplehash | miri | scoped_tuplexof256_differential:9:width=0 [extended] | passed | 2026-10-29T12:10:51Z |
| miri-a5b8c75ceb26ef3d | md5 | miri | md5-batch-mask:41 [extended] | reused | 2026-10-28T12:10:33Z |
| miri-a5c0e0757caca896 | sha1 | miri | sha1-bulk:48 [extended] | reused | 2026-10-28T12:42:09Z |
| miri-a5cf1b59308b6b01 | tuplehash | miri | tuplehash-execution-fixed:13 [routine] | passed | 2026-10-19T12:21:16Z |
| miri-a5d6deac17e47ba1 | sha1 | miri | -p brynja-legacy-sha1 --features hardened-execution --lib cpu::secret::tests [remaining suite; inspect skips with show] | passed | 2026-10-19T11:15:16Z |
| miri-a5ddda4196de4f3d | sha1 | miri | sha1-bulk:129 [routine] | passed | 2026-10-19T11:35:04Z |
| miri-a5e13c0dbf15a38d | sha3 | miri | sha3-fixed-bits:23 [routine] | passed | 2026-10-19T11:29:55Z |
| miri-a5eb646c640013f2 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:46:width=0 [extended] | reused | 2026-10-28T21:04:48Z |
| miri-a5f6ef398627102c | md5 | miri | md5-batch-mask:156 [extended] | reused | 2026-10-28T12:24:52Z |
| miri-a5ff958ebaa11e08 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:29:width=1 [extended] | reused | 2026-10-29T02:43:39Z |
| miri-a603fe4378eebdcb | md5 | miri | md5-padding:70 [extended] | reused | 2026-10-28T11:23:08Z |
| miri-a6076f8bfb48e298 | tuplehash | miri | scoped_tuplexof256_differential:27 [routine] | passed | 2026-10-19T12:36:31Z |
| miri-a614d8f2a69b7c7c | tuplehash | miri | tuplehash-staging:602 [extended] | reused | 2026-10-28T17:26:42Z |
| miri-a6183f52537c1e8d | tuplehash | miri | scoped_tuplexof128_differential:13:width=2 [extended] | passed | 2026-10-29T10:52:15Z |
| miri-a620d23543cc2cf0 | sha1 | miri | sha1-bulk:256 [routine] | passed | 2026-10-19T11:16:55Z |
| miri-a628de205623f148 | md5 | miri | md5-batch-mask:3 [extended] | reused | 2026-10-28T12:07:29Z |
| miri-a62939c9e314c5c3 | tuplehash | miri | tuplehash-staging:132 [extended] | reused | 2026-10-28T14:51:53Z |
| miri-a62b1158cdad987b | tuplehash | miri | tuplehash-staging:836 [extended] | reused | 2026-10-28T18:38:33Z |
| miri-a6354a9ce0f71f55 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:49:width=4 [extended] | reused | 2026-10-29T06:33:54Z |
| miri-a635f99961fb24e6 | sha2 | miri | -p brynja-hash-sha2 --features runtime-execution,general-sha512-t --lib execution_transaction [remaining suite; inspect skips with show] | passed | 2026-10-19T11:30:04Z |
| miri-a6368ad6db1b9fba | tuplehash | miri | tuplehash-staging:861 [extended] | reused | 2026-10-28T19:09:36Z |
| miri-a63a340195547f95 | md5 | miri | md5-scoped:196 [extended] | reused | 2026-10-28T12:06:22Z |
| miri-a6505e619db7cb33 | tuplehash | miri | tuplehash-staging:372 [extended] | reused | 2026-10-28T16:09:16Z |
| miri-a65e540ca7631b68 | sha1 | miri | sha1-bulk:32 [extended] | reused | 2026-10-28T12:41:06Z |
| miri-a66723305b424393 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:45:width=2 [extended] | reused | 2026-10-29T06:07:36Z |
| miri-a66749b2cf9fc979 | tuplehash | miri | tuplehash-staging:666 [extended] | reused | 2026-10-28T17:46:49Z |
| miri-a671679b9ad194b1 | md5 | miri | md5-bulk:79 [extended] | reused | 2026-10-28T11:33:20Z |
| miri-a6981695ebcbf0b2 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:12:width=2 [extended] | reused | 2026-10-28T22:16:00Z |
| miri-a6a57a5411c9345e | md5 | miri | md5-scoped:47 [extended] | reused | 2026-10-28T11:50:27Z |
| miri-a6b4a83bb808e31b | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:31:width=0 [extended] | reused | 2026-10-28T20:52:30Z |
| miri-a6b7bbc12754e12e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:3:width=0 [extended] | reused | 2026-10-28T22:32:17Z |
| miri-a6c7b8878edb5a77 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:13 [extended] | passed | 2026-10-29T13:52:21Z |
| miri-a6cee3aac64af457 | hmac | miri | output_clears_during_consumer_unwind [extended] | passed | 2026-10-29T15:22:15Z |
| miri-a6d47044c49a0041 | kmac | miri | kmac-streamed-setup:56 [routine] | No mapped observation | — |
| miri-a6e4cbef085fba97 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:22:width=0 [extended] | reused | 2026-10-28T20:04:30Z |
| miri-a6f8412c43608827 | md5 | miri | md5-batch-mask:83 [extended] | reused | 2026-10-28T12:13:34Z |
| miri-a6fae520633af40f | sha1 | miri | sha1-bulk:219 [extended] | reused | 2026-10-28T13:05:58Z |
| miri-a7009d304524113d | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:43:width=4 [extended] | reused | 2026-10-29T00:04:50Z |
| miri-a71e607df2f74383 | hmac | miri | -p brynja-mac-hmac --features hardened-execution --lib execution::tests [remaining suite; inspect skips with show] | passed | 2026-10-29T15:08:03Z |
| miri-a71f957615bdb4c2 | sha1 | miri | sha1-bulk:11 [extended] | reused | 2026-10-28T12:46:50Z |
| miri-a754a3b12b953cec | sha1 | miri | sha1-scoped:105 [extended] | reused | 2026-10-28T13:18:15Z |
| miri-a76513c8b5f15096 | tuplehash | miri | tuplehash-staging:811 [extended] | reused | 2026-10-29T00:47:25Z |
| miri-a773fde2854c1836 | md5 | miri | md5-bulk:86 [extended] | reused | 2026-10-28T11:38:20Z |
| miri-a795f25bf3984bc7 | tuplehash | miri | tuplehash-staging:267 [extended] | reused | 2026-10-28T21:43:39Z |
| miri-a79728208ac36630 | tuplehash | miri | tuplehash-staging:185 [extended] | reused | 2026-10-28T15:23:09Z |
| miri-a7a0f12c14c475d8 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:5 [routine] | No mapped observation | — |
| miri-a7a32ee9ff47d4c3 | tuplehash | miri | tuplehash-staging:881 [extended] | reused | 2026-10-28T19:16:44Z |
| miri-a7b394b28bf45e0f | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:12:width=4 [extended] | reused | 2026-10-28T19:46:30Z |
| miri-a7b75b18fa60a41d | md5 | miri | md5-scoped:159 [extended] | reused | 2026-10-28T11:58:01Z |
| miri-a7e1af946eb5e36b | tuplehash | miri | tuplehash-staging:333 [extended] | reused | 2026-10-28T16:12:20Z |
| miri-a8015df0d07ee7d1 | md5 | miri | md5-batch-mask:137 [extended] | reused | 2026-10-28T12:18:03Z |
| miri-a82438f3f2b4db7c | tuplehash | miri | tuplehash-staging:443 [extended] | reused | 2026-10-28T22:43:25Z |
| miri-a83e02bd45febf3d | tuplehash | miri | tuplehash-staging:599 [extended] | reused | 2026-10-28T23:35:29Z |
| miri-a8569311a1aee50f | tuplehash | miri | scoped_tuplexof128_differential:13:width=4 [extended] | passed | 2026-10-29T10:53:25Z |
| miri-a858c7296d26903c | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:10 [routine] | No mapped observation | — |
| miri-a862800d6c1eb1ef | legacy_hmac | miri | md5_long [extended] | passed | 2026-10-29T15:08:45Z |
| miri-a87ed63d311d8c58 | sha1 | miri | sha1-scoped:206 [extended] | reused | 2026-10-28T13:18:36Z |
| miri-a8840dbf1fcf6e52 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:54:width=4 [extended] | reused | 2026-10-29T00:22:37Z |
| miri-a889bea0725c8209 | tuplehash | miri | tuplehash-staging:761 [extended] | reused | 2026-10-28T18:35:55Z |
| miri-a89ea3994abf7f15 | sha3 | miri | sha3-fixed-boundaries:52 [extended] | reused | 2026-10-28T13:51:40Z |
| miri-a8aba74666dbb1c9 | md5 | miri | md5-batch-mask:236 [extended] | reused | 2026-10-28T12:31:19Z |
| miri-a8c3d98120a7ae76 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:0 [extended] | passed | 2026-10-29T13:04:20Z |
| miri-a8c739318a64d688 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:2 [extended] | passed | 2026-10-29T13:54:34Z |
| miri-a8ce87b02bf3bbf6 | md5 | miri | md5-batch-mask:196 [extended] | reused | 2026-10-28T12:28:03Z |
| miri-a8e2031d89e9cb16 | md5 | miri | md5-batch-mask:91 [extended] | reused | 2026-10-28T12:14:12Z |
| miri-a8e22307109a3868 | tuplehash | miri | tuplehash-staging:362 [extended] | reused | 2026-10-28T16:09:50Z |
| miri-a8e315454521a12d | sha3 | miri | sha3-fixed-boundaries:69 [extended] | reused | 2026-10-28T13:41:04Z |
| miri-a8f5a8fd342177d6 | hmac | miri | -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-a9056c372949416f | md5 | miri | md5-batch-mask:205 [extended] | reused | 2026-10-28T12:23:31Z |
| miri-a909dcfb89283d67 | sha1 | miri | sha1-padding:65 [routine] | passed | 2026-10-19T11:15:47Z |
| miri-a90bbd1ab5bfb651 | tuplehash | miri | tuplehash-staging:496 [extended] | reused | 2026-10-28T16:49:36Z |
| miri-a92332d3caa1eb9d | tuplehash | miri | tuplehash-staging:435 [extended] | reused | 2026-10-28T22:40:18Z |
| miri-a9284b79afe40113 | sha1 | miri | sha1-scoped:74 [extended] | reused | 2026-10-28T13:08:06Z |
| miri-a9313964701c0f45 | md5 | miri | md5-bulk:85 [extended] | reused | 2026-10-28T11:33:28Z |
| miri-a950bf79ecfe951f | md5 | miri | md5-bulk:7 [routine] | passed | 2026-10-19T11:29:03Z |
| miri-a9768911b0dffe33 | sha1 | miri | sha1-scoped:176 [extended] | reused | 2026-10-28T13:17:41Z |
| miri-a98cf35b64d29101 | sha3 | miri | -p brynja-hash-sha3 --features static-execution --lib execution [remaining suite; inspect skips with show] | reused | 2026-10-28T13:43:29Z |
| miri-a98f0d7c307b4d28 | tuplehash | miri | scoped_tuplexof128_differential:28:width=3 [extended] | reused | 2026-10-29T01:27:22Z |
| miri-a991179b2a0587a3 | tuplehash | miri | tuplehash-staging:643 [extended] | reused | 2026-10-28T23:50:42Z |
| miri-a9a2d85b1ceb1852 | parallelhash | miri | [bounded-parallelhash-v1] parallelhashxof-official:0 [extended] | passed | 2026-10-29T14:13:08Z |
| miri-a9acb0248f188c17 | tuplehash | miri | tuplehash-staging:289 [extended] | reused | 2026-10-28T15:57:30Z |
| miri-a9b7a7c4c04bcc28 | md5 | miri | md5-scoped:207 [extended] | reused | 2026-10-28T12:01:24Z |
| miri-a9bebcbc7ea1106c | md5 | miri | md5-scoped:40 [extended] | reused | 2026-10-28T11:55:38Z |
| miri-a9c906bf112c16cd | md5 | miri | md5-bulk:73 [extended] | reused | 2026-10-28T11:32:36Z |
| miri-a9e92278505c7f72 | tuplehash | miri | tuplehash-staging:77 [extended] | reused | 2026-10-28T14:46:26Z |
| miri-aa03d80f9170bb33 | md5 | miri | md5-padding:93 [extended] | reused | 2026-10-28T11:34:34Z |
| miri-aa08844e61ca66b0 | md5 | miri | md5-bulk:108 [extended] | reused | 2026-10-28T11:45:01Z |
| miri-aa208a035c32735b | tuplehash | miri | tuplehash-staging:475 [extended] | reused | 2026-10-28T22:54:19Z |
| miri-aa31a054dcff0ff1 | tuplehash | miri | scoped_tuplexof128_differential:31:width=3 [extended] | reused | 2026-10-29T02:17:45Z |
| miri-aa414031d71b054f | hmac | miri | sha256 [extended] | passed | 2026-10-29T15:02:20Z |
| miri-aa49b8ec3a2dbbde | sha1 | miri | sha1-bulk:40 [extended] | reused | 2026-10-28T12:41:37Z |
| miri-aa49c21ea84073ef | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:0:width=4 [extended] | reused | 2026-10-28T21:56:20Z |
| miri-aa540e3e63f4a5b0 | tuplehash | miri | tuplehash-staging:869 [extended] | reused | 2026-10-28T19:11:54Z |
| miri-aa756e966ec14ed9 | tuplehash | miri | tuplehash-staging:180 [extended] | reused | 2026-10-28T15:07:16Z |
| miri-aa7798ddb76f3a82 | tuplehash | miri | tuplehash-staging:672 [extended] | reused | 2026-10-28T17:45:42Z |
| miri-aa7941516e0049b7 | tuplehash | miri | tuplehash-staging:383 [extended] | reused | 2026-10-28T22:23:06Z |
| miri-aa7a95af659bc98c | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:52:width=2 [extended] | reused | 2026-10-29T00:23:27Z |
| miri-aa9b5ddceccf1f58 | parallelhash | miri | [bounded-parallelhash-v1] parallelhashxof-official:2 [routine] | No mapped observation | — |
| miri-aa9e5c569df06cad | sha3 | miri | sha3-fixed-bits:10 [routine] | passed | 2026-10-19T11:38:50Z |
| miri-aac2d2a8a4468eba | sha1 | miri | sha1-bulk:245 [extended] | reused | 2026-10-28T13:14:03Z |
| miri-aac7645ae91805ed | tuplehash | miri | scoped_tuplexof256_differential:0 [routine] | passed | 2026-10-19T12:13:48Z |
| miri-aaccbc21237dd7cd | sha1 | miri | sha1-padding:128 [extended] | reused | 2026-10-28T12:46:04Z |
| miri-aaed7ee591722b2c | tuplehash | miri | scoped_tuplexof256_differential:8:width=3 [extended] | reused | 2026-10-29T02:31:37Z |
| miri-aaf275210474694c | sha1 | miri | sha1-padding:113 [extended] | reused | 2026-10-28T12:37:40Z |
| miri-ab117d2f8736aca2 | md5 | miri | md5-padding:59 [extended] | reused | 2026-10-28T11:27:11Z |
| miri-ab20bb9907272578 | tuplehash | miri | scoped_tuplexof256_differential:29:width=0 [extended] | passed | 2026-10-29T12:37:30Z |
| miri-ab2a31db2308562e | md5 | miri | md5-batch-mask:217 [extended] | reused | 2026-10-28T12:24:29Z |
| miri-ab4462000c7a2268 | tuplehash | miri | tuplehash-staging:250 [extended] | reused | 2026-10-28T15:33:19Z |
| miri-ab4f7d956e6c7efa | tuplehash | miri | scoped_tuplexof128_differential:38:width=2 [extended] | reused | 2026-10-29T01:45:47Z |
| miri-ab59adc9fca96f64 | md5 | miri | md5-scoped:1 [extended] | reused | 2026-10-28T11:47:40Z |
| miri-ab5e5945f62dac02 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:25:width=2 [extended] | reused | 2026-10-29T05:13:15Z |
| miri-ab81324adc63071e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:39:width=2 [extended] | reused | 2026-10-28T23:52:11Z |
| miri-ab83a96e6bd4ac3e | kmac | miri | kmac-scoped-lifecycle:15 [extended] | reused | 2026-10-28T14:06:45Z |
| miri-ab8668c8598a3753 | tuplehash | miri | tuplehash-staging:838 [extended] | reused | 2026-10-28T18:42:15Z |
| miri-ab97870c920bb26b | md5 | miri | md5-scoped:142 [extended] | reused | 2026-10-28T12:07:48Z |
| miri-abce7a0c7354aca0 | sha1 | miri | sha1-bulk:67 [extended] | reused | 2026-10-28T12:50:32Z |
| miri-abf8193e6b102a29 | tuplehash | miri | tuplehash-staging:676 [extended] | reused | 2026-10-28T17:46:59Z |
| miri-abfff511b64196a9 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:48:width=2 [extended] | reused | 2026-10-28T23:58:48Z |
| miri-ac0402f8ddef9f36 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:6 [routine] | No mapped observation | — |
| miri-ac107d4f4e8a3d9c | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:40:width=1 [extended] | reused | 2026-10-28T23:22:29Z |
| miri-ac1be2341d765d8f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:32:width=1 [extended] | reused | 2026-10-28T23:01:38Z |
| miri-ac433eb2b46a4255 | static_cpu | miri | -p brynja-crypto-cpu --features runtime-execution --lib runtime_execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-ac5541727c2219cc | tuplehash | miri | tuplehash-staging:218 [extended] | reused | 2026-10-28T15:22:32Z |
| miri-ac5a4d808f8a12a4 | md5 | miri | md5-scoped:270 [extended] | reused | 2026-10-28T12:17:00Z |
| miri-ac601a333990d150 | parallelhash | miri | reordered_leaf_permanently_fails_closed [routine] | passed | 2026-10-19T13:54:59Z |
| miri-ac7182cd3ea84567 | tuplehash | miri | tuplehash-staging:634 [extended] | reused | 2026-10-28T17:36:58Z |
| miri-ac89444cce164644 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:16:width=1 [extended] | reused | 2026-10-28T19:55:42Z |
| miri-ac8d557f8984348b | tuplehash | miri | scoped_tuplexof256_differential:38:width=0 [extended] | reused | 2026-10-29T03:34:42Z |
| miri-ac99b3fd891130b0 | kmac | miri | kmac-framing:6 [extended] | reused | 2026-10-28T13:51:46Z |
| miri-ac9ed27dd4c1b920 | tuplehash | miri | tuplehash-staging:414 [extended] | reused | 2026-10-28T16:26:14Z |
| miri-acbdb1d8db68b948 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:22:width=3 [extended] | reused | 2026-10-28T20:04:30Z |
| miri-accd9f33b4f93e49 | tuplehash | miri | tuplehash-staging:374 [extended] | reused | 2026-10-28T16:14:09Z |
| miri-acd26fd3b99568c6 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:7:width=0 [extended] | reused | 2026-10-28T19:59:05Z |
| miri-acd671db6e19a929 | tuplehash | miri | tuplehash-staging:434 [extended] | reused | 2026-10-28T16:33:10Z |
| miri-ace94f78ebe615e8 | sha1 | miri | sha1-scoped:276 [extended] | reused | 2026-10-28T13:25:50Z |
| miri-aced1d16bfbd9a43 | tuplehash | miri | tuplehash-staging:803 [extended] | reused | 2026-10-29T00:44:18Z |
| miri-acef86c1efa3003a | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:45:width=3 [extended] | reused | 2026-10-29T03:28:25Z |
| miri-acf01747e87fb801 | sha3 | miri | sha3-fixed-boundaries:54 [extended] | reused | 2026-10-28T13:43:18Z |
| miri-acfec859d3d735be | tuplehash | miri | scoped_tuplexof128_differential:18:width=2 [extended] | reused | 2026-10-29T00:58:05Z |
| miri-ad016e4de951f7d5 | tuplehash | miri | tuplehash-staging:11 [extended] | reused | 2026-10-28T20:18:09Z |
| miri-ad07588cb7508408 | md5 | miri | md5-scoped:239 [extended] | reused | 2026-10-28T12:03:44Z |
| miri-ad0ba3e9a9a0ec23 | tuplehash | miri | tuplehash-staging:893 [extended] | reused | 2026-10-28T19:20:22Z |
| miri-ad264132128dee38 | tuplehash | miri | tuplehash-staging:781 [extended] | reused | 2026-10-28T18:42:40Z |
| miri-ad477c8b04332088 | tuplehash | miri | tuplehash-staging:885 [extended] | reused | 2026-10-28T19:18:04Z |
| miri-ad62bee9f2786b85 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:6:width=0 [extended] | reused | 2026-10-28T22:02:39Z |
| miri-ad7945a33aa04ea8 | kmac | miri | kmac-streamed-setup:29 [routine] | No mapped observation | — |
| miri-ad7fc4e6537affca | md5 | miri | md5-bulk:195 [extended] | reused | 2026-10-28T11:42:10Z |
| miri-ad9ebbedc9cc4ddc | tuplehash | miri | tuplehash-staging:50 [extended] | reused | 2026-10-28T14:27:38Z |
| miri-ada1c5b394f1e0b5 | tuplehash | miri | scoped_tuplexof128_differential:46:width=1 [extended] | reused | 2026-10-29T02:10:19Z |
| miri-ada3c6ceb446854f | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:8:width=1 [extended] | reused | 2026-10-28T19:39:57Z |
| miri-adac399c6cbb6f36 | tuplehash | miri | scoped_tuplexof256_differential:14:width=2 [extended] | reused | 2026-10-29T02:37:48Z |
| miri-adb035edcb102e5f | sha1 | miri | sha1-scoped:188 [extended] | reused | 2026-10-28T13:18:36Z |
| miri-adb35b045eb22d53 | sha1 | miri | sha1-bulk:191 [extended] | reused | 2026-10-28T13:02:33Z |
| miri-adb7441dc5a88665 | tuplehash | miri | tuplehash-staging:228 [extended] | reused | 2026-10-28T15:22:50Z |
| miri-ade4c972be647f26 | md5 | miri | md5-scoped:65 [extended] | reused | 2026-10-28T11:51:53Z |
| miri-ade8cb56f496ab99 | tuplehash | miri | scoped_tuplexof256_differential:23:width=2 [extended] | reused | 2026-10-29T03:50:03Z |
| miri-adeace028e1bf7b4 | sha1 | miri | sha1-scoped:217 [routine] | passed | 2026-10-19T11:35:36Z |
| miri-adeb2e9fcde05ead | sha1 | miri | sha1-scoped:192 [extended] | reused | 2026-10-28T13:18:57Z |
| miri-adf4720885a379fe | sha1 | miri | sha1-scoped:197 [extended] | reused | 2026-10-28T13:25:19Z |
| miri-ae00d92ff63bbfa4 | sha3 | miri | sha3-fixed-boundaries:59 [extended] | reused | 2026-10-28T13:44:19Z |
| miri-ae11e7cc43be909c | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:6 [routine] | No mapped observation | — |
| miri-ae13c5bf9e30c3f4 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:9 [extended] | passed | 2026-10-29T14:10:13Z |
| miri-ae3d8f00a7708de0 | kmac | miri | -p brynja-mac-kmac --tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-ae4fdd76c0b1fd8e | tuplehash | miri | tuplehash-execution-fixed:7 [routine] | passed | 2026-10-19T15:59:40Z |
| miri-ae71af05b8762313 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:54:width=3 [extended] | reused | 2026-10-28T21:49:32Z |
| miri-ae87d6df10efa107 | md5 | miri | md5-padding:63 [routine] | passed | 2026-10-19T11:32:00Z |
| miri-ae8e43ea2bfa0f42 | md5 | miri | md5-batch-mask:8 [routine] | passed | 2026-10-19T11:32:58Z |
| miri-aea7806f0cefa1c0 | core | miri | -p brynja-core --test secret_memory [remaining suite; inspect skips with show] | reused | 2026-10-28T11:23:17Z |
| miri-aeb0b463a142c0bc | md5 | miri | md5-batch-mask:255 [extended] | reused | 2026-10-28T12:27:44Z |
| miri-aeb261b78fde7443 | md5 | miri | md5-padding:103 [extended] | reused | 2026-10-28T11:30:25Z |
| miri-aeb467d03e2fe133 | sha3 | miri | sha3-fixed-boundaries:16 [extended] | reused | 2026-10-28T13:46:53Z |
| miri-aeb62294aa7c6bd1 | tuplehash | miri | tuplehash-staging:92 [extended] | reused | 2026-10-28T14:38:03Z |
| miri-aeca114d9ad8ccc8 | md5 | miri | md5-padding:119 [routine] | passed | 2026-10-19T11:25:58Z |
| miri-aee5b26eb7712f4d | sha2 | miri | -p brynja-hash-sha2 --test sha384 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | reused | 2026-10-28T13:34:05Z |
| miri-aef06402df9decf0 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:53:width=2 [extended] | reused | 2026-10-29T07:01:39Z |
| miri-aef38ecc8f338301 | sha1 | miri | -p brynja-legacy-sha1 --lib [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-af0688b0529938d7 | kmac | miri | kmac-streamed-setup:93 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-af0b50f6ca6d41dc | tuplehash | miri | tuplehash-staging:357 [extended] | reused | 2026-10-28T16:20:24Z |
| miri-af0c5a3568ab810b | tuplehash | miri | tuplehash-staging:331 [extended] | reused | 2026-10-28T22:05:37Z |
| miri-af187fa74180623b | md5 | miri | md5-padding:52 [extended] | reused | 2026-10-28T11:21:55Z |
| miri-af21208eb0dd97bd | md5 | miri | md5-batch-mask:195 [extended] | reused | 2026-10-28T12:22:44Z |
| miri-af3ac1645b711c33 | sha1 | miri | sha1-scoped:136 [extended] | reused | 2026-10-28T13:14:28Z |
| miri-af3fb92714f7ca69 | tuplehash | miri | scoped_tuplexof128_differential:29:width=2 [extended] | passed | 2026-10-29T11:05:34Z |
| miri-af648d2f61533554 | tuplehash | miri | scoped_tuplexof128_differential:11:width=1 [extended] | reused | 2026-10-29T01:31:31Z |
| miri-af6ce43efc117ab9 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:4:width=0 [extended] | reused | 2026-10-28T22:02:53Z |
| miri-af75d533983a89da | tuplehash | miri | tuplehash-staging:155 [extended] | reused | 2026-10-28T21:05:51Z |
| miri-af8ae1f63ef8a4cf | tuplehash | miri | tuplehash-staging:454 [extended] | reused | 2026-10-28T16:39:57Z |
| miri-af8cec2e1ffdf415 | sha1 | miri | sha1-padding:107 [extended] | reused | 2026-10-28T12:38:33Z |
| miri-af9758675e0dfbf1 | tuplehash | miri | scoped_tuplexof128_differential:23:width=4 [extended] | reused | 2026-10-29T01:58:09Z |
| miri-af9a210c16d05427 | md5 | miri | md5-bulk:128 [extended] | reused | 2026-10-28T11:46:33Z |
| miri-afa33f284eb2dfeb | tuplehash | miri | tuplehash-staging:229 [extended] | reused | 2026-10-28T15:37:28Z |
| miri-afa8dc32b3e89b14 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:31:width=1 [extended] | reused | 2026-10-28T23:32:36Z |
| miri-afb75d2cbabdffb4 | md5 | miri | md5-scoped:230 [extended] | reused | 2026-10-28T12:14:07Z |
| miri-afb959e7d423994e | sha3 | miri | sha3-fixed-boundaries:47 [extended] | reused | 2026-10-28T13:42:45Z |
| miri-afbe9872db8f7dfd | tuplehash | miri | tuplehash-staging:152 [extended] | reused | 2026-10-28T14:58:05Z |
| miri-afe58d840050145b | md5 | miri | md5-batch-mask:89 [extended] | reused | 2026-10-28T12:14:14Z |
| miri-aff4d6265eee0830 | tuplehash | miri | scoped_tuplexof256_differential:9:width=1 [extended] | passed | 2026-10-29T11:56:32Z |
| miri-b014378022d7bd8a | sha1 | miri | sha1-scoped:96 [extended] | reused | 2026-10-28T13:11:14Z |
| miri-b01686fb024d74fc | sha1 | miri | sha1-scoped:62 [extended] | reused | 2026-10-28T13:07:13Z |
| miri-b01c5c0f9891c3b0 | tuplehash | miri | scoped_tuplexof128_differential:7:width=3 [extended] | reused | 2026-10-29T01:24:29Z |
| miri-b04e0e2a340b4035 | tuplehash | miri | tuplehash-staging:678 [extended] | reused | 2026-10-28T17:51:23Z |
| miri-b0514e898767477c | md5 | miri | md5-bulk:69 [extended] | reused | 2026-10-28T11:32:19Z |
| miri-b051ec78d237a6d7 | tuplehash | miri | tuplehash-execution-fixed:3 [extended] | reused | 2026-10-29T01:20:49Z |
| miri-b054b49cc261f29d | md5 | miri | md5-padding:15 [extended] | reused | 2026-10-28T11:24:35Z |
| miri-b05a633907b6d3e9 | sha1 | miri | sha1-scoped:16 [extended] | reused | 2026-10-28T13:05:22Z |
| miri-b0603f1fde39715f | tuplehash | miri | tuplehash-staging:506 [extended] | reused | 2026-10-28T16:55:54Z |
| miri-b06abab95829c7e0 | tuplehash | miri | scoped_tuplexof128_differential:43:width=1 [extended] | reused | 2026-10-29T02:49:54Z |
| miri-b08513b28d79a058 | tuplehash | miri | scoped_tuplexof128_differential:45:width=3 [extended] | passed | 2026-10-29T11:52:35Z |
| miri-b08872c5e9b0561f | tuplehash | miri | scoped_tuplexof256_differential:46:width=4 [extended] | reused | 2026-10-29T03:59:12Z |
| miri-b092a61e55b3229e | parallelhash | miri | -p brynja-hash-parallel --features hardened-execution --lib execution [remaining suite; inspect skips with show] | passed | 2026-10-29T13:01:26Z |
| miri-b0a169f737755849 | sha1 | miri | sha1-padding:35 [extended] | reused | 2026-10-28T12:32:17Z |
| miri-b0a6c1f4b13168a8 | sha1 | miri | sha1-bulk:31 [extended] | reused | 2026-10-28T12:48:06Z |
| miri-b0a8bd70a444779d | kmac | miri | kmac-scoped-xof-lifecycle:7 [extended] | reused | 2026-10-28T19:56:22Z |
| miri-b0aea3504f787a5f | tuplehash | miri | scoped_tuplexof256_differential:30:width=3 [extended] | reused | 2026-10-29T03:15:42Z |
| miri-b0bbeb20b50a1c56 | tuplehash | miri | tuplehash-staging:733 [extended] | reused | 2026-10-28T18:26:29Z |
| miri-b0e107f358be77cb | tuplehash | miri | tuplehash-staging:766 [extended] | reused | 2026-10-28T18:19:35Z |
| miri-b0e1e6de977d7ee5 | md5 | miri | md5-scoped:122 [extended] | reused | 2026-10-28T12:06:25Z |
| miri-b0e1ffd0f1916ffd | tuplehash | miri | tuplehash-staging:718 [extended] | reused | 2026-10-28T18:03:50Z |
| miri-b0ec3db6c9e98660 | sha3 | miri | -p brynja-hash-sha3 --test shake256 suffix_and_rate_boundaries_have_exact_output [remaining suite; inspect skips with show] | passed | 2026-10-19T11:36:02Z |
| miri-b0f21bf4a1b5c574 | md5 | miri | md5-bulk:72 [extended] | reused | 2026-10-28T11:42:20Z |
| miri-b100455818bf1d50 | sha1 | miri | sha1-scoped:145 [extended] | reused | 2026-10-28T13:21:22Z |
| miri-b1052419e2ba2e2b | md5 | miri | md5-batch-mask:221 [extended] | reused | 2026-10-28T12:24:49Z |
| miri-b107da6961e40513 | sha1 | miri | sha1-scoped:235 [extended] | reused | 2026-10-28T13:33:43Z |
| miri-b11e214a222f0246 | tuplehash | miri | tuplehash-staging:161 [extended] | reused | 2026-10-28T15:14:39Z |
| miri-b11e72ca1b4fced5 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:7 [extended] | passed | 2026-10-29T13:53:17Z |
| miri-b12c1559d22f0945 | kmac | miri | kmac-streamed-setup:89 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-b13c301b71650e1f | tuplehash | miri | tuplehash-staging:549 [extended] | reused | 2026-10-28T17:24:55Z |
| miri-b13f26b9f22eda05 | kmac | miri | kmac-streamed-setup:86 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-b14865d9a1e7f037 | tuplehash | miri | scoped_tuplexof256_differential:37:width=0 [extended] | passed | 2026-10-29T12:44:17Z |
| miri-b153cc9de9113a30 | tuplehash | miri | scoped_tuplexof128_differential:36:width=2 [extended] | reused | 2026-10-29T01:46:32Z |
| miri-b15f2cdb37ec8a77 | tuplehash | miri | tuplehash-staging:633 [extended] | reused | 2026-10-28T17:53:12Z |
| miri-b1666677dd18eee9 | md5 | miri | md5-bulk:250 [extended] | reused | 2026-10-28T11:52:21Z |
| miri-b19fe61ad4d8710c | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:21:width=3 [extended] | reused | 2026-10-29T05:03:33Z |
| miri-b1a63eee8973f3f3 | sha1 | miri | sha1-scoped:156 [extended] | reused | 2026-10-28T13:16:05Z |
| miri-b1a6e0fe92fe6385 | tuplehash | miri | scoped_tuplexof128_differential:20:width=1 [extended] | reused | 2026-10-29T01:08:19Z |
| miri-b1a7309f99b237e8 | sha1 | miri | sha1-bulk:136 [extended] | reused | 2026-10-28T12:49:36Z |
| miri-b1c3502367c0f08c | sha3 | miri | sha3-fixed-boundaries:49 [extended] | reused | 2026-10-28T13:37:37Z |
| miri-b1caee018e5747dc | tuplehash | miri | tuplehash-staging:547 [extended] | reused | 2026-10-28T23:17:37Z |
| miri-b1da4f623bf04f16 | md5 | miri | md5-bulk:227 [extended] | reused | 2026-10-28T11:44:56Z |
| miri-b1e9e887dbbcfa60 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:22:width=3 [extended] | reused | 2026-10-28T22:33:52Z |
| miri-b1f81fc5006a986e | tuplehash | miri | scoped_tuplexof128_differential:30:width=2 [extended] | reused | 2026-10-29T01:26:26Z |
| miri-b1fb7206eef52705 | md5 | miri | md5-scoped:0 [extended] | reused | 2026-10-28T11:52:58Z |
| miri-b20f2d84cfd1efca | tuplehash | miri | tuplehash-staging:474 [extended] | reused | 2026-10-28T16:45:52Z |
| miri-b217d89b2490ad53 | tuplehash | miri | tuplehash-staging:441 [routine] | passed | 2026-10-19T15:50:21Z |
| miri-b23d14c91c1dfed9 | tuplehash | miri | scoped_tuplexof256_differential:36:width=1 [extended] | reused | 2026-10-29T03:35:29Z |
| miri-b23fffc330c35a03 | md5 | miri | md5-batch-mask:171 [extended] | reused | 2026-10-28T12:20:44Z |
| miri-b247f7143fbcb239 | tuplehash | miri | scoped_tuplexof128_differential:6:width=4 [extended] | reused | 2026-10-29T00:35:44Z |
| miri-b24a810d2c859868 | sha1 | miri | sha1-padding:55 [extended] | reused | 2026-10-28T12:33:48Z |
| miri-b24de961021d8d97 | tuplehash | miri | tuplehash-staging:59 [extended] | reused | 2026-10-28T20:34:17Z |
| miri-b259d3ace487e5fe | tuplehash | miri | tuplehash-staging:614 [extended] | reused | 2026-10-28T17:30:33Z |
| miri-b25a0decaefb5146 | md5 | miri | md5-bulk:103 [extended] | reused | 2026-10-28T11:35:04Z |
| miri-b28370c9d9319411 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:9 [routine] | No mapped observation | — |
| miri-b28b2ca436c26763 | sha1 | miri | sha1-scoped:166 [extended] | reused | 2026-10-28T13:15:20Z |
| miri-b28fec791c1ea457 | md5 | miri | md5-batch-mask:10 [extended] | reused | 2026-10-28T12:18:59Z |
| miri-b2b80ce0beea311b | core | miri | -p brynja-core --test secret_memory [remaining suite; inspect skips with show] | passed | 2026-10-19T11:24:41Z |
| miri-b2b9cd75bb7f0593 | tuplehash | miri | tuplehash-staging:409 [extended] | reused | 2026-10-28T16:38:18Z |
| miri-b2baf074c2888e4e | md5 | miri | md5-scoped:177 [extended] | reused | 2026-10-28T11:59:32Z |
| miri-b2bc8a35c4b98fe0 | sha1 | miri | sha1-scoped:234 [extended] | reused | 2026-10-28T13:20:51Z |
| miri-b2c7284148b92a04 | md5 | miri | md5-bulk:16 [extended] | reused | 2026-10-28T11:38:32Z |
| miri-b2d3f8fe93daa593 | tuplehash | miri | tuplehash-staging:406 [extended] | reused | 2026-10-28T16:24:00Z |
| miri-b2e2c0f2c51cf395 | kmac | miri | kmac-streamed-setup:78 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-b2ef7ed954d6df59 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:25:width=4 [extended] | reused | 2026-10-29T02:33:53Z |
| miri-b3075280928b7b10 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:53:width=3 [extended] | reused | 2026-10-29T07:01:39Z |
| miri-b311291c17631220 | sha1 | miri | sha1-padding:109 [extended] | reused | 2026-10-28T12:37:19Z |
| miri-b311812562c5f1d4 | md5 | miri | md5-bulk:226 [extended] | reused | 2026-10-28T11:50:06Z |
| miri-b312fcf732349818 | md5 | miri | md5-scoped:25 [extended] | reused | 2026-10-28T11:49:15Z |
| miri-b3239a134fc1a563 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:32:width=4 [extended] | reused | 2026-10-28T20:32:25Z |
| miri-b33e5d292e95d567 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:26:width=3 [extended] | reused | 2026-10-28T22:42:58Z |
| miri-b349db21384369ec | tuplehash | miri | tuplehash-staging:775 [extended] | reused | 2026-10-29T00:34:51Z |
| miri-b35d728cb95b5705 | md5 | miri | md5-bulk:56 [routine] | passed | 2026-10-19T11:13:59Z |
| miri-b36e8d8736842f50 | sha2 | miri | --manifest-path assurance/general-sha512-t/Cargo.toml --lib [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-b371b05ec816242e | tuplehash | miri | tuplehash-staging:340 [extended] | reused | 2026-10-28T15:59:17Z |
| miri-b37ff5934b933e74 | sha3 | miri | sha3-secret-xof-bits:1 [routine] | passed | 2026-10-19T11:36:18Z |
| miri-b380f29b0aafe1db | sha3 | miri | -p brynja-hash-sha3 --test shake256 suffix_and_rate_boundaries_have_exact_output [remaining suite; inspect skips with show] | reused | 2026-10-28T13:44:24Z |
| miri-b384bf667fbb28a3 | md5 | miri | md5-bulk:202 [extended] | reused | 2026-10-28T11:47:56Z |
| miri-b3850d7d90f08af7 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:9 [routine] | No mapped observation | — |
| miri-b395378ab8319c86 | kmac | miri | kmac-streamed-setup:59 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-b3a84193b27ab136 | tuplehash | miri | scoped_tuplexof256_differential:31:width=1 [extended] | reused | 2026-10-29T04:09:27Z |
| miri-b3acee3d6983ec9d | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join128:3 [routine] | No mapped observation | — |
| miri-b3ba3d49fb9d113a | tuplehash | miri | scoped_tuplexof256_differential:43:width=4 [extended] | reused | 2026-10-29T04:41:29Z |
| miri-b3c02d90dd2d3cbd | sha3 | miri | sha3-fixed-bits:27 [extended] | reused | 2026-10-28T13:49:25Z |
| miri-b3eac5c4f429a197 | tuplehash | miri | tuplehash-staging:870 [extended] | reused | 2026-10-28T18:52:28Z |
| miri-b3fb3a0964732224 | md5 | miri | md5-bulk:9 [extended] | reused | 2026-10-28T11:28:18Z |
| miri-b4009a37f6add71c | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:55:width=4 [extended] | reused | 2026-10-28T22:25:13Z |
| miri-b403bccf084f1930 | kmac | miri | scoped_mismatch_propagates_and_workspace_can_be_reused [extended] | reused | 2026-10-28T19:45:58Z |
| miri-b43b4607ebdb9a3e | md5 | miri | md5-scoped:281 [extended] | reused | 2026-10-28T12:07:04Z |
| miri-b44986df15247786 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:28:width=3 [extended] | reused | 2026-10-28T20:23:14Z |
| miri-b44eda0ba47e6e78 | tuplehash | miri | tuplehash-staging:61 [extended] | reused | 2026-10-28T14:41:08Z |
| miri-b456aa1ce5f43d18 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:44:width=3 [extended] | reused | 2026-10-28T23:34:09Z |
| miri-b456d0e4eb14beb6 | tuplehash | miri | tuplehash-staging:540 [extended] | reused | 2026-10-28T17:03:01Z |
| miri-b45c8d95d0388fa8 | tuplehash | miri | tuplehash-staging:648 [extended] | reused | 2026-10-28T17:38:04Z |
| miri-b45f010443894974 | tuplehash | miri | tuplehash-staging:808 [extended] | reused | 2026-10-28T18:29:37Z |
| miri-b45fa94131ad329e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:34:width=3 [extended] | reused | 2026-10-28T23:01:09Z |
| miri-b46c3d7057b7174b | tuplehash | miri | tuplehash-staging:490 [extended] | reused | 2026-10-28T16:50:51Z |
| miri-b46fe6d2145bbe53 | tuplehash | miri | scoped_tuplexof128_differential:12:width=1 [extended] | reused | 2026-10-29T00:49:44Z |
| miri-b474c773597b69a0 | sha1 | miri | sha1-padding:57 [routine] | passed | 2026-10-19T11:15:37Z |
| miri-b488a35a388a88ab | tuplehash | miri | tuplehash-staging:251 [extended] | reused | 2026-10-28T21:39:03Z |
| miri-b49abecf8984b2ff | md5 | miri | md5-batch-mask:122 [extended] | reused | 2026-10-28T12:27:36Z |
| miri-b49c6068d3da702e | tuplehash | miri | tuplehash-staging:764 [extended] | reused | 2026-10-28T18:14:48Z |
| miri-b49ebd2b5efe2339 | md5 | miri | md5-scoped:59 [extended] | reused | 2026-10-28T11:51:14Z |
| miri-b49ffde523400977 | md5 | miri | md5-scoped:151 [extended] | reused | 2026-10-28T11:57:29Z |
| miri-b4a355ba31fc50ab | md5 | miri | md5-batch-mask:219 [extended] | reused | 2026-10-28T12:24:42Z |
| miri-b4b63ae351460726 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-faults:2 [extended] | passed | 2026-10-29T15:06:55Z |
| miri-b4b86a3933dff123 | tuplehash | miri | tuplehash-staging:760 [extended] | reused | 2026-10-28T18:13:54Z |
| miri-b4cac28c9d6f0519 | md5 | miri | md5-batch-mask:141 [extended] | reused | 2026-10-28T12:18:23Z |
| miri-b4ccb172590c76fc | kmac | miri | kmac-scoped-lifecycle:11 [routine] | passed | 2026-10-19T11:50:41Z |
| miri-b4d4db424c6ce11e | sha1 | miri | sha1-padding:11 [extended] | reused | 2026-10-28T12:30:27Z |
| miri-b4f22dbfaff2b17e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:19:width=3 [extended] | reused | 2026-10-28T23:03:10Z |
| miri-b4fa9e42d86bd30d | sha1 | miri | sha1-bulk:197 [extended] | reused | 2026-10-28T13:07:56Z |
| miri-b50905280b39ef22 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:50:width=1 [extended] | reused | 2026-10-28T21:27:05Z |
| miri-b5106536ebc41555 | tuplehash | miri | tuplehash-staging:403 [extended] | reused | 2026-10-28T22:29:50Z |
| miri-b51b586aa350a29f | md5 | miri | md5-scoped:150 [extended] | reused | 2026-10-28T12:08:21Z |
| miri-b52a36fb4a40285c | sha3 | miri | -p brynja-hash-sha3 --test bit_inputs curated_nist_cavp_vectors_cover_every_function_and_bit_residue [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-b5516bf704811045 | parallelhash | miri | empty_input_has_zero_leaves_and_b_one_is_valid [extended] | passed | 2026-10-29T15:14:53Z |
| miri-b55614f6ed85b900 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:30:width=3 [extended] | reused | 2026-10-28T22:52:04Z |
| miri-b564cddd03dfbed0 | tuplehash | miri | tuplehash-staging:665 [extended] | reused | 2026-10-28T18:03:35Z |
| miri-b56750c7e9613a4e | sha1 | miri | sha1-bulk:64 [extended] | reused | 2026-10-28T12:43:16Z |
| miri-b573feebdce07bd0 | tuplehash | miri | scoped_tuplexof256_differential:46:width=1 [extended] | reused | 2026-10-29T03:59:12Z |
| miri-b57e7151512382bd | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-official:3 [extended] | passed | 2026-10-29T13:57:44Z |
| miri-b5a09d3e46e818ec | sha1 | miri | sha1-bulk:35 [extended] | reused | 2026-10-28T12:48:23Z |
| miri-b5a256830cfad846 | tuplehash | miri | tuplehash-staging:216 [extended] | reused | 2026-10-28T15:19:19Z |
| miri-b5a914bc6656879b | kmac | miri | kmac-scoped-xof-lifecycle:10 [routine] | passed | 2026-10-19T11:38:25Z |
| miri-b5b009dd1e2df0c6 | tuplehash | miri | tuplehash-staging:529 [extended] | reused | 2026-10-28T17:17:47Z |
| miri-b5bc55ec22fa902a | sha3 | miri | sha3-fixed-boundaries:19 [extended] | reused | 2026-10-28T13:38:46Z |
| miri-b5c9d1d22332194d | sha1 | miri | sha1-bulk:199 [extended] | reused | 2026-10-28T13:03:31Z |
| miri-b5d9af0e2f1254c7 | sha1 | miri | sha1-bulk:55 [extended] | reused | 2026-10-28T12:49:41Z |
| miri-b5f494e5619fcfbd | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:11:width=0 [extended] | reused | 2026-10-28T20:06:05Z |
| miri-b5f8bda5b0295ca5 | md5 | miri | md5-scoped:285 [extended] | reused | 2026-10-28T12:07:21Z |
| miri-b5f98668cc15c238 | tuplehash | miri | -p brynja-hash-tuple --features hardened-execution --test execution [remaining suite; inspect skips with show] | passed | 2026-10-29T10:42:38Z |
| miri-b5fa5862f85a5fde | sha1 | miri | sha1-bulk:208 [extended] | reused | 2026-10-28T12:57:10Z |
| miri-b619979cc445fc13 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:171 [routine] | No mapped observation | — |
| miri-b6407cc1a65bf219 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:6 [routine] | No mapped observation | — |
| miri-b64af4aaae6aac9f | md5 | miri | md5-padding:41 [extended] | reused | 2026-10-28T11:30:36Z |
| miri-b6576ff02ed6def1 | sha1 | miri | sha1-scoped:87 [extended] | reused | 2026-10-28T13:22:05Z |
| miri-b65c211724eca2f7 | md5 | miri | md5-batch-mask:117 [extended] | reused | 2026-10-28T12:16:29Z |
| miri-b65c561d580da18f | md5 | miri | md5-batch-mask:132 [extended] | reused | 2026-10-28T12:22:58Z |
| miri-b664f5c6a06494b7 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:29:width=3 [extended] | reused | 2026-10-29T02:43:39Z |
| miri-b665f3d20f33da09 | md5 | miri | md5-bulk:32 [extended] | reused | 2026-10-28T11:39:35Z |
| miri-b66e8b2cb5101b57 | tuplehash | miri | scoped_tuplexof128_differential:46:width=3 [extended] | reused | 2026-10-29T02:10:19Z |
| miri-b66f1b26e50c13fe | md5 | miri | md5-batch-mask:220 [extended] | reused | 2026-10-28T12:30:01Z |
| miri-b676042b2b2def61 | tuplehash | miri | tuplehash-staging:472 [extended] | reused | 2026-10-28T16:42:09Z |
| miri-b67fef08246d65ab | kmac | miri | kmac-framing:6 [routine] | passed | 2026-10-19T11:40:26Z |
| miri-b68c803d3f4ec5ce | md5 | miri | md5-bulk:25 [extended] | reused | 2026-10-28T11:29:22Z |
| miri-b694744bc439b7cf | tuplehash | miri | tuplehash-staging:171 [extended] | reused | 2026-10-28T21:12:02Z |
| miri-b69b71164397b68d | sha1 | miri | sha1-scoped:199 [extended] | reused | 2026-10-28T13:30:41Z |
| miri-b6b6f596a4640c40 | tuplehash | miri | scoped_tuplexof128_differential:17:width=0 [extended] | passed | 2026-10-29T10:54:23Z |
| miri-b6c0d93334495576 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:18 [routine] | passed | 2026-10-19T12:16:31Z |
| miri-b6ce0308b3ba1eba | md5 | miri | md5-scoped:35 [extended] | reused | 2026-10-28T11:49:39Z |
| miri-b6dc79ed7b7f465b | kmac | miri | kmac-framing:0 [routine] | passed | 2026-10-19T11:31:52Z |
| miri-b6dd88d98c2783bf | tuplehash | miri | scoped_tuplexof256_differential:38:width=3 [extended] | reused | 2026-10-29T03:34:42Z |
| miri-b6eb87985ab6fe0b | tuplehash | miri | tuplehash-staging:23 [extended] | reused | 2026-10-28T20:22:05Z |
| miri-b707c66e6acf24c4 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:10 [routine] | No mapped observation | — |
| miri-b710de3637aab845 | hmac | miri | sha384 [existing-full] | No mapped observation | — |
| miri-b71928decf29dc81 | tuplehash | miri | tuplehash-staging:543 [extended] | reused | 2026-10-28T23:16:40Z |
| miri-b719a68ec317e129 | sha1 | miri | sha1-scoped:181 [extended] | reused | 2026-10-28T13:24:04Z |
| miri-b7365beeb05348d6 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:17:width=1 [extended] | reused | 2026-10-29T02:14:18Z |
| miri-b74b628d37ac4abd | md5 | miri | md5-batch-mask:251 [routine] | passed | 2026-10-19T11:33:20Z |
| miri-b75c64e9269d4d1a | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:228 [extended] | passed | 2026-10-29T13:59:43Z |
| miri-b762ae6b822115bf | tuplehash | miri | tuplehash-staging:101 [extended] | reused | 2026-10-28T14:54:53Z |
| miri-b7759707c368bda4 | tuplehash | miri | tuplehash-staging:100 [extended] | reused | 2026-10-28T14:41:02Z |
| miri-b791468810557b23 | tuplehash | miri | tuplehash-staging:360 [extended] | reused | 2026-10-28T16:06:07Z |
| miri-b79c9b721079000e | md5 | miri | md5-bulk:234 [extended] | reused | 2026-10-28T11:50:51Z |
| miri-b7a9263f6ed4e690 | tuplehash | miri | tuplehash-staging:864 [extended] | reused | 2026-10-28T18:47:31Z |
| miri-b7b165f8222e8e90 | tuplehash | miri | tuplehash-staging:278 [extended] | reused | 2026-10-28T15:42:27Z |
| miri-b7bad933d1e65368 | md5 | miri | md5-padding:75 [extended] | reused | 2026-10-28T11:28:20Z |
| miri-b7bc7a895bd8c2fd | sha3 | miri | sha3-fixed-bits:20 [extended] | reused | 2026-10-28T13:56:31Z |
| miri-b7c35c212176d2db | tuplehash | miri | tuplehash-staging:210 [extended] | reused | 2026-10-28T15:20:20Z |
| miri-b7c431ae02b7394f | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_unwind_reuse:1 [extended] | passed | 2026-10-29T14:03:03Z |
| miri-b7d729982bd8bb4b | tuplehash | miri | scoped_tuplexof128_differential:42:width=0 [extended] | reused | 2026-10-29T01:58:04Z |
| miri-b7d849b58efd8b06 | sha1 | miri | sha1-bulk:192 [routine] | passed | 2026-10-19T11:31:37Z |
| miri-b7dd1b7fb762fbbc | md5 | miri | md5-batch-mask:168 [extended] | reused | 2026-10-28T12:25:47Z |
| miri-b7f22b8cff9f0f4d | sha1 | miri | sha1-scoped:146 [extended] | reused | 2026-10-28T13:13:44Z |
| miri-b7fd56ff30b73865 | tuplehash | miri | tuplehash-staging:579 [extended] | reused | 2026-10-28T23:28:45Z |
| miri-b80a55cd05fa1ff6 | tuplehash | miri | tuplehash-staging:791 [extended] | reused | 2026-10-29T00:40:15Z |
| miri-b8136fe893a04057 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:13:width=2 [extended] | reused | 2026-10-29T04:44:00Z |
| miri-b8156c90090a7d6a | static_cpu | miri | -p brynja-crypto-cpu --features runtime-execution --lib runtime_execution [remaining suite; inspect skips with show] | passed | 2026-10-19T13:55:11Z |
| miri-b81e2b295b70e4f7 | tuplehash | miri | scoped_tuplexof256_differential:19:width=3 [extended] | reused | 2026-10-29T03:40:19Z |
| miri-b81e48c4419fbccb | tuplehash | miri | tuplehash-staging:224 [extended] | reused | 2026-10-28T15:21:32Z |
| miri-b8203d806444f59a | tuplehash | miri | tuplehash-staging:656 [extended] | reused | 2026-10-28T17:40:36Z |
| miri-b8297c42161a98fb | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:4:width=1 [extended] | reused | 2026-10-28T19:33:24Z |
| miri-b839867c80c02d1b | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:18 [extended] | passed | 2026-10-29T13:17:11Z |
| miri-b83c5264d45ab420 | tuplehash | miri | scoped_tuplexof128_differential:45 [routine] | passed | 2026-10-19T16:16:17Z |
| miri-b8451f6b38575f2d | tuplehash | miri | scoped_tuplexof128_differential:47:width=1 [extended] | reused | 2026-10-29T03:02:30Z |
| miri-b84573ee35a319a9 | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join128:2 [routine] | No mapped observation | — |
| miri-b857ae815f33c32d | kmac | miri | kmac-streamed-setup:30 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-b85bef21dacd012c | md5 | miri | md5-batch-mask:102 [extended] | reused | 2026-10-28T12:25:59Z |
| miri-b85e103ce2fc055e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:33:width=1 [extended] | reused | 2026-10-29T02:53:27Z |
| miri-b871630569b21775 | sha1 | miri | sha1-padding:120 [routine] | passed | 2026-10-19T11:28:57Z |
| miri-b875d9c07695c23b | tuplehash | miri | tuplehash-staging:40 [extended] | reused | 2026-10-28T14:21:26Z |
| miri-b875ebb115dfb152 | tuplehash | miri | tuplehash-staging:396 [extended] | reused | 2026-10-28T16:17:25Z |
| miri-b87e22a4ff775080 | tuplehash | miri | scoped_tuplexof128_differential:34:width=0 [extended] | reused | 2026-10-29T01:36:07Z |
| miri-b883ed9964f16f1d | kmac | miri | kmac-streamed-setup:76 [routine] | No mapped observation | — |
| miri-b892a0b9d8c15fb0 | md5 | miri | md5-bulk:139 [extended] | reused | 2026-10-28T11:37:46Z |
| miri-b8b5eb194b7bd320 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:3:width=4 [extended] | reused | 2026-10-28T19:52:05Z |
| miri-b8e1a2e9f337e459 | tuplehash | miri | tuplehash-staging:280 [extended] | reused | 2026-10-28T15:39:45Z |
| miri-b8e2adad19a31fb5 | tuplehash | miri | tuplehash-staging:788 [extended] | reused | 2026-10-28T18:22:53Z |
| miri-b8e6b92eeadae004 | tuplehash | miri | tuplehash-staging:199 [extended] | reused | 2026-10-28T21:21:28Z |
| miri-b8f520a3785d1972 | tuplehash | miri | tuplehash-staging:809 [extended] | reused | 2026-10-28T18:52:05Z |
| miri-b908435f364a25f0 | md5 | miri | md5-padding:1 [extended] | reused | 2026-10-28T11:27:56Z |
| miri-b918ac3cd3df3e7c | tuplehash | miri | scoped_tuplexof128_differential:43:width=4 [extended] | reused | 2026-10-29T02:49:54Z |
| miri-b921457b5714b5e1 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:51:width=4 [extended] | reused | 2026-10-28T22:01:22Z |
| miri-b925e15830f66d81 | hmac | miri | sha256 [existing-full] | No mapped observation | — |
| miri-b940281164b4117f | tuplehash | miri | tuplehash-staging:364 [extended] | reused | 2026-10-28T16:07:02Z |
| miri-b95808298bcf636c | tuplehash | miri | tuplehash-staging:118 [extended] | reused | 2026-10-28T14:50:42Z |
| miri-b958bc89fdc6bcd6 | md5 | miri | md5-batch-mask:60 [extended] | reused | 2026-10-28T12:17:28Z |
| miri-b96b04287507cb46 | md5 | miri | md5-bulk:134 [extended] | reused | 2026-10-28T11:42:06Z |
| miri-b96b0bdbf1fe9149 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:25:width=1 [extended] | reused | 2026-10-29T05:13:15Z |
| miri-b97c61c7b8f584f6 | md5 | miri | md5-scoped:186 [extended] | reused | 2026-10-28T12:10:55Z |
| miri-b9801f91050a8fb7 | sha3 | miri | -p brynja-hash-sha3 --features hardened-execution --lib hardened::accelerated::engine::tests::every_memory_region_is_explicitly_cleared [remaining suite; inspect skips with show] | reused | 2026-10-28T13:34:57Z |
| miri-b9808827d8684899 | tuplehash | miri | tuplehash-staging:147 [extended] | reused | 2026-10-28T21:03:33Z |
| miri-b98f7a8734e325c8 | tuplehash | miri | scoped_tuplexof256_differential:43:width=2 [extended] | reused | 2026-10-29T04:41:29Z |
| miri-b994ca3c5b396c11 | md5 | miri | md5-padding:55 [routine] | passed | 2026-10-19T11:31:54Z |
| miri-b9d59bfa9877e506 | md5 | miri | md5-scoped:124 [extended] | reused | 2026-10-28T12:01:25Z |
| miri-b9d644e6f418b54a | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:51:width=1 [extended] | reused | 2026-10-29T00:43:55Z |
| miri-b9e2641691249bef | hmac | miri | sha224 [extended] | passed | 2026-10-29T15:16:48Z |
| miri-b9f0bcf92b25ac03 | tuplehash | miri | scoped_tuplexof256_differential:28:width=0 [extended] | reused | 2026-10-29T03:16:23Z |
| miri-ba14bed1601f9637 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:23:width=4 [extended] | reused | 2026-10-28T23:12:58Z |
| miri-ba1d0d6451bb7b02 | tuplehash | miri | tuplehash-staging:583 [extended] | reused | 2026-10-28T23:30:06Z |
| miri-ba23acf2db0dfdee | md5 | miri | md5-scoped:10 [extended] | reused | 2026-10-28T11:58:44Z |
| miri-ba2932e8f0254556 | tuplehash | miri | tuplehash-staging:825 [extended] | reused | 2026-10-28T18:57:52Z |
| miri-ba33ef955cb6fece | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:27 [extended] | passed | 2026-10-29T13:11:04Z |
| miri-ba3abd5c7d32d7e9 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:18:width=1 [extended] | reused | 2026-10-28T22:24:48Z |
| miri-ba3cf2d0eb4c0609 | parallelhash | miri | [bounded-parallelhash-v1] parallelhashxof-official:5 [routine] | No mapped observation | — |
| miri-ba4b2e901cd025da | md5 | miri | md5-scoped:220 [extended] | reused | 2026-10-28T12:08:03Z |
| miri-ba634bfcf675ac0e | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:42:width=3 [extended] | reused | 2026-10-28T20:52:59Z |
| miri-ba666965921c1c4c | sha1 | miri | sha1-bulk:43 [extended] | reused | 2026-10-28T12:48:53Z |
| miri-ba66a4b7434afdf7 | md5 | miri | md5-padding:66 [extended] | reused | 2026-10-28T11:22:48Z |
| miri-ba67a98276de3f2d | md5 | miri | md5-batch-mask:252 [extended] | reused | 2026-10-28T12:32:45Z |
| miri-ba6f0c2b22cbf68c | tuplehash | miri | tuplehash-staging:577 [extended] | reused | 2026-10-28T17:34:21Z |
| miri-ba7a11949338634f | md5 | miri | md5-batch-mask:45 [extended] | reused | 2026-10-28T12:10:51Z |
| miri-ba7f456069dfae36 | md5 | miri | md5-bulk:149 [extended] | reused | 2026-10-28T11:38:16Z |
| miri-ba9070d4779a3c79 | sha1 | miri | sha1-bulk:79 [extended] | reused | 2026-10-28T12:51:33Z |
| miri-bab0a7eb9ac8342f | tuplehash | miri | tuplehash-staging:528 [extended] | reused | 2026-10-28T16:59:53Z |
| miri-bab6805ed4ad5a10 | tuplehash | miri | scoped_tuplexof128_differential:1:width=0 [extended] | reused | 2026-10-29T07:08:40Z |
| miri-bacd31b06ee8bfe6 | tuplehash | miri | scoped_tuplexof256_differential:37:width=3 [extended] | passed | 2026-10-29T12:12:10Z |
| miri-bae369e7d0a4b0f2 | sha3 | miri | -p brynja-hash-sha3 --test hardened [remaining suite; inspect skips with show] | reused | 2026-10-28T13:36:05Z |
| miri-bae5126e092fcbf4 | md5 | miri | md5-bulk:4 [extended] | reused | 2026-10-28T11:37:45Z |
| miri-bae7151c8343d523 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:4:width=2 [extended] | reused | 2026-10-28T22:02:53Z |
| miri-baf9b5197442f2a9 | sha1 | miri | -p brynja-legacy-sha1 --features cpu --lib quarantined_model_clears_all_regions_without_instructions [remaining suite; inspect skips with show] | passed | 2026-10-19T11:15:20Z |
| miri-bb09c541c05c033c | tuplehash | miri | tuplehash-staging:208 [extended] | reused | 2026-10-28T15:16:20Z |
| miri-bb10179e27c32341 | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join256:1 [extended] | passed | 2026-10-29T14:18:48Z |
| miri-bb117d341606be42 | md5 | miri | md5-bulk:76 [extended] | reused | 2026-10-28T11:42:37Z |
| miri-bb3042e5767ee664 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:24:width=4 [extended] | reused | 2026-10-28T20:14:03Z |
| miri-bb3869eee68a756f | tuplehash | miri | tuplehash-staging:550 [extended] | reused | 2026-10-28T17:10:02Z |
| miri-bb491b0cd5ae0a49 | kmac | miri | kmac-framing:5 [routine] | passed | 2026-10-19T15:29:01Z |
| miri-bb49b185bea86c18 | sha3 | miri | every_fixed_identity_matches_the_ordinary_algorithm [extended] | reused | 2026-10-28T13:50:56Z |
| miri-bb4ffc9fd404a10f | sha1 | miri | sha1-scoped:183 [routine] | passed | 2026-10-19T11:32:09Z |
| miri-bb5170a67d676b2b | sha1 | miri | sha1-bulk:114 [extended] | reused | 2026-10-28T12:49:06Z |
| miri-bb5357f971e9d6f2 | tuplehash | miri | scoped_tuplexof128_differential:36:width=3 [extended] | reused | 2026-10-29T01:46:32Z |
| miri-bb53c5f72231c39a | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:5:width=2 [extended] | reused | 2026-10-29T01:50:26Z |
| miri-bb603a11743608f7 | tuplehash | miri | scoped_tuplexof128_differential:14:width=2 [extended] | reused | 2026-10-29T00:48:52Z |
| miri-bb6f969cff997dee | kmac | miri | kmac-streamed-setup:18 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-bb7530d47bc7e987 | sha1 | miri | sha1-scoped:163 [extended] | reused | 2026-10-28T13:27:52Z |
| miri-bb7a3d5f1b2ce536 | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib batch_metadata_and_public_admission [remaining suite; inspect skips with show] | passed | 2026-10-29T16:05:36Z |
| miri-bb82cb78d35e7dba | sha3 | miri | sha3-fixed-bits:21 [extended] | reused | 2026-10-28T13:43:33Z |
| miri-bb8e0ec25a12a3ae | md5 | miri | md5-batch-mask:255 [routine] | passed | 2026-10-19T11:27:18Z |
| miri-bb9ad0356dddf6b9 | md5 | miri | md5-bulk:140 [extended] | reused | 2026-10-28T11:47:31Z |
| miri-bbaf4f04730dccb3 | sha1 | miri | sha1-scoped:54 [extended] | reused | 2026-10-28T13:06:39Z |
| miri-bbb336e59f09a79d | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:14:width=1 [extended] | reused | 2026-10-28T19:46:05Z |
| miri-bbcf681fd5b00837 | md5 | miri | md5-batch-mask:0 [routine] | passed | 2026-10-19T11:32:54Z |
| miri-bbd0c31d51c9fd51 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:41:width=4 [extended] | reused | 2026-10-29T05:55:08Z |
| miri-bbd6b63c22a9c1a3 | md5 | miri | md5-scoped:238 [extended] | reused | 2026-10-28T12:14:40Z |
| miri-bbd970f28a4c683a | tuplehash | miri | tuplehash-staging:376 [extended] | reused | 2026-10-28T16:10:57Z |
| miri-bbea4b5ced05e7b1 | sha1 | miri | sha1-bulk:142 [extended] | reused | 2026-10-28T12:51:40Z |
| miri-bc1305f1f1b4d44f | md5 | miri | md5-padding:6 [extended] | reused | 2026-10-28T11:18:15Z |
| miri-bc16b4cec37b919d | md5 | miri | md5-scoped:39 [extended] | reused | 2026-10-28T11:49:55Z |
| miri-bc30cac9bcb5348d | kmac | miri | kmac-streamed-setup:54 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-bc30d1f4bb74bc68 | md5 | miri | md5-bulk:181 [extended] | reused | 2026-10-28T11:40:46Z |
| miri-bc3426b0ac9782b6 | kmac | miri | kmac-streamed-setup:80 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-bc42c9ee604ee032 | sha2 | miri | -p brynja-hash-sha2 --features general-sha512-t --test general_hash --lib dynamic_lifecycle_ [remaining suite; inspect skips with show] | reused | 2026-10-28T13:27:45Z |
| miri-bc5ae459a37e0b40 | tuplehash | miri | scoped_tuplexof256_differential:27:width=2 [extended] | reused | 2026-10-29T03:59:46Z |
| miri-bc6372271f491142 | tuplehash | miri | scoped_tuplexof256_differential:22:width=2 [extended] | reused | 2026-10-29T02:56:47Z |
| miri-bc6dee7b6ac8822a | sha1 | miri | sha1-bulk:183 [extended] | reused | 2026-10-28T13:01:42Z |
| miri-bc7b0031ca748e22 | tuplehash | miri | tuplehash-staging:860 [extended] | reused | 2026-10-28T18:46:14Z |
| miri-bc7e64b4748319ae | md5 | miri | md5-bulk:232 [extended] | reused | 2026-10-28T11:55:35Z |
| miri-bc890744ff17e284 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:33:width=4 [extended] | reused | 2026-10-29T02:53:27Z |
| miri-bc902644b9341781 | md5 | miri | md5-bulk:185 [extended] | reused | 2026-10-28T11:41:05Z |
| miri-bc9cfe32f93e1d13 | tuplehash | miri | tuplehash-staging:73 [extended] | reused | 2026-10-28T14:45:29Z |
| miri-bc9e42373c9b913a | tuplehash | miri | scoped_tuplexof256_differential:1:width=1 [extended] | passed | 2026-10-29T11:53:17Z |
| miri-bcc378e31ea6f95a | parallelhash | miri | reordered_leaf_permanently_fails_closed [extended] | passed | 2026-10-29T15:00:41Z |
| miri-bd0d3ff4724fc5fc | tuplehash | miri | tuplehash-staging:464 [extended] | reused | 2026-10-28T16:39:20Z |
| miri-bd0f105bf4ba8601 | tuplehash | miri | scoped_tuplexof128_differential:5:width=0 [extended] | reused | 2026-10-29T07:15:40Z |
| miri-bd133554cd9edaac | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:15 [routine] | No mapped observation | — |
| miri-bd13ad14128d60ec | tuplehash | miri | tuplehash-staging:75 [extended] | reused | 2026-10-28T20:39:18Z |
| miri-bd1bc78289bb67d0 | sha1 | miri | sha1-scoped:7 [extended] | reused | 2026-10-28T13:16:16Z |
| miri-bd36c9c4b9eac9cc | tuplehash | miri | scoped_tuplexof128_differential:23:width=2 [extended] | reused | 2026-10-29T01:58:09Z |
| miri-bd4300b8801ed7d6 | sha2 | miri | -p brynja-hash-sha2 --features general-sha512-t --test general_hash unwind_clears_secret_destination [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-bd4d652b4d0893a1 | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join128:3 [extended] | passed | 2026-10-29T14:18:18Z |
| miri-bd58376caea1d80e | tuplehash | miri | tuplehash-staging:369 [extended] | reused | 2026-10-28T16:24:27Z |
| miri-bd648627afc289d0 | md5 | miri | md5-bulk:169 [extended] | reused | 2026-10-28T11:39:50Z |
| miri-bd6b2c73fc98f729 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:1 [routine] | No mapped observation | — |
| miri-bd744b3bc2034a84 | sha1 | miri | sha1-bulk:31 [routine] | passed | 2026-10-19T11:31:08Z |
| miri-bd8d52f2e2e2f0f7 | md5 | miri | md5-bulk:156 [extended] | reused | 2026-10-28T11:48:50Z |
| miri-bd916f5103453136 | kmac | miri | kmac-streamed-setup:15 [routine] | No mapped observation | — |
| miri-bd9bb63945e915a6 | md5 | miri | md5-scoped:7 [extended] | reused | 2026-10-28T11:47:49Z |
| miri-bda672399eabd671 | sha1 | miri | sha1-scoped:175 [extended] | reused | 2026-10-28T13:28:47Z |
| miri-bdb248af7a0d9d38 | sha3 | miri | sha3-secret-xof-bits:5 [routine] | passed | 2026-10-19T11:36:39Z |
| miri-bdcda63071fcdcf8 | kmac | miri | kmac-official:4 [routine] | passed | 2026-10-19T11:47:37Z |
| miri-bdcde1c5416e8990 | parallelhash | miri | equal_shape_cross_plan_result_permanently_fails_closed [routine] | passed | 2026-10-19T13:58:53Z |
| miri-bdd17b211913b7f6 | kmac | miri | kmac-streamed-setup:97 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-bdd240381afe8ac9 | tuplehash | miri | tuplehash-staging:202 [extended] | reused | 2026-10-28T15:18:07Z |
| miri-bdf5f9a37266f497 | md5 | miri | md5-bulk:97 [extended] | reused | 2026-10-28T11:34:19Z |
| miri-be0f62d78b55e494 | tuplehash | miri | scoped_tuplexof256_differential:27:width=4 [extended] | reused | 2026-10-29T03:59:46Z |
| miri-be1300e65665c109 | sha1 | miri | sha1-scoped:228 [extended] | reused | 2026-10-28T13:21:57Z |
| miri-be1455d85191e8c2 | kmac | miri | kmac-scoped-xof-lifecycle:11 [routine] | passed | 2026-10-19T15:35:26Z |
| miri-be17ef86abbeace2 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:27 [routine] | No mapped observation | — |
| miri-be1e21edd38dad0a | sha3 | miri | sha3-fixed-boundaries:71 [extended] | reused | 2026-10-28T13:46:42Z |
| miri-be248dbba389378d | sha1 | miri | sha1-scoped:194 [extended] | reused | 2026-10-28T13:17:37Z |
| miri-be2a75cb739d9f17 | sha1 | miri | sha1-bulk:185 [extended] | reused | 2026-10-28T13:06:32Z |
| miri-be316eef17301955 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:8:width=4 [extended] | reused | 2026-10-28T22:09:27Z |
| miri-be35ddd89998ff86 | tuplehash | miri | scoped_tuplexof128_differential:9:width=4 [extended] | passed | 2026-10-29T10:50:53Z |
| miri-be45a8fea8f05e3c | sha3 | miri | sha3-fixed-boundaries:62 [extended] | reused | 2026-10-28T13:44:31Z |
| miri-be547ce73a664f0c | tuplehash | miri | tuplehash-staging:310 [extended] | reused | 2026-10-28T15:52:52Z |
| miri-be732c02ac63013c | sha1 | miri | sha1-scoped:272 [extended] | reused | 2026-10-28T13:25:33Z |
| miri-be7a238cff181dc4 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:3:width=1 [extended] | reused | 2026-10-28T22:32:17Z |
| miri-be90ba3fd1853f37 | md5 | miri | md5-scoped:272 [extended] | reused | 2026-10-28T12:11:53Z |
| miri-be9411870ea2b7e8 | sha1 | miri | sha1-scoped:94 [extended] | reused | 2026-10-28T13:09:35Z |
| miri-bebd02820236b3f2 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:10:width=0 [extended] | reused | 2026-10-28T22:09:09Z |
| miri-bec229772f2d9c0f | parallelhash | miri | -p brynja-hash-parallel --features hardened-execution --test execution_stream [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-bec3931a6ef42449 | tuplehash | miri | tuplehash-staging:121 [extended] | reused | 2026-10-28T15:01:13Z |
| miri-bec5307e2bfbeaec | sha2 | miri | -p brynja-hash-sha2 --features general-sha512-t --test general bounded_public_api_smoke [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-bed43b7fe91e7786 | sha1 | miri | sha1-scoped:122 [extended] | reused | 2026-10-28T13:11:48Z |
| miri-beda8a905d378eba | kmac | miri | kmac-official:0 [extended] | reused | 2026-10-28T14:00:19Z |
| miri-bedb362747fec561 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:6:width=4 [extended] | reused | 2026-10-28T22:02:39Z |
| miri-bee45edffa8c275a | md5 | miri | md5-batch-mask:67 [extended] | reused | 2026-10-28T12:12:21Z |
| miri-beef89683ff3b99b | md5 | miri | md5-bulk:92 [extended] | reused | 2026-10-28T11:43:48Z |
| miri-bef0e647f6f70168 | tuplehash | miri | tuplehash-staging:755 [extended] | reused | 2026-10-29T00:28:30Z |
| miri-bf24389bf415da5f | kmac | miri | kmac-streamed-setup:8 [routine] | No mapped observation | — |
| miri-bf32614d420f3013 | tuplehash | miri | tuplehash-staging:585 [extended] | reused | 2026-10-28T17:36:39Z |
| miri-bf32b8a021b031e7 | tuplehash | miri | scoped_tuplexof256_differential:24:width=3 [extended] | reused | 2026-10-29T03:06:57Z |
| miri-bf39e29d37b23834 | md5 | miri | md5-bulk:98 [extended] | reused | 2026-10-28T11:39:15Z |
| miri-bf3e1c556f9b8f3c | tuplehash | miri | scoped_tuplexof128_differential:29:width=3 [extended] | passed | 2026-10-29T11:00:45Z |
| miri-bf414c60c34ecf1b | kmac | miri | kmac-streamed-setup:99 [routine] | No mapped observation | — |
| miri-bf4d37cbfef824f2 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:10:width=3 [extended] | reused | 2026-10-28T19:39:30Z |
| miri-bf51516b5d06531c | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:27:width=4 [extended] | reused | 2026-10-28T23:22:47Z |
| miri-bf69688c24ebcd44 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:564 [extended] | passed | 2026-10-29T14:04:41Z |
| miri-bf7cdeefd081ebf0 | sha2 | miri | -p brynja-hash-sha2 --features general-sha512-t --test general_hash --lib dynamic_lifecycle_ [remaining suite; inspect skips with show] | passed | 2026-10-19T11:30:29Z |
| miri-bf8214de7ab5efd2 | md5 | miri | md5-scoped:108 [routine] | passed | 2026-10-19T11:32:46Z |
| miri-bf847340929b249e | tuplehash | miri | tuplehash-staging:413 [extended] | reused | 2026-10-28T16:39:15Z |
| miri-bf8c620358c93104 | md5 | miri | md5-padding:85 [extended] | reused | 2026-10-28T11:33:56Z |
| miri-bfa1ef098cb03241 | tuplehash | miri | tuplehash-staging:736 [extended] | reused | 2026-10-28T18:05:49Z |
| miri-bfaba788f6c6c534 | tuplehash | miri | tuplehash-staging:2 [extended] | reused | 2026-10-28T14:12:40Z |
| miri-bfb8d2b2585d66ec | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:11:width=4 [extended] | reused | 2026-10-28T20:06:05Z |
| miri-bfc34302af57a80e | tuplehash | miri | tuplehash-staging:641 [extended] | reused | 2026-10-28T17:55:31Z |
| miri-bfc511f328e37746 | sha1 | miri | sha1-padding:101 [extended] | reused | 2026-10-28T12:36:36Z |
| miri-bfd8b2ce587a2f1f | md5 | miri | md5-scoped:141 [extended] | reused | 2026-10-28T11:57:04Z |
| miri-bff4ad170032e010 | md5 | miri | md5-padding:120 [routine] | passed | 2026-10-19T11:32:09Z |
| miri-bff821e40b2007de | tuplehash | miri | tuplehash-staging:587 [extended] | reused | 2026-10-28T23:31:50Z |
| miri-bffc9b0b9c134d30 | sha1 | miri | -p brynja-legacy-sha1 --features hardened-execution --test hardened_execution revocation_cancellation_and_output_failures [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-bfff6e0cda8f6081 | tuplehash | miri | arbitrary_bit_items_and_outputs_are_canonical [extended] | reused | 2026-10-29T05:00:22Z |
| miri-c001393238200704 | md5 | miri | md5-scoped:162 [extended] | reused | 2026-10-28T12:09:12Z |
| miri-c004ebd4f855a40b | kmac | miri | kmac-scoped-lifecycle:0 [extended] | reused | 2026-10-28T13:54:44Z |
| miri-c00ef72c4d513429 | tuplehash | miri | tuplehash-staging:790 [extended] | reused | 2026-10-28T18:27:15Z |
| miri-c032ec4ce3cecc2d | md5 | miri | md5-bulk:101 [extended] | reused | 2026-10-28T11:34:36Z |
| miri-c03be00c70b18d19 | tuplehash | miri | tuplehash-staging:178 [extended] | reused | 2026-10-28T15:10:23Z |
| miri-c048d2a77948dcaa | md5 | miri | md5-scoped:15 [extended] | reused | 2026-10-28T11:48:20Z |
| miri-c04ae1c2b8f129fc | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:35:width=1 [extended] | reused | 2026-10-28T21:02:20Z |
| miri-c054017fc2131b15 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:9:width=4 [extended] | reused | 2026-10-29T01:57:28Z |
| miri-c05b2b485e9e3366 | tuplehash | miri | tuplehash-staging:785 [extended] | reused | 2026-10-28T18:43:37Z |
| miri-c0690f320d5d525a | tuplehash | miri | tuplehash-staging:193 [extended] | reused | 2026-10-28T15:25:27Z |
| miri-c07910a98122bd27 | tuplehash | miri | tuplehash-staging:468 [extended] | reused | 2026-10-28T16:40:54Z |
| miri-c0a4f864debd15f4 | parallelhash | miri | -p brynja-hash-parallel --features hardened-execution --test execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-c0b66ec7c9e077a1 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:30 [routine] | No mapped observation | — |
| miri-c0bd1276c7583a87 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:5 [extended] | passed | 2026-10-29T14:09:31Z |
| miri-c0be78761d47d501 | tuplehash | miri | tuplehash-execution-fixed:15 [routine] | passed | 2026-10-19T16:08:12Z |
| miri-c0bedaf3dad52e90 | tuplehash | miri | tuplehash-staging:359 [extended] | reused | 2026-10-28T22:15:01Z |
| miri-c0d688d77bb4ed31 | kmac | miri | kmac-streamed-setup:92 [routine] | No mapped observation | — |
| miri-c0fc22e4b029a7b5 | sha1 | miri | sha1-bulk:212 [extended] | reused | 2026-10-28T12:57:37Z |
| miri-c117838b090e7537 | md5 | miri | md5-batch-mask:58 [extended] | reused | 2026-10-28T12:22:34Z |
| miri-c1198f64b8b18adf | tuplehash | miri | tuplehash-staging:52 [extended] | reused | 2026-10-28T14:25:38Z |
| miri-c1206802fff9b9bd | tuplehash | miri | tuplehash-staging:259 [extended] | reused | 2026-10-28T21:41:21Z |
| miri-c126465f2c382e2a | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join128:2 [extended] | passed | 2026-10-29T15:05:45Z |
| miri-c12a62238ff4805a | kmac | miri | kmac-streamed-setup:0 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-c12b5436985604c5 | tuplehash | miri | scoped_tuplexof128_differential:4:width=2 [extended] | reused | 2026-10-29T00:36:36Z |
| miri-c14e8eff32aeed4e | hmac | miri | -p brynja-crypto-cpu-std --features strict-hmac-acceleration --lib strict_hmac [remaining suite; inspect skips with show] | passed | 2026-10-29T15:08:15Z |
| miri-c14ef2abc6889cf6 | tuplehash | miri | tuplehash-staging:335 [extended] | reused | 2026-10-28T22:07:22Z |
| miri-c152b1a1f00d55f5 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:48:width=4 [extended] | reused | 2026-10-28T21:27:32Z |
| miri-c1770a3bcc6e8667 | md5 | miri | md5-scoped:241 [extended] | reused | 2026-10-28T12:04:11Z |
| miri-c17a8328d55970a0 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:43:width=2 [extended] | reused | 2026-10-29T00:04:50Z |
| miri-c17bfa9b072037c1 | md5 | miri | -p brynja-legacy-md5 --features cpu --test cpu [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-c17d4a4e47c9086d | sha2 | miri | -p brynja-hash-sha2 --test sha256 padding_boundaries_have_exact_digests [remaining suite; inspect skips with show] | passed | 2026-10-19T11:36:04Z |
| miri-c185c8f58c291e5f | tuplehash | miri | tuplehash-staging:148 [extended] | reused | 2026-10-28T14:56:23Z |
| miri-c1b64c755a03157f | md5 | miri | md5-batch-mask:151 [extended] | reused | 2026-10-28T12:19:04Z |
| miri-c1f40bd2347e15cd | md5 | miri | md5-scoped:184 [extended] | reused | 2026-10-28T12:05:32Z |
| miri-c1fa6c714442c121 | sha1 | miri | sha1-scoped:242 [extended] | reused | 2026-10-28T13:21:31Z |
| miri-c208469d09884016 | md5 | miri | md5-batch-mask:96 [extended] | reused | 2026-10-28T12:20:09Z |
| miri-c20b0158f5989b7b | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-faults:1 [routine] | No mapped observation | — |
| miri-c21e238fcd58ce9b | sha1 | miri | sha1-padding:71 [extended] | reused | 2026-10-28T12:35:15Z |
| miri-c221317dd78c57cb | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:35:width=4 [extended] | reused | 2026-10-28T21:02:20Z |
| miri-c222e0aa0c9fa50e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:13:width=4 [extended] | reused | 2026-10-29T04:44:00Z |
| miri-c22646f04473f557 | tuplehash | miri | tuplehash-staging:439 [extended] | reused | 2026-10-28T22:42:03Z |
| miri-c230a6ae7dd44b4d | tuplehash | miri | scoped_tuplexof256_differential:41:width=3 [extended] | passed | 2026-10-29T12:26:49Z |
| miri-c24134d788b9a752 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:24:width=2 [extended] | reused | 2026-10-28T20:14:03Z |
| miri-c266f5fe845a0c15 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:52:width=1 [extended] | reused | 2026-10-28T21:49:46Z |
| miri-c270e1627b83a9b0 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:35:width=2 [extended] | reused | 2026-10-28T21:02:20Z |
| miri-c2725b41061c6297 | sha1 | miri | sha1-scoped:55 [extended] | reused | 2026-10-28T13:19:43Z |
| miri-c28b04d59c5da65d | md5 | miri | md5-batch-mask:51 [extended] | reused | 2026-10-28T12:11:06Z |
| miri-c28c575c35464eaa | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:13:width=4 [extended] | reused | 2026-10-29T02:04:31Z |
| miri-c29b62f8bc3680a0 | sha1 | miri | sha1-scoped:147 [extended] | reused | 2026-10-28T13:26:39Z |
| miri-c2a3bf48fe72f73a | sha1 | miri | sha1-scoped:19 [extended] | reused | 2026-10-28T13:17:10Z |
| miri-c2d9c2fb628a4069 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:64 [routine] | No mapped observation | — |
| miri-c2dcbd6c68ce3225 | md5 | miri | md5-batch-mask:162 [extended] | reused | 2026-10-28T12:30:45Z |
| miri-c2f094be0210ad09 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:51:width=0 [extended] | reused | 2026-10-29T00:43:55Z |
| miri-c2fde44c570d596d | md5 | miri | md5-scoped:171 [extended] | reused | 2026-10-28T11:58:50Z |
| miri-c30eb385e2cabda8 | kmac | miri | kmac-streamed-setup:7 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-c3108298f03e575f | md5 | miri | md5-scoped:226 [extended] | reused | 2026-10-28T12:13:50Z |
| miri-c31eef3def536d19 | tuplehash | miri | tuplehash-staging:651 [extended] | reused | 2026-10-28T23:53:01Z |
| miri-c34313f0e4f207b0 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:6:width=2 [extended] | reused | 2026-10-28T22:02:39Z |
| miri-c34fb96597115b54 | kmac | miri | kmac-streamed-setup:6 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-c356c9d508fb0175 | sha1 | miri | sha1-scoped:287 [extended] | reused | 2026-10-28T13:37:59Z |
| miri-c35de9ecc17cd1d7 | md5 | miri | md5-scoped:80 [extended] | reused | 2026-10-28T11:58:20Z |
| miri-c36e2020cd189bc6 | md5 | miri | md5-scoped:200 [extended] | reused | 2026-10-28T12:06:39Z |
| miri-c387da8a52c7710c | md5 | miri | md5-batch-mask:25 [extended] | reused | 2026-10-28T12:09:19Z |
| miri-c38824b14600e161 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:21:width=0 [extended] | reused | 2026-10-29T02:24:05Z |
| miri-c3900c16b446a40f | tuplehash | miri | scoped_tuplexof128_differential:37:width=1 [extended] | passed | 2026-10-29T11:03:54Z |
| miri-c3903d8fe86f33bf | tuplehash | miri | tuplehash-staging:109 [extended] | reused | 2026-10-28T14:57:11Z |
| miri-c39f07239a8107b4 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:8 [extended] | passed | 2026-10-29T14:07:41Z |
| miri-c3a298c9a8ee43db | tuplehash | miri | tuplehash-staging:712 [extended] | reused | 2026-10-28T17:58:29Z |
| miri-c3cac4cb31f937c6 | sha1 | miri | sha1-bulk:44 [extended] | reused | 2026-10-28T12:41:53Z |
| miri-c3cb08f29a19af76 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:30:width=1 [extended] | reused | 2026-10-28T20:22:51Z |
| miri-c3d01b003967a28f | md5 | miri | md5-scoped:185 [extended] | reused | 2026-10-28T12:00:05Z |
| miri-c3df232477541bb5 | tuplehash | miri | scoped_tuplexof256_differential:10:width=3 [extended] | reused | 2026-10-29T02:30:56Z |
| miri-c3f030ae0ea6455a | sha3 | miri | sha3-fixed-bits:17 [extended] | reused | 2026-10-28T13:43:09Z |
| miri-c41d6a31cd7c7bb6 | md5 | miri | md5-bulk:221 [extended] | reused | 2026-10-28T11:44:06Z |
| miri-c43b9729086c1111 | sha1 | miri | -p brynja-legacy-sha1 --features hardened-execution --lib hardened_execution::stream::tests [remaining suite; inspect skips with show] | reused | 2026-10-28T12:33:01Z |
| miri-c45069f4adb95f01 | md5 | miri | md5-scoped:73 [extended] | reused | 2026-10-28T11:52:25Z |
| miri-c450ae314dcbac32 | tuplehash | miri | tuplehash-staging:814 [extended] | reused | 2026-10-28T18:34:33Z |
| miri-c45b515f684e7334 | md5 | miri | md5-scoped:24 [extended] | reused | 2026-10-28T11:54:34Z |
| miri-c45f70d3a476c850 | sha1 | miri | sha1-scoped:78 [extended] | reused | 2026-10-28T13:08:23Z |
| miri-c460b2b2efdd1bfa | sha3 | miri | sha3-fixed-boundaries:15 [extended] | reused | 2026-10-28T13:38:22Z |
| miri-c4894916a1544b05 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:19:width=2 [extended] | reused | 2026-10-28T23:03:10Z |
| miri-c48a3ac35e54533d | tuplehash | miri | tuplehash-staging:295 [extended] | reused | 2026-10-28T21:53:06Z |
| miri-c4961b9d1df4bfe9 | md5 | miri | md5-padding:67 [extended] | reused | 2026-10-28T11:27:44Z |
| miri-c4ada3c9e6100f67 | sha1 | miri | sha1-padding:120 [extended] | reused | 2026-10-28T12:45:12Z |
| miri-c4afbf9559cb5eaa | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:27 [extended] | passed | 2026-10-29T13:18:33Z |
| miri-c4b67c2f36d0dd3c | tuplehash | miri | scoped_tuplexof128_differential:16:width=1 [extended] | reused | 2026-10-29T00:58:58Z |
| miri-c4c93c61d5047453 | hmac | miri | sha3_256 [extended] | passed | 2026-10-29T15:05:13Z |
| miri-c4c9cc04b866e751 | kmac | miri | kmac-streamed-setup:77 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-c4e664157f86ef49 | tuplehash | miri | tuplehash-staging:204 [extended] | reused | 2026-10-28T15:14:40Z |
| miri-c4ecf74506cd4838 | tuplehash | miri | tuplehash-staging:247 [extended] | reused | 2026-10-28T21:37:18Z |
| miri-c512a2b3177e6b6a | tuplehash | miri | scoped_tuplexof128_differential:47:width=0 [extended] | reused | 2026-10-29T03:02:30Z |
| miri-c514b2b6af074726 | sha1 | miri | sha1-bulk:247 [extended] | reused | 2026-10-28T13:09:31Z |
| miri-c5182bafdf82caed | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:21:width=0 [extended] | reused | 2026-10-29T05:03:33Z |
| miri-c522da707e737440 | md5 | miri | md5-batch-mask:206 [extended] | reused | 2026-10-28T12:34:23Z |
| miri-c533fa1e617e0a20 | tuplehash | miri | tuplehash-staging:411 [extended] | reused | 2026-10-28T22:32:32Z |
| miri-c53b346dd972d395 | legacy | miri | --manifest-path assurance/legacy-hash-final/Cargo.toml --no-default-features --lib dynamic_ [remaining suite; inspect skips with show] | passed | 2026-10-19T13:58:59Z |
| miri-c54b2430126a21aa | tuplehash | miri | tuplehash-staging:287 [extended] | reused | 2026-10-28T21:50:48Z |
| miri-c5500556aa719097 | md5 | miri | md5-scoped:258 [extended] | reused | 2026-10-28T12:16:08Z |
| miri-c5542457a81e836a | tuplehash | miri | tuplehash-staging:789 [extended] | reused | 2026-10-28T18:45:21Z |
| miri-c562cc3ea87d06de | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:35:width=3 [extended] | reused | 2026-10-28T23:42:23Z |
| miri-c5709862f466d661 | sha1 | miri | sha1-bulk:243 [extended] | reused | 2026-10-28T13:09:00Z |
| miri-c580fec152f60c02 | md5 | miri | md5-batch-mask:224 [extended] | reused | 2026-10-28T12:30:20Z |
| miri-c58f53167e12a4c9 | sha3 | miri | sha3-secret-xof-bits:2 [extended] | reused | 2026-10-28T13:49:43Z |
| miri-c5939d024a767eac | md5 | miri | md5-bulk:144 [extended] | reused | 2026-10-28T11:47:51Z |
| miri-c595a3f97cf35f11 | tuplehash | miri | scoped_tuplexof256_differential:29:width=1 [extended] | passed | 2026-10-29T12:06:33Z |
| miri-c5b6aa82d0c87fe5 | md5 | miri | md5-bulk:165 [extended] | reused | 2026-10-28T11:39:31Z |
| miri-c5ba097d25b35a55 | tuplehash | miri | scoped_tuplexof128_differential:14:width=4 [extended] | reused | 2026-10-29T00:48:52Z |
| miri-c5c2300e1f277d2f | md5 | miri | md5-bulk:200 [extended] | reused | 2026-10-28T11:52:33Z |
| miri-c5cc980c4b0a044f | sha1 | miri | sha1-scoped:281 [extended] | reused | 2026-10-28T13:32:19Z |
| miri-c5ef0c5abfd21654 | tuplehash | miri | tuplehash-staging:595 [extended] | reused | 2026-10-28T23:34:08Z |
| miri-c5fe5bc71dde0883 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:8:width=0 [extended] | reused | 2026-10-28T19:39:57Z |
| miri-c5ffad0464662cad | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:20:width=3 [extended] | reused | 2026-10-28T20:04:54Z |
| miri-c60f40f88ea56a9e | tuplehash | miri | tuplehash-staging:162 [extended] | reused | 2026-10-28T15:04:24Z |
| miri-c62a0916dd5b443c | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:55:width=0 [extended] | reused | 2026-10-29T01:10:24Z |
| miri-c633e9ae36fe0a41 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_unwind_reuse:2 [extended] | passed | 2026-10-29T14:53:33Z |
| miri-c648280aed37c34b | tuplehash | miri | tuplehash-staging:839 [extended] | reused | 2026-10-29T00:56:50Z |
| miri-c64c8adb7710ead9 | sha2 | miri | --manifest-path assurance/general-sha512-t/Cargo.toml --lib [remaining suite; inspect skips with show] | passed | 2026-10-19T11:33:49Z |
| miri-c64dd3325eb5659a | md5 | miri | md5-scoped:110 [extended] | reused | 2026-10-28T12:05:35Z |
| miri-c64f9a529a8932ee | sha1 | miri | sha1-bulk:172 [extended] | reused | 2026-10-28T12:53:08Z |
| miri-c656361bac639f3a | sha1 | miri | sha1-scoped:204 [extended] | reused | 2026-10-28T13:19:56Z |
| miri-c67309479b541048 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:38:width=0 [extended] | reused | 2026-10-28T20:41:14Z |
| miri-c698576dabda1d14 | sha3 | miri | -p brynja-hash-sha3 --features static-execution --lib execution [remaining suite; inspect skips with show] | passed | 2026-10-19T11:35:32Z |
| miri-c6a4ba0c545ce07e | tuplehash | miri | tuplehash-execution-fixed:10 [extended] | reused | 2026-10-28T19:14:59Z |
| miri-c6a6478caf6a1c8f | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:5 [routine] | No mapped observation | — |
| miri-c6a77e779bc60649 | md5 | miri | md5-scoped:45 [extended] | reused | 2026-10-28T11:50:34Z |
| miri-c6aa62dd0efcc70b | legacy_hmac | miri | -p brynja-legacy-hmac-std --all-features --lib missing_native [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-c6b92f9deba1720f | md5 | miri | md5-scoped:67 [extended] | reused | 2026-10-28T11:51:45Z |
| miri-c6d3ce2d1d32dae1 | tuplehash | miri | scoped_tuplexof128_differential:14:width=3 [extended] | reused | 2026-10-29T00:48:52Z |
| miri-c6fb091a3333b81a | md5 | miri | md5-bulk:64 [extended] | reused | 2026-10-28T11:41:44Z |
| miri-c7055eef9bbc18c5 | sha3 | miri | sha3-fixed-boundaries:43 [routine] | passed | 2026-10-19T11:37:21Z |
| miri-c756f4d3c63cdeac | tuplehash | miri | tuplehash-staging:246 [extended] | reused | 2026-10-28T15:31:38Z |
| miri-c75e13b263ad9065 | kmac | miri | kmac-streamed-setup:70 [routine] | No mapped observation | — |
| miri-c7630b8915fa2955 | md5 | miri | md5-bulk:84 [extended] | reused | 2026-10-28T11:43:12Z |
| miri-c768adc1e6b62f91 | tuplehash | miri | scoped_tuplexof128_differential:31:width=4 [extended] | reused | 2026-10-29T02:17:45Z |
| miri-c77a6473917ad9dc | hmac | miri | sha3_224 [routine] | No mapped observation | — |
| miri-c795a2be12b8a486 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:6 [extended] | passed | 2026-10-29T13:55:26Z |
| miri-c79e5b6983eaff5a | md5 | miri | md5-batch-mask:49 [extended] | reused | 2026-10-28T12:11:09Z |
| miri-c79f7efcda84aa12 | md5 | miri | md5-bulk:115 [extended] | reused | 2026-10-28T11:35:56Z |
| miri-c7bbd7efe72a2f18 | tuplehash | miri | tuplehash-staging:611 [extended] | reused | 2026-10-28T23:39:32Z |
| miri-c7c25b7d0c56b85b | md5 | miri | md5-padding:35 [extended] | reused | 2026-10-28T11:25:45Z |
| miri-c7c7bc32dad9c33f | tuplehash | miri | tuplehash-staging:0 [extended] | reused | 2026-10-28T14:08:48Z |
| miri-c7d0c1411e64a5aa | md5 | miri | md5-bulk:45 [extended] | reused | 2026-10-28T11:30:41Z |
| miri-c7d7e90c02d33abd | md5 | miri | md5-batch-mask:76 [extended] | reused | 2026-10-28T12:18:36Z |
| miri-c7e129f141f14c36 | tuplehash | miri | scoped_tuplexof128_differential:38:width=3 [extended] | reused | 2026-10-29T01:45:47Z |
| miri-c7e73ccc75b15ac0 | tuplehash | miri | scoped_tuplexof128_differential:11:width=2 [extended] | reused | 2026-10-29T01:31:31Z |
| miri-c7e8304fc8f18f91 | tuplehash | miri | scoped_tuplexof256_differential:11:width=1 [extended] | reused | 2026-10-29T03:23:30Z |
| miri-c7f13a21f0d7c32e | tuplehash | miri | tuplehash-staging:530 [extended] | reused | 2026-10-28T17:03:37Z |
| miri-c7f4d4554db9c03c | tuplehash | miri | tuplehash-staging:710 [extended] | reused | 2026-10-28T18:01:38Z |
| miri-c7fa572b745454f9 | legacy_hmac | miri | output_unwind [extended] | passed | 2026-10-29T15:08:56Z |
| miri-c7fc17f619ebc200 | md5 | miri | md5-padding:99 [extended] | reused | 2026-10-28T11:30:07Z |
| miri-c802fb30c044cafe | tuplehash | miri | tuplehash-staging:203 [extended] | reused | 2026-10-28T21:22:25Z |
| miri-c8278497052b7f1e | md5 | miri | md5-scoped:57 [extended] | reused | 2026-10-28T11:51:21Z |
| miri-c84dbc0708a4705b | kmac | miri | kmac-streamed-setup:16 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-c84ff201e5aae36e | sha3 | miri | -p brynja-hash-sha3 --features batch-execution --lib batch::tests::bounded_batch_lifecycle [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-c86a53d6b298e106 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:37:width=2 [extended] | reused | 2026-10-29T05:42:32Z |
| miri-c86a76cb05e12eb7 | sha1 | miri | sha1-bulk:154 [extended] | reused | 2026-10-28T12:52:53Z |
| miri-c86abd60ee5f0ef4 | tuplehash | miri | scoped_tuplexof128_differential:2:width=2 [extended] | reused | 2026-10-29T00:29:11Z |
| miri-c86aefe913d94d20 | tuplehash | miri | tuplehash-staging:768 [routine] | passed | 2026-10-19T12:04:33Z |
| miri-c86b2e21854ea268 | sha1 | miri | sha1-bulk:127 [routine] | passed | 2026-10-19T11:31:22Z |
| miri-c888996013387abf | tuplehash | miri | tuplehash-staging:746 [extended] | reused | 2026-10-28T18:12:48Z |
| miri-c88d1a52a4fee0b3 | sha1 | miri | sha1-bulk:203 [extended] | reused | 2026-10-28T13:04:01Z |
| miri-c8b46601fb2be670 | md5 | miri | md5-bulk:0 [extended] | reused | 2026-10-28T11:37:29Z |
| miri-c8b4ff7c885a1d5f | sha1 | miri | sha1-padding:30 [extended] | reused | 2026-10-28T12:41:38Z |
| miri-c8d12c6aa1c91c9e | tuplehash | miri | tuplehash-staging:227 [extended] | reused | 2026-10-28T21:30:56Z |
| miri-c8e2f19841f2ae0e | tuplehash | miri | tuplehash-execution-fixed:11 [extended] | reused | 2026-10-29T01:31:09Z |
| miri-c8e9b1b6ee166529 | sha1 | miri | sha1-padding:66 [extended] | reused | 2026-10-28T12:44:42Z |
| miri-c8faaa689e3e1c40 | sha1 | miri | sha1-scoped:157 [extended] | reused | 2026-10-28T13:22:16Z |
| miri-c9093209e95acfae | sha3 | miri | sha3-fixed-boundaries:8 [extended] | reused | 2026-10-28T13:45:41Z |
| miri-c913ae15b8ca6cf7 | sha1 | miri | sha1-scoped:3 [extended] | reused | 2026-10-28T13:16:00Z |
| miri-c919600c9a4fddbb | sha1 | miri | sha1-bulk:128 [routine] | passed | 2026-10-19T11:29:21Z |
| miri-c91dc18dc2071ebe | sha3 | miri | sha3-fixed-boundaries:38 [extended] | reused | 2026-10-28T13:41:04Z |
| miri-c92609be97bd8b32 | tuplehash | miri | scoped_tuplexof256_differential:25:width=0 [extended] | passed | 2026-10-29T12:34:09Z |
| miri-c9306a57f087a530 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:48:width=3 [extended] | reused | 2026-10-28T23:58:48Z |
| miri-c945594d7cabb4b8 | md5 | miri | md5-batch-mask:144 [extended] | reused | 2026-10-28T12:23:56Z |
| miri-c97556836f1c5783 | sha1 | miri | sha1-scoped:56 [extended] | reused | 2026-10-28T13:08:12Z |
| miri-c985d907c2fa1375 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:28:width=1 [extended] | reused | 2026-10-28T20:23:14Z |
| miri-c98bf847aea0177d | sha1 | miri | sha1-scoped:268 [extended] | reused | 2026-10-28T13:25:13Z |
| miri-c98e6316c9b3b4bc | sha1 | miri | sha1-bulk:72 [extended] | reused | 2026-10-28T12:43:56Z |
| miri-c9920eca09ef2dca | tuplehash | miri | tuplehash-staging:97 [extended] | reused | 2026-10-28T14:53:32Z |
| miri-c9ad5c71a7a86e36 | tuplehash | miri | scoped_tuplexof128_differential:12:width=3 [extended] | reused | 2026-10-29T00:49:44Z |
| miri-c9b091e4945d2380 | sha1 | miri | sha1-scoped:184 [extended] | reused | 2026-10-28T13:18:17Z |
| miri-c9c52c844868e11a | md5 | miri | md5-batch-mask:109 [extended] | reused | 2026-10-28T12:15:49Z |
| miri-c9c5516183a44ffe | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:20:width=0 [extended] | reused | 2026-10-28T20:04:54Z |
| miri-c9dac691561bf09a | tuplehash | miri | tuplehash-staging:754 [extended] | reused | 2026-10-28T18:15:22Z |
| miri-c9dc817fd5e700ef | sha1 | miri | sha1-scoped:253 [extended] | reused | 2026-10-28T13:29:59Z |
| miri-c9e2574fc65dd312 | tuplehash | miri | tuplehash-staging:566 [extended] | reused | 2026-10-28T17:15:32Z |
| miri-ca08b292af430e41 | tuplehash | miri | tuplehash-staging:426 [extended] | reused | 2026-10-28T16:30:55Z |
| miri-ca0df011e1459743 | sha3 | miri | sha3-fixed-boundaries:43 [extended] | reused | 2026-10-28T13:42:10Z |
| miri-ca1400fe822b3a96 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:27:width=3 [extended] | reused | 2026-10-28T20:42:37Z |
| miri-ca24a44b14e095e2 | sha2 | miri | -p brynja-hash-sha2 --test bit_inputs selected_official_nist_bit_vectors_match_every_identity [remaining suite; inspect skips with show] | passed | 2026-10-19T11:24:47Z |
| miri-ca298fa08be69423 | sha3 | miri | sha3-fixed-boundaries:18 [extended] | reused | 2026-10-28T13:38:33Z |
| miri-ca2a35c5602e431f | sha1 | miri | sha1-scoped:249 [extended] | reused | 2026-10-28T13:29:40Z |
| miri-ca3263bbd71da565 | md5 | miri | md5-batch-mask:5 [extended] | reused | 2026-10-28T12:07:54Z |
| miri-ca52feaaec3fd3db | sha1 | miri | sha1-bulk:116 [extended] | reused | 2026-10-28T12:47:40Z |
| miri-ca611615805c9115 | md5 | miri | md5-padding:51 [extended] | reused | 2026-10-28T11:26:42Z |
| miri-ca61c7b607bba6a9 | md5 | miri | md5-scoped:146 [extended] | reused | 2026-10-28T12:08:05Z |
| miri-ca6be728c79d00a0 | parallelhash | miri | [bounded-parallelhash-v1] parallelhashxof-official:3 [extended] | passed | 2026-10-29T14:00:03Z |
| miri-ca6beb5c06cf1fe9 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:23:width=3 [extended] | reused | 2026-10-28T20:32:45Z |
| miri-ca6e701d96c3cb45 | tuplehash | miri | tuplehash-staging:509 [extended] | reused | 2026-10-28T17:11:02Z |
| miri-ca7bf679d530ffb6 | tuplehash | miri | tuplehash-staging:441 [extended] | reused | 2026-10-28T16:48:42Z |
| miri-ca8474de6981c607 | sha3 | miri | sha3-fixed-boundaries:35 [routine] | passed | 2026-10-19T11:27:24Z |
| miri-ca8e5beb78bf9e30 | tuplehash | miri | scoped_tuplexof128_differential:28:width=0 [extended] | reused | 2026-10-29T01:27:22Z |
| miri-caa95c79dd1f22f6 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:14:width=4 [extended] | reused | 2026-10-28T22:15:42Z |
| miri-caac7af75c46ba2d | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-faults:0 [routine] | No mapped observation | — |
| miri-caacba5a4f909a54 | tuplehash | miri | tuplehash-staging:462 [extended] | reused | 2026-10-28T16:42:06Z |
| miri-caad3af6f7574017 | sha2 | miri | -p brynja-hash-sha2 --test sha384 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-cab1c5e523e05c4a | sha3 | miri | -p brynja-hash-sha3 --test sha3_512 suffix_and_rate_boundaries_have_exact_digests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-cab2fd56d3d054ec | tuplehash | miri | tuplehash-staging:446 [extended] | reused | 2026-10-28T16:37:09Z |
| miri-cab601a798a0afbd | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:23:width=0 [extended] | reused | 2026-10-28T23:12:58Z |
| miri-cabe4cb38b10b294 | md5 | miri | md5-batch-mask:121 [extended] | reused | 2026-10-28T12:16:49Z |
| miri-cac06deb851bc07c | tuplehash | miri | tuplehash-staging:802 [extended] | reused | 2026-10-28T18:30:43Z |
| miri-cacc19c7f6bc548b | kmac | miri | -p brynja-mac-kmac --features hardened-execution --lib execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-cad60addae739dde | tuplehash | miri | -p brynja-hash-tuple --test api forgotten_or_manually_dropped_items_cannot_bypass_the_open_latch [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-cad86d636e5f074b | md5 | miri | md5-batch-mask:131 [extended] | reused | 2026-10-28T12:17:25Z |
| miri-cadc1b27c7ac0d8d | tuplehash | miri | scoped_tuplexof256_differential:46:width=3 [extended] | reused | 2026-10-29T03:59:12Z |
| miri-cadd1790c9719f22 | sha3 | miri | sha3-fixed-bits:25 [extended] | reused | 2026-10-28T13:43:57Z |
| miri-caecbf2c9423bd5a | tuplehash | miri | tuplehash-staging:277 [extended] | reused | 2026-10-28T15:53:28Z |
| miri-caf8c8dd0eaa1391 | parallelhash | miri | equal_shape_cross_plan_result_permanently_fails_closed [extended] | passed | 2026-10-29T15:15:14Z |
| miri-cb06542137b7560d | sha1 | miri | sha1-scoped:125 [extended] | reused | 2026-10-28T13:19:49Z |
| miri-cb36fa1ad1b64825 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:32:width=3 [extended] | reused | 2026-10-28T23:01:38Z |
| miri-cb3e25a43b68b4f2 | md5 | miri | md5-bulk:51 [extended] | reused | 2026-10-28T11:31:24Z |
| miri-cb3eb446c6272774 | sha1 | miri | sha1-bulk:248 [extended] | reused | 2026-10-28T13:01:45Z |
| miri-cb432daa3b8c35e0 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:54:width=4 [extended] | reused | 2026-10-28T21:49:32Z |
| miri-cb659c2f7fc7e311 | tuplehash | miri | tuplehash-staging:629 [extended] | reused | 2026-10-28T17:51:51Z |
| miri-cb73e0e6f732905e | tuplehash | miri | scoped_tuplexof128_differential:4:width=1 [extended] | reused | 2026-10-29T00:36:36Z |
| miri-cb7512c4d1c68d6f | md5 | miri | md5-batch-mask:250 [extended] | reused | 2026-10-28T12:38:13Z |
| miri-cb8ef41581dda0f9 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-domains:4 [extended] | passed | 2026-10-29T15:05:14Z |
| miri-cb91c2e3eebd556e | tuplehash | miri | tuplehash-staging:244 [extended] | reused | 2026-10-28T15:28:18Z |
| miri-cb9613821397b9fb | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-slots:2 [routine] | No mapped observation | — |
| miri-cbbb777e03067d9c | sha1 | miri | sha1-bulk:94 [extended] | reused | 2026-10-28T12:47:25Z |
| miri-cbbb8e588e57dce9 | kmac | miri | kmac-scoped-lifecycle:9 [routine] | passed | 2026-10-19T15:30:34Z |
| miri-cbbf27c63932116b | tuplehash | miri | scoped_tuplexof128_differential:28:width=4 [extended] | reused | 2026-10-29T01:27:22Z |
| miri-cbcb3721d6337779 | tuplehash | miri | tuplehash-staging:797 [extended] | reused | 2026-10-28T18:48:26Z |
| miri-cbcf74a01c8595ee | legacy_hmac | miri | md5_short [existing-full] | No mapped observation | — |
| miri-cbd93dfe40fea3b7 | tuplehash | miri | scoped_tuplexof256_differential:41:width=2 [extended] | passed | 2026-10-29T12:49:10Z |
| miri-cbe0e5424c75dd7d | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:14:width=2 [extended] | reused | 2026-10-28T19:46:05Z |
| miri-cbedcecf5c94ba72 | md5 | miri | md5-scoped:214 [extended] | reused | 2026-10-28T12:12:59Z |
| miri-cbfb616908489aab | kmac | miri | kmac-streamed-setup:67 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-cc042c4f66352369 | md5 | miri | md5-bulk:131 [extended] | reused | 2026-10-28T11:37:08Z |
| miri-cc1f80cf8c8631aa | md5 | miri | md5-padding:3 [extended] | reused | 2026-10-28T11:23:52Z |
| miri-cc241e117dafc817 | sha3 | miri | sha3-fixed-boundaries:18 [routine] | passed | 2026-10-19T11:37:04Z |
| miri-cc276b5bf5413770 | sha3 | miri | sha3-fixed-boundaries:39 [extended] | reused | 2026-10-28T13:41:34Z |
| miri-cc37f398023926b3 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:43:width=1 [extended] | reused | 2026-10-28T21:24:50Z |
| miri-cc3b75c0799c4792 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:27:width=1 [extended] | reused | 2026-10-28T20:42:37Z |
| miri-cc5285762dd0eec8 | tuplehash | miri | tuplehash-staging:174 [extended] | reused | 2026-10-28T15:09:05Z |
| miri-cc54d812602f2e2f | kmac | miri | kmac-streamed-setup:33 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-cc5c4ccf51f330e8 | tuplehash | miri | tuplehash-staging:254 [extended] | reused | 2026-10-28T15:34:37Z |
| miri-cc73a85e208258d1 | tuplehash | miri | scoped_tuplexof256_differential:28:width=3 [extended] | reused | 2026-10-29T03:16:23Z |
| miri-cc757463b6b8b4f4 | md5 | miri | md5-batch-mask:124 [extended] | reused | 2026-10-28T12:22:23Z |
| miri-cc81547e667d0021 | sha1 | miri | sha1-scoped:108 [extended] | reused | 2026-10-28T13:12:12Z |
| miri-cc847c405dbc662e | sha1 | miri | sha1-scoped:121 [extended] | reused | 2026-10-28T13:19:30Z |
| miri-cc8dc8224c09d770 | tuplehash | miri | scoped_tuplexof128_differential:24:width=0 [extended] | reused | 2026-10-29T01:17:49Z |
| miri-cc9e4e7b53de6326 | md5 | miri | md5-scoped:147 [extended] | reused | 2026-10-28T11:57:12Z |
| miri-cca14fa1db0742c1 | md5 | miri | md5-padding:63 [extended] | reused | 2026-10-28T11:27:27Z |
| miri-cca3338745f0e1a3 | sha3 | miri | cancel_and_early_drop_cover_absorber_and_reader_lifecycles [routine] | passed | 2026-10-19T11:41:27Z |
| miri-ccbc7ca8ea353155 | tuplehash | miri | tuplehash-staging:832 [extended] | reused | 2026-10-28T18:37:16Z |
| miri-ccce979334cdf323 | tuplehash | miri | tuplehash-staging:225 [extended] | reused | 2026-10-28T15:35:48Z |
| miri-ccd2511e23a6f2eb | sha1 | miri | sha1-bulk:0 [extended] | reused | 2026-10-28T12:39:07Z |
| miri-cce0f881ea19332e | sha1 | miri | sha1-bulk:10 [extended] | reused | 2026-10-28T12:41:19Z |
| miri-cce6a2c43b29400e | sha3 | miri | -p brynja-hash-sha3 --lib borrowing_reader_never_extracts_the_absorbing_owner [remaining suite; inspect skips with show] | reused | 2026-10-28T13:44:06Z |
| miri-ccec1ba539ce514e | sha1 | miri | -p brynja-legacy-sha1 --lib [remaining suite; inspect skips with show] | reused | 2026-10-28T12:33:59Z |
| miri-ccfbe8ecae9a6248 | tuplehash | miri | tuplehash-staging:63 [extended] | reused | 2026-10-28T20:35:14Z |
| miri-ccffe1c3c715970b | sha1 | miri | sha1-scoped:68 [extended] | reused | 2026-10-28T13:09:03Z |
| miri-cd0733bab9863b3e | sha1 | miri | sha1-bulk:194 [extended] | reused | 2026-10-28T12:56:59Z |
| miri-cd273f3377188493 | tuplehash | miri | -p brynja-hash-tuple --tests [remaining suite; inspect skips with show] | passed | 2026-10-29T10:48:17Z |
| miri-cd309ed2a115db4a | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:27:width=2 [extended] | reused | 2026-10-28T23:22:47Z |
| miri-cd30bddf9a502afb | sha3 | miri | sha3-fixed-boundaries:28 [routine] | passed | 2026-10-19T11:37:24Z |
| miri-cd3da71074ab5038 | tuplehash | miri | tuplehash-staging:662 [extended] | reused | 2026-10-28T17:45:55Z |
| miri-cd4f4afe4dacb93e | sha1 | miri | sha1-bulk:68 [extended] | reused | 2026-10-28T12:43:36Z |
| miri-cd51d5d0abe056b9 | md5 | miri | md5-scoped:276 [extended] | reused | 2026-10-28T12:12:10Z |
| miri-cd58bbdfcedd7ebf | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:13:width=2 [extended] | reused | 2026-10-29T02:04:31Z |
| miri-cd60018a74845b7f | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:38:width=4 [extended] | reused | 2026-10-28T20:41:14Z |
| miri-cd80ea93732536c4 | md5 | miri | md5-batch-mask:62 [extended] | reused | 2026-10-28T12:22:54Z |
| miri-cd8be5f0ea6a5232 | sha1 | miri | sha1-scoped:215 [extended] | reused | 2026-10-28T13:32:03Z |
| miri-cd8e5b40b8aa8b57 | md5 | miri | md5-bulk:203 [extended] | reused | 2026-10-28T11:42:52Z |
| miri-cda7e7408b00b7b8 | tuplehash | miri | tuplehash-staging:55 [extended] | reused | 2026-10-28T20:32:55Z |
| miri-cda8c70801090a9d | sha1 | miri | sha1-scoped:219 [extended] | reused | 2026-10-28T13:32:25Z |
| miri-cddd625f944245af | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:7:width=1 [extended] | reused | 2026-10-28T19:59:05Z |
| miri-cdeb749820521f0f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:44:width=2 [extended] | reused | 2026-10-28T23:34:09Z |
| miri-cded10642838b77d | sha1 | miri | sha1-padding:18 [extended] | reused | 2026-10-28T12:40:41Z |
| miri-cdefdb6a199906d3 | md5 | miri | md5-bulk:78 [extended] | reused | 2026-10-28T11:37:43Z |
| miri-cdf2c1ed180d582d | tuplehash | miri | tuplehash-staging:130 [extended] | reused | 2026-10-28T14:54:16Z |
| miri-ce02a3a13722f23d | kmac | miri | kmacxof-official:1 [extended] | reused | 2026-10-28T20:00:54Z |
| miri-ce199fa66a11a8e0 | md5 | miri | md5-padding:16 [extended] | reused | 2026-10-28T11:19:13Z |
| miri-ce41c1905ed35a41 | md5 | miri | md5-bulk:62 [extended] | reused | 2026-10-28T11:36:29Z |
| miri-ce59221cf2613dc0 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:0 [routine] | No mapped observation | — |
| miri-ce5ad6a8d53ba737 | sha1 | miri | sha1-bulk:16 [extended] | reused | 2026-10-28T12:40:05Z |
| miri-ce68bdc001a011f3 | kmac | miri | kmac-streamed-setup:85 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-ce694ccca4e8e39d | md5 | miri | md5-bulk:244 [extended] | reused | 2026-10-28T11:56:45Z |
| miri-ce6986c1ed1f4b56 | tuplehash | miri | scoped_tuplexof128_differential:46:width=4 [extended] | reused | 2026-10-29T02:10:19Z |
| miri-ce6c5fb17a1bc29d | md5 | miri | md5-batch-mask:24 [extended] | reused | 2026-10-28T12:14:43Z |
| miri-ce86ba4a32983e53 | tuplehash | miri | scoped_tuplexof256_differential:36:width=4 [extended] | reused | 2026-10-29T03:35:29Z |
| miri-cea8e1f3ba09159a | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:22 [extended] | passed | 2026-10-29T13:35:44Z |
| miri-cebfb6500128bf80 | tuplehash | miri | scoped_tuplexof128_differential:13:width=0 [extended] | passed | 2026-10-29T10:51:34Z |
| miri-cec5f1d5cea2730a | md5 | miri | md5-padding:123 [extended] | reused | 2026-10-28T11:31:58Z |
| miri-cecdf4b2a3a98a47 | tuplehash | miri | scoped_tuplexof256_differential:13:width=1 [extended] | passed | 2026-10-29T11:58:11Z |
| miri-cedbd4a4b902d7f6 | tuplehash | miri | tuplehash-staging:856 [extended] | reused | 2026-10-28T18:44:35Z |
| miri-cef5e17a8f9352d4 | md5 | miri | md5-batch-mask:74 [extended] | reused | 2026-10-28T12:23:50Z |
| miri-cf08a4e42a82bd67 | md5 | miri | md5-bulk:63 [routine] | passed | 2026-10-19T11:29:07Z |
| miri-cf08d914d85ddeb7 | tuplehash | miri | tuplehash-staging:557 [extended] | reused | 2026-10-28T17:27:13Z |
| miri-cf39c1ea6a5920ee | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-official:0 [routine] | No mapped observation | — |
| miri-cf3c0716d84776e6 | tuplehash | miri | scoped_tuplexof256_differential:12:width=2 [extended] | reused | 2026-10-29T02:38:28Z |
| miri-cf45782ea2dc0856 | kmac | miri | kmacxof-official:2 [routine] | passed | 2026-10-19T11:48:47Z |
| miri-cf46a5dc44ed0261 | tuplehash | miri | tuplehash-staging:670 [extended] | reused | 2026-10-28T17:48:29Z |
| miri-cf498b9a33fb285c | tuplehash | miri | tuplehash-staging:555 [extended] | reused | 2026-10-28T23:20:42Z |
| miri-cf4beaa08b39b10c | sha1 | miri | sha1-scoped:236 [extended] | reused | 2026-10-28T13:22:38Z |
| miri-cf4de1fa6fc747ca | tuplehash | miri | tuplehash-staging:158 [extended] | reused | 2026-10-28T15:03:28Z |
| miri-cf5edd5257112ba1 | sha1 | miri | sha1-bulk:117 [extended] | reused | 2026-10-28T12:59:40Z |
| miri-cf7aa6f005628348 | tuplehash | miri | scoped_tuplexof256_differential:3:width=1 [extended] | reused | 2026-10-29T03:09:31Z |
| miri-cf7ecf98098c6369 | tuplehash | miri | scoped_tuplexof256_differential:17:width=3 [extended] | passed | 2026-10-29T12:01:18Z |
| miri-cf94df0520857bd8 | md5 | miri | md5-scoped:278 [extended] | reused | 2026-10-28T12:17:35Z |
| miri-cf981be5253d30f2 | sha1 | miri | -p brynja-legacy-sha1 --features cpu --test cpu [remaining suite; inspect skips with show] | passed | 2026-10-19T11:30:32Z |
| miri-cfa24ba343f1baea | md5 | miri | md5-batch-mask:85 [routine] | passed | 2026-10-19T11:33:03Z |
| miri-cfa7a391dfa1c9a0 | md5 | miri | md5-bulk:255 [routine] | passed | 2026-10-19T11:14:21Z |
| miri-cfb1b02bcbb10e85 | tuplehash | miri | tuplehash-staging:484 [extended] | reused | 2026-10-28T16:45:14Z |
| miri-cfc254e650d86b15 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:22:width=1 [extended] | reused | 2026-10-28T22:33:52Z |
| miri-cfdbadd4721bdf96 | sha3 | miri | sha3-fixed-boundaries:13 [routine] | passed | 2026-10-19T11:36:36Z |
| miri-cfdf34f7b4683839 | sha1 | miri | sha1-bulk:78 [extended] | reused | 2026-10-28T12:45:59Z |
| miri-cfe12640a227560f | md5 | miri | md5-scoped:14 [extended] | reused | 2026-10-28T11:59:01Z |
| miri-cfe290c7e2a61903 | md5 | miri | md5-batch-mask:177 [extended] | reused | 2026-10-28T12:21:15Z |
| miri-d00b614f85389db9 | sha1 | miri | sha1-scoped:58 [extended] | reused | 2026-10-28T13:06:56Z |
| miri-d00c51a948a06ca9 | tuplehash | miri | scoped_tuplexof128_differential:10:width=2 [extended] | reused | 2026-10-29T00:42:19Z |
| miri-d015674ef8498c67 | sha3 | miri | sha3-fixed-boundaries:22 [extended] | reused | 2026-10-28T13:39:00Z |
| miri-d018578f7311c57c | core | miri | -p brynja-core --test secret_memory [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-d0282b550c9b47a8 | md5 | miri | md5-bulk:246 [extended] | reused | 2026-10-28T11:51:59Z |
| miri-d02c6f8388b3eae7 | tuplehash | miri | tuplehash-staging:297 [extended] | reused | 2026-10-28T16:00:36Z |
| miri-d043a2dfd115d8b2 | md5 | miri | md5-bulk:209 [extended] | reused | 2026-10-28T11:43:05Z |
| miri-d04d77a6230cc439 | md5 | miri | md5-bulk:215 [extended] | reused | 2026-10-28T11:43:53Z |
| miri-d059d73d7322663d | tuplehash | miri | tuplehash-execution-fixed:1 [routine] | passed | 2026-10-19T12:08:31Z |
| miri-d05d2cabea784fef | tuplehash | miri | scoped_tuplexof256_differential:28:width=2 [extended] | reused | 2026-10-29T03:16:23Z |
| miri-d06a28dc36a597c2 | md5 | miri | md5-scoped:264 [extended] | reused | 2026-10-28T12:11:18Z |
| miri-d0742d72d3126341 | sha1 | miri | sha1-scoped:187 [extended] | reused | 2026-10-28T13:29:43Z |
| miri-d0816b5d4d689500 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-faults:4 [routine] | No mapped observation | — |
| miri-d090dcd9400d25df | sha1 | miri | sha1-scoped:12 [extended] | reused | 2026-10-28T13:05:05Z |
| miri-d091690735e51860 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:2:width=1 [extended] | reused | 2026-10-28T21:56:04Z |
| miri-d09fd9ee595e1b22 | hmac | miri | sha3_224 [existing-full] | No mapped observation | — |
| miri-d0a34a1423d5be00 | md5 | miri | md5-padding:117 [extended] | reused | 2026-10-28T11:36:31Z |
| miri-d0a57ec7dcded823 | sha1 | miri | sha1-padding:121 [extended] | reused | 2026-10-28T12:38:27Z |
| miri-d0a89bfae3f450e1 | tuplehash | miri | scoped_tuplexof256_differential:3:width=3 [extended] | reused | 2026-10-29T03:09:31Z |
| miri-d0a8fc15cae9d6db | md5 | miri | md5-padding:124 [extended] | reused | 2026-10-28T11:27:38Z |
| miri-d0acb20e5b6fdecd | sha3 | miri | sha3-fixed-bits:15 [extended] | reused | 2026-10-28T13:48:15Z |
| miri-d0adc3b58e39b0b5 | kmac | miri | kmac-streamed-setup:42 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-d0ae76710ac085af | sha3 | miri | -p brynja-hash-sha3 --test cshake every_official_nist_cshake_example_matches [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-d0dc4a4d6bb9b910 | md5 | miri | md5-padding:31 [extended] | reused | 2026-10-28T11:25:31Z |
| miri-d0f045725b834d88 | tuplehash | miri | scoped_tuplexof256_differential:47:width=1 [extended] | reused | 2026-10-29T04:53:59Z |
| miri-d0f64c91fb62eb02 | tuplehash | miri | tuplehash-staging:0 [routine] | passed | 2026-10-19T11:52:55Z |
| miri-d110e08fd468f9b0 | sha3 | miri | sha3-fixed-bits:22 [extended] | reused | 2026-10-28T13:48:41Z |
| miri-d11340e0d3b75bd4 | md5 | miri | md5-padding:110 [extended] | reused | 2026-10-28T11:26:16Z |
| miri-d1156221302ca64b | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:42:width=4 [extended] | reused | 2026-10-28T20:52:59Z |
| miri-d11922ef28d75039 | sha1 | miri | sha1-scoped:23 [extended] | reused | 2026-10-28T13:17:27Z |
| miri-d12bab32b962ccbc | sha2 | miri | -p brynja-hash-sha2 --test hardened [remaining suite; inspect skips with show] | reused | 2026-10-28T13:42:19Z |
| miri-d137aeff7873c7aa | sha3 | miri | sha3-fixed-bits:20 [routine] | passed | 2026-10-19T11:38:48Z |
| miri-d13a046f3cdf05ea | md5 | miri | md5-padding:98 [extended] | reused | 2026-10-28T11:25:21Z |
| miri-d1691fff9851a158 | sha1 | miri | sha1-bulk:155 [extended] | reused | 2026-10-28T12:58:43Z |
| miri-d173a5ca314b50d6 | sha3 | miri | -p brynja-hash-sha3 --features hardened-execution --lib hardened::accelerated::reader::tests [remaining suite; inspect skips with show] | reused | 2026-10-28T13:28:42Z |
| miri-d179ca13d1855b0a | kmac | miri | kmac-official:2 [extended] | reused | 2026-10-28T14:05:26Z |
| miri-d18c9140810031f8 | md5 | miri | md5-scoped:94 [extended] | reused | 2026-10-28T12:04:28Z |
| miri-d1b833acb82090a7 | md5 | miri | md5-bulk:55 [routine] | passed | 2026-10-19T11:32:18Z |
| miri-d1bacee211408c3a | kmac | miri | kmac-streamed-setup:49 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-d1c1cd4eeb876d1a | sha1 | miri | sha1-scoped:264 [extended] | reused | 2026-10-28T13:24:54Z |
| miri-d1ccdee9d7417119 | tuplehash | miri | tuplehash-staging:844 [extended] | reused | 2026-10-28T18:40:45Z |
| miri-d1d9243b8d78e89c | sha1 | miri | sha1-bulk:229 [extended] | reused | 2026-10-28T13:12:01Z |
| miri-d1e2a0bf9c6678b5 | md5 | miri | md5-batch-mask:173 [extended] | reused | 2026-10-28T12:20:56Z |
| miri-d1e5f487c9ccb31a | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:630 [extended] | passed | 2026-10-29T14:05:32Z |
| miri-d1ee8205edda8027 | md5 | miri | md5-batch-mask:147 [extended] | reused | 2026-10-28T12:18:44Z |
| miri-d1f8a4b7be429130 | tuplehash | miri | tuplehash-staging:429 [extended] | reused | 2026-10-28T16:44:39Z |
| miri-d1ffccd1f5963b5a | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:41:width=2 [extended] | reused | 2026-10-29T05:55:08Z |
| miri-d21b1132e6532d43 | md5 | miri | md5-scoped:256 [extended] | reused | 2026-10-28T12:10:42Z |
| miri-d2229cf6ba01a8da | md5 | miri | md5-bulk:43 [extended] | reused | 2026-10-28T11:30:53Z |
| miri-d231bf44d2739e21 | tuplehash | miri | tuplehash-staging:762 [extended] | reused | 2026-10-28T18:18:17Z |
| miri-d23df173a460f58d | tuplehash | miri | tuplehash-staging:601 [extended] | reused | 2026-10-28T17:42:26Z |
| miri-d243251cf8ee2dd7 | sha1 | miri | sha1-padding:69 [extended] | reused | 2026-10-28T12:33:40Z |
| miri-d2449f63123646df | md5 | miri | md5-scoped:60 [extended] | reused | 2026-10-28T11:56:59Z |
| miri-d244fde4ba24102a | sha1 | miri | sha1-bulk:167 [extended] | reused | 2026-10-28T12:59:57Z |
| miri-d249eb2b2b94d161 | sha3 | miri | sha3-fixed-boundaries:0 [extended] | reused | 2026-10-28T13:44:50Z |
| miri-d2619e2a63c62c33 | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join256:2 [extended] | passed | 2026-10-29T15:06:14Z |
| miri-d26a9152aae3a5b5 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:54:width=0 [extended] | reused | 2026-10-29T00:22:37Z |
| miri-d26dc109a62cbdf0 | md5 | miri | md5-scoped:13 [extended] | reused | 2026-10-28T11:48:28Z |
| miri-d27ecf407c7075b6 | tuplehash | miri | scoped_tuplexof128_differential:10:width=3 [extended] | reused | 2026-10-29T00:42:19Z |
| miri-d2a4c337e248d045 | tuplehash | miri | tuplehash-staging:183 [extended] | reused | 2026-10-28T21:15:17Z |
| miri-d2adc2644c69580c | tuplehash | miri | tuplehash-staging:230 [extended] | reused | 2026-10-28T15:27:09Z |
| miri-d2af993ee8078577 | sha3 | miri | sha3-fixed-boundaries:13 [extended] | reused | 2026-10-28T13:32:52Z |
| miri-d2c7fe4eb0533744 | md5 | miri | md5-batch-mask:55 [extended] | reused | 2026-10-28T12:11:25Z |
| miri-d2de60e40283722e | tuplehash | miri | tuplehash-staging:31 [extended] | reused | 2026-10-28T20:25:04Z |
| miri-d30baf022191fc8b | hmac | miri | -p brynja-mac-hmac --features hardened-execution --lib execution::tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-d31128491a281253 | tuplehash | miri | tuplehash-staging:19 [extended] | reused | 2026-10-28T20:20:47Z |
| miri-d3264d348e69d976 | parallelhash | miri | hardened_in_place::xof::tests::scoped_parallel_xof128_lifecycle [extended] | passed | 2026-10-29T14:57:30Z |
| miri-d32bff921760d888 | md5 | miri | md5-bulk:196 [extended] | reused | 2026-10-28T11:52:12Z |
| miri-d32f3bda9a5b9dcf | sha2 | miri | -p brynja-hash-sha2 --test sha224 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-d32f977b435aedbd | md5 | miri | md5-batch-mask:12 [extended] | reused | 2026-10-28T12:13:52Z |
| miri-d346a70a54f15de1 | sha1 | miri | sha1-scoped:89 [extended] | reused | 2026-10-28T13:16:59Z |
| miri-d351e8657a21ebca | md5 | miri | md5-scoped:144 [extended] | reused | 2026-10-28T12:02:47Z |
| miri-d353654cadc73c39 | md5 | miri | md5-scoped:96 [extended] | reused | 2026-10-28T11:59:28Z |
| miri-d366652793e0ab76 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:44:width=1 [extended] | reused | 2026-10-28T23:34:09Z |
| miri-d3673ed944c985b5 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:24:width=0 [extended] | reused | 2026-10-28T22:43:23Z |
| miri-d36882e2290bb04b | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:4:width=1 [extended] | reused | 2026-10-28T22:02:53Z |
| miri-d38134cf864c50f8 | tuplehash | miri | tuplehash-execution-fixed:5 [routine] | passed | 2026-10-19T12:12:30Z |
| miri-d3b35f28ced8e7d6 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_unwind_reuse:3 [routine] | No mapped observation | — |
| miri-d3d754cf10b0b420 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:13:width=3 [extended] | reused | 2026-10-29T02:04:31Z |
| miri-d3dcc65befb1c148 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:27 [extended] | passed | 2026-10-29T14:12:15Z |
| miri-d40599db8593587f | kmac | miri | kmac-streamed-setup:39 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-d4185a790a3efbe3 | tuplehash | miri | scoped_tuplexof256_differential:19:width=4 [extended] | reused | 2026-10-29T03:40:19Z |
| miri-d41fe273c71ff4ff | sha1 | miri | sha1-scoped:173 [extended] | reused | 2026-10-28T13:23:29Z |
| miri-d423cbdcdec42343 | md5 | miri | md5-scoped:240 [extended] | reused | 2026-10-28T12:09:31Z |
| miri-d42438c3bea8d619 | md5 | miri | md5-scoped:28 [extended] | reused | 2026-10-28T11:54:50Z |
| miri-d429660dacd793cf | hmac | miri | sha384 [extended] | passed | 2026-10-29T15:17:03Z |
| miri-d433228161a05f12 | tuplehash | miri | tuplehash-staging:731 [extended] | reused | 2026-10-29T00:20:24Z |
| miri-d43c61b0151c8a44 | md5 | miri | md5-bulk:11 [extended] | reused | 2026-10-28T11:28:47Z |
| miri-d44c86335ce9f809 | tuplehash | miri | tuplehash-staging:673 [extended] | reused | 2026-10-28T18:05:52Z |
| miri-d45b96d08865b006 | kmac | miri | kmac-streamed-setup:42 [routine] | No mapped observation | — |
| miri-d46319efb56b19d6 | md5 | miri | md5-bulk:189 [extended] | reused | 2026-10-28T11:41:24Z |
| miri-d477081683ee2cd1 | sha1 | miri | sha1-bulk:45 [extended] | reused | 2026-10-28T12:53:53Z |
| miri-d485c37f0035e4a8 | md5 | miri | md5-bulk:177 [extended] | reused | 2026-10-28T11:40:27Z |
| miri-d4867505c2bf80f1 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:0 [extended] | passed | 2026-10-29T13:36:05Z |
| miri-d48b50eba29f78cb | kmac | miri | kmac-streamed-setup:74 [routine] | No mapped observation | — |
| miri-d4900baef4f2b7ef | md5 | miri | md5-scoped:52 [extended] | reused | 2026-10-28T11:56:27Z |
| miri-d4a100080127637d | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:21:width=4 [extended] | reused | 2026-10-29T02:24:05Z |
| miri-d4a127b5c2c90397 | md5 | miri | md5-scoped:22 [extended] | reused | 2026-10-28T11:59:34Z |
| miri-d4a16467bdf15759 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:17:width=4 [extended] | reused | 2026-10-29T02:14:18Z |
| miri-d4a165d04c9e8e03 | md5 | miri | md5-bulk:186 [extended] | reused | 2026-10-28T11:46:30Z |
| miri-d4a426adf7f2267b | md5 | miri | md5-scoped:49 [extended] | reused | 2026-10-28T11:50:50Z |
| miri-d4ad69a3ab3b7641 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:24:width=4 [extended] | reused | 2026-10-28T22:43:23Z |
| miri-d4bf712ea3b64f75 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-domains:2 [extended] | passed | 2026-10-29T15:04:05Z |
| miri-d4c387628c96abd0 | sha1 | miri | sha1-bulk:145 [extended] | reused | 2026-10-28T13:02:27Z |
| miri-d4c61e0a487df20d | sha3 | miri | sha3-fixed-boundaries:0 [routine] | passed | 2026-10-19T11:36:15Z |
| miri-d4cd02726e55177d | kmac | miri | kmac-scoped-lifecycle:12 [extended] | reused | 2026-10-28T13:59:28Z |
| miri-d4d3ee297214c7f1 | sha3 | miri | -p brynja-crypto-cpu --features hardened-execution --lib hardened_execution::keccak::tests::all_seven_regions_clear [remaining suite; inspect skips with show] | passed | 2026-10-19T11:25:20Z |
| miri-d4e6b54d69d0354d | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:3 [routine] | No mapped observation | — |
| miri-d4f71afe8373cf9f | kmac | miri | kmac-streamed-setup:73 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-d4f75e2398324e19 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:7:width=0 [extended] | reused | 2026-10-28T22:39:20Z |
| miri-d51a9526c54aa8bd | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:15 [routine] | No mapped observation | — |
| miri-d51e9aa4377704bc | tuplehash | miri | tuplehash-staging:6 [extended] | reused | 2026-10-28T14:14:15Z |
| miri-d5234fe1fb00bcf1 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:32:width=0 [extended] | reused | 2026-10-28T20:32:25Z |
| miri-d544f4122348c908 | sha1 | miri | sha1-bulk:220 [extended] | reused | 2026-10-28T12:58:33Z |
| miri-d54f2411856e7017 | sha1 | miri | sha1-bulk:66 [extended] | reused | 2026-10-28T12:44:59Z |
| miri-d5708f1af54b14a4 | tuplehash | miri | tuplehash-staging:437 [extended] | reused | 2026-10-28T16:47:45Z |
| miri-d57cef7af6e15467 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:1:width=4 [extended] | reused | 2026-10-29T04:23:03Z |
| miri-d5828736a1835d05 | hmac | miri | general_511 [existing-full] | No mapped observation | — |
| miri-d585d89bee2b54d8 | tuplehash | miri | tuplehash-staging:616 [extended] | reused | 2026-10-28T17:27:46Z |
| miri-d58fafedb35a0093 | md5 | miri | md5-batch-mask:198 [extended] | reused | 2026-10-28T12:33:43Z |
| miri-d5b21665d6c6ff7d | tuplehash | miri | tuplehash-staging:408 [extended] | reused | 2026-10-28T16:21:15Z |
| miri-d5c4a985a1755f40 | md5 | miri | md5-scoped:33 [extended] | reused | 2026-10-28T11:49:47Z |
| miri-d5cc5516006513eb | sha1 | miri | sha1-bulk:238 [extended] | reused | 2026-10-28T13:02:00Z |
| miri-d5e12e90acfa04df | md5 | miri | md5-batch-mask:166 [extended] | reused | 2026-10-28T12:31:04Z |
| miri-d5e3e625a551b27e | md5 | miri | md5-padding:111 [extended] | reused | 2026-10-28T11:31:01Z |
| miri-d5f20020219aa99d | sha1 | miri | sha1-bulk:223 [extended] | reused | 2026-10-28T13:06:28Z |
| miri-d5f67ee0088fc2ed | sha1 | miri | sha1-scoped:33 [extended] | reused | 2026-10-28T13:12:58Z |
| miri-d6013fd356d86e73 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:46:width=4 [extended] | reused | 2026-10-28T23:33:28Z |
| miri-d6094415c592e7bc | tuplehash | miri | scoped_tuplexof256_differential:40:width=4 [extended] | reused | 2026-10-29T03:47:39Z |
| miri-d612c12d0d3bf3aa | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join256:2 [routine] | No mapped observation | — |
| miri-d613aae15e5746bb | tuplehash | miri | scoped_tuplexof256_differential:45:width=0 [extended] | passed | 2026-10-29T12:52:09Z |
| miri-d61aaac1a784ca80 | tuplehash | miri | tuplehash-staging:82 [extended] | reused | 2026-10-28T14:38:31Z |
| miri-d634450179c222bb | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-official:5 [routine] | No mapped observation | — |
| miri-d637183b86096f91 | tuplehash | miri | tuplehash-staging:523 [extended] | reused | 2026-10-28T23:09:49Z |
| miri-d63d5d195988cdae | legacy_hmac | miri | sha1_long [existing-full] | No mapped observation | — |
| miri-d658d747f0fea9f5 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:37:width=1 [extended] | reused | 2026-10-29T05:42:32Z |
| miri-d65f7d35d10b293b | sha2 | miri | -p brynja-hash-sha2 --test sha256 padding_boundaries_have_exact_digests [remaining suite; inspect skips with show] | reused | 2026-10-28T13:34:22Z |
| miri-d662daf5a06fac9c | md5 | miri | md5-scoped:250 [routine] | passed | 2026-10-19T11:29:48Z |
| miri-d66c3bc539dc48ca | acceleration | miri | --manifest-path assurance/acceleration-contract/Cargo.toml --lib [remaining suite; inspect skips with show] | passed | 2026-10-29T16:59:01Z |
| miri-d66e095609cd83ad | sha2 | miri | -p brynja-hash-sha2 --lib hardened::tests::checked_length_ [remaining suite; inspect skips with show] | passed | 2026-10-19T11:23:19Z |
| miri-d675712d82b21322 | sha1 | miri | sha1-scoped:265 [extended] | reused | 2026-10-28T13:30:57Z |
| miri-d68b5ab06299b8a5 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:46:width=1 [extended] | reused | 2026-10-28T21:04:48Z |
| miri-d6ae23ad7332227e | md5 | miri | md5-batch-mask:145 [extended] | reused | 2026-10-28T12:18:43Z |
| miri-d6bac02255d810f7 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:33:width=2 [extended] | reused | 2026-10-29T05:32:49Z |
| miri-d6c4739069f8b6ef | tuplehash | miri | scoped_tuplexof256_differential:7:width=1 [extended] | reused | 2026-10-29T03:16:31Z |
| miri-d6dda32fc5ba07cc | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:23 [routine] | No mapped observation | — |
| miri-d6e29dcf741670ed | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:19:width=1 [extended] | reused | 2026-10-28T20:22:54Z |
| miri-d6e4a0ba54335338 | tuplehash | miri | tuplehash-staging:258 [extended] | reused | 2026-10-28T15:36:19Z |
| miri-d70f92bce76cdbd5 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:14:width=2 [extended] | reused | 2026-10-28T22:15:42Z |
| miri-d7135d54975beced | md5 | miri | md5-batch-mask:95 [extended] | reused | 2026-10-28T12:14:31Z |
| miri-d7139a4b680867db | kmac | miri | kmac-scoped-xof-lifecycle:9 [extended] | reused | 2026-10-28T14:09:31Z |
| miri-d727052e6e0590e7 | md5 | miri | md5-bulk:132 [extended] | reused | 2026-10-28T11:46:52Z |
| miri-d72b7f1ace091a27 | tuplehash | miri | scoped_tuplexof256_differential:38:width=2 [extended] | reused | 2026-10-29T03:34:42Z |
| miri-d7332a0c1469c42e | md5 | miri | md5-scoped:2 [extended] | reused | 2026-10-28T11:58:12Z |
| miri-d736fc62e0a78fef | tuplehash | miri | tuplehash-staging:709 [extended] | reused | 2026-10-28T18:18:24Z |
| miri-d74bbb0c6aade9a8 | md5 | miri | md5-scoped:54 [extended] | reused | 2026-10-28T12:01:44Z |
| miri-d751276a922cb915 | tuplehash | miri | tuplehash-staging:48 [extended] | reused | 2026-10-28T14:24:21Z |
| miri-d751f97791213395 | sha1 | miri | sha1-scoped:65 [extended] | reused | 2026-10-28T13:15:09Z |
| miri-d785a1d4114c29df | tuplehash | miri | tuplehash-staging:558 [extended] | reused | 2026-10-28T17:12:36Z |
| miri-d7a92e932b7a1d37 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:10:width=1 [extended] | reused | 2026-10-28T22:09:09Z |
| miri-d7b7dbe8c9412376 | md5 | miri | md5-padding:53 [extended] | reused | 2026-10-28T11:31:24Z |
| miri-d7bb1856e207f13d | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:21 [routine] | No mapped observation | — |
| miri-d7c75564e1e5f029 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:57 [routine] | No mapped observation | — |
| miri-d800dcfcc3c3b9bd | sha1 | miri | sha1-bulk:96 [extended] | reused | 2026-10-28T12:45:54Z |
| miri-d8070140b4743bb1 | sha1 | miri | sha1-scoped:85 [extended] | reused | 2026-10-28T13:16:41Z |
| miri-d80d85e1ce8680e1 | tuplehash | miri | tuplehash-staging:593 [extended] | reused | 2026-10-28T17:39:20Z |
| miri-d81b397699748f0a | tuplehash | miri | hardened_in_place::xof::tests::scoped_tuplexof256_lifecycle [extended] | reused | 2026-10-29T04:59:27Z |
| miri-d821f7f54fc7d0a4 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:36:width=1 [extended] | reused | 2026-10-28T20:41:38Z |
| miri-d8242be73dda1192 | md5 | miri | md5-padding:102 [extended] | reused | 2026-10-28T11:25:39Z |
| miri-d8414b75d2d085d6 | kmac | miri | kmac-scoped-xof-lifecycle:0 [routine] | passed | 2026-10-19T11:42:47Z |
| miri-d84f3d90f7ae68c1 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:24:width=3 [extended] | reused | 2026-10-28T20:14:03Z |
| miri-d85fa2e42f3e297f | md5 | miri | md5-batch-mask:30 [extended] | reused | 2026-10-28T12:20:28Z |
| miri-d884c1c4cbaa114e | tuplehash | miri | tuplehash-staging:368 [extended] | reused | 2026-10-28T16:08:21Z |
| miri-d8951e1ecd6268ea | tuplehash | miri | tuplehash-staging:399 [extended] | reused | 2026-10-28T22:28:29Z |
| miri-d89f755e61452934 | sha3 | miri | sha3-fixed-boundaries:63 [extended] | reused | 2026-10-28T13:44:53Z |
| miri-d8a0ccb4fa4681be | sha3 | miri | sha3-secret-xof-bits:3 [extended] | reused | 2026-10-28T13:50:00Z |
| miri-d8ac7660472017f9 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:6:width=1 [extended] | reused | 2026-10-28T19:32:57Z |
| miri-d8badee6b8481ad5 | sha1 | miri | sha1-padding:90 [extended] | reused | 2026-10-28T12:46:59Z |
| miri-d8c25550248ba650 | md5 | miri | md5-scoped:158 [extended] | reused | 2026-10-28T12:08:55Z |
| miri-d8cadde2d8981712 | kmac | miri | kmac-streamed-setup:58 [routine] | No mapped observation | — |
| miri-d8d646b376e4dca2 | tuplehash | miri | scoped_tuplexof256_differential:6:width=0 [extended] | reused | 2026-10-29T02:24:07Z |
| miri-d9093095c9bdf9d4 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:0 [extended] | passed | 2026-10-29T14:05:58Z |
| miri-d919e9a8062fe75b | sha1 | miri | sha1-bulk:179 [extended] | reused | 2026-10-28T13:01:15Z |
| miri-d92b0d93402ad11d | tuplehash | miri | scoped_tuplexof128_differential:37:width=0 [extended] | passed | 2026-10-29T11:54:09Z |
| miri-d939a83aeb4a9773 | md5 | miri | md5-batch-mask:16 [routine] | passed | 2026-10-19T11:14:44Z |
| miri-d941f0bebb2c700c | tuplehash | miri | scoped_tuplexof256_differential:22:width=0 [extended] | reused | 2026-10-29T02:56:47Z |
| miri-d945890a177702e4 | tuplehash | miri | tuplehash-staging:786 [extended] | reused | 2026-10-28T18:25:37Z |
| miri-d97d19c8a94e4c51 | tuplehash | miri | scoped_tuplexof256_differential:46:width=0 [extended] | reused | 2026-10-29T03:59:12Z |
| miri-d99ffb6c3f696392 | md5 | miri | md5-scoped:192 [extended] | reused | 2026-10-28T12:06:05Z |
| miri-d9a335d8f68a5ad0 | tuplehash | miri | tuplehash-staging:422 [extended] | reused | 2026-10-28T16:29:15Z |
| miri-d9b4ede66e13ee16 | md5 | miri | md5-bulk:89 [extended] | reused | 2026-10-28T11:33:45Z |
| miri-da157d199420a2cd | tuplehash | miri | scoped_tuplexof256_differential:41:width=0 [extended] | passed | 2026-10-29T12:47:56Z |
| miri-da2126ebba5c0697 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:7:width=2 [extended] | reused | 2026-10-28T19:59:05Z |
| miri-da26e83fad8f256e | md5 | miri | md5-batch-mask:92 [extended] | reused | 2026-10-28T12:19:51Z |
| miri-da5b4da8913e9519 | sha2 | miri | -p brynja-hash-sha2 --features batch512-execution --test batch512 batch512_general::derived_iv_work_is_bounded_and_named_identity_is_distinct [remaining suite; inspect skips with show] | passed | 2026-10-19T11:17:17Z |
| miri-da6df19b2dc14297 | tuplehash | miri | scoped_tuplexof128_differential:35:width=2 [extended] | reused | 2026-10-29T02:27:31Z |
| miri-da72112dc1a80ee3 | kmac | miri | kmac-framing:1 [extended] | reused | 2026-10-28T19:46:54Z |
| miri-da8371b8d80f5b69 | sha1 | miri | sha1-scoped:129 [extended] | reused | 2026-10-28T13:20:08Z |
| miri-daaf9b00f530b8e1 | hmac | miri | -p brynja-crypto-cpu-std --features hmac-execution --test hmac [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-dac5867e28261b4e | tuplehash | miri | scoped_tuplexof256_differential:12:width=3 [extended] | reused | 2026-10-29T02:38:28Z |
| miri-dadaf8afb2bbd873 | kmac | miri | kmacxof-official:4 [routine] | passed | 2026-10-19T11:42:29Z |
| miri-daf174ca4c8061ac | tuplehash | miri | tuplehash-staging:569 [extended] | reused | 2026-10-28T17:31:16Z |
| miri-db0057f67f720b68 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:3 [extended] | passed | 2026-10-29T14:09:11Z |
| miri-db02fd6de79cba8e | tuplehash | miri | tuplehash-staging:877 [extended] | reused | 2026-10-28T19:14:59Z |
| miri-db16432f652127ae | tuplehash | miri | tuplehash-staging:592 [extended] | reused | 2026-10-28T17:20:05Z |
| miri-db3ce4eb28cd29b5 | tuplehash | miri | tuplehash-staging:390 [extended] | reused | 2026-10-28T16:18:53Z |
| miri-db3e894f827b2f55 | sha3 | miri | sha3-secret-xof-bits:6 [routine] | passed | 2026-10-19T11:40:20Z |
| miri-db6498d38f11988b | tuplehash | miri | tuplehash-staging:120 [extended] | reused | 2026-10-28T14:47:12Z |
| miri-db69775d49b48772 | legacy_hmac | miri | sha1_short [existing-full] | No mapped observation | — |
| miri-db6d3c4a64737a2a | tuplehash | miri | scoped_tuplexof128_differential:32:width=1 [extended] | reused | 2026-10-29T01:36:57Z |
| miri-db75da01a8c85c1e | tuplehash | miri | tuplehash-staging:517 [extended] | reused | 2026-10-28T17:14:08Z |
| miri-dba5288317b3b158 | kmac | miri | kmac-scoped-lifecycle:8 [routine] | passed | 2026-10-19T11:35:38Z |
| miri-dbc53a1b9c0351ff | tuplehash | miri | scoped_tuplexof256_differential:35:width=1 [extended] | reused | 2026-10-29T04:19:13Z |
| miri-dbcd5cd142e073fb | sha1 | miri | sha1-scoped:97 [extended] | reused | 2026-10-28T13:17:38Z |
| miri-dbd6b8ec3ae5599e | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:37:width=0 [extended] | reused | 2026-10-29T05:42:32Z |
| miri-dbdd6ff9001bae3e | parallelhash | miri | hardened_output_and_workspace_clear_on_drop [routine] | passed | 2026-10-19T17:30:25Z |
| miri-dbe03aff255358ab | md5 | miri | md5-scoped:221 [extended] | reused | 2026-10-28T12:02:44Z |
| miri-dbe90a47644a2e06 | kmac | miri | kmac-streamed-setup:37 [routine] | No mapped observation | — |
| miri-dbf961885578d870 | kmac | miri | kmac-streamed-setup:79 [routine] | No mapped observation | — |
| miri-dbf9a3c5d0129c3e | sha2 | miri | -p brynja-hash-sha2 --test hardened [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-dbfde3b9e80c9641 | tuplehash | miri | scoped_tuplexof256_differential:1:width=2 [extended] | passed | 2026-10-29T12:06:23Z |
| miri-dc127a2f411cfe98 | tuplehash | miri | tuplehash-staging:127 [extended] | reused | 2026-10-28T20:56:25Z |
| miri-dc2218f67f061f07 | md5 | miri | md5-scoped:263 [extended] | reused | 2026-10-28T12:05:30Z |
| miri-dc24a27a356e17be | tuplehash | miri | tuplehash-staging:34 [extended] | reused | 2026-10-28T14:23:12Z |
| miri-dc2952b8d2fa2b51 | sha2 | miri | -p brynja-hash-sha2 --features batch-execution --test batch bounded_batch_lifecycle_smoke [remaining suite; inspect skips with show] | passed | 2026-10-19T11:29:57Z |
| miri-dc2f4ea04cff798a | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:36:width=3 [extended] | reused | 2026-10-28T23:10:45Z |
| miri-dc308648fcf236ab | kmac | miri | kmac-streamed-setup:60 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-dc3428b5a817068d | md5 | miri | md5-batch-mask:237 [extended] | reused | 2026-10-28T12:26:07Z |
| miri-dc3731c06f44cf73 | sha1 | miri | sha1-padding:1 [routine] | passed | 2026-10-19T11:15:27Z |
| miri-dc401cd3b35ffd13 | sha1 | miri | sha1-padding:74 [extended] | reused | 2026-10-28T12:45:27Z |
| miri-dc4a1ac8ffa48626 | tuplehash | miri | tuplehash-staging:586 [extended] | reused | 2026-10-28T17:21:35Z |
| miri-dc816929ce5289ba | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:50:width=3 [extended] | reused | 2026-10-28T21:27:05Z |
| miri-dc8e234b4705f0f5 | sha3 | miri | sha3-fixed-boundaries:11 [extended] | reused | 2026-10-28T13:37:48Z |
| miri-dc9234b277a8bb63 | kmac | miri | kmacxof-official:0 [routine] | passed | 2026-10-19T11:41:21Z |
| miri-dcab7f3b6596a8c3 | sha2 | miri | -p brynja-hash-sha2 --lib buffer_length_rejects_invalid_values_without_mutation [remaining suite; inspect skips with show] | reused | 2026-10-28T13:33:11Z |
| miri-dcabdce793246dac | sha3 | miri | sha3-fixed-bits:9 [routine] | passed | 2026-10-19T11:35:11Z |
| miri-dcc36b3ca953a6a1 | md5 | miri | md5-scoped:102 [extended] | reused | 2026-10-28T12:05:02Z |
| miri-dcc6367e734c19d3 | sha1 | miri | sha1-scoped:257 [extended] | reused | 2026-10-28T13:30:18Z |
| miri-dcdc9a36ae79af6e | md5 | miri | md5-scoped:163 [extended] | reused | 2026-10-28T11:58:17Z |
| miri-dcdf2a592e7f964e | sha2 | miri | -p brynja-hash-sha2 --lib hardened::tests::checked_length_ [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-dcea304fd95087a2 | tuplehash | miri | tuplehash-execution-fixed:4 [routine] | passed | 2026-10-19T12:03:26Z |
| miri-dcf8afd9006bfdf3 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-official:2 [extended] | passed | 2026-10-29T14:11:50Z |
| miri-dcfa2dd2f4fb832e | sha1 | miri | sha1-bulk:104 [extended] | reused | 2026-10-28T12:46:36Z |
| miri-dd005de842a1d26c | kmac | miri | kmac-streamed-setup:85 [routine] | No mapped observation | — |
| miri-dd044431b5319bdf | tuplehash | miri | tuplehash-staging:467 [extended] | reused | 2026-10-28T22:51:21Z |
| miri-dd0e50cc95e28ffb | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:18 [routine] | No mapped observation | — |
| miri-dd14d2791c107758 | md5 | miri | md5-batch-mask:175 [extended] | reused | 2026-10-28T12:21:03Z |
| miri-dd35c9f470728535 | kmac | miri | kmac-streamed-setup:22 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-dd3b62dcf841996e | sha1 | miri | sha1-padding:2 [extended] | reused | 2026-10-28T12:39:24Z |
| miri-dd45a60bdad8c24e | md5 | miri | md5-scoped:274 [extended] | reused | 2026-10-28T12:17:18Z |
| miri-dd5127f384b1461d | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:52:width=3 [extended] | reused | 2026-10-29T00:23:27Z |
| miri-dd5a56037fd13079 | kmac | miri | kmacxof-official:3 [routine] | passed | 2026-10-19T11:56:40Z |
| miri-dd5d3770b30839c8 | tuplehash | miri | scoped_tuplexof256_differential:23:width=4 [extended] | reused | 2026-10-29T03:50:03Z |
| miri-dd79962175eac5aa | sha1 | miri | sha1-bulk:87 [extended] | reused | 2026-10-28T12:52:15Z |
| miri-dd7e32ed73c66852 | md5 | miri | md5-bulk:29 [extended] | reused | 2026-10-28T11:29:38Z |
| miri-dd837ee64519038a | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:40:width=4 [extended] | reused | 2026-10-28T23:22:29Z |
| miri-dd9970bf60333599 | sha3 | miri | sha3-fixed-boundaries:57 [extended] | reused | 2026-10-28T13:39:07Z |
| miri-ddb0e94b4f05df5b | md5 | miri | md5-scoped:189 [extended] | reused | 2026-10-28T12:00:21Z |
| miri-ddb52635579f7deb | tuplehash | miri | tuplehash-staging:503 [extended] | reused | 2026-10-28T23:03:29Z |
| miri-ddbd40769edd037f | tuplehash | miri | scoped_tuplexof128_differential:35:width=3 [extended] | reused | 2026-10-29T02:27:31Z |
| miri-ddd2bfde6a188e86 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:24:width=1 [extended] | reused | 2026-10-28T22:43:23Z |
| miri-dded63eaaf224521 | tuplehash | miri | tuplehash-staging:314 [extended] | reused | 2026-10-28T15:54:34Z |
| miri-ddf3f8a0fbb29488 | tuplehash | miri | tuplehash-staging:511 [extended] | reused | 2026-10-28T23:05:47Z |
| miri-ddf9afbb10b79415 | md5 | miri | md5-scoped:20 [extended] | reused | 2026-10-28T11:54:18Z |
| miri-de08344b908c37e4 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:27 [routine] | No mapped observation | — |
| miri-de0ee534a186e348 | tuplehash | miri | tuplehash-staging:822 [extended] | reused | 2026-10-28T18:37:29Z |
| miri-de1a40289468403a | tuplehash | miri | scoped_tuplexof256_differential:10:width=4 [extended] | reused | 2026-10-29T02:30:56Z |
| miri-de1e562a2fa443f3 | tuplehash | miri | tuplehash-staging:365 [extended] | reused | 2026-10-28T16:22:42Z |
| miri-de465c5b6c529d0c | sha1 | miri | sha1-bulk:71 [extended] | reused | 2026-10-28T12:50:51Z |
| miri-de4891f0cbd98804 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:1 [extended] | passed | 2026-10-29T14:08:50Z |
| miri-de4a7678e18cc430 | tuplehash | miri | scoped_tuplexof256_differential:7:width=0 [extended] | reused | 2026-10-29T03:16:31Z |
| miri-de51b19f831c8a9c | sha1 | miri | sha1-scoped:107 [extended] | reused | 2026-10-28T13:23:36Z |
| miri-de52398e8f713f4c | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:8:width=2 [extended] | reused | 2026-10-28T19:39:57Z |
| miri-de53166d5939d3e9 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:0 [extended] | passed | 2026-10-29T14:54:46Z |
| miri-de617a1f83f4f14b | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:4 [extended] | passed | 2026-10-29T13:54:55Z |
| miri-de6c3e31fd36865f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:7:width=1 [extended] | reused | 2026-10-28T22:39:20Z |
| miri-de7b711d72dea915 | sha1 | miri | sha1-bulk:134 [extended] | reused | 2026-10-28T12:50:53Z |
| miri-de8179053a1e5b6a | sha1 | miri | sha1-scoped:250 [routine] | passed | 2026-10-19T11:17:13Z |
| miri-deab837cb9d5a1ff | hmac | miri | sha3_224 [extended] | passed | 2026-10-29T15:19:40Z |
| miri-dec3bd359fea290f | md5 | miri | md5-scoped:125 [extended] | reused | 2026-10-28T11:55:59Z |
| miri-ded2ec71e1570399 | sha1 | miri | sha1-bulk:59 [extended] | reused | 2026-10-28T12:49:57Z |
| miri-dee223a9a19cb5e0 | sha1 | miri | sha1-padding:42 [extended] | reused | 2026-10-28T12:42:36Z |
| miri-dee38eac8b180725 | sha1 | miri | sha1-bulk:30 [extended] | reused | 2026-10-28T12:42:37Z |
| miri-dee7bf2f72169f19 | kmac | miri | kmac-scoped-lifecycle:17 [routine] | passed | 2026-10-19T15:33:35Z |
| miri-def6d5ad188e80ea | static_cpu | miri | --manifest-path assurance/static-cpu-execution/Cargo.toml --lib [remaining suite; inspect skips with show] | passed | 2026-10-29T15:02:06Z |
| miri-defd594b2d474dd0 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:20:width=4 [extended] | reused | 2026-10-28T20:04:54Z |
| miri-deff064b62b60f3d | sha2 | miri | -p brynja-hash-sha2 --test sha512 every_padding_boundary_matches_independent_expected_results [remaining suite; inspect skips with show] | passed | 2026-10-19T11:35:06Z |
| miri-df14dfb57c87ce74 | sha1 | miri | sha1-scoped:150 [extended] | reused | 2026-10-28T13:14:03Z |
| miri-df15fc254841bbaf | md5 | miri | md5-bulk:59 [extended] | reused | 2026-10-28T11:31:56Z |
| miri-df166ec97c64f933 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:16:width=0 [extended] | reused | 2026-10-28T22:25:09Z |
| miri-df1c30cb5da16f81 | tuplehash | miri | scoped_tuplexof256_differential:36:width=3 [extended] | reused | 2026-10-29T03:35:29Z |
| miri-df229cc0853036bf | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:20:width=2 [extended] | reused | 2026-10-28T20:04:54Z |
| miri-df386abc97210462 | tuplehash | miri | scoped_tuplexof256_differential:1:width=0 [extended] | passed | 2026-10-29T12:05:43Z |
| miri-df4450abd8dbd1b9 | sha1 | miri | sha1-padding:43 [extended] | reused | 2026-10-28T12:32:53Z |
| miri-df49870636152f8e | kmac | miri | kmac-framing:0 [extended] | reused | 2026-10-28T13:52:54Z |
| miri-df537fced2940446 | sha2 | miri | -p brynja-hash-sha2 --test sha224 official_short_and_long_vectors_match_fips_and_nist_cavp [remaining suite; inspect skips with show] | reused | 2026-10-28T13:27:59Z |
| miri-df60f0e6e3808c49 | sha1 | miri | sha1-padding:23 [extended] | reused | 2026-10-28T12:31:22Z |
| miri-df6203905d2bac69 | tuplehash | miri | tuplehash-staging:501 [extended] | reused | 2026-10-28T17:08:21Z |
| miri-df92c51004cdeedc | md5 | miri | md5-batch-mask:223 [extended] | reused | 2026-10-28T12:25:02Z |
| miri-df9513003629615d | md5 | miri | md5-batch-mask:182 [extended] | reused | 2026-10-28T12:32:26Z |
| miri-df9535b0aac254f0 | sha1 | miri | sha1-bulk:61 [extended] | reused | 2026-10-28T12:54:57Z |
| miri-df954189f85d9f69 | parallelhash | miri | -p brynja-hash-parallel --tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-dfa1839748b69f8f | md5 | miri | md5-scoped:72 [extended] | reused | 2026-10-28T11:57:46Z |
| miri-dfa7c58bfaafeddd | tuplehash | miri | tuplehash-staging:327 [extended] | reused | 2026-10-28T22:04:17Z |
| miri-dfaa81d5e84e5b5f | tuplehash | miri | tuplehash-staging:668 [extended] | reused | 2026-10-28T17:44:48Z |
| miri-dfb8495559373ea1 | sha1 | miri | sha1-padding:45 [extended] | reused | 2026-10-28T12:31:35Z |
| miri-dfb9b5e4ca2d16d6 | md5 | miri | md5-scoped:36 [extended] | reused | 2026-10-28T11:55:23Z |
| miri-dfbbb2db77d88af3 | tuplehash | miri | tuplehash-staging:739 [extended] | reused | 2026-10-29T00:22:42Z |
| miri-dfd0eeb97cc30653 | sha2 | miri | -p brynja-hash-sha2 --features runtime-execution,general-sha512-t --test execution bounded_execution_lifecycle_smoke [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-dfd35d0ffe0139ba | sha1 | miri | sha1-scoped:151 [extended] | reused | 2026-10-28T13:26:57Z |
| miri-dfda7fad314ed604 | md5 | miri | md5-bulk:19 [extended] | reused | 2026-10-28T11:29:18Z |
| miri-dff00611286a6045 | tuplehash | miri | tuplehash-staging:859 [extended] | reused | 2026-10-29T01:03:10Z |
| miri-dff74f45d1cf7382 | sha1 | miri | sha1-bulk:207 [extended] | reused | 2026-10-28T13:04:32Z |
| miri-dffa79f53c87d869 | sha1 | miri | sha1-bulk:222 [extended] | reused | 2026-10-28T13:00:11Z |
| miri-e0103c339f9504c2 | tuplehash | miri | tuplehash-staging:447 [extended] | reused | 2026-10-28T22:45:09Z |
| miri-e019076f226aa87e | sha1 | miri | sha1-padding:33 [extended] | reused | 2026-10-28T12:30:40Z |
| miri-e019bf8d00214370 | sha1 | miri | sha1-bulk:50 [extended] | reused | 2026-10-28T12:43:53Z |
| miri-e026d847084b96e3 | sha1 | miri | sha1-padding:8 [extended] | reused | 2026-10-28T12:34:57Z |
| miri-e02ec9205f550b08 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:45:width=0 [extended] | reused | 2026-10-29T06:07:36Z |
| miri-e0401bd640bce0a0 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:17:width=3 [extended] | reused | 2026-10-29T04:53:46Z |
| miri-e05a66fad61f8178 | sha1 | miri | sha1-scoped:274 [extended] | reused | 2026-10-28T13:24:10Z |
| miri-e05fd4b1f5c7db5f | tuplehash | miri | tuplehash-staging:58 [extended] | reused | 2026-10-28T14:30:34Z |
| miri-e072844ffd4d400d | md5 | miri | md5-scoped:88 [extended] | reused | 2026-10-28T11:58:54Z |
| miri-e07d2b1bda2b40bc | sha1 | miri | sha1-bulk:98 [extended] | reused | 2026-10-28T12:47:45Z |
| miri-e0d84ee9d9c6d0f9 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof256_matches_and_clears:5 [extended] | passed | 2026-10-29T13:30:59Z |
| miri-e0d91c7bbcaa5abb | sha3 | miri | sha3-secret-xof-bits:4 [extended] | reused | 2026-10-28T13:58:06Z |
| miri-e0f2c3cc0987f5d8 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_unwind_reuse:0 [extended] | passed | 2026-10-29T14:20:14Z |
| miri-e102dd86f1c926ef | sha1 | miri | sha1-scoped:203 [extended] | reused | 2026-10-28T13:31:01Z |
| miri-e1048ce2feb4f81d | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:9 [extended] | passed | 2026-10-29T13:47:05Z |
| miri-e11946fe681b1171 | tuplehash | miri | tuplehash-staging:829 [extended] | reused | 2026-10-28T18:59:13Z |
| miri-e12f7bbeaa341885 | kmac | miri | kmac-streamed-setup:32 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-e1355cdf176923c7 | tuplehash | miri | tuplehash-staging:575 [extended] | reused | 2026-10-28T23:27:01Z |
| miri-e140435615ada396 | tuplehash | miri | tuplehash-staging:461 [extended] | reused | 2026-10-28T16:55:38Z |
| miri-e143361070f45685 | kmac | miri | kmac-streamed-setup:92 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-e14b511b8d5d0e9b | md5 | miri | md5-scoped:63 [extended] | reused | 2026-10-28T11:51:30Z |
| miri-e15e342ad99987fd | tuplehash | miri | scoped_tuplexof256_differential:13:width=3 [extended] | passed | 2026-10-29T11:59:07Z |
| miri-e15ed6d1a6041f1b | sha1 | miri | sha1-bulk:184 [extended] | reused | 2026-10-28T12:54:21Z |
| miri-e1693e7c0ab6b39a | md5 | miri | md5-scoped:21 [extended] | reused | 2026-10-28T11:48:59Z |
| miri-e17f21672e435a21 | md5 | miri | md5-padding:34 [extended] | reused | 2026-10-28T11:20:19Z |
| miri-e18d5367b119d3c3 | sha1 | miri | sha1-scoped:195 [extended] | reused | 2026-10-28T13:30:21Z |
| miri-e197127d78971dd0 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:41:width=1 [extended] | reused | 2026-10-29T03:15:49Z |
| miri-e19811eff25d3f44 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:5:width=1 [extended] | reused | 2026-10-29T01:50:26Z |
| miri-e19ab80f3d602dcb | tuplehash | miri | tuplehash-staging:488 [extended] | reused | 2026-10-28T16:46:48Z |
| miri-e19e39199b910973 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:36 [extended] | passed | 2026-10-29T15:00:32Z |
| miri-e1aa7d822bfe75f1 | md5 | miri | md5-bulk:111 [extended] | reused | 2026-10-28T11:35:38Z |
| miri-e1b7bf643500d2c5 | tuplehash | miri | tuplehash-staging:845 [extended] | reused | 2026-10-28T19:04:12Z |
| miri-e1bb68cc2f20c020 | md5 | miri | md5-batch-mask:78 [extended] | reused | 2026-10-28T12:24:08Z |
| miri-e1ced195f863834b | tuplehash | miri | tuplehash-staging:123 [extended] | reused | 2026-10-28T20:55:28Z |
| miri-e1d1c9481074f64c | sha1 | miri | -p brynja-legacy-sha1 --test api [remaining suite; inspect skips with show] | reused | 2026-10-28T12:29:31Z |
| miri-e1d4d25b62f75e63 | tuplehash | miri | scoped_tuplexof256_differential:5:width=1 [extended] | passed | 2026-10-29T11:54:55Z |
| miri-e1e4985e9e6720e2 | sha1 | miri | sha1-scoped:63 [extended] | reused | 2026-10-28T13:20:19Z |
| miri-e1eb2ad1e6c23358 | sha1 | miri | sha1-bulk:232 [extended] | reused | 2026-10-28T12:59:56Z |
| miri-e1f4337ed356cb01 | md5 | miri | md5-batch-mask:251 [extended] | reused | 2026-10-28T12:27:23Z |
| miri-e1f4d6a116290a0a | kmac | miri | kmac-scoped-xof-lifecycle:5 [routine] | passed | 2026-10-19T11:52:22Z |
| miri-e1fb2583426c16a2 | md5 | miri | md5-padding:5 [extended] | reused | 2026-10-28T11:28:12Z |
| miri-e209bf97eccabec3 | sha1 | miri | -p brynja-legacy-sha1 --features execution --test execution revocation_empty_updates_capacity_and_finalization_fail_closed [remaining suite; inspect skips with show] | passed | 2026-10-19T11:27:22Z |
| miri-e21ba9f884312664 | tuplehash | miri | tuplehash-staging:248 [extended] | reused | 2026-10-28T15:29:37Z |
| miri-e22886c81bd9a019 | sha1 | miri | sha1-bulk:192 [extended] | reused | 2026-10-28T12:55:14Z |
| miri-e22bc420d47d1422 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:630 [routine] | No mapped observation | — |
| miri-e23e4b18193e3f69 | sha1 | miri | sha1-scoped:243 [extended] | reused | 2026-10-28T13:34:25Z |
| miri-e23eb60fa0eab8b0 | tuplehash | miri | tuplehash-staging:871 [extended] | reused | 2026-10-29T01:07:36Z |
| miri-e242896b2710b9dc | md5 | miri | md5-batch-mask:204 [extended] | reused | 2026-10-28T12:28:42Z |
| miri-e254aff88495858b | hmac | miri | sha384 [routine] | No mapped observation | — |
| miri-e280f1df9841a5f6 | tuplehash | miri | tuplehash-staging:184 [extended] | reused | 2026-10-28T15:08:34Z |
| miri-e28f54220c3eec70 | kmac | miri | kmac-streamed-setup:55 [routine] | No mapped observation | — |
| miri-e294ef06708d6fa7 | tuplehash | miri | tuplehash-staging:98 [extended] | reused | 2026-10-28T14:43:45Z |
| miri-e2d2fbb15ad84261 | kmac | miri | kmac128_mismatch_and_exact_width [routine] | No mapped observation | — |
| miri-e30281998e59ff22 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:8 [routine] | No mapped observation | — |
| miri-e30b4c25f2efe310 | sha1 | miri | sha1-bulk:233 [extended] | reused | 2026-10-28T13:12:31Z |
| miri-e341f879f7926cc2 | tuplehash | miri | tuplehash-staging:713 [extended] | reused | 2026-10-28T18:20:08Z |
| miri-e34ae376e1891070 | sha1 | miri | sha1-padding:119 [extended] | reused | 2026-10-28T12:39:41Z |
| miri-e350d5698c088e31 | md5 | miri | md5-padding:8 [extended] | reused | 2026-10-28T11:18:37Z |
| miri-e3525b1438089c79 | sha3 | miri | sha3-fixed-boundaries:40 [extended] | reused | 2026-10-28T13:49:52Z |
| miri-e35895d3e487b80b | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:37:width=4 [extended] | reused | 2026-10-29T03:03:13Z |
| miri-e35947af8c24e32c | sha1 | miri | sha1-scoped:270 [extended] | reused | 2026-10-28T13:23:51Z |
| miri-e36e6f76243cc203 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:28:width=2 [extended] | reused | 2026-10-28T22:52:29Z |
| miri-e38e7edd0934d1ca | tuplehash | miri | scoped_tuplexof128_differential:2:width=4 [extended] | reused | 2026-10-29T00:29:11Z |
| miri-e39321e69415f4b3 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:24 [routine] | No mapped observation | — |
| miri-e3991d914e25d343 | sha1 | miri | sha1-padding:63 [extended] | reused | 2026-10-28T12:34:31Z |
| miri-e39df7bda50239d4 | md5 | miri | md5-bulk:67 [extended] | reused | 2026-10-28T11:32:29Z |
| miri-e3a325864dd382e0 | md5 | miri | md5-bulk:168 [extended] | reused | 2026-10-28T11:49:48Z |
| miri-e3bb2ffbd42405af | kmac | miri | kmac-scoped-lifecycle:2 [routine] | passed | 2026-10-19T11:41:03Z |
| miri-e3bbc0cb54d2d020 | tuplehash | miri | scoped_tuplexof256_differential:34:width=1 [extended] | reused | 2026-10-29T03:25:12Z |
| miri-e3bfb9b6b932cf2c | md5 | miri | md5-scoped:91 [extended] | reused | 2026-10-28T11:53:24Z |
| miri-e3d86b3ea7e7103c | tuplehash | miri | scoped_tuplexof128_differential:7:width=2 [extended] | reused | 2026-10-29T01:24:29Z |
| miri-e3dafee6140a3c9e | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:13 [extended] | passed | 2026-10-29T13:41:26Z |
| miri-e3f1278268f04c4d | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:1 [extended] | passed | 2026-10-29T13:52:16Z |
| miri-e40893e19c8f62b7 | tuplehash | miri | tuplehash-staging:275 [extended] | reused | 2026-10-28T21:46:45Z |
| miri-e40f4370cc5f6655 | md5 | miri | md5-padding:21 [extended] | reused | 2026-10-28T11:29:16Z |
| miri-e416826ef1dbadd2 | tuplehash | miri | tuplehash-staging:696 [extended] | reused | 2026-10-28T17:53:44Z |
| miri-e41793100939e281 | md5 | miri | md5-scoped:252 [extended] | reused | 2026-10-28T12:10:24Z |
| miri-e41803e1cddffd6e | sha1 | miri | sha1-bulk:121 [extended] | reused | 2026-10-28T13:00:00Z |
| miri-e41ca4eff39b14fc | sha1 | miri | sha1-scoped:0 [routine] | passed | 2026-10-19T11:29:40Z |
| miri-e42f967a13abd86f | sha1 | miri | sha1-scoped:111 [extended] | reused | 2026-10-28T13:23:54Z |
| miri-e4356a4f1ecc7171 | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join128:0 [routine] | No mapped observation | — |
| miri-e43acfd4344a2291 | md5 | miri | md5-batch-mask:242 [extended] | reused | 2026-10-28T12:37:28Z |
| miri-e43f68927d29f6b0 | tuplehash | miri | scoped_tuplexof128_differential:34:width=4 [extended] | reused | 2026-10-29T01:36:07Z |
| miri-e453ace5d5db44f7 | legacy_hmac | miri | md5_short [routine] | No mapped observation | — |
| miri-e45944a4fe3f1c2b | sha1 | miri | sha1-padding:0 [extended] | reused | 2026-10-28T12:34:17Z |
| miri-e4743eaebaebcddf | md5 | miri | md5-scoped:136 [extended] | reused | 2026-10-28T12:02:14Z |
| miri-e4751c19e68aaa1e | md5 | miri | md5-bulk:176 [extended] | reused | 2026-10-28T11:50:29Z |
| miri-e475fe32451e0619 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:114 [extended] | passed | 2026-10-29T13:58:09Z |
| miri-e4772d3d2eaf7489 | sha1 | miri | sha1-bulk:236 [extended] | reused | 2026-10-28T13:00:23Z |
| miri-e4789cdfd9ac440a | tuplehash | miri | tuplehash-staging:653 [extended] | reused | 2026-10-28T17:59:32Z |
| miri-e4a3a47d3fd2c59c | sha1 | miri | -p brynja-legacy-sha1 --features hardened-execution --test hardened_execution revocation_cancellation_and_output_failures [remaining suite; inspect skips with show] | passed | 2026-10-19T11:30:28Z |
| miri-e4b756ca2f3e3e7d | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:39:width=4 [extended] | reused | 2026-10-28T21:12:11Z |
| miri-e4bdbb62ac0e5e96 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:35:width=4 [extended] | reused | 2026-10-28T23:42:23Z |
| miri-e4cbc784e75e6584 | tuplehash | miri | scoped_tuplexof256_differential:21:width=0 [extended] | passed | 2026-10-29T12:30:49Z |
| miri-e4cfc2f25f69743c | tuplehash | miri | tuplehash-staging:574 [extended] | reused | 2026-10-28T17:17:43Z |
| miri-e4d9759e0deeb02f | tuplehash | miri | scoped_tuplexof256_differential:20:width=4 [extended] | reused | 2026-10-29T02:57:28Z |
| miri-e4dfd4e2677d4d83 | md5 | miri | md5-scoped:135 [extended] | reused | 2026-10-28T11:56:24Z |
| miri-e4eb0eb695c5ad19 | tuplehash | miri | tuplehash-staging:78 [extended] | reused | 2026-10-28T14:36:50Z |
| miri-e503d10c9f884b9a | md5 | miri | md5-scoped:66 [routine] | passed | 2026-10-19T11:29:36Z |
| miri-e52872bc16e20d92 | tuplehash | miri | tuplehash-staging:882 [extended] | reused | 2026-10-28T18:56:18Z |
| miri-e5347b9079caeb4a | tuplehash | miri | tuplehash-staging:313 [extended] | reused | 2026-10-28T16:05:37Z |
| miri-e544546c88d085bb | sha1 | miri | sha1-padding:49 [extended] | reused | 2026-10-28T12:31:53Z |
| miri-e548536be5cf0811 | sha1 | miri | sha1-padding:58 [extended] | reused | 2026-10-28T12:43:56Z |
| miri-e55e30012453ec04 | sha1 | miri | sha1-bulk:9 [extended] | reused | 2026-10-28T12:51:29Z |
| miri-e55e6adf2ec63962 | sha3 | miri | sha3-fixed-bits:9 [extended] | reused | 2026-10-28T13:42:20Z |
| miri-e5862cf4b49b0a58 | md5 | miri | md5-bulk:235 [extended] | reused | 2026-10-28T11:45:38Z |
| miri-e599f04b4dff6d0e | sha3 | miri | -p brynja-hash-sha3 --test sha3_384 suffix_and_rate_boundaries_have_exact_digests [remaining suite; inspect skips with show] | reused | 2026-10-28T13:29:26Z |
| miri-e59ec3b136949aa8 | sha3 | miri | -p brynja-hash-sha3 --lib final_bit_output_clears_the_exact_reader_source [remaining suite; inspect skips with show] | reused | 2026-10-28T13:35:51Z |
| miri-e5a7549318ccf920 | md5 | miri | md5-scoped:70 [extended] | reused | 2026-10-28T12:02:48Z |
| miri-e5b9cfc32ba90a9c | tuplehash | miri | exact_length_streaming_matches_whole_items [extended] | passed | 2026-10-29T12:58:10Z |
| miri-e5bd3f85fb1fc972 | tuplehash | miri | scoped_tuplexof256_differential:35:width=2 [extended] | reused | 2026-10-29T04:19:13Z |
| miri-e5ca89ff6d116d56 | tuplehash | miri | tuplehash-staging:500 [extended] | reused | 2026-10-28T16:50:51Z |
| miri-e5cd473fcc1a3067 | md5 | miri | md5-bulk:136 [extended] | reused | 2026-10-28T11:47:12Z |
| miri-e5d504f8e7c8ebff | tuplehash | miri | scoped_tuplexof128_differential:20:width=3 [extended] | reused | 2026-10-29T01:08:19Z |
| miri-e5e46a9ef9e4aa50 | hmac | miri | general_511 [extended] | passed | 2026-10-29T15:22:30Z |
| miri-e5f5d2c5db02e225 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-domains:0 [routine] | No mapped observation | — |
| miri-e5f8f2d7a3cbbd21 | tuplehash | miri | scoped_tuplexof256_differential:6:width=4 [extended] | reused | 2026-10-29T02:24:07Z |
| miri-e606b7de2c7d4b4b | tuplehash | miri | tuplehash-staging:623 [extended] | reused | 2026-10-28T23:43:34Z |
| miri-e629b302641c8f5f | tuplehash | miri | tuplehash-staging:337 [extended] | reused | 2026-10-28T16:13:18Z |
| miri-e6456fd73c64032f | tuplehash | miri | tuplehash-staging:22 [extended] | reused | 2026-10-28T14:18:42Z |
| miri-e6719b62b8d226e9 | kmac | miri | kmac-framing:4 [extended] | reused | 2026-10-28T13:53:50Z |
| miri-e676a9d558cf877c | md5 | miri | md5-scoped:201 [extended] | reused | 2026-10-28T12:01:15Z |
| miri-e6783234e8137609 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:18 [routine] | No mapped observation | — |
| miri-e680c8afd1a6245a | md5 | miri | md5-bulk:14 [extended] | reused | 2026-10-28T11:33:20Z |
| miri-e68b06132f42eaa4 | kmac | miri | kmac-streamed-setup:31 [routine] | No mapped observation | — |
| miri-e69caf1500b341f5 | tuplehash | miri | scoped_tuplexof256_differential:1:width=4 [extended] | passed | 2026-10-29T12:07:34Z |
| miri-e6b269168da39fa1 | md5 | miri | md5-batch-mask:32 [extended] | reused | 2026-10-28T12:15:20Z |
| miri-e6b2787647e0425a | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:54:width=2 [extended] | reused | 2026-10-28T21:49:32Z |
| miri-e6bafbb6b18d64a0 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:9 [extended] | passed | 2026-10-29T13:36:24Z |
| miri-e6c5c99cb940b384 | kmac | miri | kmac-streamed-setup:84 [routine] | No mapped observation | — |
| miri-e6cb2fd280ce045b | tuplehash | miri | tuplehash-staging:427 [extended] | reused | 2026-10-28T22:37:57Z |
| miri-e6ce290d058a4e03 | tuplehash | miri | tuplehash-execution-fixed:6 [routine] | passed | 2026-10-19T11:57:23Z |
| miri-e6de73db82169ca3 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:20:width=1 [extended] | reused | 2026-10-28T20:04:54Z |
| miri-e6e693c168bdf7de | tuplehash | miri | scoped_tuplexof128_differential:18:width=3 [extended] | reused | 2026-10-29T00:58:05Z |
| miri-e6e709edbbf8dac2 | tuplehash | miri | tuplehash-staging:416 [extended] | reused | 2026-10-28T16:24:12Z |
| miri-e6fc66a638200064 | md5 | miri | md5-padding:28 [extended] | reused | 2026-10-28T11:20:06Z |
| miri-e7015916229b0e91 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel_xof128_matches_and_clears:36 [extended] | passed | 2026-10-29T12:57:01Z |
| miri-e7105d319239569b | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:228 [routine] | No mapped observation | — |
| miri-e712a8301d2f2aba | md5 | miri | md5-batch-mask:234 [extended] | reused | 2026-10-28T12:36:45Z |
| miri-e71399c20c6071f2 | tuplehash | miri | tuplehash-staging:7 [extended] | reused | 2026-10-28T20:16:51Z |
| miri-e714500408f5b40b | sha1 | miri | -p brynja-legacy-sha1 --features hardened-execution --lib hardened_execution::stream::tests [remaining suite; inspect skips with show] | passed | 2026-10-19T11:33:24Z |
| miri-e718df798927c43e | sha1 | miri | sha1-bulk:77 [extended] | reused | 2026-10-28T12:56:19Z |
| miri-e71dc548d550c71d | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:52:width=0 [extended] | reused | 2026-10-28T21:49:46Z |
| miri-e71f546df36d195d | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:35:width=2 [extended] | reused | 2026-10-28T23:42:23Z |
| miri-e7274e682957c32f | tuplehash | miri | tuplehash-staging:325 [extended] | reused | 2026-10-28T16:10:02Z |
| miri-e7289474f961984b | tuplehash | miri | scoped_tuplexof256_differential:9:width=2 [extended] | passed | 2026-10-29T12:11:34Z |
| miri-e734583a07800f29 | tuplehash | miri | tuplehash-staging:242 [extended] | reused | 2026-10-28T15:30:42Z |
| miri-e735781558037e79 | sha1 | miri | sha1-bulk:131 [extended] | reused | 2026-10-28T12:56:12Z |
| miri-e737a797d98569c1 | sha3 | miri | -p brynja-hash-sha3 --features static-execution --lib execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-e75a73b89789caf4 | md5 | miri | -p brynja-legacy-md5 --features cpu --lib [remaining suite; inspect skips with show] | passed | 2026-10-19T11:28:31Z |
| miri-e761d30f8fa6af08 | md5 | miri | -p brynja-legacy-md5 --features execution --test execution callback_unwind_is_terminal_and_transactional [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-e76ed167702f2c7a | tuplehash | miri | tuplehash-staging:894 [extended] | reused | 2026-10-28T19:00:07Z |
| miri-e771a5480b6aa5cc | tuplehash | miri | tuplehash-staging:200 [extended] | reused | 2026-10-28T15:13:46Z |
| miri-e7791bf37d5f8d43 | sha3 | miri | sha3-fixed-bits:0 [extended] | reused | 2026-10-28T13:54:29Z |
| miri-e79969a2e51bcd89 | tuplehash | miri | tuplehash-staging:588 [extended] | reused | 2026-10-28T17:18:46Z |
| miri-e7a47c7e60458f00 | tuplehash | miri | scoped_tuplexof256_differential:0:width=3 [extended] | reused | 2026-10-29T02:17:57Z |
| miri-e7aaef0ecd3a7ae5 | md5 | miri | md5-bulk:127 [extended] | reused | 2026-10-28T11:36:49Z |
| miri-e7b401ab5732b6c5 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:10:width=4 [extended] | reused | 2026-10-28T22:09:09Z |
| miri-e7b952364010133e | tuplehash | miri | tuplehash-staging:35 [extended] | reused | 2026-10-28T20:26:01Z |
| miri-e7d4f02d23a70a12 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:2:width=3 [extended] | reused | 2026-10-28T21:56:04Z |
| miri-e7e0605a878f7cd7 | kmac | miri | kmac-streamed-setup:17 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-e7e1ee70987ab802 | tuplehash | miri | scoped_tuplexof256_differential:5:width=4 [extended] | passed | 2026-10-29T12:10:10Z |
| miri-e81c1ce73f07904b | md5 | miri | md5-padding:91 [extended] | reused | 2026-10-28T11:29:31Z |
| miri-e81f90c1d8956f67 | tuplehash | miri | tuplehash-staging:356 [extended] | reused | 2026-10-28T16:04:49Z |
| miri-e83ecfc962218d6b | md5 | miri | md5-padding:20 [extended] | reused | 2026-10-28T11:19:30Z |
| miri-e83f9699ee2d6ca6 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:47:width=2 [extended] | reused | 2026-10-29T00:17:25Z |
| miri-e84e457bff505f60 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:14:width=1 [extended] | reused | 2026-10-28T22:15:42Z |
| miri-e8707bafa2aef529 | sha3 | miri | sha3-fixed-boundaries:51 [extended] | reused | 2026-10-28T13:43:21Z |
| miri-e87ae8a2b61bcda1 | tuplehash | miri | tuplehash-staging:842 [extended] | reused | 2026-10-28T18:43:31Z |
| miri-e88e9889d4198ad4 | sha3 | miri | sha3-fixed-bits:24 [extended] | reused | 2026-10-28T13:56:55Z |
| miri-e8998f1b9afd436c | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:49:width=4 [extended] | reused | 2026-10-29T03:52:14Z |
| miri-e8a3e1b8131e3b02 | tuplehash | miri | scoped_tuplexof128_differential:35:width=0 [extended] | reused | 2026-10-29T02:27:31Z |
| miri-e8a868f2d7537550 | tuplehash | miri | tuplehash-staging:792 [extended] | reused | 2026-10-28T18:23:46Z |
| miri-e8a89397389f070d | sha3 | miri | sha3-fixed-boundaries:27 [routine] | passed | 2026-10-19T11:33:25Z |
| miri-e8af65719f4b07f2 | md5 | miri | md5-batch-mask:2 [extended] | reused | 2026-10-28T12:18:24Z |
| miri-e8c9a139b6b4b69a | tuplehash | miri | scoped_tuplexof256_differential:20:width=2 [extended] | reused | 2026-10-29T02:57:28Z |
| miri-e8d9126c3e6e0da9 | sha1 | miri | sha1-scoped:1 [extended] | reused | 2026-10-28T13:10:50Z |
| miri-e8fecf026bc2d1ef | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:52:width=2 [extended] | reused | 2026-10-28T21:49:46Z |
| miri-e90034b12947e2ab | tuplehash | miri | scoped_tuplexof128_differential:16:width=4 [extended] | reused | 2026-10-29T00:58:58Z |
| miri-e923f35e4e5c975a | tuplehash | miri | tuplehash-staging:795 [extended] | reused | 2026-10-29T00:41:36Z |
| miri-e927940668460a1f | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:9 [extended] | passed | 2026-10-29T13:53:37Z |
| miri-e92c2f00a946c2b0 | kmac | miri | kmac-streamed-setup:99 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-e92d54ff7a0d6e68 | md5 | miri | md5-scoped:137 [extended] | reused | 2026-10-28T11:56:48Z |
| miri-e93089c759c3a1ae | tuplehash | miri | scoped_tuplexof256_differential:11:width=0 [extended] | reused | 2026-10-29T03:23:30Z |
| miri-e933dea246fe2cc8 | hmac | miri | sha512_256 [extended] | passed | 2026-10-29T15:02:48Z |
| miri-e948d4d089858ff1 | tuplehash | miri | tuplehash-staging:90 [extended] | reused | 2026-10-28T14:41:30Z |
| miri-e949bd849ddc5cbd | tuplehash | miri | tuplehash-staging:192 [routine] | passed | 2026-10-19T15:49:43Z |
| miri-e94c2b232bc875bf | tuplehash | miri | tuplehash-staging:239 [extended] | reused | 2026-10-28T21:34:12Z |
| miri-e95524e683b93688 | md5 | miri | md5-bulk:164 [extended] | reused | 2026-10-28T11:49:28Z |
| miri-e95688520753a972 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:42:width=0 [extended] | reused | 2026-10-28T20:52:59Z |
| miri-e97518e6731fe38a | sha1 | miri | sha1-bulk:28 [extended] | reused | 2026-10-28T12:40:50Z |
| miri-e975f6360d229f66 | tuplehash | miri | tuplehash-staging:238 [extended] | reused | 2026-10-28T15:29:22Z |
| miri-e98543ba403f2be6 | md5 | miri | md5-batch-mask:244 [extended] | reused | 2026-10-28T12:32:02Z |
| miri-e9934bb9183dfe9f | tuplehash | miri | tuplehash-staging:677 [extended] | reused | 2026-10-28T18:07:37Z |
| miri-e9ab74aebd86de4d | tuplehash | miri | tuplehash-staging:298 [extended] | reused | 2026-10-28T15:48:56Z |
| miri-e9b7a075fc8923fc | tuplehash | miri | scoped_tuplexof128_differential:19:width=0 [extended] | reused | 2026-10-29T01:48:20Z |
| miri-e9ba0a983feec651 | tuplehash | miri | tuplehash-staging:520 [extended] | reused | 2026-10-28T16:56:56Z |
| miri-e9bccd76a5f16df4 | kmac | miri | kmac-scoped-lifecycle:5 [routine] | passed | 2026-10-19T15:29:58Z |
| miri-e9bfa3dbb6ca1315 | tuplehash | miri | tuplehash-staging:69 [extended] | reused | 2026-10-28T14:44:08Z |
| miri-e9db8ea8251e5441 | sha3 | miri | sha3-fixed-boundaries:19 [routine] | passed | 2026-10-19T11:26:52Z |
| miri-e9df96e82e1b2747 | tuplehash | miri | tuplehash-staging:169 [extended] | reused | 2026-10-28T15:16:58Z |
| miri-e9e05b6932440beb | kmac | miri | kmac-scoped-xof-lifecycle:14 [extended] | reused | 2026-10-28T14:03:55Z |
| miri-e9ebf6083cf52d46 | tuplehash | miri | tuplehash-staging:763 [extended] | reused | 2026-10-29T00:30:48Z |
| miri-e9f9338d2946648a | tuplehash | miri | scoped_tuplexof128_differential:37:width=4 [extended] | passed | 2026-10-29T11:56:37Z |
| miri-ea12821de13b82b6 | md5 | miri | md5-scoped:69 [extended] | reused | 2026-10-28T11:52:08Z |
| miri-ea236984240bb6b4 | tuplehash | miri | scoped_tuplexof128_differential:39:width=1 [extended] | reused | 2026-10-29T02:37:19Z |
| miri-ea2990a505d416fb | sha1 | miri | sha1-scoped:114 [extended] | reused | 2026-10-28T13:11:09Z |
| miri-ea2aed872f9f2c8c | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:44:width=4 [extended] | reused | 2026-10-28T21:05:12Z |
| miri-ea383c47958af390 | sha3 | miri | -p brynja-hash-sha3 --test shake128 suffix_and_rate_boundaries_have_exact_output [remaining suite; inspect skips with show] | passed | 2026-10-19T11:26:08Z |
| miri-ea5b115402b28d53 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-official:4 [routine] | No mapped observation | — |
| miri-ea63c92b31c27fd1 | md5 | miri | md5-bulk:46 [extended] | reused | 2026-10-28T11:35:26Z |
| miri-ea7b700fcc68630c | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:44:width=4 [extended] | reused | 2026-10-28T23:34:09Z |
| miri-ea88014218ef3b01 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:35:width=0 [extended] | reused | 2026-10-28T23:42:23Z |
| miri-ea9e5c884a8941ae | tuplehash | miri | scoped_tuplexof128_differential:45:width=1 [extended] | passed | 2026-10-29T11:51:05Z |
| miri-eaaf85638da36ac3 | tuplehash | miri | tuplehash-staging:607 [extended] | reused | 2026-10-28T23:38:12Z |
| miri-eabcdf454d9c8189 | tuplehash | miri | scoped_tuplexof128_differential:47:width=3 [extended] | reused | 2026-10-29T03:02:30Z |
| miri-eac12fa44d0cb778 | tuplehash | miri | tuplehash-staging:823 [extended] | reused | 2026-10-29T00:51:03Z |
| miri-eacb3b37b8fc00dd | sha1 | miri | sha1-bulk:105 [extended] | reused | 2026-10-28T12:58:39Z |
| miri-ead410a5a3d54d4d | md5 | miri | md5-bulk:256 [extended] | reused | 2026-10-28T11:57:56Z |
| miri-ead926db181b65e7 | sha3 | miri | sha3-secret-xof-bits:0 [routine] | passed | 2026-10-19T11:39:23Z |
| miri-eaebf46363d85e13 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-official:1 [routine] | No mapped observation | — |
| miri-eaf567e870e4d17f | sha1 | miri | sha1-bulk:42 [extended] | reused | 2026-10-28T12:43:23Z |
| miri-eaf674d6eccf5e61 | tuplehash | miri | tuplehash-staging:164 [extended] | reused | 2026-10-28T15:02:23Z |
| miri-eaf91e4b1f23547a | tuplehash | miri | scoped_tuplexof256_differential:24:width=1 [extended] | reused | 2026-10-29T03:06:57Z |
| miri-eaffe4d4fdffee3b | kmac | miri | kmac-official:1 [routine] | passed | 2026-10-19T11:54:38Z |
| miri-eb1e98a6872378d3 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:7:width=4 [extended] | reused | 2026-10-28T19:59:05Z |
| miri-eb29baafa8ba8a66 | kmac | miri | kmac-streamed-setup:20 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-eb38560d7307c3c6 | sha1 | miri | sha1-bulk:204 [extended] | reused | 2026-10-28T12:56:42Z |
| miri-eb3f805231607ee0 | sha1 | miri | sha1-bulk:7 [routine] | passed | 2026-10-19T11:16:05Z |
| miri-eb3fcfeda3a2c761 | md5 | miri | md5-bulk:127 [routine] | passed | 2026-10-19T11:26:15Z |
| miri-eb4491cbf40b62bb | sha3 | miri | -p brynja-hash-sha3 --test sha3_512 suffix_and_rate_boundaries_have_exact_digests [remaining suite; inspect skips with show] | passed | 2026-10-19T11:36:28Z |
| miri-eb72ec6fff8c8b12 | tuplehash | miri | tuplehash-staging:44 [extended] | reused | 2026-10-28T14:22:43Z |
| miri-eb7343b74c5859f7 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:22:width=4 [extended] | reused | 2026-10-28T20:04:30Z |
| miri-eb8943275b5b4d0d | sha2 | miri | -p brynja-hash-sha2 --features runtime-execution,general-sha512-t --lib execution_transaction [remaining suite; inspect skips with show] | reused | 2026-10-28T13:27:06Z |
| miri-ebae939c5b5ffd9c | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:49:width=0 [extended] | reused | 2026-10-29T03:52:14Z |
| miri-ebb8cdab2f84b555 | tuplehash | miri | tuplehash-staging:635 [extended] | reused | 2026-10-28T23:47:37Z |
| miri-ebbaadf70d664c37 | sha1 | miri | sha1-scoped:286 [extended] | reused | 2026-10-28T13:25:06Z |
| miri-ebbdbdbc74b74ee3 | tuplehash | miri | tuplehash-staging:348 [extended] | reused | 2026-10-28T16:01:53Z |
| miri-ebc95096dc14fe5a | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:48:width=0 [extended] | reused | 2026-10-28T21:27:32Z |
| miri-ebebf838e509ff82 | md5 | miri | md5-scoped:68 [extended] | reused | 2026-10-28T11:57:29Z |
| miri-ebec02455e92a916 | tuplehash | miri | tuplehash-execution-fixed:14 [routine] | passed | 2026-10-19T12:06:11Z |
| miri-ebf12cbf8fdf76a6 | tuplehash | miri | tuplehash-staging:749 [extended] | reused | 2026-10-28T18:31:52Z |
| miri-ec174f8f97392a5c | sha1 | miri | sha1-padding:61 [extended] | reused | 2026-10-28T12:32:55Z |
| miri-ec1bbc4302f84ba4 | sha1 | miri | sha1-scoped:254 [extended] | reused | 2026-10-28T13:22:33Z |
| miri-ec22354adbfb6c81 | sha3 | miri | sha3-fixed-boundaries:36 [extended] | reused | 2026-10-28T13:49:26Z |
| miri-ec32e4d558ff7e39 | kmac | miri | kmac-streamed-setup:23 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-ec3e264d96a85fdb | sha1 | miri | sha1-padding:75 [extended] | reused | 2026-10-28T12:35:38Z |
| miri-ec4200caf93b8c12 | tuplehash | miri | tuplehash-staging:515 [extended] | reused | 2026-10-28T23:07:08Z |
| miri-ec4a37320b1cb4fd | md5 | miri | md5-scoped:193 [extended] | reused | 2026-10-28T12:00:39Z |
| miri-ec51b4293dbe5348 | md5 | miri | md5-scoped:145 [extended] | reused | 2026-10-28T11:57:20Z |
| miri-ec54d4ff8989574c | tuplehash | miri | tuplehash-staging:816 [extended] | reused | 2026-10-28T18:31:48Z |
| miri-ec5d7a3a04187f15 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:11:width=3 [extended] | reused | 2026-10-28T22:46:21Z |
| miri-ec6e315a499dd3b0 | sha1 | miri | sha1-bulk:88 [extended] | reused | 2026-10-28T12:45:15Z |
| miri-ec6fe4558a3a1b4a | sha1 | miri | sha1-bulk:63 [extended] | reused | 2026-10-28T12:50:12Z |
| miri-ec87a64053795e4a | md5 | miri | md5-scoped:210 [extended] | reused | 2026-10-28T12:12:40Z |
| miri-ec97655f3412d19c | tuplehash | miri | tuplehash-staging:505 [extended] | reused | 2026-10-28T17:09:18Z |
| miri-eca529a1f1683442 | sha1 | miri | sha1-scoped:221 [extended] | reused | 2026-10-28T13:27:21Z |
| miri-eca8924c0ec18a38 | kmac | miri | kmac-streamed-setup:80 [routine] | No mapped observation | — |
| miri-ecae437e0322d091 | tuplehash | miri | tuplehash-staging:26 [extended] | reused | 2026-10-28T14:20:19Z |
| miri-ecb457d6f205acc6 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-order:3 [extended] | passed | 2026-10-29T15:10:40Z |
| miri-ecc21f56ce06e66e | sha3 | miri | sha3-secret-xof-bits:2 [routine] | passed | 2026-10-19T11:39:59Z |
| miri-ecc99ef80824fa09 | sha1 | miri | sha1-scoped:177 [extended] | reused | 2026-10-28T13:23:47Z |
| miri-ecd2cf0ceb63bab2 | md5 | miri | md5-scoped:176 [extended] | reused | 2026-10-28T12:04:59Z |
| miri-ecd816d1b2cb77c9 | sha1 | miri | sha1-bulk:17 [extended] | reused | 2026-10-28T12:52:01Z |
| miri-ecda58d51698c385 | sha1 | miri | sha1-bulk:86 [extended] | reused | 2026-10-28T12:46:42Z |
| miri-eceb9156004a1b64 | tuplehash | miri | tuplehash-staging:576 [routine] | passed | 2026-10-19T11:48:08Z |
| miri-ecf4feefb5e47682 | tuplehash | miri | tuplehash-staging:830 [extended] | reused | 2026-10-28T18:39:41Z |
| miri-ecf99041dc2329c1 | sha3 | miri | sha3-fixed-bits:14 [extended] | reused | 2026-10-28T13:47:49Z |
| miri-ed0984605decf60b | tuplehash | miri | tuplehash-staging:375 [extended] | reused | 2026-10-28T22:20:25Z |
| miri-ed287bb953f982b3 | sha2 | miri | -p brynja-hash-sha2 --features hardened-execution,general-sha512-t --lib hardened_execution::tests::output_owner_clears_during_recoverable_unwind [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-ed29d4c5f41f4768 | tuplehash | miri | tuplehash-staging:212 [extended] | reused | 2026-10-28T15:17:38Z |
| miri-ed5334f7c1696432 | tuplehash | miri | tuplehash-staging:863 [extended] | reused | 2026-10-29T01:04:31Z |
| miri-ed68009af2f385a9 | sha1 | miri | sha1-scoped:152 [extended] | reused | 2026-10-28T13:15:45Z |
| miri-ed730cd6e04598a3 | tuplehash | miri | tuplehash-staging:828 [extended] | reused | 2026-10-28T18:35:37Z |
| miri-ed8dcba928109541 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:36:width=4 [extended] | reused | 2026-10-28T23:10:45Z |
| miri-edb1070c5dc66690 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:53:width=3 [extended] | reused | 2026-10-29T04:16:00Z |
| miri-edb56f39f2f5cb53 | sha1 | miri | sha1-scoped:119 [extended] | reused | 2026-10-28T13:24:30Z |
| miri-edbccb0a0dcfbeb2 | md5 | miri | md5-bulk:0 [routine] | passed | 2026-10-19T11:26:02Z |
| miri-edbeacd40efc263c | tuplehash | miri | scoped_tuplexof128_differential:38:width=1 [extended] | reused | 2026-10-29T01:45:47Z |
| miri-edc29a1271b6bf79 | sha1 | miri | sha1-bulk:57 [extended] | reused | 2026-10-28T12:54:40Z |
| miri-edca43556818823f | tuplehash | miri | scoped_tuplexof256_differential:0:width=2 [extended] | reused | 2026-10-29T02:17:57Z |
| miri-edceb9a3318f29bf | tuplehash | miri | tuplehash-staging:70 [extended] | reused | 2026-10-28T14:34:34Z |
| miri-edde772f4438d3b2 | md5 | miri | md5-padding:71 [extended] | reused | 2026-10-28T11:28:02Z |
| miri-edf661d26aa78cf0 | tuplehash | miri | tuplehash-staging:264 [extended] | reused | 2026-10-28T15:34:30Z |
| miri-ee1afc6fb92eadf4 | md5 | miri | md5-batch-mask:21 [extended] | reused | 2026-10-28T12:09:01Z |
| miri-ee24d73de5cfe228 | sha2 | miri | -p brynja-hash-sha2 --features batch512-execution --test batch512 bounded_batch_lifecycle_smoke [remaining suite; inspect skips with show] | passed | 2026-10-19T11:35:39Z |
| miri-ee268dca31cab89c | tuplehash | miri | scoped_tuplexof128_differential:16:width=2 [extended] | reused | 2026-10-29T00:58:58Z |
| miri-ee3275cef8dd9dc5 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:36 [routine] | passed | 2026-10-19T12:10:40Z |
| miri-ee4bf1313495a24f | tuplehash | miri | scoped_tuplexof256_differential:23:width=0 [extended] | reused | 2026-10-29T03:50:03Z |
| miri-ee58d6630e237498 | tuplehash | miri | scoped_tuplexof128_differential:5:width=3 [extended] | reused | 2026-10-29T07:15:40Z |
| miri-ee620acee9007545 | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join128:0 [extended] | passed | 2026-10-29T15:05:30Z |
| miri-ee630c36cb73f41a | sha1 | miri | sha1-scoped:38 [extended] | reused | 2026-10-28T13:05:31Z |
| miri-ee71cb09f63df82f | tuplehash | miri | tuplehash-staging:729 [extended] | reused | 2026-10-28T18:24:44Z |
| miri-ee860e52fc7df43f | tuplehash | miri | tuplehash-staging:194 [extended] | reused | 2026-10-28T15:15:10Z |
| miri-ee96f2d87ded203b | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:47:width=4 [extended] | reused | 2026-10-28T21:37:27Z |
| miri-ee99c715c3cb1466 | tuplehash | miri | tuplehash-staging:682 [extended] | reused | 2026-10-28T17:52:39Z |
| miri-eea7e0d9e9dd95ca | sha1 | miri | sha1-bulk:56 [routine] | passed | 2026-10-19T11:34:45Z |
| miri-eeaac8a917af4ac4 | tuplehash | miri | tuplehash-staging:831 [extended] | reused | 2026-10-29T00:53:45Z |
| miri-eebb591cd66be4cf | md5 | miri | md5-padding:116 [extended] | reused | 2026-10-28T11:26:58Z |
| miri-eec496d527019c0c | sha1 | miri | sha1-scoped:100 [extended] | reused | 2026-10-28T13:11:34Z |
| miri-ef042934201e850a | sha3 | miri | sha3-fixed-boundaries:17 [routine] | passed | 2026-10-19T11:33:05Z |
| miri-ef04b67f7482003d | md5 | miri | md5-scoped:250 [extended] | reused | 2026-10-28T12:15:33Z |
| miri-ef06f3553efd35a9 | sha1 | miri | sha1-padding:57 [extended] | reused | 2026-10-28T12:32:33Z |
| miri-ef072853ed9d2f73 | kmac | miri | kmac-official:3 [extended] | reused | 2026-10-28T19:59:39Z |
| miri-ef159f9ba9269ad3 | md5 | miri | md5-batch-mask:154 [extended] | reused | 2026-10-28T12:30:07Z |
| miri-ef22561eac997955 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:37:width=3 [extended] | reused | 2026-10-29T03:03:13Z |
| miri-ef3184a1db1c7868 | tuplehash | miri | tuplehash-staging:418 [extended] | reused | 2026-10-28T16:27:56Z |
| miri-ef64199523755e4b | md5 | miri | md5-scoped:245 [extended] | reused | 2026-10-28T12:04:30Z |
| miri-ef6524819d9a122a | tuplehash | miri | scoped_tuplexof256_differential:1:width=3 [extended] | passed | 2026-10-29T11:54:14Z |
| miri-ef72d0c1ad4186e1 | kmac | miri | kmac-official:5 [routine] | passed | 2026-10-19T11:55:47Z |
| miri-ef836eb7d756d84c | tuplehash | miri | tuplehash-staging:449 [extended] | reused | 2026-10-28T16:51:00Z |
| miri-ef85f99120cd68d2 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:39:width=3 [extended] | reused | 2026-10-28T23:52:11Z |
| miri-ef91e91439f9ab6b | md5 | miri | md5-padding:22 [extended] | reused | 2026-10-28T11:19:26Z |
| miri-ef97986e8262fd76 | md5 | miri | md5-scoped:79 [extended] | reused | 2026-10-28T11:52:35Z |
| miri-efabb985e7292eaa | kmac | miri | kmac-scoped-xof-lifecycle:5 [extended] | reused | 2026-10-28T14:08:46Z |
| miri-efaf3aa662e1a904 | tuplehash | miri | tuplehash-staging:573 [extended] | reused | 2026-10-28T17:33:00Z |
| miri-efb9edff3c827bc2 | tuplehash | miri | -p brynja-hash-tuple --tests [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-efd7a62708ccb0fd | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:10 [extended] | passed | 2026-10-29T14:08:23Z |
| miri-efe61a4da7146c2f | tuplehash | miri | tuplehash-staging:485 [extended] | reused | 2026-10-28T17:03:07Z |
| miri-effafa8fa422d066 | sha1 | miri | sha1-scoped:116 [extended] | reused | 2026-10-28T13:12:51Z |
| miri-f029384608e73672 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:6:width=4 [extended] | reused | 2026-10-28T19:32:57Z |
| miri-f034acbeb56c7d5a | md5 | miri | md5-padding:30 [extended] | reused | 2026-10-28T11:20:01Z |
| miri-f03d077954c91763 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:42 [routine] | No mapped observation | — |
| miri-f044f0bd693c7ddb | md5 | miri | md5-scoped:143 [extended] | reused | 2026-10-28T11:56:56Z |
| miri-f0464d13f7c54984 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:20:width=4 [extended] | reused | 2026-10-28T22:34:16Z |
| miri-f0500808eb11f035 | tuplehash | miri | tuplehash-staging:285 [extended] | reused | 2026-10-28T15:56:10Z |
| miri-f054960928c1b24e | md5 | miri | md5-scoped:273 [extended] | reused | 2026-10-28T12:06:30Z |
| miri-f05be8d45b8fecdf | tuplehash | miri | tuplehash-staging:312 [extended] | reused | 2026-10-28T15:50:08Z |
| miri-f05c96c7af53b27b | tuplehash | miri | scoped_tuplexof128_differential:14:width=1 [extended] | reused | 2026-10-29T00:48:52Z |
| miri-f07dc6c2e1ec12dc | tuplehash | miri | tuplehash-staging:271 [extended] | reused | 2026-10-28T21:45:24Z |
| miri-f07f6e2602fdfbe5 | tuplehash | miri | scoped_tuplexof128_differential:4:width=0 [extended] | reused | 2026-10-29T00:36:36Z |
| miri-f08446832f15af74 | tuplehash | miri | tuplehash-staging:122 [extended] | reused | 2026-10-28T14:52:01Z |
| miri-f0859412af0cb7d2 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:0:width=3 [extended] | reused | 2026-10-28T19:26:50Z |
| miri-f08f2f4ce7bcfe74 | md5 | miri | md5-padding:38 [extended] | reused | 2026-10-28T11:20:37Z |
| miri-f091aafab16255c5 | tuplehash | miri | xof_partitions_and_hardened_output_match [extended] | reused | 2026-10-29T04:08:09Z |
| miri-f09e9f1e0cfae8cf | tuplehash | miri | tuplehash-staging:493 [extended] | reused | 2026-10-28T17:06:06Z |
| miri-f0abded755676111 | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join256:0 [routine] | No mapped observation | — |
| miri-f0d68693dd1977ad | tuplehash | miri | tuplehash-staging:179 [extended] | reused | 2026-10-28T21:14:20Z |
| miri-f0f204538f822404 | tuplehash | miri | scoped_tuplexof128_differential:15:width=4 [extended] | reused | 2026-10-29T01:38:34Z |
| miri-f0fdaa328f41488a | sha2 | miri | -p brynja-hash-sha2 --features batch512-execution --test batch512 bounded_batch_lifecycle_smoke [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-f0fdea59a5740df9 | sha3 | miri | sha3-fixed-bits:16 [extended] | reused | 2026-10-28T13:56:07Z |
| miri-f0ff385de4e5b221 | tuplehash | miri | tuplehash-staging:354 [extended] | reused | 2026-10-28T16:07:14Z |
| miri-f110fc833e96e897 | kmac | miri | kmac-streamed-setup:25 [routine] | No mapped observation | — |
| miri-f13998be09e4afa1 | tuplehash | miri | tuplehash-staging:640 [extended] | reused | 2026-10-28T17:35:52Z |
| miri-f13d3d8a8d48b4af | sha1 | miri | sha1-scoped:247 [extended] | reused | 2026-10-28T13:34:46Z |
| miri-f14159a9647b67a1 | sha1 | miri | sha1-scoped:101 [extended] | reused | 2026-10-28T13:17:56Z |
| miri-f165e4e3a7901a04 | md5 | miri | md5-batch-mask:127 [extended] | reused | 2026-10-28T12:17:08Z |
| miri-f16cf221d0c99f30 | md5 | miri | md5-bulk:40 [extended] | reused | 2026-10-28T11:40:06Z |
| miri-f16dfcfcccba1194 | md5 | miri | md5-bulk:49 [extended] | reused | 2026-10-28T11:30:56Z |
| miri-f176051dea4d78ca | sha1 | miri | sha1-bulk:73 [extended] | reused | 2026-10-28T12:55:59Z |
| miri-f17c4bc081e6022e | md5 | miri | -p brynja-legacy-md5 --features hardened-execution --lib cpu::scratch::tests [remaining suite; inspect skips with show] | passed | 2026-10-19T11:30:55Z |
| miri-f1a1c44d43eab15a | sha3 | miri | sha3-fixed-bits:11 [routine] | passed | 2026-10-19T11:29:18Z |
| miri-f1a20b4c3a344640 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:43:width=4 [extended] | reused | 2026-10-28T21:24:50Z |
| miri-f1acd92fe849ab0a | md5 | miri | md5-scoped:51 [extended] | reused | 2026-10-28T11:50:42Z |
| miri-f1bfa0c64d03535a | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:8:width=1 [extended] | reused | 2026-10-28T22:09:27Z |
| miri-f1c8de6f5a7b4b4a | md5 | miri | md5-bulk:138 [extended] | reused | 2026-10-28T11:42:26Z |
| miri-f1cb27f0c6d5997b | sha1 | miri | sha1-bulk:85 [extended] | reused | 2026-10-28T12:56:59Z |
| miri-f1d632723a3fca20 | tuplehash | miri | tuplehash-staging:738 [extended] | reused | 2026-10-28T18:10:37Z |
| miri-f1d8dce21eb2a762 | kmac | miri | kmac-streamed-setup:48 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-f1ed0fd485cd69c5 | tuplehash | miri | scoped_tuplexof128_differential:0:width=2 [extended] | reused | 2026-10-29T00:30:00Z |
| miri-f1fde4aa47c6223b | sha3 | miri | every_fixed_secret_output_transfers_and_clears [routine] | passed | 2026-10-19T11:40:22Z |
| miri-f21b1ca3f3a6189d | md5 | miri | md5-bulk:251 [extended] | reused | 2026-10-28T11:47:04Z |
| miri-f21bf915d88a8197 | md5 | miri | md5-bulk:257 [extended] | reused | 2026-10-28T11:47:18Z |
| miri-f21d0681e63044ea | tuplehash | miri | scoped_tuplexof128_differential:44:width=3 [extended] | reused | 2026-10-29T02:11:09Z |
| miri-f21e94b9763da575 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:393 [routine] | No mapped observation | — |
| miri-f228b7ea7d4e33f5 | tuplehash | miri | tuple_boundaries_order_and_empty_items_are_distinct [routine] | passed | 2026-10-19T12:20:26Z |
| miri-f23de5b29d9939f5 | sha1 | miri | sha1-bulk:128 [extended] | reused | 2026-10-28T12:48:45Z |
| miri-f24f765b5fb2a8f7 | sha1 | miri | sha1-padding:99 [extended] | reused | 2026-10-28T12:37:50Z |
| miri-f2827ee5c63c3232 | sha1 | miri | sha1-bulk:217 [extended] | reused | 2026-10-28T13:10:29Z |
| miri-f284516b32a4a7df | sha1 | miri | sha1-scoped:223 [extended] | reused | 2026-10-28T13:32:45Z |
| miri-f28c63ee28469115 | sha1 | miri | sha1-bulk:227 [extended] | reused | 2026-10-28T13:06:59Z |
| miri-f28e405a0cd3b99d | kmac | miri | kmac-streamed-setup:98 [routine] | No mapped observation | — |
| miri-f296adddeabb32e2 | hmac | miri | sha512_256 [routine] | No mapped observation | — |
| miri-f2a415f2185927cf | md5 | miri | md5-scoped:194 [extended] | reused | 2026-10-28T12:11:30Z |
| miri-f2a710d614412829 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:22:width=1 [extended] | reused | 2026-10-28T20:04:30Z |
| miri-f2c8ca7a9230b930 | sha1 | miri | sha1-scoped:280 [extended] | reused | 2026-10-28T13:26:08Z |
| miri-f2cfb6ae3c84950c | tuplehash | miri | scoped_tuplexof128_differential:18 [routine] | passed | 2026-10-19T12:21:49Z |
| miri-f2d7a8feedac7d02 | kmac | miri | -p brynja-mac-kmac --features hardened-execution --test execution [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-f2e4625a152dfb90 | kmac | miri | kmac-streamed-setup:58 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-f2f5c7abeed99bc8 | tuplehash | miri | tuplehash-staging:220 [extended] | reused | 2026-10-28T15:20:37Z |
| miri-f2f8090fc11c74d3 | md5 | miri | md5-scoped:95 [extended] | reused | 2026-10-28T11:53:40Z |
| miri-f312a0fbf05f9178 | sha1 | miri | sha1-padding:89 [extended] | reused | 2026-10-28T12:35:29Z |
| miri-f31b21ca1627930f | sha1 | miri | sha1-scoped:205 [extended] | reused | 2026-10-28T13:26:00Z |
| miri-f31dbf55829e0f6b | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:351 [routine] | No mapped observation | — |
| miri-f32149bb88421494 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:46:width=1 [extended] | reused | 2026-10-28T23:33:28Z |
| miri-f3383838ea4b145d | tuplehash | miri | tuplehash-staging:521 [extended] | reused | 2026-10-28T17:15:29Z |
| miri-f3535439214a0840 | tuplehash | miri | scoped_tuplexof128_differential:18:width=1 [extended] | reused | 2026-10-29T00:58:05Z |
| miri-f3675d5270bcd231 | md5 | miri | md5-bulk:242 [extended] | reused | 2026-10-28T11:51:37Z |
| miri-f36d385ceda6d58f | md5 | miri | md5-bulk:28 [extended] | reused | 2026-10-28T11:39:19Z |
| miri-f373cca35182bfe5 | kmac | miri | kmac-streamed-setup:57 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-f37943e015c391b2 | tuplehash | miri | tuplehash-staging:315 [extended] | reused | 2026-10-28T22:00:14Z |
| miri-f37f8e231b0d4064 | tuplehash | miri | scoped_tuplexof256_differential:44:width=0 [extended] | reused | 2026-10-29T03:59:50Z |
| miri-f388e55549bd45e0 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:19:width=0 [extended] | reused | 2026-10-28T20:22:54Z |
| miri-f38e96b0e461f515 | md5 | miri | md5-scoped:132 [extended] | reused | 2026-10-28T12:01:58Z |
| miri-f3912e73d9fd0a21 | sha2 | miri | -p brynja-crypto-cpu --features sha256-batch --lib sha256_batch::tests::failed_revalidation_and_unwind_revoke_before_instruction_entry [remaining suite; inspect skips with show] | reused | 2026-10-28T13:26:52Z |
| miri-f397247f8c6dc196 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:33:width=0 [extended] | reused | 2026-10-29T02:53:27Z |
| miri-f3bc99b6a4d1d227 | tuplehash | miri | scoped_tuplexof128_differential:10:width=1 [extended] | reused | 2026-10-29T00:42:19Z |
| miri-f3beadadee47aea7 | md5 | miri | md5-scoped:261 [extended] | reused | 2026-10-28T12:05:38Z |
| miri-f3c2c79f4eae2026 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-faults:4 [extended] | passed | 2026-10-29T15:07:26Z |
| miri-f3c31721b4ca4549 | sha1 | miri | sha1-scoped:36 [extended] | reused | 2026-10-28T13:06:47Z |
| miri-f3cee077747bb700 | md5 | miri | md5-batch-mask:73 [extended] | reused | 2026-10-28T12:12:59Z |
| miri-f4139ce4e12efd7c | sha1 | miri | sha1-bulk:257 [extended] | reused | 2026-10-28T13:15:42Z |
| miri-f41618bebd0dee7c | tuplehash | miri | tuplehash-staging:646 [extended] | reused | 2026-10-28T17:40:49Z |
| miri-f41e7e3e0d3ac814 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:31:width=1 [extended] | reused | 2026-10-28T20:52:30Z |
| miri-f421563c32f0fa49 | tuplehash | miri | tuplehash-staging:173 [extended] | reused | 2026-10-28T15:18:42Z |
| miri-f42d4188c3c3decc | tuplehash | miri | tuplehash-staging:591 [extended] | reused | 2026-10-28T23:33:11Z |
| miri-f43572b426317b6d | md5 | miri | md5-scoped:172 [extended] | reused | 2026-10-28T12:04:42Z |
| miri-f440820338e99978 | tuplehash | miri | scoped_tuplexof256_differential:27:width=0 [extended] | reused | 2026-10-29T03:59:46Z |
| miri-f46d8cc72865d168 | md5 | miri | md5-padding:57 [routine] | passed | 2026-10-19T11:28:42Z |
| miri-f48491c8047396b0 | md5 | miri | md5-bulk:142 [extended] | reused | 2026-10-28T11:42:46Z |
| miri-f48a48e51dd097ed | sha1 | miri | sha1-scoped:277 [extended] | reused | 2026-10-28T13:31:58Z |
| miri-f49c6ffdfa216e3d | tuplehash | miri | tuplehash-staging:324 [extended] | reused | 2026-10-28T15:54:04Z |
| miri-f4a694df3fc9e597 | sha1 | miri | sha1-scoped:47 [extended] | reused | 2026-10-28T13:19:10Z |
| miri-f4c41d155039a3d5 | md5 | miri | md5-batch-mask:190 [extended] | reused | 2026-10-28T12:33:08Z |
| miri-f4cf0064ce3d36c9 | tuplehash | miri | tuplehash-staging:108 [extended] | reused | 2026-10-28T14:44:03Z |
| miri-f4d2a3b829ca612e | static_cpu | miri | --manifest-path assurance/hosted-cpu-execution/Cargo.toml --lib [remaining suite; inspect skips with show] | passed | 2026-10-29T15:01:55Z |
| miri-f4f125a6a51a6f6b | sha3 | miri | every_fixed_secret_output_transfers_and_clears [extended] | reused | 2026-10-28T13:59:03Z |
| miri-f4fea3b774a25a22 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:18:width=3 [extended] | reused | 2026-10-28T19:55:16Z |
| miri-f504b9ab8ed21992 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:12:width=0 [extended] | reused | 2026-10-28T22:16:00Z |
| miri-f514f4f200ef1714 | tuplehash | miri | scoped_tuplexof256_differential:2:width=1 [extended] | reused | 2026-10-29T02:17:15Z |
| miri-f51b3a67f1e25ec7 | kmac | miri | kmac-scoped-xof-lifecycle:8 [routine] | passed | 2026-10-19T11:44:25Z |
| miri-f522e6b0469ef3c2 | md5 | miri | md5-bulk:219 [extended] | reused | 2026-10-28T11:44:15Z |
| miri-f529b1c8d115dfd4 | md5 | miri | md5-batch-mask:150 [extended] | reused | 2026-10-28T12:29:48Z |
| miri-f52b77d4e44e6f33 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_lifecycle:3 [routine] | No mapped observation | — |
| miri-f52dced6a4d0a514 | sha1 | miri | sha1-bulk:12 [extended] | reused | 2026-10-28T12:39:51Z |
| miri-f537c41377ef39bd | tuplehash | miri | tuplehash-staging:890 [extended] | reused | 2026-10-28T18:58:29Z |
| miri-f541e420d40a0481 | tuplehash | miri | scoped_tuplexof128_differential:15 [routine] | passed | 2026-10-19T12:34:21Z |
| miri-f55224d91a2dde77 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:26:width=1 [extended] | reused | 2026-10-28T22:42:58Z |
| miri-f557663bdcbcf889 | tuplehash | miri | scoped_tuplexof256_differential:30:width=4 [extended] | reused | 2026-10-29T03:15:42Z |
| miri-f5786fea8ee6942e | md5 | miri | md5-batch-mask:222 [extended] | reused | 2026-10-28T12:35:45Z |
| miri-f5a007209de6de73 | sha3 | miri | sha3-fixed-boundaries:57 [routine] | passed | 2026-10-19T11:34:36Z |
| miri-f5a525b4d65a666f | sha1 | miri | sha1-scoped:48 [extended] | reused | 2026-10-28T13:07:38Z |
| miri-f5a93c714f46423d | tuplehash | miri | scoped_tuplexof128_differential:27:width=2 [extended] | reused | 2026-10-29T02:07:59Z |
| miri-f5bed8c424ce90c4 | sha1 | miri | sha1-bulk:91 [extended] | reused | 2026-10-28T12:52:36Z |
| miri-f5dd7e070df0a215 | kmac | miri | kmac-streamed-setup:57 [routine] | No mapped observation | — |
| miri-f5ebdc890681522f | md5 | miri | md5-scoped:257 [extended] | reused | 2026-10-28T12:05:21Z |
| miri-f5f0e180685af2cc | md5 | miri | md5-batch-mask:18 [extended] | reused | 2026-10-28T12:19:34Z |
| miri-f5f41a611c2ab99e | tuplehash | miri | scoped_tuplexof256_differential:45:width=3 [extended] | passed | 2026-10-29T12:29:32Z |
| miri-f5f67c5082ea15ea | md5 | miri | md5-bulk:66 [extended] | reused | 2026-10-28T11:36:46Z |
| miri-f613b30f5ad8a21f | tuplehash | miri | tuplehash-staging:81 [extended] | reused | 2026-10-28T14:47:46Z |
| miri-f6369d82cf1482e1 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:26:width=4 [extended] | reused | 2026-10-28T20:13:39Z |
| miri-f65ffe911cc7d156 | sha3 | miri | -p brynja-hash-sha3 --test cshake every_official_nist_cshake_example_matches [remaining suite; inspect skips with show] | reused | 2026-10-28T13:36:34Z |
| miri-f66b4b872f504f3d | hmac | miri | -p brynja-crypto-cpu-std --features macos-resident-hmac-acceleration --lib macos_resident::hmac [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-f66fcbd7fc111e33 | md5 | miri | md5-batch-mask:212 [extended] | reused | 2026-10-28T12:29:22Z |
| miri-f67e9e6d68b88918 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:48:width=1 [extended] | reused | 2026-10-28T21:27:32Z |
| miri-f691f11134801598 | tuplehash | miri | scoped_tuplexof128_differential:19:width=4 [extended] | reused | 2026-10-29T01:48:20Z |
| miri-f69891c78709b9ae | sha3 | miri | sha3-fixed-bits:5 [routine] | passed | 2026-10-19T11:34:59Z |
| miri-f6b904ac459a582e | sha3 | miri | -p brynja-hash-sha3 --test cshake every_official_nist_cshake_example_matches [remaining suite; inspect skips with show] | passed | 2026-10-19T11:26:18Z |
| miri-f6bb985ec798bc3f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:28:width=0 [extended] | reused | 2026-10-28T22:52:29Z |
| miri-f6c305d3918610a4 | md5 | miri | md5-batch-mask:210 [extended] | reused | 2026-10-28T12:34:43Z |
| miri-f70502e6759532e4 | md5 | miri | md5-bulk:104 [extended] | reused | 2026-10-28T11:44:43Z |
| miri-f70b38996d308861 | md5 | miri | md5-scoped:203 [extended] | reused | 2026-10-28T12:01:06Z |
| miri-f7130aaba6f9f39d | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:8:width=2 [extended] | reused | 2026-10-28T22:09:27Z |
| miri-f719825bba215ccd | md5 | miri | md5-padding:33 [extended] | reused | 2026-10-28T11:30:04Z |
| miri-f726b5df045535f0 | tuplehash | miri | tuplehash-staging:621 [extended] | reused | 2026-10-28T17:48:46Z |
| miri-f730856d21cd3b5d | tuplehash | miri | tuplehash-staging:694 [extended] | reused | 2026-10-28T17:55:45Z |
| miri-f735b0c6b606ac9f | kmac | miri | kmac-framing:4 [routine] | passed | 2026-10-19T11:31:56Z |
| miri-f74381a74fa20605 | sha1 | miri | sha1-scoped:213 [extended] | reused | 2026-10-28T13:26:40Z |
| miri-f7515956af79695d | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:39:width=1 [extended] | reused | 2026-10-28T23:52:11Z |
| miri-f75668d02263090b | md5 | miri | md5-bulk:183 [extended] | reused | 2026-10-28T11:41:12Z |
| miri-f76279908a92d00a | md5 | miri | md5-bulk:13 [extended] | reused | 2026-10-28T11:28:34Z |
| miri-f764566640cd73db | tuplehash | miri | tuplehash-staging:18 [extended] | reused | 2026-10-28T14:17:47Z |
| miri-f7854fa82591ff92 | sha2 | miri | -p brynja-hash-sha2 --features general-sha512-t --test general_hash dynamic_general_secret_lifecycle [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-f7b991e300c2b348 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:12 [extended] | passed | 2026-10-29T14:56:20Z |
| miri-f7c477ee81220eb8 | md5 | miri | md5-padding:95 [extended] | reused | 2026-10-28T11:29:49Z |
| miri-f7d821c21693ef09 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:27 [routine] | No mapped observation | — |
| miri-f7d82ee44d4e9dd6 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:15:width=0 [extended] | reused | 2026-10-28T22:53:23Z |
| miri-f7eef56b4240094d | tuplehash | miri | scoped_tuplexof256_differential:16:width=0 [extended] | reused | 2026-10-29T02:47:58Z |
| miri-f80447f87e443b3b | sha2 | miri | -p brynja-crypto-cpu --features sha256-batch --lib sha256_batch::tests::failed_revalidation_and_unwind_revoke_before_instruction_entry [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-f81f93600a120ff4 | md5 | miri | md5-batch-mask:153 [extended] | reused | 2026-10-28T12:19:22Z |
| miri-f8239a704ba10b47 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:50:width=1 [extended] | reused | 2026-10-28T23:58:01Z |
| miri-f823cb4a238bbbfa | tuplehash | miri | scoped_tuplexof128_differential:39:width=3 [extended] | reused | 2026-10-29T02:37:19Z |
| miri-f82642e283f824da | tuplehash | miri | scoped_tuplexof256_differential:20:width=0 [extended] | reused | 2026-10-29T02:57:28Z |
| miri-f83b5a078823c6fe | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_matches:18 [routine] | No mapped observation | — |
| miri-f83e73b2cad8cb88 | tuplehash | miri | scoped_tuplexof256_differential:26:width=0 [extended] | reused | 2026-10-29T03:06:14Z |
| miri-f857109ac44adba1 | sha1 | miri | sha1-scoped:88 [extended] | reused | 2026-10-28T13:10:36Z |
| miri-f87545d956396878 | md5 | miri | md5-bulk:117 [extended] | reused | 2026-10-28T11:35:46Z |
| miri-f87bb6d40eb1c3d8 | sha3 | miri | -p brynja-hash-sha3 --test hardened [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-f88054abc9037f94 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:18:width=4 [extended] | reused | 2026-10-28T22:24:48Z |
| miri-f88dfa478e55b865 | tuplehash | miri | tuplehash-staging:86 [extended] | reused | 2026-10-28T14:39:49Z |
| miri-f88f8c50d7071338 | md5 | miri | md5-bulk:81 [extended] | reused | 2026-10-28T11:33:10Z |
| miri-f8936ce9103688d3 | md5 | miri | md5-bulk:240 [extended] | reused | 2026-10-28T11:56:21Z |
| miri-f8cda8102d0d904d | tuplehash | miri | abandoned_or_incomplete_items_fail_closed [extended] | reused | 2026-10-29T04:04:55Z |
| miri-f8fb74da5e8d99ee | legacy_hmac | miri | sha1_long [routine] | No mapped observation | — |
| miri-f8fda2a37b9e9a7c | sha1 | miri | sha1-bulk:119 [routine] | passed | 2026-10-19T11:34:52Z |
| miri-f90c314e997b1a6b | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:171 [extended] | passed | 2026-10-29T13:40:50Z |
| miri-f94297780feef53b | tuplehash | miri | tuplehash-staging:747 [extended] | reused | 2026-10-29T00:25:24Z |
| miri-f94ac6afc679d8b0 | md5 | miri | md5-padding:88 [extended] | reused | 2026-10-28T11:24:49Z |
| miri-f94b27627d1fcafa | md5 | miri | md5-scoped:178 [extended] | reused | 2026-10-28T12:10:21Z |
| miri-f95f9356db5d1c72 | md5 | miri | md5-batch-mask:1 [extended] | reused | 2026-10-28T12:07:37Z |
| miri-f966bdf375cef98c | tuplehash | miri | tuplehash-staging:551 [extended] | reused | 2026-10-28T23:19:21Z |
| miri-f97be2dac4233a29 | md5 | miri | md5-batch-mask:143 [extended] | reused | 2026-10-28T12:18:23Z |
| miri-f98ac661f62ed5c7 | tuplehash | miri | tuplehash-staging:432 [extended] | reused | 2026-10-28T16:29:03Z |
| miri-f99a84b11a2c8c29 | tuplehash | miri | scoped_tuplexof256_differential:2:width=0 [extended] | reused | 2026-10-29T02:17:15Z |
| miri-f99cc7783db5879e | md5 | miri | md5-batch-mask:50 [extended] | reused | 2026-10-28T12:21:58Z |
| miri-f9d5369743a993b8 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:9:width=0 [extended] | reused | 2026-10-29T01:57:28Z |
| miri-f9d6bc71346eb9c7 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:5:width=0 [extended] | reused | 2026-10-29T01:50:26Z |
| miri-f9e0733bbd234a03 | sha1 | miri | sha1-padding:24 [extended] | reused | 2026-10-28T12:36:11Z |
| miri-f9f77581958669ff | tuplehash | miri | tuplehash-staging:175 [extended] | reused | 2026-10-28T21:13:00Z |
| miri-fa0ef02ed1740f75 | sha1 | miri | sha1-scoped:185 [extended] | reused | 2026-10-28T13:24:22Z |
| miri-fa2f2cb2f812d253 | md5 | miri | md5-batch-mask:194 [extended] | reused | 2026-10-28T12:33:26Z |
| miri-fa31b221b668e662 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-execution-stream:45 [extended] | passed | 2026-10-29T14:12:56Z |
| miri-fa3abc9dec058e10 | tuplehash | miri | scoped_tuplexof256_differential:34:width=2 [extended] | reused | 2026-10-29T03:25:12Z |
| miri-fa3d299d88322103 | md5 | miri | md5-padding:2 [extended] | reused | 2026-10-28T11:17:57Z |
| miri-fa44238518cc6a77 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:18 [extended] | passed | 2026-10-29T12:44:14Z |
| miri-fa5217aa2a100e6b | md5 | miri | md5-bulk:50 [extended] | reused | 2026-10-28T11:35:42Z |
| miri-fa56e65c483ad9c9 | tuplehash | miri | tuplehash-staging:689 [extended] | reused | 2026-10-28T18:12:02Z |
| miri-fa75e2209d77f74e | kmac | miri | kmac-streamed-setup:82 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-fa81ddc58cbf7ed7 | tuplehash | miri | scoped_tuplexof128_differential:6:width=0 [extended] | reused | 2026-10-29T00:35:44Z |
| miri-fa83d9d4eb2f90f8 | sha1 | miri | sha1-padding:1 [extended] | reused | 2026-10-28T12:28:19Z |
| miri-fa881bbaea24c7f4 | sha3 | miri | xof_secret_fragments_transfer_and_clear_independently [extended] | reused | 2026-10-28T13:51:40Z |
| miri-fa8b67e45c18a1f3 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-hosted-domains:0 [extended] | passed | 2026-10-29T15:03:02Z |
| miri-fa9084d3761c990e | sha3 | miri | sha3-fixed-boundaries:12 [routine] | passed | 2026-10-19T11:26:39Z |
| miri-fa98dcb2bb5a5af4 | sha3 | miri | sha3-fixed-bits:8 [routine] | passed | 2026-10-19T11:38:08Z |
| miri-fa9e9ca5f4d24baf | md5 | miri | md5-padding:14 [extended] | reused | 2026-10-28T11:18:50Z |
| miri-faaaffee93ff71b9 | sha1 | miri | sha1-bulk:153 [extended] | reused | 2026-10-28T13:03:15Z |
| miri-fab7249432866e02 | md5 | miri | md5-bulk:34 [extended] | reused | 2026-10-28T11:34:38Z |
| miri-fac1f488326ba2bf | tuplehash | miri | scoped_tuplexof128_differential:33:width=0 [extended] | passed | 2026-10-29T11:50:45Z |
| miri-fad78be28cbbf272 | md5 | miri | md5-batch-mask:253 [extended] | reused | 2026-10-28T12:27:30Z |
| miri-fae5e9c1fbc0f6a5 | md5 | miri | md5-padding:97 [extended] | reused | 2026-10-28T11:34:54Z |
| miri-fb03a4c14da8eac3 | parallelhash | miri | [bounded-parallelhash-v1] parallelhashxof-official:4 [extended] | passed | 2026-10-29T14:14:51Z |
| miri-fb0a51c83848328f | tuplehash | miri | tuplehash-staging:371 [extended] | reused | 2026-10-28T22:19:03Z |
| miri-fb14ad163baa6219 | tuplehash | miri | tuplehash-staging:620 [extended] | reused | 2026-10-28T17:29:04Z |
| miri-fb1d1d7e95469a2d | tuplehash | miri | scoped_tuplexof256_differential:40:width=3 [extended] | reused | 2026-10-29T03:47:39Z |
| miri-fb47a89f9ef25737 | md5 | miri | md5-scoped:93 [extended] | reused | 2026-10-28T11:53:48Z |
| miri-fb4b59ca765ecc80 | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:0 [extended] | passed | 2026-10-29T13:54:03Z |
| miri-fb52d3778c2c1502 | sha2 | miri | -p brynja-crypto-cpu --features sha512-batch --lib sha512_batch::tests::failed_revalidation_and_unwind_revoke_before_instruction_entry [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-fb6849ca4ae3dd9e | md5 | miri | md5-scoped:31 [extended] | reused | 2026-10-28T11:49:23Z |
| miri-fb6f8e5d5b6ff4de | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled256_lifecycle:8 [extended] | passed | 2026-10-29T13:55:46Z |
| miri-fb72ae9440f5631a | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel256_matches_and_clears:36 [routine] | No mapped observation | — |
| miri-fb83f0b042d06145 | tuplehash | miri | scoped_tuplexof256_differential:45:width=2 [extended] | passed | 2026-10-29T12:53:22Z |
| miri-fb8dd08afb6e9f4c | sha1 | miri | sha1-scoped:246 [extended] | reused | 2026-10-28T13:21:52Z |
| miri-fbb9733b82744d67 | tuplehash | miri | tuplehash-execution-fixed:12 [routine] | passed | 2026-10-19T12:12:09Z |
| miri-fbda5ed86ce356e8 | tuplehash | miri | scoped_tuplexof256_differential:41:width=1 [extended] | passed | 2026-10-29T12:13:26Z |
| miri-fbed1724a21d31e5 | parallelhash | miri | [bounded-parallelhash-v1] scoped_parallel128_matches_and_clears:18 [routine] | No mapped observation | — |
| miri-fc0ff28e807d9c02 | tuplehash | miri | tuplehash-staging:837 [extended] | reused | 2026-10-28T19:01:32Z |
| miri-fc2f06331e8a630c | tuplehash | miri | tuplehash-staging:240 [extended] | reused | 2026-10-28T15:26:39Z |
| miri-fc34a99584d51856 | sha1 | miri | sha1-scoped:222 [extended] | reused | 2026-10-28T13:19:53Z |
| miri-fc3acdaf84f79212 | md5 | miri | md5-scoped:66 [extended] | reused | 2026-10-28T12:02:32Z |
| miri-fc3e2bcabf0cfba1 | kmac | miri | kmac-streamed-setup:95 [routine] | No mapped observation | — |
| miri-fc40a975435e4c2c | md5 | miri | md5-scoped:0 [routine] | passed | 2026-10-19T11:32:43Z |
| miri-fc43858c953415a8 | sha2 | miri | -p brynja-hash-sha2 --features general-sha512-t --test general_hash dynamic_general_secret_lifecycle [remaining suite; inspect skips with show] | passed | 2026-10-19T11:35:55Z |
| miri-fc540e812a2e5973 | kmac | miri | kmac-streamed-setup:19 [extended] | reused | 2026-10-28T19:45:58Z |
| miri-fc547dffd289029f | sha2 | miri | -p brynja-hash-sha2 --features general-sha512-t --test general bounded_public_api_smoke [remaining suite; inspect skips with show] | passed | 2026-10-19T11:33:53Z |
| miri-fc55e0d96ad424c1 | tuplehash | miri | tuplehash-staging:159 [extended] | reused | 2026-10-28T21:07:36Z |
| miri-fc586caf1ddd5b0e | md5 | miri | md5-bulk:216 [extended] | reused | 2026-10-28T11:54:04Z |
| miri-fc680af0c01effad | md5 | miri | md5-padding:10 [extended] | reused | 2026-10-28T11:18:33Z |
| miri-fc6f759d73258a82 | sha1 | miri | sha1-scoped:103 [extended] | reused | 2026-10-28T13:23:18Z |
| miri-fc8fd89cd862b3fa | parallelhash | miri | [bounded-parallelhash-v1] scoped_scheduled128_matches:13 [routine] | No mapped observation | — |
| miri-fcc563630bd07f04 | md5 | miri | md5-scoped:267 [extended] | reused | 2026-10-28T12:05:47Z |
| miri-fcc5eea3a29739a2 | tuplehash | miri | scoped_tuplexof256_differential:42:width=0 [extended] | reused | 2026-10-29T03:47:02Z |
| miri-fcd41b287aa8bcb8 | tuplehash | miri | tuplehash-staging:367 [extended] | reused | 2026-10-28T22:18:07Z |
| miri-fcd44b9051ee7523 | tuplehash | miri | scoped_tuplexof128_differential:8:width=4 [extended] | reused | 2026-10-29T00:43:10Z |
| miri-fce33b096ba4edec | md5 | miri | md5-padding:69 [extended] | reused | 2026-10-28T11:32:38Z |
| miri-fce33f6f25a8a7fe | parallelhash | miri | [bounded-parallelhash-v1] scoped_execution_workers_join128:1 [extended] | passed | 2026-10-29T14:17:50Z |
| miri-fce788f92963de9b | kmac | miri | kmac-scoped-lifecycle:13 [extended] | reused | 2026-10-28T19:51:12Z |
| miri-fd05234f1dc8096f | sha3 | miri | sha3-secret-xof-bits:6 [extended] | reused | 2026-10-28T13:50:20Z |
| miri-fd07f10b92355d89 | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-leaf:37 [extended] | passed | 2026-10-29T13:55:33Z |
| miri-fd0d2a96e73204e7 | tuplehash | miri | tuplehash-staging:780 [extended] | reused | 2026-10-28T18:20:41Z |
| miri-fd3651493c50c6f7 | tuplehash | miri | scoped_tuplexof256_differential:24:width=2 [extended] | reused | 2026-10-29T03:06:57Z |
| miri-fd3ef46c54f9f5c8 | tuplehash | miri | scoped_tuplexof256_differential:17:width=1 [extended] | passed | 2026-10-29T12:00:05Z |
| miri-fd48ba07fce4fa1f | tuplehash | miri | scoped_tuplexof256_differential:4:width=4 [extended] | reused | 2026-10-29T02:24:45Z |
| miri-fd5e999cec0aa934 | tuplehash | miri | tuplehash-staging:391 [extended] | reused | 2026-10-28T22:26:12Z |
| miri-fd6fbbfe4ce9beff | kmac | miri | kmac-streamed-setup:93 [routine] | No mapped observation | — |
| miri-fd725c6d372ca5da | tuplehash | miri | scoped_tuplexof256_differential:47:width=0 [extended] | reused | 2026-10-29T04:53:59Z |
| miri-fd996a76cf0f1842 | tuplehash | miri | scoped_tuplexof128_differential:33:width=2 [extended] | passed | 2026-10-29T11:51:43Z |
| miri-fdb1d4cf26a28ac6 | md5 | miri | md5-bulk:192 [extended] | reused | 2026-10-28T11:51:51Z |
| miri-fdb5c6fdf07d5a2e | sha1 | miri | sha1-padding:111 [extended] | reused | 2026-10-28T12:38:55Z |
| miri-fdbefd7840051c36 | hmac | miri | output_clears_during_consumer_unwind [existing-full] | No mapped observation | — |
| miri-fdc49a4107c587fc | md5 | miri | md5-batch-mask:128 [routine] | passed | 2026-10-19T11:30:04Z |
| miri-fdc7cfec71a8aa05 | tuplehash | miri | tuplehash-staging:743 [extended] | reused | 2026-10-29T00:23:39Z |
| miri-fdcd9c5b1e1901b3 | kmac | miri | kmac-streamed-setup:96 [routine] | No mapped observation | — |
| miri-fddb748ffb8ec92b | tuplehash | miri | scoped_tuplexof128_differential:25:width=4 [extended] | passed | 2026-10-29T11:03:38Z |
| miri-fdfb0d1b1ef788bc | sha3 | miri | sha3-fixed-boundaries:42 [routine] | passed | 2026-10-19T11:27:44Z |
| miri-fdfeba42341a784f | sha3 | miri | sha3-fixed-boundaries:27 [extended] | reused | 2026-10-28T13:39:45Z |
| miri-fe07352a54605ea4 | sha1 | miri | -p brynja-legacy-sha1 --features cpu --lib quarantined_model_clears_all_regions_without_instructions [remaining suite; inspect skips with show] | No mapped observation | — |
| miri-fe1346f43e3882b3 | tuplehash | miri | tuplehash-staging:813 [extended] | reused | 2026-10-28T18:53:02Z |
| miri-fe15f727567fbdab | md5 | miri | md5-bulk:254 [extended] | reused | 2026-10-28T11:52:43Z |
| miri-fe2fd0843da8b99c | tuplehash | miri | tuplehash-staging:866 [extended] | reused | 2026-10-28T18:51:11Z |
| miri-fe4b7189895f258b | tuplehash | miri | tuplehash-staging:266 [extended] | reused | 2026-10-28T15:38:35Z |
| miri-fe5f76dc15bed506 | md5 | miri | md5-padding:13 [extended] | reused | 2026-10-28T11:28:44Z |
| miri-fe74dbaddd0635b1 | sha1 | miri | sha1-scoped:102 [extended] | reused | 2026-10-28T13:10:11Z |
| miri-fe88eb72696e584d | tuplehash | miri | tuplehash-staging:518 [extended] | reused | 2026-10-28T16:59:44Z |
| miri-feb73a014bd0c7f7 | sha3 | miri | recoverable_unwind_clears_typed_secret_destination [extended] | reused | 2026-10-28T13:52:03Z |
| miri-fed0cf191f30805d | kmac | miri | kmac-streamed-setup:68 [routine] | No mapped observation | — |
| miri-fed8b4827a18fcb9 | tuplehash | miri | scoped_tuplexof256_differential:31:width=2 [extended] | reused | 2026-10-29T04:09:27Z |
| miri-fee48e6d4350ac60 | tuplehash | miri | scoped_tuplexof128_differential:29:width=0 [extended] | passed | 2026-10-29T11:04:36Z |
| miri-feec6afece2136f8 | md5 | miri | md5-batch-mask:161 [extended] | reused | 2026-10-28T12:19:59Z |
| miri-fef640215547e6fd | kmac | miri | kmac-scoped-lifecycle:10 [routine] | passed | 2026-10-19T11:41:59Z |
| miri-ff08d952f01288eb | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:17:width=4 [extended] | reused | 2026-10-29T04:53:46Z |
| miri-ff1cb1b1594e0d32 | tuplehash | miri | tuplehash-staging:448 [routine] | passed | 2026-10-19T11:54:31Z |
| miri-ff2088400162fdf4 | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:41:width=1 [extended] | reused | 2026-10-29T05:55:08Z |
| miri-ff2ae7af3a54b2dc | md5 | miri | md5-scoped:235 [extended] | reused | 2026-10-28T12:03:27Z |
| miri-ff47a6dc5e54ebda | parallelhash | miri | [bounded-parallelhash-v1] parallelhash-buffering:285 [extended] | passed | 2026-10-29T13:43:37Z |
| miri-ff6d5323db414a9f | tuplehash | miri | scoped_tuple256_matches_portable_bits_and_streaming:42:width=3 [extended] | reused | 2026-10-28T23:21:51Z |
| miri-ff72a1490a97e5d6 | md5 | miri | md5-padding:84 [extended] | reused | 2026-10-28T11:24:30Z |
| miri-ff8be07ead79831c | md5 | miri | md5-scoped:4 [extended] | reused | 2026-10-28T11:53:14Z |
| miri-ffbe04ceff14fb46 | tuplehash | miri | scoped_tuple128_matches_portable_bits_and_streaming:10:width=2 [extended] | reused | 2026-10-28T19:39:30Z |
| miri-ffc41a9a7cba1b43 | md5 | miri | md5-scoped:155 [extended] | reused | 2026-10-28T11:57:45Z |
| miri-ffc8def25e73f3a6 | tuplehash | miri | scoped_tuplexof256_differential:17:width=0 [extended] | passed | 2026-10-29T12:27:28Z |
| miri-ffcb996a7b97f473 | tuplehash | miri | tuplehash-staging:456 [extended] | reused | 2026-10-28T16:36:30Z |
| miri-ffcba9970504f84d | md5 | miri | md5-scoped:117 [extended] | reused | 2026-10-28T11:55:26Z |
| miri-ffd094fa979fdb9f | tuplehash | miri | tuplehash-staging:889 [routine] | passed | 2026-10-19T15:51:57Z |
| miri-ffe2275224905bf6 | sha1 | miri | sha1-bulk:244 [extended] | reused | 2026-10-28T13:01:18Z |
| miri-ffeb74424ac8760a | kmac | miri | kmac-streamed-setup:24 [routine] | No mapped observation | — |
| repository-00593fabad741825 | sha2 | repository (manual diagnostic) | python3 scripts/sha2/test-sha2-hardened-native.py | reused | 2026-10-30T07:20:03Z |
| repository-01aab5d012b3ff6a | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_msrv_output_speculation_is_not_admission HostedTests.test_output_provenance_lifetimes_and_cleanup_paths | passed | 2026-10-30T17:51:56Z |
| repository-029588db55097bbf | core | repository | python3 scripts/foundations/test-fips-architecture.py | reused | 2026-10-29T20:21:17Z |
| repository-0372254cb3b25c98 | sha1 | repository | cargo test --locked --manifest-path assurance/sha1-public-api/Cargo.toml | reused | 2026-10-30T07:17:42Z |
| repository-03f1d2b9bebce80b | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_md5_tag_cleanup_defects Hosted.test_md5_tag_cleanup_paths_and_mutations | passed | 2026-10-30T19:59:53Z |
| repository-03f6eccffadc5706 | parallelhash | repository (manual diagnostic) | python3 scripts/parallelhash/test-parallelhash-execution-native.py | reused | 2026-10-30T08:25:17Z |
| repository-04473d9e27a0546d | md5 | repository | python3 scripts/md5/test-md5-hardened.py | reused | 2026-10-29T20:21:09Z |
| repository-04810a9618a8e021 | repository | repository (manual diagnostic) | python3 scripts/repository/check-verification-status.py | passed | 2026-10-30T16:33:58Z |
| repository-0587525c246f4819 | parallelhash | repository | python3 scripts/parallelhash/test-parallelhash.py | reused | 2026-10-30T08:27:15Z |
| repository-058f9e2b2b42f93d | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_stream_input_output_and_checkpoints | passed | 2026-10-30T20:14:21Z |
| repository-0597b4d6eb4df922 | core | repository | python3 scripts/foundations/check-security-event.py | reused | 2026-10-29T20:19:31Z |
| repository-06056caa6196d2a6 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-consumer-return.py | passed | 2026-10-30T20:12:45Z |
| repository-074bceded615a96a | repository | repository (manual diagnostic) | cargo clippy --workspace --all-targets --no-default-features -- -A clippy::chunks_exact_to_as_chunks -D warnings | passed | 2026-10-30T18:16:20Z |
| repository-0776f2191750ea2d | repository | repository (manual diagnostic) | cargo clippy --workspace --all-targets --all-features -- -A clippy::chunks_exact_to_as_chunks -D warnings | passed | 2026-10-30T18:46:53Z |
| repository-08205189cb8db546 | core | repository | python3 scripts/foundations/test-provider-contract.py | reused | 2026-10-29T20:20:36Z |
| repository-092797bc89937204 | repository | repository | python3 scripts/kmac/test-kmac.py | passed | 2026-10-30T16:31:28Z |
| repository-0974afde7ff13a34 | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_public_verification_result_domain_and_profile HostedTests.test_real_compiling_public_verification_mutants | passed | 2026-10-30T18:16:17Z |
| repository-09f9719a59c97b57 | sha3 | repository | cargo test --locked --offline --manifest-path assurance/keccak-batch/Cargo.toml | reused | 2026-10-30T08:20:21Z |
| repository-0b807be959429197 | hmac | repository | python3 scripts/hmac/test-hmac-x86-sha512.py | passed | 2026-10-30T16:37:09Z |
| repository-0c796a2b0bab0a2f | sha3 | repository | python3 scripts/sha3/check-keccak-hardened.py | reused | 2026-10-30T08:21:34Z |
| repository-0c818d1da4e0e06a | pki | repository | python3 scripts/pki/check-der-reader.py | passed | 2026-10-30T16:30:22Z |
| repository-0d37731bc48e5a68 | core | repository | python3 scripts/foundations/test-security-event.py | reused | 2026-10-29T20:21:38Z |
| repository-0ea0fced22d08259 | sha3 | repository | python3 scripts/sha3/test-sha3.py | reused | 2026-10-30T08:17:43Z |
| repository-0f4c82f715ce8865 | tuplehash | repository | python3 scripts/tuplehash/check-tuplehash-execution-codegen.py | reused | 2026-10-30T08:26:17Z |
| repository-10a5e003f6d75465 | repository | repository (manual diagnostic) | scripts/assurance/check-kani.sh --policy-only | passed | 2026-10-30T16:43:31Z |
| repository-11aa04ba9aa2a947 | sha3 | repository | python3 scripts/sha3/check-sha3-bit-differential.py | reused | 2026-10-30T08:17:58Z |
| repository-1235d79db0c8165b | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-execution-cleanup.py --target aarch64-unknown-linux-gnu --toolchain 1.99.1 | passed | 2026-10-30T18:49:42Z |
| repository-12cd44154f0154cd | tuplehash | repository | python3 scripts/tuplehash/test-tuplehash-execution-policy.py | reused | 2026-10-30T08:24:37Z |
| repository-13497a5a75e6dad2 | repository | repository (manual diagnostic) | python3 scripts/standards/test-requirement-residuals.py | passed | 2026-10-30T16:36:32Z |
| repository-13aa84f010701afe | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-inner-report.py | passed | 2026-10-30T20:15:02Z |
| repository-1545d555408fcfcb | sha1 | repository | python3 scripts/sha1/test-sha1-hardened.py | reused | 2026-10-30T07:17:32Z |
| repository-154f7bb66fe7529c | repository | repository (manual diagnostic) | cargo doc --workspace --all-features --no-deps | passed | 2026-10-30T18:16:34Z |
| repository-165b43be27411ea4 | sha3 | repository | python3 scripts/sha3/check-cshake-differential.py | reused | 2026-10-30T08:19:26Z |
| repository-168d78b98ec10e61 | repository | repository (manual diagnostic) | python3 scripts/release/test-detached-verification.py | passed | 2026-10-30T16:27:07Z |
| repository-169ed476bbd3b4f6 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-consumer-internal.py | passed | 2026-10-30T20:57:07Z |
| repository-17a45d54f013fcc0 | sha3 | repository | python3 scripts/sha3/test-sha3-public-api.py | reused | 2026-10-30T08:21:20Z |
| repository-1819357493210a67 | sha2 | repository | python3 scripts/sha2/check-sha2-hardened-execution-codegen.py | reused | 2026-10-30T07:19:54Z |
| repository-1835bb300b1f9eb0 | hmac | repository | cargo test --locked --offline --manifest-path assurance/hmac-policy/Cargo.toml | passed | 2026-10-30T18:15:57Z |
| repository-183dac729969f3fc | repository | repository (manual diagnostic) | scripts/standards/verify-rfcs.sh | passed | 2026-10-30T16:35:13Z |
| repository-18b3efab01527526 | repository | repository (manual diagnostic) | scripts/release/test-release-readiness.sh | passed | 2026-10-30T16:35:04Z |
| repository-192affc2575f3c7a | kmac | repository | python3 scripts/kmac/check-kmac-execution-package.py | reused | 2026-10-30T08:25:10Z |
| repository-193e966806d36b31 | hmac | repository | python3 scripts/hmac/check-hmac-package.py | passed | 2026-10-30T18:13:57Z |
| repository-1a3adc7360e589b8 | sha2 | repository | python3 scripts/sha2/check-sha512-t-contract.py | reused | 2026-10-30T07:18:42Z |
| repository-1a53d0edb573a5a9 | kmac | repository | python3 scripts/kmac/check-kmac-differential.py | reused | 2026-10-30T08:22:51Z |
| repository-1d056c749ddf037a | static_cpu | repository (manual diagnostic) | python3 scripts/cpu/test-cpu-evidence-runner.py | reused | 2026-10-30T08:33:34Z |
| repository-1e03d0910df930ec | hmac | repository | python3 scripts/hmac/check-hmac-protected.py | passed | 2026-10-30T18:15:37Z |
| repository-1f2d3ca2205a7fc3 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-setup-reports.py | passed | 2026-10-30T20:20:12Z |
| repository-1f62d887582afc01 | core | repository | python3 scripts/foundations/check-pending-contract.py | reused | 2026-10-29T20:04:41Z |
| repository-1fd4b3e430cb1fba | repository | repository (manual diagnostic) | python3 scripts/zeroization/check-zeroization-evidence.py | passed | 2026-10-30T16:33:41Z |
| repository-1ff9a4ad7fcb6f4d | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_scalar_retained_cleanup_and_actual_helpers Hosted.test_scalar_retained_initialization_and_terminals Hosted.test_scalar_retained_storage | passed | 2026-10-30T19:28:20Z |
| repository-218fa83447cfbefb | repository | repository (manual diagnostic) | python3 scripts/cpu/check-hosted-execution.py --policy-only | passed | 2026-10-30T16:30:41Z |
| repository-21f6dc5c89c1eb3b | repository | repository (manual diagnostic) | python3 scripts/repository/test-script-layout.py | passed | 2026-10-30T16:27:33Z |
| repository-2209bcd5a36ee102 | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-md5-cleanup.py --simd | passed | 2026-10-30T18:24:42Z |
| repository-22162af270fe25cb | repository | repository (manual diagnostic) | python3 scripts/repository/check-first-party-rust-crypto.py | passed | 2026-10-30T16:28:17Z |
| repository-23096eb90924d5dd | sha2, sha3 | repository | python3 scripts/hash/test-final-acceptance.py | reused | 2026-10-30T08:32:58Z |
| repository-235e32dbf14110eb | parallelhash | repository | cargo clippy --locked --manifest-path assurance/parallelhash-std-public-api/Cargo.toml --all-targets -- -A clippy::chunks_exact_to_as_chunks -D warnings | reused | 2026-10-30T08:32:22Z |
| repository-23c7ff15f7baace2 | repository | repository (manual diagnostic) | python3 scripts/zeroization/test-scope-inputs.py | passed | 2026-10-30T16:29:30Z |
| repository-23e5298e8a0f6053 | hmac | repository | python3 scripts/hmac/test-hmac-engine-cleanup.py | passed | 2026-10-30T16:39:00Z |
| repository-240031c2653eac24 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-keys.py | passed | 2026-10-30T21:01:43Z |
| repository-24046be4f9898718 | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_emitted_compiler_identity_cannot_borrow_other_niche HostedTests.test_msrv_authority_error_niche_is_not_interchangeable HostedTests.test_worker_authority_transfer_admission_and_lifetime | passed | 2026-10-30T16:55:20Z |
| repository-24d750f6f6a5b475 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_mode_declarations Hosted.test_compiled_out_workers_only_reject Hosted.test_keyed_selection_capture_operands Hosted.test_worker_backend_matching_guard | passed | 2026-10-30T18:41:33Z |
| repository-26a0b0fc61844f33 | sha2 | repository | python3 scripts/sha2/test-sha2-public-api.py | reused | 2026-10-30T07:23:10Z |
| repository-26a4093a06f2f933 | md5 | repository | python3 scripts/md5/check-md5-cpu.py | reused | 2026-10-29T20:22:19Z |
| repository-2824182480710513 | repository | repository (manual diagnostic) | python3 scripts/repository/check-facade-package.py | passed | 2026-10-30T16:40:43Z |
| repository-2826c0743c92f2dd | hmac | repository | python3 scripts/hmac/test-hmac-cleanup.py | passed | 2026-10-30T16:44:50Z |
| repository-289a670bb3bb4739 | sha2 | repository | python3 scripts/sha2/test-sha2-hardened.py | reused | 2026-10-30T07:20:48Z |
| repository-2c48d4dbc9bb7407 | sha3 | repository | cargo clippy --locked --offline --manifest-path assurance/sha3-execution/Cargo.toml --all-targets -- -A clippy::chunks_exact_to_as_chunks -D warnings | reused | 2026-10-30T08:20:02Z |
| repository-2d20803fae49f256 | repository | repository (manual diagnostic) | cargo fmt --all --check | passed | 2026-10-30T16:27:24Z |
| repository-2d3a5f52f1419bb0 | core | repository | python3 scripts/foundations/check-provider-contract.py | reused | 2026-10-29T20:04:07Z |
| repository-2d77a203f3d71790 | repository | repository | python3 scripts/sha2/test-sha256-batch.py | passed | 2026-10-30T16:32:24Z |
| repository-2dbc1283d4de291a | tuplehash | repository | python3 scripts/tuplehash/check-tuplehash.py | reused | 2026-10-30T08:22:26Z |
| repository-2e323cc13df0ac0f | md5 | repository | python3 scripts/md5/check-md5-package.py | reused | 2026-10-30T07:16:29Z |
| repository-2e6dfa586a4bd705 | md5 | repository | scripts/md5/check-md5-codegen.sh | reused | 2026-10-29T20:23:28Z |
| repository-2ed71af2bac7b388 | hmac | repository | python3 scripts/hmac/test-hmac-strict.py | passed | 2026-10-30T18:45:49Z |
| repository-2f2fb68d409da260 | repository | repository (manual diagnostic) | python3 scripts/standards/check-protocol-surfaces.py | passed | 2026-10-30T16:35:40Z |
| repository-2fae19f115dd01bc | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-hosted-cleanup.py | passed | 2026-10-30T19:02:59Z |
| repository-30a1004b9d4ac307 | md5 | repository (manual diagnostic) | python3 scripts/md5/test-md5-execution-native.py | reused | 2026-10-29T20:21:33Z |
| repository-30b0beffbc8bc8f4 | repository | repository | python3 scripts/cryptography/test-macos-legacy-resident-package.py | passed | 2026-10-30T16:26:22Z |
| repository-30ef5e318c19e065 | sha3 | repository | python3 scripts/sha3/cshake_execution_vectors.py | reused | 2026-10-30T08:20:58Z |
| repository-31a431bc10eda930 | kmac, parallelhash, sha3, tuplehash | repository | python3 scripts/sp800185/test-portable-acceptance.py | reused | 2026-10-30T08:32:37Z |
| repository-31af0ce4fa7cf724 | parallelhash | repository | cargo test --locked --offline --manifest-path assurance/parallelhash-differential/Cargo.toml --features execution --doc | reused | 2026-10-30T08:25:49Z |
| repository-32027562cb710267 | repository | repository | python3 scripts/sha2/test-sha256.py | passed | 2026-10-30T16:31:05Z |
| repository-3332c4e80deeae2c | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-return-metadata.py | passed | 2026-10-30T21:07:07Z |
| repository-3343ad197127cf1d | repository | repository (manual diagnostic) | python3 scripts/repository/check-tracked-build-artifacts.py | passed | 2026-10-30T16:28:54Z |
| repository-3356fde6bbceef32 | parallelhash | repository | cargo test --locked --manifest-path assurance/parallelhash-std-public-api/Cargo.toml | reused | 2026-10-30T08:26:36Z |
| repository-36276815ebcafdfa | repository | repository (manual diagnostic) | python3 scripts/release/test-native-metadata-carry-forward.py | passed | 2026-10-30T16:27:03Z |
| repository-3728f8f997e23036 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_md5_report_count_backend_and_rejection_transport Hosted.test_md5_report_decision_truth_table Hosted.test_md5_report_typed_layout_probes | passed | 2026-10-30T19:07:50Z |
| repository-38759ba91053f676 | sha3 | repository | python3 scripts/sha3/check-keccak-batch.py | reused | 2026-10-30T08:18:11Z |
| repository-39665b2afe05f3ea | repository | repository (manual diagnostic) | cargo check --workspace --all-features | passed | 2026-10-30T18:46:38Z |
| repository-39dded231efc63bb | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_msrv_hosted_constructor_transfers_and_tag_provenance HostedTests.test_real_compiled_hosted_constructor_mutants | passed | 2026-10-30T17:27:07Z |
| repository-3af285b0c7f86ce3 | repository | repository (manual diagnostic) | python3 scripts/zeroization/miri_scope.py --check | passed | 2026-10-30T16:29:15Z |
| repository-3af4026c2c9b2e6d | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-cleanup.py | passed | 2026-10-30T19:04:32Z |
| repository-3b26e14866c6df93 | repository | repository (manual diagnostic) | python3 scripts/release/test-verification-plan.py | passed | 2026-10-30T16:26:36Z |
| repository-3d478f1001d638dc | sha2 | repository | python3 scripts/sha2/check-sha256-batch-codegen.py | reused | 2026-10-30T07:18:50Z |
| repository-3d4f9d8b1647b12f | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-execution-construct.py | passed | 2026-10-30T19:06:15Z |
| repository-3d87f457b5d890aa | repository | repository (manual diagnostic) | python3 scripts/repository/test-offline-bootstrap.py | passed | 2026-10-30T16:25:59Z |
| repository-3e7b54caef9e6ead | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-hosted-cleanup.py --target aarch64-unknown-linux-gnu --toolchain 1.99.1 --generic | passed | 2026-10-30T18:32:38Z |
| repository-3e9c310047203eca | kmac, parallelhash, sha3, tuplehash | repository (manual diagnostic) | python3 scripts/sp800185/check-portable-acceptance.py | reused | 2026-10-30T08:26:46Z |
| repository-3f060a5f15bf3310 | hmac, legacy_hmac | repository | python3 scripts/hmac/check-hmac-facade.py | passed | 2026-10-30T18:14:46Z |
| repository-3f735d65d5299b64 | kmac | repository | cargo clippy --locked --manifest-path assurance/kmac-public-api/Cargo.toml --all-targets -- -D warnings | reused | 2026-10-30T08:25:43Z |
| repository-423c176329812bc3 | md5 | repository | python3 scripts/md5/check-md5-differential.py | reused | 2026-10-29T20:23:17Z |
| repository-430e56a1f918beab | repository | repository (manual diagnostic) | python3 scripts/standards/test-requirements.py | passed | 2026-10-30T16:35:59Z |
| repository-4493409383c97899 | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-engine-cleanup.py --target aarch64-apple-darwin --toolchain 1.99.1 | passed | 2026-10-30T18:49:08Z |
| repository-4520c85af2da7894 | repository | repository (manual diagnostic) | python3 scripts/release/test-evidence-scope.py | passed | 2026-10-30T16:28:33Z |
| repository-463cf6a4210b0f30 | repository | repository (manual diagnostic) | python3 scripts/release/test-release-crates.py | passed | 2026-10-30T16:41:43Z |
| repository-4685ff66ef013b7b | tuplehash | repository | scripts/tuplehash/check-tuplehash-codegen.sh | reused | 2026-10-30T08:26:53Z |
| repository-46aab85ce765cc7e | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-package.py | passed | 2026-10-30T21:09:18Z |
| repository-46fea9f32b02676f | sanitization | repository | scripts/sanitization/check-sanitization-candidate.sh | reused | 2026-10-30T08:34:02Z |
| repository-479a69434532d888 | sha2 | repository | python3 scripts/sha2/check-sha512-batch-codegen.py | reused | 2026-10-30T07:18:12Z |
| repository-4835ffc01182b8f1 | repository | repository (manual diagnostic) | cargo test --workspace --all-features | passed | 2026-10-30T18:48:21Z |
| repository-48992f3b79c21e24 | repository | repository (manual diagnostic) | python3 scripts/repository/check-commit-classification.py | passed | 2026-10-30T16:33:49Z |
| repository-49a2d6df6b88773e | legacy | repository | python3 scripts/legacy-hash/test-legacy-final-acceptance.py | reused | 2026-10-30T07:15:09Z |
| repository-4a536e8362bead7c | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-teardown.py | passed | 2026-10-30T21:09:08Z |
| repository-4c157e693da4a66c | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-md5-cleanup.py | passed | 2026-10-30T18:55:40Z |
| repository-4c5385cab46413c2 | repository | repository (manual diagnostic) | python3 scripts/zeroization/test-miri-scope.py | passed | 2026-10-30T16:27:59Z |
| repository-4d3d4580e45a9111 | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-engine-cleanup.py --target aarch64-unknown-linux-gnu --toolchain 1.99.1 | passed | 2026-10-30T18:17:11Z |
| repository-4d495bd7c6f1abd8 | sha3 | repository (manual diagnostic) | python3 scripts/sha3/test-keccak-hardened-native.py | reused | 2026-10-30T08:20:38Z |
| repository-4de6f66a75c6a9a7 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_projection_reconciliation Hosted.test_reconciliation_output_is_atomic | passed | 2026-10-30T20:10:46Z |
| repository-4eafeb02930efc77 | md5 | repository | cargo test --locked --manifest-path assurance/md5-public-api/Cargo.toml | reused | 2026-10-30T07:16:39Z |
| repository-4f3fc8a30975dbb5 | sha2 | repository | python3 scripts/sha2/test-general-sha512-t-cpu.py | reused | 2026-10-30T07:19:24Z |
| repository-4f68b614ca690261 | sha3 | repository | python3 scripts/sha3/check-sha3-execution.py | reused | 2026-10-30T08:19:52Z |
| repository-4fe746dcb9d21c88 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_every_capture_field_initialization Hosted.test_worker_capture_reads_and_take_order Hosted.test_worker_completion_panic_and_result_order | passed | 2026-10-30T18:46:04Z |
| repository-50297f9aaa720bb1 | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-execution-cleanup.py | passed | 2026-10-30T18:18:10Z |
| repository-503ca631e030ab96 | sha1 | repository | python3 scripts/sha1/check-sha1-package.py | reused | 2026-10-30T07:16:38Z |
| repository-504d6844437d0bde | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_public_verification_defects Hosted.test_public_verification_results Hosted.test_public_verification_typed_and_padding | passed | 2026-10-30T20:19:24Z |
| repository-5061d56452202c67 | core | repository | python3 scripts/foundations/test-pending-contract.py | reused | 2026-10-29T20:21:05Z |
| repository-510cceb0eca9b8fc | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_actual_scalar_constructor_and_consuming_callees HostedTests.test_msrv_scalar_constructor_and_consuming_callees HostedTests.test_real_compiling_scalar_callee_mutants HostedTests.test_scalar_tag_and_partial_owner_cannot_escape | passed | 2026-10-30T17:50:43Z |
| repository-51443eab97eb3a5c | sha3 | repository | python3 scripts/sha3/check-keccak-hardened-codegen.py | reused | 2026-10-30T08:20:28Z |
| repository-5191a0fa1ae06221 | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_capture_fields_reject_substitution_and_missing_initialization HostedTests.test_capture_type_declarations_do_not_admit_owned_keyed_state HostedTests.test_worker_factory_inputs_and_local_destinations | passed | 2026-10-30T17:04:21Z |
| repository-51c062e82ebdc452 | repository | repository (manual diagnostic) | scripts/repository/check_shell_syntax.sh | passed | 2026-10-30T16:29:05Z |
| repository-52382ee0d626d362 | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_actual_wrapper_and_abstraction HostedTests.test_every_instruction_and_argument_is_load_bearing HostedTests.test_extra_access_unknown_identity_and_alias_cycle_reject | passed | 2026-10-30T17:41:46Z |
| repository-5253984cd7d41b9e | sha2 | repository | python3 scripts/sha2/check-sha2-bit-differential.py | reused | 2026-10-30T07:20:25Z |
| repository-5284d7f30b5c7f0f | sha3 | repository | cargo clippy --locked --manifest-path assurance/cshake-public-api/Cargo.toml --all-targets -- -D warnings | reused | 2026-10-30T08:19:05Z |
| repository-52ad22f57c08499e | parallelhash | repository | python3 scripts/parallelhash/check-parallelhash-differential.py | reused | 2026-10-30T08:27:32Z |
| repository-52f6fd22f835e3be | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_unknown_effects_and_fatal_join_failure | passed | 2026-10-30T20:55:38Z |
| repository-53d1503b17e4ee1e | hmac | repository | python3 scripts/hmac/check-hmac-hosted-cleanup.py --target aarch64-unknown-linux-gnu | passed | 2026-10-30T16:50:27Z |
| repository-545f5356bf01a7f0 | sha2 | repository | python3 scripts/sha2/check-sha256-batch.py --package | reused | 2026-10-30T07:18:04Z |
| repository-549d2005774ac3a1 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_normalization_descriptor_lifetimes_and_drops Hosted.test_normalization_independent_layout_and_initial_bytes Hosted.test_normalization_routes_and_copy_results | passed | 2026-10-30T19:21:26Z |
| repository-54f30d9a2aa764bf | repository | repository (manual diagnostic) | python3 scripts/repository/check-crate-readmes.py | passed | 2026-10-30T16:26:11Z |
| repository-55d7386e3f879f55 | sha2 | repository | python3 scripts/sha2/check-sha2-hardened.py | reused | 2026-10-30T07:23:22Z |
| repository-55fcad8fc4597e80 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_md5_health_checkpoint_defects | passed | 2026-10-30T19:42:57Z |
| repository-57936d560ccf738f | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_stream_output_provenance_and_cleanup | passed | 2026-10-30T20:16:19Z |
| repository-5801bc020263f950 | repository | repository (manual diagnostic) | python3 scripts/release/test-native-evidence-approval.py | passed | 2026-10-30T16:27:15Z |
| repository-59cc699620abb7a9 | hmac | repository | python3 scripts/hmac/test-hmac-protected.py | passed | 2026-10-30T18:45:57Z |
| repository-5a0039922598c76d | sanitization | repository | python3 scripts/sanitization/test-sanitization-admission.py | reused | 2026-10-30T08:28:20Z |
| repository-5a3fcbc138d0c920 | kmac | repository | scripts/kmac/check-kmac-conformance-gate.sh | reused | 2026-10-30T08:21:26Z |
| repository-5b05cbaefd90c3c9 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-package.py | passed | 2026-10-30T20:05:28Z |
| repository-5b64e119adc2f1bd | hmac | repository | python3 scripts/hmac/check-hmac-inventory.py | passed | 2026-10-30T16:37:26Z |
| repository-5c59dd796186975a | repository | repository (manual diagnostic) | scripts/release/validate-release-metadata.sh | passed | 2026-10-30T16:41:34Z |
| repository-5d44d72084862e85 | repository | repository | python3 scripts/cryptography/check-api-profiles.py | passed | 2026-10-30T16:28:38Z |
| repository-5d744757d910a7f6 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-descriptors.py | passed | 2026-10-30T21:00:36Z |
| repository-5d7e27f6d0a6d6ec | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-hosted-cleanup.py --generic | passed | 2026-10-30T18:31:57Z |
| repository-5df98b0bba640ac1 | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-hosted-cleanup.py --target aarch64-apple-darwin --toolchain 1.99.1 --generic | passed | 2026-10-30T18:33:19Z |
| repository-5e615e313e11bc3f | kmac, parallelhash, sha3, tuplehash | repository | python3 scripts/sp800185/test-execution-acceptance.py | reused | 2026-10-30T08:32:49Z |
| repository-5eadfa6b7be85bdd | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_emitted_checkpoint_callees HostedTests.test_msrv_worker_checkpoint_guards_and_results HostedTests.test_real_compiled_checkpoint_callee_mutants HostedTests.test_real_compiled_worker_checkpoint_mutants | passed | 2026-10-30T17:05:55Z |
| repository-5ef0f0021b5b8e30 | repository | repository (manual diagnostic) | python3 scripts/standards/test-standards-ledger.py | passed | 2026-10-30T16:42:14Z |
| repository-5f3701ac4b9baca3 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-output-path.py | passed | 2026-10-30T21:03:08Z |
| repository-6005881f8e06a1ec | repository | repository (manual diagnostic) | python3 scripts/release/check-release-plan.py | passed | 2026-10-30T16:34:09Z |
| repository-60110912a5a18484 | repository | repository | python3 scripts/cryptography/test-mir-cleanup-flow.py | passed | 2026-10-30T16:29:22Z |
| repository-61354f8ec2602390 | sha1 | repository | scripts/sha1/check-sha1-codegen.sh | reused | 2026-10-30T07:17:17Z |
| repository-61e8614b2cfe0ab7 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-engine-cleanup.py | passed | 2026-10-30T18:33:42Z |
| repository-62efb3f994944926 | core | repository | python3 scripts/constant-time/test-constant-time.py | reused | 2026-10-29T20:03:22Z |
| repository-6430a55003b60d8c | core | repository | python3 scripts/foundations/check-entropy-contract.py | reused | 2026-10-29T20:04:19Z |
| repository-671417c12ed85b82 | hmac | repository (manual diagnostic) | python3 scripts/hmac/test-hmac-verification.py | passed | 2026-10-30T16:37:18Z |
| repository-672f9033654dc340 | repository | repository | cargo clippy --locked --offline --manifest-path assurance/acceleration-contract/Cargo.toml --all-targets -- -D warnings | passed | 2026-10-30T16:31:20Z |
| repository-678b24accf409085 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_scalar_checkpoint_boundaries_and_error_transport Hosted.test_scalar_checkpoint_callee_acquire_and_result Hosted.test_stream_input_iterators_tail_and_error_admission Hosted.test_stream_iteration_repeated_update | passed | 2026-10-30T19:30:32Z |
| repository-67b2526cefae01f7 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_native_call_population_and_handle_identity Hosted.test_no_work_or_reclaim_while_worker_unjoined Hosted.test_shared_checker_is_unchanged_and_intrinsics_are_narrow Hosted.test_stack_clear_identity_and_completion | passed | 2026-10-30T20:05:19Z |
| repository-699c87ebc95e33fd | repository | repository | python3 scripts/sha3/test-keccak-batch-policy.py | passed | 2026-10-30T16:32:46Z |
| repository-6a3043fc6b194498 | kmac | repository | cargo test --locked --manifest-path assurance/kmac-public-api/Cargo.toml | reused | 2026-10-30T08:22:16Z |
| repository-6a7e0005ead08563 | tuplehash | repository | cargo test --locked --manifest-path assurance/tuplehash-public-api/Cargo.toml | reused | 2026-10-30T08:24:57Z |
| repository-6ad014bd8eb7896f | md5 | repository | python3 scripts/md5/test-md5.py | reused | 2026-10-30T07:16:14Z |
| repository-6c170960081ccdd0 | sha3 | repository | python3 scripts/sha3/test-keccak-hardened.py --compiled | reused | 2026-10-30T08:22:03Z |
| repository-6c3f78371d859cb3 | tuplehash | repository | python3 scripts/tuplehash/test-tuplehash.py | reused | 2026-10-30T08:25:54Z |
| repository-6dedb7b870dcef88 | sha2 | repository | cargo clippy --locked --offline --manifest-path assurance/sha256-batch/Cargo.toml --all-targets -- -D warnings -A clippy::chunks_exact_to_as_chunks | reused | 2026-10-30T07:18:59Z |
| repository-6ff5f3297ddba36c | repository | repository | python3 scripts/sha2/test-sha512-batch.py | passed | 2026-10-30T16:30:55Z |
| repository-71a86486bfd3e33f | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_split_scalar_initialization_and_tag_state | passed | 2026-10-30T18:01:45Z |
| repository-72d268f4afbaadbe | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-kani.py --policy-only | passed | 2026-10-30T18:48:31Z |
| repository-738912989d891937 | sha3 | repository (manual diagnostic) | python3 scripts/sha3/test-keccak-batch-native.py | reused | 2026-10-30T08:18:21Z |
| repository-7545585bf69c3468 | repository | repository (manual diagnostic) | scripts/release/release_crates.py --check | passed | 2026-10-30T16:34:53Z |
| repository-764b14da3f906017 | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-hosted-package.py | passed | 2026-10-30T20:20:52Z |
| repository-783c07d1613dae57 | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-md5-cleanup.py --target aarch64-unknown-linux-gnu --toolchain 1.99.1 | passed | 2026-10-30T18:58:44Z |
| repository-78af38ebfcb8bca5 | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-hosted-cleanup.py --target aarch64-apple-darwin --toolchain 1.99.1 | passed | 2026-10-30T19:04:23Z |
| repository-79147912acb27a09 | parallelhash | repository | python3 scripts/parallelhash/check-parallelhash.py | reused | 2026-10-30T08:25:06Z |
| repository-7965ceea8904c78e | sha2 | repository | python3 scripts/sha2/test-sha256-public-api.py | reused | 2026-10-30T07:22:49Z |
| repository-797354369057fc29 | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_actual_public_loan_and_construction_mutations HostedTests.test_actual_public_loan_resource_mutations HostedTests.test_loan_flow_undefined_shift_and_unreviewed_effects HostedTests.test_msrv_public_loan_and_construction_mutations | passed | 2026-10-30T17:46:24Z |
| repository-7998824660bc5b3f | kmac | repository | python3 scripts/kmac/test-kmac-execution-policy.py | reused | 2026-10-30T08:25:21Z |
| repository-79dd7c8fe009d130 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_batch_loan_scalar_walker Hosted.test_compiled_batch_loan_defects | passed | 2026-10-30T18:44:10Z |
| repository-79fdf1dde9ec9bf8 | md5 | repository | python3 scripts/md5/test-md5-execution-asan.py | reused | 2026-10-29T20:23:16Z |
| repository-7a024598f5c6fcfe | repository | repository | python3 scripts/cryptography/test-api-profiles.py | passed | 2026-10-30T16:30:15Z |
| repository-7a6576ae58a502c9 | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-hosted-cleanup.py --target aarch64-unknown-linux-gnu --toolchain 1.99.1 | passed | 2026-10-30T19:03:40Z |
| repository-7a7b61a686e0d363 | kmac | repository | python3 scripts/kmac/check-kmac-execution-codegen.py | reused | 2026-10-30T08:21:54Z |
| repository-7b8d1c6bf7310ad3 | static_cpu | repository | python3 scripts/cpu/test-backend-contract.py | reused | 2026-10-30T08:27:31Z |
| repository-7e85aabd7ebae624 | hmac | repository | python3 scripts/hmac/check-hmac-execution-cleanup.py --target aarch64-unknown-linux-gnu | passed | 2026-10-30T16:39:47Z |
| repository-7fd410b9142c250f | repository | repository (manual diagnostic) | python3 scripts/release/test-native-dependency-scope.py | passed | 2026-10-30T16:28:22Z |
| repository-801379c4e9e5bf58 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-pads.py | passed | 2026-10-30T20:16:27Z |
| repository-827cad63230beeef | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-native.py | passed | 2026-10-30T20:15:34Z |
| repository-8297c3f72601e797 | hmac | repository | python3 scripts/hmac/check-hmac-engine-cleanup.py | passed | 2026-10-30T16:38:13Z |
| repository-8382b149035f1763 | repository | repository (manual diagnostic) | python3 scripts/repository/test-facade-package.py | passed | 2026-10-30T16:34:35Z |
| repository-83b40307549efae6 | hmac | repository | python3 scripts/hmac/check-hmac-cleanup.py | passed | 2026-10-30T16:44:39Z |
| repository-83e685274c97f2aa | repository | repository | python3 scripts/hmac/test-hmac-owner-contract.py | passed | 2026-10-30T16:37:43Z |
| repository-841cf06de4709a02 | repository | repository (manual diagnostic) | python3 scripts/standards/test-protocol-surfaces.py | passed | 2026-10-30T16:42:36Z |
| repository-849e181fdefee754 | hmac | repository | python3 scripts/hmac/check-hmac-general-differential.py | passed | 2026-10-30T18:46:28Z |
| repository-8534481cfad2a79c | parallelhash | repository | cargo clippy --locked --manifest-path assurance/parallelhash-public-api/Cargo.toml --all-targets -- -A clippy::chunks_exact_to_as_chunks -D warnings | reused | 2026-10-30T08:32:12Z |
| repository-85850037b0352ae4 | repository | repository (manual diagnostic) | python3 scripts/assurance/test-assurance.py | passed | 2026-10-30T16:36:42Z |
| repository-85f103b354f288bf | tuplehash | repository | python3 scripts/tuplehash/check-tuplehash-execution.py | reused | 2026-10-30T08:26:06Z |
| repository-8643ac1fa90919e3 | hmac | repository | python3 scripts/hmac/test-hmac-inventory.py | passed | 2026-10-30T16:44:28Z |
| repository-8727d9b8bfd39625 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_host_transaction_defects Hosted.test_host_output_quarantine_transactions | passed | 2026-10-30T19:34:05Z |
| repository-88a87ed42af520ad | md5 | repository | python3 scripts/md5/check-md5.py | reused | 2026-10-29T20:20:16Z |
| repository-88c00e745399b84a | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-timing.py | passed | 2026-10-30T20:20:30Z |
| repository-88caf3aa426de5bc | sha2 | repository | python3 scripts/sha2/check-sha2-public-api.py | reused | 2026-10-30T07:20:15Z |
| repository-89014c76411dae5f | hmac | repository | python3 scripts/hmac/check-hmac-strict.py | passed | 2026-10-30T18:15:14Z |
| repository-8916a8c0eaede3e5 | sha2 | repository | scripts/sha2/check-sha2-hardened-codegen.sh | reused | 2026-10-30T07:23:32Z |
| repository-892a316456250c6c | kmac, parallelhash, sha3, tuplehash | repository (manual diagnostic) | python3 scripts/sp800185/check-execution-acceptance.py | reused | 2026-10-30T08:26:58Z |
| repository-89471bdebc405867 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-phases.py | passed | 2026-10-30T21:04:53Z |
| repository-89a27cc5e59e85c7 | acceleration, core, hmac, kmac, legacy, legacy_hmac, md5, parallelhash, sanitization, sha1, sha2, sha3, static_cpu, tuplehash | repository | scripts/zeroization/check-zeroization-codegen.sh 1.99.1 x86_64-unknown-linux-gnu | passed | 2026-10-30T16:32:25Z |
| repository-89cd4e459dc04a84 | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_dynamic_tag_cannot_escape_before_returned_owners HostedTests.test_dynamic_tag_partial_overwrites HostedTests.test_exact_constructor_helper_contexts HostedTests.test_hosted_constructor_transfers_and_tag_provenance | passed | 2026-10-30T17:12:06Z |
| repository-89fa210b0b54d13e | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_md5_report_defects | passed | 2026-10-30T19:52:20Z |
| repository-8b81a09bebcb5d2a | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_create_and_join_status_polarity Hosted.test_exact_worker_identity_not_another_valid_closure Hosted.test_graph_identity_features_paths_and_edges Hosted.test_launch_storage_and_attribute_transport | passed | 2026-10-30T20:51:38Z |
| repository-8c6ef61a7c82c141 | repository | repository | python3 scripts/cpu/test-acceleration-availability.py | passed | 2026-10-30T16:30:29Z |
| repository-8cc3ff8e8550755d | tuplehash | repository | python3 scripts/tuplehash/check-tuplehash-execution-package.py | reused | 2026-10-30T08:24:28Z |
| repository-8d3a9f8f4797e57f | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_md5_lane_defects Hosted.test_md5_lane_slots_payloads_and_rejections Hosted.test_md5_lane_typed_geometry | passed | 2026-10-30T19:04:44Z |
| repository-8e98266e2126d497 | repository | repository (manual diagnostic) | python3 scripts/repository/check-script-layout.py | passed | 2026-10-30T16:28:43Z |
| repository-8e9fb307da5f9f1c | repository | repository | python3 scripts/sha2/check-sha256.py | passed | 2026-10-30T16:30:45Z |
| repository-8e9fc491ac9f9034 | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_actual_public_verification_mutations HostedTests.test_composed_hosted_checker_reaches_every_boundary HostedTests.test_msrv_public_verification_mutations HostedTests.test_public_verification_decision_guard_is_load_bearing | passed | 2026-10-30T18:05:47Z |
| repository-8ebcaeda1446c4cf | core | repository | python3 scripts/foundations/check-fips-architecture.py | reused | 2026-10-29T20:19:10Z |
| repository-8ffa6dd32f7885e4 | sha1 | repository | python3 scripts/sha1/check-sha1-differential.py | reused | 2026-10-30T07:17:07Z |
| repository-8ffaacf4ee581ef5 | sha3 | repository | scripts/sha3/check-sha3-hardened-codegen.sh | reused | 2026-10-30T08:20:50Z |
| repository-902bcf903d1fd21a | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-cleanup.py --target aarch64-unknown-linux-gnu --toolchain 1.99.1 | passed | 2026-10-30T18:48:48Z |
| repository-90ae35843117eac7 | md5 | repository | python3 scripts/md5/test-md5-execution.py | reused | 2026-10-29T20:23:05Z |
| repository-90f6a99c12209460 | repository | repository (manual diagnostic) | python3 scripts/constant-time/test-constant-time-evidence.py | passed | 2026-10-30T16:29:58Z |
| repository-91e631c8d7850a57 | hmac | repository | python3 scripts/hmac/check-hmac-differential.py | passed | 2026-10-30T18:46:08Z |
| repository-93e7fd62e71cafd1 | hmac | repository | python3 scripts/hmac/check-hmac-execution-cleanup.py | passed | 2026-10-30T16:45:54Z |
| repository-943e504f698620a9 | repository | repository (manual diagnostic) | scripts/release/test-release-plan.sh | passed | 2026-10-30T16:33:59Z |
| repository-949afe6f0d00b474 | core | repository | python3 scripts/foundations/test-entropy-contract.py | reused | 2026-10-29T20:20:44Z |
| repository-95ca491b32dbcfa9 | repository | repository (manual diagnostic) | python3 scripts/repository/test-verification-status.py | passed | 2026-10-30T16:32:58Z |
| repository-95f64c70f8fa8e27 | hmac | repository | python3 scripts/hmac/test-hmac-acceptance.py | passed | 2026-10-30T16:37:00Z |
| repository-96a0b14c8845d403 | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_nonunwinding_source_premises_are_raw_byte_bound HostedTests.test_real_compiled_resource_and_capture_mutants HostedTests.test_unavailable_only_build_cannot_count_as_accelerated_coverage | passed | 2026-10-30T18:45:32Z |
| repository-9706d7dcd9dde9a9 | sha1 | repository | python3 scripts/sha1/check-sha1-hardened-codegen.py | reused | 2026-10-30T07:17:31Z |
| repository-972ca4fedea77521 | md5 | repository | python3 scripts/md5/test-md5-cpu.py | reused | 2026-10-29T20:23:27Z |
| repository-974585705e9c5d4c | hmac | repository | cargo clippy --locked --offline --manifest-path assurance/hmac-timing/Cargo.toml --all-targets -- -D warnings | passed | 2026-10-30T16:44:05Z |
| repository-97d6246503a60322 | sha1 | repository | python3 scripts/sha1/check-sha1-cpu.py | reused | 2026-10-30T07:16:13Z |
| repository-98c1e865fecd9e14 | sha3 | repository | cargo clippy --locked --manifest-path assurance/sha3-public-api/Cargo.toml --all-targets -- -A clippy::chunks_exact_to_as_chunks -D warnings | reused | 2026-10-30T08:21:02Z |
| repository-998ca5153f3428dc | legacy_hmac | repository (manual diagnostic) | python3 scripts/legacy-hmac/test-legacy-hmac-verification.py | passed | 2026-10-30T18:16:43Z |
| repository-9a9bb3460c18d6fb | repository | repository (manual diagnostic) | python3 scripts/sha2/check-sha2-hardened-execution.py --policy-only | passed | 2026-10-30T16:32:35Z |
| repository-9b398551a1cd2a98 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_md5_report_transport_defects Hosted.test_md5_result_bytes_lifetimes_and_errors Hosted.test_md5_result_typed_projections | passed | 2026-10-30T19:12:05Z |
| repository-9b778eff81545a08 | pki | repository | python3 scripts/pki/check-asn1-values.py | passed | 2026-10-30T16:30:33Z |
| repository-9ba3babfaaa26411 | static_cpu | repository | python3 scripts/cpu/check-backend-contract.py | reused | 2026-10-30T08:33:07Z |
| repository-9bbe59d74c22fa80 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_prearm_defects Hosted.test_prearm_projection_cache_and_walker Hosted.test_prearm_request_policy_and_artifact_defects Hosted.test_prearm_typed_layout_probes | passed | 2026-10-30T20:07:53Z |
| repository-9c1e52e6221cb76a | sha3 | repository | python3 scripts/sha3/check-keccak-batch-codegen.py | reused | 2026-10-30T08:18:32Z |
| repository-9d1f53314890a9d7 | md5 | repository (manual diagnostic) | python3 scripts/md5/test-md5-hardened-native.py | reused | 2026-10-29T20:22:55Z |
| repository-9e62255d58ec8bf9 | repository | repository (manual diagnostic) | cargo test --locked --offline --manifest-path assurance/crate-readmes/Cargo.toml --doc | passed | 2026-10-30T16:26:36Z |
| repository-a03068027be82a53 | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_compiled_worker_cleanup_paths_and_helpers HostedTests.test_msrv_inline_cleanup_and_loop_lifetimes HostedTests.test_retained_storage_lifetimes HostedTests.test_scalar_worker_cleanup_paths_and_helpers | passed | 2026-10-30T17:58:29Z |
| repository-a08b90c35936569e | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_ordinary_loan_defects Hosted.test_ordinary_loan_factories Hosted.test_ordinary_loan_methods Hosted.test_ordinary_loan_probe_population | passed | 2026-10-30T19:37:28Z |
| repository-a0d20e40ed7ecd4b | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-normalization.py | passed | 2026-10-30T21:01:55Z |
| repository-a1ce1bf917fc41e4 | tuplehash | repository | cargo clippy --locked --manifest-path assurance/tuplehash-public-api/Cargo.toml --all-targets -- -A clippy::chunks_exact_to_as_chunks -D warnings | reused | 2026-10-30T08:27:04Z |
| repository-a1dec0b792960f48 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-native.py | passed | 2026-10-30T20:20:21Z |
| repository-a248b2db5edd35e7 | md5 | repository | python3 scripts/md5/check-md5-execution-codegen.py | reused | 2026-10-29T20:21:22Z |
| repository-a34e6d863b97fadc | repository | repository (manual diagnostic) | python3 scripts/cpu/check-cpu-evidence.py | passed | 2026-10-30T16:33:32Z |
| repository-a46112ff4355701c | core | repository | python3 scripts/foundations/test-security-outcome.py | reused | 2026-10-29T20:21:28Z |
| repository-a4fb7887321604dc | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_callbacks_must_resolve_and_belong_to_the_actual_session HostedTests.test_demangler_fallback_and_exact_population HostedTests.test_each_host_executor_rejects_lifecycle_mutations HostedTests.test_graph_contamination_and_missing_owners | passed | 2026-10-30T18:12:55Z |
| repository-a5c8b2756e30eed5 | sha2 | repository | python3 scripts/sha2/check-sha2-hardened-execution.py | reused | 2026-10-30T07:22:22Z |
| repository-a6db8e2c6fa70def | sha2 | repository | python3 scripts/sha2/check-sha256-public-api.py | reused | 2026-10-30T07:19:36Z |
| repository-a88b8995e202a026 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_borrowed_lifetime_reconciliation Hosted.test_compiled_batch_width_probe_defect Hosted.test_compiled_ordinary_setup_cleanup_defect Hosted.test_ordinary_setup_error_paths | passed | 2026-10-30T19:26:17Z |
| repository-a8d20419e1864367 | repository | repository (manual diagnostic) | python3 scripts/standards/check-authority-lifecycle.py | passed | 2026-10-30T16:35:31Z |
| repository-a9764d934891597c | sha2 | repository | python3 scripts/sha2/check-sha512-batch.py --package | reused | 2026-10-30T07:18:28Z |
| repository-aac899294848e85d | repository | repository | cargo test --locked --offline --manifest-path assurance/acceleration-contract/Cargo.toml | passed | 2026-10-30T16:29:11Z |
| repository-ab29a47dff98e709 | sha3 | repository | python3 scripts/sha3/test-sha3-hardened.py | reused | 2026-10-30T08:22:14Z |
| repository-abe7941ccae18fcb | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_input_iterators_and_tail_provenance HostedTests.test_msrv_input_split_and_result_cases HostedTests.test_nonempty_part_cannot_repeat_before_advance HostedTests.test_real_compiled_input_mutants | passed | 2026-10-30T17:40:14Z |
| repository-ac507bf216d1c3bc | kmac | repository | python3 scripts/kmac/check-kmac-execution.py | reused | 2026-10-30T08:21:44Z |
| repository-ad34b409df244f44 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-cleanup.py | passed | 2026-10-30T20:12:16Z |
| repository-ad881636bd972acb | repository | repository | python3 scripts/sha2/test-sha2-hardened-execution.py | passed | 2026-10-30T16:31:15Z |
| repository-aec57f520d07a0fa | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-outer.py | passed | 2026-10-30T20:16:11Z |
| repository-af41975fd30189a6 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_md5_decision_defects Hosted.test_md5_candidate_and_decision_transport Hosted.test_md5_typed_decision_and_success_modes | passed | 2026-10-30T19:47:16Z |
| repository-b1390ef6065db2e9 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_attribute_error_cannot_launch Hosted.test_compiled_consumer_route_mutants Hosted.test_compiled_public_adapter_arguments Hosted.test_consumer_arguments_and_route_binding | passed | 2026-10-30T19:47:16Z |
| repository-b1814b08afa7a63d | core | repository | python3 scripts/foundations/check-security-outcome.py | reused | 2026-10-29T20:19:20Z |
| repository-b2ec9647e6d0c901 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-caller.py | passed | 2026-10-30T20:56:01Z |
| repository-b36fca7a5149b314 | legacy_hmac | repository | cargo test --locked --offline --manifest-path assurance/legacy-hmac-policy/Cargo.toml | passed | 2026-10-30T18:48:39Z |
| repository-b3ac65b7cc30366b | sha3 | repository | python3 scripts/sha3/check-sha3-hardened.py | reused | 2026-10-30T08:20:14Z |
| repository-b3c2a67125e3abf5 | repository | repository (manual diagnostic) | python3 scripts/standards/test-surface-security.py | passed | 2026-10-30T16:35:48Z |
| repository-b40e8d9fc76c55e1 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_md5_control_defects Hosted.test_md5_control_transport_and_vtable Hosted.test_md5_control_typed_layout_and_callbacks | passed | 2026-10-30T18:58:12Z |
| repository-b4613f13c350ffee | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_md5_pending_result_defects Hosted.test_md5_pending_result_cleanup_mutations | passed | 2026-10-30T19:56:01Z |
| repository-b577fcc764868ffa | hmac, legacy_hmac | repository | python3 scripts/hmac/test-hmac-package.py | passed | 2026-10-30T16:43:40Z |
| repository-b5a246a8af970b39 | hmac | repository | python3 scripts/hmac/check-hmac-bit-differential.py | passed | 2026-10-30T18:15:48Z |
| repository-b5c18b678bbb9503 | acceleration, core, hmac, kmac, legacy, legacy_hmac, md5, parallelhash, sanitization, sha1, sha2, sha3, static_cpu, tuplehash | repository | scripts/cryptography/check-api-profile-contract.sh | passed | 2026-10-30T16:31:42Z |
| repository-b622af90de81be9c | legacy | repository | python3 scripts/legacy-hash/test-legacy-acceptance.py | reused | 2026-10-30T07:14:46Z |
| repository-b62d09402ed9fa4d | repository | repository | python3 scripts/cryptography/test-secret-owner-compiler.py | passed | 2026-10-30T16:31:30Z |
| repository-b6c75d24b64ee6c2 | hmac | repository | python3 scripts/hmac/check-hmac-static-cleanup.py | passed | 2026-10-30T16:42:13Z |
| repository-b7204019859d89a1 | repository | repository (manual diagnostic) | python3 scripts/repository/test-unsafe-policy.py | passed | 2026-10-30T16:29:40Z |
| repository-b8123c57915c793f | sha3 | repository | python3 scripts/sha3/test-keccak-batch-codegen.py | reused | 2026-10-30T08:20:10Z |
| repository-b841986284db0eaa | hmac | repository | python3 scripts/hmac/check-hmac-engine-cleanup.py --target aarch64-unknown-linux-gnu | passed | 2026-10-30T16:45:08Z |
| repository-b9b201d645ec42df | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_accelerated_checkpoint_callee_paths_and_lifetimes Hosted.test_accelerated_checkpoint_placement_and_error_results Hosted.test_checkpoint_typed_probes_are_load_bearing Hosted.test_inlined_checkpoint_temporary_owner_provenance | passed | 2026-10-30T18:48:20Z |
| repository-b9c70a822266c929 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-inner-owner.py | passed | 2026-10-30T21:00:54Z |
| repository-ba42279cb1636280 | protocol | repository | python3 scripts/protocols/test-record-framing.py | passed | 2026-10-30T16:31:52Z |
| repository-baff4343dc916488 | protocol | repository | python3 scripts/protocols/check-record-framing.py | passed | 2026-10-30T16:30:11Z |
| repository-bbf524f8808b3888 | tuplehash | repository (manual diagnostic) | python3 scripts/tuplehash/test-tuplehash-execution-native.py | reused | 2026-10-30T08:26:27Z |
| repository-bc46e99d1cd31421 | repository | repository (manual diagnostic) | python3 scripts/standards/test-authority-lifecycle.py | passed | 2026-10-30T16:42:25Z |
| repository-bc694ba269117314 | hmac | repository | python3 scripts/hmac/test-hmac-static-cleanup.py | passed | 2026-10-30T16:47:17Z |
| repository-bc9fc370d0857f1c | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_public_loan_clear_guard_is_load_bearing HostedTests.test_real_compiling_public_loan_mutants | passed | 2026-10-30T17:38:31Z |
| repository-bcb6c5ba62acb225 | md5 | repository | scripts/md5/check-md5-cpu-codegen.sh | reused | 2026-10-29T20:22:31Z |
| repository-bd1ac9c1c5f312cf | kmac | repository (manual diagnostic) | python3 scripts/kmac/test-kmac-execution-native.py | reused | 2026-10-30T08:22:03Z |
| repository-bfe70249c664e16f | repository | repository (manual diagnostic) | python3 scripts/repository/test-macos-resident-ci.py | passed | 2026-10-30T16:26:22Z |
| repository-c021f9d379864f86 | repository | repository (manual diagnostic) | python3 scripts/standards/check-requirements.py | passed | 2026-10-30T16:42:45Z |
| repository-c06efd63d431e4a5 | sha1 | repository | python3 scripts/sha1/check-sha1-hardened.py | reused | 2026-10-30T07:17:16Z |
| repository-c0b30169cd6d35de | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_buffer_destructor_identity_order_and_keep Hosted.test_capture_extra_late_conditional_and_escaped_writes Hosted.test_capture_source_contracts Hosted.test_compiled_host_capture_and_buffer_defects | passed | 2026-10-30T19:29:16Z |
| repository-c1eda40dac2a9c6c | hmac, kmac, parallelhash, sha2, sha3, static_cpu, tuplehash | repository | python3 scripts/cpu/check-hosted-execution.py | passed | 2026-10-30T16:31:09Z |
| repository-c35c121eeeb77f06 | hmac | repository | python3 scripts/hmac/check-hmac-kani.py --policy-only | passed | 2026-10-30T16:36:51Z |
| repository-c3fac1cd95a724a6 | parallelhash | repository | cargo clippy --locked --offline --manifest-path assurance/parallelhash-differential/Cargo.toml --all-features --all-targets -- -D warnings -A clippy::chunks_exact_to_as_chunks | reused | 2026-10-30T08:32:02Z |
| repository-c42c734b4947d0b6 | sha2 | repository | scripts/sha2/check-sha256-cpu-codegen.sh | reused | 2026-10-30T08:27:22Z |
| repository-c442cf549c7e28e8 | repository | repository (manual diagnostic) | python3 scripts/standards/test-requirement-domains.py | passed | 2026-10-30T16:42:55Z |
| repository-c47f4aa199aaab6c | legacy | repository (manual diagnostic) | python3 scripts/legacy-hash/check-legacy-final-acceptance.py | reused | 2026-10-30T07:16:04Z |
| repository-c601c3e7699bcd87 | sha2 | repository | python3 scripts/sha2/check-general-sha512-t.py | reused | 2026-10-30T07:19:14Z |
| repository-c6266b078656d1d7 | repository | repository (manual diagnostic) | python3 scripts/release/test-github-release-controls.py | passed | 2026-10-30T16:34:44Z |
| repository-c6960b125cb9e1aa | sanitization | repository | scripts/sanitization/check-sanitization-adapter-codegen.sh 1.99.1 x86_64-unknown-linux-gnu | reused | 2026-10-30T08:34:17Z |
| repository-c7cb17750d1ff1b5 | hmac | repository | python3 scripts/hmac/check-hmac-cleanup.py --target aarch64-unknown-linux-gnu | passed | 2026-10-30T16:37:54Z |
| repository-c7db16863f458ed2 | sha3 | repository | python3 scripts/sha3/check-sha3.py | reused | 2026-10-30T08:19:03Z |
| repository-c80830c381b09811 | repository | repository | scripts/kmac/check-kmac-codegen.sh | passed | 2026-10-30T16:33:15Z |
| repository-c8595fe33a51884a | hmac | repository | python3 scripts/hmac/check-hmac-static-cleanup.py --target aarch64-unknown-linux-gnu | passed | 2026-10-30T16:54:41Z |
| repository-c8b7d62224f1cedf | repository | repository | python3 scripts/cpu/check-cpu-boundary.py | passed | 2026-10-30T16:33:24Z |
| repository-c90146e888135b29 | repository | repository (manual diagnostic) | python3 scripts/standards/test-requirement-sections.py | passed | 2026-10-30T16:43:05Z |
| repository-c95423351cbd278d | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-engine-cleanup.py | passed | 2026-10-30T18:48:59Z |
| repository-c9970a5c705ba80f | parallelhash | repository | cargo test --locked --manifest-path assurance/parallelhash-public-api/Cargo.toml | reused | 2026-10-30T08:26:24Z |
| repository-c9e678cc3be33b1a | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-results.py | passed | 2026-10-30T20:19:47Z |
| repository-cbacc653ab0a7b71 | core | repository | scripts/constant-time/check-constant-time-codegen.sh 1.99.1 x86_64-unknown-linux-gnu | reused | 2026-10-29T20:01:57Z |
| repository-cda8bfef3a37d333 | repository | repository (manual diagnostic) | python3 scripts/standards/test-requirement-transports.py | passed | 2026-10-30T16:36:09Z |
| repository-ce2b1f0c9c412fcb | sha3 | repository | python3 scripts/sha3/check-sha3-public-api.py | reused | 2026-10-30T08:20:46Z |
| repository-cf0a436ed516e9c5 | parallelhash | repository | python3 scripts/parallelhash/check-parallelhash-execution-codegen.py --toolchain 1.98.1 | reused | 2026-10-30T08:26:12Z |
| repository-cf79c7f6156a9b6b | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-cleanup.py | passed | 2026-10-30T18:16:53Z |
| repository-d144398cb1acbc32 | pki | repository | python3 scripts/pki/test-der-reader.py | passed | 2026-10-30T16:32:03Z |
| repository-d21b9dc44625f653 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_scalar_constructor_provenance | passed | 2026-10-30T20:02:29Z |
| repository-d2646eed3d308e4c | sha3 | repository | cargo test --locked --manifest-path assurance/cshake-public-api/Cargo.toml | reused | 2026-10-30T08:20:33Z |
| repository-d273904dffd0ae84 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_scalar_constructor_births_transfers_and_renaming Hosted.test_scalar_constructor_key_pad_status_and_cleanup Hosted.test_scalar_constructor_scratch_and_catch_boundary | passed | 2026-10-30T19:35:01Z |
| repository-d2f163fc5f001ac4 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_md5_checkpoint_callee_provenance Hosted.test_md5_health_and_checkpoint_boundaries Hosted.test_md5_status_bit_identity_and_cycle_rejection | passed | 2026-10-30T18:53:20Z |
| repository-d30837d21063a917 | hmac | repository | python3 scripts/hmac/check-hmac-hosted-cleanup.py --target aarch64-apple-darwin | passed | 2026-10-30T17:00:57Z |
| repository-d3438695ea6156c9 | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-md5-cleanup.py --target aarch64-apple-darwin --toolchain 1.99.1 | passed | 2026-10-30T19:01:46Z |
| repository-d3af4dc516a5d9c7 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-md5-handoff.py | passed | 2026-10-30T20:14:30Z |
| repository-d4579e03970a40e8 | repository | repository | python3 scripts/cpu/check-acceleration-availability.py | passed | 2026-10-30T16:28:49Z |
| repository-d5cf997d4f90583a | sha1 | repository | python3 scripts/sha1/test-sha1.py | reused | 2026-10-30T07:16:49Z |
| repository-d7dca58b5097b240 | sha1 | repository | python3 scripts/sha1/check-sha1.py | reused | 2026-10-30T07:15:23Z |
| repository-d8c125313200f4e5 | repository | repository | python3 scripts/cpu/test-cpu-boundary.py | passed | 2026-10-30T16:31:53Z |
| repository-d935df4568c321a6 | repository | repository (manual diagnostic) | scripts/repository/test-shell-syntax.sh | passed | 2026-10-30T16:27:50Z |
| repository-dc7410428d2320eb | sha2 | repository | python3 scripts/sha2/test-sha512-t-contract.py | reused | 2026-10-30T07:19:07Z |
| repository-dd135bf60cea4054 | parallelhash | repository | python3 scripts/parallelhash/check-parallelhash-execution-codegen.py --toolchain 1.90.0 | reused | 2026-10-30T08:31:52Z |
| repository-dda38d51f2f2b25f | hmac | repository (manual diagnostic) | python3 scripts/hmac/test-hmac-workspace.py | passed | 2026-10-30T16:44:15Z |
| repository-ddf7a456ca340765 | core | repository | python3 scripts/constant-time/check-constant-time.py | reused | 2026-10-29T20:01:45Z |
| repository-de3123d02730081d | hmac | repository | python3 scripts/hmac/test-hmac-timing.py | passed | 2026-10-30T16:43:55Z |
| repository-de6ddc8bb9811223 | repository | repository (manual diagnostic) | python3 scripts/zeroization/test-zeroization-evidence.py | passed | 2026-10-30T16:32:14Z |
| repository-debfb1a561f3a093 | repository | repository (manual diagnostic) | python3 scripts/cpu/test-cpu-evidence.py | passed | 2026-10-30T16:32:04Z |
| repository-decb54c0995ba3da | md5 | repository | python3 scripts/md5/check-md5-hardened.py | reused | 2026-10-29T20:20:57Z |
| repository-dee01a01b23e40e0 | sha1 | repository | python3 scripts/sha1/test-sha1-cpu.py | reused | 2026-10-30T07:16:58Z |
| repository-df4aa0d5ebec4408 | core | repository | python3 scripts/constant-time/test-constant-time-codegen.py | reused | 2026-10-29T20:03:32Z |
| repository-dfa5d046ada59c0e | static_cpu | repository | scripts/cpu/check-cpu-admission-fixture.sh | reused | 2026-10-30T08:28:02Z |
| repository-dfe1132d65f1e9aa | sha2 | repository | python3 scripts/sha2/test-general-sha512-t.py | reused | 2026-10-30T07:20:33Z |
| repository-e07fb603210a43af | sanitization | repository | python3 scripts/sanitization/check-sanitization-admission.py | reused | 2026-10-30T08:33:52Z |
| repository-e09e8a5265cf62d7 | pki | repository | python3 scripts/pki/test-asn1-values.py | passed | 2026-10-30T16:32:13Z |
| repository-e1116624b931ffd5 | repository | repository | python3 scripts/kmac/check-kmac.py | passed | 2026-10-30T16:32:57Z |
| repository-e1ee14d77592d7c2 | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_real_compiled_host_transaction_mutants HostedTests.test_transaction_undefined_bits_and_unsigned_extension | passed | 2026-10-30T18:08:28Z |
| repository-e1fe14644fe1257a | repository | repository (manual diagnostic) | scripts/standards/verify-local-references.sh | passed | 2026-10-30T16:42:05Z |
| repository-e20fe3e39d237fd7 | sha3 | repository | cargo clippy --locked --offline --manifest-path assurance/keccak-batch/Cargo.toml --all-targets -- -D warnings -A clippy::chunks_exact_to_as_chunks | reused | 2026-10-30T08:18:54Z |
| repository-e29f3dd756b3d0c4 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_accelerated_checkpoint_defects | passed | 2026-10-30T19:32:49Z |
| repository-e38661d8f4a011e4 | hmac | repository | python3 scripts/hmac/test-hmac-execution-cleanup.py | passed | 2026-10-30T16:52:15Z |
| repository-e3bb1fa117b41f8e | md5 | repository | python3 scripts/md5/check-md5-hardened-codegen.py | reused | 2026-10-29T20:22:46Z |
| repository-e4447e60fa1691af | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-md5-cleanup.py --target aarch64-apple-darwin --toolchain 1.99.1 --simd | passed | 2026-10-30T18:30:49Z |
| repository-e4dba8f25ab60c13 | repository | repository (manual diagnostic) | python3 scripts/repository/test-tracked-build-artifacts.py | passed | 2026-10-30T16:27:41Z |
| repository-e5e14ae29a33d170 | repository | repository (manual diagnostic) | python3 scripts/standards/test-requirement-history.py | passed | 2026-10-30T16:43:14Z |
| repository-e5fa01e2760b6f09 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_authority_compiler_identity_is_not_inferred_from_niche Hosted.test_authority_error_exclusion_and_live_storage Hosted.test_authority_every_transfer_write_and_escape Hosted.test_authority_factory_mode_identity_and_keyed_borrow | passed | 2026-10-30T19:23:14Z |
| repository-e64f9e5f65e6977c | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_compiled_md5_tag_copy_defects Hosted.test_md5_tag_copy_masks_lengths_and_errors Hosted.test_md5_tag_copy_operand_guard_and_effect_mutations | passed | 2026-10-30T19:19:03Z |
| repository-e68ddbb3db98c9b8 | sha1 | repository | scripts/sha1/check-sha1-cpu-codegen.sh | reused | 2026-10-30T07:16:24Z |
| repository-e81cd93a5eac2f01 | repository | repository | python3 scripts/cryptography/check-secret-owner-compiler.py | passed | 2026-10-30T16:30:01Z |
| repository-e8455929d0446a37 | repository | repository (manual diagnostic) | python3 scripts/assurance/check-assurance.py | passed | 2026-10-30T16:43:23Z |
| repository-e87bb3abc7d28c2a | sha3 | repository | python3 scripts/sha3/check-sha3-differential.py | reused | 2026-10-30T08:19:14Z |
| repository-e9d228227aabc82d | repository | repository (manual diagnostic) | cargo fetch --locked | passed | 2026-10-30T16:25:59Z |
| repository-ea316f2ad1e87ee4 | md5 | repository | python3 scripts/md5/check-md5-execution.py | reused | 2026-10-29T20:22:28Z |
| repository-ea5beda1b6764a28 | hmac | repository | python3 scripts/hmac/test-hmac-facade.py | passed | 2026-10-30T18:45:40Z |
| repository-ec9e9b7905858137 | sha2 | repository | python3 scripts/sha2/check-sha2-execution.py | reused | 2026-10-30T07:21:02Z |
| repository-ed64eadd8c18580b | repository | repository (manual diagnostic) | scripts/repository/validate-workspace.sh | passed | 2026-10-30T16:34:19Z |
| repository-ee14450624659eca | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_actual_compiled_consuming_handoffs_and_cleanup HostedTests.test_compiled_handoff_continuation_guard_is_load_bearing HostedTests.test_msrv_compiled_consuming_handoffs_and_cleanup HostedTests.test_real_compiling_accelerated_consumer_mutants | passed | 2026-10-30T17:17:39Z |
| repository-eee7be1ad0faab8f | repository | repository (manual diagnostic) | python3 scripts/repository/check-unsafe-policy.py | passed | 2026-10-30T16:28:08Z |
| repository-ef26b10195d1c606 | tuplehash | repository | python3 scripts/tuplehash/check-tuplehash-differential.py | reused | 2026-10-30T08:22:43Z |
| repository-ef816123cb0b7187 | repository | repository (manual diagnostic) | python3 scripts/repository/test-crate-readmes.py | passed | 2026-10-30T16:26:11Z |
| repository-eff89e7447bf2554 | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_worker_checkpoint_arguments_guards_and_results | passed | 2026-10-30T17:08:03Z |
| repository-f022c8192bf777b0 | repository | repository (manual diagnostic) | python3 scripts/cpu/check-static-execution.py --policy-only | passed | 2026-10-30T16:29:00Z |
| repository-f14d5029d1464b3b | core | repository | python3 scripts/foundations/check-clock-contract.py | reused | 2026-10-29T20:04:31Z |
| repository-f246ef13db815d31 | sha3 | repository | scripts/sha3/check-sha3-cpu-codegen.sh | reused | 2026-10-30T08:22:25Z |
| repository-f2702024f870bb53 | repository | repository (manual diagnostic) | scripts/repository/check_doc_links.sh | passed | 2026-10-30T16:32:37Z |
| repository-f3239e176ec5272d | legacy | repository (manual diagnostic) | python3 scripts/legacy-hash/check-legacy-acceptance.py | reused | 2026-10-30T07:15:53Z |
| repository-f3813d956f8d6816 | parallelhash | repository | python3 scripts/parallelhash/check-parallelhash-execution-differential.py | reused | 2026-10-30T08:25:36Z |
| repository-f392abf9eb42d1ad | core | repository | python3 scripts/foundations/test-clock-contract.py | reused | 2026-10-29T20:20:53Z |
| repository-f414afa008addb0d | repository | repository (manual diagnostic) | python3 scripts/repository/test-workspace-metadata.py | passed | 2026-10-30T16:34:23Z |
| repository-f5a510a29ad67f57 | sha3 | repository | python3 scripts/sha3/test-keccak-batch-package.py | reused | 2026-10-30T08:19:59Z |
| repository-f5ea4cbf08d3b58d | kmac | repository | cargo clippy --locked --offline --manifest-path assurance/kmac-execution/Cargo.toml --all-targets -- -D warnings | reused | 2026-10-30T08:25:32Z |
| repository-f7303a3d4f3ae00d | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_batch_loan_factories Hosted.test_batch_loan_forwarding_and_move Hosted.test_batch_loan_methods Hosted.test_batch_loan_projection_cache_identity | passed | 2026-10-30T19:25:19Z |
| repository-f79adba66ad393d3 | parallelhash | repository | python3 scripts/parallelhash/check-parallelhash-execution-package.py | reused | 2026-10-30T08:31:29Z |
| repository-f7a41bc0b96b410e | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-execution-handoff.py | passed | 2026-10-30T18:35:51Z |
| repository-f80b3fac4f72e1f5 | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-execution-cleanup.py | passed | 2026-10-30T18:35:25Z |
| repository-f88dab0f8b34d1b8 | tuplehash | repository | cargo clippy --locked --offline --manifest-path assurance/tuplehash-execution/Cargo.toml --all-targets -- -D warnings | reused | 2026-10-30T08:24:47Z |
| repository-f8963b5ad3b3f084 | hmac | repository | python3 scripts/hmac/check-hmac-hosted-cleanup.py | passed | 2026-10-30T16:57:48Z |
| repository-f8a94fc1629ffab2 | repository | repository (manual diagnostic) | python3 scripts/hash/check-final-acceptance.py | passed | 2026-10-30T16:31:40Z |
| repository-fa119b87d760d44f | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-execution-admission.py | passed | 2026-10-30T19:05:01Z |
| repository-fa5fb9c537b949d3 | repository | repository (manual diagnostic) | cargo check --workspace --no-default-features | passed | 2026-10-30T18:16:06Z |
| repository-fa7c53436aa3d9d5 | repository | repository (manual diagnostic) | python3 scripts/standards/check-standards-ledger.py | passed | 2026-10-30T16:35:22Z |
| repository-faf282d949ab66c0 | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_keyed_result_admission_transfer_and_lifetimes HostedTests.test_msrv_keyed_error_niche_is_not_interchangeable | passed | 2026-10-30T17:32:35Z |
| repository-fb0212e34aa4e7dc | repository | repository (manual diagnostic) | scripts/repository/check-packages.sh | passed | 2026-10-30T16:41:56Z |
| repository-fb882fc26723aabd | sha2 | repository | cargo clippy --locked --offline --manifest-path assurance/sha512-batch/Cargo.toml --all-targets -- -D warnings -A clippy::chunks_exact_to_as_chunks | reused | 2026-10-30T07:18:21Z |
| repository-fba9750816212ae2 | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-package.py | passed | 2026-10-30T21:09:32Z |
| repository-fbf07590353e12a8 | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-execution-cleanup.py --target aarch64-apple-darwin --toolchain 1.99.1 | passed | 2026-10-30T18:18:45Z |
| repository-fbf3d8c0759c6cfa | repository | repository (manual diagnostic) | python3 scripts/repository/test-commit-classification.py | passed | 2026-10-30T16:32:47Z |
| repository-fbfb892cc9fd0b87 | static_cpu | repository | python3 scripts/cpu/check-static-execution.py | reused | 2026-10-29T20:17:58Z |
| repository-fc5a212548255f56 | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-md5-cleanup.py --target aarch64-unknown-linux-gnu --toolchain 1.99.1 --simd | passed | 2026-10-30T18:27:44Z |
| repository-fc9995b9c28f75ae | legacy_hmac | repository | python3 scripts/legacy-hmac/test-legacy-hmac-hosted-cleanup.py Hosted.test_keyed_admission_bytes_errors_and_renaming Hosted.test_keyed_storage_lifetimes_and_escapes Hosted.test_keyed_terminal_handoffs Hosted.test_retained_cleanup_and_selector_immutability | passed | 2026-10-30T18:50:17Z |
| repository-fcf051493055c21c | sha3 | repository | python3 scripts/sha3/test-keccak-batch-asan.py | reused | 2026-10-30T08:18:43Z |
| repository-fd18013034bff4a2 | hmac | repository | python3 scripts/hmac/test-hmac-hosted-cleanup.py HostedTests.test_emitted_buffer_destructor_mutations HostedTests.test_hosted_actual_constructor_authority_binding HostedTests.test_joined_host_transaction_mutations HostedTests.test_msrv_joined_host_transaction_mutations | passed | 2026-10-30T17:55:56Z |
| repository-fd95a7b7cbbcd3df | repository | repository (manual diagnostic) | python3 scripts/constant-time/check-constant-time-evidence.py | passed | 2026-10-30T16:28:27Z |
| repository-fdd7a5395cf533af | repository | repository (manual diagnostic) | python3 scripts/standards/test-requirement-lifecycles.py | passed | 2026-10-30T16:36:19Z |
| repository-fea98a075116864b | legacy_hmac | repository | python3 scripts/legacy-hmac/check-legacy-hmac-cleanup.py --target aarch64-apple-darwin --toolchain 1.99.1 | passed | 2026-10-30T18:17:02Z |
| repository-ff1f5f34fb4250cc | repository | repository (manual diagnostic) | python3 scripts/repository/test-first-party-rust-crypto.py | passed | 2026-10-30T16:29:48Z |
| asan-042a47777703c066 | legacy | retired-history | RUSTFLAGS="-Zsanitizer=address" cargo +nightly-2026-09-11 test --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib --target x86_64-unknown-linux-gnu | reused | 2026-10-26T14:15:02Z |
| matrix-0def8b57fe9ef9e5 | legacy | retired-history | cargo "+1.93.0" test --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib | reused | 2026-10-26T14:08:37Z |
| matrix-115ca02bce643a21 | legacy | retired-history | cargo "+1.98.0" test --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib | passed | 2026-10-26T20:17:49Z |
| matrix-2889f28544f5fc12 | legacy | retired-history | cargo "+1.99.0" test --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib | passed | 2026-10-26T20:20:00Z |
| matrix-2a7abbe13a2f301f | legacy | retired-history | cargo "+1.94.0" test --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib | passed | 2026-10-26T20:11:13Z |
| matrix-39344ee38b6bbd9b | legacy | retired-history | cargo "+1.96.0" test --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib | passed | 2026-10-26T20:13:20Z |
| matrix-3b067f54759152c9 | legacy | retired-history | cargo "+1.91.0" test --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib | reused | 2026-10-26T14:05:15Z |
| matrix-7f02130edb73ba1a | legacy | retired-history | cargo "+1.97.1" test --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib | reused | 2026-10-26T14:18:22Z |
| matrix-8489c9531ba7c5d7 | legacy | retired-history | cargo "+1.97.0" test --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib | passed | 2026-10-26T20:15:29Z |
| matrix-8a571ebf3dbb2cdf | legacy | retired-history | cargo "+1.98.1" test --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib | reused | 2026-10-26T14:21:15Z |
| matrix-a30061292f60c7d1 | legacy | retired-history | cargo "+1.99.1" test --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib | reused | 2026-10-26T14:24:03Z |
| matrix-aee008dcd9522c08 | legacy | retired-history | cargo "+1.92.0" test --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib | passed | 2026-10-26T20:09:06Z |
| matrix-bd9dc7cf59e176fe | legacy | retired-history | cargo "+1.96.1" test --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib | reused | 2026-10-26T14:15:19Z |
| matrix-c5f5037fdede34b2 | legacy | retired-history | cargo "+1.95.0" test --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib | reused | 2026-10-26T14:12:01Z |
| matrix-e87d7f3803ee07df | legacy | retired-history | cargo "+1.90.0" test --locked --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib | passed | 2026-10-26T20:07:00Z |
| miri-00f1be442aa8cc65 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=44 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:34:09Z |
| miri-0131539d045c14ce | legacy | retired-history | --manifest-path assurance/legacy-hash-public-api/Cargo.toml --lib dynamic_ [remaining suite; inspect skips with show] | passed | 2026-10-19T13:55:08Z |
| miri-01a65bca484a39a9 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=31 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:17:45Z |
| miri-0340dbf8e318de0f | parallelhash | retired-history | parallelhash-execution-stream:33 [routine] | passed | 2026-10-19T13:47:31Z |
| miri-0362e7c8d9afedaa | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=45 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T06:07:36Z |
| miri-03e3a5ff6804faa3 | parallelhash | retired-history | parallelhashxof-official:5 [routine] | passed | 2026-10-19T13:26:25Z |
| miri-04681db14f50c845 | parallelhash | retired-history | scoped_scheduled128_lifecycle:2 [routine] | passed | 2026-10-19T17:07:27Z |
| miri-046bac6d816421d7 | parallelhash | retired-history | parallelhash-execution-stream:36 [routine] | passed | 2026-10-19T17:22:57Z |
| miri-068775b28cd166ac | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=46 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:59:12Z |
| miri-06c485d0a64b3fb3 | parallelhash | retired-history | scoped_scheduled256_matches:22 [routine] | passed | 2026-10-19T13:07:10Z |
| miri-06d02f7d21e082a6 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=29 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:43:39Z |
| miri-072b191b96580588 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=8 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:09:27Z |
| miri-07819e157b6ae344 | parallelhash | retired-history | parallelhash-buffering:336 [routine] | passed | 2026-10-19T13:34:17Z |
| miri-07c3774bd20a020d | parallelhash | retired-history | scoped_scheduled128_matches:31 [routine] | passed | 2026-10-19T16:54:14Z |
| miri-086935c105700a91 | parallelhash | retired-history | parallelhash-buffering:507 [routine] | passed | 2026-10-19T13:31:45Z |
| miri-086d8e61b41497d2 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=15 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:13:06Z |
| miri-089589fd8bd3449d | parallelhash | retired-history | scoped_scheduled128_lifecycle:3 [routine] | passed | 2026-10-19T13:33:48Z |
| miri-0a5289d563d66551 | parallelhash | retired-history | -p brynja-hash-parallel --features hardened-execution --lib hardened_in_place::tests::scoped_parallel128_matches_and_clears -- --exact BRYNJA_MIRI_CASE=4 BRYNJA_MIRI_PROFILE=extended | cancelled | 2026-10-29T07:16:31Z |
| miri-0b32acbc613461f7 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=11 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:46:21Z |
| miri-0c1493ea04e1ef3a | parallelhash | retired-history | scoped_parallel256_matches_and_clears:36 [routine] | passed | 2026-10-19T12:44:26Z |
| miri-0d7de7a08bff200d | parallelhash | retired-history | parallelhash-leaf:37 [routine] | passed | 2026-10-19T13:29:39Z |
| miri-0d90eb2eee5827d7 | parallelhash | retired-history | parallelhash-buffering:285 [routine] | passed | 2026-10-19T13:13:51Z |
| miri-0e6fb4bcf664f226 | kmac | retired-history | -p brynja-mac-kmac --features hardened-execution --test execution -- --skip packer::framing_tests::borrowed_fragments_match_bit_oracle_at_every_alignment --skip hardened_in_place::tests::scoped_lifecycle_strength_and_verification_failures --skip hardened_in_place::xof::tests::scoped_xof_lifecycle_shapes_and_large_public_reads --skip all_six_official_kmac_examples_match --skip all_six_official_kmacxof_examples_match --skip streaming_and_one_shot_are_identical_at_rate_boundaries --skip domain_substitution_changes_outputs_and_fixed_is_not_xof_prefix --skip verification_accepts_exact_tag_and_rejects_first_last_and_length_changes --skip arbitrary_bits_are_canonical_and_streaming_xof_tracks_output | passed | 2026-10-28T14:01:48Z |
| miri-0f7c733e969a934d | parallelhash | retired-history | scoped_parallel128_matches_and_clears:9 [routine] | passed | 2026-10-19T12:47:56Z |
| miri-103043462ffd868f | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=24 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:06:57Z |
| miri-104de4347559e92a | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=22 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:33:52Z |
| miri-110db66856c0da47 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=47 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T21:37:27Z |
| miri-11212bbbf0a43cbc | parallelhash | retired-history | parallelhash-execution-stream:27 [routine] | passed | 2026-10-19T13:32:31Z |
| miri-11a5fe849d4cafe6 | parallelhash | retired-history | parallelhash-hosted-domains:0 [routine] | passed | 2026-10-19T17:24:26Z |
| miri-121d1adf5d9e1134 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=9 BRYNJA_MIRI_PROFILE=extended | cancelled | 2026-10-29T07:16:31Z |
| miri-122d0e4b0a3876cb | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=0 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:17:57Z |
| miri-129dd920397c8472 | parallelhash | retired-history | parallelhash-hosted-faults:0 [routine] | passed | 2026-10-19T13:55:53Z |
| miri-13dc2589fe6c8139 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=7 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:24:29Z |
| miri-14676940f62e43a2 | parallelhash | retired-history | parallelhash-buffering:57 [routine] | passed | 2026-10-19T13:09:54Z |
| miri-14ac90a872bad5e9 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=27 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:59:46Z |
| miri-15515f1da130524c | parallelhash | retired-history | scoped_scheduled256_matches:18 [routine] | passed | 2026-10-19T13:02:13Z |
| miri-15cc710ae9c8c09b | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=35 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:42:23Z |
| miri-16d642678ec73d22 | parallelhash | retired-history | scoped_scheduled128_unwind_reuse:3 [routine] | passed | 2026-10-19T13:27:02Z |
| miri-18156ce8101b647e | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=45 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:28:25Z |
| miri-19167ed9c1bd6cad | parallelhash | retired-history | parallelhash-execution-stream:24 [routine] | passed | 2026-10-19T17:21:47Z |
| miri-1a6299270ee6a94b | parallelhash | retired-history | parallelhash-execution-stream:12 [routine] | passed | 2026-10-19T17:19:48Z |
| miri-1ab72adcedf60bfc | parallelhash | retired-history | scoped_parallel256_matches_and_clears:27 [routine] | passed | 2026-10-19T16:32:21Z |
| miri-1c0a230b645db9e8 | parallelhash | retired-history | scoped_parallel_xof128_matches_and_clears:36 [routine] | passed | 2026-10-19T12:55:11Z |
| miri-1c486128e6964d62 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=44 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T21:05:12Z |
| miri-1d2e882a42ba5db4 | parallelhash | retired-history | parallelhash-execution-stream:18 [routine] | passed | 2026-10-19T13:49:11Z |
| miri-1d89333b0f06234b | parallelhash | retired-history | -p brynja-hash-parallel --features hardened-execution --lib hardened_in_place::tests::scoped_parallel128_matches_and_clears -- --exact BRYNJA_MIRI_CASE=1 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T06:59:11Z |
| miri-1ddc017964991c31 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=37 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:03:13Z |
| miri-1ee0bfac0b879fdb | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=7 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:39:20Z |
| miri-1f788d0c4ca653e2 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=11 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:23:30Z |
| miri-201061d5173bb82d | parallelhash | retired-history | parallelhash-buffering:0 [routine] | passed | 2026-10-19T13:30:48Z |
| miri-201808d9e13f4bdf | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=49 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:52:14Z |
| miri-2046db34d78114bc | kmac | retired-history | -p brynja-mac-kmac --features hardened-execution --lib execution -- --skip packer::framing_tests::borrowed_fragments_match_bit_oracle_at_every_alignment --skip hardened_in_place::tests::scoped_lifecycle_strength_and_verification_failures --skip hardened_in_place::xof::tests::scoped_xof_lifecycle_shapes_and_large_public_reads --skip all_six_official_kmac_examples_match --skip all_six_official_kmacxof_examples_match --skip streaming_and_one_shot_are_identical_at_rate_boundaries --skip domain_substitution_changes_outputs_and_fixed_is_not_xof_prefix --skip verification_accepts_exact_tag_and_rejects_first_last_and_length_changes --skip arbitrary_bits_are_canonical_and_streaming_xof_tracks_output | passed | 2026-10-28T13:49:53Z |
| miri-20aa50a351c08c71 | parallelhash | retired-history | -p brynja-hash-parallel --features hardened-execution --lib hardened_in_place::tests::scoped_parallel128_matches_and_clears -- --exact BRYNJA_MIRI_CASE=5 BRYNJA_MIRI_PROFILE=extended | cancelled | 2026-10-29T07:16:31Z |
| miri-21b3964aed9dd393 | parallelhash | retired-history | scoped_execution_workers_join128:0 [routine] | passed | 2026-10-19T13:55:30Z |
| miri-229e3f6dd87c21e6 | parallelhash | retired-history | scoped_parallel_xof256_matches_and_clears:23 [routine] | passed | 2026-10-19T16:48:34Z |
| miri-23efbc6eeaf0ef88 | parallelhash | retired-history | parallelhash-buffering:630 [routine] | passed | 2026-10-19T17:06:49Z |
| miri-24882616da701fe2 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=18 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:47:19Z |
| miri-257aaa68961b90cf | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=23 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:50:03Z |
| miri-25f6c7d24acff071 | parallelhash | retired-history | scoped_parallel128_matches_and_clears:6 [routine] | passed | 2026-10-19T12:28:36Z |
| miri-273ba5234594b220 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=12 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:16:00Z |
| miri-27554bd1b34b0b52 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=16 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T19:55:42Z |
| miri-279d912d705f5313 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=4 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:02:53Z |
| miri-290d4758cddcc5a1 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=4 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:24:45Z |
| miri-2a85fd249eab0be8 | parallelhash | retired-history | scoped_scheduled128_unwind_reuse:1 [routine] | passed | 2026-10-19T13:41:06Z |
| miri-2b35b903c7fe5afa | kmac | retired-history | -p brynja-mac-kmac --tests -- --skip packer::framing_tests::borrowed_fragments_match_bit_oracle_at_every_alignment --skip hardened_in_place::tests::scoped_lifecycle_strength_and_verification_failures --skip hardened_in_place::xof::tests::scoped_xof_lifecycle_shapes_and_large_public_reads --skip all_six_official_kmac_examples_match --skip all_six_official_kmacxof_examples_match --skip streaming_and_one_shot_are_identical_at_rate_boundaries --skip domain_substitution_changes_outputs_and_fixed_is_not_xof_prefix --skip verification_accepts_exact_tag_and_rejects_first_last_and_length_changes --skip arbitrary_bits_are_canonical_and_streaming_xof_tracks_output | passed | 2026-10-28T19:45:58Z |
| miri-2b940233739f3edc | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=36 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:35:29Z |
| miri-2d3ee04f47087449 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=1 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T07:08:40Z |
| miri-2e84ad0bd674e791 | parallelhash | retired-history | parallelhash-leaf:46 [routine] | passed | 2026-10-19T13:08:11Z |
| miri-2f75ef0e3e2a93bb | parallelhash | retired-history | parallelhash-hosted-order:3 [routine] | passed | 2026-10-19T13:58:33Z |
| miri-2f9244fdfc38910e | parallelhash | retired-history | scoped_scheduled256_matches:0 [routine] | passed | 2026-10-19T13:19:48Z |
| miri-318f3ef059f0d640 | parallelhash | retired-history | scoped_execution_workers_join256:3 [routine] | passed | 2026-10-19T13:52:10Z |
| miri-31db91be4769396d | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=2 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:17:15Z |
| miri-31ec1f618477ffac | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=41 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T05:55:08Z |
| miri-3236bd8df521e729 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=7 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T19:59:05Z |
| miri-328aeb96b1a8fb5b | parallelhash | retired-history | parallelhash-hosted-order:0 [routine] | passed | 2026-10-19T13:38:12Z |
| miri-338cf9bd245cfd71 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=43 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T04:41:29Z |
| miri-345ac776f2e2fb9f | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=18 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:24:48Z |
| miri-34c60c754dd8bed6 | parallelhash | retired-history | scoped_scheduled256_lifecycle:4 [routine] | passed | 2026-10-19T13:34:57Z |
| miri-361e0fe333454aac | parallelhash | retired-history | parallelhash-official:2 [routine] | passed | 2026-10-19T13:40:44Z |
| miri-36b7ebccfb1d7ed8 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=15 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:38:34Z |
| miri-36f78ed3d1a207ac | parallelhash | retired-history | parallelhash-hosted-faults:1 [routine] | passed | 2026-10-19T13:36:27Z |
| miri-3a6b2b921a567ab8 | parallelhash | retired-history | parallelhash-buffering:114 [routine] | passed | 2026-10-19T17:02:48Z |
| miri-3b8286afcb898c19 | parallelhash | retired-history | parallelhash-buffering:351 [routine] | passed | 2026-10-19T13:33:28Z |
| miri-3c8766c2e4e6f300 | parallelhash | retired-history | parallelhashxof-official:3 [routine] | passed | 2026-10-19T13:38:22Z |
| miri-3ce7c73b46ece707 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=7 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:16:31Z |
| miri-3d2ac4ca59b7223a | parallelhash | retired-history | parallelhash-leaf:28 [routine] | passed | 2026-10-19T13:25:37Z |
| miri-3de1558c94f93003 | parallelhash | retired-history | parallelhash-hosted-domains:2 [routine] | passed | 2026-10-19T13:55:19Z |
| miri-3e38dbd6471bb85a | parallelhash | retired-history | scoped_scheduled128_unwind_reuse:2 [routine] | passed | 2026-10-19T13:45:07Z |
| miri-3f2c06d70320359a | parallelhash | retired-history | parallelhash-hosted-domains:1 [routine] | passed | 2026-10-19T13:49:45Z |
| miri-3f5b8a37f3f85290 | parallelhash | retired-history | scoped_parallel_xof128_matches_and_clears:0 [routine] | passed | 2026-10-19T12:51:48Z |
| miri-3fc18217ddba863e | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=32 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:36:57Z |
| miri-40639ba9451560b6 | parallelhash | retired-history | parallelhash-execution-stream:21 [routine] | passed | 2026-10-19T13:46:22Z |
| miri-4084983d88404521 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=34 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:36:07Z |
| miri-40ca04cab229b9ce | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=23 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:32:45Z |
| miri-410d3da091ec4639 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=17 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T04:53:46Z |
| miri-41a1cc32a2ebe42c | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=9 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T04:37:02Z |
| miri-42616ca2b716753b | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=11 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:31:31Z |
| miri-42642fe17230f845 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=23 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:58:09Z |
| miri-42f8fcabc166c829 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=54 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:22:37Z |
| miri-45b79f172cc62717 | parallelhash | retired-history | scoped_scheduled256_matches:31 [routine] | passed | 2026-10-19T16:59:55Z |
| miri-463469e75e4bc7a7 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=8 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:31:37Z |
| miri-46435819c76450ab | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=50 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T21:27:05Z |
| miri-47189573f41674be | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=23 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:12:58Z |
| miri-47901e910e60e8d9 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=43 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:04:50Z |
| miri-47bea3455cddedca | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=29 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T05:23:03Z |
| miri-49334cd787bfe85e | parallelhash | retired-history | parallelhash-leaf:1 [routine] | passed | 2026-10-19T13:29:08Z |
| miri-4a0cf0377d0d637b | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=26 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:16:55Z |
| miri-4a8ab3cd1e4729c3 | parallelhash | retired-history | scoped_parallel_xof128_matches_and_clears:14 [routine] | passed | 2026-10-19T12:41:03Z |
| miri-4b25ae44eb0b9841 | parallelhash | retired-history | scoped_scheduled256_matches:13 [routine] | passed | 2026-10-19T13:28:46Z |
| miri-4bbb0b791ba120c1 | parallelhash | retired-history | scoped_scheduled128_lifecycle:4 [routine] | passed | 2026-10-19T13:37:56Z |
| miri-4c1441cd5c50b6a6 | parallelhash | retired-history | parallelhash-execution-stream:3 [routine] | passed | 2026-10-19T13:29:22Z |
| miri-4cc937017ab80adb | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=12 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:38:28Z |
| miri-4df86342e8234bbc | parallelhash | retired-history | scoped_scheduled256_lifecycle:0 [routine] | passed | 2026-10-19T13:34:37Z |
| miri-4e553133f33c9e60 | parallelhash | retired-history | scoped_execution_workers_join128:1 [routine] | passed | 2026-10-19T13:35:48Z |
| miri-4e8b6ae31cf30f91 | kmac | retired-history | -p brynja-mac-kmac --features hardened-execution --test execution [remaining suite; inspect skips with show] | passed | 2026-10-19T11:48:59Z |
| miri-50afba7490217a53 | parallelhash | retired-history | parallelhash-leaf:0 [routine] | passed | 2026-10-19T13:25:06Z |
| miri-51237ef2a4561e3f | parallelhash | retired-history | parallelhash-hosted-slots:0 [routine] | passed | 2026-10-19T17:27:39Z |
| miri-51922bcbd78f0f06 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=10 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T19:39:30Z |
| miri-51d12b6c2aee78b9 | parallelhash | retired-history | parallelhash-official:1 [routine] | passed | 2026-10-19T13:36:02Z |
| miri-5378b5e1b40f1ef2 | parallelhash | retired-history | scoped_scheduled256_lifecycle:9 [routine] | passed | 2026-10-19T13:39:25Z |
| miri-53b47621a63eb343 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=33 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:53:27Z |
| miri-53df2001c18f54f3 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=38 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:45:47Z |
| miri-545afc3decbf16e4 | parallelhash | retired-history | parallelhash-buffering:171 [routine] | passed | 2026-10-19T13:28:18Z |
| miri-550e59e7b8a1c226 | parallelhash | retired-history | scoped_parallel256_matches_and_clears:0 [routine] | passed | 2026-10-19T12:42:15Z |
| miri-55f40ceac39fe3b9 | parallelhash | retired-history | parallelhash-execution-stream:9 [routine] | passed | 2026-10-19T13:45:30Z |
| miri-564d624b53399958 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=49 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T06:33:54Z |
| miri-57676a72a7b5be3f | parallelhash | retired-history | scoped_execution_workers_join128:2 [routine] | passed | 2026-10-19T17:26:15Z |
| miri-586be7ce08bb206d | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=24 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:17:49Z |
| miri-58df236cd96c206c | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=26 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:42:58Z |
| miri-5a033eb6294f3ea1 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=0 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:30:00Z |
| miri-5cf62c8f5fa15976 | parallelhash | retired-history | parallelhash-official:3 [routine] | passed | 2026-10-19T13:24:13Z |
| miri-5cfff56c15fff577 | parallelhash | retired-history | parallelhash-hosted-slots:1 [routine] | passed | 2026-10-19T13:53:14Z |
| miri-5d47199019b2a56d | parallelhash | retired-history | parallelhashxof-official:0 [routine] | passed | 2026-10-19T13:41:29Z |
| miri-5e3c6488ac3b7936 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=11 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:06:05Z |
| miri-5eb77244a36f6300 | parallelhash | retired-history | parallelhash-execution-stream:39 [routine] | passed | 2026-10-19T13:33:41Z |
| miri-5f78f4bcbd88c45b | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=8 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T19:39:57Z |
| miri-6019787fe07ddc6b | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=3 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T19:52:05Z |
| miri-60ae2bb616dacf2f | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=2 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:29:11Z |
| miri-618b3c182dffb9d0 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=39 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:52:11Z |
| miri-61c83b7dc866930f | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=27 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:22:47Z |
| miri-643f971444dc274b | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=31 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:32:36Z |
| miri-649a315f53e1f6f9 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=0 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T21:56:20Z |
| miri-6577d80285f99bfd | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=4 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:36:36Z |
| miri-67234b99c789110d | parallelhash | retired-history | scoped_parallel_xof128_matches_and_clears:5 [routine] | passed | 2026-10-19T13:02:09Z |
| miri-67b7a3f757479f06 | parallelhash | retired-history | -p brynja-hash-parallel --features hardened-execution --lib hardened_in_place::tests::scoped_parallel128_matches_and_clears -- --exact BRYNJA_MIRI_CASE=0 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T05:59:31Z |
| miri-67f7176e0d985e04 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=40 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:58:45Z |
| miri-697f669a4f13c304 | parallelhash | retired-history | scoped_scheduled128_lifecycle:7 [routine] | passed | 2026-10-19T13:34:08Z |
| miri-6afc81d384e430c5 | parallelhash | retired-history | scoped_scheduled256_unwind_reuse:0 [routine] | passed | 2026-10-19T17:16:55Z |
| miri-6b673b225c132b08 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=22 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:04:30Z |
| miri-6c4ef37ada26d185 | parallelhash | retired-history | -p brynja-hash-parallel-std --features runtime-execution --lib execution [remaining suite; inspect skips with show] | passed | 2026-10-19T16:25:22Z |
| miri-6c63cbe052578d19 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=44 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:11:09Z |
| miri-6cbd711113563c62 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=42 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:58:04Z |
| miri-6dde9b47bbef315d | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=30 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:26:26Z |
| miri-6dfa0d8f05343c6f | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=36 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:41:38Z |
| miri-6e2f7b14ca41db1d | parallelhash | retired-history | parallelhash-execution-stream:0 [routine] | passed | 2026-10-19T17:18:39Z |
| miri-6f4d7c6cc1fbe6e2 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=36 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:46:32Z |
| miri-6f969bb4135759e0 | parallelhash | retired-history | parallelhash-execution-stream:42 [routine] | passed | 2026-10-19T13:51:48Z |
| miri-7014de7e6cb5e2bb | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=47 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:17:25Z |
| miri-706a4ed55a854018 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=6 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T19:32:57Z |
| miri-70a7d8b14d69718f | parallelhash | retired-history | scoped_parallel_xof128_matches_and_clears:9 [routine] | passed | 2026-10-19T12:58:18Z |
| miri-71ccff297e095204 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=20 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:57:28Z |
| miri-72da84fe7c454b54 | parallelhash | retired-history | parallelhash-buffering:228 [routine] | passed | 2026-10-19T13:33:08Z |
| miri-72e2224aff43b217 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=18 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T19:55:16Z |
| miri-735fc9ebd25d22f4 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=51 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:43:55Z |
| miri-73eff8ba65ca7c07 | parallelhash | retired-history | scoped_scheduled256_lifecycle:10 [routine] | passed | 2026-10-19T13:23:20Z |
| miri-74f649adf5eda802 | parallelhash | retired-history | scoped_scheduled128_lifecycle:5 [routine] | passed | 2026-10-19T13:20:52Z |
| miri-760879c9020762c3 | parallelhash | retired-history | scoped_parallel_xof256_matches_and_clears:0 [routine] | passed | 2026-10-19T13:02:56Z |
| miri-7703a92d1b1d840b | parallelhash | retired-history | parallelhash-buffering:564 [routine] | passed | 2026-10-19T13:37:07Z |
| miri-79c5387ea2e84882 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=14 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:48:52Z |
| miri-7a31f87b31abaf14 | parallelhash | retired-history | scoped_parallel_xof256_matches_and_clears:36 [routine] | passed | 2026-10-19T13:06:20Z |
| miri-7ab662eb12c56883 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=14 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T19:46:05Z |
| miri-7b20e9f4e168b03a | parallelhash | retired-history | parallelhash-leaf:10 [routine] | passed | 2026-10-19T13:07:32Z |
| miri-7c128e7d8d9a7343 | parallelhash | retired-history | -p brynja-hash-parallel --features hardened-execution --lib execution -- --skip hardened_in_place::tests::scoped_parallel128_matches_and_clears --skip hardened_in_place::tests::scoped_parallel256_matches_and_clears --skip hardened_in_place::xof::tests::scoped_parallel_xof128_matches_and_clears --skip hardened_in_place::xof::tests::scoped_parallel_xof256_matches_and_clears --skip hardened_in_place::scheduled::tests::scoped_scheduled128_matches --skip hardened_in_place::scheduled::tests::scoped_scheduled256_matches --skip backend::tests::scoped_leaf_matches_shake_for_every_tail_and_rate_boundary --skip core_state::assurance_contract::borrowed_buffering_and_tails_match_direct_leaves --skip hardened_in_place::scheduled::tests::scoped_scheduled128_lifecycle --skip hardened_in_place::scheduled::tests::scoped_scheduled256_lifecycle --skip all_six_official_fixed_examples_match --skip all_six_official_xof_examples_match --skip scoped_scheduled128_unwind_reuse --skip scoped_scheduled256_unwind_reuse --skip execution::stream::tests::borrowed_updates_and_tail_preserve_planned_digest --skip execution::in_place::tests::scoped_execution_fixed_xof_domains_and_zero_output --skip execution::in_place::worker::tests::scoped_execution_workers_join128 --skip execution::in_place::worker::tests::scoped_execution_workers_join256 --skip execution::worker::tests::spawn_errors_panics_and_cancellation_join_and_close_root --skip execution::worker::tests::every_completed_or_panicking_worker_clears_its_output_slot --skip execution::worker::tests::reversed_worker_completion_is_merged_in_submission_order --skip streamed_scheduled_and_one_shot_are_identical --skip empty_input_has_zero_leaves_and_b_one_is_valid --skip reordered_leaf_permanently_fails_closed --skip equal_shape_cross_plan_result_permanently_fails_closed --skip arbitrary_bit_input_and_output_partition_are_stable --skip hardened_output_and_workspace_clear_on_drop | passed | 2026-10-29T05:04:17Z |
| miri-8017430d8217f444 | parallelhash | retired-history | parallelhash-execution-stream:6 [routine] | passed | 2026-10-19T13:50:55Z |
| miri-814a60dbd3185662 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=19 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:03:10Z |
| miri-833f08fd2a9a3b85 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=32 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:01:38Z |
| miri-8477bbfb2321d6c4 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=24 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:14:03Z |
| miri-85f03c89b1534368 | parallelhash | retired-history | scoped_parallel_xof128_matches_and_clears:18 [routine] | passed | 2026-10-19T12:37:39Z |
| miri-86703dc7be15e94c | parallelhash | retired-history | -p brynja-hash-parallel --tests [remaining suite; inspect skips with show] | passed | 2026-10-19T12:31:27Z |
| miri-87851023f85e7837 | parallelhash | retired-history | parallelhash-hosted-slots:2 [routine] | passed | 2026-10-19T13:57:07Z |
| miri-88336782363e6db4 | parallelhash | retired-history | scoped_parallel128_matches_and_clears:18 [routine] | passed | 2026-10-19T12:26:00Z |
| miri-886bd47c7d0d13e5 | parallelhash | retired-history | scoped_parallel256_matches_and_clears:18 [routine] | passed | 2026-10-19T12:31:13Z |
| miri-899cbbb75f7ef33b | parallelhash | retired-history | parallelhashxof-official:1 [routine] | passed | 2026-10-19T13:24:58Z |
| miri-89def4415dbf1d4c | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=15 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:30:33Z |
| miri-8a7ac21f9980077b | parallelhash | retired-history | scoped_scheduled256_unwind_reuse:2 [routine] | passed | 2026-10-19T13:48:18Z |
| miri-8a7b8e5916f48794 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=34 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:01:09Z |
| miri-8aac00cf179f490e | parallelhash | retired-history | scoped_parallel256_matches_and_clears:15 [routine] | passed | 2026-10-19T16:34:56Z |
| miri-8c2e3fb7b0970b39 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=6 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:24:07Z |
| miri-8c53159c823467d1 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=28 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:16:23Z |
| miri-8d32082f0a52ab92 | parallelhash | retired-history | scoped_scheduled128_matches:13 [routine] | passed | 2026-10-19T13:18:49Z |
| miri-8d89c65047bb0eaa | parallelhash | retired-history | parallelhash-hosted-order:1 [routine] | passed | 2026-10-19T17:29:04Z |
| miri-8f679f320af86919 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=48 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:58:48Z |
| miri-90857583bea55194 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=21 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:24:05Z |
| miri-91c8be53039b8920 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=19 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:22:54Z |
| miri-91cb8d5edb9ca21c | parallelhash | retired-history | -p brynja-hash-parallel --features hardened-execution --lib hardened_in_place::tests::scoped_parallel128_matches_and_clears -- --exact BRYNJA_MIRI_CASE=6 BRYNJA_MIRI_PROFILE=extended | cancelled | 2026-10-29T07:16:31Z |
| miri-925b6bb8c8359cae | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=5 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:50:26Z |
| miri-92e763359f1eb12f | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=13 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T04:44:00Z |
| miri-9335256e27aacc6f | parallelhash | retired-history | scoped_execution_workers_join256:1 [routine] | passed | 2026-10-19T13:36:08Z |
| miri-9368c915f9271a77 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=30 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:15:42Z |
| miri-951198c5bf6af838 | parallelhash | retired-history | scoped_scheduled256_lifecycle:2 [routine] | passed | 2026-10-19T13:21:50Z |
| miri-964d848a9b67f804 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=28 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:27:22Z |
| miri-96c811e9614e8cd0 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=6 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:02:39Z |
| miri-97a0a911a47ea8a3 | parallelhash | retired-history | scoped_scheduled256_lifecycle:3 [routine] | passed | 2026-10-19T17:09:17Z |
| miri-97f1c706dc7db29f | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=5 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T04:30:03Z |
| miri-99313988da02fc51 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=24 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:43:23Z |
| miri-997686acb5164f2b | parallelhash | retired-history | parallelhash-buffering:15 [routine] | passed | 2026-10-19T13:30:02Z |
| miri-99bcd68606fcc111 | parallelhash | retired-history | -p brynja-hash-parallel --features hardened-execution --lib execution [remaining suite; inspect skips with show] | passed | 2026-10-19T12:45:45Z |
| miri-9a7802e0a08785b9 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=12 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:49:44Z |
| miri-9b9c53b41b03a0d3 | parallelhash | retired-history | scoped_scheduled128_lifecycle:1 [routine] | passed | 2026-10-19T13:20:32Z |
| miri-9c04914ceb6b745f | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=38 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:10:13Z |
| miri-9c583cd00bcd09fa | parallelhash | retired-history | parallelhash-official:0 [routine] | passed | 2026-10-19T17:10:23Z |
| miri-9d6fa30dc1a63d78 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=28 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:52:29Z |
| miri-9f2069434b9b9a30 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=4 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T19:33:24Z |
| miri-9f36c79662ac8de5 | parallelhash | retired-history | scoped_parallel_xof256_matches_and_clears:5 [routine] | passed | 2026-10-19T13:10:15Z |
| miri-a0e67e8522f5e6ce | parallelhash | retired-history | scoped_parallel_xof256_matches_and_clears:18 [routine] | passed | 2026-10-19T12:44:53Z |
| miri-a18498c00ad7566e | parallelhash | retired-history | scoped_scheduled256_lifecycle:5 [routine] | passed | 2026-10-19T13:39:05Z |
| miri-a3c948500bb4ffb0 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=52 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T21:49:46Z |
| miri-a3e0f0621de1bddc | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=32 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:32:25Z |
| miri-a53031dee6cefc7d | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=35 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T21:02:20Z |
| miri-a63656397cfa32fc | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=47 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:02:30Z |
| miri-a68135c41ac4c796 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=53 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T04:16:00Z |
| miri-a6987502a40e8b00 | parallelhash | retired-history | scoped_scheduled128_matches:9 [routine] | passed | 2026-10-19T13:14:32Z |
| miri-a69cd7680d6d20cd | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=38 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:41:14Z |
| miri-a6e39db5dfb6f59d | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=22 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:56:47Z |
| miri-a75cda1cb61c5453 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=14 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:15:42Z |
| miri-a7a130a5f36d0d65 | parallelhash | retired-history | scoped_scheduled256_lifecycle:6 [routine] | passed | 2026-10-19T13:22:27Z |
| miri-a834ec480d6c2c55 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=32 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:25:53Z |
| miri-a8f8e85c7af4cb38 | parallelhash | retired-history | scoped_parallel_xof256_matches_and_clears:14 [routine] | passed | 2026-10-19T12:48:43Z |
| miri-a97507ebb9f374e9 | parallelhash | retired-history | parallelhash-hosted-domains:4 [routine] | passed | 2026-10-19T17:26:03Z |
| miri-a990ee8df0763a5f | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=31 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T04:09:27Z |
| miri-aa5ded118899adad | parallelhash | retired-history | scoped_scheduled128_matches:22 [routine] | passed | 2026-10-19T12:57:15Z |
| miri-ab8458bbe5c4e8c1 | parallelhash | retired-history | parallelhash-execution-stream:30 [routine] | passed | 2026-10-19T13:53:47Z |
| miri-acb70228df45f4be | parallelhash | retired-history | parallelhash-leaf:55 [routine] | passed | 2026-10-19T17:01:05Z |
| miri-acfef219dec6577d | parallelhash | retired-history | parallelhash-buffering:621 [routine] | passed | 2026-10-19T13:20:03Z |
| miri-aea332912cc9e4c3 | parallelhash | retired-history | scoped_scheduled128_lifecycle:0 [routine] | passed | 2026-10-19T13:37:36Z |
| miri-aefe4d77f8422fb9 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=50 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:58:01Z |
| miri-af8a8f5a38b74c53 | parallelhash | retired-history | parallelhash-official:5 [routine] | passed | 2026-10-19T13:37:29Z |
| miri-af9846a758ce7ff8 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=10 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:30:56Z |
| miri-b0040ff9d066d7ba | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=30 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:22:51Z |
| miri-b021c729ce56e859 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=9 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:57:28Z |
| miri-b04e5e055d1a5fe5 | parallelhash | retired-history | scoped_scheduled256_matches:4 [routine] | passed | 2026-10-19T13:24:45Z |
| miri-b0ecc49c39f0a5bc | parallelhash | retired-history | scoped_execution_workers_join256:2 [routine] | passed | 2026-10-19T17:26:26Z |
| miri-b1850ee711e3a387 | parallelhash | retired-history | scoped_scheduled128_matches:0 [routine] | passed | 2026-10-19T13:10:35Z |
| miri-b1a6fa5b193b18a6 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=10 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:09:09Z |
| miri-b22a637cf24a4033 | parallelhash | retired-history | scoped_parallel128_matches_and_clears:27 [routine] | passed | 2026-10-19T16:27:34Z |
| miri-b3442a135ab605f1 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=55 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:25:13Z |
| miri-b3ca751f784642c5 | parallelhash | retired-history | scoped_scheduled128_lifecycle:10 [routine] | passed | 2026-10-19T17:08:57Z |
| miri-b3cd94dca23db424 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=6 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:35:44Z |
| miri-b471a3001fe83ef6 | parallelhash | retired-history | scoped_parallel128_matches_and_clears:45 [routine] | passed | 2026-10-19T12:50:07Z |
| miri-b6a45560bff2916d | parallelhash | retired-history | scoped_scheduled128_lifecycle:9 [routine] | passed | 2026-10-19T13:21:12Z |
| miri-b6d9262da897913f | parallelhash | retired-history | scoped_scheduled256_matches:9 [routine] | passed | 2026-10-19T13:23:46Z |
| miri-b816d1de895e3861 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=46 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:33:28Z |
| miri-b82246098841d67f | parallelhash | retired-history | scoped_parallel_xof128_matches_and_clears:27 [routine] | passed | 2026-10-19T16:37:55Z |
| miri-b869d90e8a94bbd9 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=27 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:42:37Z |
| miri-b8cf08351e2237ef | parallelhash | retired-history | scoped_parallel256_matches_and_clears:45 [routine] | passed | 2026-10-19T12:54:54Z |
| miri-ba4678c6ebe80d05 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=39 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T21:12:11Z |
| miri-ba78a872e2dd711c | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=3 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:09:31Z |
| miri-bba7f9b4d8c265c3 | parallelhash | retired-history | parallelhashxof-official:2 [routine] | passed | 2026-10-19T17:12:34Z |
| miri-bc0e178c8a472579 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=53 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T07:01:39Z |
| miri-bd1111fa423a9737 | parallelhash | retired-history | -p brynja-hash-parallel --features hardened-execution --test execution [remaining suite; inspect skips with show] | passed | 2026-10-19T12:23:48Z |
| miri-bd9a34fa0a76a2aa | parallelhash | retired-history | -p brynja-hash-parallel --features hardened-execution --test execution_stream [remaining suite; inspect skips with show] | passed | 2026-10-19T16:25:13Z |
| miri-befda4a27c26712b | parallelhash | retired-history | scoped_parallel_xof256_matches_and_clears:9 [routine] | passed | 2026-10-19T13:05:59Z |
| miri-bfaa333ba3af191f | parallelhash | retired-history | parallelhash-leaf:64 [routine] | passed | 2026-10-19T13:26:34Z |
| miri-c03404f315a9506c | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=20 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:08:19Z |
| miri-c03ca2b3066bad06 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=31 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:52:30Z |
| miri-c15cc4e6ac7e351b | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=42 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:47:02Z |
| miri-c1dd82aed2ede2b0 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=25 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:33:53Z |
| miri-c20c3e204dfde99f | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=16 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:25:09Z |
| miri-c23007adde7be6f5 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=40 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:22:29Z |
| miri-c26bca015f9aa583 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=3 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:17:27Z |
| miri-c2e2040b0e18c860 | parallelhash | retired-history | scoped_scheduled256_unwind_reuse:1 [routine] | passed | 2026-10-19T13:44:19Z |
| miri-c3b528d2887206b9 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=38 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:34:42Z |
| miri-c82ecf5107be6686 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=5 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T07:15:40Z |
| miri-cd168e8757dd77fb | parallelhash | retired-history | scoped_parallel256_matches_and_clears:6 [routine] | passed | 2026-10-19T12:34:14Z |
| miri-ce868dbbefcf4b35 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=0 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T19:26:50Z |
| miri-ce8d3bb57e6dd0ac | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=21 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T05:03:33Z |
| miri-cecd43112d13dd30 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=1 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T04:23:03Z |
| miri-cee1cda7eae89415 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=51 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:01:22Z |
| miri-cf57584409a52059 | parallelhash | retired-history | scoped_scheduled256_lifecycle:7 [routine] | passed | 2026-10-19T17:09:37Z |
| miri-cf965a88b30ab226 | parallelhash | retired-history | scoped_parallel128_matches_and_clears:36 [routine] | passed | 2026-10-19T12:37:32Z |
| miri-cfb10a6d253d1654 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=34 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:25:12Z |
| miri-d03b79cc7760fb4f | parallelhash | retired-history | scoped_scheduled256_lifecycle:8 [routine] | passed | 2026-10-19T13:35:17Z |
| miri-d046a872cc610512 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=46 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T21:04:48Z |
| miri-d25c2c873c2536b5 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=40 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:53:24Z |
| miri-d2bbe26698c6ab4e | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=36 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:10:45Z |
| miri-d2e4d4913ee61f0e | parallelhash | retired-history | scoped_scheduled256_lifecycle:1 [routine] | passed | 2026-10-19T13:38:45Z |
| miri-d4254bd9922ad4fa | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=2 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T19:26:23Z |
| miri-d4abfb9ae278c1bf | parallelhash | retired-history | parallelhash-hosted-faults:5 [routine] | passed | 2026-10-19T13:36:47Z |
| miri-d4d3c8376a36eb65 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=19 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:40:19Z |
| miri-d5115090d9051e36 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=12 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T19:46:30Z |
| miri-d53643d6d1ee6269 | parallelhash | retired-history | parallelhash-official:4 [routine] | passed | 2026-10-19T17:11:16Z |
| miri-d6d1411e5f602e5b | parallelhash | retired-history | -p brynja-hash-parallel --tests -- --skip hardened_in_place::tests::scoped_parallel128_matches_and_clears --skip hardened_in_place::tests::scoped_parallel256_matches_and_clears --skip hardened_in_place::xof::tests::scoped_parallel_xof128_matches_and_clears --skip hardened_in_place::xof::tests::scoped_parallel_xof256_matches_and_clears --skip hardened_in_place::scheduled::tests::scoped_scheduled128_matches --skip hardened_in_place::scheduled::tests::scoped_scheduled256_matches --skip backend::tests::scoped_leaf_matches_shake_for_every_tail_and_rate_boundary --skip core_state::assurance_contract::borrowed_buffering_and_tails_match_direct_leaves --skip hardened_in_place::scheduled::tests::scoped_scheduled128_lifecycle --skip hardened_in_place::scheduled::tests::scoped_scheduled256_lifecycle --skip all_six_official_fixed_examples_match --skip all_six_official_xof_examples_match --skip scoped_scheduled128_unwind_reuse --skip scoped_scheduled256_unwind_reuse --skip execution::stream::tests::borrowed_updates_and_tail_preserve_planned_digest --skip execution::in_place::tests::scoped_execution_fixed_xof_domains_and_zero_output --skip execution::in_place::worker::tests::scoped_execution_workers_join128 --skip execution::in_place::worker::tests::scoped_execution_workers_join256 --skip execution::worker::tests::spawn_errors_panics_and_cancellation_join_and_close_root --skip execution::worker::tests::every_completed_or_panicking_worker_clears_its_output_slot --skip execution::worker::tests::reversed_worker_completion_is_merged_in_submission_order --skip streamed_scheduled_and_one_shot_are_identical --skip empty_input_has_zero_leaves_and_b_one_is_valid --skip reordered_leaf_permanently_fails_closed --skip equal_shape_cross_plan_result_permanently_fails_closed --skip arbitrary_bit_input_and_output_partition_are_stable --skip hardened_output_and_workspace_clear_on_drop | passed | 2026-10-29T04:07:04Z |
| miri-d72e63835115af65 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=37 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T05:42:32Z |
| miri-d748639fcc89d7e2 | parallelhash | retired-history | parallelhash-hosted-domains:5 [routine] | passed | 2026-10-19T13:51:30Z |
| miri-d7ce7afc01fbc683 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=43 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:49:54Z |
| miri-d8600c2ac250099b | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=28 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:23:14Z |
| miri-d868bc8eeb1ac1fa | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=16 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:47:58Z |
| miri-d9198191f4df35d2 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=3 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:32:17Z |
| miri-d9298cc75f8b7386 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=41 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:15:49Z |
| miri-d9780af5668c8105 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=42 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T23:21:51Z |
| miri-d9a722f3ba7b9d6a | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=17 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:14:18Z |
| miri-da3709cf9eb43dd4 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=52 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:23:27Z |
| miri-da57e542650ed3ae | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=20 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:04:54Z |
| miri-dae5dfb1be86040e | parallelhash | retired-history | scoped_scheduled128_matches:27 [routine] | passed | 2026-10-19T16:51:24Z |
| miri-dc503f60f6947ae4 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=15 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:53:23Z |
| miri-dc7743040fbe6a7d | parallelhash | retired-history | parallelhash-buffering:393 [routine] | passed | 2026-10-19T13:15:34Z |
| miri-dea66d3802454c2c | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=20 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:34:16Z |
| miri-deb9b6be2b29a5eb | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=39 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:37:19Z |
| miri-dfcd8e0db5c0dbb6 | parallelhash | retired-history | scoped_scheduled128_lifecycle:8 [routine] | passed | 2026-10-19T13:38:16Z |
| miri-e0318701a458445e | parallelhash | retired-history | parallelhashxof-official:4 [routine] | passed | 2026-10-19T13:42:22Z |
| miri-e0be1296a0f63042 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=8 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:43:10Z |
| miri-e17d45859fa7fc63 | parallelhash | retired-history | scoped_scheduled128_lifecycle:6 [routine] | passed | 2026-10-19T17:08:04Z |
| miri-e2441f8bf818fb95 | parallelhash | retired-history | -p brynja-hash-parallel --features hardened-execution --test execution -- --skip all_identities_bits_blocks_and_outputs_match_portable --skip hardened_in_place::tests::scoped_parallel128_matches_and_clears --skip hardened_in_place::tests::scoped_parallel256_matches_and_clears --skip hardened_in_place::xof::tests::scoped_parallel_xof128_matches_and_clears --skip hardened_in_place::xof::tests::scoped_parallel_xof256_matches_and_clears --skip hardened_in_place::scheduled::tests::scoped_scheduled128_matches --skip hardened_in_place::scheduled::tests::scoped_scheduled256_matches --skip backend::tests::scoped_leaf_matches_shake_for_every_tail_and_rate_boundary --skip core_state::assurance_contract::borrowed_buffering_and_tails_match_direct_leaves --skip hardened_in_place::scheduled::tests::scoped_scheduled128_lifecycle --skip hardened_in_place::scheduled::tests::scoped_scheduled256_lifecycle --skip all_six_official_fixed_examples_match --skip all_six_official_xof_examples_match --skip scoped_scheduled128_unwind_reuse --skip scoped_scheduled256_unwind_reuse --skip execution::stream::tests::borrowed_updates_and_tail_preserve_planned_digest --skip execution::in_place::tests::scoped_execution_fixed_xof_domains_and_zero_output --skip execution::in_place::worker::tests::scoped_execution_workers_join128 --skip execution::in_place::worker::tests::scoped_execution_workers_join256 --skip execution::worker::tests::spawn_errors_panics_and_cancellation_join_and_close_root --skip execution::worker::tests::every_completed_or_panicking_worker_clears_its_output_slot --skip execution::worker::tests::reversed_worker_completion_is_merged_in_submission_order --skip streamed_scheduled_and_one_shot_are_identical --skip empty_input_has_zero_leaves_and_b_one_is_valid --skip reordered_leaf_permanently_fails_closed --skip equal_shape_cross_plan_result_permanently_fails_closed --skip arbitrary_bit_input_and_output_partition_are_stable --skip hardened_output_and_workspace_clear_on_drop | passed | 2026-10-29T04:11:00Z |
| miri-e3a8ae8b5c2b4718 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=14 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:37:48Z |
| miri-e3b85459a203fec6 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=34 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:32:01Z |
| miri-e4965a73453c1c7d | parallelhash | retired-history | parallelhash-execution-stream:45 [routine] | passed | 2026-10-19T13:48:24Z |
| miri-e49911a4807ef6a4 | parallelhash | retired-history | parallelhash-hosted-faults:2 [routine] | passed | 2026-10-19T17:26:54Z |
| miri-e4d92471f83a00f5 | parallelhash | retired-history | parallelhash-hosted-faults:4 [routine] | passed | 2026-10-19T13:56:30Z |
| miri-e5a19bc8b1198050 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=25 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T05:13:15Z |
| miri-e61191230180c80f | parallelhash | retired-history | scoped_parallel_xof256_matches_and_clears:27 [routine] | passed | 2026-10-19T16:44:43Z |
| miri-e635bcc297dfd22e | parallelhash | retired-history | scoped_scheduled128_unwind_reuse:0 [routine] | passed | 2026-10-19T17:14:36Z |
| miri-e6485403fe344da0 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=43 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T21:24:50Z |
| miri-e67cd8006ac4a961 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=1 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:43:26Z |
| miri-e743c91673142172 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=26 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:13:39Z |
| miri-e83e872267c19f34 | parallelhash | retired-history | parallelhash-execution-stream:15 [routine] | passed | 2026-10-19T13:30:32Z |
| miri-e85c6b00698b9172 | kmac | retired-history | -p brynja-mac-kmac --tests [remaining suite; inspect skips with show] | passed | 2026-10-19T15:28:53Z |
| miri-e97a9c3056361bde | parallelhash | retired-history | parallelhash-hosted-order:2 [routine] | passed | 2026-10-19T13:54:40Z |
| miri-ea0edfd9ca0726d7 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=13 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:04:31Z |
| miri-eb0b4aeff5bc00ec | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=39 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T04:28:59Z |
| miri-eb93d4add08ea452 | parallelhash | retired-history | scoped_parallel128_matches_and_clears:0 [routine] | passed | 2026-10-19T12:35:47Z |
| miri-eba15ec1d87de9bd | parallelhash | retired-history | parallelhash-buffering:450 [routine] | passed | 2026-10-19T17:05:40Z |
| miri-ebbeedca2ce40ade | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=55 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:10:24Z |
| miri-ebf229ff79723ead | parallelhash | retired-history | parallelhash-leaf:19 [routine] | passed | 2026-10-19T17:00:26Z |
| miri-ed9c710be9957459 | kmac | retired-history | -p brynja-mac-kmac --features hardened-execution --lib execution [remaining suite; inspect skips with show] | passed | 2026-10-19T11:40:18Z |
| miri-edbe0d2c0cf10aa3 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=42 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T20:52:59Z |
| miri-ef125a7bb740b048 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=33 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T05:32:49Z |
| miri-eff70ec3a9f4b172 | parallelhash | retired-history | scoped_execution_workers_join128:3 [routine] | passed | 2026-10-19T13:51:50Z |
| miri-eff777861ffa17b0 | parallelhash | retired-history | scoped_scheduled128_matches:18 [routine] | passed | 2026-10-19T12:52:58Z |
| miri-effc2acd34e08e47 | parallelhash | retired-history | parallelhash-hosted-faults:3 [routine] | passed | 2026-10-19T13:52:46Z |
| miri-f1141534f4d80e6e | parallelhash | retired-history | scoped_scheduled256_matches:27 [routine] | passed | 2026-10-19T16:57:04Z |
| miri-f11e96b101add988 | parallelhash | retired-history | scoped_parallel128_matches_and_clears:15 [routine] | passed | 2026-10-19T16:29:45Z |
| miri-f1888fbd1a4235d3 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=27 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:07:59Z |
| miri-f1cf85fdfd50b1cb | parallelhash | retired-history | scoped_execution_workers_join256:0 [routine] | passed | 2026-10-19T13:55:41Z |
| miri-f26a57b2105e4704 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=22 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:07:25Z |
| miri-f2f3fb52de58fcce | parallelhash | retired-history | scoped_scheduled128_matches:4 [routine] | passed | 2026-10-19T13:14:51Z |
| miri-f420c9be2a27b179 | parallelhash | retired-history | parallelhash-buffering:294 [routine] | passed | 2026-10-19T17:03:57Z |
| miri-f5db7984bf709b45 | parallelhash | retired-history | -p brynja-hash-parallel --features hardened-execution --lib hardened_in_place::tests::scoped_parallel128_matches_and_clears -- --exact BRYNJA_MIRI_CASE=2 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T06:01:40Z |
| miri-f65b6e060713e31d | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=54 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T21:49:32Z |
| miri-f7ab002d50295560 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=44 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:59:50Z |
| miri-f7e1b4ad4cdaaf75 | parallelhash | retired-history | scoped_parallel_xof128_matches_and_clears:23 [routine] | passed | 2026-10-19T16:41:20Z |
| miri-f812f0908903c82c | parallelhash | retired-history | parallelhash-hosted-domains:3 [routine] | passed | 2026-10-19T13:35:28Z |
| miri-f93bac56d769869c | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=40 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:47:39Z |
| miri-f95b2bf102e5b4cd | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple128_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=48 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T21:27:32Z |
| miri-f9c6046b21ffc92b | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=16 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:58:58Z |
| miri-fa92bde73b412a06 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=47 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T04:53:59Z |
| miri-fad53fb64b57af12 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=19 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T01:48:20Z |
| miri-fb859566506fd9a7 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=46 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:10:19Z |
| miri-fc275a511a0fcf56 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=35 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T04:19:13Z |
| miri-fc3e38935a5a3b4b | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=30 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T22:52:04Z |
| miri-fc5052d4372d87da | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=18 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:58:05Z |
| miri-fc5fb55ac4447f6c | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=35 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T02:27:31Z |
| miri-fd6100bab611c6e1 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof128_differential -- --exact BRYNJA_MIRI_CASE=10 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T00:42:19Z |
| miri-ff02da445275c4f4 | parallelhash | retired-history | scoped_scheduled256_unwind_reuse:3 [routine] | passed | 2026-10-19T13:27:39Z |
| miri-ff6a0b0cf659fc35 | parallelhash | retired-history | scoped_parallel256_matches_and_clears:9 [routine] | passed | 2026-10-19T12:52:43Z |
| miri-ff6d2f9d4b1b9a0d | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::tests::scoped_tuple256_matches_portable_bits_and_streaming -- --exact BRYNJA_MIRI_CASE=2 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-28T21:56:04Z |
| miri-ffb055ed73013b85 | tuplehash | retired-history | -p brynja-hash-tuple --lib hardened_in_place::xof::tests::scoped_tuplexof256_differential -- --exact BRYNJA_MIRI_CASE=26 BRYNJA_MIRI_PROFILE=extended | passed | 2026-10-29T03:06:14Z |
| repository-33ef4e09d39132cd | repository | retired-history | python3 scripts/release/test-test-dashboard.py | passed | 2026-10-29T07:32:41+00:00 |
| workflow-0354f3616639719d | repository | workflow | .github/workflows/dedicated-sha512.yml / emulated-sha512 | No mapped observation | — |
| workflow-0f2f10d8dd1f463a | repository | workflow | .github/workflows/qualification.yml / rust-version | No mapped observation | — |
| workflow-3026d63fbf9a110c | repository | workflow | .github/workflows/standards-lifecycle.yml / observe | No mapped observation | — |
| workflow-7c39d7dcec8b597f | repository | workflow | .github/workflows/qualification.yml / ordinary-md5 | No mapped observation | — |
| workflow-82190f0d5a2614d3 | repository | workflow | .github/workflows/qualification.yml / host | No mapped observation | — |
| workflow-8d43bc552bb1bc1a | repository | workflow | .github/workflows/qualification.yml / hardened-sha1 | No mapped observation | — |
| workflow-d253e985a6f47bab | repository | workflow | .github/workflows/qualification.yml / macos-resident | No mapped observation | — |
| workflow-d3affe6199f95eee | repository | workflow | .github/workflows/release.yml / metadata | No mapped observation | — |
| workflow-dcd50d1952320a78 | repository | workflow | .github/workflows/ci.yml / checks | No mapped observation | — |
| workflow-f18b9c558e5fb043 | repository | workflow | .github/workflows/ci.yml / audit | No mapped observation | — |
| workflow-fea03fed70a96fa1 | repository | workflow | .github/workflows/qualification.yml / target | No mapped observation | — |
