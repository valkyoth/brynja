# Hardened multibuffer native observations

Runtime collection and project review: 2026-09-17.
Capture commit: `6978bc2a2339095533d60430a1a9e9158b3ba661`.
All four records bind that commit and tree, the Rust 1.98.1 native host compiler,
the required AVX/AVX2 or NEON bundle, all fourteen commands and their outputs.
The existing standalone validator accepted every record. Its 484 tamper cases
and orchestration regression tests also passed during import.

## Original runtime records

| Lane | Original record | SHA-256 |
| --- | --- | --- |
| AMD Ryzen 9 9950X3D | [AMD](../assurance/hardened-batch-native/amd-x86_64-v02448.json) | `649717d73aeb2c65cffd52db01c1109054223ade98f24a273a34506b831ca2db` |
| Intel Xeon 6975P-C, C8i | [Intel](../assurance/hardened-batch-native/intel-x86_64-v02448.json) | `e7d2720d05146b031e6d573ce6784e071559bd53826348d3b600e74b41bb2048` |
| Arm Neoverse-V2, C8g | [AWS Arm](../assurance/hardened-batch-native/aws-aarch64-v02448.json) | `500cdbc494b4779b5d09a674485231555a485664347d9ddd48d5d4baf8eedf34` |
| Apple M2 Pro | [Apple](../assurance/hardened-batch-native/apple-m2-aarch64-v02448.json) | `d6245340ad2475736c8bb090b635b39b1998d9e646bb7142d4da3b037e1c73a7` |

Each lane passed six optimized feature-owning library suites with required
native execution markers; five independent-oracle drivers (narrow/wide SHA-2,
Keccak, local scheduled/streaming and threaded ParallelHash); 640 leaf benchmark
rows and 96 threaded rows with output/work checks; and extracted-package tests,
doctests, 129 ownership negatives, 16 ordinary-owner substitutions/conversions
and eleven compiled cleanup/dispatch mutants. See the
[collection contract](hardened-batch-native-collection.md) for scope and exclusions.

These JSON files remain unmodified operator captures, including their original
`owner_review: pending` field. This dated document records the subsequent
project-owned runtime review; it does not rewrite them as independently verified
or make a release approval claim.

## Measured performance, including slower outcomes

The ranges below include every measured shape that actually executed vector
calls, not just the fastest row. Leaf ratios are portable/selected elapsed time;
ParallelHash ratios are scheduled-portable/threaded-selected elapsed time.
Ratios below one mean the selected implementation was slower. Different native
lane widths qualify different subsets of shapes, so these are not like-for-like
cross-machine speed rankings. All rows, including portable fallbacks, remain in
the original records.

| Lane | Narrow SHA-2 | Wide SHA-2 | Keccak family | Threaded ParallelHash |
| --- | --- | --- | --- | --- |
| AMD | 1.133–1.946× | 0.912–0.978× | 1.267–1.585× | 0.273–1.834× |
| Intel C8i | 1.185–2.232× | 1.040–1.225× | 1.401–2.038× | 0.383–1.269× |
| AWS Arm C8g | 0.853–0.976× | 0.408–0.861× | 0.740–0.937× | 0.280–0.824× |
| Apple M2 Pro | 0.950–1.045× | 0.474–0.893× | 0.545–1.127× | 0.244–1.041× |

No universal speedup, crossover threshold or automatic preference follows from
these results. In particular, these NEON workloads frequently lose to portable
execution. No implementation was changed to improve the reported numbers.
This comparison is not against every dedicated single-stream hash instruction.

The C8i launch exposes one physical core with two SMT threads; C8g exposes two
cores. Four-worker rows oversubscribe both and do not qualify four-core scaling.
See the [hardware inventory](native-hardware-inventory.md) for future instance
selection, feature probes and the missing dedicated Intel SHA512 capability.

## Separate obligations

Fresh six-layer ASan/forced-LeakSanitizer runs passed on local AMD, AWS Intel and
AWS Arm. Each original log retains 117 passing tests:
[AMD](../assurance/hardened-batch-native/amd-x86_64-v02448-asan.txt),
[Intel](../assurance/hardened-batch-native/intel-x86_64-v02448-asan.txt), and
[Arm](../assurance/hardened-batch-native/aws-aarch64-v02448-asan.txt).
These runs used the existing pinned nightly driver, which forces leak detection
and fatal ASan/LSan exit codes. Both AWS collection jobs exited zero after the
sanitizer and unchanged-checkout checks. This is separate from the supplied
pentest's ptrace-blocked LeakSanitizer attempt, which is not counted as a pass.

The changed shared CPU surface also required fresh SHA-2, Keccak, KMAC,
TupleHash and ParallelHash captures. All fifteen records from AWS Intel,
AWS Arm and Apple passed the existing source/commit/compiler/route/result
validators at the same capture commit. The existing indexes bind the unmodified
artifacts and their SHA-256 hashes:

- [SHA-2](../security/sha2-hardened-native.json)
- [Keccak](../security/keccak-hardened-native.json)
- [KMAC](../security/kmac-execution-native.json)
- [TupleHash](../security/tuplehash-execution-native.json)
- [ParallelHash](../security/parallelhash-execution-native.json)

The required three-platform lane sets are unchanged. No new native gate or
source carry-forward exception was introduced. Capture-time documentation status
labels remain historical inputs; this dated review records subsequent collection.

Miri, Kani, emitted-code cleanup, package/release checks and GitHub approval are
separate obligations. Native functional comparisons do not prove physical
side-channel resistance, migration safety, linked-unwinder restoration or
register/compiler-copy erasure. These are project-reviewed, operator-self-attested
results, not independent cryptographic review, provider attestation, military
approval or FIPS validation. No gate or publication rule was changed.

## SHA-2 refresh after the Kani policy update

The `0.68.0` Kani update changed `assurance/policy.toml`, which is an exact input
of the shared SHA-2 native capture. On 2026-09-17, all three required lanes were
therefore recaptured at `99549a02aa466dc1fbd97a54db0d39f0a1cbbb05`; no native
source-binding exception was introduced. The original captures remain above
as historical evidence. The current SHA-2 index points to these new raw records:

| Lane | Record | SHA-256 |
| --- | --- | --- |
| Local AMD Ryzen 9 9950X3D | [Linux x86](../assurance/sha2-hardened-native/linux-x86_64-v02448-kani068.json) | `a0f9f95d648dd79f4f1c35e4252fb0533979ead077bd5060e8d447d0e5abb742` |
| AWS Arm Neoverse-V2 | [Linux Arm](../assurance/sha2-hardened-native/linux-aarch64-v02448-kani068.json) | `1d945ea7ca952a3a03e0337b2e95dee8fb8d246cea7ed985094538031d0ed783` |
| Apple M2 Pro | [Apple Arm](../assurance/sha2-hardened-native/apple-aarch64-v02448-kani068.json) | `9f532765c5470909cceaf06bfd20ed2ba12a073d5d502a2a83448418853dadcc` |

Each record passed the unchanged schema, compiler, exact-source, route, vector
and actual-kernel marker checks. The Linux x86 lane exercised SHA-NI on AMD;
the Arm lanes exercised SHA-256 and SHA-512 through hosted and static routes.
The replacement AWS host exposes four Neoverse-V2 cores and about 7.6 GiB RAM;
this SHA-2 refresh is not a new four-worker batching benchmark.

Keccak, KMAC, TupleHash and ParallelHash native source closures were unchanged
by the verifier update and their existing records still passed validation.
The original four-platform hardened-batch runtime observations are preserved;
none is relabelled as a Kani `0.68.0` proof or a completed final release sweep.
