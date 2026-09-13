# Hardened SHA-1 native observations

Historical captures: a subsequent pentest removed public hardened-stream
capacity queries. These original observations remain unchanged for traceability,
but do not qualify the changed source closure. The native index is pending a
fresh capture/review; these files must not be relabeled as current evidence.

All four captures used commit `e66376c513de4a3c0cfa77bc8056745973645084`
and Rust 1.98.1. The original JSON bytes are preserved. The repository owner
supplied the Apple M2 Pro artifact; the local AMD and owner-provided AWS Intel
and Arm hosts were collected through the same native capture script.

Maintainer-workflow artifact review checked commit ancestry, current source
hashes, compiler/host identities, feature bundles, complete transcripts and
artifact checksums. Each lane passed:

- Actual hardened kernel execution over 512 state/block cases.
- Portable and accelerated hardened APIs, including NIST bit vectors.
- 1,135 independent bit-message oracle cases with public and secret outputs.
- 22 ownership/classification negatives, ten algorithm/error mutants and ten
  compiled owner/scratch cleanup removals.
- Native-target MIR/LLVM/assembly checks for all seven owned regions.

The generic hosted route remains portable on x86; explicit compiled-target
SHA-NI execution passed on AMD and Intel. Both Arm hosts passed hosted and
compiled-target acceleration. Apple's valid kernel inlining was checked inside
the secret authority, not an unrelated ordinary function.

The [evidence index](../../../security/sha1-hardened-native.json) originally
recorded acceptance of native correctness evidence with residual limits; its
current pending state reflects the later source change noted above. Captures remain
operator-self-attested: this is not independent cryptographic verification,
FIPS validation, a timing proof, CPU migration/hotplug qualification, register
erasure or military-deployment approval. SHA-1 remains collision-broken.
Native capture does not run ASan/LSan; the separately enforced sanitizer gate
and final release checks remain distinct requirements.

These observations do not close the pending owner retest of the Apple tooling
correction or authorize a release tag.
