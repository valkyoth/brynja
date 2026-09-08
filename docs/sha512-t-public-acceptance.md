# General SHA-512/t portable public acceptance

v0.24.28 freezes a runnable consumer of the default-off `general-sha512-t`
feature in `brynja-hash-sha2`. It adds no production algorithm or facade API.
The family remains **In progress** until v0.24.29 final evidence closure.
The [final evidence candidate](sha512-t-final-evidence.md) reuses this corpus
and adds work, storage and local performance checks; owner pentest is pending.

## Run it yourself

From the repository root, these are complete single-line commands:

```sh
cargo run --locked --offline --release --manifest-path assurance/general-sha512-t/Cargo.toml < crates/brynja-hash-sha2/tests/vectors/general-sha512-t-digest.txt
python3 scripts/sha2/check-general-sha512-t.py
python3 scripts/sha2/test-general-sha512-t.py
```

The first command executes the no_std consumer library through a small hosted
stdin adapter. It must report **510 parameters and 4590 independent cases**.
The second additionally packages the dependency closure, extracts the `.crate`
archives, builds the consumer outside the workspace with an empty Cargo home
and offline local registry patches, checks its resolved graph, and reruns it in
debug and release. It also retains the IV/digest oracle, source policy,
emitted-code cleanup checks and v0.24.27 destructor probe. The third exercises
negative and compiled-mutation controls. None of these commands publishes.

The consumer graph is exactly the consumer, `brynja-hash-sha2`,
`brynja-hash-core` and `brynja-core`. The reused packaging helper assembles a
wider first-party workspace to normalize manifests without registry downloads;
the active consumer closure is checked separately and cannot include the
facade, optional CPU crate, sanitization adapter or any external crate.
The mandatory core clearing boundary remains present for hardened state.

## Frozen operation matrix

| Surface | Positive and negative public acceptance |
| --- | --- |
| Parameter | Every u16 admission outcome, all 510 valid t, TryFrom, exact output width, public IV labels and short-destination preservation; existing all-parameter independent IV oracle retained |
| Ordinary one-shot | Byte and MSB-first arbitrary-bit digest vs independent expected bytes |
| Ordinary streaming | Byte finalization and bit-tail finalization; empty updates, strides 1/19/128, public parameter/count and preflight overflow rejection |
| Hardened public | One-shot and consuming streaming byte/bit finalization require explicit declassification and match independent expected bytes |
| Hardened secret | All four entry points produce typed parameter-bound output; fresh guaranteed-wrong poison before each positive route, exact outputs, Drop and consuming declassification clear original storage |
| Secret rejection | Every valid t with wrong destination widths 0–65, all four routes, whole-region clearing and unchanged adjacent sentinel bytes |
| Digest import/view | Exact width and canonical bits, public parameter identity, malformed low bits and invalid widths; this importer is for already-public bytes, not secret conversion |
| Named compatibility | General /224 and /256 match the named byte API outputs but cannot be assigned to the named digest types |
| Affine ownership | External compile failures reject consumed-state reuse, cancellation reuse, hardened cloning and secret cloning; existing ownership suite remains required |
| Hostile assurance input | Bounded corpus and row sizes, exact fields and parameter/case ordering, malformed hex/count overflow, missing/duplicate/reordered/corrupted records rejected by the compiled executable |

All nine independent messages per parameter are replayed, including empty,
`abc`, all seven partial-bit widths and SHA-512 padding/rate boundaries. The
corpus is regenerated independently in Python and /224 and /256 byte controls
are also checked against the platform hash implementation. The corpus is not
generated from Brynja's implementation. Six compiled package mutants (wrong
ordinary IV, wrong hardened IV, skipped secret declassification destruction,
each debug/release) must execute and fail assertions; compiler failures do not
count as detection. Corrupted-corpus controls must fail inside the executable.

The consumer library uses fixed buffers and no allocation, filesystem or OS API.
Its separate stdin adapter caps reads at 3,000,001 bytes, rejects inputs above
3,000,000 bytes, and reserves storage fallibly. Inputs here are assurance data,
not a new production parser. Package tooling assumes a trusted, quiescent
checkout and reuses the existing safe archive extractor; it is not an untrusted
build-script sandbox. Rust 1.90.0 through the current supported default and the
existing three bare-metal targets execute/check this consumer through the
repository matrix scripts. Cross-compilation alone is not native execution.

## Evidence and limits

The [contract](sha512-t-contract.md) and [lifecycle inventory](sha512-t-lifecycle.md)
remain normative. The [official FIPS 180-4 page](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
was rechecked on 2026-09-08: August 2015 remains the listed final, with the
2023 revision announcement. The pinned authority has not been replaced.

This step is scalar-only. No new AWS/Mac hardware evidence is needed to execute
portable package acceptance, and no CPU backend becomes admitted. Private
memory destruction continues to be checked separately through the live-storage
probe and emitted-code controls: safe consumer code cannot inspect freed memory.
No register/spill/cache/dump/swap/DMA/abort/forget/caller-copy erasure is promised.
Short arbitrary t does not gain full-width strength or protocol approval.

Acceptance passing is not named independent cryptographic review, FIPS 140-3
validation, production TLS readiness or approval for classified deployment.
An exceptional owner pentest is required before tagging this assurance change;
the current disposition is in [the v0.24.28 report](../security/pentest/v0.24.28.md).
