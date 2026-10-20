# HMAC timing observations

This is a bounded **portable timing screen**, not a constant-time proof,
cache/branch analysis, independent review, or release approval. It measures the
actual public HMAC construction/update/finalization and verification APIs with
synthetic inputs. It does not measure accelerated or protected/resident workers.

Run it on a suitably quiet supported host and retain the new local output:

```sh
python3 scripts/hmac/check-hmac-timing.py --output target/hmac-timing.json
```

The output path must not already exist. The runner uses a private build
directory, clean Cargo environment, locked dependencies and Rust 1.99.1 release
code. It records the compiler identity, source revision and tracked-diff digest,
fixture and binary hashes, host description, complete raw samples and derived
statistics. This is diagnostic provenance, not authenticated runner attestation.
Do not commit the large raw output or include it in a crates.io package.

## Population and interpretation

The ten named SHA-2/SHA-3 identities and general SHA-512/t at 129 and 511 bits
each run eight campaigns: 32/200-byte keys, 16-byte/largest-whole-byte tags,
and two contrasts at identical public lengths:

- First-byte versus last-byte mismatch; both must reject authentication.
- Two different key contents while producing public tags.

General 129's two whole-byte lengths both equal 16; these remain two ordered
campaigns, not a hidden deduplication. Fractional full tags and final-bit
messages are functionally checked elsewhere, not covered by this timing screen.

Each campaign uses 32 discarded warmup pairs, then 512 measured pairs with four
operations per class. A deterministic xorshift sequence reverses class order
within pairs. Logging occurs after both measurements. No sample is trimmed.
The analysis uses the mean paired difference divided by its standard error.
A constant nonzero difference signals rather than causing a divide-by-zero
pass. Missing, reordered, invalid or extra samples reject the observation.

An absolute paired statistic of at least 10 exits unsuccessfully **after saving
the observation**. This coarse alarm needs investigation, including scheduling,
frequency changes and timer noise. Do not retry until a passing result hides
the original. The threshold is not a security bound; a result below it cannot
establish absence of a leak. Samples can be dependent, the two input classes
are deliberately limited, and clocks/hardware vary.

Deterministic analyser controls, malformed-population regressions and compilation
run in normal HMAC checks. Wall-clock observations are explicitly requested
outside shared CI; noisy CI is not silently treated as security qualification.

## Native adapter cleanup is a separate check

The extracted-package harness optionally checks real native hash-output
handoffs, including consumer success, errors, unwinding and rejected lengths:

```sh
python3 scripts/hmac/check-hmac-package.py --adapter-kernel sha256 --adapter-kernel keccak
```

On a capable Arm host, add `--adapter-kernel sha512`. Each selected route is
mandatory; an unavailable route fails rather than falling back. A separate
dependency-free, generic CPU probe executes before a feature-enabled build:
feature detection inside the latter can otherwise fold to `true`.
This relies on the host OS detection contract, not live-migration monitoring.

Package preparation and portable acceptance run once for multiple routes;
each route receives a separate private source copy. Compiled mutants check
forgotten output owners, lost callback errors and cleanup omitted only during
unwinding. These are live digest-storage/ownership observations, not inspection
of freed stack memory, all hash-owner fields, compiler copies or registers.
