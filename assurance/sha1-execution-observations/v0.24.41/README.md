# v0.24.41 ordinary SHA-1 native observations

All four registered lanes passed capture and artifact review at exact commit
`83a30e230a0aa11868f7b14af4053240a27d711a`, using Rust 1.98.1/compiler commit
`48a229ceaefd4985c50990b14116b6d856af0985`.

These are ordinary public-data execution observations, not independent
cryptographic verification, FIPS validation, side-channel evidence, migration
safety proof, hardened acceleration approval or release approval. SHA-1 remains
collision-broken. The earlier candidate API remains unadmitted; the separate
operational API is explicitly opt-in and hardened hashing remains portable-only.

## Captures and integrity

| Lane | Original JSON SHA-256 | Operational route |
| --- | --- | --- |
| [Local AMD](amd-x86_64.json) | `22082eaa02f900815c2497637044b9a6378bee9e4441145bb13c5ffb16011b92` | Static SHA-NI; generic hosted unavailable |
| [AWS Intel](intel-x86_64.json) | `e45665da9d74ec3c88dfe79c7c05bfd3b60a78deab39b468745ac0f057876cd3` | Static SHA-NI; generic hosted unavailable |
| [AWS Arm](aws-aarch64.json) | `0d619299885d1a24477e43e34e16c3034a6d8841732fce37e803df618a43dd0c` | Static and hosted AArch64 SHA1 |
| [Apple M2 Pro](apple-m2-aarch64.json) | `96480261d162e8ee9a2df8109252ab36f1091b9ff7c6e3e871abd8b616641215` | Static and hosted AArch64 SHA1 |

Original JSON bytes are preserved. Remote AWS checksums match the downloaded
files, and both remote checkouts remained clean at the captured commit. The
operator supplied the macOS artifact; no remote Mac access was used. The AWS
guests reported Intel Xeon Platinum 8488C and Arm Neoverse-V1, each with two
vCPUs. Capture checked the required features on all enumerated Linux CPUs and
the Apple system feature flags. These are OS/guest reports, not authenticated
hardware attestations. No QEMU user-mode runner was used.

Review rejected duplicate JSON keys, checked the exact field set, lane, commit,
compiler target/version, route and public-only limitations, and recomputed every
source SHA-256 from the captured Git commit. All four files contain the same
complete reviewed source set. No hostnames, login paths, server IPs or keys are
included. Installation logs and unfiltered SSH diagnostics are not archived.

## Coverage observed on every lane

- Four generic ordinary execution tests: all 529 NIST vectors, irregular
  streaming, million-byte input, lifecycle/length checks and static selection.
- Sixteen unit tests plus four execution tests with the exact compile-time
  instruction bundle. The actual operational backend marker was present.
- Callback revocation of live streams and failed-startup/revalidation tests ran
  with the native bundle enabled; restored callbacks cannot revive owners.
- Hosted selection produced `None` on x86 and `Some(Aarch64Sha1)` on Arm/Mac.
  A hosted report of `None` is the intended x86 disposition, not missing coverage.
- Packaged consumers passed 1,135 independently generated bit-message cases,
  rejected 19 ownership/classification violations and rejected four compiled
  debug/release revocation/finalization mutations.

Tests gated to the old evidence-only candidate API may skip their candidate
execution in an ordinary build; passing unit-test totals do not override that
gate. The operational marker, native-enabled revocation test and packaged
consumer results identify what actually executed here.

## Reproduction and limitations

At the exact clean commit, fetch the locked dependencies, then run:

```sh
python3 scripts/sha1/capture-sha1-execution-native.py LANE OUTPUT.json --attest-native
```

Use a matching registered lane (`amd-x86_64`, `intel-x86_64`, `aws-aarch64` or
`apple-m2-aarch64`). The capture uses the pinned compiler, generic hosted and
portable tests, explicit static features, and package-external tests. It refuses
to overwrite an output or accept source/commit drift. See the
[execution contract](../../../docs/legacy-sha1-execution.md).

The raw `pending owner review` disposition is retained because it describes
capture-time state; this README records subsequent artifact review without
rewriting evidence. Native correctness does not remove the documented Low
platform-trust residual: cached OS detection cannot detect a later advertised
ABI violation. Android, iOS and Windows are not native-qualified by these lanes.
Final release checks and GitHub checks remain separate requirements.
