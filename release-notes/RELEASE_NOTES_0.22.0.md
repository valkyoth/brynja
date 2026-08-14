# Brynja 0.22.0 Release Notes

Status: pentest PASS/PASS; zero open findings; awaiting green GitHub and CodeQL

Brynja 0.22.0 is an internal development milestone. It selects zero crates.io
packages. The signed v0.20.0 checkpoint remains the latest published release,
and every v0.22.0 change remains inside the cumulative v0.20.0-to-v0.25.0
assessment range.

## Added

- `brynja-hash-core 0.1.0` with small algorithm-independent streaming and
  fixed-output interfaces.
- `brynja-hash-sha2 0.1.0` with complete portable FIPS 180-4 SHA-256 one-shot
  and streaming APIs, checked byte-length accounting, deterministic
  exhaustion, consuming finalization, and an exact digest value.
- Reuse of the exact SHA-256 implementation through `brynja-crypto` and the
  modern `brynja` facade without adding a second implementation.
- Official vectors, padding-boundary cases, arbitrary chunk partitions,
  repeated input, and a public downstream-style consumer test.

## Security Boundaries

The implementation is allocation-free `no_std` safe Rust. It uses no foreign
or external cryptographic implementation, I/O, global mutable state, runtime
CPU detector, or accelerated backend. SHA-256 output is an unkeyed public
digest and must not be treated as a MAC, password hash, signature, or
authentication result.

The assessment confirmed as a disclosed future constraint—not a current
finding—that working state, the message schedule, and buffered input are not
explicitly zeroized because this release exposes only unkeyed hashing. Before
HMAC or other key-derived use, the owning construction must add hardened
secret-state cleanup and emitted-code verification across the supported
compiler and target matrix.

## Deliberate Exclusions

SHA-224, SHA-384, SHA-512, HMAC, HKDF, password hashing, signatures,
accelerated backends, independent cryptographic verification, and FIPS 140-3
validation remain absent. Complete TLS, DTLS, X.509, and OpenPGP engines remain
unimplemented.

## Release Process

The first executable cryptographic primitive triggered an exceptional pentest.
The exact signed implementation candidate received a committed PASS/PASS
report with zero open findings. The final report commit still requires the
complete local tag gate, green GitHub and CodeQL, and explicit tag
authorization. No crates.io publication follows this internal tag.
