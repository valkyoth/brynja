# v0.29.4 — AES-GCM and GMAC public API usability (internal candidate)

The [installed-consumer fixture](../assurance/aead-installed-consumer/README.md)
checks that downstream users can opt into either algorithm through
`brynja-crypto` or the `brynja` facade and get the documented results and
errors. No cryptographic implementation, public signature, backend, or
dependency changed. Only the facade version advances; zero crates are
selected for publication.

On Linux x86-64 all 16 install/run combinations passed (two compiler
endpoints × two imports × two algorithms × portable/required native).
The full frozen portable Go comparison, archived Cortex-M compile checks,
and the native AES-NI/PCLMUL Go/NIST replays and linked-code screen also
passed on the candidate working tree. General-IV coverage comes from those
replays, not the 96-bit-IV install fixture.

The [v0.29.3 native records](../assurance/aead-native-observations/v0.29.3)
were checked for integrity. Linux ARM64, Apple Silicon and Windows x86-64
native functional results are from that milestone, not new v0.29.4 runs.
Arm timing remains unresolved. No timing experiment, validation claim,
new publication gate or crates.io install is implied by this milestone.
