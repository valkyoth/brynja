# Brynja 0.3.3 Release Notes

Status: pentest passed; awaiting green GitHub checks and tag authorization

Brynja 0.3.3 completes the cryptography, encoding, and PKIX normative-coverage
pass. It does not implement TLS, cryptography, PKI, QUIC, DTLS, platform
services, or legacy protocols and must not be used to secure network traffic.

## Complete Domain Coverage

The normative matrix grows from its 12-record foundation to 46 stable
requirements. Thirty-four new records cover the currently admitted or
explicitly rejected:

- SHA-2, SHA-3, SHAKE, HMAC, HKDF, AES, GHASH, AES-GCM, ChaCha20,
  ChaCha20-Poly1305, elliptic-curve, RSA, and Ed25519 surfaces;
- DER, canonical ASN.1, PEM/Base64, and private-key containers;
- X.509 decoding, service identity, path construction and validation,
  AlgorithmIdentifier handling, name constraints, certificate policy, trust
  anchors and cross-signing, CRLs, `noRevAvail`, and unsigned-certificate
  rejection;
- OCSP validation, Must-Staple, lightweight OCSP messages and caller-owned
  transport/cache effects, status_request_v2 rejection, and certificate-status
  negotiation; and
- strictly separated Certificate Transparency protocol generations.

Every new requirement records its owning implementation milestone, authority
role, decision lifecycle, assurance invariants, planned symbol, positive and
negative tests, explicit work bound, unresolved evidence, residual risk, and
reviewed mapping rationale.

## Authority And Surface Closure

The domain scope covers all 53 exact current, compatibility, evidence, and
exclusion authorities assigned to the symmetric, public-key, key-container,
PKIX, OCSP, and CT source domains. Every uppercase RFC 2119/RFC 8174 normative
section is recorded with an exact text hash and keyword occurrence counts.

All 3,322 cryptography, PKIX, PKI, OCSP, and CT surfaces are assigned to a
requirement or an explicit later milestone. Only `algorithm.ml-kem` and
`format.ml-kem-pkix-credentials` are deferred to v0.3.5, where their complete
hybrid authority review belongs.

The source inventory now includes local-only, checksum-pinned FIPS 202 and the
in-force ITU-T X.690 (2021) plus Erratum 1 authorities. Three missing semantic
algorithm decisions were added for SHA-3/SHAKE, GHASH, and ChaCha20, and stale
SHA-2, HMAC, HKDF, and AES milestone ownership was corrected.

Five newly reported RFC Editor errata were reviewed and remain
`track-not-applied`; no reported erratum was silently applied.

## Fail-Closed Verification

The requirement checker now consumes compact domain policies and emits a
separate deterministic domain-coverage artifact. Shared validation keeps the
foundation and domain records under the same target, test, evidence, history,
and lifecycle rules.

Fifteen dedicated domain fixtures reject source-ledger or surface-register
drift, authority-role misclassification, absent test polarity, weak work
bounds, missing resource/work invariants, unknown owners, out-of-scope
decisions, missing or duplicate surface groups, nondeterminism, and stale
generated evidence. Existing requirement, history, lifecycle, standards, and
surface fixtures continue to pass.

## Publication

Only `brynja 0.3.3` is selected for crates.io publication. All unchanged
modern supporting crates retain version `0.1.0` and are not republished.
Legacy and repository-only packages remain unpublished.

Publication requires a committed PASS pentest report, green hosted GitHub
checks, explicit tag authorization, and the exact signed tag at `HEAD`.

## Pentest

The repository owner pentested signed implementation candidate
`a5dd438159613da3b9869c37fe13c8f16b5a258b` and reported a green result with
no findings. No remediation was required, zero findings remain open, and the
permanent v0.3.3 report records `PASS`/`PASS`.

## Limitations

This release proves reviewed requirement coverage, not implementation,
interoperability, cryptographic correctness, side-channel resistance, protocol
security, or FIPS 140-3 validation. Planned targets and tests do not exist yet.
v0.3.4 covers TLS, DTLS, and QUIC normative requirements; v0.3.5 covers
optional, legacy, residual, and hybrid requirements before implementation
begins.
