# Historical Protocol Implementation Plan

Status: deferred and isolated

Historical support is not part of the modern `brynja` facade or its 1.0
production claim. Work begins only after the shared primitive it needs has
passed external audit. Every package has an independent version line, threat
model, source ledger, test corpus, warnings, audit, pentest, and publish
decision.

## Universal Isolation Rules

- No dependency, feature, re-export, version enum, configuration builder,
  negotiation range, session cache, ticket key, credential store, listener, or
  fallback path is shared with the modern facade.
- Enabling every feature of `brynja` cannot compile historical code.
- `brynja-historical` has no default features and only re-exports explicitly
  selected historical packages.
- Every public type and crate README states that the protocol is obsolete,
  insecure, and intended only for controlled interoperability or research.
- Protocols use distinct wire/state types even when primitive implementations
  are reused.
- Security scanners and policy engines can reject historical use by package
  name.

## Independent Small-Pass Sequence

Each implementation package follows versions `0.1.0` through `0.8.0`, with a
separate admission freeze before codec work:

| Version | Goal | Required verification |
| --- | --- | --- |
| `0.1.0` | Lock authentic specifications, rights, errata, insecurity statement, and threat model | provenance review and source hashes |
| `0.1.1` | Freeze the exact cipher-suite, compression, extension, message, certificate, key-format, and primitive admission register | source-to-register completeness, IANA or source-value checks, explicit rejection and research-only decisions, and no unspecified primitive |
| `0.2.0` | Strict bounded wire codec | truncation, canonicality, mutation, and resource tests |
| `0.3.0` | Typed handshake state machine without cryptography | complete transition and illegal-message model |
| `0.4.0` | Bind only required reviewed primitives | official/derived vectors and cross-protocol separation |
| `0.5.0` | Client-only controlled interoperability | isolated mature-peer fixtures and expected failures |
| `0.6.0` | Server-only controlled interoperability, if justified | amplification, downgrade, credential, and load tests |
| `0.7.0` | Operational containment API | separate listener/config/cache proofs and misuse tests |
| `0.8.0` | External historical-protocol review | remediation, clean retest, release warnings, pentest |

This sequence applies separately to `brynja-tls11`, `brynja-tls10`,
`brynja-ssl3`, `brynja-ssl2`, `brynja-wtls`, `brynja-pct`, and
`brynja-snp`; completion in one package cannot satisfy another.

`brynja-ssl1-research` stops after source/provenance reconstruction,
documentation, and parser research. It remains `publish = false`, exposes no
secure transport API, and must not accept production credentials.

Every version exits with: `vX.Y.Z implementation stop reached. Run pentest
for this exact commit.`

## RFC Source Baselines

TLS 1.0 uses RFC 2246, TLS 1.1 uses RFC 4346, and SSL 3.0 uses the
historical RFC 6101 publication as locked compatibility baselines. Current
prohibition and deprecation documents remain mandatory warning and containment
inputs; they never make a historical protocol modern or recommended.

SSL 2.0, SSL 1.0 research, WTLS, PCT, and SNP depend on separately authenticated
local-only sources. No package may leave H0.1.0 or H0.1.1 until exact source
identity, rights, errata, wire values, cipher subset, and primitive ownership
are frozen.
