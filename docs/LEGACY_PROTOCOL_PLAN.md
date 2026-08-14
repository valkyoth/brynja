# Legacy Protocol Implementation Plan

Status: normative pre-1.0 completeness boundary; isolated from modern defaults

Legacy support is not part of the modern `brynja` facade or its secure-default
claim, but every named legacy package is part of Brynja's complete `1.0.0`
ecosystem claim and therefore blocks `1.0.0` until its authenticated standard
surface is complete. Work begins only after every shared primitive it needs has
passed external audit. Every package retains an independent crate version line,
threat model, source ledger, test corpus, warnings, audit, pentest, and publish
decision.

## Universal Isolation Rules

- Every engine is named `brynja-legacy-<protocol>`; abbreviated names that
  can appear modern or generally supported are prohibited.
- No dependency, feature, re-export, version enum, configuration builder,
  negotiation range, session cache, ticket key, credential store, listener, or
  fallback path is shared with the modern facade.
- Enabling every feature of `brynja` cannot compile legacy code.
- `brynja-legacy` has no default features and only re-exports explicitly
  selected legacy packages.
- Every public type and crate README states that the protocol is obsolete,
  insecure, and intended only for controlled interoperability or research.
- Protocols use distinct wire/state types even when primitive implementations
  are reused.
- Security scanners and policy engines can reject legacy use by package
  name.

## Future TLS Retirement

A TLS generation is not legacy merely because a successor is standardized.
Multiple externally reviewed generations may remain in the modern
`brynja-tls` router while their cryptography and deployment profiles remain
admitted.

Moving a modern generation to this plan requires a dedicated numbered
security-boundary milestone. It must:

- cite the current standards, cryptographic, ecosystem, and Brynja policy
  evidence requiring retirement;
- remove the version engine from `brynja-tls`, `brynja`, QUIC, FIPS, and every
  modern feature graph before legacy work begins;
- prohibit negotiation retry, compatibility forwarding, shared types,
  credentials, caches, tickets, PSKs, and state across the boundary;
- issue an explicit deprecation release for the former modern package; and
- create a new `brynja-legacy-tls1N` package only when controlled
  interoperability remains justified, starting again at the independent
  legacy sequence below.

The former modern crate never changes meaning in place and never forwards to
the legacy package.

## Numbered Pre-1.0 Completion Sequence

Repository milestones v0.180.1-v0.180.24 apply separately to
`brynja-legacy-tls12`, `brynja-legacy-dtls12`, `brynja-legacy-tls11`,
`brynja-legacy-tls10`, `brynja-legacy-dtls10`, `brynja-legacy-ssl3`,
`brynja-legacy-ssl2`, `brynja-legacy-wtls`, `brynja-legacy-pct`, and
`brynja-legacy-snp`. Completion in one package cannot satisfy another.

Each named protocol must complete all of these duties before its acceptance
gate:

- authenticated specification, rights, errata, warning, threat model and exact
  registry closure;
- every bounded wire codec and every client and server state and operation;
- every specified suite, compression method, extension, credential, key format,
  import/export and generation direction over the exact shared primitive owner;
- public client and server usability fixtures, independent or archived
  interoperability, hostile-input and resource campaigns;
- separate configuration, listeners, credentials, caches, storage,
  diagnostics, process containment, audit and pentest.

Deprecation or weakness requires explicit dangerous policy; it cannot justify a
read-only, client-only, subset, recognition-only, or unimplemented status.
Reserved, unassigned and unauthenticated values remain non-capabilities.

`brynja-research-ssl1` stops after source/provenance reconstruction,
documentation, and parser research. It remains `publish = false`, exposes no
secure transport API, and must not accept production credentials.

Each repository milestone follows the ordinary signed-tag cadence. Package
publication remains selected independently by the checkpoint release closure.

## RFC Source Baselines

TLS 1.0 uses RFC 2246, TLS 1.1 uses RFC 4346, and SSL 3.0 uses the
legacy RFC 6101 publication as locked compatibility baselines. Current
prohibition and deprecation documents remain mandatory warning and containment
inputs; they never make a legacy protocol modern or recommended.

SSL 2.0, SSL 1.0 research, WTLS, PCT, and SNP depend on separately authenticated
local-only sources. No production package may proceed until exact source
identity, rights, errata, wire values, complete cipher and operation surface,
and primitive ownership are frozen. SSL 1 remains the only standalone
source-blocked post-1.0 research exception unless a future authenticated source
and explicit scope decision move it into a numbered pre-1.0 milestone.
