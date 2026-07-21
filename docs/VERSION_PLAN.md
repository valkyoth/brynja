# Brynja Version Plan

Status: planning summary

The normative per-version goals, verification, and exit criteria are in
[RELEASE_PLAN.md](RELEASE_PLAN.md). Versions are intentionally small; patch
releases or additional milestones are added whenever one pass becomes hard to
review.

| Range | Theme | Result |
| --- | --- | --- |
| `0.1.0..=0.4.0` | Repository, release, standards, and test foundation | Claims and evidence become enforceable |
| `0.5.0..=0.8.0` | Core bounded domains and provider contracts | Platform-neutral protocol substrate |
| `0.9.0..=0.22.0` | First-party cryptographic substrate | Auditable TLS cipher-suite primitives |
| `0.23.0..=0.32.0` | DER, X.509, validation, and revocation | Fail-closed PKI engine |
| `0.33.0..=0.45.0` | TLS 1.3 | Complete modern core engine |
| `0.46.0..=0.51.0` | Hardened TLS 1.2 | Explicit legacy-modern compatibility |
| `0.52.0..=0.62.0` | Facade, platform integration, and operations | Usable runtime-neutral API |
| `0.63.0..=0.72.0` | QUIC TLS and DTLS | Separate transport integrations |
| `0.73.0..=0.80.0` | Modern extensions and completeness review | Complete reviewed 1.0 feature scope |
| `0.81.0..=0.95.0` | Assurance, audits, remediation, and freeze | Production admission evidence |
| `1.0.0-rc.N` | Exact production candidate | Immutable artifact under final review |
| `1.0.0` | First serious production-ready Brynja release | Unchanged approved modern TLS artifacts |

Historical packages have independent version lines and do not block or inherit
the modern facade's `1.0.0` claim. Their implementation begins only after the
shared first-party primitives they require are audited. Each historical crate
must publish with conspicuous insecurity warnings and its own protocol-specific
pentest; `brynja-ssl1-research` remains non-production and unpublished.

