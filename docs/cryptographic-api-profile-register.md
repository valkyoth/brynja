# Cryptographic API Profile And Secret-State Register

Generated from the reviewed policy and semantic standards surfaces. Do not edit by hand.

- Capabilities: **129**
- API dimensions per capability: **22**
- Current secret owners: **8**
- Registered capability owners: **2**
- Planned secret owners: **73**

## Profile Coverage

| Profile | Capabilities |
| --- | ---: |
| `aead` | 2 |
| `asymmetric` | 6 |
| `fixed-hash` | 1 |
| `hash-xof-family` | 1 |
| `keyed-construction` | 4 |
| `protocol` | 23 |
| `public-component` | 42 |
| `public-format` | 8 |
| `rejected` | 4 |
| `secret-component` | 34 |
| `secret-format` | 1 |
| `symmetric-cipher` | 2 |
| `test-secret-support` | 1 |

## Implementation Dispositions

| Disposition | Capabilities |
| --- | ---: |
| `future-work` | 117 |
| `implemented` | 7 |
| `intentionally-rejected` | 1 |
| `legacy-only` | 3 |
| `safely-ignored` | 1 |

Every capability classifies every API dimension and binds an owner milestone.
Secret owners enumerate exact fields, temporaries, lifecycle edges, cleanup symbols,
output handling, evidence, and residual risks. Ordinary state never implies hardened
ownership. The optional sanitization adapter cannot replace mandatory core cleanup or
enter the FIPS graph.
