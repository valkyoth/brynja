# Cryptographic API Profile And Secret-State Register

Generated from the reviewed policy and semantic standards surfaces. Do not edit by hand.

- Capabilities: **135**
- API dimensions per capability: **22**
- Current secret owners: **8**
- Registered capability owners: **9**
- Planned secret owners: **72**

## Profile Coverage

| Profile | Capabilities |
| --- | ---: |
| `aead` | 2 |
| `asymmetric` | 6 |
| `fixed-hash` | 3 |
| `general-sha512-t` | 1 |
| `hash-xof-family` | 3 |
| `keyed-construction` | 5 |
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
| `future-work` | 116 |
| `implemented` | 14 |
| `intentionally-rejected` | 1 |
| `legacy-only` | 3 |
| `safely-ignored` | 1 |

Every capability classifies every API dimension and binds an owner milestone.
Secret owners enumerate fields, temporaries, lifecycle edges, cleanup contracts,
output handling, evidence, and residual risks. Ordinary state never implies hardened
ownership. The optional sanitization adapter cannot replace mandatory core cleanup or
enter the FIPS graph. HMAC registers transitive inner/outer hash ownership and
consuming handoffs, not an invented Engine destructor. Its existing emitted-code
checks remain separate from the direct-destructor MIR checks. Registration is
not native release qualification, independent review or whole-frame erasure.
