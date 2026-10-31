# Verification results

Local developer observations, not certification or a release gate. No unrun or outdated assessment automatically blocks release. Execution timestamps are original UTC times. Freshness is the last meaningful component scan; unchanged scans do not rewrite timestamps.

## hmac

| Check | Source tested | Performed at | Result | Freshness | Status last changed (UTC) |
| --- | --- | --- | --- | --- | --- |
| tag-policy — hmac tag policy (portable) |  |  | Not run | Not scanned |  |
| vectors — hmac vectors (portable) |  |  | Not run | Not scanned |  |

## kmac

| Check | Source tested | Performed at | Result | Freshness | Status last changed (UTC) |
| --- | --- | --- | --- | --- | --- |
| official-vectors — kmac official vectors (portable) |  |  | Not run | Not scanned |  |
| verification-errors — kmac verification errors (portable) |  |  | Not run | Not scanned |  |

## legacy_hmac

| Check | Source tested | Performed at | Result | Freshness | Status last changed (UTC) |
| --- | --- | --- | --- | --- | --- |
| contracts — legacy_hmac contracts (portable) |  |  | Not run | Not scanned |  |
| rfc2202 — legacy_hmac rfc2202 (portable) |  |  | Not run | Not scanned |  |

## md5

| Check | Source tested | Performed at | Result | Freshness | Status last changed (UTC) |
| --- | --- | --- | --- | --- | --- |
| boundaries — Padding and partial-bit boundaries | — | — | Not run | No recorded result | 2026-10-31T14:24:38.188882334Z |
| known-answers — RFC vectors, ordinary/hardened/streaming | — | — | Not run | No recorded result | 2026-10-31T14:24:37.74621993Z |

## parallelhash

| Check | Source tested | Performed at | Result | Freshness | Status last changed (UTC) |
| --- | --- | --- | --- | --- | --- |
| api — parallelhash api (portable) |  |  | Not run | Not scanned |  |
| official-vectors — parallelhash official vectors (portable) |  |  | Not run | Not scanned |  |

## sha1

| Check | Source tested | Performed at | Result | Freshness | Status last changed (UTC) |
| --- | --- | --- | --- | --- | --- |
| boundaries — Padding and partial-bit boundaries |  |  | Not run | Not scanned |  |
| known-answers — NIST vectors, ordinary/hardened/streaming |  |  | Not run | Not scanned |  |

## sha2

| Check | Source tested | Performed at | Result | Freshness | Status last changed (UTC) |
| --- | --- | --- | --- | --- | --- |
| sha224 — sha2 sha224 (portable) |  |  | Not run | Not scanned |  |
| sha256 — sha2 sha256 (portable) |  |  | Not run | Not scanned |  |
| sha384 — sha2 sha384 (portable) |  |  | Not run | Not scanned |  |
| sha512 — sha2 sha512 (portable) |  |  | Not run | Not scanned |  |
| sha512-224 — sha2 sha512 224 (portable) |  |  | Not run | Not scanned |  |
| sha512-256 — sha2 sha512 256 (portable) |  |  | Not run | Not scanned |  |

## sha3

| Check | Source tested | Performed at | Result | Freshness | Status last changed (UTC) |
| --- | --- | --- | --- | --- | --- |
| cshake — sha3 cshake (portable) |  |  | Not run | Not scanned |  |
| sha3-224 — sha3 sha3 224 (portable) |  |  | Not run | Not scanned |  |
| sha3-256 — sha3 sha3 256 (portable) |  |  | Not run | Not scanned |  |
| sha3-384 — sha3 sha3 384 (portable) |  |  | Not run | Not scanned |  |
| sha3-512 — sha3 sha3 512 (portable) |  |  | Not run | Not scanned |  |
| shake128 — sha3 shake128 (portable) |  |  | Not run | Not scanned |  |
| shake256 — sha3 shake256 (portable) |  |  | Not run | Not scanned |  |

## tuplehash

| Check | Source tested | Performed at | Result | Freshness | Status last changed (UTC) |
| --- | --- | --- | --- | --- | --- |
| api — tuplehash api (portable) |  |  | Not run | Not scanned |  |
| official-vectors — tuplehash official vectors (portable) |  |  | Not run | Not scanned |  |

## Historical / unmapped evidence

These records are retained without assigning a new execution time or a current input fingerprint.

- verification/historical-index.json: Indexed 47 preserved dashboard files containing 10020 historical observation rows (5470 passed, 4543 reused, 3 failed, 4 cancelled), with original file digests and recorded date ranges. These overlapping rows are not distinct fresh executions. None matches the 27 registered portable commands; no current pass or new execution date was imported.
- docs/evidence-index.md: Original evidence index retained. No new execution or current fingerprint is inferred from this index.
- docs/assurance/test-dashboard.md: The previous dashboard and sealed detached results remain available. Its aggregated runs have not yet been mapped to this initial named-check catalog; not run here does not mean the component was never tested.
