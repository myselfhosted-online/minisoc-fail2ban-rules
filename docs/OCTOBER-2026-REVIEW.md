# October 2026: deduplicated detection review

Source: operator-supplied Nginx/Fail2Ban alerts, 19–31 October 2026. Some earlier events are available only as summarized evidence, not original log exports. This document deliberately does not republish repeated IP addresses or previously covered request paths as new indicators.

## Newly promoted indicators

| Request target | Signature | Why |
|---|---|---|
| `/.kube/config` | `kube-config` | Exact Kubernetes client configuration path; may expose cluster credentials |
| `/.git/credentials` | `git-internal-credentials` | Exact Git credential-file discovery path |

Both are HIGH-confidence *probe indicators*, not proof of compromise. HTTP 401 and 404 are not evidence of successful file disclosure.

## Already covered; not republished as new rules

`/.env`, `/.aws/credentials`, `/.aws/credentials.bak`, `/.docker/config.json`, `/.docker/.env`, `/.git/config`, `/.git-credentials`. Existing patterns remain in place. Do not treat matching the same path from a different source IP as a novel signature.

## Review-only candidates

- Vite `/@fs/` file access with dotenv-related targets: require request-target normalization tests.
- Encoded `..%2f` traversal: evaluate decoding and false positives before promotion.
- NTFS ADS-like `::$DATA` suffixes: require platform and escaping checks.

See `rules/candidates.list`. Review candidates are not standalone ban rules.

## Incident counting and AbuseIPDB

An IP generating the same request burst that triggers `nginx-skanery`, `nginx-highconf`, `nginx-dev-honeypot`, or `nginx-fake-searchbots` should count as **one parent incident** when timestamps and requests overlap. Preserve jail alerts for diagnostics, but deduplicate downstream reports using a stable incident key and an aggregation window. This repository documents the method; it does not claim to implement production alert deduplication.

Do not infer common operator identity from identical User-Agent strings, ASN or similar paths. Never ban by ASN, provider, country or crawler-looking User-Agent alone. Authorized scanner policy takes precedence over reporting.

## Validation

The fixture `tests/fixtures/october-2026-new.log` contains documentation-range IPs, not real scanner addresses. Verify positive matches for both exact paths and negative matches for benign requests. No private hostnames, headers, tokens, or credentials are included.
