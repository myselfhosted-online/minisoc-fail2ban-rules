# Changelog

## 1.1.1 — 2026-10-18

Correction release.

- promoted `/wp-content/wuhr9.php` from review-only status to an exact HIGH WordPress webshell/backdoor-hunting signature;
- added the exact path to the active `nginx-skanery` Fail2Ban filter;
- added a malicious regression fixture for `/wp-content/wuhr9.php`;
- corrected the candidate list and validation so this path is no longer treated as pending review;
- kept the distinction that the path is a high-confidence malicious probe indicator, not proof of a specific named PHP shell family.

## 1.1.0 — 2026-10-18

Detection-policy and regression update.

- added explicit benign/research scanner handling with `SAFE_DISCOVERY` and `TRUSTED_ONLY` policies;
- added Cloudflare Radar / agent-readiness regression cases to prevent benign discovery from becoming automatic bans;
- added `rules/benign-scanners.list`;
- added `rules/candidates.list` so suspicious paths can be reviewed without immediately becoming one-hit blocking rules;
- added `/wp-content/wuhr9.php` as a review candidate rather than a confirmed shell signature;
- expanded the curated incident index with reviewed 2026-10-13 through 2026-10-16 WordPress scanning campaigns;
- documented detailed Fail2Ban installation, verification, troubleshooting, updating, unbanning, and uninstall procedures;
- strengthened false-positive and authorized-scanner policy documentation;
- extended benign regression fixtures and repository validation;
- retained the principle that ASN, cloud provider, Tor status, country, and User-Agent are context rather than standalone ban reasons.

## 1.0.0 — 2026-10-13

Initial public release.

- real-world homelab-derived detection methodology;
- Fail2Ban filters for scanner and secret-discovery traffic;
- MiniSOC signature database;
- WordPress webshell/backdoor exact-path indicators;
- cloud/container secret-discovery indicators;
- correlation and authorized-scanner policy;
- sanitized representative samples;
- GitHub Actions validation.
