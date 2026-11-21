# Changelog

## 1.3.4 — 2026-11-21 (candidate; not released)

- Fix a v1.3.3 dry-run failure when a locally installed MiniSOC signature database contains a regex that the updater's Python validator cannot compile (e.g. `Invalid regex /etc/minisoc/signatures-v2.db:1`).
- Distinguish invalid bundled signatures (still fatal) from incompatible local legacy signatures (preserved for manual review). The dry run now reports `WARNING PRESERVED` rather than aborting before showing the update plan.
- Default installation remains fail-closed; `--preserve-custom-signatures` explicitly permits a **partial** update of other managed files while leaving the incompatible MiniSOC database byte-for-byte unchanged. This option is independent of `--preserve-custom-filters`; both must be supplied when both components cannot be merged.
- Add regression tests for the reported line-1 failure, explicit dual preservation, backup manifest exclusions, rollback, and the new v1.3.3 filter baseline.
- No new blocking rules, no automatic changes to MiniSOC, and no attempt to repair or reinterpret the operator's existing regex.

## 1.3.3 — 2026-11-21

- Fix the v1.3.2 updater's hard-coded `.git` regex fingerprint, which rejected legitimate locally customized `nginx-skanery.conf` filters even when Git was installed.
- Evaluate clean three-way merges against all bundled, verified historical baselines (including v1.3.2), and require the incoming upstream `failregex` to survive the merge verbatim.
- Report incompatible or unknown custom filters during `--dry-run` without writing to the system. Normal installation still stops before making changes unless the operator explicitly chooses `--preserve-custom-filters`.
- In explicit partial-update mode, leave unknown custom filters byte-for-byte unchanged and warn that the newest bundled filter rules are **not** activated for those filters. Other managed files can be updated with the existing backup, validation, and rollback safeguards.
- Add regression tests reproducing a custom `(config|HEAD)` regex spelling, partial-update safety, version v1.3.2 baseline upgrades, and automatic rollback without touching custom filters.
- No new one-hit blocking signatures or jail policy changes in this maintenance release.

## 1.3.2 — 2026-11-21

- Add narrowly scoped rules for encoded environment-file traversal, root SQL backup discovery, sensitive service-account and Streamlit paths; preserve broad discovery patterns as review-only candidates.
- Harden the update path with a v1.3.1 baseline, conflict checks, backups, and automated rollback on validation or reload failure.
- Introduce a fail-closed uninstaller and a SHA-256-verified manual backup restoration tool. Customized filters and jail files are never silently removed.
- Add deduplicated incident diagnostics distinguishing jail notifications, individual requests, distinct paths, and short-window HTTP status transitions.
- Expand sanitized November 2026 test fixtures and offline regression coverage.
- Require a real Fail2Ban parser in both validation and release workflows; unit-test success alone does not certify regex integration.

## 1.3.1 — 2026-11-15

Maintenance and bug-fix release focused on upgrade safety.

- Prevent accidental overwriting of customized Fail2Ban filters by using known-version baselines and conservative merge handling.
- Synchronize the active MiniSOC signature database by unique ID without replacing operator-defined signatures; reject conflicting definitions.
- Detect local Fail2Ban filter overrides and unknown baselines before making changes.
- Preserve existing jail configuration, including custom ban policy and log paths.
- Add dry-run inspection, atomic file replacement, preflight validation, and automatic restoration after failed validation or reload.
- Add ten installer regression tests and version-specific release notes.
- Clarify that the MiniSOC application is not updated or restarted automatically.


## 1.3.0 — 2026-11-15

- Expanded exact HIGH Git metadata indicators: `/.git/HEAD`, `/.git/index`, `/.git/packed-refs`, `/.git/info/refs`.
- Added narrow environment backup indicators for `/.env.1`, `/.env.2`, `/env.bak` and `/env.old`.
- Added review-only WordPress PHP, REST API and environment-backup candidate families, including November 15 observations.
- Preserved the distinction between public rule definitions and production MiniSOC classification; production discrepancies require a separate application fix.
- Documented optional GitHub stars and Monero support.


## 1.2.1 — 2026-10-31

Release retry for the reviewed v1.2.0 changes after the previous version bump did not produce a visible GitHub Release. No duplicate detection signatures added. Includes GitHub issue templates for bug reports, feature requests, and proposed signatures.

## 1.2.0 — 2026-10-31

Focused October 2026 rule expansion after comparing incident evidence against v1.1.1.

- added exact HIGH detection for `/.kube/config` and `/.git/credentials` in the signature database and relevant Fail2Ban filters;
- retained existing `.env`, AWS, Docker and Git rules without duplicating previously covered paths;
- added regression fixtures for new indicators and documented cross-jail incident deduplication;
- kept Vite `@fs`, encoded traversal and NTFS ADS-like probes as review-only candidates pending decoding and false-positive tests;
- treated ASN, IP location and User-Agent strictly as context; no IP-based bans were added.

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
