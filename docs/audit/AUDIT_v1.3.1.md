# MiniSOC Fail2Ban Rules — v1.3.1 audit and offline remediation

**Status:** working draft, not published. **Source baseline:** official GitHub tag `v1.3.1`, commit `ba70f017281c23b86465b7829214e4e953f4a6e8`. This overlay changes no running server.

## Scope and provenance

Reviewed published release structure, code of `install/install.sh`, `install/safe_update.py`, `install/uninstall.sh`, `install/test.sh`, signature DB, candidates, the two public Fail2Ban filters, jail example, existing unit tests, repository validation and release workflows, plus release notes. Audit also sampled **20 previously generated local `*-myselfhosted.zip` archives**. These older local archives are from a *different line of code* and **must not be treated as the official v1.3.1 source**.

**Important scope limit:** Public v1.3.1 does **not** contain the production MiniSOC application classifier, or production jails `nginx-highconf` and `nginx-fake-searchbots`. Their source/configuration was not audited or modified. Server-specific settings and Nginx logs were not available. An offline code audit is not a production certification.

## Findings / remediations in this patch

| ID | Severity | v1.3.1 problem | Patch |
|---|---|---|---|
| A01 | HIGH | `uninstall.sh` uses unconditional `rm -f` for filters and jail, no backup, no rollback | New `safe_uninstall.py`, hashes/known baselines, `--dry-run`, backup, validation and reload rollback; refuses customized files |
| A02 | HIGH | `install/test.sh` can report PASS when `fail2ban-regex` executes but matches zero hostile requests | New integration verifier checks **positive and negative match counts**; uses exact sanitized fixtures |
| A03 | HIGH | Old scanner `failregex` can search ahead through arbitrary request text; a benign query parameter containing `/.env` may produce a one-hit match | Active filters now anchor the inspected request target instead of scanning arbitrary text; negative fixtures added |
| A04 | MEDIUM | Updater backups had flat numbered files with no restoration manifest and no manual verified restore utility | File-hash manifest with original paths, owner, mode; `restore_backup.py` verifies current/backup hashes and restores only allowed targets |
| A05 | MEDIUM | Installation of a changed filter might silently lose local customizations or conflict | Explicit baseline verification, conservative three-way merge, change detection, symlink refusal; unknown/ambiguous local changes abort before writes |
| A06 | MEDIUM | Unexpected update failure after the first file could leave inconsistent rule state | Register planned file **before** writing, atomic replacements, preflight checks, and rollback of already touched files |
| A07 | MEDIUM | Existing version's CI checks simulated `fail2ban-client`, but did not run actual `fail2ban-regex` | Draft CI installs `fail2ban` and requires real parser integration. Pending CI verification until later push |
| A08 | MEDIUM | Credentials/configuration sweep produced only generic MEDIUM incident with duplicated cross-jail alerts | New REVIEW candidates plus sanitized correlation fixture; **not** an automatic HIGH ban for generic config filenames |
| A09 | LOW | Old local release archives have different filters (`nginx-vuln-scanner`, `nginx-fake-crawler-on-exploit`), jail (`minisoc-scanners.local`) and helper scripts | Builder verifies exact official v1.3.1 Git blob SHAs before reconstructing a full archive; never mixes unrelated distributions |
| A10 | INFO | User-Agent strings copied from Googlebot, Bingbot, Qwenbot, etc. were rotated within a seconds-long scan | Count distinct UA claims only as context; **do not** use UA or cloud ASN as sole ban/attribution evidence |

## New defensive indicators (not blanket bans)

Active HIGH signatures, narrowly scoped:

- `/terraform.tfstate.backup` — potentially sensitive infrastructure state backup.
- `/client_secrets.json` — OAuth credential-file discovery at the web root.
- `/api/uploads/%2e%2e%2f%2e%2e%2f.env` — exact encoded traversal with `.env` target.
- `/uploads../.env`, `/img../.env`, `/public../.env`, `/images../.env` — adjacent-dot `.env` probes.

Review-only signatures: Flowise credentials endpoint, CI workflow YAML, `configuration.js`, Firebase front-end config, encoded settings path, `config.json`, `config/config.json`, `config.yaml`, and `credentials.json/.yml`. These **must not** become automatic one-hit blocking rules without context and false-positive review.

## Behavior and safety constraints

1. `--dry-run` never creates a backup directory, lock, or changes files/services.
2. Real apply is root-only; performs full preflight before touching a file.
3. Existing `minisoc-fail2ban.local` settings (including `logpath`, `maxretry`, `bantime`) are always preserved.
4. A corresponding Fail2Ban `filter.d/*.local` override stops updating; no silently masked rules.
5. The update adds MiniSOC signatures by ID and stops on conflicting definitions rather than replacing local definitions.
6. A root-protected snapshot is written before changes, followed by atomic writes, `fail2ban-client -t`, and reload. On failure, previous bytes are restored and the restored Fail2Ban configuration is revalidated/reloaded.
7. The safe uninstaller will not remove altered or unrecognized files. It intentionally keeps MiniSOC's production signature database.
8. The manual restore command refuses to overwrite post-update local edits (hash mismatch) and validates the backup manifest.
9. The MiniSOC application/Telegram classifier is **not** updated or restarted. This patch alone cannot fix its `hellopress` HIGH/MEDIUM classification discrepancy.

## Test results in authoring environment

- Offline `unittest`: **24 tests passed** (installer, update, custom jail, signature merges, conflict fail-closed behavior, symlinks, backup manifest, rollback on failed validation/reload, manual restore, regex compilation, sanitized deduplication).
- Filter parsing: Python `configparser` (percent interpolation) and equivalent regex positive/negative fixtures passed.
- Real `fail2ban-regex`: **not available** in the authoring container. The draft CI has a mandatory real-parser step, but that workflow has **not been run** or pushed.
- Production Nginx logs and live jail reload: **not tested**. The deferred deployment must include preflight output review and a staging test.

## Packaging and next release

This archive is an **offline overlay** and source/audit pack, not a repackaged official release. The assembly helper checks official v1.3.1 source hashes and produces a complete staged ZIP when given an authentic base. `VERSION` is intentionally unchanged until explicit publication approval. No GitHub commit, push or Release is authorized by this audit alone.
