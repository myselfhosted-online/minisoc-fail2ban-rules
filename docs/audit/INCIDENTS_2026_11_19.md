# MiniSOC observed case — 19 November 2026 (CET)

Source: operator-provided Fail2Ban Telegram notifications. The full Nginx access log has not been independently reviewed. Synthetic test fixtures replace the observed public IP with documentation address 198.51.100.26 while preserving paths, timestamps, methods and statuses.

## Incident I — 10:16:14

- Reported IP: **35.195.20.89**, Google LLC AS396982, geolocated to Brussels, Belgium; cloud-provider ownership does not attribute the activity to Google.
- Two jail alerts: **nginx-skanery** (MEDIUM, generic-vulnerability-scan, ban at 10:16:17) and **nginx-dev-honeypot** (HIGH, backup ×1 and secret ×1, ban at 10:16:19).
- **12 request entries, 12 distinct raw paths, one correlated parent incident**, all within one second, all HTTP 404, with one browser-like partial User-Agent string.
- nginx-skanery sample: /config.yaml, /config.json, /credentials.yml, /credentials.json, /secrets.json, /secrets.yml.
- nginx-dev-honeypot sample: /database.sql, /site/.env, /backup.sql, /dump.sql, /env.js, /__ENV.js.

## Assessment and detection policy

The source enumerated configuration, credential, secret, database export and frontend runtime-environment filenames in a dense burst. Different jails covered **different requests**, so no event was duplicated across alerts. The overall incident receives investigative HIGH severity based on the high-confidence SQL dump and .env targets, not merely generic config filenames.

Existing scoped draft rules already detect the exact root SQL filenames and the /site/.env family; no change to active one-hit filters is required by this evidence. New /secrets.json, /secrets.yml, /env.js and /__ENV.js variants are **REVIEW-only** pending context: frontend env.js files can be intentionally public. A potential future multi-category same-source burst score must be diagnostic until false-positive rates and production logging are tested.

No returned HTTP 200/206 appears among these twelve requests. HTTP 404 does not prove that all possible related endpoints are secure, only that the shown requests did not return the target files. Do not use ASN or a self-reported User-Agent for attribution. No production installation or GitHub publication was performed.

## Incident II — 16:46:39–16:46:41

- Reported IP: **20.199.182.84**, Microsoft Corporation AS8075, geolocated to Zurich, Switzerland. Provider ownership is not actor attribution.
- One **nginx-skanery** alert, MEDIUM, WordPress ×4.
- **6 displayed entries, 6 distinct request targets, 6 unique HTTP events**, all HTTP 404, no declared User-Agent.
- Paths: `/wp-content/plugins/hellopress/wp_filemanager.php`, `/wp-xserver.php?p=`, `/wp-content/uploads/`, `//wp-includes/l10n/`, `/wp-load.php`, `/wp-admin/css/colors/modern/`.
- `/wp-xserver.php?p=` is a review-only PHP anomaly; a single request for `/wp-load.php` or `/wp-content/uploads/` is insufficient for a ban because legitimate WordPress deployments may expose those paths.

## Incident III — 19:39:51–19:39:54

- Reported IP: **77.90.185.239**, Limited Network LTD AS213790, geolocated to Vilnius, Lithuania.
- Two overlapping jail notifications, **nginx-dev-honeypot** and **nginx-skanery**, each HIGH for secret ×4.
- **12 displayed entries across the two notifications, but only 6 unique HTTP events and 6 distinct paths** after deduplication by IP, timestamp, HTTP method, raw target and HTTP status. All HTTP 404.
- Both jail notifications repeat the same six requests: `/site.zip`, `/.env`, `/dev/.env`, `/backend/.env`, `/sendgrid.env` and `/laravel/.env`.
- The User-Agent claims a very old Chrome release on Windows XP, which is caller-controlled and does not establish a genuine browser identity.
- `/site.zip` and `/sendgrid.env` were added as **REVIEW-only** candidates; generic archive probing should not become a one-hit ban without context.

## Full 19 November tally and caveats

Across three distinct source incidents: **5 jail alerts, 30 displayed log entries and 24 unique HTTP events / raw request targets**, all HTTP 404. The original Nginx access log was not available for verification. These are counts of the alerts that were supplied, not total server traffic. No production changes or publication occurred.
