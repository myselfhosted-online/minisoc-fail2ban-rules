# MiniSOC observed cases — 18 November 2026 (CET)

Source: operator-provided Telegram Fail2Ban alerts. Evidence has not been independently verified against full Nginx access logs. The test fixture uses reserved documentation IPs while preserving request targets, statuses and seconds (except display escaping noted under incident F). Recorded HTTP responses were **404 or 401**; none demonstrate successful file disclosure.

## Incident A — 02:20:22–02:20:25

- Source as reported: **20.87.218.237**, Microsoft AS8075 (Johannesburg IP geolocation; not attribution of attacker).
- One jail alert: nginx-skanery / MEDIUM / wordpress ×4.
- **6 sampled requests, 6 distinct raw paths**, all HTTP 404, User-Agent omitted.
- Paths: /wp-content/plugins/hellopress/wp_filemanager.php, /wp-includes/js/tinymce/index.php?p=, /wp-filemannger.php, /wp-gans.php, /wp-admin/css/about.php, /wp-admin/maint/wp-login.php.
- Assessment: WordPress PHP/file-manager enumeration; several paths resemble webshell or compromised-plugin probes. Add names to *review* candidates, not proof that WordPress is installed or compromised. Signature count 4 is not the total-request count 6.

## Incident B — 02:30:12–02:30:25

- Source as reported: **45.138.12.35**, TC DATACENTER LIMITED AS218785 (Warsaw IP geolocation; not attribution).
- One jail alert: nginx-skanery / HIGH / secret ×2, wordpress ×1.
- **6 sampled requests, 6 distinct raw paths**, all HTTP 404, uniform browser-like User-Agent.
- Paths: /wp-login.php, /backend/.env, /backend/%2eenv, /backend/%252eenv, /backend/.%65nv, /backend/./.env.
- Assessment: **five raw variants of one logical /backend/.env target**. %2e denotes encoded dot, %252e a double-encoded dot, .%65nv an encoded letter, and /./ a dot segment. This is obfuscation/normalization evasion, **not in itself directory traversal**. The *raw* request paths are never replaced by canonicalized paths for enforcement; only exact, narrow encoded variants become draft active indicators. Correlator separately reports diagnostic canonical variants.

## Incident C — 04:23:58–04:23:59

- Source as reported: **34.77.109.125**, Google LLC AS396982 (Belgium IP geolocation; not attribution).
- **2 jail alerts** (nginx-skanery, nginx-dev-honeypot) representing **6 distinct HTTP requests** repeated in both notifications.
- **12 requests displayed across the two jail alerts, 6 deduplicated request events, 6 distinct raw paths**; all HTTP 404.
- Paths: /.circleci/config.yml, /database.sql, /backup.sql, /dump.sql, /api/v1/namespaces/default/secrets, /.env.production.backup.
- Assessment: SQL dump/backup discovery + CI configuration and Kubernetes API secret enumeration. Exact root SQL filenames become scoped draft detection indicators for active filters; the CI file and Kubernetes endpoint remain review-only because they can have legitimate contexts. .env.production.backup was covered by the existing .env family.

## Correlation and heuristics

Morning subset (02:20–04:24): **4 raw jail alerts → 3 parent incidents → 24 sampled request entries → 18 deduplicated HTTP events → 18 distinct raw paths.** This only describes the requests shown in operator alerts, **not all Nginx traffic**.

The diagnostic tool now separately exposes (a) requests printed in alerts, (b) deduplicated events, (c) distinct raw URL paths, (d) sets of syntactically different paths with the same decoded diagnostic path, and (e) HTTP status changes for the same IP and raw path inside a short window. Neither normalization nor status changes are standalone banning conditions.

## Rollout gate

Do not attribute these requests to Microsoft or Google as organizations operating scanners based solely on network ownership. Do not make a GitHub release or touch production based on these alerts. Run real Fail2Ban parser tests and review existing Debian jail/filter integration before promotion.

## Incident D — 14:48:48–14:48:52

- Reported source **34.147.165.189**, Google LLC AS396982 (UK geolocation). Three jails: nginx-skanery, nginx-highconf and nginx-fake-searchbots.
- **3 jail alerts / 18 distinct request events / 18 raw paths / HTTP 401 ×18**, all within five seconds.
- High-confidence probes: /.streamlit/secrets.toml, /userfiles?path=../../../.env, /userfiles/x?path=../../.env, /cache/original/%2e%2e/.env, /project/.env, /api/v1/.env, /services/.env, /client/.env, /.env.secret, /.env.keys, /.env.prod.local.
- Other configuration paths include /instance/config.py, /config/settings.py, /backend/settings.py, /supabase/config.toml, /.turbo/config.json and /.changeset/config.json. One /admin/ request by itself is not an indication of exploitation.
- Assessment: query-parameter traversal to .env and encoded dot-segment traversal are strong evidence of automated probing. User-Agent values rotated among unrelated purported crawlers, but are unauthenticated strings and must not be used for attribution.

## Incident E — 16:02:14–16:02:17

- Reported source **34.145.216.121**, Google LLC AS396982 (US geolocation). Three jails: nginx-highconf, nginx-skanery and nginx-fake-searchbots.
- **3 jail alerts / 18 distinct request events / 18 raw paths / HTTP 401 ×18**, all within four seconds.
- Raw encoded / unusual variants: /settings%2F.env, /api%2F.env, /laravel../.env, /static../.env, /static//app/.env, /.//.env and /.git/config%3F.css.
- Additional targets: /app/service-account.json, /docker/.env, /config.env, various .env backups and /admin/config.json. Generic /runtime-config.js and /app-config.json are context-dependent; they remain review-only.
- Assessment: environment and repository reconnaissance with encoded separators and encoded question-mark lookalikes. Encoded slash probes are *not automatically* evidence of parent-directory traversal. User-Agent values cannot authenticate any crawler identity.

## 18 November alert sample before the evening update (historical subtotal)

**10 jail alerts → 5 parent incidents → 60 request entries displayed in alerts → 54 deduplicated HTTP events → 54 raw paths counted per parent incident.**

- HTTP **404 ×18**, **401 ×36** in the distinct events shown.
- Three Morning incidents: 18 distinct events, including a 6-request event repeated in two jails.
- Two Afternoon incidents: 36 distinct events, no duplicate HTTP request events across the three jails per source.
- All figures describe only the requests included in operator alerts. The underlying Nginx logs might contain more.

The 18 November afternoon JSON fixture replaces both cloud addresses with documentation IPs. High-confidence new exact indicators can be tested offline, while context-dependent configuration paths are kept in the non-blocking review catalog. No installation or publication is authorized.

## Incident F — 18:37:31 (three jail notifications until 18:37:37)

- Reported source **34.146.57.92**, Google LLC AS396982 (Tokyo IP geolocation, no organizational attribution).
- Three alerts: nginx-highconf, nginx-skanery and nginx-fake-searchbots, each listing six HTTP 401 requests.
- **18 displayed entries, only 9 distinct observed requests/paths.** The first six paths are duplicated by the first two jails; three of those appear once more in the third jail, which also contains three new requests.
- Notable requests: `/api/system/fileView?file=/app/.env`, `/api/fs/read?allowOutsideWorkspace=true&amp;path=/app/.env`, `/api/console/api_server?sense_version=%40%40SENSE_VERSION&amp;apis=../../../../../../.env`, `/laravel/.env`, `/.env.php.bak`, `/configuration.php.bak`, `/wp-config.old`, `/storage/.env`, `/wp/.env`.
- Classification: potential API file-read abuse, traversal using a query parameter and environment / configuration backup discovery. **The text provided by Telegram includes literal `&amp;`**, which may be escaped HTML rather than the raw Nginx request delimiter. The fixture faithfully retains the text as shown; verify raw access logs before adding an exact blocking query rule. Candidates are review-only.

## Incident G — 19:59:08–19:59:12

- Reported source **34.148.107.198**, Google LLC AS396982 (US South Carolina IP geolocation).
- Three alerts: nginx-skanery, nginx-highconf and nginx-fake-searchbots.
- **18 displayed entries, 18 distinct requests/paths**, all HTTP 401. No inter-jail duplicated events were present in this sample.
- Targets span `/.env.supabase`, `/admin/config.json`, `/static//app/.env`, `/static../.env`, `/media../.env`, `/.turbo/config.json`, `/prisma/.env`, `/.env.shared`, `/.env.common`, `/api/.env/public/.env`, `/.env.monorepo`, `/api/console/api_server?...`, `/.env.old`, `/.env.save`, `/.env.prod`, `/admin/.env`, `/api/.env` and `/backend/.env`.
- Classification: secret enumeration with mixed normal, double-slash, adjacent-dot and query-traversal shapes. One API-console target recurs in Incident F, **but from a different IP at a different time**, so it must not be deduplicated between the two parent incidents.

## Incident H — 22:19:01–22:19:06

- Reported source **40.123.240.128**, Microsoft AS8075 (Johannesburg IP geolocation).
- One nginx-skanery alert; **6 displayed entries, 6 distinct paths**, all HTTP 404 and without User-Agent.
- Targets: `/wp-content/plugins/hellopress/wp_filemanager.php`, `/wp-optimizer.php`, `/wp-Iogin.php`, `/wp-devirot.php`, `/wp-devirus.php`, `/config.php?`.
- Classification: repeated WordPress PHP filename probing resembling earlier Azure batches. The `I` in `wp-Iogin.php` is an uppercase i (not the lowercase l in `wp-login.php`); keep this evidence literal. New patterns are review-only; no proof of an installed WordPress or successful access.

## Complete 18 November alert sample (including evening)

**17 jail alerts → 8 parent incidents → 102 request entries displayed in alerts → 87 deduplicated HTTP events → 87 distinct raw request targets counted within incidents.**

- Unique-event HTTP statuses: **401 ×63** and **404 ×24**.
- Evening subset alone: **7 jail alerts → 3 parent incidents → 42 displayed entries → 33 distinct events/targets** (401 ×27, 404 ×6).
- The "unique paths" metric is counted *within each parent incident*, and then summed. This is **not** the number of unique path strings across every incident, since multiple sources can probe the same path.
- Jail alerts are samples rather than complete Nginx logs; the incident total and status distribution may differ from the complete server traffic.
- Rotating User-Agent strings impersonating multiple crawler brands are an indication of automated spoofing, **not evidence that those companies scanned the server**.
- All new file-read API, trailing-question-mark, configuration-backup and WordPress lookalike candidates remain **non-blocking, review-only** pending raw-log confirmation and operator approval.
