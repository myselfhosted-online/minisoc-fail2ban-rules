# MiniSOC observed case — 20 November 2026 (CET)

Evidence: operator-supplied Fail2Ban Telegram alert only. All synthetic fixtures use documentation addresses; the original Nginx access log and underlying server were not accessed.

## Incident — 09:40:12

- Reported IP: **34.77.109.125**, Google LLC AS396982, geolocated to Brussels, Belgium. Cloud-provider ownership does not attribute the scan to Google.
- Jail: **nginx-dev-honeypot**, HIGH, secret ×4; ban notification at 09:40:15.
- **6 displayed requests / 6 unique HTTP events / 6 unique request targets**, all HTTP 404.
- Targets: `/.docker/.env`, `/.aws/.env`, `/.env-example`, `/.docker/laravel/app/.env`, `/.env-sample` and `/.env.anthropic`.
- All six requests share a partial browser-like User-Agent value. This is not trustworthy identity evidence.

## Repeat source across dates

The same IP was recorded in a separate **18 November 04:23:58–04:23:59** incident: two jail alerts, six unique HTTP requests for CircleCI configuration, SQL dump names, a Kubernetes secrets API and a production env backup. The **20 November 09:40:12** incident comprises different request paths more than two days later. Source-IP recurrence is useful as a reporting enrichment, but **does not merge incidents across days** and does not independently increase ban severity. Cloud IP reuse must also be considered.

There were no successful HTTP 200/206 responses among the displayed requests. HTTP 404 for these paths is a reassuring observation, not proof that every secret file is inaccessible. Existing specific env rules already cover the high-confidence paths; no additional blocking regex is warranted from this sample alone. No GitHub release or Debian deployment was performed.
