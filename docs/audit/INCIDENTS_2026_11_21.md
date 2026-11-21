# MiniSOC observed case — 21 November 2026 (CET)

Evidence: operator-supplied Fail2Ban Telegram alerts; no direct access to the original Nginx log. Test fixtures use documentation IP 198.51.100.29 instead of the actual public address.

## Incident — 09:04:27

- Reported source: **23.251.141.4**, Google LLC AS396982, geolocated to Brussels, Belgium; this does not identify the actor controlling the host.
- Two jail notifications: **nginx-skanery** (ban 09:04:30) and **nginx-dev-honeypot** (ban 09:04:32). Both HIGH, secret ×4.
- Both alerts list the **same six HTTP requests**, at **09:04:27 CET**, all GET, all HTTP 404. Consequently **12 displayed alert entries = 6 unique events, 6 distinct request targets, one correlated parent incident**.
- Targets: `/.docker/.env`, `/.aws/.env`, `/.docker/laravel/app/.env`, `/.env-example`, `/.env-sample`, `/.env.anthropic`.
- The shared browser-like User-Agent is a claimed value and is not evidence of an actual Windows client.

## Repeat scanning template, not proven common actor

This is **the same set of six paths** seen in the separately reported **20 November 09:40:12** incident involving source **34.77.109.125**. Both sources are associated with Google-hosted address space in the operator-provided IP metadata, but IP geolocation and a matching scan template are **not sufficient to establish the same operator or campaign**. Keep the two events as distinct parent incidents; report matching path-set similarity only as an investigative lead.

No newly observed path requires a new active signature, since the existing specific env-file patterns cover these targets. These samples show no HTTP 200/206 response, but 404 on the displayed targets does not prove the entire application has no exposure. Do not use path-set similarity, ASN or User-Agent alone to trigger a ban. Neither GitHub publication nor production deployment was performed.
