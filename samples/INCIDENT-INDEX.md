# Curated incident index

This index summarizes reviewed real-world traffic observed by the myselfhosted.online homelab. ASN/provider names are context only.

| Date | Source | Family | Severity |
|---|---|---|---|
| 2026-09-21 | 34.140.103.186 | traversal + dotenv/config discovery | HIGH |
| 2026-09-23 | 34.14.73.98 | Vite/config/credentials/AWS discovery | HIGH |
| 2026-09-23 | 35.240.58.49 | env/config discovery | HIGH |
| 2026-09-26 | 213.209.159.133 | Git + encoded dotenv + credentials | HIGH |
| 2026-09-26 | 34.14.99.143 | Docker/Anthropic/GCP/AWS secret discovery | HIGH |
| 2026-09-29 | 138.2.69.249 | generic WordPress reconnaissance | MEDIUM |
| 2026-10-01 | 104.199.243.204 | traversal + secret discovery | HIGH |
| 2026-10-03 | 20.249.5.100 | WordPress webshell/backdoor hunting | HIGH |
| 2026-10-05 | 20.219.2.60 | WordPress color-scheme webshell paths | HIGH |
| 2026-10-07 | 94.26.106.175 | phpinfo reconnaissance | MEDIUM |
| 2026-10-10 | 45.148.10.32 | AWS/config credential discovery | HIGH |
| 2026-10-11 | 45.138.12.25 | Docker/AWS/dotenv discovery | HIGH |
| 2026-10-13 | 35.215.184.98 | Git + multi-environment dotenv discovery | HIGH |
| 2026-10-13 | 35.240.58.49 | Docker/AWS/dotenv discovery; repeat source | HIGH |
| 2026-10-13 | 20.211.27.190 | WordPress webshell hunting | HIGH |
| 2026-10-13 | 20.194.17.163 | WordPress webshell hunting | HIGH |
| 2026-10-13 | 185.220.101.154 | WordPress recon + suspicious /wp-content/wuhr9.php candidate; Tor exit context only | HIGH (contextual) |
| 2026-10-14 | 20.214.144.216 | HelloPress + repeated WordPress webshell/backdoor paths | HIGH |
| 2026-10-16 | 20.196.193.222 | HelloPress file-manager hunting + WordPress theme/config probes | HIGH |

## Authorized / benign regression cases

The following are retained separately from malicious incidents:

- 2026-10-18 — user-initiated Cloudflare Radar URL Scanner / agent-readiness checks;
- `/.well-known/openid-configuration` with `AgentReadinessScanner/1.0` -> SAFE_DISCOVERY / INFO;
- `/dev/injector%20php` with research scanner context -> TRUSTED_ONLY, requiring independently verified authorization.

See [2026-10-18-authorized-url-scanner.md](2026-10-18-authorized-url-scanner.md).

The full private MiniSOC dataset contains more telemetry than is appropriate to publish. Public samples are intentionally curated and sanitized.
