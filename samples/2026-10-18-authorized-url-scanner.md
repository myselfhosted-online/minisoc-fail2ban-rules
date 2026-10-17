# 2026-10-18 — User-initiated URL scanner / agent-readiness checks

These requests were observed immediately after the operator submitted the site to Cloudflare Radar URL Scanner.

They are retained as **false-positive / authorized-scan regression cases**, not as malicious samples.

Representative requests:

```text
GET /.well-known/openid-configuration
User-Agent: Mozilla/5.0 (compatible; AgentReadinessScanner/1.0; +https://isitagentready.com)

GET /dev/injector%20php
User-Agent: urlscan-secret-watcher/1.0 (research; contact: local)
```

Policy:

- `/.well-known/openid-configuration` with the agent-readiness scanner is SAFE_DISCOVERY / INFO.
- exploit-looking research probes are TRUSTED_ONLY: suppress enforcement only when independently correlated with a user-initiated/authorized scan.
- do not permanently whitelist transient Cloudflare, cloud, or residential IPs.
- a benign-scanner rule never overrides HIGH-confidence malicious behavior such as credential discovery or known webshell paths.
