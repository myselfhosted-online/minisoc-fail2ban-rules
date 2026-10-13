# 2026-10-13 — Cloud/container secret discovery

**Source:** 35.240.58.49  
**Observed jail:** nginx-dev-honeypot  
**Classification:** Automated vulnerability scanner  
**Severity:** HIGH

Observed paths:

```text
/.env
/.docker/config.json
/.docker/.env
/.aws/credentials.bak
/.aws/config
/.env-sample
```

Behavioral interpretation:

- dotenv/secret discovery;
- Docker credential/config discovery;
- AWS credential-backup discovery;
- cloud configuration discovery.

This source had previously appeared in similar environment/config discovery traffic, so it can be treated as a repeat offender for local correlation. ASN ownership is context only.
