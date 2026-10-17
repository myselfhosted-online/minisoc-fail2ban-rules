# Benign and research scanners

The project blocks **malicious behavior**, not scanners merely because they identify themselves as scanners.

## Policy

There are two classes of exceptions:

### SAFE_DISCOVERY

A request is inherently low-risk/standards-oriented and should be logged as INFO rather than banned.

Current example:

```text
GET /.well-known/openid-configuration
User-Agent: AgentReadinessScanner/1.0
```

This is standards/agent-readiness discovery. A 404 response is not evidence of abuse.

### TRUSTED_ONLY

Some research scanners deliberately probe suspicious-looking paths. Those requests must **not** be globally whitelisted by User-Agent, because User-Agent text is spoofable.

Current example:

```text
GET /dev/injector%20php
User-Agent: urlscan-secret-watcher/1.0
```

This pattern was observed during a user-initiated URL scan. Enforcement may be suppressed only when the request is independently correlated with an authorized scan using a trusted marker/session/IP/mTLS or other verifiable signal.

## Precedence

A benign/research scanner rule must never override a HIGH-confidence malicious signature.

Examples that remain blockable even if the User-Agent claims to be a scanner:

- `/.env`
- `/.git/config`
- `/.git-credentials`
- AWS/Docker/cloud credential paths
- exact known WordPress webshell/backdoor paths

## Source IPs

Do not permanently whitelist transient Cloudflare, cloud-provider, residential, or research-scanner IPs solely because one authorized scan used them.

Behavior and verified authorization are the decision inputs.
