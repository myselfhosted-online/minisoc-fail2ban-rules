# Data Sources

This project is grounded in real-world hostile HTTP traffic observed on the operator's home/homelab server:

- https://terminal.myselfhosted.online/
- public project owner: https://github.com/myselfhosted-online/
- AbuseIPDB reporting history: https://www.abuseipdb.com/user/200671

## Pipeline

Observed requests are processed through Nginx, Fail2Ban, and MiniSOC. High-confidence abusive sources may be reported to AbuseIPDB. Reviewed and sanitized incidents can then become public samples or rule candidates.

## Privacy

Public samples may preserve source IPs and malicious request paths when useful for defensive research, but must remove:

- credentials;
- API tokens;
- session identifiers;
- authorization headers;
- cookies;
- private query values;
- unrelated personal information.

## Attribution

Cloud ASN ownership is context only. A source IP located in a provider network does not imply that provider performed, approved, or controlled the scan.
