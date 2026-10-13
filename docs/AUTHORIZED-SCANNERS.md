# Authorized scanners

Detection and authorization are separate concerns.

An authorized internal scanner should still match behavioral signatures. The policy layer may then suppress enforcement while retaining telemetry.

## Do not trust User-Agent alone

A User-Agent is attacker-controlled text and is not authentication.

Prefer one or more of:

- dedicated scanner egress IP;
- mTLS;
- authenticated private marker;
- dedicated proxy path or network;
- another cryptographically or operationally verifiable signal.

Recommended handling:

```text
behavior match -> classify normally -> authorization check
                                  |
                                  +-> trusted: log/telemetry, no ban/report
                                  +-> untrusted: normal enforcement
```
