# Samples

This directory contains reviewed, sanitized real-world incidents from the myselfhosted.online homelab.

Samples are evidence, not policy. A public sample can justify a new signature candidate, but a blocking rule should still be evaluated for false positives and regression-tested.

## Required sanitization

Never publish:

- passwords;
- API tokens;
- cookies;
- Authorization headers;
- private application payloads;
- unrelated personal information.

Source IPs and malicious request paths may be retained where they are materially useful for defensive research.
