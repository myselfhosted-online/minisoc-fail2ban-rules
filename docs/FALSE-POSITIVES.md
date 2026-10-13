# False-positive policy

The project intentionally separates **high-confidence blocking rules** from **context and correlation signals**.

## Never ban on these alone

- ASN or cloud provider;
- country or region;
- empty User-Agent;
- crawler-looking User-Agent;
- generic `/wp-login.php`, `/wp-admin/`, or `/wp-json/` access;
- generic framework assets.

## Promotion rule

A broad pattern should first be used for correlation. Promote it to a one-hit blocking rule only when there is strong evidence, benign regression coverage, and low false-positive risk.

Exact malicious paths are preferred over sweeping families such as `/wp-*.php`.
