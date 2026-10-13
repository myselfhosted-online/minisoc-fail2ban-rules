# Detection Methodology

## Core principle

> Behavior is the indicator. IP ownership is context.

## Parent incident correlation

Multiple Fail2Ban jails may fire on the same request burst. Raw alerts should be preserved, but statistics should count one parent incident when:

- the source IP is the same;
- timestamps overlap closely (typically within ~30 seconds);
- request sets overlap or clearly belong to one burst.

## Severity aggregation

If several signatures match one parent incident, the normal incident severity is the maximum severity among matched signatures.

## High-confidence behavior

Examples:

- dotenv and environment-secret discovery;
- AWS/Docker/cloud credential-file discovery;
- `.git/config` and related repository disclosure;
- exact WordPress webshell/backdoor paths;
- exploit or webshell hunting.

## Context-only signals

These must not become standalone ban reasons:

- ASN/provider/country;
- empty User-Agent;
- crawler-looking User-Agent;
- generic WordPress reconnaissance such as `/wp-login.php`, `/wp-admin/`, or `/wp-json/`.

## Authorized scanners

Detection and authorization are separate. An authorized scanner should still match behavior signatures. Enforcement can then be suppressed by a trusted policy layer using a verifiable mechanism such as mTLS, a dedicated egress address, or an authenticated marker.
