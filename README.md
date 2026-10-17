# MiniSOC Fail2Ban Rules

Real-world Fail2Ban filters, MiniSOC detection signatures, samples, and operational guidance for detecting automated vulnerability scanners, secret discovery, repository disclosure, WordPress webshell hunting, and abusive reconnaissance.

> **Behavior is the indicator. IP ownership is context.**

This project is built from **real hostile HTTP traffic observed on a live home/homelab server** operated at [terminal.myselfhosted.online](https://terminal.myselfhosted.online/). Events are detected by Nginx/Fail2Ban and MiniSOC, reviewed, correlated, and—when appropriate—reported to AbuseIPDB through the operator profile: [AbuseIPDB user 200671](https://www.abuseipdb.com/user/200671).

The repository intentionally focuses on request behavior rather than blaming network owners. A source IP being hosted by Microsoft, Google, Oracle, DigitalOcean, or another provider does **not** mean that provider performed or authorized the scan.

## What this repository contains

- production-oriented Fail2Ban filters for high-confidence HTTP probes;
- MiniSOC-style behavioral signatures and severity guidance;
- real-world samples captured by the homelab, with secrets and private data removed;
- multi-jail correlation and repeat-offender methodology;
- installation, validation, and rollback scripts;
- GitHub Actions validation;
- documentation for false-positive handling and authorized security scanners.

## Detection philosophy

The rules favor high-confidence behavior such as:

- `.env` and environment-secret discovery;
- AWS, Docker, cloud and credential-file discovery;
- `.git/config`, `.git-credentials` and repository disclosure;
- exact known WordPress webshell/backdoor paths;
- webshell/file-manager hunting;
- exploit or secret probes using crawler-looking user agents.

The following are **not** sufficient on their own for a HIGH classification:

- ASN, cloud provider or country;
- an empty User-Agent;
- a crawler-looking User-Agent;
- generic `/wp-login.php`, `/wp-admin/` or `/wp-json/` reconnaissance;
- a single generic framework asset request.

## Data flow

```text
Internet
   |
   v
Nginx access logs
   |
   +--> Fail2Ban --------------------> temporary ban
   |
   +--> MiniSOC
          |
          +--> signature classification
          +--> severity
          +--> incident correlation
          +--> repeat-offender tracking
          +--> operator alert
          |
          +--> AbuseIPDB report when appropriate
          |
          +--> sanitized public sample / rule candidate
```

Raw alerts from multiple jails can refer to the same burst. The project therefore separates **raw alerts** from **parent incidents** and correlates overlapping requests from the same source within a short time window.

## Using these rules with Fail2Ban

For the full installation, verification, troubleshooting, update, unban, and uninstall procedure, see **[docs/FAIL2BAN.md](docs/FAIL2BAN.md)**.

The short version is:

```bash
git clone https://github.com/myselfhosted-online/minisoc-fail2ban-rules.git
cd minisoc-fail2ban-rules
sudo bash ./install/install.sh
sudo fail2ban-client -t
sudo fail2ban-client status
sudo fail2ban-client status nginx-skanery
sudo fail2ban-client status nginx-dev-honeypot
```

## Quick install

Debian/Ubuntu with Nginx and Fail2Ban:

```bash
git clone https://github.com/myselfhosted-online/minisoc-fail2ban-rules.git
cd minisoc-fail2ban-rules
sudo bash ./install/install.sh
sudo bash ./install/test.sh
```

Custom Nginx access log:

```bash
sudo NGINX_LOG=/path/to/access.log bash ./install/install.sh
```

The installer creates backups before touching existing project-managed files, validates Fail2Ban configuration, and rolls back if validation fails.

## Repository layout

```text
fail2ban/
  filter.d/          Fail2Ban filters
  jail.d/            example jail configuration
install/             install, test and uninstall helpers
rules/               MiniSOC-style signature database
samples/             reviewed real-world samples
scripts/             validation tools
tests/fixtures/      benign and malicious regression fixtures
docs/                methodology and policy documentation
.github/workflows/   CI validation
```

## Severity

| Level | Meaning |
|---|---|
| HIGH | Strong evidence of secret discovery, credential theft preparation, repository disclosure, exploit probing, or known webshell/backdoor hunting |
| MEDIUM | Suspicious reconnaissance that needs context or correlation |
| INFO | Context-only signal; never enough for a ban by itself |

When multiple signatures match one incident, the incident severity should be the **maximum matched severity**, unless an explicit authorization policy overrides enforcement.

## Authorized scanners

An internal or authorized security scanner should still match the same behavioral signatures. Authorization is a separate policy layer.

Do **not** trust a User-Agent string as authorization. Prefer authenticated markers, mTLS, a dedicated egress IP, or another verifiable mechanism. Authorized scans may remain visible in MiniSOC while suppressing Fail2Ban and AbuseIPDB reporting.

## Real-world samples

The samples in this repository come from actual internet traffic hitting the operator's homelab. They may contain real source IP addresses and exact malicious request paths when those details are relevant to detection research. Secrets, authentication material, private application data, and unrelated personal information must never be published.

See [docs/DATA-SOURCES.md](docs/DATA-SOURCES.md), [docs/METHODOLOGY.md](docs/METHODOLOGY.md), and [docs/BENIGN-SCANNERS.md](docs/BENIGN-SCANNERS.md).

## False positives

High-confidence rules are intentionally narrow. Broad pattern families are used for correlation before they are promoted to one-hit blocking rules.

If a legitimate request is matched, open an issue with:

1. the filter/signature ID;
2. the request path;
3. the relevant log format;
4. why the request is legitimate;
5. sensitive values removed.

## Responsible use

These rules are defensive. They are intended for administrators protecting systems they own or are authorized to operate.

## Releases

Releases are automated from the root `VERSION` file. Changing `VERSION` on `main` triggers validation, creates a `vX.Y.Z` tag, packages ZIP and tar.gz archives, generates SHA-256 checksums, and publishes a GitHub Release.

See **[docs/RELEASING.md](docs/RELEASING.md)**.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).

---

Project: **myselfhosted.online**  
Homelab endpoint: [terminal.myselfhosted.online](https://terminal.myselfhosted.online/)  
AbuseIPDB reports: [user 200671](https://www.abuseipdb.com/user/200671)
