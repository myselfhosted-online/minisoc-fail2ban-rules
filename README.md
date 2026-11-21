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

## Safe updates (v1.3.1 and later)

For existing installations, review the plan before applying it:

```bash
sudo bash ./install/install.sh --dry-run
sudo bash ./install/install.sh
```

The update preserves existing jail settings, supports conservative merges of known previous filter versions, and merges MiniSOC signatures by ID. Conflicts stop the upgrade without overwriting custom rules. Backups are created before applying changes. The MiniSOC application itself is not restarted.

See [docs/FAIL2BAN.md](docs/FAIL2BAN.md) and [v1.3.4 candidate notes](docs/releases/v1.3.4.md).

### Incompatible local signature databases (v1.3.4 candidate)

The v1.3.3 updater could abort even in `--dry-run` while compiling an existing, operator-maintained `/etc/minisoc/signatures-v2.db` regex using Python. A failed validation does **not** prove the live MiniSOC service is broken, nor should the installer rewrite local rules to make them pass. This update distinguishes local incompatibility from an invalid release signature database.

The dry run reports `WARNING PRESERVED` and the location of the local parsing problem without changing files. An ordinary installation still refuses to proceed. If manual review confirms that the local MiniSOC database must remain untouched, explicitly permit a **partial** update:

```bash
sudo bash ./install/install.sh --dry-run --preserve-custom-filters --preserve-custom-signatures
sudo bash ./install/install.sh --preserve-custom-filters --preserve-custom-signatures
```

Only use the preservation flags for components actually reported as incompatible. Preserved local filters and signatures are not upgraded, and the MiniSOC application is not restarted. Before enabling any update, investigate the invalid regex with the operator who maintains that database. Existing signature ID collisions remain fatal and cannot be bypassed.

### Fix for customized filters in v1.3.3

The v1.3.2 updater could mistake a customized but valid filter for an unsupported version because it required one literal `.git` regex spelling. Version 1.3.3 removes this fingerprint test. It attempts only conflict-free, unambiguous three-way merges against known upstream baselines, and **never** silently replaces an unrelated operator-maintained filter.

Preview the real outcome first:

```bash
sudo bash ./install/install.sh --dry-run
```

If the output says `WARNING PRESERVED`, the local filter is incompatible with an automatic merge. An ordinary installation will still stop before modifying files. To explicitly update other project-managed components while leaving the customized filter intact:

```bash
sudo bash ./install/install.sh --dry-run --preserve-custom-filters
sudo bash ./install/install.sh --preserve-custom-filters
```

**This is a partial update:** bundled v1.3.3 filter changes are *not* installed into a preserved custom filter. Review and migrate that filter separately; do not bypass the safeguard with a forced overwrite. Backups and rollback apply to files actually changed by the updater.

### Maintenance update in v1.3.2

Version 1.3.2 includes additional, conservative detection signatures, an audited uninstaller and a manual backup restoration utility. Run `--dry-run` first and inspect the plan, especially when local Fail2Ban filters or MiniSOC signature IDs have been customized.

For an already-created MiniSOC backup, first inspect it without making changes:

```bash
sudo python3 install/restore_backup.py /etc/fail2ban/minisoc-backup-YYYYMMDDTHHMMSSZ-PID --dry-run
```

The restore command verifies its manifest, original hashes, and expected installed-file state before making any changes. See [the Fail2Ban operating guide](docs/FAIL2BAN.md) and [the v1.3.2 release notes](docs/releases/v1.3.2.md). Publishing this release does not automatically deploy it on a Debian server.

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

## Support the project

If this project helps you manage your Fail2Ban rules, please consider giving the repository a ⭐ star on GitHub. It helps others discover the project.

You can also support ongoing development with a small Monero (XMR) donation. Every contribution is appreciated, but completely optional.

**Monero (XMR) address:**

```text
891i2HuM2Bg1Y54QfpphkCGZdhb3Mas8TZ3YUgGfH3MrRLiduKR2acsUWtcPxxhn72TF6fRd9WuTSDmt9m12DsanV725gQF
```

Please verify the full address before sending funds. Donations are voluntary and do not influence security recommendations or detection rules.

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
