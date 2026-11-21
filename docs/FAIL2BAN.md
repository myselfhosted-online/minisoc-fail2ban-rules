# Using the rules with Fail2Ban

This repository ships production-oriented Fail2Ban filters for Nginx access logs.

## Requirements

- Linux with Fail2Ban installed
- Nginx access log in a standard combined-style format
- root privileges for installation
- default log path: `/var/log/nginx/access.log`

Check that Fail2Ban is running:

```bash
sudo systemctl status fail2ban --no-pager
sudo fail2ban-client status
```

## Recommended installation

Clone the repository:

```bash
git clone https://github.com/myselfhosted-online/minisoc-fail2ban-rules.git
cd minisoc-fail2ban-rules
```

Install the project filters and jail definitions:

```bash
sudo bash ./install/install.sh
```

The installer:

1. creates a backup of project-managed Fail2Ban files;
2. installs the filters into `/etc/fail2ban/filter.d/`;
3. installs the jail configuration into `/etc/fail2ban/jail.d/minisoc-fail2ban.local`;
4. runs `fail2ban-client -t`;
5. reloads Fail2Ban only if the configuration is valid.

## Custom Nginx access log

If your access log is not `/var/log/nginx/access.log`:

```bash
sudo NGINX_LOG=/path/to/access.log bash ./install/install.sh
```

Example:

```bash
sudo NGINX_LOG=/var/log/nginx/terminal.access.log bash ./install/install.sh
```

## Verify the installation

Validate the complete Fail2Ban configuration:

```bash
sudo fail2ban-client -t
```

Show all active jails:

```bash
sudo fail2ban-client status
```

Check the scanner jail:

```bash
sudo fail2ban-client status nginx-skanery
```

Check the development/secret-discovery jail:

```bash
sudo fail2ban-client status nginx-dev-honeypot
```

Expected output should show the jail as active and include counters such as currently failed, total failed, currently banned, and total banned.

## Test the filters against your Nginx log

```bash
sudo bash ./install/test.sh
```

Or test a specific log:

```bash
sudo bash ./install/test.sh /var/log/nginx/terminal.access.log
```

For direct troubleshooting with Fail2Ban:

```bash
sudo fail2ban-regex /var/log/nginx/access.log /etc/fail2ban/filter.d/nginx-skanery.conf
sudo fail2ban-regex /var/log/nginx/access.log /etc/fail2ban/filter.d/nginx-dev-honeypot.conf
```

## What each jail is for

### nginx-skanery

High-confidence vulnerability and webshell hunting, including examples such as:

- `/.git/config`
- `/.git-credentials`
- `/.env`
- AWS credential paths
- Docker credential/config paths
- exact WordPress webshell/backdoor paths observed in real traffic

### nginx-dev-honeypot

High-confidence secret and developer-environment discovery, including examples such as:

- dotenv files
- AWS credentials/config
- Docker configuration
- developer credential paths

These rules are intentionally narrower than generic "bad bot" filters.

## Important: do not ban on metadata alone

The project does not recommend banning based only on:

- ASN
- cloud provider
- country
- empty User-Agent
- crawler-looking User-Agent

Request behavior is the primary signal.

## Manual installation

If you do not want to use the installer:

```bash
sudo cp fail2ban/filter.d/nginx-skanery.conf /etc/fail2ban/filter.d/
sudo cp fail2ban/filter.d/nginx-dev-honeypot.conf /etc/fail2ban/filter.d/
sudo cp fail2ban/jail.d/minisoc-fail2ban.local.example /etc/fail2ban/jail.d/minisoc-fail2ban.local
sudo fail2ban-client -t
sudo fail2ban-client reload
```

Before reloading, edit the jail file if your Nginx log path differs:

```bash
sudo nano /etc/fail2ban/jail.d/minisoc-fail2ban.local
```

## Adjust ban policy

The example currently uses:

```ini
findtime = 300
maxretry = 1
bantime = 3600
```

That means one high-confidence match within the five-minute window is enough to ban the source for one hour.

Change these values to fit your environment. Always test after editing:

```bash
sudo fail2ban-client -t && sudo fail2ban-client reload
```

## Unban an address

```bash
sudo fail2ban-client set nginx-skanery unbanip 203.0.113.10
```

or:

```bash
sudo fail2ban-client set nginx-dev-honeypot unbanip 203.0.113.10
```

## Watch bans live

```bash
sudo journalctl -u fail2ban -f
```

On systems using a dedicated Fail2Ban log:

```bash
sudo tail -f /var/log/fail2ban.log
```

## Safely updating the rules (v1.3.1 and later)

Download and extract the official Release ZIP/tar.gz, or update an existing cloned checkout with `git pull`. From the top-level directory, preview the update first:

```bash
sudo bash ./install/install.sh --dry-run
```

If the preview contains no conflicts, apply and verify:

```bash
sudo bash ./install/install.sh
sudo fail2ban-client -t
sudo fail2ban-client status
```

The updater:

1. checks for local filter overrides and unknown versions before modifying files;
2. preserves existing jail settings such as `bantime`, `maxretry`, and `logpath`;
3. merges filters conservatively against bundled v1.2.1/v1.3.0/v1.3.1/v1.3.2 baselines; conflicting local changes require manual review;
4. merges `/etc/minisoc/signatures-v2.db` by signature ID, preserving custom entries and rejecting conflicting IDs;
5. creates root-protected backups under `/etc/fail2ban/minisoc-backup-*`;
6. validates and reloads Fail2Ban, restoring files and attempting to reload the previous configuration if an update fails.

If MiniSOC is not installed, its signature update is skipped. Set `MINISOC_SIGNATURES=/absolute/path` to specify a different database or `MINISOC_REQUIRED=1` to require it. The installer does **not** restart MiniSOC; if its classification engine caches the database, it needs a separate reload.

A safe update cannot automatically resolve all user-modified regexes. On conflict, **do not force an overwrite**: review the local rule and reconcile it with the new upstream filter.

### Customized filter compatibility (v1.3.3)

Version 1.3.2 incorrectly required an exact `.git` regex fragment to recognize modified filters, even though equivalent custom regex spellings are legitimate. Version 1.3.3 tries verified three-way merges without that fingerprint, but it never guesses a baseline when local modifications conflict with the upstream regex. It also recognizes an exact v1.3.2 filter as a known source.

For unrecognized custom filters, `--dry-run` reports `WARNING PRESERVED` and explicitly warns that the latest bundled filter rules would **not** be activated. No live file changes occur. A normal installation fails closed until an operator chooses one of two paths:

1. Manually review and merge the custom filter with the new upstream regex, test it using `fail2ban-regex` and `fail2ban-client -t`, and continue managing that custom filter separately (future installer runs may still require the explicit preservation flag); or
2. Explicitly allow a **partial** update, preserving the custom filter byte-for-byte while updating only other managed components:

```bash
sudo bash ./install/install.sh --dry-run --preserve-custom-filters
sudo bash ./install/install.sh --preserve-custom-filters
```

The second option does **not** install the latest bundled filter rules into any preserved custom filter. Backup and automatic rollback cover only the files listed in the update plan. Existing jail settings and filters are never silently replaced.

### Inspect or restore a saved backup (v1.3.2)

The backup manifest records the original file hashes, ownership and modes. Inspect the selected backup before attempting restoration:

```bash
sudo python3 install/restore_backup.py /etc/fail2ban/minisoc-backup-YYYYMMDDTHHMMSSZ-PID --dry-run
```

To restore the specific backup after reviewing its plan, omit `--dry-run`. Restoration refuses to overwrite a file whose contents changed since the backup, and it tests/reloads Fail2Ban with rollback on failure. Run it locally with a console or out-of-band recovery option available. Backup paths under `/etc/fail2ban` are examples; use the exact path printed by the updater.

## Uninstall

```bash
sudo bash ./install/uninstall.sh --dry-run
sudo bash ./install/uninstall.sh
```

The v1.3.2 fail-closed uninstaller removes only files identical to recognized project baselines or the currently bundled versions. Customized filters, local overrides and modified jail files cause the entire operation to stop for manual review. Before deleting project-owned files it creates a backup, and after removal it validates/reloads Fail2Ban; failure triggers automatic restoration. It intentionally preserves the MiniSOC signature database.

## Before using in production

Review the regexes and jail policy for your log format and environment. Run `fail2ban-regex` against historical logs and check benign traffic before enabling one-hit bans.
