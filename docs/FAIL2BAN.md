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

## Updating the rules

```bash
cd minisoc-fail2ban-rules
git pull
sudo bash ./install/install.sh
sudo fail2ban-client status
```

The installer validates the configuration before reloading Fail2Ban.

## Uninstall

```bash
sudo bash ./install/uninstall.sh
```

The uninstall helper removes only files managed by this project, validates the remaining Fail2Ban configuration, and reloads the service.

## Before using in production

Review the regexes and jail policy for your log format and environment. Run `fail2ban-regex` against historical logs and check benign traffic before enabling one-hit bans.
