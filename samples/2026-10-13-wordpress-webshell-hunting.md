# 2026-10-13 — WordPress webshell hunting

Representative observed paths from multiple bursts:

```text
/wp-content/plugins/hellopress/wp_filemanager.php
/wp-content/admin.php
/wp-admin/js/index.php
/wp-css.php
/wp-fgban13jx3.php
/wp-blink.php
/wp-logis.php
/wp-trbacks.php
/wp-ss.php
```

These incidents were observed with empty User-Agent values in several cases. Empty User-Agent is not itself malicious; the classification comes from the request behavior and known/high-confidence exact paths.

The broad family `/wp-*.php` must not be treated as universally malicious because legitimate WordPress core files exist with that naming style.
