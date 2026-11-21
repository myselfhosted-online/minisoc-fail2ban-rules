#!/usr/bin/env python3
"""Offline, rootless regression suite for the MiniSOC safe updater."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("minisoc_safe_update", ROOT / "install/safe_update.py")
module = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = module
spec.loader.exec_module(module)

class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="minisoc-test-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.f2b = self.base / "f2b"
        self.db = self.base / "minisoc" / "signatures-v2.db"
        self.f2b.mkdir()
        self.db.parent.mkdir()
        self.bin = self.base / "bin"
        self.bin.mkdir()
        self.log = self.base / "calls.log"
        client = self.bin / "fail2ban-client"
        client.write_text('''#!/bin/sh
echo "$@" >> "$FAKE_LOG"
if [ "$1" = "-t" ] && [ -n "$FAKE_FAIL_ON_TEST" ]; then
  count=$(grep -c '^-t$' "$FAKE_LOG")
  [ "$count" -eq "$FAKE_FAIL_ON_TEST" ] && exit 17
fi
exit 0
''')
        client.chmod(0o755)
        env = {"F2B_ETC": str(self.f2b), "MINISOC_SIGNATURES": str(self.db),
               "FAKE_LOG": str(self.log), "PATH": str(self.bin) + os.pathsep + os.environ["PATH"]}
        self.patch_env = patch.dict(os.environ, env, clear=False)
        self.patch_env.start()
        self.addCleanup(self.patch_env.stop)
        self.patch_uid = patch.object(module.os, "geteuid", return_value=0)
        self.patch_uid.start()
        self.addCleanup(self.patch_uid.stop)

    def execute(self, dry_run=False, preserve_custom_filters=False, preserve_custom_signatures=False):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            module.run(dry_run, preserve_custom_filters, preserve_custom_signatures)
        return output.getvalue()

    def create_installed_filter(self, version="v1.3.0", filename="nginx-skanery.conf", suffix=b""):
        installed = self.f2b / "filter.d" / filename
        installed.parent.mkdir(parents=True, exist_ok=True)
        content = (ROOT / "install" / "baselines" / version / filename).read_bytes() + suffix
        installed.write_bytes(content)
        return installed

    def test_fresh_install_and_idempotency(self):
        result = self.execute()
        self.assertIn("SUCCESS", result)
        self.assertEqual(self.db.read_bytes(), (ROOT / "rules/signatures-v2.db").read_bytes())
        self.assertTrue((self.f2b / "jail.d" / "minisoc-fail2ban.local").is_file())
        self.assertIn("Already up to date", self.execute())
        self.assertEqual(self.log.read_text().splitlines().count("reload"), 1)

    def test_upgrade_from_121_keeps_custom_jail_and_custom_signatures(self):
        current = self.create_installed_filter("v1.2.1")
        other = self.create_installed_filter("v1.2.1", "nginx-dev-honeypot.conf")
        jail = self.f2b / "jail.d" / "minisoc-fail2ban.local"
        jail.parent.mkdir(exist_ok=True)
        jail.write_text("[nginx-skanery]\nmaxretry = 3\nbantime = 9000\n")
        existing = "# Local operator changes\noperator-custom|MEDIUM|operator|/operator-check(?:$|\\?)\n"
        self.db.write_text(existing)
        self.execute()
        self.assertEqual(current.read_bytes(), (ROOT / "fail2ban/filter.d/nginx-skanery.conf").read_bytes())
        self.assertEqual(other.read_bytes(), (ROOT / "fail2ban/filter.d/nginx-dev-honeypot.conf").read_bytes())
        self.assertEqual(jail.read_text(), "[nginx-skanery]\nmaxretry = 3\nbantime = 9000\n")
        self.assertIn(existing, self.db.read_text())
        self.assertIn("git-head|HIGH|repository", self.db.read_text())

    def test_custom_filter_comments_are_preserved(self):
        filter_path = self.create_installed_filter(suffix=b"\n# Custom security note\n")
        self.execute()
        self.assertIn("# Custom security note", filter_path.read_text())

    def test_version_132_baseline_is_recognized(self):
        filter_path = self.create_installed_filter(version="v1.3.2")
        self.execute()
        self.assertEqual(filter_path.read_bytes(), (ROOT / "fail2ban/filter.d/nginx-skanery.conf").read_bytes())

    def test_version_133_baseline_is_recognized(self):
        filter_path = self.create_installed_filter(version="v1.3.3")
        self.execute()
        self.assertEqual(filter_path.read_bytes(), (ROOT / "fail2ban/filter.d/nginx-skanery.conf").read_bytes())

    def test_git_not_required_for_exact_known_baseline(self):
        original = (ROOT / 'install/baselines/v1.3.2/nginx-skanery.conf').read_bytes()
        incoming = (ROOT / 'fail2ban/filter.d/nginx-skanery.conf').read_bytes()
        with patch.object(module.shutil, 'which', return_value=None):
            result, reason = module.filter_merge(original, incoming, 'nginx-skanery.conf')
        self.assertEqual(result, incoming)
        self.assertIn('already current', reason)

    def test_user_style_custom_regex_preserved_and_dry_run_reports_blocker(self):
        # Reproduces the Debian report without publishing the private filter.
        # The user's regex uses (config|HEAD), not the upstream (?:config|...) spelling.
        custom = (b'[Definition]\n'
                  b'failregex = ^<HOST> .*"(?:GET|POST) [^\"]*(?:/\\.git/(config|HEAD)|/\\.env) '
                  b'HTTP/[0-9.]+" (?:401|404)\\b\n'
                  b'ignoreregex =\n')
        installed = self.f2b / 'filter.d' / 'nginx-skanery.conf'
        installed.parent.mkdir(parents=True)
        installed.write_bytes(custom)
        dry_run = self.execute(dry_run=True)
        self.assertIn('WARNING PRESERVED', dry_run)
        self.assertIn('REQUIRES REVIEW', dry_run)
        self.assertIn('bundled v1.3.4 filter rules NOT activated', dry_run)
        with self.assertRaisesRegex(module.UpdateError, '--preserve-custom-filters'):
            self.execute()
        self.assertEqual(installed.read_bytes(), custom)
        self.assertFalse(self.log.exists())
        self.assertFalse((self.f2b / 'jail.d').exists())

        result = self.execute(preserve_custom_filters=True)
        self.assertIn('PARTIAL UPDATE', result)
        self.assertEqual(installed.read_bytes(), custom)
        self.assertEqual((self.f2b / 'filter.d' / 'nginx-dev-honeypot.conf').read_bytes(),
                         (ROOT / 'fail2ban/filter.d/nginx-dev-honeypot.conf').read_bytes())
        self.assertIn('reload', self.log.read_text())
        manifests = list(self.f2b.glob('minisoc-backup-*/manifest.json'))
        self.assertEqual(len(manifests), 1)
        changed_paths = [row['path'] for row in __import__('json').loads(manifests[0].read_text())['changes']]
        self.assertNotIn(str(installed), changed_paths)

    def test_partial_update_rollback_does_not_touch_custom_filter(self):
        custom = b'[Definition]\nfailregex = ^<HOST> .*unexpected-private-scanner HTTP/1\\.1\n'
        installed = self.f2b / 'filter.d' / 'nginx-skanery.conf'
        installed.parent.mkdir(parents=True)
        installed.write_bytes(custom)
        os.environ['FAKE_FAIL_ON_TEST'] = '2'
        self.addCleanup(os.environ.pop, 'FAKE_FAIL_ON_TEST', None)
        with self.assertRaisesRegex(module.UpdateError, 'restored automatically'):
            self.execute(preserve_custom_filters=True)
        self.assertEqual(installed.read_bytes(), custom)
        self.assertFalse((self.f2b / 'filter.d' / 'nginx-dev-honeypot.conf').exists())
        self.assertFalse(self.db.exists())

    def test_conflicting_filter_aborts_without_writes(self):
        filter_path = self.create_installed_filter("v1.2.1")
        content = filter_path.read_bytes().replace(b"GET|POST|HEAD", b"GET|POST")
        filter_path.write_bytes(content)
        with self.assertRaises(module.UpdateError):
            self.execute()
        self.assertEqual(filter_path.read_bytes(), content)
        self.assertFalse((self.f2b / "jail.d").exists())

    def test_conflicting_signature_id_aborts_without_writes(self):
        current = "git-head|MEDIUM|repository|/custom-path\n"
        self.db.write_text(current)
        with self.assertRaisesRegex(module.UpdateError, "git-head"):
            self.execute()
        self.assertEqual(self.db.read_text(), current)
        self.assertFalse((self.f2b / "filter.d").exists())

    def test_invalid_legacy_regex_is_reported_and_preserved(self):
        # Mirrors the production error: regex validation fails on line 1,
        # but changing this MiniSOC-owned database would be unsafe.
        legacy = b'operator-rule|HIGH|secret|^)bad-regex\n'
        self.db.write_bytes(legacy)
        output = self.execute(dry_run=True)
        self.assertIn('WARNING PRESERVED', output)
        self.assertIn('Invalid regex', output)
        self.assertIn('bundled v1.3.4 signatures NOT activated', output)
        self.assertIn('--preserve-custom-signatures', output)
        self.assertEqual(self.db.read_bytes(), legacy)
        self.assertFalse(self.log.exists())
        with self.assertRaisesRegex(module.UpdateError, '--preserve-custom-signatures'):
            self.execute()
        self.assertEqual(self.db.read_bytes(), legacy)
        self.assertFalse((self.f2b / 'filter.d').exists())

        output = self.execute(preserve_custom_signatures=True)
        self.assertIn('PARTIAL UPDATE: incompatible local signature database was preserved', output)
        self.assertEqual(self.db.read_bytes(), legacy)
        self.assertIn('reload', self.log.read_text())
        manifests = list(self.f2b.glob('minisoc-backup-*/manifest.json'))
        self.assertEqual(len(manifests), 1)
        changed_paths = [row['path'] for row in __import__('json').loads(manifests[0].read_text())['changes']]
        self.assertNotIn(str(self.db), changed_paths)

    def test_invalid_legacy_db_and_custom_filters_both_require_explicit_preservation(self):
        custom = b'[Definition]\nfailregex = ^<HOST> .*custom-test\n'
        path = self.f2b / 'filter.d/nginx-skanery.conf'
        path.parent.mkdir()
        path.write_bytes(custom)
        legacy = b'local-secret|HIGH|secret|^)broken\n'
        self.db.write_bytes(legacy)
        plan = self.execute(dry_run=True)
        self.assertEqual(plan.count('WARNING PRESERVED'), 2)
        with self.assertRaisesRegex(module.UpdateError, '--preserve-custom-signatures'):
            self.execute(preserve_custom_filters=True)
        with self.assertRaisesRegex(module.UpdateError, '--preserve-custom-filters'):
            self.execute(preserve_custom_signatures=True)
        self.assertFalse(self.log.exists())
        self.assertEqual(self.db.read_bytes(), legacy)
        self.assertEqual(path.read_bytes(), custom)
        result = self.execute(preserve_custom_filters=True, preserve_custom_signatures=True)
        self.assertEqual(result.count('PARTIAL UPDATE:'), 2)
        self.assertEqual(self.db.read_bytes(), legacy)
        self.assertEqual(path.read_bytes(), custom)

    def test_preserved_invalid_db_survives_rollback(self):
        legacy = b'operator-rule|HIGH|secret|^)invalid-regex\n'
        self.db.write_bytes(legacy)
        os.environ['FAKE_FAIL_ON_TEST'] = '2'
        self.addCleanup(os.environ.pop, 'FAKE_FAIL_ON_TEST', None)
        with self.assertRaisesRegex(module.UpdateError, 'restored automatically'):
            self.execute(preserve_custom_signatures=True)
        self.assertEqual(self.db.read_bytes(), legacy)
        self.assertFalse((self.f2b / 'filter.d/nginx-skanery.conf').exists())
        self.assertFalse((self.f2b / 'jail.d/minisoc-fail2ban.local').exists())

    def test_corrupt_bundled_db_is_never_silently_preserved(self):
        source = Path('shipped-signatures.db')
        invalid = b'bad-shipped-rule|HIGH|secret|^)invalid\n'
        with self.assertRaisesRegex(module.SignatureParseError, 'Invalid regex'):
            module.merge_db(b'local|INFO|operator|/ok\n', invalid, self.db, source)

    def test_local_override_aborts(self):
        path = self.f2b / "filter.d" / "nginx-skanery.local"
        path.parent.mkdir()
        path.write_text("[Definition]\nfailregex = ignored\n")
        with self.assertRaisesRegex(module.UpdateError, "override"):
            self.execute()
        self.assertFalse((self.f2b / "jail.d").exists())

    def test_failed_validation_restores_both_filters_and_db(self):
        old = self.create_installed_filter("v1.2.1")
        old_content = old.read_bytes()
        old_db = "# local database\noperator-custom|MEDIUM|operator|/operator-check\n"
        self.db.write_text(old_db)
        os.environ["FAKE_FAIL_ON_TEST"] = "2"
        self.addCleanup(os.environ.pop, "FAKE_FAIL_ON_TEST", None)
        with self.assertRaisesRegex(module.UpdateError, "restored automatically"):
            self.execute()
        self.assertEqual(old.read_bytes(), old_content)
        self.assertEqual(self.db.read_text(), old_db)
        self.assertFalse((self.f2b / "jail.d" / "minisoc-fail2ban.local").exists())
        self.assertIn("reload", self.log.read_text())

    def test_dry_run_is_non_destructive(self):
        self.execute(dry_run=True)
        self.assertFalse(self.db.exists())
        self.assertFalse((self.f2b / "filter.d").exists())
        self.assertFalse(self.log.exists())

    def test_skip_mini_soc_if_directory_missing(self):
        self.db.parent.rmdir()
        result = self.execute()
        self.assertIn("SKIPPED", result)
        self.assertFalse(self.db.exists())

    def test_reject_symlink_in_existing_filter(self):
        dst = self.f2b / "filter.d" / "nginx-skanery.conf"
        dst.parent.mkdir()
        dst.symlink_to(self.base / "elsewhere")
        with self.assertRaisesRegex(module.UpdateError, "symlink"):
            self.execute()

if __name__ == "__main__":
    unittest.main(verbosity=2)
