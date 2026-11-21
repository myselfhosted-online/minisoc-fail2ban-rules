#!/usr/bin/env python3
"""Offline, rootless regression suite for the MiniSOC safe updater."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import re
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

    @staticmethod
    def load_like_correlator(content):
        """Mirror the actual production MiniSOC `load_signatures` loop."""
        rows=[]
        for raw in content.decode('utf-8').splitlines():
            raw=raw.strip()
            if not raw or raw.startswith('#'):
                continue
            try:
                kind, sev, pat=raw.split('|', 2)
                sev=sev.strip().upper()
                rx=re.compile(pat.strip(), re.I)
            except Exception:
                continue
            if sev not in {'LOW','MEDIUM','HIGH','CRITICAL'}:
                continue
            rows.append((kind.strip(), sev, rx.pattern))
        return rows

    def test_fresh_install_and_idempotency(self):
        result = self.execute()
        self.assertIn("SUCCESS", result)
        runtime = self.db.read_bytes()
        self.assertIn(b'wordpress-webshell|HIGH|/wp-content/plugins/hellopress/', runtime)
        self.assertNotIn(b'dotenv-basic|HIGH|secret|', runtime)
        self.assertEqual(len(self.load_like_correlator(runtime)), len(module.parse_db(
            (ROOT / 'rules/signatures-v2.db').read_bytes(), ROOT / 'rules/signatures-v2.db')))
        self.assertTrue((self.f2b / "jail.d" / "minisoc-fail2ban.local").is_file())
        self.assertIn("Already up to date", self.execute())
        self.assertEqual(self.log.read_text().splitlines().count("reload"), 1)

    def test_upgrade_from_121_keeps_custom_jail_and_custom_signatures(self):
        current = self.create_installed_filter("v1.2.1")
        other = self.create_installed_filter("v1.2.1", "nginx-dev-honeypot.conf")
        jail = self.f2b / "jail.d" / "minisoc-fail2ban.local"
        jail.parent.mkdir(exist_ok=True)
        jail.write_text("[nginx-skanery]\nmaxretry = 3\nbantime = 9000\n")
        existing = "# Local operator changes\noperator|MEDIUM|/operator-check(?:$|\\?)\n"
        self.db.write_text(existing)
        self.execute()
        self.assertEqual(current.read_bytes(), (ROOT / "fail2ban/filter.d/nginx-skanery.conf").read_bytes())
        self.assertEqual(other.read_bytes(), (ROOT / "fail2ban/filter.d/nginx-dev-honeypot.conf").read_bytes())
        self.assertEqual(jail.read_text(), "[nginx-skanery]\nmaxretry = 3\nbantime = 9000\n")
        self.assertIn(existing, self.db.read_text())
        self.assertIn("repository|HIGH|/\\.git/HEAD", self.db.read_text())

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
        self.assertIn('bundled v1.3.5 filter rules NOT activated', dry_run)
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

    def test_existing_pattern_keeps_local_metadata_and_adds_other_patterns(self):
        current = "operator|MEDIUM|/\\.git/HEAD(?:$|\\?)\n"
        self.db.write_text(current)
        plan = self.execute(dry_run=True)
        self.assertIn('WARNING SKIPPED 1 existing signature pattern', plan)
        self.assertEqual(self.db.read_text(), current)
        output = self.execute()
        self.assertIn('WARNING SKIPPED 1 existing signature pattern', output)
        merged = self.db.read_text()
        self.assertTrue(merged.startswith(current))
        self.assertEqual(merged.count('/\\.git/HEAD(?:$|\\?)'), 1)
        self.assertIn('secret|HIGH|/(?:\\.env)', merged)
        self.assertIn('reload', self.log.read_text())
        self.assertIn('Already up to date', self.execute())

    def test_existing_database_crlf_bytes_and_regex_pipes_survive_merge(self):
        existing = (b'# operator notes\r\n'
                    b'operator|MEDIUM|/(?:first|second)(?:$|\\?)\r\n'
                    b'custom|LOW|/git-is-private\r\n')
        source = ROOT / 'rules/signatures-v2.db'
        merged = module.merge_db(existing, source.read_bytes(), self.db, source)
        self.assertTrue(merged.startswith(existing))
        self.assertEqual(merged.count(b'/git-is-private'), 1)
        self.assertEqual(merged.count(b'/(?:first|second)'), 1)
        self.assertIn(b'\r\n# Added by MiniSOC v1.3.5 (runtime kind|severity|regex)\r\n', merged)
        self.assertEqual(merged.count(b'\n'), merged.count(b'\r\n'))
        self.assertEqual(module.merge_db(merged, source.read_bytes(), self.db, source), merged)

    def test_reported_debian_runtime_categories_are_not_unique_ids(self):
        # Exact *structure* from the operator's November 21 `awk -F'|' output.
        # Regex alternations introduce extra `|` characters, but the actual
        # correlator uses split('|', 2), and categories intentionally repeat.
        old_db = (b'secret|HIGH|/\\.env([./? ]|$)\n'
                  b'secret|HIGH|/\\.env\\.(bak|old|save|prod)([/? ]|$)\n'
                  b'repository|HIGH|/\\.git/(config|HEAD)([/? ]|$)\n'
                  b'credential|HIGH|/\\.aws/(credentials|config)([/? ]|$)\n')
        self.db.write_bytes(old_db)
        original_count=len(self.load_like_correlator(old_db))
        self.assertEqual(original_count, 4)
        dry = self.execute(dry_run=True, preserve_custom_filters=True)
        self.assertIn(f'WOULD UPDATE {self.db}', dry)
        self.assertNotIn(f'WARNING PRESERVED {self.db}', dry)
        self.assertNotIn('--preserve-custom-signatures', dry)
        self.assertEqual(self.db.read_bytes(), old_db)
        self.assertFalse(self.log.exists())
        result = self.execute(preserve_custom_filters=True)
        self.assertIn('SUCCESS', result)
        merged = self.db.read_bytes()
        self.assertTrue(merged.startswith(old_db))
        self.assertGreater(len(self.load_like_correlator(merged)), original_count)
        self.assertNotIn(b'dotenv-basic|HIGH|secret|', merged)
        self.assertEqual(self.load_like_correlator(merged)[:original_count],
                         self.load_like_correlator(old_db))
        for kind, sev, pattern in self.load_like_correlator(merged):
            self.assertTrue(kind and sev and pattern)
        backup = next(self.f2b.glob('minisoc-backup-*/manifest.json'))
        records = __import__('json').loads(backup.read_text())['changes']
        db_record = next(row for row in records if row['path']==str(self.db))
        self.assertEqual((backup.parent/db_record['backup_file']).read_bytes(), old_db)
        self.assertIn('Already up to date', self.execute())

    def test_existing_jail_in_separate_file_is_not_shadowed_by_new_defaults(self):
        # Reported Debian preview tried to add a new default jail file even
        # though an operator may already enable these jails elsewhere.
        path=self.f2b/'jail.d'/'custom-homelab.local'
        path.parent.mkdir()
        original=b'[nginx-skanery]\nenabled = true\nmaxretry = 6\nbantime = 7d\n'
        path.write_bytes(original)
        dry=self.execute(dry_run=True)
        self.assertIn('WARNING SKIPPED new default jail', dry)
        self.assertNotIn('new default jail\n', dry)
        self.execute()
        self.assertFalse((self.f2b/'jail.d'/'minisoc-fail2ban.local').exists())
        self.assertEqual(path.read_bytes(), original)
        self.assertTrue(self.db.exists())

    def test_preexisting_jail_in_top_level_local_is_preserved(self):
        path=self.f2b/'jail.local'
        original=b'[nginx-dev-honeypot]\nenabled = true\nmaxretry = 4\n'
        path.write_bytes(original)
        self.execute()
        self.assertEqual(path.read_bytes(),original)
        self.assertFalse((self.f2b/'jail.d/minisoc-fail2ban.local').exists())

    def test_repeated_categories_and_regex_alternation_remain_distinct(self):
        old = (b'secret|HIGH|/\\.env([./? ]|$)\n'
               b'secret|HIGH|/\\.env\\.(bak|old)([/? ]|$)\n'
               b'secret|MEDIUM|/\\.env-example(?:$|\\?)\n')
        patterns=module.parse_runtime_db(old,self.db)
        self.assertEqual(len(patterns), 3)
        self.assertIn('/\\.env([./? ]|$)', patterns)

    def test_existing_canonical_four_column_file_requires_review(self):
        old=(b'# Format: id|severity|category|regex\n'
             b'dotenv-basic|HIGH|secret|/(?:\\.env)(?:$|[./_-])\n')
        self.db.write_bytes(old)
        preview=self.execute(dry_run=True)
        self.assertIn('WARNING PRESERVED', preview)
        self.assertIn('public four-column signature format', preview)
        with self.assertRaisesRegex(module.UpdateError,'--preserve-custom-signatures'):
            self.execute()
        self.assertEqual(self.db.read_bytes(), old)

    def test_headerless_public_four_column_file_requires_review(self):
        # A missing header must not trick a 3-column reader into treating
        # public `category|regex` as a compilable legacy regex.
        old=b'dotenv-basic|HIGH|secret|/(?:\\.env)(?:$|[./_-])\n'
        self.db.write_bytes(old)
        preview=self.execute(dry_run=True)
        self.assertIn('WARNING PRESERVED', preview)
        self.assertIn('public four-column signature format', preview)
        with self.assertRaisesRegex(module.UpdateError,'--preserve-custom-signatures'):
            self.execute()
        self.assertEqual(self.db.read_bytes(), old)

    def test_unsupported_upstream_severity_is_never_installed(self):
        incoming=b'unsafe-info|INFO|secret|/bad\n'
        with self.assertRaisesRegex(module.SignatureParseError,'Invalid signature fields'):
            module.merge_db(b'secret|HIGH|/legacy\n',incoming,self.db,Path('bundled'))

    def test_duplicate_categories_survive_automatic_rollback(self):
        old_db=(b'secret|HIGH|/\\.env([./? ]|$)\n'
                b'secret|HIGH|/\\.env\\.(bak|old)([/? ]|$)\n')
        self.db.write_bytes(old_db)
        os.environ['FAKE_FAIL_ON_TEST']='2'
        self.addCleanup(os.environ.pop,'FAKE_FAIL_ON_TEST',None)
        with self.assertRaisesRegex(module.UpdateError,'restored automatically'):
            self.execute()
        self.assertEqual(self.db.read_bytes(), old_db)
        self.assertFalse((self.f2b/'jail.d/minisoc-fail2ban.local').exists())

    def test_existing_database_without_final_newline_preserved(self):
        existing = b'operator|LOW|/already-exists'
        source = ROOT / 'rules/signatures-v2.db'
        merged = module.merge_db(existing, source.read_bytes(), self.db, source)
        self.assertTrue(merged.startswith(existing + b'\n\n# Added by MiniSOC v1.3.5 (runtime kind|severity|regex)\n'))
        self.assertEqual(merged.count(b'/already-exists'), 1)
        self.assertEqual(module.merge_db(merged, source.read_bytes(), self.db, source), merged)

    def test_empty_installed_database_uses_exact_bundled_content(self):
        self.db.write_bytes(b'')
        output = self.execute()
        self.assertIn('SUCCESS', output)
        self.assertIn(b'# Added by MiniSOC v1.3.5', self.db.read_bytes())
        self.assertEqual(len(self.load_like_correlator(self.db.read_bytes())), 40)

    def test_non_utf8_existing_database_is_preserved_without_loss(self):
        raw = b'\xff\xfelocal-data\n'
        self.db.write_bytes(raw)
        preview = self.execute(dry_run=True)
        self.assertIn('WARNING PRESERVED', preview)
        self.assertIn('Invalid UTF-8', preview)
        self.assertEqual(self.db.read_bytes(), raw)
        with self.assertRaisesRegex(module.UpdateError, '--preserve-custom-signatures'):
            self.execute()
        self.assertEqual(self.db.read_bytes(), raw)

    def test_duplicate_ids_in_bundled_signatures_rejected(self):
        malformed = (b'duplicate|HIGH|secret|/first\n'
                     b'duplicate|LOW|operator|/second\n')
        with self.assertRaisesRegex(module.SignatureParseError, 'Duplicate signature ID duplicate'):
            module.merge_db(b'local|INFO|operator|/ok\n', malformed, self.db, Path('bundled-db'))

    def test_invalid_python_legacy_regex_is_retained_in_merged_database(self):
        # Reproduces production line-1 failure without changing its regex.
        legacy = b'secret|HIGH|^)bad-regex\n'
        self.db.write_bytes(legacy)
        output = self.execute(dry_run=True)
        self.assertIn('WARNING EXISTING REGEX', output)
        self.assertIn('unbalanced parenthesis at position 1', output)
        self.assertIn(f'WOULD UPDATE {self.db}', output)
        self.assertNotIn(f'WARNING PRESERVED {self.db}', output)
        self.assertEqual(self.db.read_bytes(), legacy)
        self.assertFalse(self.log.exists())
        output = self.execute()
        merged = self.db.read_bytes()
        self.assertTrue(merged.startswith(legacy))
        self.assertIn(b'repository|HIGH|/\\.git/HEAD', merged)
        self.assertEqual(merged.count(b'bad-regex'), 1)
        self.assertIn('reload', self.log.read_text())
        manifests = list(self.f2b.glob('minisoc-backup-*/manifest.json'))
        self.assertEqual(len(manifests), 1)
        records = __import__('json').loads(manifests[0].read_text())['changes']
        db_record = next(row for row in records if row['path'] == str(self.db))
        self.assertEqual((manifests[0].parent / db_record['backup_file']).read_bytes(), legacy)
        self.assertIn('Already up to date', self.execute())

    def test_reported_debian_case_two_custom_filters_and_legacy_db_merge(self):
        # End-to-end reproduction of the reported v1.3.3 dry-run sequence.
        originals = {}
        filter_dir = self.f2b / 'filter.d'
        filter_dir.mkdir()
        for name in module.FILTERS:
            content = b'[Definition]\nfailregex = ^<HOST> .*private-production-filter\n'
            path = filter_dir / name
            path.write_bytes(content)
            originals[path] = content
        old_db = b'secret|HIGH|^)legacy-regex\n'
        self.db.write_bytes(old_db)

        preview = self.execute(dry_run=True)
        self.assertEqual(preview.count('WARNING PRESERVED'), 2)
        self.assertIn('WARNING EXISTING REGEX', preview)
        self.assertIn(f'WOULD UPDATE {self.db}', preview)
        self.assertIn('REQUIRES REVIEW', preview)
        with self.assertRaisesRegex(module.UpdateError, '--preserve-custom-filters'):
            self.execute()
        self.assertEqual(self.db.read_bytes(), old_db)
        self.assertFalse(self.log.exists())

        result = self.execute(preserve_custom_filters=True)
        self.assertIn('PARTIAL UPDATE: customized filters were preserved', result)
        self.assertNotIn('signature database was preserved', result)
        self.assertTrue(self.db.read_bytes().startswith(old_db))
        self.assertIn(b'secret|HIGH|/(?:\\.env)', self.db.read_bytes())
        for path, raw in originals.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_malformed_local_database_is_preserved_without_overwriting(self):
        legacy = b'operator-rule|HIGH\n'
        self.db.write_bytes(legacy)
        plan = self.execute(dry_run=True)
        self.assertIn(f'WARNING PRESERVED {self.db}', plan)
        self.assertIn('--preserve-custom-signatures', plan)
        with self.assertRaisesRegex(module.UpdateError, '--preserve-custom-signatures'):
            self.execute()
        self.assertEqual(self.db.read_bytes(), legacy)
        self.assertFalse(self.log.exists())
        output = self.execute(preserve_custom_signatures=True)
        self.assertIn('PARTIAL UPDATE: incompatible local signature database was preserved', output)
        self.assertEqual(self.db.read_bytes(), legacy)

    def test_invalid_legacy_db_and_custom_filters_both_require_explicit_preservation(self):
        custom = b'[Definition]\nfailregex = ^<HOST> .*custom-test\n'
        path = self.f2b / 'filter.d/nginx-skanery.conf'
        path.parent.mkdir()
        path.write_bytes(custom)
        legacy = b'local-secret|HIGH\n'
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

    def test_merged_legacy_db_survives_rollback(self):
        legacy = b'secret|HIGH|^)invalid-regex\n'
        self.db.write_bytes(legacy)
        os.environ['FAKE_FAIL_ON_TEST'] = '2'
        self.addCleanup(os.environ.pop, 'FAKE_FAIL_ON_TEST', None)
        with self.assertRaisesRegex(module.UpdateError, 'restored automatically'):
            self.execute()
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
        old_db = "# local database\noperator|MEDIUM|/operator-check\n"
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

    def test_reject_symlink_in_existing_database(self):
        self.db.symlink_to(self.base / 'unexpected-signatures.db')
        with self.assertRaisesRegex(module.UpdateError, 'symlink'):
            self.execute()

if __name__ == "__main__":
    unittest.main(verbosity=2)
