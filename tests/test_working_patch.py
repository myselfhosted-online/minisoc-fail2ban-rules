#!/usr/bin/env python3
import configparser
import importlib.util
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]

def module(name, filename):
    spec=importlib.util.spec_from_file_location(name,filename)
    target=importlib.util.module_from_spec(spec)
    import sys
    sys.modules[name]=target
    spec.loader.exec_module(target)
    return target

update=module('safe_update',ROOT/'install/safe_update.py')
uninstall=module('safe_uninstall',ROOT/'install/safe_uninstall.py')
restore=module('restore_backup',ROOT/'install/restore_backup.py')
correlate=module('correlate_incidents',ROOT/'scripts/correlate_incidents.py')

class Patches(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir=Path(self.tmp.name)
        self.etc=self.dir/'etc'/'fail2ban'
        self.db=self.dir/'etc'/'minisoc'/'signatures-v2.db'
        self.db.parent.mkdir(parents=True)
        self.etc.mkdir()
        self.env=mock.patch.dict(os.environ,{'F2B_ETC':str(self.etc),'MINISOC_SIGNATURES':str(self.db)},clear=False)
        self.env.start();self.addCleanup(self.env.stop)
        self.uid=mock.patch.object(update.os,'geteuid',return_value=0)
        self.uid.start();self.addCleanup(self.uid.stop)
        self.fake=mock.patch.object(update,'f2b')
        self.f2b=self.fake.start();self.addCleanup(self.fake.stop)
        self.uninstall_fake=mock.patch.object(uninstall,'f2b',side_effect=lambda *args:self.f2b(*args))
        self.uninstall_fake.start();self.addCleanup(self.uninstall_fake.stop)
        self.restore_fake=mock.patch.object(restore,'f2b',side_effect=lambda *args:self.f2b(*args))
        self.restore_fake.start();self.addCleanup(self.restore_fake.stop)
        self.which=mock.patch.object(update.shutil,'which',return_value='/usr/bin/fake')
        self.which.start();self.addCleanup(self.which.stop)

    def baseline(self,version='v1.3.1',filename='nginx-skanery.conf',tail=b''):
        dest=self.etc/'filter.d'/filename
        dest.parent.mkdir(parents=True,exist_ok=True)
        dest.write_bytes((ROOT/'install'/'baselines'/version/filename).read_bytes()+tail)
        return dest

    def test_fresh_install_and_second_run(self):
        update.run()
        self.assertTrue(self.db.exists())
        self.assertIn('terraform-state-backup',self.db.read_text())
        self.assertEqual((self.etc/'filter.d'/'nginx-skanery.conf').read_bytes(),(ROOT/'fail2ban/filter.d/nginx-skanery.conf').read_bytes())
        old_calls=self.f2b.call_count
        update.run()
        self.assertEqual(old_calls,self.f2b.call_count)

    def test_upgrade_from_v121_preserves_jail_and_local_db(self):
        self.baseline('v1.2.1')
        self.baseline('v1.2.1','nginx-dev-honeypot.conf')
        jail=self.etc/'jail.d'/'minisoc-fail2ban.local'
        jail.parent.mkdir(parents=True)
        jail.write_text('[nginx-skanery]\nmaxretry = 8\n')
        self.db.write_text('custom-detection|MEDIUM|custom|/my-private-prefix\n')
        update.run()
        self.assertEqual(jail.read_text(),'[nginx-skanery]\nmaxretry = 8\n')
        self.assertIn('custom-detection|MEDIUM',self.db.read_text())
        self.assertIn('oauth-client-secrets-root|HIGH',self.db.read_text())

    def test_dry_run_has_no_effect(self):
        update.run(dry_run=True)
        self.assertFalse(self.db.exists())
        self.assertFalse((self.etc/'filter.d').exists())
        self.f2b.assert_not_called()

    def test_custom_signature_conflict_preserves_local_and_appends_missing(self):
        self.db.write_text('git-head|INFO|custom|/other\n')
        update.run()
        merged = self.db.read_text()
        self.assertTrue(merged.startswith('git-head|INFO|custom|/other\n'))
        self.assertEqual(merged.count('git-head|'),1)
        self.assertIn('dotenv-basic|HIGH|secret|',merged)
        self.assertTrue((self.etc/'filter.d').is_dir())
        self.assertTrue(self.f2b.called)

    def test_unknown_local_filter_is_not_overwritten(self):
        path=self.etc/'filter.d'/'nginx-skanery.conf';path.parent.mkdir()
        path.write_text('[Definition]\nfailregex = danger\n')
        with self.assertRaisesRegex(update.UpdateError,'Customized filters require manual review'):
            update.run()
        self.assertEqual(path.read_text(),'[Definition]\nfailregex = danger\n')

    def test_override_aborts(self):
        path=self.etc/'filter.d'/'nginx-skanery.local';path.parent.mkdir()
        path.write_text('[Definition]\n')
        with self.assertRaisesRegex(update.UpdateError,'Local override'):
            update.run()
        self.f2b.assert_not_called()

    def test_automatic_rollback_on_validation_error(self):
        old=self.baseline('v1.3.0')
        old_content=old.read_bytes()
        old_db=b'custom-detection|MEDIUM|custom|/my-private-prefix\n'
        self.db.write_bytes(old_db)
        calls=0
        def client(*args):
            nonlocal calls
            calls+=1
            if args==('-t',) and calls==2:
                raise update.UpdateError('simulated validation error')
        self.f2b.side_effect=client
        with self.assertRaisesRegex(update.UpdateError,'previous files restored'):
            update.run()
        self.assertEqual(old.read_bytes(),old_content)
        self.assertEqual(self.db.read_bytes(),old_db)
        self.assertFalse((self.etc/'jail.d'/'minisoc-fail2ban.local').exists())
        self.assertTrue(list(self.etc.glob('minisoc-backup-*/manifest.json')))

    def test_backup_copies_and_manifest(self):
        self.baseline('v1.3.0')
        update.run()
        manifest=list(self.etc.glob('minisoc-backup-*/manifest.json'))
        self.assertEqual(len(manifest),1)
        data=__import__('json').loads(manifest[0].read_text())
        self.assertEqual(data['schema'],1)
        self.assertTrue(all('logical_name' in row for row in data['changes']))
        self.assertTrue(any('backup_file' in row for row in data['changes']))

    def test_uninstall_refuses_customizations(self):
        update.run()
        jail=self.etc/'jail.d'/'minisoc-fail2ban.local'
        jail.write_text('[nginx-skanery]\nmaxretry = 40\n')
        with self.assertRaisesRegex(uninstall.UpdateError,'Customized jail'):
            uninstall.run()
        self.assertTrue((self.etc/'filter.d'/'nginx-skanery.conf').exists())

    def test_uninstall_complete_after_fresh_install(self):
        update.run()
        uninstall.run()
        self.assertFalse((self.etc/'filter.d'/'nginx-skanery.conf').exists())
        self.assertTrue(self.db.exists())
        self.assertTrue(list(self.etc.glob('minisoc-uninstall-backup-*')))

    def test_uninstall_rollback_on_reload_failure(self):
        update.run()
        old=(self.etc/'filter.d'/'nginx-skanery.conf').read_bytes()
        count=0
        def client(*args):
            nonlocal count
            count+=1
            if args==('reload',) and count==3:
                raise update.UpdateError('simulated reload error')
        # Actual call sequence: initial -t, post-delete -t, reload => third call.
        self.f2b.side_effect=client
        with self.assertRaisesRegex(uninstall.UpdateError,'previous files restored'):
            uninstall.run()
        self.assertEqual((self.etc/'filter.d'/'nginx-skanery.conf').read_bytes(),old)

    def test_custom_filter_comment_preserved(self):
        current=self.baseline('v1.3.1',tail=b'\n# Local customer note\n')
        update.run()
        self.assertIn(b'# Local customer note',current.read_bytes())

    def test_uninstall_dry_run_never_changes_files(self):
        update.run()
        path=self.etc/'filter.d'/'nginx-skanery.conf'
        previous=path.read_bytes()
        calls=self.f2b.call_count
        uninstall.run(dry_run=True)
        self.assertEqual(path.read_bytes(),previous)
        self.assertEqual(calls,self.f2b.call_count)

    def test_restore_rejects_corrupt_backup(self):
        self.baseline('v1.2.1')
        update.run()
        backup=next(self.etc.glob('minisoc-backup-*'))
        (backup/'00.orig').write_bytes(b'tampered')
        with self.assertRaisesRegex(restore.UpdateError,'Corrupt or missing'):
            restore.restore_backup(backup)

    def test_manual_verified_restore_of_previous_version(self):
        old=self.baseline('v1.2.1')
        original=old.read_bytes()
        update.run()
        backup=next(self.etc.glob('minisoc-backup-*'))
        restore.restore_backup(backup,dry_run=True)
        self.assertNotEqual(old.read_bytes(),original)
        restore.restore_backup(backup)
        self.assertEqual(old.read_bytes(),original)
        self.assertFalse(self.db.exists())

    def test_restore_rejects_modified_target(self):
        update.run()
        backup=next(self.etc.glob('minisoc-backup-*'))
        path=self.etc/'filter.d'/'nginx-skanery.conf'
        path.write_bytes(path.read_bytes()+b'\n# changed after install\n')
        with self.assertRaisesRegex(restore.UpdateError,'Target changed'):
            restore.restore_backup(backup)

    def test_uninstall_rollback_keeps_original_permissions(self):
        update.run()
        path=self.etc/'filter.d'/'nginx-skanery.conf'
        path.chmod(0o600)
        counter=0
        def client(*args):
            nonlocal counter
            counter+=1
            if args==('reload',) and counter==3:
                raise update.UpdateError('simulated reload failure')
        self.f2b.side_effect=client
        with self.assertRaisesRegex(uninstall.UpdateError,'previous files restored'):
            uninstall.run()
        self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_symlink_guard(self):
        link=self.etc/'filter.d';link.symlink_to(self.db.parent)
        with self.assertRaisesRegex(update.UpdateError,'symlink'):
            update.run()

class Detection(unittest.TestCase):
    def test_filters_are_valid_configparser(self):
        for name in update.FILTERS:
            config=configparser.ConfigParser()
            config.read(ROOT/'fail2ban/filter.d'/name)
            regex=config.get('Definition','failregex')
            self.assertTrue(regex)
            self.assertNotIn('%%2',regex)

    def test_malicious_and_benign_log_fixtures(self):
        positive=(ROOT/'tests/fixtures/november-2026-malicious.log').read_text().splitlines()
        negative=(ROOT/'tests/fixtures/november-2026-benign.log').read_text().splitlines()
        for name in update.FILTERS:
            config=configparser.ConfigParser()
            config.read(ROOT/'fail2ban/filter.d'/name)
            regex=config.get('Definition','failregex')
            regex=regex.replace('<HOST>',r'(?P<host>[0-9.]+)')
            pattern=re.compile(regex)
            matches=sum(bool(pattern.search(line)) for line in positive)
            self.assertGreaterEqual(matches,3,(name,matches))
            for line in negative:
                self.assertIsNone(pattern.search(line),(name,line))

    def test_exact_github_baseline_git_blob_ids(self):
        import hashlib
        known={'v1.2.1':'7608206e663ec2e353c476f04ccaadab33c3890b',
               'v1.3.0':'67ac242f620bb4563517f932e4951a6d614911bd',
               'v1.3.1':'67ac242f620bb4563517f932e4951a6d614911bd'}
        for version,expected in known.items():
            data=(ROOT/'install'/'baselines'/version/'nginx-skanery.conf').read_bytes()
            got=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            self.assertEqual(got,expected,version)

    def test_common_config_paths_remain_nonblocking(self):
        config=configparser.ConfigParser()
        config.read(ROOT/'fail2ban/filter.d/nginx-skanery.conf')
        pattern=re.compile(config.get('Definition','failregex').replace('<HOST>',r'(?P<host>[0-9.]+)'))
        for path in ['/config.json','/config/config.json','/config.yaml','/firebaseConfig.js','/credentials.json']:
            self.assertIsNone(pattern.search('203.0.113.9 - - [16/Nov/2026:05:06:24 +0100] "GET '+path+' HTTP/1.1" 404 0 "-" "UA"'))

    def test_signatures_compile_and_new_iocs(self):
        entries=update.parse_db((ROOT/'rules/signatures-v2.db').read_bytes(),ROOT/'rules/signatures-v2.db')
        self.assertGreaterEqual(len(entries),38)
        for key in ['terraform-state-backup','oauth-client-secrets-root','traversal-encoded-env',
                    'traversal-adjacent-dotenv','hellopress-filemanager','backend-encoded-dotenv',
                    'sql-dump-root','userfiles-env-query-traversal','cache-encoded-dotdot-env',
                    'encoded-slash-env','git-config-encoded-question','service-account-json',
                    'streamlit-secrets']:
            self.assertIn(key,entries)
        self.assertFalse(re.search(entries['terraform-state-backup'].split('|',3)[-1],'/terraform.tfstate.backup-old'))

    def test_correlation_dedup_three_jails_two_alerts(self):
        p=ROOT/'tests/fixtures/november-alerts-sanitized.json'
        alerts=__import__('json').loads(p.read_text())
        report=correlate.brief(correlate.correlation(alerts))
        self.assertEqual(report['raw_alerts'],5)
        self.assertEqual(report['parent_incidents'],2)
        self.assertEqual(report['unique_http_events'],24)
        self.assertEqual(sorted([x['unique_requests'] for x in report['incidents']]),[6,18])

    def test_november_18_dedup_and_encoded_dotenv_variants(self):
        alerts=__import__('json').loads((ROOT/'tests/fixtures/november-18-alerts-sanitized.json').read_text())
        report=correlate.brief(correlate.correlation(alerts))
        self.assertEqual(report['raw_alerts'],4)
        self.assertEqual(report['parent_incidents'],3)
        self.assertEqual(report['sampled_requests_in_alerts'],24)
        self.assertEqual(report['unique_http_events'],18)
        self.assertEqual(report['unique_paths'],18)
        target=next(g for g in report['incidents'] if g['source']=='198.51.100.19')
        self.assertEqual(target['unique_requests'],6)
        self.assertEqual(target['normalized_variants'],[{
            'canonical_path':'/backend/.env',
            'raw_paths':sorted(['/backend/.env','/backend/%2eenv','/backend/%252eenv',
                                '/backend/.%65nv','/backend/./.env'])
        }])
        doubled=next(g for g in report['incidents'] if g['source']=='198.51.100.20')
        self.assertEqual(doubled['alerts'],2)
        self.assertEqual(doubled['sampled_requests_in_alerts'],12)
        self.assertEqual(doubled['unique_requests'],6)
        self.assertEqual(doubled['statuses'],{'404':6})

    def test_http_status_transition_only_diagnostic(self):
        alert=[{'ip':'198.51.100.31','jail':'nginx-skanery','events':[
            {'time':'2026-11-18T02:20:10+01:00','path':'/backend/.env','status':401},
            {'time':'2026-11-18T02:20:14+01:00','path':'/backend/.env','status':404},
            {'time':'2026-11-18T02:20:16+01:00','path':'/backend/.env','status':404}]}]
        report=correlate.brief(correlate.correlation(alert))
        g=report['incidents'][0]
        self.assertEqual(g['unique_requests'],3)
        self.assertEqual(g['unique_paths'],1)
        self.assertEqual(g['status_transitions'],[
            {'path':'/backend/.env','from':401,'to':404,'seconds':4.0}])

    def test_november_18_encoded_secret_and_sql_scanners(self):
        lines=(ROOT/'tests/fixtures/november-18-malicious.log').read_text().splitlines()
        for name,expected in [('nginx-skanery.conf',10),('nginx-dev-honeypot.conf',9)]:
            cfg=configparser.ConfigParser()
            cfg.read(ROOT/'fail2ban/filter.d'/name)
            regex=cfg.get('Definition','failregex').replace('<HOST>',r'(?P<host>[0-9.]+)')
            pattern=re.compile(regex)
            self.assertEqual(sum(bool(pattern.search(s)) for s in lines),expected,name)
            for path in ['/backup.sql.old','/backend/%2eenv.backup','/backend/%252eenv.js',
                         '/assets/backup.sql','/img.svg?next=/database.sql']:
                line='198.51.100.31 - - [18/Nov/2026:02:30:19 +0100] "GET '+path+' HTTP/1.1" 200 7 "-" "UA"'
                self.assertIsNone(pattern.search(line),(name,path))

    def test_november_18_afternoon_incidents_and_daywide_totals(self):
        import json
        base=ROOT/'tests/fixtures'
        earlier=json.loads((base/'november-18-alerts-sanitized.json').read_text())
        afternoon=json.loads((base/'november-18-afternoon-alerts-sanitized.json').read_text())
        result=correlate.brief(correlate.correlation(afternoon))
        self.assertEqual((result['raw_alerts'],result['parent_incidents']), (6,2))
        self.assertEqual(result['sampled_requests_in_alerts'],36)
        self.assertEqual(result['unique_http_events'],36)
        self.assertEqual(result['unique_paths'],36)
        self.assertEqual(sorted(g['unique_requests'] for g in result['incidents']),[18,18])
        self.assertTrue(all(len(g['jails'])==3 and g['statuses']=={'401':18}
                            for g in result['incidents']))
        day=correlate.brief(correlate.correlation(earlier+afternoon))
        self.assertEqual((day['raw_alerts'],day['parent_incidents']),(10,5))
        self.assertEqual(day['sampled_requests_in_alerts'],60)
        self.assertEqual(day['unique_http_events'],54)
        self.assertEqual(day['unique_paths'],54)

    def test_november_18_afternoon_scoped_rules_and_benign_paths(self):
        positives=(ROOT/'tests/fixtures/november-18-afternoon-malicious.log').read_text().splitlines()
        negatives=(ROOT/'tests/fixtures/november-2026-benign.log').read_text().splitlines()
        for name,expected in [('nginx-skanery.conf',25),('nginx-dev-honeypot.conf',22)]:
            cfg=configparser.ConfigParser()
            cfg.read(ROOT/'fail2ban/filter.d'/name)
            pattern=re.compile(cfg.get('Definition','failregex').replace('<HOST>',
                           r'(?P<host>[0-9.]+)'))
            self.assertEqual(sum(bool(pattern.search(s)) for s in positives),expected,name)
            for entry in negatives:
                self.assertIsNone(pattern.search(entry),(name,entry))

    def test_november_18_evening_cross_jail_dedup(self):
        import json
        base=ROOT/'tests/fixtures'
        evening=json.loads((base/'november-18-evening-alerts-sanitized.json').read_text())
        report=correlate.brief(correlate.correlation(evening))
        self.assertEqual((report['raw_alerts'],report['parent_incidents']),(7,3))
        self.assertEqual((report['sampled_requests_in_alerts'],report['unique_http_events'],
                          report['unique_paths']), (42,33,33))
        incident=next(i for i in report['incidents'] if i['source']=='198.51.100.23')
        self.assertEqual((incident['alerts'],incident['sampled_requests_in_alerts'],
                          incident['unique_requests']), (3,18,9))
        self.assertEqual(incident['statuses'],{'401':9})
        self.assertEqual(len(incident['jails']),3)
        self.assertEqual(incident['status_transitions'],[])
        second=next(i for i in report['incidents'] if i['source']=='198.51.100.24')
        self.assertEqual((second['alerts'],second['unique_requests']), (3,18))
        self.assertEqual(second['statuses'],{'401':18})
        last=next(i for i in report['incidents'] if i['source']=='198.51.100.25')
        self.assertEqual((last['alerts'],last['unique_requests']), (1,6))
        self.assertEqual(last['statuses'],{'404':6})

    def test_november_18_daywide_all_eight_incidents(self):
        import json
        base=ROOT/'tests/fixtures'
        full=json.loads((base/'november-18-all-alerts-sanitized.json').read_text())
        morning=json.loads((base/'november-18-alerts-sanitized.json').read_text())
        afternoon=json.loads((base/'november-18-afternoon-alerts-sanitized.json').read_text())
        evening=json.loads((base/'november-18-evening-alerts-sanitized.json').read_text())
        self.assertEqual(full,morning+afternoon+evening)
        report=correlate.brief(correlate.correlation(full))
        self.assertEqual((report['raw_alerts'],report['parent_incidents']), (17,8))
        self.assertEqual((report['sampled_requests_in_alerts'],report['unique_http_events'],
                          report['unique_paths']), (102,87,87))
        self.assertEqual(sum(g['statuses'].get('401',0) for g in report['incidents']),63)
        self.assertEqual(sum(g['statuses'].get('404',0) for g in report['incidents']),24)

    def test_november_18_evening_fixture_and_review_only_candidates(self):
        positives=(ROOT/'tests/fixtures/november-18-evening-malicious.log').read_text().splitlines()
        self.assertEqual(len(positives),33)
        for name,expected in [('nginx-skanery.conf',20),('nginx-dev-honeypot.conf',19)]:
            cfg=configparser.ConfigParser()
            cfg.read(ROOT/'fail2ban/filter.d'/name)
            pattern=re.compile(cfg.get('Definition','failregex').replace('<HOST>',
                           r'(?P<host>[0-9.]+)'))
            self.assertEqual(sum(bool(pattern.search(line)) for line in positives),
                             expected,name)
        catalog=(ROOT/'rules/candidates.list').read_text()
        # Candidate regexes may themselves contain "|" alternation; split
        # on the first three and final delimiter, preserving the full regex.
        candidates=[row.split('|',3)[:3]+row.split('|',3)[3].rsplit('|',1)
                    for row in catalog.splitlines()
                    if row and not row.startswith('#')]
        self.assertTrue(all(len(row)==5 for row in candidates))
        by_name={row[0]:row for row in candidates}
        self.assertGreaterEqual(len(candidates),40)
        for identifier,state,category,regex,notes in candidates:
            self.assertEqual(state,'REVIEW',identifier)
            self.assertTrue(category and notes,identifier)
            re.compile(regex)
        for key in ['api-system-fileview-env','api-fs-outside-workspace-env',
                    'api-console-traversal-env','adjacent-dotenv-media',
                    'wordpress-login-lookalike-capital-i','wordpress-optimizer-php',
                    'wordpress-config-query']:
            self.assertEqual(by_name[key][1],'REVIEW')
            re.compile(by_name[key][3])
        self.assertIsNotNone(re.search(by_name['api-console-traversal-env'][3],
                 '/api/console/api_server?sense_version=%40%40SENSE_VERSION&amp;apis=../../../../../../.env'))
        self.assertIsNone(re.search(by_name['api-console-traversal-env'][3],
                 '/api/console/api_server?sense_version=%40%40SENSE_VERSION&apis=normal.txt'))

    def test_november_19_multijail_same_second_without_duplicate_requests(self):
        import json
        base=ROOT/'tests/fixtures'
        alert=json.loads((base/'november-19-alerts-sanitized.json').read_text())
        self.assertEqual(len(alert),2)
        report=correlate.brief(correlate.correlation(alert))
        self.assertEqual((report['raw_alerts'],report['parent_incidents']),(2,1))
        self.assertEqual((report['sampled_requests_in_alerts'],report['unique_http_events'],
                          report['unique_paths']),(12,12,12))
        incident=report['incidents'][0]
        self.assertEqual(incident['jails'],['nginx-dev-honeypot','nginx-skanery'])
        self.assertEqual(incident['statuses'],{'404':12})
        self.assertEqual(incident['status_transitions'],[])
        prior=json.loads((base/'november-18-all-alerts-sanitized.json').read_text())
        total=correlate.brief(correlate.correlation(prior+alert))
        self.assertEqual((total['raw_alerts'],total['parent_incidents']),(19,9))
        self.assertEqual((total['sampled_requests_in_alerts'],total['unique_http_events'],
                          total['unique_paths']),(114,99,99))

    def test_november_19_precision_and_nonblocking_review(self):
        synthetic=(ROOT/'tests/fixtures/november-19-malicious.log').read_text().splitlines()
        self.assertEqual(len(synthetic),12)
        for name in update.FILTERS:
            cfg=configparser.ConfigParser()
            cfg.read(ROOT/'fail2ban/filter.d'/name)
            pattern=re.compile(cfg.get('Definition','failregex').replace('<HOST>',
                           r'(?P<host>[0-9.]+)'))
            observed=[line.split('"')[1].split(' ')[1] for line in synthetic
                      if pattern.search(line)]
            self.assertEqual(set(observed),
                {'/site/.env','/database.sql','/backup.sql','/dump.sql'})
            for path in ['/config.yaml','/config.json','/credentials.yml',
                         '/credentials.json','/secrets.json','/secrets.yml',
                         '/env.js','/__ENV.js']:
                line='198.51.100.26 - - [19/Nov/2026:10:16:14 +0100] "GET '+path+' HTTP/1.1" 404 0 "-" "synthetic"'
                self.assertIsNone(pattern.search(line),(name,path))
        catalog=(ROOT/'rules/candidates.list').read_text()
        rows=[line.split('|',3)[:3]+line.split('|',3)[3].rsplit('|',1)
              for line in catalog.splitlines() if line and not line.startswith('#')]
        candidates={row[0]:row for row in rows}
        for key in ['secrets-json-yaml','env-frontend-js','env-frontend-double-underscore']:
            self.assertEqual(candidates[key][1],'REVIEW')
            re.compile(candidates[key][3])
        self.assertTrue(re.search(candidates['env-frontend-double-underscore'][3],
                                  '/__ENV.js'))

    def test_november_19_late_wordpress_and_cross_jail_duplicate(self):
        import json
        base=ROOT/'tests/fixtures'
        late=json.loads((base/'november-19-late-alerts-sanitized.json').read_text())
        report=correlate.brief(correlate.correlation(late))
        self.assertEqual((report['raw_alerts'],report['parent_incidents']),(3,2))
        self.assertEqual((report['sampled_requests_in_alerts'],report['unique_http_events'],
                          report['unique_paths']),(18,12,12))
        other=next(g for g in report['incidents'] if g['source']=='198.51.100.28')
        self.assertEqual((other['alerts'],other['sampled_requests_in_alerts'],
                          other['unique_requests']),(2,12,6))
        self.assertEqual(other['jails'],['nginx-dev-honeypot','nginx-skanery'])
        self.assertEqual(other['statuses'],{'404':6})
        self.assertTrue(all(g['status_transitions']==[] for g in report['incidents']))

    def test_november_19_full_day_and_november_20_repeat_source(self):
        import json
        base=ROOT/'tests/fixtures'
        earlier=json.loads((base/'november-19-alerts-sanitized.json').read_text())
        late=json.loads((base/'november-19-late-alerts-sanitized.json').read_text())
        full=json.loads((base/'november-19-all-alerts-sanitized.json').read_text())
        self.assertEqual(full,earlier+late)
        day=correlate.brief(correlate.correlation(full))
        self.assertEqual((day['raw_alerts'],day['parent_incidents']),(5,3))
        self.assertEqual((day['sampled_requests_in_alerts'],day['unique_http_events'],
                          day['unique_paths']),(30,24,24))
        nov20=json.loads((base/'november-20-alerts-sanitized.json').read_text())
        self.assertEqual(len(nov20),1)
        self.assertEqual(nov20[0]['ip'],'198.51.100.20')
        today=correlate.brief(correlate.correlation(nov20))
        self.assertEqual((today['raw_alerts'],today['parent_incidents'],
                          today['sampled_requests_in_alerts'],today['unique_http_events']),
                         (1,1,6,6))
        self.assertEqual(today['incidents'][0]['statuses'],{'404':6})
        prev=json.loads((base/'november-18-all-alerts-sanitized.json').read_text())
        result=correlate.brief(correlate.correlation(prev+full+nov20))
        self.assertEqual((result['raw_alerts'],result['parent_incidents'],
                          result['sampled_requests_in_alerts'],result['unique_http_events'],
                          result['unique_paths']),(23,12,138,117,117))
        same_ip=[g for g in result['incidents'] if g['source']=='198.51.100.20']
        self.assertEqual(len(same_ip),2)  # Separate November 18 and November 20 incidents
        self.assertEqual(sorted(g['unique_requests'] for g in same_ip),[6,6])
        self.assertEqual(sum(g['statuses'].get('401',0) for g in result['incidents']),63)
        self.assertEqual(sum(g['statuses'].get('404',0) for g in result['incidents']),54)

    def test_november_19_late_and_20_scoped_review_candidates(self):
        fixture=ROOT/'tests/fixtures'
        for name,expected in [('nginx-skanery.conf',(5,6)),
                              ('nginx-dev-honeypot.conf',(4,6))]:
            cfg=configparser.ConfigParser()
            cfg.read(ROOT/'fail2ban/filter.d'/name)
            pat=re.compile(cfg.get('Definition','failregex').replace('<HOST>',
                           r'(?P<host>[0-9.]+)'))
            for file,count in [('november-19-late-malicious.log',expected[0]),
                               ('november-20-malicious.log',expected[1])]:
                lines=(fixture/file).read_text().splitlines()
                self.assertEqual(sum(bool(pat.search(line)) for line in lines),count,
                                 (name,file))
            for target in ['/wp-load.php','/wp-content/uploads/',
                           '//wp-includes/l10n/','/site.zip']:
                sample=('198.51.100.27 - - [19/Nov/2026:16:46:41 +0100] '
                        '"GET '+target+' HTTP/1.1" 404 0 "-" "synthetic"')
                self.assertIsNone(pat.search(sample),(name,target))
        rows=[row.split('|',3)[:3]+row.split('|',3)[3].rsplit('|',1)
              for row in (ROOT/'rules/candidates.list').read_text().splitlines()
              if row and not row.startswith('#')]
        candidates={row[0]:row for row in rows}
        for name,path in [('wordpress-xserver-php','/wp-xserver.php?p='),
                          ('wordpress-double-slash-l10n','//wp-includes/l10n/'),
                          ('site-zip-archive','/site.zip'),
                          ('sendgrid-env','/sendgrid.env')]:
            self.assertEqual(candidates[name][1],'REVIEW')
            self.assertIsNotNone(re.search(candidates[name][3],path),name)

    def test_november_21_two_jails_same_six_events(self):
        import json
        base=ROOT/'tests/fixtures'
        alerts=json.loads((base/'november-21-alerts-sanitized.json').read_text())
        self.assertEqual(len(alerts),2)
        report=correlate.brief(correlate.correlation(alerts))
        self.assertEqual((report['raw_alerts'],report['parent_incidents'],
                          report['sampled_requests_in_alerts'],report['unique_http_events'],
                          report['unique_paths']),(2,1,12,6,6))
        incident=report['incidents'][0]
        self.assertEqual(incident['jails'],['nginx-dev-honeypot','nginx-skanery'])
        self.assertEqual(incident['statuses'],{'404':6})
        self.assertEqual(incident['status_transitions'],[])
        nov20=json.loads((base/'november-20-alerts-sanitized.json').read_text())
        self.assertNotEqual(nov20[0]['ip'],alerts[0]['ip'])
        self.assertEqual({row['path'] for row in nov20[0]['events']},
                         {row['path'] for row in alerts[0]['events']})
        separate=correlate.brief(correlate.correlation(nov20+alerts))
        self.assertEqual((separate['raw_alerts'],separate['parent_incidents'],
                          separate['unique_http_events']),(3,2,12))

    def test_november_21_filter_samples_and_full_incident_totals(self):
        import json
        base=ROOT/'tests/fixtures'
        lines=(base/'november-21-malicious.log').read_text().splitlines()
        self.assertEqual(len(lines),6)
        for name in update.FILTERS:
            cfg=configparser.ConfigParser()
            cfg.read(ROOT/'fail2ban/filter.d'/name)
            pattern=re.compile(cfg.get('Definition','failregex').replace('<HOST>',
                               r'(?P<host>[0-9.]+)'))
            self.assertEqual(sum(bool(pattern.search(line)) for line in lines),6,name)
        sources=['november-18-all-alerts-sanitized.json',
                 'november-19-all-alerts-sanitized.json',
                 'november-20-alerts-sanitized.json',
                 'november-21-alerts-sanitized.json']
        alerts=[a for source in sources for a in json.loads((base/source).read_text())]
        full=correlate.brief(correlate.correlation(alerts))
        self.assertEqual((full['raw_alerts'],full['parent_incidents'],
                          full['sampled_requests_in_alerts'],full['unique_http_events'],
                          full['unique_paths']),(25,13,150,123,123))
        self.assertEqual(sum(g['statuses'].get('401',0) for g in full['incidents']),63)
        self.assertEqual(sum(g['statuses'].get('404',0) for g in full['incidents']),60)

if __name__=='__main__':
    unittest.main(verbosity=2)
