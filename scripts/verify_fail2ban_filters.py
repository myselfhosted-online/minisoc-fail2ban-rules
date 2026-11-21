#!/usr/bin/env python3
"""Real fail2ban-regex integration: positive and negative fixtures, not exit code alone."""
from __future__ import annotations
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
ANSI=re.compile(r'\x1b\[[0-9;]*m')
SUMMARY=re.compile(r'Lines:\s*\d+\s+lines,\s*\d+\s+ignored,\s*(\d+)\s+matched',re.I)


def verify(log:Path, filt:Path, *, expected_min:int=0, expected_max:int|None=None)->int:
    cmd=['fail2ban-regex',str(log),str(filt)]
    p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,check=False)
    output=ANSI.sub('',p.stdout)
    if p.returncode:
        raise RuntimeError(f'fail2ban-regex error {p.returncode} ({filt.name}):\n{output[-4000:]}')
    result=SUMMARY.search(output)
    if not result:
        raise RuntimeError(f'Cannot parse fail2ban-regex matched-line summary for {filt.name}:\n{output[-3000:]}')
    matched=int(result.group(1))
    if matched<expected_min or (expected_max is not None and matched>expected_max):
        raise RuntimeError(f'{filt.name} matched {matched} lines in {log.name}, expected between {expected_min} and {expected_max};\n{output[-3000:]}')
    print(f'PASS {filt.name} {log.name}: {matched} matched lines')
    return matched


def main()->int:
    arg=argparse.ArgumentParser()
    arg.add_argument('--filter-dir',type=Path,default=Path('/etc/fail2ban/filter.d'))
    arg.add_argument('--log',type=Path,help='optional real Nginx log (parsing only, no expected matches)')
    args=arg.parse_args()
    if not shutil.which('fail2ban-regex'):
        print('ERROR: fail2ban-regex unavailable, cannot claim integration test passed',file=sys.stderr)
        return 1
    fixtures=ROOT/'tests'/'fixtures'
    filters={'nginx-skanery.conf':{'legacy':9,'nov18':10,'afternoon':25,'evening':20,'nov19':4,'nov19late':5,'nov20':6,'nov21':6},
             'nginx-dev-honeypot.conf':{'legacy':5,'nov18':9,'afternoon':22,'evening':19,'nov19':4,'nov19late':4,'nov20':6,'nov21':6}}
    for name,expected in filters.items():
        path=args.filter_dir/name
        verify(fixtures/'november-2026-malicious.log',path,
               expected_min=expected['legacy'],expected_max=expected['legacy'])
        verify(fixtures/'november-18-malicious.log',path,
               expected_min=expected['nov18'],expected_max=expected['nov18'])
        verify(fixtures/'november-18-afternoon-malicious.log',path,
               expected_min=expected['afternoon'],expected_max=expected['afternoon'])
        verify(fixtures/'november-18-evening-malicious.log',path,
               expected_min=expected['evening'],expected_max=expected['evening'])
        verify(fixtures/'november-19-malicious.log',path,
               expected_min=expected['nov19'],expected_max=expected['nov19'])
        verify(fixtures/'november-19-late-malicious.log',path,
               expected_min=expected['nov19late'],expected_max=expected['nov19late'])
        verify(fixtures/'november-20-malicious.log',path,
               expected_min=expected['nov20'],expected_max=expected['nov20'])
        verify(fixtures/'november-21-malicious.log',path,
               expected_min=expected['nov21'],expected_max=expected['nov21'])
        verify(fixtures/'november-2026-benign.log',path,expected_min=0,expected_max=0)
        if args.log:
            verify(args.log,path,expected_min=0)
    return 0

if __name__=='__main__':
    try:
        raise SystemExit(main())
    except (OSError,RuntimeError) as exc:
        print('ERROR:',exc,file=sys.stderr)
        raise SystemExit(1)
