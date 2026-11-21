#!/usr/bin/env python3
"""Sanitized alert-only parent incident grouping, not a complete access-log audit.

Group alert bursts by source IP and overlapping request time windows. Dedupe
HTTP events by IP, event timestamp, method, request target, and status; jail and
claimed User-Agent are *not* independent incidents. Never ban based on ASN/UA.
"""
import argparse
from datetime import datetime, timedelta
import json
from pathlib import Path
import re
from urllib.parse import unquote


def diagnostic_path(target: str) -> str:
    """Canonicalize only for reporting; never use this as a ban condition.

    Retain the raw request target in evidence and matching. At most two URL
    decoding passes identify obfuscated dots, and only harmless '/./' segments
    are collapsed; parent-directory traversal is never resolved away.
    """
    path = target.split('?', 1)[0]
    for _ in range(2):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    return re.sub(r'/\./', '/', path)


def correlation(alerts: list[dict], window_seconds: int=60) -> list[dict]:
    incidents=[]
    for alert in alerts:
        ip=alert['ip']
        events=[]
        for item in alert['events']:
            instant=datetime.fromisoformat(item['time'])
            events.append({**item,'instant':instant,'method':item.get('method','GET').upper()})
        if not events:
            continue
        start=min(e['instant'] for e in events)
        end=max(e['instant'] for e in events)
        matching=[]
        for group in incidents:
            if group['ip']==ip and not (start>group['end']+timedelta(seconds=window_seconds) or
                                        end<group['start']-timedelta(seconds=window_seconds)):
                matching.append(group)
        if matching:
            target=matching[0]
            for other in matching[1:]:
                target['events'].update(other['events'])
                target['jails'].update(other['jails'])
                target['alerts']+=other['alerts']
                target['sampled_requests']+=other['sampled_requests']
                target['start']=min(target['start'],other['start'])
                target['end']=max(target['end'],other['end'])
                incidents.remove(other)
        else:
            target={'ip':ip,'start':start,'end':end,'events':{},'jails':set(),
                    'alerts':0,'sampled_requests':0}
            incidents.append(target)
        target['start']=min(target['start'],start)
        target['end']=max(target['end'],end)
        target['jails'].add(alert['jail'])
        target['alerts']+=1
        target['sampled_requests']+=len(events)
        for event in events:
            # Duplicate jail alerts show the same request event, possibly with UA redaction.
            key=(event['instant'].isoformat(),event['method'],event['path'],int(event['status']))
            target['events'][key]=event
    return sorted(incidents,key=lambda x:(x['start'],x['ip']))


def diagnostics(group: dict, window_seconds: int=60) -> dict:
    events=list(group['events'].values())
    variants={}
    changes={}
    for event in events:
        raw=event['path'].split('?',1)[0]
        variants.setdefault(diagnostic_path(raw),set()).add(raw)
        changes.setdefault(raw,[]).append(event)
    normalized_variants=[{'canonical_path':path,'raw_paths':sorted(raw_paths)}
                         for path,raw_paths in sorted(variants.items()) if len(raw_paths)>1]
    status_transitions=[]
    for path,items in sorted(changes.items()):
        ordered=sorted(items,key=lambda e:e['instant'])
        for left,right in zip(ordered,ordered[1:]):
            if (int(left['status'])!=int(right['status']) and
                right['instant']-left['instant']<=timedelta(seconds=window_seconds)):
                status_transitions.append({'path':path,'from':int(left['status']),
                                           'to':int(right['status']),
                                           'seconds':(right['instant']-left['instant']).total_seconds()})
    return {'unique_paths':len(changes),'normalized_variants':normalized_variants,
            'status_transitions':status_transitions}


def brief(groups:list[dict]) -> dict:
    return {'parent_incidents':len(groups),
            'raw_alerts':sum(g['alerts'] for g in groups),
            'sampled_requests_in_alerts':sum(g['sampled_requests'] for g in groups),
            'unique_http_events':sum(len(g['events']) for g in groups),
            'unique_paths':sum(diagnostics(g)['unique_paths'] for g in groups),
            'incidents':[{'source':g['ip'],'jails':sorted(g['jails']),
                          'alerts':g['alerts'],
                          'sampled_requests_in_alerts':g['sampled_requests'],
                          'unique_requests':len(g['events']),
                          **diagnostics(g),
                          'statuses':{str(s):sum(1 for e in g['events'].values() if int(e['status'])==s)
                                      for s in sorted({int(e['status']) for e in g['events'].values()})}}
                         for g in groups]}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('json_file',type=Path)
    args=parser.parse_args()
    alerts=json.loads(args.json_file.read_text(encoding='utf-8'))
    print(json.dumps(brief(correlation(alerts)),indent=2,ensure_ascii=False))

if __name__=='__main__':
    main()
