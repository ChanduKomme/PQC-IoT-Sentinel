#!/usr/bin/env python3
"""Classify operator-recorded outcomes; empty or incomplete campaigns cannot pass."""
import argparse,csv,json,sys
from pathlib import Path
REQUIRED=('trial','boot_ok','auth_bypass','secret_exposed','reset_detected')
def boolean(v):
    text=str(v).strip().lower()
    if text in ('1','true','yes'):return True
    if text in ('0','false','no'):return False
    raise ValueError('boolean cells must be 0/1, true/false, or yes/no')
def analyze(rows):
    if not rows:raise ValueError('campaign is empty')
    seen=set();counts={k:0 for k in REQUIRED[1:]}
    for row in rows:
        if any(k not in row for k in REQUIRED) or not row['trial'] or row['trial'] in seen:raise ValueError('missing column or empty/duplicate trial')
        seen.add(row['trial'])
        for k in counts:counts[k]+=boolean(row[k])
    return {'trials':len(rows),**counts,'security_result':'FAIL' if counts['auth_bypass'] or counts['secret_exposed'] else 'NO_BYPASS_OBSERVED','scope':'operator-recorded outcomes only; no certification or untested-parameter claim'}
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('csv',type=Path);ap.add_argument('--out',type=Path);ap.add_argument('--expected-trials',type=int);a=ap.parse_args()
    try:
        with a.csv.open(newline='') as f:result=analyze(list(csv.DictReader(f)))
        if a.expected_trials is not None and (a.expected_trials<1 or result['trials']!=a.expected_trials):raise ValueError('recorded trial count differs from expected campaign size')
        text=json.dumps(result,indent=2)+'\n'
        if a.out:a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(text)
        print(text,end='');return 1 if result['security_result']=='FAIL' else 0
    except (ValueError,OSError) as e:print(f'INVALID: {e}',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
