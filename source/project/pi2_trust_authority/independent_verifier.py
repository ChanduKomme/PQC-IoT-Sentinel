#!/usr/bin/env python3
"""Verify exact event counts for one experiment; absence alone is not resistance evidence."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from evidence import read_events,unique_events
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--experiment-id',required=True);ap.add_argument('--event',required=True)
    ap.add_argument('--expected-min',type=int,default=1);ap.add_argument('--expected-max',type=int);ap.add_argument('--receiver-log',type=Path);ap.add_argument('--splunk-csv',type=Path)
    ap.add_argument('--device-id');ap.add_argument('--out',type=Path,required=True);a=ap.parse_args()
    try:
        if a.expected_min<0 or (a.expected_max is not None and a.expected_max<a.expected_min):raise ValueError('invalid count range')
        checks={}
        for name,path in [('receiver_log',a.receiver_log),('splunk_csv',a.splunk_csv)]:
            if path is None:continue
            rows=[r for r in unique_events(read_events(path)) if r['origin']=='firmware' and r['role']=='gateway' and r['experiment_id']==a.experiment_id and (not a.device_id or r['device_id']==a.device_id)]
            if not rows:raise ValueError(name+': no matching gateway evidence; result is inconclusive')
            count=sum(r['event_type']==a.event for r in rows)
            checks[name]={'matching_evidence':len(rows),'count':count,'pass':count>=a.expected_min and (a.expected_max is None or count<=a.expected_max)}
        if not checks:raise ValueError('provide receiver-log and/or splunk-csv')
        result={'experiment_id':a.experiment_id,'event':a.event,'expected_min':a.expected_min,'expected_max':a.expected_max,'checks':checks,'pass':all(c['pass'] for c in checks.values()),'scope':'event counts only; campaign completeness and physical resistance are not established'}
        a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));return 0 if result['pass'] else 1
    except (ValueError,OSError,json.JSONDecodeError) as e:print(f'INCONCLUSIVE: {e}',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
