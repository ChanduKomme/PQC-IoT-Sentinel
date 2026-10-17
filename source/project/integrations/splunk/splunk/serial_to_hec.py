#!/usr/bin/env python3
"""Forward captured firmware JSONL to Splunk HEC; never synthesize board events."""
import argparse,json,os,ssl,sys,urllib.request,urllib.parse
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools'))
from evidence import read_events,unique_events
from project_config import read_env
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--input',type=Path,required=True);ap.add_argument('--env-file',type=Path,default=ROOT/'.env')
    ap.add_argument('--dry-run',action='store_true');ap.add_argument('--ca-file');a=ap.parse_args()
    try:
        rows=unique_events(read_events(a.input))
        if not rows or any(r['origin']!='firmware' for r in rows):raise ValueError('input must contain firmware-origin events')
        if a.dry_run:print(f'Validated {len(rows)} unique events; no network requests sent');return 0
        cfg=read_env(a.env_file);cfg.update({k:v for k,v in os.environ.items() if k.startswith('SPLUNK_')})
        url=cfg.get('SPLUNK_HEC_URL','').rstrip('/');token=cfg.get('SPLUNK_HEC_TOKEN','')
        parsed=urllib.parse.urlsplit(url)
        if parsed.scheme!='https':raise ValueError('SPLUNK_HEC_URL must use HTTPS; configure a trusted certificate')
        if not token or token.startswith('YOUR_'):raise ValueError('configure SPLUNK_HEC_TOKEN')
        endpoint=url if parsed.path.endswith('/services/collector/event') else url+'/services/collector/event'
        context=ssl.create_default_context(cafile=a.ca_file or cfg.get('SPLUNK_CA_FILE') or None)
        for row in rows:
            body={'index':cfg.get('SPLUNK_INDEX','pqc_iot'),'source':'pqc_serial_capture','sourcetype':'pqc:iot:event','event':row}
            req=urllib.request.Request(endpoint,data=json.dumps(body).encode(),headers={'Authorization':'Splunk '+token,'Content-Type':'application/json'})
            with urllib.request.urlopen(req,context=context,timeout=10) as response:
                result=json.load(response)
                if result.get('code')!=0:raise ValueError('HEC rejected an event: '+str(result.get('code')))
        print(f'Forwarded {len(rows)} events. Deduplicate event_id in searches if this capture is uploaded again.');return 0
    except (ValueError,OSError,json.JSONDecodeError) as e:print(f'ERROR: {e}',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
