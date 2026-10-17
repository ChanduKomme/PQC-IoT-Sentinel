#!/usr/bin/env python3
"""Capture raw serial plus exact firmware JSON events; one capture process per port."""
import argparse,json,sys,time,uuid
from pathlib import Path
from evidence import parse_event
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--port',required=True);ap.add_argument('--baud',type=int,default=2000000)
    ap.add_argument('--seconds',type=float,default=120);ap.add_argument('--out-dir',type=Path,required=True);ap.add_argument('--experiment-id',required=True);a=ap.parse_args()
    if a.seconds<=0 or a.baud<=0:ap.error('seconds and baud must be positive')
    try:import serial
    except ImportError:print('Install: python3 -m pip install -r requirements-host.txt',file=sys.stderr);return 2
    a.out_dir.mkdir(parents=True,exist_ok=True)
    if any(a.out_dir.iterdir()):ap.error('out-dir must be empty to avoid mixing captures')
    capture=uuid.uuid4().hex;count=0;invalid=0;start=time.monotonic()
    with (a.out_dir/'serial.log').open('w') as raw,(a.out_dir/'events.jsonl').open('w') as events,serial.Serial(a.port,a.baud,timeout=0.5) as port:
        print('Capturing; reset the board now if boot evidence is needed. Ctrl+C stops cleanly.',flush=True)
        try:
            while time.monotonic()-start<a.seconds:
                chunk=port.read_until(b'\n',size=8192)
                if not chunk:continue
                line=chunk.decode('utf-8',errors='replace').rstrip('\r\n');raw.write(line+'\n');raw.flush()
                try:obj=parse_event(line)
                except ValueError:invalid+=1;continue
                if obj is None:continue
                if obj['experiment_id']!=a.experiment_id:
                    invalid+=1;print('Event experiment_id differs from capture; rebuild with matching PQC_EXPERIMENT_ID',file=sys.stderr);continue
                count+=1;obj.update(event_id=f'{capture}:{count}',capture_id=capture,captured_unix=time.time(),capture_origin='serial_host')
                events.write(json.dumps(obj,separators=(',',':'))+'\n');events.flush()
        except KeyboardInterrupt:pass
    summary={'capture_id':capture,'experiment_id':a.experiment_id,'duration_seconds':time.monotonic()-start,'events':count,'invalid_or_mismatched':invalid,'complete':invalid==0 and count>0}
    (a.out_dir/'capture_summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary))
    return 0 if summary['complete'] else 2
if __name__=='__main__':raise SystemExit(main())
