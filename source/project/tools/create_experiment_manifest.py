#!/usr/bin/env python3
"""Record experiment intent plus hashes of supplied firmware and evidence files."""
import argparse,hashlib,json,platform,sys,time
from pathlib import Path
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--id',required=True);ap.add_argument('--profile',required=True);ap.add_argument('--messages',type=int,default=300)
    ap.add_argument('--notes',default='');ap.add_argument('--file',type=Path,action='append',default=[]);ap.add_argument('--out',type=Path,required=True);a=ap.parse_args()
    try:
        if a.messages<1:raise ValueError('messages must be positive')
        files=[{'name':p.name,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in a.file]
        obj={'experiment_id':a.id,'profile':a.profile,'planned_messages':a.messages,'created_unix':time.time(),'host':platform.platform(),'notes':a.notes,'files':files,'signed':False,'result':'planned; measurements must be supplied separately'}
        a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(obj,indent=2)+'\n');print(a.out);return 0
    except (ValueError,OSError) as e:print(f'ERROR: {e}',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
