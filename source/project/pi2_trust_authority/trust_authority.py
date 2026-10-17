#!/usr/bin/env python3
"""Offline registry. Credentials remain local; no online authority service is implied."""
import argparse,json,secrets,sys,time,os
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from project_config import atomic_write,validate_registry,uint32
DEFAULT=Path(__file__).resolve().parent/'state/device_registry.json'

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--state',type=Path,default=DEFAULT)
    sub=ap.add_subparsers(dest='cmd',required=True);sub.add_parser('init');sub.add_parser('list')
    p=sub.add_parser('enroll');p.add_argument('--slot',type=int,required=True);p.add_argument('--sender-id',required=True);p.add_argument('--name',required=True)
    p=sub.add_parser('revoke');p.add_argument('--slot',type=int,required=True);p.add_argument('--reason',default='operator_revocation')
    p=sub.add_parser('rotate');p.add_argument('--slot',type=int,required=True)
    a=ap.parse_args();lock=a.state.with_suffix('.lock'); acquired=False
    try:
        a.state.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.close(fd);acquired=True
        data=validate_registry(json.loads(a.state.read_text())) if a.state.exists() else {'version':1,'devices':[],'events':[]}
        if a.cmd=='list':
            for d in sorted(data['devices'],key=lambda d:d['slot']):
                print(f"slot={d['slot']} id=0x{d['sender_id']:08X} name={d['name']} status={d['status']} generation={d['generation']}")
            return 0
        now=int(time.time())
        if a.cmd=='enroll':
            if any(d['slot']==a.slot for d in data['devices']):raise ValueError('slot already enrolled; use rotate, which increments generation')
            data['devices'].append({'slot':a.slot,'sender_id':int(a.sender_id,0),'name':a.name,'status':'active','generation':1,'auth_key_hex':secrets.token_hex(32),'updated_at':now})
        elif a.cmd in ('revoke','rotate'):
            d=next((d for d in data['devices'] if d['slot']==a.slot),None)
            if d is None:raise ValueError('unknown slot')
            d['updated_at']=now
            if a.cmd=='revoke':d['status']='revoked'
            else:
                d['generation']=uint32(d['generation']+1,'generation');d['auth_key_hex']=secrets.token_hex(32);d['status']='active'
        if a.cmd!='init': data.setdefault('events',[]).append({'event':a.cmd,'slot':a.slot,'time':now,'reason':getattr(a,'reason','')})
        validate_registry(data);atomic_write(a.state,json.dumps(data,indent=2)+'\n')
        print(f'{a.cmd}: saved {a.state}; secret values are not printed');return 0
    except (ValueError,OSError,json.JSONDecodeError) as e:
        print(f'ERROR: {e}',file=sys.stderr);return 2
    finally:
        if acquired:lock.unlink(missing_ok=True)
if __name__=='__main__':raise SystemExit(main())
