#!/usr/bin/env python3
"""Provision validated per-device credentials; rebuild and flash after every change."""
import argparse,json,re,sys
from pathlib import Path
from project_config import atomic_write,validate_registry
ROOT=Path(__file__).resolve().parents[1]
def array(key):return ','.join(f'0x{b:02X}' for b in bytes.fromhex(key))
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--project-root',type=Path,default=ROOT)
    sub=ap.add_subparsers(dest='mode',required=True)
    s=sub.add_parser('sender');s.add_argument('--registry',type=Path,required=True);s.add_argument('--slot',type=int,required=True)
    r=sub.add_parser('receiver');r.add_argument('--registry',type=Path,required=True)
    a=ap.parse_args()
    try:
        devs=sorted(validate_registry(json.loads(a.registry.read_text()))['devices'],key=lambda d:d['slot'])
        if a.mode=='sender':
            d=next((d for d in devs if d['slot']==a.slot and d['status']=='active'),None)
            if d is None:raise ValueError('sender slot is missing or revoked')
            p=a.project_root/'sender/sender/include/security_profile.h';text=p.read_text()
            text,n=re.subn(r'#define PQC_SENDER_ID\s+0x[0-9A-Fa-f]+u',f'#define PQC_SENDER_ID 0x{d["sender_id"]:08X}u',text)
            if n!=1:raise ValueError('expected one PQC_SENDER_ID define')
            header=f"""#ifndef PQC_SENDER_AUTH_KEY_H
#define PQC_SENDER_AUTH_KEY_H
#include "security_profile.h"
#define PQC_CREDENTIAL_GENERATION {d['generation']}u
#define PQC_CREDENTIAL_SENDER_ID 0x{d['sender_id']:08X}u
#if PQC_CREDENTIAL_SENDER_ID != PQC_SENDER_ID
#error "Sender ID does not match the provisioned credential"
#endif
static const uint8_t kPqcSenderAuthKey[PQC_DEVICE_AUTH_KEY_LEN] = {{{array(d['auth_key_hex'])}}};
static inline int pqc_sender_auth_key_is_provisioned(void) {{
    uint8_t acc=0;for(size_t i=0;i<PQC_DEVICE_AUTH_KEY_LEN;i++)acc|=kPqcSenderAuthKey[i];return acc!=0;
}}
#endif
"""
            atomic_write(p,text);atomic_write(p.with_name('sender_auth_key.h'),header)
            print(f'Provisioned slot={a.slot} sender_id=0x{d["sender_id"]:08X} generation={d["generation"]}')
        else:
            if {d['slot'] for d in devs}!={1,2}:raise ValueError('enroll slots 1 and 2 first (unused slot may be revoked)')
            rows=['    {0x%08Xu,%uu,%uu,{%s}}' % (d['sender_id'],d['generation'],int(d['status']=='active'),array(d['auth_key_hex'])) for d in devs]
            header = ('#ifndef PQC_SENDER_AUTH_REGISTRY_H\n#define PQC_SENDER_AUTH_REGISTRY_H\n'
                      '#include "security_profile.h"\n'
                      'typedef struct {uint32_t sender_id,generation;uint8_t enabled;uint8_t auth_key[32];} PqcProvisionedSender;\n'
                      'static const PqcProvisionedSender kPqcProvisionedSenders[PQC_MAX_AUTHORIZED_SENDERS] = {\n'
                      + ',\n'.join(rows) + '\n};\n#endif\n')
            atomic_write(a.project_root/'Receiver/Receiver/include/sender_auth_registry.h',header)
            print('Provisioned receiver registry; existing KEM key and matching-generation counters are retained')
        return 0
    except (ValueError,OSError,json.JSONDecodeError) as e:print(f'ERROR: {e}',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
