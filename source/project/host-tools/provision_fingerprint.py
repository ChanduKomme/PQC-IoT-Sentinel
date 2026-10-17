#!/usr/bin/env python3
"""Pin the receiver fingerprint while preserving the current crypto profile and identity."""
import argparse,ipaddress,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools'))
from project_config import atomic_write,uint32
DEFAULT=ROOT/'sender/sender/include/security_profile.h'
def normalize_fingerprint(value):
    text=re.sub(r'[\s:]','',value)
    if not re.fullmatch(r'[0-9A-Fa-f]{64}',text) or int(text,16)==0:raise ValueError('fingerprint must be 64 nonzero hexadecimal digits; spaces/colons are allowed')
    return text.upper()
def patch_header(text,fingerprint,ip,sender_id=None,discovery=False):
    if sender_id is not None:
        text,n=re.subn(r'(#define PQC_SENDER_ID)\s+0x[0-9A-Fa-f]+u',lambda m:f'{m[1]} 0x{sender_id:08X}u',text)
        if n!=1:raise ValueError('sender ID define missing or duplicated')
    for name,value in [('PQC_GATEWAY_STATIC_IP',f'"{ip}"'),('PQC_ALLOW_BROADCAST_DISCOVERY',f'{int(discovery)}u')]:
        text,n=re.subn(r'(#define '+name+r')\s+[^\n]+',lambda m:m[1]+' '+value,text)
        if n!=1:raise ValueError(name+' missing or duplicated')
    arr=','.join('0x'+fingerprint[i:i+2] for i in range(0,64,2))
    text,n=re.subn(r'(kProvisionedGatewayPkFingerprint\[PQC_PK_FINGERPRINT_LEN\]\s*=\s*)\{.*?\};',lambda m:m[1]+'{'+arr+'};',text,flags=re.S)
    if n!=1:raise ValueError('fingerprint array missing or duplicated')
    return text
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--fingerprint-hex',required=True);ap.add_argument('--gateway-ip',required=True)
    ap.add_argument('--sender-id',help='Normally omit: preserve the enrolled identity');ap.add_argument('--out','--output',type=Path,default=DEFAULT)
    ap.add_argument('--allow-discovery',action='store_true');a=ap.parse_args()
    try:
        fp=normalize_fingerprint(a.fingerprint_hex);ip=str(ipaddress.IPv4Address(a.gateway_ip)) if a.gateway_ip else ''
        if not ip and not a.allow_discovery:raise ValueError('set an IPv4 address or explicitly allow discovery')
        sid=uint32(int(a.sender_id,0),'sender_id') if a.sender_id else None
        text=(a.out if a.out.exists() else DEFAULT).read_text()
        keyfile=a.out.with_name('sender_auth_key.h')
        if sid and keyfile.exists():
            match=re.search(r'#define PQC_CREDENTIAL_SENDER_ID\s+(0x[0-9a-fA-F]+)u',keyfile.read_text())
            if match and int(match[1],16)!=sid:raise ValueError('ID conflicts with provisioned key; enroll the intended slot first')
        atomic_write(a.out,patch_header(text,fp,ip,sid,a.allow_discovery))
        print(f'Pinned receiver fingerprint in {a.out}; rebuild and flash sender.');return 0
    except (ValueError,OSError) as e:print(f'ERROR: {e}',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
