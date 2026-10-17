#!/usr/bin/env python3
from __future__ import annotations
import argparse,csv,math,re,statistics
from datetime import datetime
from pathlib import Path

STAMP=re.compile(r'^\[(?P<ts>\d{4}-\d{2}-\d{2}T[^\]]+)\]\s*(?P<body>.*)$')
KV=re.compile(r'([A-Za-z_][A-Za-z0-9_-]*)=([^\s,;]+)')

def kvs(s): return {k.lower().replace('-','_'):v.strip('[](){}<>\"\'') for k,v in KV.findall(s)}
def num(v):
    try:return float(str(v).rstrip('Bbms'))
    except:return None

def first(d,*names):
    for n in names:
        v=num(d.get(n))
        if v is not None:return v
    return None

def read(path):
    entries=[]; stamps=[]; elapsed=None
    for raw in Path(path).read_text(encoding='utf-8',errors='replace').splitlines():
        body=raw; m=STAMP.match(raw)
        if m:
            body=m.group('body')
            try:stamps.append(datetime.fromisoformat(m.group('ts')))
            except:pass
        if raw.startswith('#') and 'elapsed_seconds=' in raw:
            try:elapsed=float(kvs(raw)['elapsed_seconds'])
            except:pass
        entries.append((body,kvs(body)))
    if elapsed is None and len(stamps)>1:elapsed=(max(stamps)-min(stamps)).total_seconds()
    return entries,elapsed or 0

def desc(v):
    if not v:return {k:math.nan for k in ('mean','median','sd','min','max','p95','p99')}
    s=sorted(v)
    def pct(q):
        p=(len(s)-1)*q; lo=math.floor(p); hi=math.ceil(p)
        return s[lo] if lo==hi else s[lo]+(s[hi]-s[lo])*(p-lo)
    return {'mean':statistics.fmean(v),'median':statistics.median(v),'sd':statistics.stdev(v) if len(v)>1 else 0,
            'min':min(v),'max':max(v),'p95':pct(.95),'p99':pct(.99)}
def mode(v):
    if not v:return math.nan
    try:return float(statistics.mode(v))
    except:return float(v[0])
def success(d,default=True):
    for k in ('success','ok','accepted','delivered','decrypted'):
        if k in d:return d[k].lower() in ('1','true','yes','ok','success')
    if 'status' in d:return d['status'].lower() in ('0','ok','success','accepted')
    return default

def f(v):
    if v is None:return ''
    if isinstance(v,float):return '' if math.isnan(v) else f'{v:.3f}'
    return str(v)

def classify(profile,body,d):
    b=body.lower(); path=d.get('path','').lower(); prof=d.get('profile','').lower()
    if profile=='plain':return '[plain_bench]' in b or path in ('plain','plain_coap') or prof in ('plain','plain_coap') or ('[baseline]' in b and 'ecdh' not in b)
    if profile=='classical':return '[classical_bench]' in b or path in ('classical','ecdh','ecdh_aes') or 'ecdh' in b
    if profile=='pqc':return '[bench]' in b and (path=='pqc' or 'kem_ms' in d or 'protected_payload_len' in d)
    if profile=='dtls':return '[dtls_bench]' in b
    return False

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--profile',choices=('plain','classical','dtls','pqc'),required=True)
    ap.add_argument('--sender-log',required=True); ap.add_argument('--receiver-log',required=True); ap.add_argument('--out-dir',required=True)
    a=ap.parse_args(); se,sd=read(a.sender_log); re_,rd=read(a.receiver_log); duration=max(sd,rd)
    srows=[(b,d) for b,d in se if classify(a.profile,b,d)]; rrows=[(b,d) for b,d in re_ if classify(a.profile,b,d)]
    rtt=[]; process=[]; app=[]; wire=[]; keys=[]; samples=[]; sok=sf=rok=rf=0; extra={}
    if a.profile=='plain':
        for b,d in srows:
            x=first(d,'rtt_ms','round_trip_ms','latency_ms','total_ms')
            if x is None:continue
            rtt.append(x); ok=success(d); sok+=ok; sf+=not ok
            if (x:=first(d,'app_payload_len','payload_len','plaintext_len','app_len')) is not None:app.append(x)
            if (x:=first(d,'wire_len','coap_wire_len','packet_len','coap_len')) is not None:wire.append(x)
            samples.append({'role':'sender',**d})
        for b,d in rrows:
            x=first(d,'process_ms','recv_ms','receive_ms','rx_ms','latency_ms')
            if x is None:continue
            process.append(x); ok=success(d); rok+=ok; rf+=not ok; samples.append({'role':'receiver',**d})
        name='Plain CoAP'
    elif a.profile=='classical':
        detail={k:[] for k in ('s_keygen','s_shared','s_hkdf','s_aes','r_shared','r_hkdf','r_aes')}
        for b,d in srows:
            rt=first(d,'rtt_ms','round_trip_ms','latency_ms','total_ms'); kg=first(d,'ecdh_keygen_ms','keygen_ms','ec_keygen_ms'); sh=first(d,'ecdh_shared_ms','shared_ms','ecdh_ms','secret_ms'); hk=first(d,'hkdf_ms','kdf_ms'); ae=first(d,'aead_ms','aes_ms','encrypt_ms','enc_ms')
            for k,x in (('s_keygen',kg),('s_shared',sh),('s_hkdf',hk),('s_aes',ae)):
                if x is not None:detail[k].append(x)
            p=[x for x in (kg,sh,hk) if x is not None]
            if p:keys.append(sum(p))
            if rt is not None:rtt.append(rt); ok=success(d); sok+=ok; sf+=not ok
            if (x:=first(d,'app_payload_len','payload_len','plaintext_len','app_len')) is not None:app.append(x)
            if (x:=first(d,'wire_len','coap_wire_len','packet_len','coap_len')) is not None:wire.append(x)
            samples.append({'role':'sender',**d})
        for b,d in rrows:
            pr=first(d,'process_ms','recv_ms','receive_ms','rx_ms','latency_ms'); sh=first(d,'ecdh_shared_ms','shared_ms','ecdh_ms','secret_ms'); hk=first(d,'hkdf_ms','kdf_ms'); ae=first(d,'aead_ms','aes_ms','decrypt_ms','dec_ms')
            for k,x in (('r_shared',sh),('r_hkdf',hk),('r_aes',ae)):
                if x is not None:detail[k].append(x)
            if pr is not None:process.append(pr); ok=success(d); rok+=ok; rf+=not ok
            samples.append({'role':'receiver',**d})
        extra={k+'_mean_ms':desc(v)['mean'] for k,v in detail.items()}; name='Classical P-256 ECDH + HKDF-SHA-256 + AES-CCM over CoAP'
    elif a.profile=='dtls':
        sh=[]; rh=[]
        for b,d in se:
            if '[DTLS_HANDSHAKE]' in b and success(d) and (x:=first(d,'handshake_ms')) is not None:sh.append(x)
        for b,d in re_:
            if '[DTLS_HANDSHAKE]' in b and success(d) and (x:=first(d,'handshake_ms')) is not None:rh.append(x)
        keys=sh
        for b,d in srows:
            x=first(d,'rtt_ms'); ok=success(d); sok+=ok; sf+=not ok
            if x is not None:rtt.append(x)
            if (x:=first(d,'app_payload_len','payload_len')) is not None:app.append(x)
            if (x:=first(d,'estimated_dtls_record_len','wire_len','coap_len')) is not None:wire.append(x)
            samples.append({'role':'sender',**d})
        for b,d in rrows:
            x=first(d,'process_ms'); ok=success(d); rok+=ok; rf+=not ok
            if x is not None:process.append(x)
            samples.append({'role':'receiver',**d})
        extra={'sender_handshakes':len(sh),'receiver_handshakes':len(rh),'receiver_handshake_mean_ms':desc(rh)['mean']}; name='DTLS 1.2 + ECDHE P-256 + ECDSA + AES-256-CCM'
    else:
        ks=[]; kh=[]; ka=[]; rs=[]; rh=[]; ra=[]; protected=[]
        for b,d in srows:
            for arr,names in ((ks,('kem_ms',)),(kh,('hkdf_ms',)),(ka,('aead_ms','aes_ms'))):
                if (x:=first(d,*names)) is not None:arr.append(x)
            if (x:=first(d,'plaintext_len','app_payload_len','payload_len')) is not None:app.append(x)
            if (x:=first(d,'coap_wire_len','wire_len','coap_len')) is not None:wire.append(x)
            if (x:=first(d,'protected_payload_len','protected_len')) is not None:protected.append(x)
            samples.append({'role':'sender',**d})
        for b,d in rrows:
            for arr,names in ((rs,('kem_ms',)),(rh,('hkdf_ms',)),(ra,('aead_ms','aes_ms'))):
                if (x:=first(d,*names)) is not None:arr.append(x)
            samples.append({'role':'receiver',**d})
        keys=[x+y for x,y in zip(ks,kh)] if ks and kh else ks
        sok=sum('msg_delivered' in b.lower() for b,d in se); rok=sum('msg_decrypted' in b.lower() for b,d in re_)
        fail=('pk_auth_fail','aead_auth_fail','sender_auth_fail','key_id_reject','timed out waiting','unable to resolve gateway','message delivery failed','kem decapsulation failed','hkdf failed','encrypt failed','decrypt failed')
        sf=sum(sum(m in b.lower() for m in fail) for b,d in se); rf=sum(sum(m in b.lower() for m in fail) for b,d in re_)
        if not wire:wire=protected
        extra={'sender_kem_mean_ms':desc(ks)['mean'],'sender_hkdf_mean_ms':desc(kh)['mean'],'sender_aes_mean_ms':desc(ka)['mean'],'receiver_kem_mean_ms':desc(rs)['mean'],'receiver_hkdf_mean_ms':desc(rh)['mean'],'receiver_aes_mean_ms':desc(ra)['mean'],'protected_payload_bytes':mode(protected)}; name='ML-KEM-512-style + HKDF-SHA-256 + AES-256-CCM over CoAP'
    kd=desc(keys); rt=desc(rtt); pr=desc(process); hours=duration/3600; total=sok+sf
    summary={'Profile':name,'Observed duration hours':hours,'Sender successful messages':int(sok),'Sender failed messages':int(sf),'Receiver successful messages':int(rok),'Receiver failed messages':int(rf),'Sender success rate percent':100*sok/total if total else math.nan,'Messages per hour':sok/hours if hours else math.nan,'Key or handshake mean ms':kd['mean'],'Key or handshake p95 ms':kd['p95'],'Sender RTT mean ms':rt['mean'],'Sender RTT median ms':rt['median'],'Sender RTT p95 ms':rt['p95'],'Sender RTT p99 ms':rt['p99'],'Sender RTT maximum ms':rt['max'],'Receiver processing mean ms':pr['mean'],'Receiver processing p95 ms':pr['p95'],'Application payload bytes':mode(app),'Wire or protected bytes':mode(wire),'Sender benchmark rows':len(srows),'Receiver benchmark rows':len(rrows),**extra}
    out=Path(a.out_dir); out.mkdir(parents=True,exist_ok=True)
    with (out/f'{a.profile}_10h_summary.csv').open('w',newline='',encoding='utf-8') as h:
        w=csv.writer(h); w.writerow(['Metric','Value']); [w.writerow([k,f(v)]) for k,v in summary.items()]
    if samples:
        fields=sorted({k for row in samples for k in row})
        with (out/f'{a.profile}_10h_samples.csv').open('w',newline='',encoding='utf-8') as h:
            w=csv.DictWriter(h,fieldnames=fields); w.writeheader(); w.writerows(samples)
    diag=[f'Parsed sender rows: {len(srows)}',f'Parsed receiver rows: {len(rrows)}',f'Observed duration hours: {hours:.3f}']
    if hours<9.5:diag.append('WARNING: duration below 9.5 hours')
    if sok==0:diag.append('ERROR: no successful sender messages found')
    if a.profile in ('plain','classical','dtls') and not rtt:diag.append('ERROR: no sender RTT values found')
    if a.profile=='pqc':diag.append('NOTE: current PQC firmware has no end-to-end rtt_ms field; RTT stays blank unless firmware is extended')
    (out/f'{a.profile}_diagnostics.txt').write_text('\n'.join(diag)+'\n',encoding='utf-8')
    md=['| Metric | Value |','|---|---:|']+[f'| {k} | {f(v)} |' for k,v in summary.items()]
    (out/f'{a.profile}_10h_summary.md').write_text('\n'.join(md)+'\n',encoding='utf-8')
    selected=('Observed duration hours','Sender successful messages','Sender failed messages','Sender success rate percent','Key or handshake mean ms','Sender RTT mean ms','Sender RTT p95 ms','Sender RTT p99 ms','Application payload bytes','Wire or protected bytes')
    def esc(s):return str(s).replace('&',r'\&').replace('_',r'\_').replace('%',r'\%')
    rows='\n'.join(f'{esc(k)} & {esc(f(summary[k]))} \\\\' for k in selected)
    tex='\\begin{table}[t]\n\\centering\n\\caption{Ten-hour '+esc(name)+' results.}\n\\label{tab:'+a.profile+'-10h}\n\\footnotesize\n\\begin{tabular}{p{0.66\\columnwidth}r}\n\\toprule\nMetric & Value \\\\ \n\\midrule\n'+rows+'\n\\bottomrule\n\\end{tabular}\n\\end{table}\n'
    (out/f'{a.profile}_10h_table.tex').write_text(tex,encoding='utf-8')
    print(f'[OK] {a.profile}: duration={hours:.3f}h sender_ok={sok} sender_fail={sf}')
if __name__=='__main__':main()
