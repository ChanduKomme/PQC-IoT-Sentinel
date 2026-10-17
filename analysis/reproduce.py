#!/usr/bin/env python3
"""Reconstruct Version 1 counts, latency, continuity, retries and packet forwarding.

Python 3.10+, standard library only. Inputs are extracted public evidence, not
screenshots or dashboard totals. --check compares with the committed summary.
"""
import argparse
import collections
import csv
import datetime as dt
import hashlib
import json
import math
import re
import statistics
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIELDS = re.compile(r'(\w+)=([^\s]+)')

def kv(line):
    return dict(FIELDS.findall(line))

def percentile(values, p):
    values = sorted(values)
    n = (len(values) - 1) * p / 100
    lower = math.floor(n)
    return values[lower] + (values[min(lower + 1, len(values)-1)] - values[lower]) * (n-lower)

def stats(values):
    return dict(n=len(values), mean=statistics.mean(values), median=statistics.median(values),
                p95=percentile(values,95), p99=percentile(values,99), maximum=max(values))

def jsonl(path):
    with path.open() as file:
        for line in file:
            if line.strip():
                yield json.loads(line)

def event(line):
    if '[EVENT]' not in line:
        return None
    try:
        return json.loads(line[line.index('{'):].strip())
    except (ValueError, json.JSONDecodeError):
        return None

def identity(row):
    return tuple(int(row.get(key,0)) for key in ('sender_id','generation','sequence'))

def write_csv(path, rows):
    rows = list(rows)
    with path.open('w',newline='') as file:
        out = csv.DictWriter(file,fieldnames=list(rows[0]))
        out.writeheader()
        out.writerows(rows)

def primary(raw, out):
    pq = raw / 'PQC_24H_FINAL'
    benches=[]
    crypto=collections.defaultdict(list)
    for line in (pq/'sender/serial.log').open():
        if '[BENCH]' not in line:
            continue
        row=kv(line)
        if 'rtt_ms' in row:
            benches.append(row)
        for field in ('kem_ms','hkdf_ms','aead_ms'):
            if field in row:
                crypto[field].append(int(row[field]))
    events=list(jsonl(pq/'sender/events.jsonl'))
    delivered=[r for r in events if r['event_type']=='MSG_DELIVERED']
    receiver=collections.Counter(r['event_type'] for r in jsonl(pq/'receiver/events.jsonl'))
    pq_t=sorted(r['captured_unix'] for r in delivered)
    pq_rtt=[int(r['rtt_ms']) for r in benches if r.get('ok')=='1']
    pq_result=dict(profile='PQC',host_capture_seconds=json.loads((pq/'live_summary.json').read_text())['capture_uptime_seconds'],
                   delivered=len(delivered),failed=sum(r['event_type']=='SEND_FAILED' for r in events),
                   receiver_successes=receiver['MSG_DECRYPTED'],rtt_ms=stats(pq_rtt),
                   max_observed_delivery_gap_s=max(b-a for a,b in zip(pq_t,pq_t[1:])),
                   crypto_ms={key:stats(val) for key,val in crypto.items()})
    assert len(pq_rtt)==len(delivered), 'PQC raw BENCH count differs from structured successes'
    dtls=raw/'DTLS_24H_FINAL'
    role_data={}
    dt_times=[]
    dt_rtt=[]
    error_rows=[]
    for role in ('sender','receiver'):
        successes=failures=errors=0
        handshake=[]
        for line in (dtls/f'{role}.log').open():
            row=kv(line)
            if '[DTLS_BENCH]' in line:
                successes+=row.get('success')=='1'
                failures+=row.get('success')=='0'
                if role=='sender' and row.get('success')=='1':
                    dt_rtt.append(int(row['rtt_ms']))
                    stamp=re.match(r'\[([^]]+)\]',line)[1]
                    dt_times.append(dt.datetime.fromisoformat(stamp).timestamp())
            if '[DTLS_HANDSHAKE]' in line and row.get('success')=='1':
                handshake.append(int(row['handshake_ms']))
            if 'ssl_handshake failed rc=' in line:
                errors+=1
                error_rows.append(dict(role=role,timestamp=line.split(']')[0].lstrip('['),reason=line.split('[DTLS] ',1)[1].strip()))
        role_data[role]=dict(delivered=successes,failed=failures,successful_handshakes=len(handshake),
                             raw_handshake_errors=errors,successful_handshake_ms=stats(handshake))
    saved=json.loads((dtls/'analysis/dtls_baseline_summary.json').read_text())
    assert saved['sender_success']==len(dt_rtt)
    assert math.isclose(saved['rtt_ms']['mean'],statistics.mean(dt_rtt),abs_tol=1e-10)
    host=json.loads((dtls/'live_run_summary.json').read_text())
    dt_result=dict(profile='DTLS',host_capture_seconds=host['elapsed_seconds'],
                   delivered=len(dt_rtt),failed=role_data['sender']['failed'],receiver_successes=role_data['receiver']['delivered'],
                   rtt_ms=stats(dt_rtt),max_observed_delivery_gap_s=max(b-a for a,b in zip(dt_times,dt_times[1:])),roles=role_data,
                   structured_handshake_failures={role:host[role]['handshakes_failed'] for role in role_data})
    write_csv(out/'dtls_handshake_errors.csv',error_rows)
    write_csv(out/'rtt_samples.csv',({'profile':profile,'sample':i+1,'rtt_ms':v} for profile,vals in [('PQC',pq_rtt),('DTLS',dt_rtt)] for i,v in enumerate(vals)))
    rows=[]
    for profile,times in [('PQC',pq_t),('DTLS',dt_times)]:
        first=times[0]
        for hour in range(24):
            selected=[t for t in times if hour<=(t-first)/3600<hour+1]
            rows.append(dict(profile=profile,hour_from_first_delivery=hour,delivered=len(selected)))
    write_csv(out/'hourly_delivery.csv',rows)
    write_csv(out/'delivery_gaps.csv',({'profile':p,'hours_from_first_delivery':(b-ts[0])/3600,'gap_s':b-a} for p,ts in [('PQC',pq_t),('DTLS',dt_times)] for a,b in zip(ts,ts[1:])))
    return [pq_result,dt_result]

def packet_counts(path):
    """Read classic little-endian PCAP, Linux cooked-v2 (DLT 276), IPv4 UDP.

    Count observed packets before/after gateway forwarding. Capture-wide counts
    are not restricted to the selected 1,000-outcome application window.
    """
    counts=collections.Counter()
    with path.open('rb') as file:
        head=file.read(24)
        assert head[:4]==b'\xd4\xc3\xb2\xa1' and struct.unpack('<I',head[20:24])[0]==276, 'Unexpected PCAP format'
        while True:
            header=file.read(16)
            if not header:
                break
            assert len(header)==16, 'Truncated PCAP record header'
            length=struct.unpack('<IIII',header)[2]
            packet=file.read(length)
            assert len(packet)==length, 'Truncated PCAP packet'
            if len(packet)<48 or packet[:2]!=b'\x08\x00':
                continue
            ip=packet[20:]
            ihl=(ip[0]&15)*4
            if ip[9]!=17 or len(ip)<ihl+8 or struct.unpack('>H',ip[6:8])[0]&0x1fff:
                continue
            src,dst=struct.unpack('>HH',ip[ihl:ihl+4])
            direction='out' if packet[10]==4 else 'in'
            if dst==5683:
                counts['forward_'+direction]+=1
            elif src==5683:
                counts['reverse_'+direction]+=1
    return counts

def networks(raw,out):
    base=raw/'PQC_NETWORK_RESILIENCE_20260919'
    result=[]
    retry_rows=[]
    seals=[]
    for condition in sorted(base.glob('0[1-5]_*')):
        runs=sorted(p for p in condition.glob('*official*') if p.is_dir() and p.name!='random_loss_10pct_official_20260926T233003Z')
        assert len(runs)==1, f'Expected one official run in {condition}'
        run=runs[0]
        window=run/'analysis_window'
        terminal=window/'terminal_outcomes_1000.jsonl'
        if not terminal.exists():
            terminal=window/'sender_MSG_DELIVERED_1000.jsonl'
        rows=list(jsonl(terminal))
        assert len(rows)==1000
        successes=[r for r in rows if r['event_type']=='MSG_DELIVERED']
        actions=collections.Counter(r['action'] for r in rows if r['event_type']=='SEND_FAILED')
        success_keys={identity(r) for r in successes}
        rtts={}
        attempts=collections.Counter()
        metadata=0
        inside=False
        for line in (run/'sender/serial.log').open():
            row=event(line)
            if row and row.get('event_counter')==rows[0]['event_counter']:
                inside=True
            if inside and 'ERROR: failed to get gateway metadata' in line:
                metadata+=1
            if '[BENCH]' in line and 'rtt_ms=' in line:
                bench=kv(line)
                key=identity(bench)
                if key in success_keys and bench.get('ok')=='1':
                    rtts[key]=(int(bench['rtt_ms']),int(bench['attempts']))
            if row and row.get('event_counter')==rows[-1]['event_counter']:
                break
        assert len(rtts)==len(successes),(run.name,len(rtts),len(successes))
        for value,attempt in rtts.values():
            attempts[attempt]+=1
        counts=packet_counts(run/'pi1/udp5683.pcap')
        # An independent count from the archived tcpdump rendering must agree.
        txt=collections.Counter()
        for line in (run/'pi1/udp5683.txt').open():
            m=re.search(r'\b(In|Out)\s+IP ([^ >]+) > ([^:]+):',line)
            if not m:
                continue
            direction=m[1].lower()
            if m[3].endswith('.5683'):txt['forward_'+direction]+=1
            elif m[2].endswith('.5683'):txt['reverse_'+direction]+=1
        assert counts==txt,(run.name,counts,txt)
        count=1000+metadata
        failures=actions['cycle_failed']
        item=dict(condition=condition.name,run_id=run.name,delivered=len(successes),
                  structured_terminal_outcomes=1000,structured_delivery_pct=len(successes)/10,
                  metadata_failures_omitted_from_structured_totals=metadata,completed_cycles=count,
                  completed_cycle_delivery_pct=100*len(successes)/count,pk_fetch_failures=actions['pk_fetch_failed'],
                  protected_data_retry_exhaustions=failures,rtt_ms=stats([x[0] for x in rtts.values()]),
                  success_on_attempt={str(k):attempts[k] for k in (1,2,3)},
                  extra_data_transmissions=sum((k-1)*n for k,n in attempts.items())+2*failures,
                  packet_counts=dict(counts),capture_forward_missing_pct=100*(counts['forward_in']-counts['forward_out'])/counts['forward_in'])
        result.append(item)
        retry_rows.append(dict(condition=condition.name,attempt_1=attempts[1],attempt_2=attempts[2],attempt_3=attempts[3],exhausted_after_3=failures,extra_transmissions=item['extra_data_transmissions']))
        manifest=run/'SHA256SUMS_COMPLETE'
        checked=0
        for line in manifest.read_text().splitlines():
            digest,name=line.split(None,1)
            path=run/name.strip().lstrip('*').removeprefix('./')
            assert path.is_file(),str(path)
            assert hashlib.sha256(path.read_bytes()).hexdigest()==digest,str(path)
            checked+=1
        seals.append(dict(run_id=run.name,manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),verified_files=checked))
    write_csv(out/'retry_outcomes.csv',retry_rows)
    write_csv(out/'network_seals.csv',seals)
    write_csv(out/'network_completed_cycles.csv',({k:v for k,v in item.items() if k not in ('rtt_ms','success_on_attempt','packet_counts')} for item in result))
    return result

def same(expected,actual,path='summary'):
    if isinstance(expected,dict):
        assert expected.keys()==actual.keys(),path+' keys differ'
        for key in expected:same(expected[key],actual[key],path+'.'+key)
    elif isinstance(expected,list):
        assert len(expected)==len(actual),path+' length differs'
        for i,(a,b) in enumerate(zip(expected,actual)):same(a,b,path+f'[{i}]')
    elif isinstance(expected,(int,float)):
        assert math.isclose(expected,actual,rel_tol=1e-10,abs_tol=1e-7),f'{path}: {expected} != {actual}'
    else:
        assert expected==actual,f'{path}: {expected} != {actual}'

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--raw',type=Path,default=ROOT/'.reproduce/raw')
    ap.add_argument('--out',type=Path,default=ROOT/'.reproduce/results')
    ap.add_argument('--check',action='store_true')
    args=ap.parse_args()
    args.out.mkdir(parents=True,exist_ok=True)
    summary=dict(schema=1,quantiles='linear interpolation, percentile rank (n-1)*p',
                 primary=primary(args.raw,args.out),network=networks(args.raw,args.out))
    (args.out/'reproduced_summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    if args.check:
        same(json.loads((ROOT/'results/reproduced_summary.json').read_text()),summary)
        print('PASS: raw-data reconstruction matches the committed result summary')
    print('Primary deliveries:',[r['delivered'] for r in summary['primary']])
    print('Network completed cycles:',[r['completed_cycles'] for r in summary['network']])
    print('Results:',args.out)

if __name__=='__main__':
    main()
